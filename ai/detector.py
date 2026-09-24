"""Post-login behavioral threat detection for the SSH Defense Gateway.

Scores live sessions against a baseline of suspicious commands and, when
the score crosses the threshold, terminates the session processes for
real and asks the firewall manager to drop the offending source IP.

The module also carries the learnable command baseline used by training
mode (``--train``). ``BaselineProfile`` accumulates per-user feature
statistics (mean and standard deviation) that are persisted to a JSON
model file; live sessions are then compared against that profile with a
per-feature z-score (standard-deviation) test instead of a hardcoded
binary list.
"""

import json
import math
import os
import signal
import tempfile

from ai.anomaly import SessionVectorizer as _SessionVectorizer

DEFAULT_SUSPICIOUS_COMMANDS = ("sudo", "apt", "python3")

# Subset of the SessionVectorizer row used for the learned baseline.
# novelty_ratio is excluded because it depends on transient cross-session
# state; the remaining features are computed purely from the session
# content, so a trained profile stays comparable on a fresh process.
BASELINE_FEATURE_NAMES = (
    "distinct_commands",
    "process_count",
    "avg_tokens",
    "suspicious_tokens",
    "command_entropy",
)
_BASELINE_COLUMNS = (0, 1, 2, 4, 5)


class _UserStats:
    """Online accumulator of per-feature count/sum/sum-of-squares."""

    __slots__ = ("width", "count", "sums", "sumsq")

    def __init__(self, width):
        self.width = width
        self.count = 0
        self.sums = [0.0] * width
        self.sumsq = [0.0] * width

    def update(self, row):
        self.count += 1
        for index, value in enumerate(row):
            self.sums[index] += value
            self.sumsq[index] += value * value

    def mean_std(self):
        """Per-feature (mean, standard deviation) pairs, variance clamped."""
        pairs = []
        for index in range(self.width):
            mean = self.sums[index] / self.count
            variance = max(
                self.sumsq[index] / self.count - mean * mean, 0.0
            )
            pairs.append((mean, math.sqrt(variance)))
        return pairs

    def to_dict(self):
        return {
            "width": self.width,
            "count": self.count,
            "sums": self.sums,
            "sumsq": self.sumsq,
        }

    @classmethod
    def from_dict(cls, data):
        stats = cls(int(data["width"]))
        stats.count = int(data["count"])
        stats.sums = [float(value) for value in data["sums"]]
        stats.sumsq = [float(value) for value in data["sumsq"]]
        return stats


class BaselineProfile:
    """Persisted per-user command baseline learned during training mode.

    Each user accumulates the mean and standard deviation of the baseline
    features seen during training. A live session is scored against those
    learned stats using a per-feature z-score test: its worst ``|z|`` is
    compared to ``z_threshold`` once at least ``min_samples`` training
    observations exist. The profile serializes atomically to the JSON
    model file ``--train`` writes, so a rebooted gateway never forgets
    what "normal" looks like for a user.
    """

    VERSION = 1

    def __init__(
        self,
        min_samples=5,
        z_threshold=2.5,
        feature_names=BASELINE_FEATURE_NAMES,
    ):
        self.min_samples = min_samples
        self.z_threshold = z_threshold
        self.feature_names = tuple(feature_names)
        self._users = {}

    def observe(self, username, features):
        """Fold one session's features into the user's statistics.

        Returns the new observation count for the user so callers know a
        fresh baseline has grown.
        """
        stats = self._users.get(username)
        if stats is None:
            stats = _UserStats(len(features))
            self._users[username] = stats
        stats.update(features)
        return stats.count

    def score(self, username, features):
        """Score a session against the learned profile (None when unusable).

        Returns None while the user is unknown or has fewer than
        ``min_samples`` training sessions. Otherwise returns a dict with
        the maximum per-feature ``|z|`` and whether it crossed the
        threshold.
        """
        stats = self._users.get(username)
        if stats is None or stats.count < self.min_samples:
            return None

        pairs = stats.mean_std()
        scored = []
        for index, (mean, std) in enumerate(pairs):
            if std <= 1e-12:
                continue
            scored.append((index, (features[index] - mean) / std))

        z_max = max((abs(z) for _, z in scored), default=0.0)
        deviations = sorted(
            (
                {"feature": self.feature_names[i], "z": round(z, 3)}
                for i, z in scored
                if abs(z) >= 1.5
            ),
            key=lambda item: abs(item["z"]),
            reverse=True,
        )[:3]
        return {
            "z_max": round(z_max, 6),
            "flagged": z_max >= self.z_threshold,
            "samples": stats.count,
            "deviations": deviations,
        }

    def save(self, path):
        """Atomically persist the profile to ``path`` for later reloads."""
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = {
            "version": self.VERSION,
            "min_samples": self.min_samples,
            "z_threshold": self.z_threshold,
            "feature_names": list(self.feature_names),
            "users": {
                name: stats.to_dict() for name, stats in self._users.items()
            },
        }
        fd, tmp_path = tempfile.mkstemp(
            dir=directory or ".",
            prefix=".behavior_baseline.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @classmethod
    def load(cls, path):
        """Rebuild a profile from disk, or return an empty fresh one."""
        profile = cls()
        try:
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError):
            return profile
        if isinstance(payload, dict) and payload.get("version") == cls.VERSION:
            profile.min_samples = int(
                payload.get("min_samples", profile.min_samples)
            )
            profile.z_threshold = float(
                payload.get("z_threshold", profile.z_threshold)
            )
            names = payload.get("feature_names")
            if isinstance(names, list):
                profile.feature_names = tuple(names)
            for name, data in (payload.get("users") or {}).items():
                try:
                    profile._users[name] = _UserStats.from_dict(data)
                except (KeyError, TypeError, ValueError):
                    continue
        return profile


class BehaviorDetector:
    """Score live sessions and actively terminate high-risk ones."""

    def __init__(
        self,
        suspicious_commands=None,
        score_threshold=1,
        firewall=None,
        logger=None,
        whitelist=None,
        baseline=None,
    ):
        self._suspicious_commands = set(
            suspicious_commands or DEFAULT_SUSPICIOUS_COMMANDS
        )
        self._score_threshold = score_threshold
        self._firewall = firewall
        self._logger = logger
        self._whitelist = whitelist
        self._last_response = None
        self._baseline = baseline
        self._vectorizer = (
            _SessionVectorizer(self._suspicious_commands)
            if baseline is not None
            else None
        )

    def score_process(self, command):
        """Return the number of distinct baseline tokens in a command."""
        return len(set(command.split()) & self._suspicious_commands)

    def score_session(self, session):
        """Return the cumulative threat score across a session's processes."""
        return sum(
            self.score_process(process["command"])
            for process in session.get("processes", [])
            if process.get("command")
        )

    def _baseline_features(self, session):
        """The machine-usable subset of the feature row, or None."""
        if self._vectorizer is None:
            return None
        row = self._vectorizer.extract(session)
        return [row[index] for index in _BASELINE_COLUMNS]

    def train(self, session):
        """Record a session into the baseline without any response.

        Training mode coats every observation as "normal" — no process is
        killed and no IP is blocked — and returns the user's updated
        observation count so callers know when the baseline file changed.
        """
        if self._baseline is None or self._vectorizer is None:
            return None
        username = session.get("username")
        if not username:
            return None
        features = self._baseline_features(session)
        return self._baseline.observe(username, features)

    def evaluate_baseline(self, session):
        """Score a session against the learned profile (None when unusable)."""
        if self._baseline is None or self._vectorizer is None:
            return None
        username = session.get("username")
        if not username:
            return None
        features = self._baseline_features(session)
        return self._baseline.score(username, features)

    @property
    def last_response(self):
        """The most recent mitigation summary, or None if never triggered."""
        return self._last_response

    def _terminate(self, pid):
        """Kill a single process, tolerating already-dead targets.

        Guards against ``None`` and non-positive pids: those values make
        ``os.kill`` target a whole process group rather than one process,
        which could just as easily kill the daemon's own session. Returns
        True when the process is gone, False when it could not be killed.
        """
        if not isinstance(pid, int) or pid <= 0:
            return False
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            # Already exited on its own — nothing left to do, count as handled.
            return True
        except PermissionError:
            # Not ours to kill; report instead of crashing the response loop.
            return False
        return True

    def respond(self, session):
        """Terminate the session processes and block the source IP.

        Every listed pid gets a kill attempt, but a single stubborn
        process won't hold up the rest — the firewall block is always
        attempted as long as we know the client address. Returns a short
        summary dict and stores it on ``self.last_response``. Each
        kill attempt is permanently recorded through the audit logger.

        A client listed in the administrator whitelist is never touched:
        the response returns immediately with a ``whitelisted`` marker so
        the operator cannot lock themselves out.
        """
        client_address = session.get("client_address")
        whitelisted = bool(
            client_address
            and self._whitelist is not None
            and self._whitelist.is_whitelisted(client_address)
        )
        if whitelisted:
            self._last_response = {
                "kills": [],
                "blocked": False,
                "whitelisted": True,
            }
            return self._last_response

        kills = []
        for process in session.get("processes", []):
            pid = process.get("pid")
            killed = self._terminate(pid)
            kills.append({"pid": pid, "killed": killed})
            if self._logger is not None:
                self._logger.record(
                    "kill",
                    pid=pid,
                    command=process.get("command"),
                    killed=killed,
                    session_id=session.get("session_id"),
                    client_address=client_address,
                )
        blocked = False
        if self._firewall is not None and client_address:
            self._firewall.apply_block(client_address)
            blocked = True
        self._last_response = {"kills": kills, "blocked": blocked}
        return self._last_response

    def evaluate(self, session):
        """Score a session, triggering the automated response on a spike."""
        score = self.score_session(session)
        baseline = self.evaluate_baseline(session)
        flagged = score >= self._score_threshold or bool(
            baseline and baseline["flagged"]
        )
        if flagged:
            self.respond(session)
            if self._logger is not None:
                response = self._last_response or {}
                self._logger.record(
                    "anomaly",
                    session_id=session.get("session_id"),
                    client_address=session.get("client_address"),
                    score=score,
                    threshold=self._score_threshold,
                    baseline_score=(
                        baseline["z_max"] if baseline is not None else None
                    ),
                    baseline_threshold=(
                        self._baseline.z_threshold
                        if self._baseline is not None
                        else None
                    ),
                    whitelisted=bool(response.get("whitelisted")),
                    response=response,
                )
        return score
