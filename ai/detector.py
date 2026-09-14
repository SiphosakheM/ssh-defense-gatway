"""Post-login behavioral threat detection for the SSH Defense Gateway.

Scores live sessions against a baseline of suspicious commands and, when
the score crosses the threshold, terminates the session processes for
real and asks the firewall manager to drop the offending source IP.
"""

import os
import signal

DEFAULT_SUSPICIOUS_COMMANDS = ("sudo", "apt", "python3")


class BehaviorDetector:
    """Score live sessions and actively terminate high-risk ones."""

    def __init__(
        self,
        suspicious_commands=None,
        score_threshold=1,
        firewall=None,
        logger=None,
        whitelist=None,
    ):
        self._suspicious_commands = set(
            suspicious_commands or DEFAULT_SUSPICIOUS_COMMANDS
        )
        self._score_threshold = score_threshold
        self._firewall = firewall
        self._logger = logger
        self._whitelist = whitelist
        self._last_response = None

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
        if score >= self._score_threshold:
            self.respond(session)
            if self._logger is not None:
                response = self._last_response or {}
                self._logger.record(
                    "anomaly",
                    session_id=session.get("session_id"),
                    client_address=session.get("client_address"),
                    score=score,
                    threshold=self._score_threshold,
                    whitelisted=bool(response.get("whitelisted")),
                    response=response,
                )
        return score
