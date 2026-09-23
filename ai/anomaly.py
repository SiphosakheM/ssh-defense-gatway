"""Lightweight ML anomaly detection for the SSH Defense Gateway.

Implements a compact Isolation Forest in pure Python (no third-party ML
dependencies) that flags SSH sessions whose behavior diverges from a
per-user baseline, without relying on a hardcoded list of "suspicious"
binaries.

The pipeline has three cooperating pieces:

- ``SessionVectorizer`` turns a live session into a fixed-width feature
  vector (distinct command count, process count, average tokens per
  command, novelty versus the user's past commands, and hits against the
  rule baseline).
- ``IsolationForest`` isolates outliers with random hyperplane splits;
  anomaly score is the standard 2 ** (-avg_path / c(n)) in [0, 1].
- ``AnomalyDetector`` keeps a bounded per-user memory of recent feature
  vectors, lazily refits the forest as the baseline grows, and wraps the
  whole thing in a small JSON-safe assessment dict.

The design stays deliberately cheap for a live daemon: bounded memory
per user, tiny sub-sampled trees, deterministic seeded RNG, and no
system calls other than a bounded re-train when the baseline grows.
"""

import math
import random
from collections import defaultdict

_EULER_GAMMA = 0.5772156649015328606

FEATURE_NAMES = (
    "distinct_commands",
    "process_count",
    "avg_tokens",
    "novelty_ratio",
    "suspicious_tokens",
)


def _avg_path_length(size):
    """Average isolation path length c(n) from the isolation forest paper."""
    if size <= 1:
        return 0.0
    return (
        2.0 * (math.log(size - 1) + _EULER_GAMMA)
        - 2.0 * (size - 1) / size
    )


class _Node:
    """Internal (split) or external (leaf) node of a single isolation tree."""

    __slots__ = ("depth", "size", "feature", "split", "left", "right")

    def __init__(self, depth):
        self.depth = depth
        self.size = 0
        self.feature = None
        self.split = None
        self.left = None
        self.right = None


class IsolationForest:
    """Random hyperplane forest that scores samples in [0, 1].

    ``fit`` builds ``n_trees`` trees over random sub-samples of the
    training rows; ``anomaly_score`` returns the expected path-length
    based anomaly score: values near 1 are outliers, near 0.5 noise,
    well below 0.5 regular observations.
    """

    def __init__(
        self,
        n_trees=16,
        max_samples=64,
        leaf_size=4,
        seed=7,
    ):
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.leaf_size = leaf_size
        self.max_depth = max(1, math.ceil(math.log2(max_samples)))
        self._rng = random.Random(seed)
        self._trees = []
        self._n = 0

    def fit(self, rows):
        """Build the forest from an iterable of fixed-width vectors."""
        rows = list(rows)
        self._n = len(rows)
        self._trees = []
        if not rows:
            return self
        for _ in range(self.n_trees):
            size = min(self.max_samples, len(rows))
            sample = self._rng.sample(rows, size)
            self._trees.append(self._build_tree(sample, 0))
        return self

    def _build_tree(self, rows, depth):
        """Recursively split rows until they form pure / tiny leaves."""
        node = _Node(depth)
        node.size = len(rows)
        if len(rows) <= self.leaf_size or depth >= self.max_depth:
            return node

        width = len(rows[0])
        candidates = []
        for feature in range(width):
            values = [row[feature] for row in rows]
            low, high = min(values), max(values)
            if high - low > 1e-12:
                candidates.append((feature, low, high))
        if not candidates:
            return node

        feature, low, high = self._rng.choice(candidates)
        split = self._rng.uniform(low, high)
        node.feature = feature
        node.split = split
        node.left = self._build_tree(
            [row for row in rows if row[feature] < split], depth + 1
        )
        node.right = self._build_tree(
            [row for row in rows if row[feature] >= split], depth + 1
        )
        return node

    def _path_length(self, node, row, depth):
        """Number of splits isolating ``row`` in this tree, plus c(leaf_size)."""
        if node.feature is None:
            return depth + _avg_path_length(node.size)
        if row[node.feature] < node.split:
            return self._path_length(node.left, row, depth + 1)
        return self._path_length(node.right, row, depth + 1)

    def anomaly_score(self, row):
        """Return the anomaly score of a single feature vector in [0, 1]."""
        if not self._trees or self._n < 2:
            return 0.5
        lengths = [
            self._path_length(tree, row, 0) for tree in self._trees
        ]
        average = sum(lengths) / len(lengths)
        return 2.0 ** (-average / _avg_path_length(self._n))


class SessionVectorizer:
    """Turn session dicts into fixed-width features.

    ``novelty_ratio`` is computed against the per-user vocabulary of
    commands seen so far, so the same commands quickly become "normal"
    while never-before-seen ones push the score up. The rule baseline
    (``suspicious_commands``) remains one feature so both signals mix.
    """

    def __init__(self, suspicious_commands=()):
        self._suspicious = set(suspicious_commands or ())
        self._seen = defaultdict(set)

    def commands(self, session):
        """The list of non-empty command strings in the session."""
        return [
            process.get("command")
            for process in session.get("processes", [])
            if process.get("command")
        ]

    def extract(self, session):
        """Return the feature vector, updating the seen vocabulary."""
        username = session.get("username") or session.get("client_address")
        commands = self.commands(session)
        distinct = set(commands)
        history = self._seen.get(username, set())
        novel = distinct - history

        avg_tokens = (
            sum(len(command.split()) for command in commands) / len(commands)
            if commands
            else 0.0
        )
        distinct_tokens = set(
            token for command in distinct for token in command.split()
        )
        suspicious = len(distinct_tokens & self._suspicious)
        novelty = len(novel) / len(distinct) if distinct else 0.0

        if username is not None:
            self._seen[username].update(distinct)

        return [
            len(distinct),
            len(commands),
            avg_tokens,
            novelty,
            suspicious,
        ]


class AnomalyDetector:
    """Maintain a per-user baseline and score sessions against it.

    Keeps at most ``max_memory`` recent feature vectors per user and
    lazily refits the forest once the baseline passes ``min_train`` and
    grows by ``retrain_every`` new sessions — so a long-lived daemon
    never burns CPU re-training on every single scan.
    """

    def __init__(
        self,
        suspicious_commands=(),
        forest_trees=16,
        max_samples=64,
        leaf_size=4,
        max_memory=150,
        min_train=25,
        retrain_every=24,
        seed=7,
    ):
        self._vectorizer = SessionVectorizer(suspicious_commands)
        self._buffer = defaultdict(list)
        self._forest = IsolationForest(
            n_trees=forest_trees,
            max_samples=max_samples,
            leaf_size=leaf_size,
            seed=seed,
        )
        self.max_memory = max_memory
        self.min_train = min_train
        self.retrain_every = retrain_every
        self._fitted = False
        self._last_fit_count = 0

    def assess(self, session):
        """Score a session and return a JSON-safe assessment dict."""
        username = session.get("username") or session.get("client_address")
        features = self._vectorizer.extract(session)
        buffer = self._buffer[username]
        buffer.append(features)
        if len(buffer) > self.max_memory:
            del buffer[: len(buffer) - self.max_memory]

        should_fit = (
            len(buffer) >= self.min_train
            and not self._fitted
        ) or (
            self._fitted
            and len(buffer) - self._last_fit_count >= self.retrain_every
        )
        if should_fit and len(buffer) >= 1:
            self._forest.fit(buffer)
            self._last_fit_count = len(buffer)
            self._fitted = True

        return {
            "features": [
                round(value, 6) for value in features
            ],
            "anomaly_score": (
                round(self._forest.anomaly_score(features), 6)
                if self._fitted
                else None
            ),
            "trained": bool(self._fitted),
            "samples": len(buffer),
            "why": self._explain(features, buffer),
        }

    def _explain(self, features, buffer):
        """Return the features whose value deviates most from the baseline."""
        width = len(features)
        deviations = []
        for column in range(width):
            values = [row[column] for row in buffer]
            mean = sum(values) / len(values)
            variance = sum((value - mean) ** 2 for value in values) / len(values)
            std = math.sqrt(variance)
            if std <= 1e-12:
                continue
            z = (features[column] - mean) / std
            if abs(z) >= 1.5:
                deviations.append(
                    {"feature": FEATURE_NAMES[column], "z": round(z, 3)}
                )
        deviations.sort(key=lambda item: abs(item["z"]), reverse=True)
        return deviations[:3]