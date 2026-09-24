import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ai.anomaly import (
    AnomalyDetector,
    IsolationForest,
    SessionVectorizer,
    _shannon_entropy,
)
from ai.ml_detector import AnomalyAwareDetector
from config.loader import load_config
from core.logger import AuditLogger
from core.state_manager import StateManager

CLIENT_IP = "10.0.0.9"


def _session(commands, username="alice", client=CLIENT_IP):
    return {
        "session_id": f"ssh:{client}:1",
        "username": username,
        "client_address": client,
        "processes": [
            {"pid": 1000 + index, "ppid": 1000, "command": command}
            for index, command in enumerate(commands)
        ],
    }


class FakeFirewall:
    """Record-only firewall used to observe detector responses."""

    def __init__(self):
        self.blocked_ips = []

    def apply_block(self, ip):
        self.blocked_ips.append(ip)


def _read_entries(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def test_forest_separates_outliers_from_cluster():
    """Far outliers isolate faster and score higher than the in-cluster rows."""
    normal = [[2, 2, 1.0, 0.0, 0.0, 3.2] for _ in range(60)]
    normal += [[3, 3, 1.0, 0.1, 1.0, 3.4] for _ in range(20)]
    outliers = [[40, 80, 250.0, 1.0, 10.0, 4.9] for _ in range(3)]
    forest = IsolationForest(n_trees=30, max_samples=32)
    forest.fit(normal + outliers)

    normal_scores = [forest.anomaly_score(row) for row in normal]
    outlier_scores = [forest.anomaly_score(row) for row in outliers]
    assert all(0.0 <= score <= 1.0 for score in outlier_scores)
    assert max(normal_scores) < min(outlier_scores)


def test_forest_is_deterministic_with_seed():
    """The same seed produces identical scores, so tests are reproducible."""
    rows = [[i, i % 3, float(i), i / 10, i % 5] for i in range(40)]
    first = IsolationForest(seed=11)
    second = IsolationForest(seed=11)
    first.fit(rows)
    second.fit(rows)
    scores_a = [first.anomaly_score(row) for row in rows]
    scores_b = [second.anomaly_score(row) for row in rows]
    assert scores_a == scores_b


def test_forest_unfitted_returns_neutral_score():
    """Without training data the forest cannot decide, so scores stay 0.5."""
    forest = IsolationForest()
    assert forest.anomaly_score([1, 2, 3, 0, 0]) == 0.5


def test_vectorizer_extracts_feature_row():
    """Commands are folded into distinct count, process count, tokens, novelty."""
    vectorizer = SessionVectorizer(suspicious_commands=["sudo", "apt"])
    features = vectorizer.extract(_session(["ls -la", "ls -la", "sudo apt update"]))
    assert features[0] == 2  # distinct commands
    assert features[1] == 3  # process count
    assert features[2] == pytest.approx(7 / 3)  # mean tokens per command
    assert features[3] == pytest.approx(1.0)  # first observation => all novel
    assert features[4] == 2  # sudo + apt both present
    assert features[5] == pytest.approx(
        _shannon_entropy("ls -la ls -la sudo apt update")
    )


def test_vectorizer_entropy_spikes_on_obfuscated_payloads():
    """High-information command strings score far above routine admin work."""
    vectorizer = SessionVectorizer()
    routine = vectorizer.extract(_session(["ls -la", "pwd", "whoami"]))
    obfuscated = vectorizer.extract(
        _session(["echo p1Y2a3s4s5w0r6d7 | base64 -d | bash -i"])
    )
    assert routine[5] >= 0.0
    assert obfuscated[5] > routine[5] + 0.5


def test_vectorizer_novelty_fades_as_commands_repeat():
    """Repeated commands become baseline; brand-new ones spike novelty again."""
    vectorizer = SessionVectorizer()
    first = vectorizer.extract(_session(["ls", "pwd", "whoami"]))
    assert first[3] == pytest.approx(1.0)
    repeat = vectorizer.extract(_session(["ls", "pwd"]))
    assert repeat[3] == pytest.approx(0.0)
    novel = vectorizer.extract(_session(["curl", "bash", "base64"]))
    assert novel[3] == pytest.approx(1.0)


def test_assess_trains_only_after_minimum_baseline():
    """Nothing is scored until enough of a per-user baseline exists."""
    detector = AnomalyDetector(min_train=3, retrain_every=100)
    detector.assess(_session(["ls", "pwd"]))
    early = detector.assess(_session(["ls"]))
    assert early["trained"] is False
    assert early["anomaly_score"] is None

    later = detector.assess(_session(["ls", "pwd", "cat /etc/hostname"]))
    assert later["trained"] is True
    assert later["samples"] == 3
    assert later["anomaly_score"] is not None


def test_assess_bounds_memory_per_user():
    """The rolling buffer never grows past max_memory, keeping the daemon light."""
    detector = AnomalyDetector(max_memory=4, min_train=1000)
    result = None
    for index in range(10):
        result = detector.assess(_session([f"cmd{index}"]))
    assert result["samples"] == 4
    assert result["trained"] is False


def test_assess_tracks_each_user_separately():
    """Baseline per user, so one busy user cannot mask another's anomaly."""
    detector = AnomalyDetector(max_memory=2, min_train=1000)
    detector.assess(_session(["ls"], username="alice"))
    detector.assess(_session(["ls"], username="bob"))
    assert detector.assess(_session(["ls"], username="alice"))["samples"] == 2
    assert detector.assess(_session(["ls"], username="bob"))["samples"] == 2


def test_assessment_explains_driving_feature():
    """The response explains which feature deviated from the baseline."""
    detector = AnomalyDetector(min_train=3, retrain_every=100)
    for _ in range(4):
        detector.assess(_session(["ls", "pwd"]))
    result = detector.assess(_session(["base64", "bash", "nc", "curl"]))
    assert result["trained"] is True
    features = [item["feature"] for item in result["why"]]
    assert "distinct_commands" in features


def test_ml_flags_unusual_behavior_without_suspicious_binaries(tmp_path):
    """An outlier session is killed and blocked even with an empty rule baseline."""
    log_path = tmp_path / "audit.log"
    firewall = FakeFirewall()
    detector = AnomalyAwareDetector(
        suspicious_commands=[],
        score_threshold=100,
        anomaly_threshold=0.6,
        min_train=3,
        retrain_every=2,
        firewall=firewall,
        logger=AuditLogger(str(log_path)),
    )
    detector._terminate = lambda pid: True

    for _ in range(10):
        detector.evaluate(_session(["ls", "pwd", "cat /etc/hostname"]))

    score = detector.evaluate(
        _session(["curl -s http://x && base64 -d && nc y 4444 && tar xf z"])
    )
    assert score == 0  # no rule-baseline binaries, so the rule score is zero
    assert detector.last_assessment["trained"] is True
    assert detector.last_assessment["anomaly_score"] >= 0.6
    assert firewall.blocked_ips == [CLIENT_IP]
    assert detector.last_response["blocked"] is True

    anomalies = [
        entry
        for entry in _read_entries(log_path)
        if entry["event_type"] == "anomaly"
    ]
    assert anomalies
    assert anomalies[-1]["ml_score"] >= 0.6
    assert anomalies[-1]["response"]["blocked"] is True


def test_rule_score_still_triggers_before_ml_baseline_ready(tmp_path):
    """The classic suspicious-binary path fires even when the model is untrained."""
    log_path = tmp_path / "audit.log"
    firewall = FakeFirewall()
    detector = AnomalyAwareDetector(
        suspicious_commands=["sudo"],
        score_threshold=1,
        min_train=1000,
        firewall=firewall,
        logger=AuditLogger(str(log_path)),
    )
    detector._terminate = lambda pid: True

    score = detector.evaluate(_session(["sudo apt update"]))
    assert score == 1
    assert detector.last_assessment["trained"] is False
    assert detector.last_assessment["anomaly_score"] is None
    assert firewall.blocked_ips == [CLIENT_IP]
    assert detector.last_response["blocked"] is True


def test_untrained_ml_baseline_never_responds(tmp_path):
    """No response without either the rule score or a trained baseline."""
    log_path = tmp_path / "audit.log"
    firewall = FakeFirewall()
    detector = AnomalyAwareDetector(
        suspicious_commands=[],
        score_threshold=50,
        min_train=1000,
        firewall=firewall,
        logger=AuditLogger(str(log_path)),
    )
    detector._terminate = lambda pid: (_ for _ in ()).throw(AssertionError())

    detector.evaluate(_session(["base64 bash curl nc"]))
    assert firewall.blocked_ips == []
    assert detector.last_response is None
    assert _read_entries(log_path) == []


def test_whitelisted_client_is_never_terminated_or_blocked_by_ml(tmp_path):
    """The admin whitelist still protects clients from the ML response path."""
    log_path = tmp_path / "audit.log"
    firewall = FakeFirewall()
    detector = AnomalyAwareDetector(
        suspicious_commands=[],
        score_threshold=50,
        anomaly_threshold=0.6,
        min_train=3,
        retrain_every=2,
        firewall=firewall,
        logger=AuditLogger(str(log_path)),
        whitelist=StateManager([CLIENT_IP]),
    )
    detector._terminate = lambda pid: (_ for _ in ()).throw(AssertionError())

    for _ in range(8):
        detector.evaluate(_session(["ls", "pwd"]))
    detector.evaluate(_session(["base64 -d && bash -i"]))

    assert detector.last_response == {
        "kills": [],
        "blocked": False,
        "whitelisted": True,
    }
    assert firewall.blocked_ips == []
    anomalies = [
        entry
        for entry in _read_entries(log_path)
        if entry["event_type"] == "anomaly"
    ]
    assert anomalies
    assert anomalies[-1]["whitelisted"] is True
    assert anomalies[-1]["response"]["whitelisted"] is True


def test_from_config_parses_optional_ml_tuning_keys(tmp_path):
    """Optional anomaly keys load without breaking the strict config contract."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "max_attempts: 5\n"
        "time_window_seconds: 300\n"
        "block_duration_minutes: 15\n"
        "suspicious_commands: []\n"
        "whitelist_ips: []\n"
        "anomaly_enabled: false\n"
        "anomaly_threshold: 0.5\n"
        "anomaly_forest_trees: 8\n"
        "anomaly_max_memory: 20\n"
        "anomaly_min_train: 2\n"
        "anomaly_retrain_every: 1\n"
    )
    detector = AnomalyAwareDetector.from_config(load_config(str(config_path)))
    assert detector.ml_enabled is False
    assert detector.anomaly_threshold == 0.5
    assert detector._anomaly.min_train == 2
    assert detector._anomaly.max_memory == 20
    assert detector._anomaly.retrain_every == 1
    assert detector._anomaly._forest.n_trees == 8


def test_config_without_ml_keys_keeps_safe_defaults(tmp_path):
    """A classic five-key config still builds a working, enabled detector."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "max_attempts: 5\n"
        "time_window_seconds: 300\n"
        "block_duration_minutes: 15\n"
        "suspicious_commands:\n"
        "  - sudo\n"
        "whitelist_ips: []\n"
    )
    detector = AnomalyAwareDetector.from_config(load_config(str(config_path)))
    assert detector.ml_enabled is True
    assert detector.anomaly_threshold == pytest.approx(0.72)
    assert detector._suspicious_commands == {"sudo"}