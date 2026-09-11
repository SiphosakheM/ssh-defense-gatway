import os
import signal
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ai.behavior_monitor import BehaviorMonitor
from ai.detector import BehaviorDetector
from config.loader import load_config
from core.firewall import FirewallManager

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
    fw = FirewallManager(chain="SSH_DEFENSE_TEST")
    try:
        fw.ensure_chain()
    except RuntimeError as exc:
        pytest.skip(f"iptables not usable (requires root): {exc}")
    yield fw
    fw.drop_chain()


def _capture_session(monitor, deadline=10):
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
    detector = BehaviorDetector(suspicious_commands=["sudo", "apt"])
    assert detector.score_process("apt update") == 1
    assert detector.score_process("sudo apt update") == 2
    assert detector.score_process("ls -la") == 0


def test_score_session_sums_across_processes():
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
    killed = []
    detector = BehaviorDetector(suspicious_commands=["sudo"], score_threshold=1)
    detector._terminate = lambda pid: killed.append(pid)
    score = detector.evaluate(
        {"processes": [{"pid": 4242, "command": "sudo ls"}]}
    )
    assert score == 1
    assert killed == [4242]


def test_evaluate_is_a_noop_below_threshold():
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
    # None, zero, and negative pids would make os.kill nuke a whole
    # process group instead of one process — that must never happen.
    calls = []
    monkeypatch.setattr("ai.detector.os.kill", lambda pid, sig: calls.append(pid))
    detector = BehaviorDetector()
    assert detector._terminate(None) is False
    assert detector._terminate(0) is False
    assert detector._terminate(-5) is False
    assert calls == []


def test_terminate_treats_already_dead_process_as_handled(monkeypatch):
    def already_gone(pid, sig):
        raise ProcessLookupError

    monkeypatch.setattr("ai.detector.os.kill", already_gone)
    detector = BehaviorDetector()
    assert detector._terminate(9999) is True


def test_respond_blocks_ip_even_when_kill_is_denied(monkeypatch):
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
    detector = BehaviorDetector()
    result = detector.respond({"client_address": "10.0.0.9", "processes": []})
    assert detector.last_response is result