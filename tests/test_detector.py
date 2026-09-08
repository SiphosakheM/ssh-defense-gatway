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