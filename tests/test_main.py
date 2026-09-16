import json
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main
from core.firewall import FirewallManager

CHAIN = "SSH_DEFENSE_TEST"
TEST_IP = "203.0.113.9"
OTHER_IP = "198.51.100.7"


def _failure_line(ip):
    return (
        "Mar  1 10:00:01 hostname sshd[1234]: Failed password for invalid user "
        f"root from {ip} port 22 ssh2"
    )


FAILURE_LINE = _failure_line(TEST_IP)
OTHER_FAILURE_LINE = _failure_line(OTHER_IP)


@pytest.fixture
def firewall():
    """Provide a real iptables chain, skipping when root is unavailable."""
    fw = FirewallManager(chain=CHAIN)
    try:
        fw.ensure_chain()
    except RuntimeError as exc:
        pytest.skip(f"iptables not usable (requires root): {exc}")
    yield fw
    fw.drop_chain()


def _write_config(path, whitelist_ips=None):
    path.write_text(
        "max_attempts: 2\n"
        "time_window_seconds: 300\n"
        "block_duration_minutes: 15\n"
        "suspicious_commands: []\n"
        f"whitelist_ips: {whitelist_ips or []}\n"
    )


def _append_failures(log_path, lines):
    """Append tail lines, fsync-ing so the polling daemon sees them."""
    with open(log_path, "a") as f:
        for line in lines:
            f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


def _pump_until(log_path, lines, predicate, deadline=10):
    """Re-append lines until ``predicate`` holds or the deadline passes."""
    start = time.monotonic()
    while time.monotonic() - start < deadline:
        if predicate():
            return True
        _append_failures(log_path, lines)
        time.sleep(0.2)
    return predicate()


@pytest.fixture
def env(firewall, tmp_path):
    """Return temporary auth log and config paths for a daemon run."""
    log_path = tmp_path / "auth.log"
    log_path.write_text("")
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)
    return log_path, config_path


class RecordingFirewall:
    """Stand-in firewall that records block requests instead of touching iptables."""

    def __init__(self, chain=None, logger=None, state_store=None):
        self.blocked_ips = []

    def ensure_chain(self):
        pass

    def rule_exists(self, ip):
        return False

    def apply_block(self, ip, duration_seconds=None):
        self.blocked_ips.append(ip)

    def schedule_block_removal(self, ip, duration_seconds):
        pass


def test_daemon_bypasses_whitelisted_ip(tmp_path, monkeypatch):
    """A whitelisted IP is never sent to the firewall, other attackers are."""
    log_path = tmp_path / "auth.log"
    log_path.write_text("")
    config_path = tmp_path / "config.yaml"
    _write_config(config_path, whitelist_ips=[TEST_IP])

    recorder = RecordingFirewall()
    monkeypatch.setattr(main, "FirewallManager", lambda **kwargs: recorder)
    stop = threading.Event()
    thread = threading.Thread(
        target=main.run_daemon,
        kwargs={
            "config_path": str(config_path),
            "log_path": str(log_path),
            "chain": CHAIN,
            "stop_event": stop,
            "audit_log_path": str(log_path.parent / "audit.log"),
            "state_path": str(log_path.parent / "defense_state.json"),
        },
        daemon=True,
    )
    thread.start()

    lines = (FAILURE_LINE, FAILURE_LINE, OTHER_FAILURE_LINE, OTHER_FAILURE_LINE)
    assert _pump_until(
        log_path,
        lines,
        lambda: OTHER_IP in recorder.blocked_ips,
    )
    assert recorder.blocked_ips == [OTHER_IP]
    assert TEST_IP not in recorder.blocked_ips

    stop.set()
    with open(log_path, "a") as f:
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    thread.join(timeout=5)
    assert thread.is_alive() is False


def test_daemon_never_drops_whitelisted_ip(env, firewall, tmp_path):
    """On the real chain the whitelisted IP's DROP rule is explicitly bypassed."""
    log_path, config_path = env
    config_path.write_text(
        "max_attempts: 2\n"
        "time_window_seconds: 300\n"
        "block_duration_minutes: 15\n"
        "suspicious_commands: []\n"
        f"whitelist_ips: ['{TEST_IP}']\n"
    )
    stop = threading.Event()
    thread = threading.Thread(
        target=main.run_daemon,
        kwargs={
            "config_path": str(config_path),
            "log_path": str(log_path),
            "chain": CHAIN,
            "stop_event": stop,
            "audit_log_path": str(log_path.parent / "audit.log"),
            "state_path": str(log_path.parent / "defense_state.json"),
        },
        daemon=True,
    )
    thread.start()

    lines = (FAILURE_LINE, FAILURE_LINE, OTHER_FAILURE_LINE, OTHER_FAILURE_LINE)
    assert _pump_until(
        log_path,
        lines,
        lambda: firewall.rule_exists(OTHER_IP),
    )
    assert firewall.rule_exists(OTHER_IP) is True
    assert firewall.rule_exists(TEST_IP) is False

    with open(log_path.parent / "audit.log") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    blocks = [entry for entry in entries if entry["event_type"] == "block"]
    assert {entry["ip"] for entry in blocks} == {OTHER_IP}

    stop.set()
    with open(log_path, "a") as f:
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    thread.join(timeout=5)
    assert thread.is_alive() is False


def test_daemon_reapplies_persisted_blocks_on_start(tmp_path, monkeypatch):
    """Blocks found on disk at startup are restored onto the firewall."""
    log_path = tmp_path / "auth.log"
    log_path.write_text("")
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)
    state_path = tmp_path / "defense_state.json"

    from core.state_store import DefenseStateStore

    DefenseStateStore(str(state_path)).record_block(
        TEST_IP, expires_at=time.time() + 3600
    )

    recorder = RecordingFirewall()
    monkeypatch.setattr(main, "FirewallManager", lambda **kwargs: recorder)
    stop = threading.Event()
    thread = threading.Thread(
        target=main.run_daemon,
        kwargs={
            "config_path": str(config_path),
            "log_path": str(log_path),
            "chain": CHAIN,
            "stop_event": stop,
            "audit_log_path": str(log_path.parent / "audit.log"),
            "state_path": str(state_path),
        },
        daemon=True,
    )
    thread.start()

    deadline = time.monotonic() + 10
    while TEST_IP not in recorder.blocked_ips and time.monotonic() < deadline:
        time.sleep(0.05)
    assert recorder.blocked_ips == [TEST_IP]

    stop.set()
    with open(log_path, "a") as f:
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    thread.join(timeout=5)
    assert thread.is_alive() is False


def test_daemon_blocks_ip_after_failure_threshold(env, firewall):
    """The daemon drops traffic from an IP once failures hit the threshold."""
    log_path, config_path = env
    stop = threading.Event()
    thread = threading.Thread(
        target=main.run_daemon,
        kwargs={
            "config_path": str(config_path),
            "log_path": str(log_path),
            "chain": CHAIN,
            "stop_event": stop,
            "audit_log_path": str(log_path.parent / "audit.log"),
            "state_path": str(log_path.parent / "defense_state.json"),
        },
        daemon=True,
    )
    thread.start()

    assert _pump_until(
        log_path,
        (FAILURE_LINE, FAILURE_LINE),
        lambda: firewall.rule_exists(TEST_IP),
    )
    assert firewall.rule_exists(TEST_IP) is True

    with open(log_path.parent / "audit.log") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    assert entries
    assert entries[-1]["event_type"] == "block"
    assert entries[-1]["ip"] == TEST_IP

    stop.set()
    with open(log_path, "a") as f:
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    thread.join(timeout=5)
    assert thread.is_alive() is False