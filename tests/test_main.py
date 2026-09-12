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
FAILURE_LINE = (
    "Mar  1 10:00:01 hostname sshd[1234]: Failed password for invalid user "
    f"root from {TEST_IP} port 22 ssh2"
)


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


@pytest.fixture
def env(firewall, tmp_path):
    """Return temporary auth log and config paths for a daemon run."""
    log_path = tmp_path / "auth.log"
    log_path.write_text("")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "max_attempts: 2\n"
        "time_window_seconds: 300\n"
        "block_duration_minutes: 15\n"
        "suspicious_commands: []\n"
    )
    return log_path, config_path


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
        },
        daemon=True,
    )
    thread.start()

    with open(log_path, "a") as f:
        f.write(FAILURE_LINE + "\n")
        f.write(FAILURE_LINE + "\n")
        f.flush()
        os.fsync(f.fileno())

    deadline = time.monotonic() + 10
    while not firewall.rule_exists(TEST_IP) and time.monotonic() < deadline:
        time.sleep(0.05)
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