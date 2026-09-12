import json
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.firewall import FirewallManager
from core.logger import AuditLogger

CHAIN = "SSH_DEFENSE_TEST"
TEST_IP = "203.0.113.42"
AUDIT_LOG = os.path.join(
    os.path.dirname(__file__), "..", "logs", "gateway_audit.log"
)


def _read_entries(path):
    """Parse every non-empty line of the audit log back into a dict."""
    try:
        with open(path, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def test_record_writes_single_structured_json_line(tmp_path):
    """A recorded event lands as one JSON object on one line."""
    log_path = tmp_path / "audit.log"

    entry = AuditLogger(str(log_path)).record(
        "block", ip=TEST_IP, chain=CHAIN
    )

    assert entry["event_type"] == "block"
    assert entry["ip"] == TEST_IP
    assert entry["chain"] == CHAIN
    assert "timestamp" in entry
    assert _read_entries(log_path) == [entry]


def test_record_appends_and_preserves_order(tmp_path):
    """Sequential events accumulate as separate ordered lines."""
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(str(log_path))

    logger.record("block", ip="10.0.0.1")
    logger.record("unblock", ip="10.0.0.1")
    logger.record("kill", pid=123, killed=True)

    entries = _read_entries(log_path)
    assert [entry["event_type"] for entry in entries] == [
        "block",
        "unblock",
        "kill",
    ]


def test_concurrent_writers_never_garble_a_line(tmp_path):
    """Threads racing to write must produce complete, parseable JSON lines."""
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(str(log_path))
    thread_count = 8
    entries_per_thread = 50
    failures = []

    def worker(offset):
        try:
            for attempt in range(entries_per_thread):
                logger.record(
                    "block", ip=f"10.0.0.{offset + attempt}", attempt=attempt
                )
        except Exception as exc:  # pragma: no cover - failure probe
            failures.append(exc)

    threads = [
        threading.Thread(target=worker, args=(t * entries_per_thread,))
        for t in range(thread_count)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    entries = _read_entries(log_path)
    assert len(entries) == thread_count * entries_per_thread
    assert {entry["event_type"] for entry in entries} == {"block"}


def test_firewall_apply_and_remove_block_record_audit_entries(tmp_path):
    """Block and unblock actions each leave their own structured entry."""
    log_path = tmp_path / "audit.log"
    manager = FirewallManager(chain=CHAIN, logger=AuditLogger(str(log_path)))

    class Ok:
        returncode = 0
        stderr = ""

    manager._run = lambda *args: Ok()
    manager.apply_block(TEST_IP)
    manager.remove_block(TEST_IP)

    entries = _read_entries(log_path)
    assert entries[0]["event_type"] == "block"
    assert entries[0]["ip"] == TEST_IP
    assert entries[0]["chain"] == CHAIN
    assert entries[1]["event_type"] == "unblock"
    assert entries[1]["ip"] == TEST_IP
    assert entries[1]["chain"] == CHAIN


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


def test_block_event_written_to_real_audit_log(firewall):
    """A real block event lands a structured entry in logs/gateway_audit.log."""
    try:
        os.remove(AUDIT_LOG)
    except FileNotFoundError:
        pass

    manager = FirewallManager(chain=CHAIN, logger=AuditLogger(AUDIT_LOG))
    manager.apply_block(TEST_IP)

    entry = _read_entries(AUDIT_LOG)[-1]
    assert entry["event_type"] == "block"
    assert entry["ip"] == TEST_IP
    assert entry["chain"] == CHAIN
    assert "timestamp" in entry