import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.firewall import FirewallManager
from core.state_store import DefenseStateStore

TEST_IP = "203.0.113.55"
REAL_STATE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "logs", "defense_state.json"
)


class Clock:
    """Deterministic time source for expiry tests."""

    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _cleanup(path=REAL_STATE_PATH):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def test_blocked_state_survives_store_restart():
    """A block saved to logs/defense_state.json reloads in a fresh store."""
    _cleanup()
    try:
        first = DefenseStateStore(REAL_STATE_PATH)
        first.record_block(TEST_IP, expires_at=first._clock() + 3600)

        restarted = DefenseStateStore(REAL_STATE_PATH)
        state = restarted.load()

        assert os.path.exists(REAL_STATE_PATH)
        assert TEST_IP in state
        assert state[TEST_IP]["expires_at"] > state[TEST_IP]["blocked_at"]
        assert restarted.is_blocked(TEST_IP) is True
    finally:
        _cleanup()


def test_unblocked_ip_is_forgotten_across_restart():
    """An unblock removes the IP from both memory and the persisted file."""
    _cleanup()
    try:
        first = DefenseStateStore(REAL_STATE_PATH)
        first.record_block(TEST_IP, expires_at=first._clock() + 3600)
        first.record_unblock(TEST_IP)

        restarted = DefenseStateStore(REAL_STATE_PATH)
        assert restarted.load() == {}
        assert restarted.is_blocked(TEST_IP) is False
    finally:
        _cleanup()


def test_expired_block_is_pruned_on_load(tmp_path):
    """Blocks whose window elapsed are not restored after a restart."""
    clock = Clock()
    path = tmp_path / "state.json"
    store = DefenseStateStore(str(path), clock=clock)
    store.record_block(TEST_IP, expires_at=clock())

    clock.advance(60)

    assert store.load() == {}
    assert store.is_blocked(TEST_IP) is False


def test_firewall_block_and_unblock_persist_to_store(tmp_path):
    """Every real block/unblock writes through to the on-disk state."""
    path = tmp_path / "state.json"
    store = DefenseStateStore(str(path))
    manager = FirewallManager(chain="SSH_DEFENSE_TEST", state_store=store)

    class Ok:
        returncode = 0
        stderr = ""

    manager._run = lambda *args: Ok()

    manager.apply_block(TEST_IP, duration_seconds=300)
    assert store.is_blocked(TEST_IP) is True
    with open(path) as f:
        payload = json.load(f)
    entry = payload["blocks"][TEST_IP]
    assert entry["expires_at"] > entry["blocked_at"]

    manager.remove_block(TEST_IP)
    assert store.is_blocked(TEST_IP) is False
    with open(path) as f:
        payload = json.load(f)
    assert TEST_IP not in payload["blocks"]