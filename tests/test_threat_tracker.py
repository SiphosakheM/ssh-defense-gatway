import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.threat_tracker import ThreatTracker


class Clock:
    """Controllable fake clock for deterministic time-window tests."""

    def __init__(self, start=1000.0):
        """Start the fake clock at the given timestamp."""
        self.now = start

    def __call__(self):
        """Return the fake current time."""
        return self.now

    def advance(self, seconds):
        """Move the fake clock forward by ``seconds``."""
        self.now += seconds


def test_track_failures_per_ip_and_retrieve_counts():
    """Failures are recorded per IP and retrievable with current counts."""
    clock = Clock()
    tracker = ThreatTracker(max_attempts=5, time_window_seconds=300, clock=clock)

    tracker.record_failure("192.168.1.10")
    tracker.record_failure("192.168.1.10")
    tracker.record_failure("192.168.1.11")

    assert tracker.failure_count("192.168.1.10") == 2
    assert tracker.failure_count("192.168.1.11") == 1
    assert len(tracker.attempts("192.168.1.10")) == 2


def test_expired_events_are_purged_after_window():
    """Failures older than the window stop counting toward the total."""
    clock = Clock()
    tracker = ThreatTracker(max_attempts=5, time_window_seconds=300, clock=clock)

    tracker.record_failure("192.168.1.10")  # t=1000
    clock.advance(100)
    tracker.record_failure("192.168.1.10")  # t=1100
    clock.advance(100)
    tracker.record_failure("192.168.1.10")  # t=1200

    assert tracker.failure_count("192.168.1.10") == 3

    clock.advance(100)  # t=1300, first event at 1000 is expired
    assert tracker.failure_count("192.168.1.10") == 2

    clock.advance(200)  # t=1500, events at 1100 and 1200 now expired
    assert tracker.failure_count("192.168.1.10") == 0


def test_threshold_triggers_when_max_attempts_reached():
    """An IP is flagged only once its failure count meets the threshold."""
    clock = Clock()
    tracker = ThreatTracker(max_attempts=3, time_window_seconds=300, clock=clock)

    tracker.record_failure("192.168.1.10")
    tracker.record_failure("192.168.1.10")
    assert tracker.is_threat("192.168.1.10") is False

    tracker.record_failure("192.168.1.10")
    assert tracker.is_threat("192.168.1.10") is True


def test_threshold_resets_after_events_expire():
    """Threat status clears once the window passes with no new failures."""
    clock = Clock()
    tracker = ThreatTracker(max_attempts=3, time_window_seconds=300, clock=clock)

    tracker.record_failure("192.168.1.10")
    tracker.record_failure("192.168.1.10")
    tracker.record_failure("192.168.1.10")
    assert tracker.is_threat("192.168.1.10") is True

    clock.advance(301)
    assert tracker.is_threat("192.168.1.10") is False
    assert tracker.failure_count("192.168.1.10") == 0
