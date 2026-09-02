import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.threat_tracker import ThreatTracker


class Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_track_failures_per_ip_and_retrieve_counts():
    clock = Clock()
    tracker = ThreatTracker(max_attempts=5, time_window_seconds=300, clock=clock)

    tracker.record_failure("192.168.1.10")
    tracker.record_failure("192.168.1.10")
    tracker.record_failure("192.168.1.11")

    assert tracker.failure_count("192.168.1.10") == 2
    assert tracker.failure_count("192.168.1.11") == 1
    assert len(tracker.attempts("192.168.1.10")) == 2


def test_expired_events_are_purged_after_window():
    clock = Clock()
    tracker = ThreatTracker(max_attempts=5, time_window_seconds=300, clock=clock)

    tracker.record_failure("192.168.1.10")  # t=1000
    clock.advance(100)
    tracker.record_failure("192.168.1.10")  # t=1100
    clock.advance(100)
    tracker.record_failure("192.168.1.10")  # t=1200

    assert tracker.failure_count("192.168.1.10") == 3

    clock.advance(500)  # t=1700, first two are beyond 300s window
    assert tracker.failure_count("192.168.1.10") == 1

    clock.advance(250)  # t=1950, last event at 1200 also expired
    assert tracker.failure_count("192.168.1.10") == 0


def test_threshold_triggers_when_max_attempts_reached():
    clock = Clock()
    tracker = ThreatTracker(max_attempts=3, time_window_seconds=300, clock=clock)

    tracker.record_failure("192.168.1.10")
    tracker.record_failure("192.168.1.10")
    assert tracker.is_threat("192.168.1.10") is False

    tracker.record_failure("192.168.1.10")
    assert tracker.is_threat("192.168.1.10") is True


def test_threshold_resets_after_events_expire():
    clock = Clock()
    tracker = ThreatTracker(max_attempts=3, time_window_seconds=300, clock=clock)

    tracker.record_failure("192.168.1.10")
    tracker.record_failure("192.168.1.10")
    tracker.record_failure("192.168.1.10")
    assert tracker.is_threat("192.168.1.10") is True

    clock.advance(301)
    assert tracker.is_threat("192.168.1.10") is False
    assert tracker.failure_count("192.168.1.10") == 0
