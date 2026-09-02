"""Threat state tracking for the SSH Defense Gateway.

Tracks failed login timestamps per IP over a rolling time window and
evaluates when an IP crosses the failure threshold.
"""

import time


class ThreatTracker:
    """In-memory tracker mapping IP addresses to failure timestamps."""

    def __init__(self, max_attempts=5, time_window_seconds=300, clock=None):
        self.max_attempts = max_attempts
        self.time_window_seconds = time_window_seconds
        self._clock = clock or time.time
        self._failures = {}

    def record_failure(self, ip):
        self._failures.setdefault(ip, []).append(self._clock())
        self._cleanup(ip)

    def attempts(self, ip):
        self._cleanup(ip)
        return list(self._failures.get(ip, []))

    def failure_count(self, ip):
        return len(self.attempts(ip))

    def is_threat(self, ip):
        return self.failure_count(ip) >= self.max_attempts

    def _cleanup(self, ip=None):
        now = self._clock()
        cutoff = now - self.time_window_seconds
        targets = [ip] if ip else list(self._failures.keys())
        for addr in targets:
            timestamps = self._failures.get(addr)
            if not timestamps:
                continue
            remaining = [ts for ts in timestamps if ts > cutoff]
            if remaining:
                self._failures[addr] = remaining
            else:
                self._failures.pop(addr, None)
