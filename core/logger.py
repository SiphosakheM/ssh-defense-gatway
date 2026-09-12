"""Secure append-only audit logging for the SSH Defense Gateway.

Writes one structured JSON object per line to a designated audit log,
guarded by a ``threading.Lock`` so concurrent writers (the daemon loop,
background block-expiry timers, and the behavioral detector) can never
interleave characters inside a single line. Every write is appended in
``a`` mode and ``fsync``-ed so a recorded defense measure survives a
crash rather than lingering in a buffer.
"""

import json
import os
import threading
from datetime import datetime, timezone


class AuditLogger:
    """Thread-safe writer of append-only JSON audit records."""

    def __init__(self, log_path="logs/gateway_audit.log"):
        self._log_path = log_path
        self._lock = threading.Lock()
        self._directory = os.path.dirname(log_path)
        if self._directory:
            os.makedirs(self._directory, exist_ok=True)

    @property
    def log_path(self):
        """The filesystem path this logger appends to."""
        return self._log_path

    def record(self, event_type, **payload):
        """Serialize and append a single JSON audit entry, returning it.

        ``event_type`` names the defense measure (e.g. ``block``,
        ``kill``, ``anomaly``); remaining keyword arguments become the
        entry's payload. The entry is returned so callers could echo the
        exact durable record without re-reading the file.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **payload,
        }
        line = json.dumps(entry, sort_keys=True) + "\n"
        with self._lock:
            self._append(line)
        return entry

    def _append(self, line):
        """Write one full line and flush it out of the kernel buffers."""
        with open(self._log_path, "a", encoding="utf-8", buffering=1) as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())