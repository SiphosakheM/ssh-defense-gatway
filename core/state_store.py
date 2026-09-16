"""Persistent threat state for the SSH Defense Gateway.

Mirrors the currently active firewall blocks to a JSON file on every
block and unblock so the daemon can restore them across restarts and
reboots using real file I/O. Writes are atomic (temp file + rename) and
guarded by a lock so concurrent block operations and expiry timers can
never corrupt the on-disk state.
"""

import json
import os
import tempfile
import threading
import time


class DefenseStateStore:
    """Durably track which IPs are blocked and for how long."""

    DEFAULT_PATH = "logs/defense_state.json"

    def __init__(self, path=DEFAULT_PATH, clock=None):
        self._path = path
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._blocks = {}
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    @property
    def path(self):
        """The filesystem path this store persists to."""
        return self._path

    def load(self):
        """Read persisted blocks back into memory, pruning expired ones.

        Returns a dict mapping each still-active IP to its ``blocked_at``
        and ``expires_at`` timestamps, and feeds it into this instance's
        in-memory view so further writes stay consistent with disk.
        """
        with self._lock:
            try:
                with open(self._path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except (FileNotFoundError, json.JSONDecodeError):
                self._blocks = {}
                return {}

            raw = payload.get("blocks", {}) if isinstance(payload, dict) else {}
            self._blocks = {}
            now = self._clock()
            for ip, info in raw.items():
                expires_at = (
                    info.get("expires_at")
                    if isinstance(info, dict)
                    else None
                )
                if expires_at is not None and expires_at <= now:
                    continue
                self._blocks[ip] = info
            return dict(self._blocks)

    def record_block(self, ip, expires_at=None):
        """Mark an IP as blocked and persist the state immediately.

        ``expires_at`` is an epoch-seconds deadline; ``None`` means the
        block stays in place until explicitly removed.
        """
        with self._lock:
            self._blocks[ip] = {
                "blocked_at": self._clock(),
                "expires_at": expires_at,
            }
            self._save_locked()

    def record_unblock(self, ip):
        """Forget an IP's block and persist the removal immediately."""
        with self._lock:
            if self._blocks.pop(ip, None) is None:
                return
            self._save_locked()

    def is_blocked(self, ip):
        """Return True while an unexpired block is recorded for the IP."""
        info = self._blocks.get(ip)
        if info is None:
            return False
        expires_at = info.get("expires_at")
        return expires_at is None or expires_at > self._clock()

    def active_blocks(self):
        """Return the currently unexpired blocks as an ip-to-info dict."""
        return {
            ip: info
            for ip, info in self._blocks.items()
            if self.is_blocked(ip)
        }

    def _save_locked(self):
        """Atomically replace the state file with the in-memory blocks."""
        directory = os.path.dirname(self._path) or "."
        fd, tmp_path = tempfile.mkstemp(
            dir=directory,
            prefix=".defense_state.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"blocks": self._blocks}, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self._path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)