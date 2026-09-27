"""Durable session audit storage for the SSH Defense Gateway.

Every SSH session the behavioral scanner observes is recorded twice: as a
human-greppable JSONL line in ``logs/sessions/YYYY-MM-DD.jsonl`` and as a
row in a local SQLite database so the operator (or a dashboard) can query
logins, source IPs, and the commands each external computer ran without
parsing flat files.

Records are deduplicated by session id + command signature: a long-lived
shell is only re-recorded when its command set actually changes or when it
gets flagged, so the audit trail shows meaningful events, not one row per
30-second scan.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone


class SessionStore:
    """Persist session telemetry to per-day JSONL plus SQLite.

    Both sinks are best-effort: a failure writing one must never crash the
    daemon's behavioral scan, so each write is guarded and surfaced only
    through the method's return value.
    """

    def __init__(
        self,
        log_dir="logs/sessions",
        sqlite_path="logs/sessions.db",
        retention_days=30,
    ):
        self._log_dir = log_dir
        self._sqlite_path = sqlite_path
        self._retention_days = retention_days
        self._lock = threading.Lock()
        self._last_signature = {}
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        self._init_sqlite()

    def _init_sqlite(self):
        """Create the sessions table and its address index once."""
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT,
                        collected_at TEXT,
                        username TEXT,
                        client_address TEXT,
                        commands TEXT,
                        threat_score REAL,
                        ml_score REAL,
                        flagged INTEGER,
                        mitigation TEXT
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_sessions_address
                    ON sessions(client_address)
                    """
                )
        except sqlite3.Error:
            pass

    def _connect(self):
        """Open a dedicated SQLite connection for one statement batch."""
        return sqlite3.connect(self._sqlite_path)

    def _signature(self, session):
        """A hashable fingerprint of the session's current commands."""
        commands = self._commands(session)
        return tuple(
            (item.get("pid"), item.get("command")) for item in commands
        )

    @staticmethod
    def _commands(session):
        """The session's command history, falling back to its processes."""
        history = session.get("command_history")
        if history:
            return history
        return session.get("processes", [])

    def record(
        self,
        session,
        collected_at=None,
        threat_score=None,
        ml_score=None,
        baseline_z=None,
        flagged=False,
        mitigation=None,
    ):
        """Persist one session snapshot, pruning the archive when due.

        Before writing, the store checks whether anything changed: a
        session that is unchanged and unflagged only counts once in the
        trail. Returns True when a row was actually written.
        """
        session_id = session.get("session_id") or f"unknown:{session.get('username')}"
        signature = self._signature(session)
        state = (signature, bool(flagged))
        if self._last_signature.get(session_id) == state:
            return False
        self._last_signature[session_id] = state

        record = {
            "session_id": session_id,
            "collected_at": collected_at
            or datetime.now(timezone.utc).isoformat(),
            "username": session.get("username"),
            "client_address": session.get("client_address"),
            "commands": self._commands(session),
            "threat_score": threat_score,
            "ml_score": ml_score,
            "baseline_z": baseline_z,
            "flagged": bool(flagged),
            "mitigation": mitigation or {},
        }
        with self._lock:
            jsonl_ok = self._append_jsonl(record)
            sqlite_ok = self._append_sqlite(record)
        if jsonl_ok or sqlite_ok:
            self._prune_archive()
        return jsonl_ok or sqlite_ok

    def _append_jsonl(self, record):
        """Write one JSON line to today's file in the archive."""
        try:
            day = datetime.now().strftime("%Y-%m-%d")
            path = os.path.join(self._log_dir, f"{day}.jsonl")
            with open(path, "a", encoding="utf-8", buffering=1) as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return True
        except OSError:
            return False

    def _append_sqlite(self, record):
        """Insert one row into the sessions table."""
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO sessions (
                        session_id, collected_at, username, client_address,
                        commands, threat_score, ml_score, flagged, mitigation
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["session_id"],
                        record["collected_at"],
                        record["username"],
                        record["client_address"],
                        json.dumps(record["commands"], sort_keys=True),
                        record["threat_score"],
                        record["ml_score"],
                        int(record["flagged"]),
                        json.dumps(record["mitigation"], sort_keys=True),
                    ),
                )
            return True
        except sqlite3.Error:
            return False

    def recent_sessions(self, limit=50):
        """Return the newest session rows as plain dicts, oldest first."""
        rows = []
        try:
            with self._connect() as connection:
                connection.row_factory = sqlite3.Row
                cursor = connection.execute(
                    "SELECT * FROM sessions ORDER BY id DESC LIMIT ?",
                    (int(limit),),
                )
                rows = [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error:
            return []
        rows.reverse()
        for row in rows:
            row["flagged"] = bool(row["flagged"])
            try:
                row["commands"] = json.loads(row["commands"])
            except (TypeError, json.JSONDecodeError):
                row["commands"] = []
            try:
                row["mitigation"] = json.loads(row["mitigation"])
            except (TypeError, json.JSONDecodeError):
                row["mitigation"] = {}
        return rows

    def _prune_archive(self):
        """Delete JSONL files untouched for longer than the retention window."""
        try:
            cutoff = datetime.now().timestamp() - self._retention_days * 86400
            with os.scandir(self._log_dir) as entries:
                for entry in entries:
                    if not entry.name.endswith(".jsonl"):
                        continue
                    try:
                        if entry.stat().st_mtime < cutoff:
                            os.unlink(entry.path)
                    except OSError:
                        continue
        except OSError:
            return