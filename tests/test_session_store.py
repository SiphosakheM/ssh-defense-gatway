import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.session_store import SessionStore


def _session(
    session_id="ssh:10.0.0.5:100",
    username="bob",
    commands=("ls", "pwd"),
):
    history = [
        {
            "pid": 100 + index,
            "command": command,
            "observed_at": "2026-01-01T00:00:00+00:00",
        }
        for index, command in enumerate(commands)
    ]
    return {
        "session_id": session_id,
        "username": username,
        "client_address": "10.0.0.5",
        "processes": [
            {"pid": item["pid"], "ppid": 1, "command": item["command"]}
            for item in history
        ],
        "command_history": history,
    }


def test_record_writes_jsonl_line_including_commands(tmp_path):
    store = SessionStore(
        log_dir=str(tmp_path / "sessions"),
        sqlite_path=str(tmp_path / "sessions.db"),
    )
    session = _session()
    written = store.record(
        session,
        collected_at="2026-01-01T00:00:00+00:00",
        threat_score=2,
        ml_score=0.9,
        flagged=True,
        mitigation={"blocked": True},
    )
    assert written is True

    day_files = list((tmp_path / "sessions").glob("*.jsonl"))
    assert len(day_files) == 1
    parsed = json.loads(day_files[0].read_text())
    assert parsed["session_id"] == "ssh:10.0.0.5:100"
    assert parsed["username"] == "bob"
    assert parsed["client_address"] == "10.0.0.5"
    assert parsed["threat_score"] == 2
    assert parsed["flagged"] is True
    assert [entry["command"] for entry in parsed["commands"]] == ["ls", "pwd"]


def test_unchanged_benign_sessions_are_not_duplicated(tmp_path):
    store = SessionStore(
        log_dir=str(tmp_path / "sessions"),
        sqlite_path=str(tmp_path / "sessions.db"),
    )
    session = _session()
    assert store.record(session) is True
    assert store.record(session) is False

    changed = _session(commands=("ls", "sudo evil"))
    assert store.record(changed) is True

    assert store.record(changed, flagged=True) is True
    assert store.record(changed, flagged=True) is False

    day_files = list((tmp_path / "sessions").glob("*.jsonl"))
    lines = day_files[0].read_text().splitlines()
    assert len(lines) == 3


def test_recent_sessions_queries_sqlite_rows(tmp_path):
    store = SessionStore(
        log_dir=str(tmp_path / "sessions"),
        sqlite_path=str(tmp_path / "sessions.db"),
    )
    for index in range(3):
        store.record(
            _session(session_id=f"ssh:10.0.0.{index + 1}:{index}", username=f"u{index}"),
            threat_score=index,
            flagged=(index == 2),
        )

    rows = store.recent_sessions(limit=2)
    assert [row["username"] for row in rows] == ["u1", "u2"]
    assert rows[-1]["flagged"] is True
    assert rows[-1]["threat_score"] == 2
    assert [entry["command"] for entry in rows[-1]["commands"]] == ["ls", "pwd"]
    assert rows[-1]["mitigation"] == {}


def test_retention_removes_old_archive_files(tmp_path):
    log_dir = tmp_path / "sessions"
    store = SessionStore(
        log_dir=str(log_dir),
        sqlite_path=str(tmp_path / "sessions.db"),
        retention_days=30,
    )
    old_path = log_dir / "2026-01-01.jsonl"
    fresh_path = log_dir / "2026-09-12.jsonl"
    old_path.write_text("{}\n")
    fresh_path.write_text("{}\n")
    expired = time.time() - 90 * 86400
    os.utime(old_path, (expired, expired))

    store._prune_archive()

    assert not old_path.exists()
    assert fresh_path.exists()