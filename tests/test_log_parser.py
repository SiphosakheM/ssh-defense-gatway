import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.log_parser import parse_failure, tail_log


@pytest.fixture
def auth_log(tmp_path):
    path = tmp_path / "auth.log"
    content = [
        "Mar  1 10:00:01 hostname sshd[1234]: Failed password for invalid user root from 192.168.1.10 port 22 ssh2",
        "Mar  1 10:00:02 hostname sshd[1235]: Failed password for root from 192.168.1.11 port 22 ssh2",
        "Mar  1 10:00:03 hostname sshd[1236]: Connection closed by authenticating user admin 192.168.1.12 port 22 [preauth]",
    ]
    path.write_text("\n".join(content) + "\n")
    yield path
    if path.exists():
        path.unlink()


def test_parse_failure_extracts_ip(auth_log):
    for line in auth_log.read_text().splitlines():
        parsed = parse_failure(line)
        if parsed is None:
            continue
        if "invalid user root" in line:
            assert parsed["ip"] == "192.168.1.10"
            assert parsed["username"] == "root"
        elif "Failed password for root" in line:
            assert parsed["ip"] == "192.168.1.11"
            assert parsed["username"] == "root"


def test_tail_log_yields_live_appended_lines(auth_log):
    gen = tail_log(str(auth_log))
    next(gen)
    with open(auth_log, "a") as f:
        f.write("Mar  1 10:00:04 hostname sshd[1237]: Failed password for user alice from 203.0.113.5 port 22 ssh2\n")
        f.flush()
        os.fsync(f.fileno())
    received = []
    for line in gen:
        if "203.0.113.5" in line:
            received.append(line)
        if received:
            break
    assert any("203.0.113.5" in line for line in received)
