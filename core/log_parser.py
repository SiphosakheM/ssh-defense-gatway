"""Log parsing utilities for the SSH Defense Gateway.

Parses authentication log lines and tails live log files.
"""

import os
import re
import time

_FAILURE_PATTERNS = [
    re.compile(
        r"Failed password for (?:invalid user )?(?P<username>\S+) from "
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port"
    ),
    re.compile(
        r"Connection closed by authenticating user (?P<username>\S+) "
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port"
    ),
]


def parse_failure(line):
    """Parse an SSH authentication log line.

    Returns a dict with ``username`` and ``ip`` keys, or None if the line
    is not a recognized failure event.
    """
    for pattern in _FAILURE_PATTERNS:
        match = pattern.search(line)
        if match:
            return {
                "username": match.group("username"),
                "ip": match.group("ip"),
            }
    return None


def tail_log(path):
    """Yield new lines appended to a log file, one at a time.

    Reads any existing content up front, then continuously watches the
    file for newly appended lines.
    """
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
            else:
                time.sleep(0.1)
