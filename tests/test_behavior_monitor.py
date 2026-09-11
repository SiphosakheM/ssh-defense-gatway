import getpass
import json
import os
import signal
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ai.behavior_monitor import BehaviorMonitor

CLIENT_IP = "10.0.0.55"


@pytest.fixture
def live_shell():
    """Spawn a real SSH-tagged shell that the monitor should capture."""
    env = dict(os.environ)
    env["SSH_CONNECTION"] = f"{CLIENT_IP} 51234 127.0.0.1 22"
    process = subprocess.Popen(
        ["bash", "-c", "sleep 120 & wait"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    yield process
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _telemetry_with_shell(monitor, process, deadline=10):
    """Poll telemetry until the tagged test shell shows up, then return it."""
    start = time.monotonic()
    while time.monotonic() - start < deadline:
        telemetry = monitor.collect()
        for session in telemetry["sessions"]:
            if session["client_address"] == CLIENT_IP:
                return telemetry, session
        time.sleep(0.1)
    raise AssertionError("telemetry did not capture the live shell")


def test_spawned_shell_and_command_captured_as_json_telemetry(live_shell):
    """The live shell and its children surface as JSON-serializable telemetry."""
    monitor = BehaviorMonitor()
    telemetry, session = _telemetry_with_shell(monitor, live_shell)

    assert session["username"] == getpass.getuser()
    commands = [p["command"] for p in session["processes"]]
    assert any("bash" in command for command in commands)
    assert any("sleep 120" in command for command in commands)

    parsed = json.loads(json.dumps(telemetry, sort_keys=True))
    assert set(parsed) == {"collected_at", "sessions"}
    assert set(parsed["sessions"][0]) == {
        "session_id",
        "username",
        "client_address",
        "processes",
        "command_history",
    }
    assert all(
        set(process) == {"pid", "ppid", "command"}
        for process in parsed["sessions"][0]["processes"]
    )
    assert all(
        set(entry) == {"pid", "command", "observed_at"}
        for entry in parsed["sessions"][0]["command_history"]
    )


def test_session_disappears_from_telemetry_after_termination(live_shell):
    """A killed session stops appearing in subsequent telemetry snapshots."""
    monitor = BehaviorMonitor()
    _telemetry_with_shell(monitor, live_shell)

    os.killpg(live_shell.pid, signal.SIGKILL)
    live_shell.wait()

    gone = False
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        telemetry = monitor.collect()
        if not any(
            session["client_address"] == CLIENT_IP
            for session in telemetry["sessions"]
        ):
            gone = True
            break
        time.sleep(0.1)
    assert gone is True