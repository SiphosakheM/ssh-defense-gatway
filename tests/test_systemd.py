import os
import shutil
import subprocess
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PYTHON = os.path.join(REPO_ROOT, ".venv", "bin", "python")
TEST_IP = "203.0.113.77"


def _failure_line(ip):
    return (
        "Mar  1 10:00:01 hostname sshd[1234]: Failed password for invalid user "
        f"root from {ip} port 22 ssh2"
    )


def _user_systemd_ready():
    """True when a user-level systemd manager is actually running."""
    if shutil.which("systemctl") is None:
        return False
    xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return os.path.exists(os.path.join(xdg, "systemd", "private"))


def _systemctl(*args):
    env = dict(os.environ)
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return subprocess.run(
        ["systemctl", "--user", *args],
        env=env,
        capture_output=True,
        text=True,
    )


def _is_active(unit_name):
    proc = _systemctl("is-active", unit_name)
    return proc.stdout.strip() == "active"


def _uninstall_unit(unit_name):
    """Remove a linked user unit by name (idempotent)."""
    _systemctl("stop", unit_name)
    _systemctl("disable", unit_name)
    config_home = os.environ.get(
        "XDG_CONFIG_HOME", os.path.join(os.path.expanduser("~"), ".config")
    )
    link_path = os.path.join(config_home, "systemd", "user", unit_name)
    if os.path.lexists(link_path):
        os.unlink(link_path)
    _systemctl("daemon-reload")


@pytest.fixture
def service(tmp_path):
    """Register, start, and tear down a live user-level gateway unit."""
    if not _user_systemd_ready():
        pytest.skip("user-level systemd is not available")

    # A unique unit name per run prevents systemd from serving a stale
    # loaded definition that still points at a deleted temporary directory.
    unit_name = f"ssh-gateway-test-{str(uuid.uuid4())[:8]}.service"

    auth_log = tmp_path / "auth.log"
    auth_log.write_text("")
    config = tmp_path / "config.yaml"
    config.write_text(
        "max_attempts: 2\n"
        "time_window_seconds: 300\n"
        "block_duration_minutes: 15\n"
        "suspicious_commands: []\n"
        "whitelist_ips: []\n"
    )
    audit_log = tmp_path / "audit.log"
    state_path = tmp_path / "defense_state.json"

    shim = tmp_path / "iptables"
    shim.write_text('#!/bin/bash\necho "$@" >> "$SHIM_LOG"\nexit 0\n')
    shim.chmod(0o755)
    shim_log = tmp_path / "iptables.log"
    shim_log.write_text("")

    unit = tmp_path / unit_name
    unit.write_text(
        "[Unit]\n"
        "Description=SSH Defense Gateway test\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={REPO_ROOT}\n"
        f"Environment=PATH={shim.parent}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n"
        f"Environment=SHIM_LOG={shim_log}\n"
        f'ExecStart="{PYTHON}" "{REPO_ROOT}/main.py" '
        f"--config {config} --auth-log {auth_log} --chain SSH_DEFENSE_TEST "
        f"--audit-log {audit_log} --state {state_path}\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )

    registered = _systemctl("link", str(unit))
    assert registered.returncode == 0, registered.stderr
    _systemctl("daemon-reload")
    started = _systemctl("start", unit_name)
    assert started.returncode == 0, started.stderr

    yield {
        "auth_log": auth_log,
        "shim_log": shim_log,
        "unit_name": unit_name,
    }

    _uninstall_unit(unit_name)


def test_ssh_gateway_runs_as_background_service(service):
    """The unit starts, stays active, and does real defense work in the background."""
    unit_name = service["unit_name"]
    deadline = time.monotonic() + 15
    while not _is_active(unit_name) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert _is_active(unit_name) is True

    auth_log = service["auth_log"]
    shim_log = service["shim_log"]

    def processed_block():
        return "DROP" in shim_log.read_text()

    line = _failure_line(TEST_IP)
    deadline = time.monotonic() + 15
    while not processed_block() and time.monotonic() < deadline:
        with open(auth_log, "a") as f:
            f.write(line + "\n")
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        time.sleep(0.3)

    shim = shim_log.read_text()
    assert "DROP" in shim
    assert "SSH_DEFENSE_TEST" in shim
    assert _is_active(unit_name) is True