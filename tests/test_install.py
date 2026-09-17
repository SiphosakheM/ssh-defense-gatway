import os
import stat
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
INSTALL_SH = os.path.join(REPO_ROOT, "install.sh")


def _run_install(tmp_path, **overrides):
    """Run install.sh into a throwaway prefix without touching systemd."""
    env = os.environ.copy()
    env.update(
        {
            "INSTALL_ROOT": str(tmp_path / "opt" / "ssh-defense-gateway"),
            "SYSTEMD_DIR": str(tmp_path / "etc" / "systemd" / "system"),
            "SKIP_VENV": "1",
            "SKIP_SYSTEMD": "1",
        }
    )
    env.update(overrides)
    return subprocess.run(
        ["bash", INSTALL_SH],
        env=env,
        capture_output=True,
        text=True,
    )


def test_install_copies_application_tree(tmp_path):
    """The full runtime tree lands under the configured install root."""
    result = _run_install(tmp_path)
    assert result.returncode == 0, result.stderr

    root = tmp_path / "opt" / "ssh-defense-gateway"
    assert (root / "main.py").is_file()
    assert (root / "requirements.txt").is_file()
    assert (root / "core" / "firewall.py").is_file()
    assert (root / "core" / "state_store.py").is_file()
    assert (root / "ai" / "detector.py").is_file()
    assert (root / "config" / "config.yaml").is_file()
    assert (root / "logs").is_dir()


def test_install_renders_service_unit_with_install_root(tmp_path):
    """The unit file lands in SYSTEMD_DIR with the rendered ExecStart."""
    result = _run_install(tmp_path)
    assert result.returncode == 0, result.stderr

    unit = tmp_path / "etc" / "systemd" / "system" / "ssh-gateway.service"
    assert unit.is_file()
    content = unit.read_text()
    root = tmp_path / "opt" / "ssh-defense-gateway"
    assert f"WorkingDirectory={root}" in content
    assert f"ExecStart={root}/.venv/bin/python {root}/main.py" in content
    assert "Restart=on-failure" in content
    assert "WantedBy=multi-user.target" in content
    assert stat.S_IMODE(unit.stat().st_mode) == 0o644


def test_install_sets_sane_permissions_on_tree(tmp_path):
    """Files land world-readable and directories searchable, not executable."""
    result = _run_install(tmp_path)
    assert result.returncode == 0, result.stderr

    root = tmp_path / "opt" / "ssh-defense-gateway"
    assert stat.S_IMODE(root.stat().st_mode) == 0o755
    assert stat.S_IMODE((root / "main.py").stat().st_mode) == 0o644
    assert stat.S_IMODE((root / "core").stat().st_mode) == 0o755


def test_install_rejects_unprivileged_privileged_default():
    """A non-root user must not be allowed to write to /etc/systemd/system."""
    if os.geteuid() == 0:
        pytest.skip("running as root; default install is permitted")
    env = os.environ.copy()
    env.update(
        {
            "INSTALL_ROOT": "/tmp/ssh-defense-unsafe",
            "SKIP_VENV": "1",
            "SKIP_SYSTEMD": "1",
        }
    )
    result = subprocess.run(
        ["bash", INSTALL_SH],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert not os.path.exists("/tmp/ssh-defense-unsafe")