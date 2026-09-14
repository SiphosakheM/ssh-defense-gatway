import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.loader import load_config

EXPECTED_KEYS = {
    "max_attempts",
    "time_window_seconds",
    "block_duration_minutes",
    "suspicious_commands",
    "whitelist_ips",
}


@pytest.fixture
def config_file():
    """Create a temporary YAML config with default protection settings."""
    content = """\
max_attempts: 5
time_window_seconds: 300
block_duration_minutes: 15
suspicious_commands:
  - sudo
  - apt
  - python3
whitelist_ips:
  - 127.0.0.1
  - 192.168.0.0/16
"""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        f.write(content)
    yield path
    os.remove(path)


def test_loader_returns_all_expected_keys(config_file):
    """The loaded config contains every key the daemon depends on."""
    config = load_config(config_file)
    assert EXPECTED_KEYS.issubset(config.keys())


def test_loader_populates_default_thresholds(config_file):
    """Defaults from the sample config survive the load round-trip."""
    config = load_config(config_file)
    assert config["max_attempts"] == 5
    assert config["time_window_seconds"] == 300
    assert config["block_duration_minutes"] == 15
    assert config["suspicious_commands"] == ["sudo", "apt", "python3"]
    assert config["whitelist_ips"] == ["127.0.0.1", "192.168.0.0/16"]


def test_loader_handles_missing_file():
    """A missing config path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_config("/tmp/does_not_exist_xyz.yaml")
