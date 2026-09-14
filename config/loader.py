"""Configuration loader for the SSH Defense Gateway.

Loads and validates the YAML configuration file into a dict of
default protection thresholds and suspicious commands.
"""

import os

import yaml

EXPECTED_KEYS = {
    "max_attempts",
    "time_window_seconds",
    "block_duration_minutes",
    "suspicious_commands",
    "whitelist_ips",
}


def load_config(path="config/config.yaml"):
    """Load a YAML config file and validate its required keys.

    Raises FileNotFoundError if the file does not exist and raises a
    ValueError if any of the expected configuration keys are missing.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(path, "r") as f:
        config = yaml.safe_load(f)

    missing = EXPECTED_KEYS - set(config.keys())
    if missing:
        raise ValueError(
            f"Configuration file {path} is missing required keys: "
            f"{sorted(missing)}"
        )

    return config
