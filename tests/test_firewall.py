import os
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.firewall import FirewallManager

CHAIN = "SSH_DEFENSE_TEST"
TEST_IP = "203.0.113.7"


@pytest.fixture
def firewall():
    """Provide a real iptables chain, skipping when root is unavailable."""
    fw = FirewallManager(chain=CHAIN)
    try:
        fw.ensure_chain()
    except RuntimeError as exc:
        pytest.skip(f"iptables not usable (requires root): {exc}")
    yield fw
    fw.drop_chain()


def test_apply_block_inserts_drop_rule_viewable_with_iptables_l(firewall):
    """A DROP rule for the flagged IP appears on the custom chain."""
    firewall.apply_block(TEST_IP)

    proc = subprocess.run(
        [firewall.iptables_bin, "-L", CHAIN, "-n"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert TEST_IP in proc.stdout


def test_block_rule_is_auto_removed_by_background_timer(firewall):
    """The DROP rule expires on its own after the configured duration."""
    firewall.apply_block(TEST_IP)
    assert firewall.rule_exists(TEST_IP) is True

    firewall.schedule_block_removal(TEST_IP, duration_seconds=1)

    deadline = time.monotonic() + 10
    while firewall.rule_exists(TEST_IP) and time.monotonic() < deadline:
        time.sleep(0.05)

    assert firewall.rule_exists(TEST_IP) is False