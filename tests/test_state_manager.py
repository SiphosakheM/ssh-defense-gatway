import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.state_manager import StateManager


def test_exact_whitelisted_ip_is_admin():
    """A bare IP in the whitelist never counts as a target."""
    state = StateManager(["127.0.0.1", "10.0.0.42"])
    assert state.is_whitelisted("127.0.0.1") is True
    assert state.is_whitelisted("10.0.0.42") is True


def test_cidr_subnet_whitelists_every_member():
    """A whitelisted subnet protects every address inside it."""
    state = StateManager(["10.0.0.0/8", "192.168.0.0/16"])
    assert state.is_whitelisted("10.1.2.3") is True
    assert state.is_whitelisted("192.168.55.9") is True
    assert state.is_whitelisted("10.255.0.1") is True


def test_ip_outside_whitelist_is_not_protected():
    """Unrelated addresses stay eligible for defense responses."""
    state = StateManager(["127.0.0.1", "10.0.0.0/8"])
    assert state.is_whitelisted("203.0.113.9") is False
    assert state.is_whitelisted("198.51.100.7") is False


def test_whitelist_ips_property_exposes_networks():
    """The normalized whitelist is inspectable for reporting."""
    state = StateManager(["127.0.0.1", "192.168.0.0/16"])
    assert set(state.whitelist_ips) == {"127.0.0.1/32", "192.168.0.0/16"}


def test_empty_whitelist_protects_nothing():
    """Without an explicit whitelist no address is exempt."""
    state = StateManager([])
    assert state.is_whitelisted("127.0.0.1") is False


def test_malformed_whitelist_entry_rejected_at_construction():
    """Broken CIDR entries fail fast instead of silently filtering."""
    with pytest.raises(ValueError):
        StateManager(["not-an-ip", "10.0.0.0/8"])