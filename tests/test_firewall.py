import os
import socket
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


@pytest.fixture
def hooked_firewall():
    """A real chain wired into INPUT, as the production daemon configures it."""
    fw = FirewallManager(chain=CHAIN, hook_input=True)
    try:
        fw.ensure_chain()
    except RuntimeError as exc:
        pytest.skip(f"iptables not usable (requires root): {exc}")
    yield fw
    fw.drop_chain()


# --- Fake iptables -------------------------------------------------------
# A stateful stand-in so the rule-emission logic can be asserted without
# root. It models chain existence, the INPUT jump, and DROP rules.

_FAKE_IPTABLES = r'''#!/usr/bin/env python3
import json, os, sys

STATE = os.environ["FAKE_IPTABLES_STATE"]
ARGS = sys.argv[1:]


def load():
    try:
        with open(STATE) as handle:
            return json.load(handle)
    except (FileNotFoundError, ValueError):
        return {"chains": {}, "hooks": {}}


def save(state):
    with open(STATE, "w") as handle:
        json.dump(state, handle)


def main():
    state = load()
    flag = ARGS[0]

    if flag == "-L":
        chain = ARGS[1]
        if chain not in state["chains"]:
            print("No chain/target/match by that name.", file=sys.stderr)
            return 1
        refs = len(state["hooks"].get(chain, []))
        noun = "reference" if refs == 1 else "references"
        print("Chain %s (%d %s)" % (chain, refs, noun))
        print("target     prot opt source               destination")
        for rule in state["chains"][chain]:
            print("%s" % rule)
        return 0

    if flag == "-N":
        state["chains"].setdefault(ARGS[1], [])
        save(state)
        return 0

    if flag == "-C":
        chain, target = ARGS[1], ARGS[-1]
        if target in state["hooks"].get(chain, []):
            return 0
        return 1

    if flag == "-I":
        chain = ARGS[1]
        target = ARGS[-1]
        if target in state["chains"]:
            # A jump to another chain, e.g. "-I INPUT 1 -j SSH_DEFENSE".
            state["hooks"].setdefault(chain, []).insert(0, target)
        elif "-s" in ARGS:
            # A source-matched rule, e.g. "-I CHAIN 1 -s 1.2.3.4 -j DROP".
            source = ARGS[ARGS.index("-s") + 1]
            state["chains"][chain].insert(0, "DROP all -- %s 0.0.0.0/0" % source)
        else:
            state["chains"][chain].insert(0, " ".join(ARGS[2:]))
        save(state)
        return 0

    if flag == "-D":
        chain, target = ARGS[1], ARGS[-1]
        if target in state["hooks"].get(chain, []):
            state["hooks"][chain].remove(target)
            if not state["hooks"][chain]:
                del state["hooks"][chain]
            save(state)
            return 0
        if "-s" in ARGS:
            source = ARGS[ARGS.index("-s") + 1]
            wanted = "DROP all -- %s 0.0.0.0/0" % source
            if wanted in state["chains"].get(chain, []):
                state["chains"][chain].remove(wanted)
                save(state)
                return 0
        return 1

    if flag == "-X":
        if ARGS[1] in state["chains"]:
            del state["chains"][ARGS[1]]
            save(state)
            return 0
        return 1

    if flag == "-F":
        state["chains"][ARGS[1]] = []
        save(state)
        return 0

    return 0


sys.exit(main())
'''


@pytest.fixture
def fake_iptables(tmp_path, monkeypatch):
    """A stateful fake ``iptables`` binary plus a call log."""
    script = tmp_path / "fake-iptables"
    script.write_text(_FAKE_IPTABLES)
    script.chmod(0o755)
    state_path = tmp_path / "state.json"
    log_path = tmp_path / "calls.log"
    monkeypatch.setenv("FAKE_IPTABLES_STATE", str(state_path))

    real_run = subprocess.run

    def logging_run(args, **kwargs):
        if args and args[0] == str(script):
            with open(log_path, "a") as handle:
                handle.write(" ".join(args[1:]) + "\n")
            return real_run(args, **kwargs)
        return real_run(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", logging_run)
    return script, log_path


def test_ensure_chain_inserts_input_jump(fake_iptables):
    """Hooked chains are jumped to from INPUT, which is what makes them work."""
    script, log = fake_iptables
    fw = FirewallManager(
        chain=CHAIN, iptables_bin=str(script), hook_input=True
    )

    fw.ensure_chain()

    calls = log.read_text().splitlines()
    assert "-N SSH_DEFENSE_TEST" in calls
    assert "-I INPUT 1 -j SSH_DEFENSE_TEST" in calls


def test_ensure_chain_is_idempotent(fake_iptables):
    """Repeated daemon starts must not stack duplicate INPUT jumps."""
    script, log = fake_iptables
    fw = FirewallManager(
        chain=CHAIN, iptables_bin=str(script), hook_input=True
    )

    fw.ensure_chain()
    fw.ensure_chain()
    fw.ensure_chain()

    jumps = [
        line
        for line in log.read_text().splitlines()
        if line.startswith("-I INPUT")
    ]
    assert len(jumps) == 1
    assert fw.input_hook_exists() is True


def test_ensure_chain_without_hook_leaves_input_untouched(fake_iptables):
    """Unhooked managers never mutate the live packet path."""
    script, log = fake_iptables
    fw = FirewallManager(chain=CHAIN, iptables_bin=str(script))

    fw.ensure_chain()

    calls = log.read_text().splitlines()
    assert "-N SSH_DEFENSE_TEST" in calls
    assert not [line for line in calls if line.startswith(("-I INPUT", "-C INPUT"))]
    assert fw.input_hook_exists() is False


def test_drop_chain_unhooks_before_deleting(fake_iptables):
    """Teardown removes the INPUT jump, otherwise -X would leave both behind."""
    script, log = fake_iptables
    fw = FirewallManager(
        chain=CHAIN, iptables_bin=str(script), hook_input=True
    )
    fw.ensure_chain()

    log.write_text("")
    fw.drop_chain()

    calls = log.read_text().splitlines()
    delete_jump = calls.index("-D INPUT -j SSH_DEFENSE_TEST")
    delete_chain = calls.index("-X SSH_DEFENSE_TEST")
    assert delete_jump < delete_chain
    assert fw.input_hook_exists() is False


def test_block_rules_still_land_on_the_chain(fake_iptables):
    """A blocked address gets a DROP rule on the hooked chain."""
    script, _ = fake_iptables
    fw = FirewallManager(
        chain=CHAIN, iptables_bin=str(script), hook_input=True
    )
    fw.ensure_chain()

    fw.apply_block(TEST_IP)

    assert fw.rule_exists(TEST_IP) is True


# --- Real iptables (root) -------------------------------------------------


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


def test_chain_is_referenced_from_input_when_hooked(hooked_firewall):
    """iptables reports a reference count proving the chain is live."""
    assert hooked_firewall.input_hook_exists() is True
    assert hooked_firewall.chain_references() >= 1


def test_unhooked_chain_reports_no_references(firewall):
    """An unhooked chain is inert — the bug this suite exists to prevent."""
    assert firewall.chain_references() == 0


def _loopback_connect(port, timeout=2):
    """Try to reach a local listener; return True if the connect succeeded.

    Loopback traffic traverses INPUT, so a DROP rule on the hooked chain
    makes this time out exactly as a blocked remote host would.
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(("127.0.0.1", port))
        return True
    except socket.timeout:
        return False
    except OSError:
        return False
    finally:
        client.close()


def test_blocked_source_traffic_is_actually_dropped(hooked_firewall):
    """End-to-end proof that a DROP rule on the chain stops real traffic.

    This is the regression test for the original defect: the chain was
    created but never jumped to from INPUT, so every block was inert and
    real connections still succeeded. Asserting only that the rule exists
    cannot catch that, so this drives an actual TCP connection.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]

        # Control: unblocked traffic must reach the listener, otherwise a
        # pass below would prove nothing.
        assert _loopback_connect(port) is True, "control connect failed; test invalid"

        hooked_firewall.apply_block("127.0.0.1")
        assert hooked_firewall.rule_exists("127.0.0.1") is True

        assert _loopback_connect(port) is False, (
            "blocked traffic still reached the host — the chain is inert"
        )
    finally:
        listener.close()


def test_removing_the_block_restores_connectivity(hooked_firewall):
    """Unblocking an address lets traffic through again."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]

        hooked_firewall.apply_block("127.0.0.1")
        assert _loopback_connect(port) is False

        hooked_firewall.remove_block("127.0.0.1")
        assert _loopback_connect(port) is True
    finally:
        listener.close()
