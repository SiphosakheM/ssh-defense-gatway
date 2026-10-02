"""Live iptables firewall management for the SSH Defense Gateway.

Applies and removes DROP rules on a dedicated iptables chain by shelling
out to the real ``iptables`` binary. Rules live on a custom chain so each
blocked address can be managed independently; when ``hook_input`` is set
the chain is also jumped to from ``INPUT`` so the rules actually filter
live traffic. Without that jump the chain is inert — DROP rules would sit
on a chain nothing ever traverses.
"""

import re
import subprocess
import threading
import time

_RULE_RE = re.compile(r"^\s*DROP\s+all\s+--\s+(?P<source>\S+)\s")
_REFERENCES_RE = re.compile(r"\((?P<count>\d+)\s+references?\)")


class FirewallManager:
    """Apply, inspect, and schedule removal of DROP rules on an iptables chain."""

    def __init__(
        self,
        chain="SSH_DEFENSE_TEST",
        iptables_bin="iptables",
        logger=None,
        state_store=None,
        hook_input=False,
        input_chain="INPUT",
    ):
        self.chain = chain
        self.iptables_bin = iptables_bin
        self._logger = logger
        self._state_store = state_store
        self.hook_input = hook_input
        self.input_chain = input_chain

    def _run(self, *args):
        return subprocess.run(
            [self.iptables_bin, *args],
            capture_output=True,
            text=True,
        )

    def ensure_chain(self):
        """Create the custom chain and, when hooked, jump to it from INPUT.

        The ``INPUT`` jump is what makes the DROP rules effective; it is
        inserted idempotently (only once) and is created only when
        ``hook_input`` is enabled so unit tests can exercise the chain
        without mutating the live packet path.
        """
        result = self._run("-L", self.chain, "-n")
        if result.returncode != 0:
            create = self._run("-N", self.chain)
            if create.returncode != 0:
                raise RuntimeError(create.stderr.strip())
        if self.hook_input:
            self.ensure_input_hook()

    def ensure_input_hook(self):
        """Insert the jump from INPUT into the custom chain, once.

        Uses ``iptables -C`` to detect an existing jump so repeated
        daemon starts do not stack duplicate rules.
        """
        if self._run("-C", self.input_chain, "-j", self.chain).returncode == 0:
            return False
        result = self._run("-I", self.input_chain, "1", "-j", self.chain)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        return True

    def remove_input_hook(self):
        """Delete the INPUT jump, if present. Returns True when removed."""
        return self._run("-D", self.input_chain, "-j", self.chain).returncode == 0

    def input_hook_exists(self):
        """True when INPUT currently jumps to the custom chain."""
        check = self._run("-C", self.input_chain, "-j", self.chain)
        return check.returncode == 0

    def chain_references(self):
        """How many rules point at this chain (0 means it is inert).

        ``iptables -L`` prints the reference count in the chain header,
        which is the cheapest reliable proof that the chain is wired
        into the live packet path rather than floating unused.
        """
        result = self._run("-L", self.chain, "-n")
        if result.returncode != 0:
            return 0
        for line in result.stdout.splitlines():
            if line.startswith("Chain"):
                match = _REFERENCES_RE.search(line)
                if match:
                    return int(match.group("count"))
        return 0

    def flush_chain(self):
        """Remove all rules from the custom chain."""
        self._run("-F", self.chain)

    def drop_chain(self):
        """Unhook, flush, and delete the custom chain.

        The INPUT jump is removed first — ``iptables -X`` refuses to
        delete a chain that is still referenced, so leaving it would
        strand both the jump and the chain on the host.
        """
        self.remove_input_hook()
        self.flush_chain()
        self._run("-X", self.chain)

    def apply_block(self, ip, duration_seconds=None):
        """Insert a DROP rule for the source IP at the top of the chain.

        ``duration_seconds``, when given, records an expiry deadline in
        the persistent state store so the block survives restarts.
        """
        result = self._run("-I", self.chain, "1", "-s", ip, "-j", "DROP")
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        if self._logger is not None:
            self._logger.record(
                "block",
                ip=ip,
                chain=self.chain,
            )
        if self._state_store is not None:
            expires_at = (
                None
                if duration_seconds is None
                else time.time() + duration_seconds
            )
            self._state_store.record_block(ip, expires_at=expires_at)

    def remove_block(self, ip):
        """Delete the DROP rule for the source IP from the chain."""
        result = self._run("-D", self.chain, "-s", ip, "-j", "DROP")
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        if self._logger is not None:
            self._logger.record(
                "unblock",
                ip=ip,
                chain=self.chain,
            )
        if self._state_store is not None:
            self._state_store.record_unblock(ip)

    def rule_exists(self, ip):
        """Return True if a DROP rule for the IP is listed on the chain.

        Inspected via ``iptables -L`` output.
        """
        result = self._run("-L", self.chain, "-n")
        if result.returncode != 0:
            return False
        for line in result.stdout.splitlines():
            match = _RULE_RE.search(line)
            if match and match.group("source") == ip:
                return True
        return False

    def schedule_block_removal(self, ip, duration_seconds):
        """Remove the block rule in the background after the given duration."""
        timer = threading.Timer(
            duration_seconds,
            self.remove_block,
            args=(ip,),
        )
        timer.daemon = True
        timer.start()
        return timer