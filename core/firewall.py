"""Live iptables firewall management for the SSH Defense Gateway.

Applies and removes DROP rules on a dedicated iptables chain by shelling
out to the real ``iptables`` binary. Rules live on a custom chain so the
manager can exercise actual network behaviour without touching the live
``INPUT``/``OUTPUT`` packet flow.
"""

import re
import subprocess
import threading

_RULE_RE = re.compile(r"^\s*DROP\s+all\s+--\s+(?P<source>\S+)\s")


class FirewallManager:
    """Apply, inspect, and schedule removal of DROP rules on an iptables chain."""

    def __init__(self, chain="SSH_DEFENSE_TEST", iptables_bin="iptables"):
        self.chain = chain
        self.iptables_bin = iptables_bin

    def _run(self, *args):
        return subprocess.run(
            [self.iptables_bin, *args],
            capture_output=True,
            text=True,
        )

    def ensure_chain(self):
        """Create the custom chain if it does not exist yet."""
        result = self._run("-L", self.chain, "-n")
        if result.returncode == 0:
            return
        create = self._run("-N", self.chain)
        if create.returncode != 0:
            raise RuntimeError(create.stderr.strip())

    def flush_chain(self):
        """Remove all rules from the custom chain."""
        self._run("-F", self.chain)

    def drop_chain(self):
        """Flush and delete the custom chain."""
        self.flush_chain()
        self._run("-X", self.chain)

    def apply_block(self, ip):
        """Insert a DROP rule for the source IP at the top of the chain."""
        result = self._run("-I", self.chain, "1", "-s", ip, "-j", "DROP")
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())

    def remove_block(self, ip):
        """Delete the DROP rule for the source IP from the chain."""
        result = self._run("-D", self.chain, "-s", ip, "-j", "DROP")
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())

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