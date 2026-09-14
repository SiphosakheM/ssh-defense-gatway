"""Administrative whitelist and failsafe state for the SSH Defense Gateway.

Determines whether a source IP is exempt from automated defense response,
so an administrator configuring the gateway can never lock their own
machine out during a block or kill.
"""

import ipaddress


class StateManager:
    """Hold the protected-address networks and answer whitelist queries."""

    def __init__(self, whitelist_ips=None):
        self._whitelist = [
            ipaddress.ip_network(entry, strict=False)
            for entry in (whitelist_ips or [])
        ]

    @property
    def whitelist_ips(self):
        """The normalized list of whitelisted networks, for reporting."""
        return [str(network) for network in self._whitelist]

    def is_whitelisted(self, ip):
        """Return True when the IP falls inside any whitelisted network.

        Accepts exact addresses (treated as a ``/32`` host) or any member
        of a configured CIDR subnet. Raises ``ValueError`` for strings
        that are not valid IP addresses at all.
        """
        address = ipaddress.ip_address(str(ip))
        return any(address in network for network in self._whitelist)