"""Post-login behavioral threat detection for the SSH Defense Gateway.

Scores live sessions against a baseline of suspicious commands and, when
the score crosses the threshold, terminates the session processes for
real and asks the firewall manager to drop the offending source IP.
"""

import os
import signal

DEFAULT_SUSPICIOUS_COMMANDS = ("sudo", "apt", "python3")


class BehaviorDetector:
    """Score live sessions and actively terminate high-risk ones."""

    def __init__(
        self,
        suspicious_commands=None,
        score_threshold=1,
        firewall=None,
    ):
        self._suspicious_commands = set(
            suspicious_commands or DEFAULT_SUSPICIOUS_COMMANDS
        )
        self._score_threshold = score_threshold
        self._firewall = firewall

    def score_process(self, command):
        """Return the number of distinct baseline tokens in a command."""
        return len(set(command.split()) & self._suspicious_commands)

    def score_session(self, session):
        """Return the cumulative threat score across a session's processes."""
        return sum(
            self.score_process(process["command"])
            for process in session.get("processes", [])
            if process.get("command")
        )

    def _terminate(self, pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def respond(self, session):
        """Terminate the session processes and block the source IP."""
        for process in session.get("processes", []):
            self._terminate(process.get("pid"))
        if self._firewall is not None and session.get("client_address"):
            self._firewall.apply_block(session["client_address"])

    def evaluate(self, session):
        """Score a session, triggering the automated response on a spike."""
        score = self.score_session(session)
        if score >= self._score_threshold:
            self.respond(session)
        return score