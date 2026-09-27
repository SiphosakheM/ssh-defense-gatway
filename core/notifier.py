"""Phone push notifications for the SSH Defense Gateway.

Alerts reach the operator's phone through ntfy.sh's free pub/sub push
service: a single HTTP POST to a chosen topic delivers a notification to
every device subscribed to it. The topic string is effectively the access
token — it should be long and unguessable, and anyone who knows it can
read the warnings, so it is kept in the daemon config file rather than in
code.

Notification pushes are best-effort by design: a reachable phone is a
nice-to-have, but a notification outage must never take down the defense
loop, so network failures are swallowed and only recorded through the
optional audit logger.
"""

import json
import urllib.error
import urllib.request

DEFAULT_NTFY_URL = "https://ntfy.sh"


class Notifier:
    """Send one-off push notifications through the ntfy.sh webhook."""

    def __init__(
        self,
        topic=None,
        base_url=DEFAULT_NTFY_URL,
        priority="default",
        logger=None,
        enabled=True,
    ):
        self._topic = (topic or "").strip()
        self._base_url = (base_url or DEFAULT_NTFY_URL).rstrip("/")
        self._priority = priority
        self._logger = logger
        self._enabled = bool(enabled and self._topic)

    @property
    def enabled(self):
        """True when a topic is configured and pushes are switched on."""
        return self._enabled

    def _record(self, event_type, **payload):
        """Mirror a push attempt into the audit trail when one exists."""
        if self._logger is not None:
            self._logger.record(event_type, **payload)

    def send(self, title, message, tags=None):
        """Push ``title``/``message`` to the configured topic.

        Returns True when the server acknowledged the push. When the
        notifier is unconfigured or the network fails, returns False and
        records the reason through the audit logger instead of raising.
        """
        if not self._enabled:
            self._record("notify_skipped", title=title, reason="not configured")
            return False
        payload = {
            "topic": self._topic,
            "title": title,
            "message": message,
            "priority": self._priority,
        }
        if tags:
            payload["tags"] = tags
        request = urllib.request.Request(
            f"{self._base_url}/{self._topic}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                acknowledged = response.status < 400
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self._record("notify_failed", title=title, reason=str(exc))
            return False
        self._record(
            "notify",
            title=title,
            topic=self._topic,
            acknowledged=acknowledged,
        )
        return acknowledged