import json
import os
import sys
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.notifier import Notifier


class FakeResponse:
    """Stand-in for the urllib response object used as a context manager."""

    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _captured():
    holder = {}

    def fake_urlopen(request, timeout=None):
        holder["url"] = request.full_url
        holder["data"] = json.loads(request.data.decode("utf-8"))
        holder["headers"] = dict(request.header_items())
        return FakeResponse()

    return holder, fake_urlopen


def test_send_posts_json_payload_to_the_topic(monkeypatch):
    holder, fake_urlopen = _captured()
    monkeypatch.setattr("core.notifier.urllib.request.urlopen", fake_urlopen)

    notifier = Notifier(topic="secret-topic", base_url="https://ntfy.example")
    assert notifier.enabled is True
    acknowledged = notifier.send("Alert", "blocked an IP", tags=["warning"])
    assert acknowledged is True
    assert holder["url"] == "https://ntfy.example/secret-topic"
    assert holder["data"]["topic"] == "secret-topic"
    assert holder["data"]["title"] == "Alert"
    assert holder["data"]["message"] == "blocked an IP"
    assert holder["data"]["tags"] == ["warning"]
    assert holder["headers"]["Content-type"] == "application/json"


def test_blank_topic_disables_the_notifier(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("unconfigured notifier must not touch the network")

    monkeypatch.setattr("core.notifier.urllib.request.urlopen", boom)
    notifier = Notifier(topic="   ")
    assert notifier.enabled is False
    assert notifier.send("t", "m") is False


def test_network_failure_returns_false_without_raising(monkeypatch):
    def fail(*args, **kwargs):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("core.notifier.urllib.request.urlopen", fail)
    notifier = Notifier(topic="abc")
    assert notifier.send("t", "m") is False