import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.hardening import Hardening


class RecordingNotifier:
    """Captures pushes so tests can inspect what would reach the phone."""

    def __init__(self):
        self.sent = []

    def send(self, title, message, tags=None):
        self.sent.append({"title": title, "message": message, "tags": tags})
        return True


def _completed(args, returncode, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args, returncode, stdout=stdout, stderr=stderr
    )


def test_rotate_password_sets_new_password_and_sends_armored_blob(monkeypatch):
    monkeypatch.setattr(
        "core.hardening.secrets.token_urlsafe", lambda n: "S3cureTestPass!"
    )
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[0] == "chpasswd":
            return _completed(args, 0)
        return _completed(
            args,
            0,
            stdout="-----BEGIN PGP MESSAGE-----\nabc123\n-----END PGP MESSAGE-----\n",
        )

    notifier = RecordingNotifier()
    hardening = Hardening(
        notifier=notifier,
        rotate_password=True,
        gpg_recipient="ABC123DEF",
        runner=fake_run,
    )
    outcome = hardening.respond({"username": "bob", "client_address": "10.0.0.9"})

    assert outcome["password_rotated"] is True
    chpasswd_calls = [call for call in calls if call[0][0] == "chpasswd"]
    assert len(chpasswd_calls) == 1
    assert chpasswd_calls[0][1]["input"] == "bob:S3cureTestPass!\n"

    gpg_calls = [call for call in calls if call[0][0] == "gpg"]
    assert gpg_calls[0][0][-1] == "ABC123DEF"
    assert gpg_calls[0][1]["input"] == "S3cureTestPass!"

    assert len(notifier.sent) == 1
    assert "BEGIN PGP MESSAGE" in notifier.sent[0]["message"]
    assert "S3cureTestPass!" not in notifier.sent[0]["message"]


def test_rotate_is_skipped_without_a_gpg_recipient():
    def boom(*args, **kwargs):
        raise AssertionError("no system command may run without a recipient")

    notifier = RecordingNotifier()
    hardening = Hardening(
        notifier=notifier,
        rotate_password=True,
        gpg_recipient="",
        runner=boom,
    )
    outcome = hardening.respond({"username": "bob"})
    assert outcome["password_rotated"] is False
    assert notifier.sent == []


def test_rotate_stops_when_chpasswd_rejects_the_change():
    def fake_run(args, **kwargs):
        if args[0] == "chpasswd":
            return _completed(args, 1, stderr="Permission denied")
        raise AssertionError("gpg must never run after a failed chpasswd")

    notifier = RecordingNotifier()
    hardening = Hardening(
        notifier=notifier,
        rotate_password=True,
        gpg_recipient="ABCD",
        runner=fake_run,
    )
    outcome = hardening.respond({"username": "bob"})
    assert outcome["password_rotated"] is False
    assert notifier.sent == []


def test_rotation_without_encryption_warns_instead_of_leaking(monkeypatch):
    monkeypatch.setattr(
        "core.hardening.secrets.token_urlsafe", lambda n: "S3cureTestPass!"
    )

    def fake_run(args, **kwargs):
        if args[0] == "chpasswd":
            return _completed(args, 0)
        return _completed(args, 2, stderr="no usable public key")

    notifier = RecordingNotifier()
    hardening = Hardening(
        notifier=notifier,
        rotate_password=True,
        gpg_recipient="ABCD",
        runner=fake_run,
    )
    outcome = hardening.respond({"username": "bob"})

    assert outcome["password_rotated"] is True
    assert len(notifier.sent) == 1
    assert "BEGIN PGP MESSAGE" not in notifier.sent[0]["message"]
    assert "S3cureTestPass!" not in notifier.sent[0]["message"]


def test_disable_password_auth_tightens_sshd_config(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("Port 22\nPasswordAuthentication yes\n")
    calls = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        return _completed(args, 0)

    hardening = Hardening(
        disable_password_auth=True,
        sshd_config_path=str(config),
        runner=fake_run,
    )
    outcome = hardening.respond({"username": "bob"})

    assert outcome["password_auth_disabled"] is True
    text = config.read_text()
    assert "PasswordAuthentication no" in text
    assert "PasswordAuthentication yes" not in text
    assert ["systemctl", "reload", "sshd"] in calls


def test_disable_password_auth_preserves_other_config_lines(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("Port 2222\nPermitRootLogin no\nPasswordAuthentication no\n")

    def fake_run(args, **kwargs):
        return _completed(args, 0)

    hardening = Hardening(
        disable_password_auth=True,
        sshd_config_path=str(config),
        runner=fake_run,
    )
    outcome = hardening.respond({"username": "x"})

    assert outcome["password_auth_disabled"] is True
    text = config.read_text()
    assert "Port 2222" in text
    assert "PermitRootLogin no" in text
    assert text.count("PasswordAuthentication no") == 1


def test_hardening_is_a_noop_when_nothing_is_enabled():
    notifier = RecordingNotifier()

    def boom(*args, **kwargs):
        raise AssertionError("nothing is enabled, so nothing may run")

    hardening = Hardening(
        notifier=notifier,
        rotate_password=False,
        disable_password_auth=False,
        runner=boom,
    )
    outcome = hardening.respond({"username": "bob", "client_address": "10.0.0.9"})
    assert outcome == {"password_rotated": False, "password_auth_disabled": False}
    assert notifier.sent == []