import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.hardening import Hardening

# A verdict strong enough to justify the destructive lockdown steps.
CONFIRMED = {
    "flagged": True,
    "score": 5,
    "threshold": 1,
    "ml_flagged": True,
    "baseline_flagged": True,
}


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
    outcome = hardening.respond(
        {"username": "bob", "client_address": "10.0.0.9"}, verdict=CONFIRMED
    )

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
    outcome = hardening.respond({"username": "bob"}, verdict=CONFIRMED)
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
    outcome = hardening.respond({"username": "bob"}, verdict=CONFIRMED)
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
    outcome = hardening.respond({"username": "bob"}, verdict=CONFIRMED)

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
    outcome = hardening.respond({"username": "bob"}, verdict=CONFIRMED)

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
    outcome = hardening.respond({"username": "x"}, verdict=CONFIRMED)

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
    outcome = hardening.respond(
        {"username": "bob", "client_address": "10.0.0.9"}, verdict=CONFIRMED
    )
    assert outcome == {
        "password_rotated": False,
        "password_auth_disabled": False,
        "suppressed": False,
    }
    assert notifier.sent == []

class RecordingLogger:
    """Captures audit records so tests can inspect suppression reasons."""

    def __init__(self):
        self.entries = []

    def record(self, event_type, **payload):
        self.entries.append({"event_type": event_type, **payload})
        return True


def _exploding_runner(*args, **kwargs):
    raise AssertionError(
        "no destructive command may run on uncorroborated evidence"
    )


def test_single_weak_signal_does_not_rotate_password():
    """One ordinary command must never destroy a legitimate user's password.

    The default config scores a single `python3` as exactly 1, which meets
    the response threshold, so without corroboration the hardener would
    rotate the password of anyone doing routine work.
    """
    hardening = Hardening(
        notifier=RecordingNotifier(),
        rotate_password=True,
        gpg_recipient="ABC123",
        runner=_exploding_runner,
    )
    weak = {"flagged": True, "score": 1, "threshold": 1, "ml_flagged": False,
            "baseline_flagged": False}

    outcome = hardening.respond({"username": "alice"}, verdict=weak)

    assert outcome["password_rotated"] is False
    assert outcome["suppressed"] is True


def test_single_weak_signal_does_not_disable_password_auth(tmp_path):
    """A host-wide sshd lockdown also waits for corroboration."""
    config = tmp_path / "sshd_config"
    config.write_text("Port 22\nPasswordAuthentication yes\n")
    hardening = Hardening(
        notifier=RecordingNotifier(),
        disable_password_auth=True,
        sshd_config_path=str(config),
        runner=_exploding_runner,
    )
    weak = {"flagged": True, "score": 1, "threshold": 1, "ml_flagged": False,
            "baseline_flagged": False}

    outcome = hardening.respond({"username": "alice"}, verdict=weak)

    assert outcome["password_auth_disabled"] is False
    assert "PasswordAuthentication yes" in config.read_text()


def test_missing_verdict_suppresses_destructive_steps():
    """With no verdict to corroborate, fail closed rather than assume."""
    hardening = Hardening(
        notifier=RecordingNotifier(),
        rotate_password=True,
        gpg_recipient="ABC123",
        runner=_exploding_runner,
    )

    outcome = hardening.respond({"username": "alice"})

    assert outcome["suppressed"] is True
    assert outcome["password_rotated"] is False


def test_strong_rule_score_alone_authorizes_hardening():
    """Sustained suspicious activity is sufficient on its own."""
    hardening = Hardening(notifier=RecordingNotifier(), runner=_exploding_runner)
    strong = {"flagged": True, "score": 3, "threshold": 1, "ml_flagged": False,
              "baseline_flagged": False}

    allowed, reason = hardening.should_harden(strong)

    assert allowed is True
    assert "strong threshold" in reason


def test_two_agreeing_signals_authorize_hardening_despite_low_score():
    """ML plus a learned-baseline outlier is corroboration on its own."""
    hardening = Hardening(notifier=RecordingNotifier(), runner=_exploding_runner)
    agreed = {"flagged": True, "score": 1, "threshold": 1, "ml_flagged": True,
              "baseline_flagged": True}

    allowed, reason = hardening.should_harden(agreed)

    assert allowed is True
    assert "agree" in reason


def test_one_ml_signal_alone_is_not_corroboration():
    """A single ML flag without rule or baseline support is not enough."""
    hardening = Hardening(notifier=RecordingNotifier(), runner=_exploding_runner)
    only_ml = {"flagged": True, "score": 0, "threshold": 1, "ml_flagged": True,
               "baseline_flagged": False}

    allowed, _reason = hardening.should_harden(only_ml)

    assert allowed is False


def test_corroboration_can_be_disabled_explicitly():
    """Operators who accept the risk can opt back into single-signal action."""
    hardening = Hardening(
        notifier=RecordingNotifier(),
        rotate_password=True,
        gpg_recipient="ABC123",
        require_corroboration=False,
        runner=lambda args, **kw: _completed(args, 0, stdout="encrypted"),
    )

    outcome = hardening.respond({"username": "bob"}, verdict=None)

    assert outcome["suppressed"] is False
    assert outcome["password_rotated"] is True


def test_suppression_is_recorded_in_the_audit_trail():
    """A skipped lockdown must be explainable after the fact."""
    logger = RecordingLogger()
    hardening = Hardening(
        notifier=RecordingNotifier(),
        logger=logger,
        rotate_password=True,
        gpg_recipient="ABC123",
        runner=_exploding_runner,
    )
    weak = {"flagged": True, "score": 1, "threshold": 1, "ml_flagged": False,
            "baseline_flagged": False}

    hardening.respond(
        {"username": "alice", "client_address": "203.0.113.9"}, verdict=weak
    )

    suppressed = [
        e for e in logger.entries if e["event_type"] == "hardening_suppressed"
    ]
    assert len(suppressed) == 1
    assert suppressed[0]["username"] == "alice"
    assert suppressed[0]["client_address"] == "203.0.113.9"
    assert "uncorroborated" in suppressed[0]["reason"]
