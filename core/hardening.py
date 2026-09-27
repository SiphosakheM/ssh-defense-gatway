"""Automated post-threat hardening for the SSH Defense Gateway.

When the behavioral scanner confirms a suspicious login, the gateway does
more than drop the source IP: it also tightens the door the intruder came
through. The enabled steps are:

- Rotate the compromised account's password to a fresh, cryptographically
  random value via ``chpasswd``, so the attacker's stolen credential
  stops working immediately. The replacement is encrypted with the
  operator's GPG public key and only then pushed to their phone, so the
  new secret never crosses the messenger in plaintext.
- Disable password authentication in ``sshd_config`` and reload the
  daemon, so password-based break-ins are impossible until an admin
  re-enables them (key-only login keeps the legitimate user working).

Every step is rooted: writing a password or touching sshd requires root,
and each action degrades gracefully (logs, notifies, and moves on) so one
failed tool never blocks the others.
"""

import secrets
import subprocess

SSHD_RELOAD_COMMANDS = (
    ("systemctl", "reload", "sshd"),
    ("service", "ssh", "reload"),
    ("systemctl", "reload", "ssh"),
)


class Hardening:
    """Execute the configured lockdown steps for one flagged session."""

    def __init__(
        self,
        notifier=None,
        logger=None,
        rotate_password=False,
        gpg_recipient="",
        disable_password_auth=False,
        sshd_config_path="/etc/ssh/sshd_config",
        runner=None,
    ):
        self._notifier = notifier
        self._logger = logger
        self._rotate_password = rotate_password
        self._gpg_recipient = (gpg_recipient or "").strip()
        self._disable_password_auth = disable_password_auth
        self._sshd_config_path = sshd_config_path
        self._run = runner or (lambda args, **kw: subprocess.run(args, **kw))

    def _record(self, event_type, **payload):
        """Mirror a hardening action into the audit trail when one exists."""
        if self._logger is not None:
            self._logger.record(event_type, **payload)

    def _generate_password(self):
        """A fresh, strong, URL-safe random password for the account."""
        return secrets.token_urlsafe(18)

    def _set_account_password(self, username, password):
        """Apply the new password through chpasswd's stdin pipe."""
        result = self._run(
            ["chpasswd"],
            input=f"{username}:{password}\n",
            text=True,
            capture_output=True,
        )
        return result.returncode == 0

    def _encrypt_password(self, password):
        """GPG-encrypt the password to the operator's key, armored on stdout."""
        result = self._run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--armor",
                "--encrypt",
                "--recipient",
                self._gpg_recipient,
            ],
            input=password,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            self._record(
                "password_encrypt_failed",
                reason=result.stderr.strip() or "gpg exited non-zero",
            )
            return None
        return result.stdout.strip()

    def rotate_user_password(self, username):
        """Rotate one account's password and push the encrypted replacement.

        The flow is: generate -> set via chpasswd -> encrypt to the GPG
        recipient -> push the armored blob to the phone. Encryption or
        notification trouble never rolls back a successful rotation, so
        the attacker is still locked out even when the phone push fails.
        Returns True when the account password was changed.
        """
        if not self._rotate_password:
            return False
        if not self._gpg_recipient:
            self._record(
                "password_rotate_skipped",
                username=username,
                reason="gpg_recipient not configured",
            )
            return False

        password = self._generate_password()
        if not self._set_account_password(username, password):
            self._record(
                "password_rotate_failed",
                username=username,
                reason="chpasswd rejected the change",
            )
            return False

        self._record("password_rotated", username=username)
        encrypted = self._encrypt_password(password)
        if encrypted:
            self._notifier.send(
                "SSH account password rotated",
                f"Compromised account '{username}' now uses a new password.\n\n"
                f"Decrypt it with your GPG private key:\n\n{encrypted}",
                tags=["warning", "key"],
            )
        else:
            # The rotation succeeded but we could not safely transmit the
            # secret, so warn the operator without leaking the plaintext.
            self._notifier.send(
                "SSH account password rotated",
                f"Password for '{username}' was rotated, but it could not be "
                "encrypted for delivery. Reset it manually with: "
                "sudo passwd <user>",
                tags=["warning"],
            )
        return True

    def disable_password_authentication(self):
        """Flip PasswordAuthentication off in sshd_config and reload sshd.

        Writes the config atomically and reloads (never restarts) the SSH
        daemon so open sessions survive. Returns True when the config is
        updated and sshd picked it up.
        """
        if not self._disable_password_auth:
            return False
        try:
            with open(self._sshd_config_path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except OSError as exc:
            self._record(
                "sshd_hardening_failed",
                reason=f"cannot read config: {exc}",
            )
            return False

        updated = self._rewrite_sshd_config(lines)
        if not updated:
            self._record("sshd_hardening_failed", reason="cannot write config")
            return False
        if not self._reload_sshd():
            self._record(
                "sshd_hardening_failed",
                reason="config updated but sshd reload failed",
            )
            return False
        self._record("sshd_password_auth_disabled", path=self._sshd_config_path)
        return True

    def _rewrite_sshd_config(self, lines):
        """Return a new config with PasswordAuthentication forced to 'no'."""
        rewritten = []
        found_password_line = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("PasswordAuthentication"):
                found_password_line = True
                if stripped == "PasswordAuthentication yes":
                    rewritten.append(
                        "PasswordAuthentication no  # hardened by ssh-gateway"
                    )
                else:
                    rewritten.append(line)
            else:
                rewritten.append(line)
        if not found_password_line:
            rewritten.append(
                "PasswordAuthentication no  # hardened by ssh-gateway"
            )
        return self._atomic_write(rewritten)

    def _atomic_write(self, lines):
        """Swap the config file for a temp copy so a crash can't corrupt it."""
        try:
            tmp_path = f"{self._sshd_config_path}.tmp-gateway"
            with open(tmp_path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
                handle.flush()
            import os

            os.replace(tmp_path, self._sshd_config_path)
            return True
        except OSError:
            return False

    def _reload_sshd(self):
        """Ask the service manager to reload sshd; true if anything accepted."""
        for command in SSHD_RELOAD_COMMANDS:
            result = self._run(list(command), capture_output=True, text=True)
            if result.returncode == 0:
                return True
        return False

    def respond(self, session):
        """Run every enabled hardening step and summarize the outcome.

        ``session`` must include a ``username`` for password rotation.
        Returns a dict mapping each step name to whether it happened, so
        callers can audit the response path.
        """
        username = session.get("username")
        return {
            "password_rotated": bool(
                username and self.rotate_user_password(username)
            ),
            "password_auth_disabled": self.disable_password_authentication(),
        }