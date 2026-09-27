# SSH Defense Gateway

A hybrid active defense gateway for SSH that combines real-time dynamic
network blocking for brute-force attacks with AI-driven behavioral monitoring
for post-login zero-trust security.

- **Brute-force defense** tails the SSH authentication log, counts failed
  attempts per source IP over a rolling window, and drops offenders on a
  dedicated `iptables` chain once they cross the threshold — with automatic
  expiry after the block duration.
- **Behavioral defense** scans the live process table for authenticated SSH
  sessions, scores each session's commands against a baseline of suspicious
  binaries (the "AI" detector), and actively kills the session's processes and
  blocks the source IP when the score spikes.
- **Alert & harden** every observed session is stored to an audit trail (who
  logged in from where, and what they ran); a confirmed external threat pushes
  an instant ntfy.sh alert to your phone and tightens the compromised account
  (GPG-encrypted password rotation, optional sshd lockdown).

## Architecture

| Component | Role |
| --- | --- |
| `core/log_parser.py` | Parses sshd failure lines and tails the auth log. |
| `core/threat_tracker.py` | Per-IP failure counting inside a rolling time window. |
| `core/firewall.py` | Creates a custom `iptables` chain, inserts/removes DROP rules. |
| `ai/behavior_monitor.py` | Enumerates `/proc`, groups processes into SSH sessions. |
| `ai/detector.py` | Scores sessions against a suspicious-command baseline and mitigates. |
| `ai/anomaly.py` | Pure-Python isolation forest: flags sessions that diverge from a user's own command baseline. |
| `ai/ml_detector.py` | `AnomalyAwareDetector` — combines the rule score with the ML outlier score. |
| `core/state_manager.py` | Holds the admin whitelist and protects listed IPs from response. |
| `core/state_store.py` | Mirrors active blocks to `logs/defense_state.json` for restart recovery. |
| `core/session_store.py` | Persists every observed SSH session as day-structured JSONL plus SQLite rows. |
| `core/notifier.py` | Pushes ntfy.sh alerts to the operator's phone. |
| `core/hardening.py` | Rotates compromised passwords and disables sshd password auth on threat. |
| `config/loader.py` | Loads and validates `config/config.yaml`. |
| `core/logger.py` | Thread-safe append-only audit logger emitting JSON lines. |
| `main.py` | Daemon tying log tailing, threat tracking, and blocking together. |

## Requirements

- Linux (uses `/proc` and `iptables`)
- Python 3.10+
- `iptables` and root privileges for the *firewall integration tests* and for
  the daemon to actually block offenders

## Installation

```bash
git clone https://github.com/SiphosakheM/ssh-defense-gatway.git
cd ssh-defense-gatway

# Create an isolated virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Runtime dependencies
pip install -r requirements.txt

# Dev/test dependencies (optional)
pip install -r requirements-dev.txt
```

For a production deployment as a native systemd service, skip the manual venv
steps and use `install.sh` (see below).

## Configuration

All thresholds live in `config/config.yaml`:

| Key | Description | Default |
| --- | --- | --- |
| `max_attempts` | Failed logins allowed before an IP is flagged. | `5` |
| `time_window_seconds` | Rolling window in which failures are counted. | `300` |
| `block_duration_minutes` | How long a flagged IP stays blocked. | `15` |
| `suspicious_commands` | Binaries the behavioral detector scores against. | `sudo`, `apt`, `python3` |
| `whitelist_ips` | IPs/CIDRs never blocked or terminated (failsafe). | `127.0.0.1`, `192.168.0.0/16` |
| `session_audit.enabled` | Master switch for session storing. | `true` |
| `session_audit.log_dir` | Where per-day JSONL session records land. | `logs/sessions` |
| `session_audit.sqlite_path` | SQLite copy of the same records, for queries. | `logs/sessions.db` |
| `session_audit.retention_days` | JSONL archive files older than this are pruned. | `30` |
| `notifier.enabled` | Master switch for phone alerts. | `true` |
| `notifier.ntfy_url` | ntfy.sh server or a self-hosted one. | `https://ntfy.sh` |
| `notifier.ntfy_topic` | Your long, unguessable alert topic (see below). | `(unset)` |
| `hardening.rotate_password_on_threat` | Rotate a flagged account's password. | `true` |
| `hardening.gpg_recipient` | Your GPG public-key fingerprint for delivery. | `(unset)` |
| `hardening.disable_password_auth_on_threat` | Force `PasswordAuthentication no` in sshd. | `false` |
| `hardening.sshd_config_path` | sshd config edited by the hardening step. | `/etc/ssh/sshd_config` |

The config file is validated on load: missing keys raise `ValueError` and a
missing file raises `FileNotFoundError`. Every key in the three optional
blocks above (`session_audit`, `notifier`, `hardening`) is read with a
fallback default, so an older config without them still loads untouched.

## Session audit trail

Every session the behavioral scanner observes is recorded twice, so you can
always reconstruct *who* logged in, *from where*, and *what they ran*:

- **JSONL archive** — one JSON line per meaningful event in
  `logs/sessions/YYYY-MM-DD.jsonl` (human-greppable, pruned after
  `session_audit.retention_days`).
- **SQLite copy** — the same record in `logs/sessions.db` for programmatic
  queries via `SessionStore.recent_sessions()`.

A record carries the `session_id`, `username`, `client_address`, the full
command history (with per-command timestamps), the threat score, the ML
anomaly score, whether the session was flagged, and the mitigation applied.
Long-lived shells are only re-recorded when their commands actually change or
when they get flagged, so the trail shows real events rather than one row per
30-second scan.

## Phone alerts with ntfy.sh

When an external SSH session is flagged, the daemon pushes an instant alert
to your phone through [ntfy.sh](https://ntfy.sh)'s free pub/sub service — no
account, no bot tokens:

1. Install the free *ntfy* app on your phone.
2. Pick a **long, unguessable topic string** (think: a password token).
3. Subscribe to that topic in the app.
4. Put the same string in `notifier.ntfy_topic`, then start the daemon.

The alert names the flagged user, the source IP, the commands observed, and
the threat score. The topic *is* the access token — anyone who knows it can
see the alerts, so keep it secret and unique. Notifications are best-effort:
if the network is down the daemon logs `notify_failed` and keeps defending.

## Active hardening on threat

A flagged login triggers more than a firewall drop. In
`core/hardening.py`, escalating steps close the door the intruder used:

- **Password rotation** (`hardening.rotate_password_on_threat`): the
  compromised account's password is replaced with a fresh
  cryptographically-random value via `chpasswd`, so the stolen credential
  stops working instantly. The new password is encrypted to your GPG key
  (`hardening.gpg_recipient`) and only the armored, `-----BEGIN PGP MESSAGE
  -----` blob is pushed to your phone — the plaintext never crosses the
  messenger. If encryption or delivery fails, the rotation still happens and
  you are warned to reset the password manually; the plaintext is never sent.
- **sshd lockdown** (`hardening.disable_password_auth_on_threat`): flips
  `PasswordAuthentication` to `no` in `sshd_config` and *reloads* (never
  restarts) sshd, so password-based break-ins are impossible until you
  re-enable them. Key-based access for legitimate users keeps working.

Both steps require root and degrade gracefully without one another; a failed
step is recorded in the audit log instead of crashing the daemon.

## Usage

Run the daemon (requires root for `iptables`):

```bash
sudo .venv/bin/python main.py
```

The daemon tails `/var/log/auth.log` by default and applies DROP rules on the
`SSH_DEFENSE` chain. `Ctrl+C` stops it cleanly.

All runtime paths can be overridden via command-line flags, which the systemd
unit relies on:

| Flag | Default |
| --- | --- |
| `--config` | `config/config.yaml` |
| `--auth-log` | `/var/log/auth.log` |
| `--chain` | `SSH_DEFENSE` |
| `--audit-log` | `logs/gateway_audit.log` |
| `--state` | `logs/defense_state.json` |

## Running as a native systemd service

The repository ships a systemd unit template, `ssh-gateway.service`, and an
`install.sh` that copies the application tree into production and registers the
service:

```bash
sudo ./install.sh
```

By default the application lands in `/opt/ssh-defense-gateway`, the rendered
unit goes into `/etc/systemd/system/ssh-gateway.service`, a virtualenv is
built, and the service is enabled to start at boot:

```bash
sudo systemctl start ssh-gateway
systemctl status ssh-gateway
```

`install.sh` honours a few environment overrides for non-standard installs:

| Variable | Default | Purpose |
| --- | --- | --- |
| `INSTALL_ROOT` | `/opt/ssh-defense-gateway` | Where the application tree is copied |
| `SYSTEMD_DIR` | `/etc/systemd/system` | Where the rendered unit is installed |
| `SKIP_VENV=1` | off | Skip venv creation / `pip install` |
| `SKIP_SYSTEMD=1` | off | Skip `daemon-reload` and `enable` |

A non-root invocation that targets the default `/etc/systemd/system` fails
loudly; the test suite uses `SKIP_VENV`/`SKIP_SYSTEMD` and throwaway
`INSTALL_ROOT`/`SYSTEMD_DIR` prefixes to exercise the installer without root or
touching the live systemd manager.

The unit runs the daemon with `WorkingDirectory=@INSTALL_ROOT@` and
`ExecStart=@INSTALL_ROOT@/.venv/bin/python @INSTALL_ROOT@/main.py`, so all
relative defaults (`config/config.yaml`, `logs/`) resolve inside the install
tree. `Restart=on-failure` brings the daemon back up if it exits unexpectedly.

## Running the tests

The suite is split into pure unit tests and live integration tests that touch
real processes and `iptables`.

```bash
source .venv/bin/activate

# Everything you can run as a normal user (most of the suite)
python -m pytest tests/ -v

# Full integration suite, including firewall + daemon tests
sudo -E python -m pytest tests/ -v
```

### Integration test requirements

- **Root is required** for `tests/test_firewall.py`, `tests/test_main.py`, and
  the firewall path of `tests/test_detector.py` — the tests call the real
  `iptables` binary. Without root those tests `SKIP` rather than fail.
- The behavioral tests spawn **real processes**: a live shell tagged with an
  `SSH_CONNECTION` environment variable, and a process tree that the detector
  genuinely `SIGKILL`s. They run against `/proc`, so they only work on Linux.
- Tests use a dedicated `SSH_DEFENSE_TEST` iptables chain. Each test creates
  it up front and deletes it during teardown, so clean runs never leave
  orphaned chains or rules behind.
- Spawned shells and processes are killed in their own process groups and
  waited on, so no dangling processes survive a clean run.

To check the environment is clean after a run:

```bash
sudo iptables -L -n | grep -c SSH_DEFENSE   # expect 0 rules, no chain needed
pgrep -fa "sleep 120|time.sleep\(120\)"     # expect nothing
```

## How the detector works

1. `BehaviorMonitor.collect()` scans `/proc`, finds processes whose
   environment contains `SSH_CONNECTION`, and groups each root with all of its
   descendants into a session snapshot.
2. `BehaviorDetector.evaluate()` scores the session: every command is matched
   against `suspicious_commands` and each distinct hit adds to the total.
3. When the score meets the threshold (rule score, ML outlier score, or
   learned-baseline deviation), `respond()` kills every process in the
   session and calls `FirewallManager.apply_block()` on the client IP. The
   mitigation summary is available via the detector's `last_response`. For a
   flagged *external* session the daemon then also stores the session in the
   audit trail, pushes an ntfy.sh alert to your phone, and runs the
   configured hardening steps for the compromised account.

### ML anomaly layer

`AnomalyAwareDetector` (in `ai/ml_detector.py`) keeps everything above and
adds a lightweight, dependency-free anomaly detector. Each session becomes a
five-value feature vector — distinct command count, process count, mean
tokens per command, novelty against the user's past commands, and rule-baseline
hits — and a pure-Python isolation forest (`ai/anomaly.py`) scores it in
[0, 1]. A session is now mitigated when either:

- its classic rule score meets the threshold, **or**
- the forest — trained on the user's own rolling command baseline — returns an
  anomaly score at or above `anomaly_threshold`.

The design is deliberately cheap for a live daemon: no third-party ML
libraries, bounded per-user memory (`anomaly_max_memory`), tiny sub-sampled
trees, and a lazy refit that only retrains after the baseline grows by
`anomaly_retrain_every` sessions. A detected deviation is explained via the
`last_assessment` dict, which lists the features that drove the score (the
`why` field), and every ML-triggered mitigation still honours the whitelist
failsafe and the JSON audit trail. All ML tuning keys are optional — the
defaults below apply when the key is absent from `config/config.yaml`:

| Key | Description | Default |
| --- | --- | --- |
| `anomaly_enabled` | Master switch for the ML layer. | `true` |
| `anomaly_threshold` | Outlier score (0-1) required to respond. | `0.72` |
| `anomaly_forest_trees` | Trees in the isolation forest. | `16` |
| `anomaly_max_memory` | Rolling per-user feature vectors retained. | `150` |
| `anomaly_min_train` | Sessions before the baseline is usable. | `25` |
| `anomaly_retrain_every` | New sessions before the forest refits. | `24` |

## Whitelist failsafe

IP addresses or CIDR networks in `whitelist_ips` are exempt from every
automated defense response, so a misconfiguration can never lock the
operator out of their own machine:

- The brute-force daemon checks `StateManager.is_whitelisted()` before
  calling `FirewallManager.apply_block()` on any IP that crosses the
  failure threshold.
- The behavioral detector checks the same whitelist in `respond()` and
  skips both the process kill and the firewall block for a whitelisted
  client, recording the deferral as a `whitelisted` anomaly entry.

`StateManager` accepts bare addresses (treated as `/32` hosts) and CIDR
subnets; malformed entries raise `ValueError` at construction.

## Audit logging

Every active defense measure is permanently recorded as one JSON line in
`logs/gateway_audit.log`:

| Event | Source | Payload |
| --- | --- | --- |
| `block` | `FirewallManager.apply_block()` | `ip`, `chain` |
| `unblock` | `FirewallManager.remove_block()` | `ip`, `chain` |
| `kill` | `BehaviorDetector.respond()` | `pid`, `command`, `killed`, `session_id`, `client_address` |
| `anomaly` | `BehaviorDetector.evaluate()` | `score`, `threshold`, `session_id`, `client_address`, `response` |
| `notify` / `notify_failed` / `notify_skipped` | `Notifier.send()` | `title`, `topic`, optional `reason` |
| `password_rotated` | `Hardening` | `username` |
| `password_rotate_failed` / `password_rotate_skipped` | `Hardening` | `username`, `reason` |
| `password_encrypt_failed` | `Hardening` | `reason` |
| `sshd_password_auth_disabled` / `sshd_hardening_failed` | `Hardening` | `path`, optional `reason` |

Each entry is a flat JSON object with a UTC `timestamp` and an `event_type`,
for example:

```json
{"chain": "SSH_DEFENSE", "event_type": "block", "ip": "203.0.113.9", "timestamp": "2026-09-12T13:45:01.123456+00:00"}
```

`AuditLogger` serializes writes behind a lock, opens the file in append mode,
and `fsync`s every entry so concurrent writers (the daemon loop, background
block-expiry timers, and the detector) can never garble a line and a recorded
measure survives a crash. The log lives under `logs/` and is git-ignored.

## Persistent threat state

Every `apply_block` and `remove_block` on the firewall is mirrored into
`logs/defense_state.json` through `core/state_store.py`, which stores each
IP along with its `blocked_at` and `expires_at` timestamps:

```json
{
  "blocks": {
    "203.0.113.9": {
      "blocked_at": 1789590866.35,
      "expires_at": 1789594466.35
    }
  }
}
```

Writes are atomic (temp file + `os.replace`) and lock-guarded, so concurrent
block/expiry timers can never corrupt the file or leave a partial snapshot.
On startup, `run_daemon` calls `state_store.load()`, prunes expired entries,
and replays the surviving blocks onto the iptables chain — re-applying any
missing DROP rules and rescheduling their removal — so active defenses
survive a daemon restart or a full system reboot.