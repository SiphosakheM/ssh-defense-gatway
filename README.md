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

## Architecture

| Component | Role |
| --- | --- |
| `core/log_parser.py` | Parses sshd failure lines and tails the auth log. |
| `core/threat_tracker.py` | Per-IP failure counting inside a rolling time window. |
| `core/firewall.py` | Creates a custom `iptables` chain, inserts/removes DROP rules. |
| `ai/behavior_monitor.py` | Enumerates `/proc`, groups processes into SSH sessions. |
| `ai/detector.py` | Scores sessions against a suspicious-command baseline and mitigates. |
| `config/loader.py` | Loads and validates `config/config.yaml`. |
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

## Configuration

All thresholds live in `config/config.yaml`:

| Key | Description | Default |
| --- | --- | --- |
| `max_attempts` | Failed logins allowed before an IP is flagged. | `5` |
| `time_window_seconds` | Rolling window in which failures are counted. | `300` |
| `block_duration_minutes` | How long a flagged IP stays blocked. | `15` |
| `suspicious_commands` | Binaries the behavioral detector scores against. | `sudo`, `apt`, `python3` |

The config file is validated on load: missing keys raise `ValueError` and a
missing file raises `FileNotFoundError`.

## Usage

Run the daemon (requires root for `iptables`):

```bash
sudo .venv/bin/python main.py
```

The daemon tails `/var/log/auth.log` by default and applies DROP rules on the
`SSH_DEFENSE` chain. `Ctrl+C` stops it cleanly.

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
3. When the score meets the threshold, `respond()` kills every process in the
   session and calls `FirewallManager.apply_block()` on the client IP. The
   mitigation summary is available via the detector's `last_response`.