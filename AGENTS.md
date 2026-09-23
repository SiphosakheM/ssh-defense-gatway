# Handover — Outstanding Work

This file is read automatically by AI coding agents (opencode, Claude Code,
etc.) at the start of a session. If you are an LLM agent and the "Finish the
in-flight ML commits" section below is still open, that is the very first
thing to pick up.

Status snapshot of the SSH Defense Gateway, what still needs doing, and how
to verify each item. The pattern is: feature + unit tests already merged,
integration/daemon wiring and live verification still open.

## 1. Finish the in-flight ML commits (immediate)

All five of the ML-scoped commits are on `main`:

- `feat(ai): add pure-Python isolation forest anomaly engine` (`d19012a`)
- `feat(ai): combine rule scoring with the ML outlier detector` (`eaea543`)
- `feat(config): add optional ML anomaly tuning knobs` (`b81104b`)
- `test(ai): cover isolation forest and ML detector wiring` (`d272764`)
- `docs(project): document the ML anomaly layer` (`bcbde99`)

If this section is still open, resume from section 2 (daemon wiring). If all
five commits exist, this entire section is done and can be dropped.

## 2. Wire the AI defense into the daemon (highest priority)

`main.py` runs **only** the brute-force path. The entire behavioral/ML layer
— `BehaviorMonitor`, `BehaviorDetector`, `AnomalyAwareDetector` — is built,
unit-tested, and documented but never invoked by `run_daemon`, so the "AI
defense" the README describes is not actually active in production.

Missing work:

- Add a behavioral scan loop to `run_daemon` (e.g. every N seconds) that:
  1. calls `BehaviorMonitor.collect()` for live sessions;
  2. evaluates each session with `AnomalyAwareDetector` (built from config via
     `AnomalyAwareDetector.from_config(...)`);
  3. honours the same `whitelist` failsafe and audit logger.
- Add an optional `behavior_scan_interval_seconds` config key (default ~30s),
  optional to keep the strict config contract untouched (do **not** add it to
  `config.loader.EXPECTED_KEYS`).
- Add a daemon-level integration test mirroring the pattern already used in
  `tests/test_main.py` (threaded daemon + polled assertions, no root needed
  where possible; the real-kill test stays in `tests/test_detector.py`).

## 3. Run the root-only integration tests

Full non-root suite passes: `60 passed, 6 skipped`. The 6 skips are
`iptables` tests that require root and have **never been exercised in this
environment** (sudo requires a password here):

- `tests/test_firewall.py` (real chain insert/autoremove)
- `tests/test_detector.py::test_detector_blocks_flagged_ip_on_firewall_chain`
- `tests/test_logger.py::test_block_event_written_to_real_audit_log`
- `tests/test_main.py` daemon block tests (2)

Execute:

```bash
sudo -E .venv/bin/python -m pytest tests/ -v
```

and verify the environment is clean afterward:

```bash
sudo iptables -L -n | grep -c SSH_DEFENSE_TEST   # expect 0
pgrep -fa "sleep 120|time.sleep\(120\)"          # expect nothing
```

## 4. Verify the system-level service end-to-end

The user-level systemd integration test passes, but the native production
path was designed, not run:

- `install.sh` was never executed against the real `/etc/systemd/system`
  (only throwaway prefixes via `SKIP_VENV`/`SKIP_SYSTEMD`).
- The actual `systemctl enable` + boot-time start and `Restart=on-failure`
  recovery were not observed.

Verify on a root box:

```bash
sudo ./install.sh
sudo systemctl start ssh-gateway
systemctl status ssh-gateway
# simulate a crash to check Restart=on-failure recovers it
sudo systemctl restart ssh-gateway
```

## 5. Harden and tune the ML model with real data

The isolation forest is a correct, deterministic, dependency-free
implementation, but its thresholds are placeholders:

- `anomaly_threshold` (default `0.72`) and `anomaly_min_train`/memory sizing
  were validated against synthetic sessions only. Tune against real auth
  workloads before trusting it in production.
- The forest scores per-user command vectors; consider adding richer features
  later (command entropy, session duration, network endpoints) — the
  vectorizer lives in `ai/anomaly.py` (`FEATURE_NAMES`) and extending it means
  updating the tests in `tests/test_anomaly.py`.

## 6. CI / portability (nice-to-have)

- No CI pipeline exists; the suite is Linux-only by design (`/proc`,
  `iptables`, systemd).
- An optional `Makefile` or GitHub Actions matrix (non-root + root runner)
  would let the root-only tests actually run in CI.

## Test reference

```bash
source .venv/bin/activate
python -m pytest tests/ -v            # non-root, most of the suite
sudo -E python -m pytest tests/ -v    # full suite
```