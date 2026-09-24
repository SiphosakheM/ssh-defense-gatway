"""Main orchestrator daemon for the SSH Defense Gateway.

Tails the SSH authentication log, records failed attempts in the threat
tracker, and blocks offending IPs on a dedicated iptables chain once they
cross the configured threshold. Active blocks are mirrored to disk so
they survive a restart or reboot.

A background behavioral scan also runs every
``behavior_scan_interval_seconds`` (default 30), feeding live session
telemetry to the ``AnomalyAwareDetector`` so post-login zero-trust
defense is active in production, not just in unit tests.
"""

import argparse
import threading
import time

from ai.behavior_monitor import BehaviorMonitor
from ai.ml_detector import AnomalyAwareDetector
from config.loader import load_config
from core.firewall import FirewallManager
from core.log_parser import parse_failure, tail_log
from core.logger import AuditLogger
from core.state_manager import StateManager
from core.state_store import DefenseStateStore
from core.threat_tracker import ThreatTracker


def run_daemon(
    config_path="config/config.yaml",
    log_path="/var/log/auth.log",
    chain="SSH_DEFENSE",
    stop_event=None,
    audit_log_path="logs/gateway_audit.log",
    state_path="logs/defense_state.json",
):
    """Run the defense loop until signaled.

    ``stop_event`` is an optional ``threading.Event``; once set, the loop
    exits on the next line read from the tailed log. On startup, blocks
    recorded in ``state_path`` are restored onto the firewall.
    """
    config = load_config(config_path)
    tracker = ThreatTracker(
        max_attempts=config["max_attempts"],
        time_window_seconds=config["time_window_seconds"],
    )
    state = StateManager(config["whitelist_ips"])
    state_store = DefenseStateStore(state_path)
    audit_logger = AuditLogger(audit_log_path)
    firewall = FirewallManager(
        chain=chain,
        logger=audit_logger,
        state_store=state_store,
    )
    firewall.ensure_chain()
    block_seconds = config["block_duration_minutes"] * 60

    now = time.time()
    for ip, info in state_store.load().items():
        expires_at = info.get("expires_at")
        remaining = (expires_at - now) if expires_at else None
        if not firewall.rule_exists(ip):
            firewall.apply_block(ip, duration_seconds=remaining)
        if remaining is not None and remaining > 0:
            firewall.schedule_block_removal(ip, remaining)

    monitor = BehaviorMonitor()
    detector = AnomalyAwareDetector.from_config(
        config,
        firewall=firewall,
        logger=audit_logger,
        whitelist=state,
    )
    scan_interval = float(config.get("behavior_scan_interval_seconds", 30))

    def behavior_scan():
        """Periodically score live sessions and respond to AI-flagged ones.

        The whitelist failsafe and audit logging are honoured by the
        detector itself, so every evaluated session is safe to kill or
        block. Sleeping in small slices keeps shutdown responsive.
        """
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            telemetry = monitor.collect()
            for session in telemetry.get("sessions", []):
                detector.evaluate(session)
            if scan_interval <= 0:
                continue
            deadline = time.monotonic() + scan_interval
            while time.monotonic() < deadline:
                if stop_event is not None and stop_event.is_set():
                    return
                time.sleep(0.1)

    scan_thread = threading.Thread(target=behavior_scan, daemon=True)
    scan_thread.start()

    for line in tail_log(log_path):
        if stop_event is not None and stop_event.is_set():
            break
        failure = parse_failure(line)
        if failure is None:
            continue
        ip = failure["ip"]
        tracker.record_failure(ip)
        if (
            tracker.is_threat(ip)
            and not firewall.rule_exists(ip)
            and not state.is_whitelisted(ip)
        ):
            firewall.apply_block(ip, duration_seconds=block_seconds)
            firewall.schedule_block_removal(ip, block_seconds)

    scan_thread.join(timeout=1)


def main(argv=None):
    """Entry point that runs the defense daemon until interrupted.

    Accepts the same paths as ``run_daemon`` so the process can be driven
    directly from a systemd unit or a terminal.
    """
    parser = argparse.ArgumentParser(
        prog="ssh-gateway",
        description="SSH Defense Gateway - active defense daemon",
    )
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--auth-log", default="/var/log/auth.log")
    parser.add_argument("--chain", default="SSH_DEFENSE")
    parser.add_argument("--audit-log", default="logs/gateway_audit.log")
    parser.add_argument("--state", default="logs/defense_state.json")
    args = parser.parse_args(argv)

    try:
        run_daemon(
            config_path=args.config,
            log_path=args.auth_log,
            chain=args.chain,
            audit_log_path=args.audit_log,
            state_path=args.state,
        )
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()