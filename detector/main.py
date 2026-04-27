"""
main.py - Entry point for the HNG anomaly detection daemon.

Wires together:
  LogMonitor -> Baseline + Detector -> Blocker -> Notifier
                                               -> AuditLogger
  Unbanner (background thread)
  Dashboard (background thread)

The main loop runs continuously, calling detector.evaluate() and
baseline.maybe_recalculate() every second.
"""

import time
import signal
import logging
import sys
import yaml

from monitor import LogMonitor, LogEntry
from baseline import BaselineTracker
from detector import Detector, AnomalyEvent
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from audit import AuditLogger
from dashboard import Dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("main")


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    logger.info("HNG Anomaly Detection Daemon starting")
    config = load_config()

    # Initialise components
    baseline = BaselineTracker(config)
    detector = Detector(config, baseline)
    blocker = Blocker(config)
    notifier = Notifier(config)
    audit = AuditLogger(config)
    dashboard = Dashboard(config, baseline, detector, blocker)

    # Wire log monitor -> baseline + detector
    monitor = LogMonitor(config["nginx"]["log_path"])

    def on_log_entry(entry: LogEntry):
        baseline.record_request(entry.source_ip, entry.is_error())
        detector.record(entry.source_ip)

    monitor.register_handler(on_log_entry)

    # Wire detector -> blocker + notifier + audit
    def on_anomaly(event: AnomalyEvent):
        if event.kind == "ip":
            record = blocker.ban(event.source_ip, event.condition)
            if record:
                notifier.send_ban(
                    ip=event.source_ip,
                    condition=event.condition,
                    current_rate=event.current_rate,
                    baseline_mean=event.baseline_mean,
                    duration=record.duration,
                )
                audit.log_ban(
                    ip=event.source_ip,
                    condition=event.condition,
                    rate=event.current_rate,
                    baseline_mean=event.baseline_mean,
                    duration=record.duration,
                )
        elif event.kind == "global":
            notifier.send_global_alert(
                condition=event.condition,
                current_rate=event.current_rate,
                baseline_mean=event.baseline_mean,
                baseline_stddev=event.baseline_stddev,
            )

    detector.register_handler(on_anomaly)

    # Wire baseline recalculation to audit log
    original_recalculate = baseline._recalculate

    def recalculate_with_audit(now: float):
        original_recalculate(now)
        mean, stddev = baseline.get_global_stats()
        hour_key = int(now // 3600)
        audit.log_baseline_recalc(
            mean=mean,
            stddev=stddev,
            samples=len(baseline._global_buckets),
            hour_key=hour_key,
        )

    baseline._recalculate = recalculate_with_audit

    # Start background threads
    unbanner = Unbanner(blocker, notifier, audit)
    unbanner.start()

    dashboard.start_background()

    # Graceful shutdown handler
    def shutdown(signum, frame):
        logger.info("Shutdown signal received")
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Start log monitor in background thread
    import threading
    monitor_thread = threading.Thread(
        target=monitor.run, daemon=True, name="monitor"
    )
    monitor_thread.start()

    logger.info("All components started. Entering main evaluation loop.")

    # Main loop: evaluate every second, recalculate baseline every 60s
    while True:
        try:
            detector.evaluate()
            baseline.maybe_recalculate()
        except Exception as e:
            logger.error(f"Main loop error: {e}")
        time.sleep(1)


if __name__ == "__main__":
    main()
