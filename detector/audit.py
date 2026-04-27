"""
audit.py - Writes structured audit log entries for every ban, unban,
and baseline recalculation.

Format: [timestamp] ACTION ip | condition | rate | baseline | duration
"""

import os
import time
import logging
from threading import Lock
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class AuditLogger:
    def __init__(self, config: dict):
        self._log_path = config["audit"]["log_path"]
        self._lock = Lock()
        os.makedirs(os.path.dirname(self._log_path), exist_ok=True)
        logger.info(f"AuditLogger writing to {self._log_path}")

    def _write(self, line: str):
        with self._lock:
            try:
                with open(self._log_path, "a") as f:
                    f.write(line + "\n")
            except Exception as e:
                logger.error(f"Audit log write failed: {e}")

    def _ts(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def log_ban(
        self,
        ip: str,
        condition: str,
        rate: float,
        baseline_mean: float,
        duration: int,
    ):
        duration_str = "permanent" if duration == -1 else f"{duration}s"
        line = (
            f"[{self._ts()}] BAN {ip} | "
            f"condition={condition} | "
            f"rate={rate:.2f} | "
            f"baseline={baseline_mean:.2f} | "
            f"duration={duration_str}"
        )
        self._write(line)

    def log_unban(self, ip: str, condition: str, duration: int):
        duration_str = "permanent" if duration == -1 else f"{duration}s"
        line = (
            f"[{self._ts()}] UNBAN {ip} | "
            f"condition={condition} | "
            f"duration_served={duration_str}"
        )
        self._write(line)

    def log_baseline_recalc(
        self,
        mean: float,
        stddev: float,
        samples: int,
        hour_key: int,
    ):
        line = (
            f"[{self._ts()}] BASELINE_RECALC | "
            f"mean={mean:.3f} | "
            f"stddev={stddev:.3f} | "
            f"samples={samples} | "
            f"hour_slot={hour_key}"
        )
        self._write(line)
