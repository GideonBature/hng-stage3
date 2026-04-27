"""
baseline.py - Computes a rolling baseline of normal traffic.

Architecture:
- Maintains a deque of per-second request counts over the last 30 minutes
- Recalculates mean and stddev every 60 seconds
- Maintains per-hour slots and prefers the current hour's data when
  it has enough samples (>= min_samples)
- Tracks per-IP and global error rates for error surge detection
"""

import time
import math
import logging
from collections import deque, defaultdict
from threading import Lock
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class BaselineTracker:
    """
    Tracks rolling traffic statistics for anomaly detection.

    The baseline works as follows:
    1. Every incoming request increments a per-second counter bucket.
    2. A background thread (called from main loop) recalculates every
       recalc_interval seconds.
    3. The rolling window is a deque of (timestamp, count) tuples covering
       the last window_minutes minutes. Old entries are evicted when they
       fall outside the window.
    4. Per-hour slots store the computed mean/stddev for each clock hour.
       When the current hour has enough data, it is preferred over the
       global rolling window.
    """

    def __init__(self, config: dict):
        bc = config["baseline"]
        self.window_seconds = bc["window_minutes"] * 60
        self.recalc_interval = bc["recalc_interval"]
        self.min_rps_floor = bc["min_rps_floor"]
        self.min_samples = bc["min_samples"]

        # Per-second count buckets: {floor(timestamp): count}
        self._global_buckets: Dict[int, int] = {}
        self._ip_buckets: Dict[str, Dict[int, int]] = defaultdict(dict)
        self._error_buckets: Dict[int, int] = {}
        self._ip_error_buckets: Dict[str, Dict[int, int]] = defaultdict(dict)

        # Rolling window: deque of (second_ts, global_count)
        self._window: deque = deque()

        # Per-hour slots: {hour_key: {"mean": float, "stddev": float, "samples": int}}
        self._hour_slots: Dict[int, dict] = {}

        # Current computed baseline
        self._effective_mean: float = self.min_rps_floor
        self._effective_stddev: float = 1.0
        self._error_mean: float = 0.1
        self._error_stddev: float = 0.1

        self._last_recalc: float = 0.0
        self._lock = Lock()

        logger.info(
            f"BaselineTracker init: window={bc['window_minutes']}min "
            f"recalc={self.recalc_interval}s floor={self.min_rps_floor}"
        )

    def record_request(self, source_ip: str, is_error: bool):
        """Record one incoming request. Called for every log entry."""
        now_bucket = int(time.time())
        with self._lock:
            self._global_buckets[now_bucket] = \
                self._global_buckets.get(now_bucket, 0) + 1
            self._ip_buckets[source_ip][now_bucket] = \
                self._ip_buckets[source_ip].get(now_bucket, 0) + 1
            if is_error:
                self._error_buckets[now_bucket] = \
                    self._error_buckets.get(now_bucket, 0) + 1
                self._ip_error_buckets[source_ip][now_bucket] = \
                    self._ip_error_buckets[source_ip].get(now_bucket, 0) + 1

    def maybe_recalculate(self):
        """
        Called from the main loop. Recalculates baseline if enough time
        has passed since the last recalculation.
        """
        now = time.time()
        if now - self._last_recalc < self.recalc_interval:
            return
        self._last_recalc = now
        self._recalculate(now)

    def _recalculate(self, now: float):
        """
        Evict old buckets, rebuild the rolling window deque, compute
        mean and stddev, update per-hour slots.
        """
        cutoff = int(now) - self.window_seconds
        with self._lock:
            # Evict expired global buckets
            expired = [ts for ts in self._global_buckets if ts < cutoff]
            for ts in expired:
                del self._global_buckets[ts]

            # Evict expired error buckets
            expired_err = [ts for ts in self._error_buckets if ts < cutoff]
            for ts in expired_err:
                del self._error_buckets[ts]

            # Evict expired per-IP buckets
            for ip in list(self._ip_buckets.keys()):
                expired_ip = [
                    ts for ts in self._ip_buckets[ip] if ts < cutoff
                ]
                for ts in expired_ip:
                    del self._ip_buckets[ip][ts]

            # Build list of per-second counts for the window
            counts = list(self._global_buckets.values())
            error_counts = list(self._error_buckets.values())

        if len(counts) < self.min_samples:
            logger.debug(
                f"Baseline: not enough samples ({len(counts)}), "
                f"using floor values"
            )
            return

        mean, stddev = self._compute_stats(counts)
        mean = max(mean, self.min_rps_floor)
        stddev = max(stddev, 0.5)

        err_mean, err_stddev = self._compute_stats(error_counts) \
            if error_counts else (0.1, 0.1)

        # Update per-hour slot
        hour_key = int(now // 3600)
        with self._lock:
            self._hour_slots[hour_key] = {
                "mean": mean,
                "stddev": stddev,
                "samples": len(counts),
                "updated": now,
            }

            # Prefer current hour slot if it has enough samples
            current_slot = self._hour_slots.get(hour_key)
            if current_slot and current_slot["samples"] >= self.min_samples:
                self._effective_mean = current_slot["mean"]
                self._effective_stddev = current_slot["stddev"]
            else:
                self._effective_mean = mean
                self._effective_stddev = stddev

            self._error_mean = max(err_mean, 0.05)
            self._error_stddev = max(err_stddev, 0.05)

        logger.info(
            f"Baseline recalculated: mean={self._effective_mean:.2f} "
            f"stddev={self._effective_stddev:.2f} "
            f"samples={len(counts)} "
            f"error_mean={self._error_mean:.3f}"
        )

    def _compute_stats(self, values: list) -> Tuple[float, float]:
        """Compute mean and population stddev from a list of values."""
        if not values:
            return 0.0, 0.0
        n = len(values)
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n
        stddev = math.sqrt(variance)
        return mean, stddev

    def get_global_stats(self) -> Tuple[float, float]:
        """Return current effective mean and stddev."""
        with self._lock:
            return self._effective_mean, self._effective_stddev

    def get_error_stats(self) -> Tuple[float, float]:
        with self._lock:
            return self._error_mean, self._error_stddev

    def get_ip_rate(self, ip: str, window: int = 60) -> float:
        """Return requests per second for an IP over the last window seconds."""
        cutoff = int(time.time()) - window
        with self._lock:
            buckets = self._ip_buckets.get(ip, {})
            total = sum(v for ts, v in buckets.items() if ts >= cutoff)
        return total / window

    def get_global_rate(self, window: int = 60) -> float:
        """Return global requests per second over the last window seconds."""
        cutoff = int(time.time()) - window
        with self._lock:
            total = sum(
                v for ts, v in self._global_buckets.items() if ts >= cutoff
            )
        return total / window

    def get_ip_error_rate(self, ip: str, window: int = 60) -> float:
        """Return error requests per second for an IP."""
        cutoff = int(time.time()) - window
        with self._lock:
            buckets = self._ip_error_buckets.get(ip, {})
            total = sum(v for ts, v in buckets.items() if ts >= cutoff)
        return total / window

    def get_top_ips(self, n: int = 10, window: int = 60) -> list:
        """Return top N IPs by request count in the last window seconds."""
        cutoff = int(time.time()) - window
        with self._lock:
            ip_counts = {}
            for ip, buckets in self._ip_buckets.items():
                total = sum(v for ts, v in buckets.items() if ts >= cutoff)
                if total > 0:
                    ip_counts[ip] = total
        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_hour_slots(self) -> dict:
        with self._lock:
            return dict(self._hour_slots)
