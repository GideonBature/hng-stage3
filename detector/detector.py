"""
detector.py - Anomaly detection using z-score and rate multiplier thresholds.

Detection logic:
- For each IP and globally, compute the current request rate over the
  sliding 60-second window.
- Compute z-score = (current_rate - baseline_mean) / baseline_stddev
- Flag as anomalous if z-score > threshold OR rate > multiplier * mean
- If an IP has elevated error rate (>= error_multiplier * error_mean),
  tighten its detection thresholds by 50%
- Anomaly events are passed to registered callbacks
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Callable, List
from collections import deque
from threading import Lock

logger = logging.getLogger(__name__)


@dataclass
class AnomalyEvent:
    kind: str           # "ip" or "global"
    source_ip: str      # empty string for global events
    current_rate: float
    baseline_mean: float
    baseline_stddev: float
    zscore: float
    condition: str      # human-readable description of what fired
    timestamp: float = field(default_factory=time.time)


class Detector:
    """
    Evaluates traffic rates against the rolling baseline and fires anomaly
    events when thresholds are exceeded.

    The sliding window per IP is maintained as a deque of timestamps.
    Each incoming request appends its timestamp. On evaluation, timestamps
    older than window_seconds are evicted from the left of the deque.
    This gives an exact count of requests in the last window_seconds.
    """

    def __init__(self, config: dict, baseline):
        dc = config["detection"]
        self.window_seconds: int = dc["window_seconds"]
        self.zscore_threshold: float = dc["zscore_threshold"]
        self.rate_multiplier: float = dc["rate_multiplier"]
        self.error_rate_multiplier: float = dc["error_rate_multiplier"]

        self._baseline = baseline
        self._handlers: List[Callable[[AnomalyEvent], None]] = []

        # Per-IP sliding window: deque of request timestamps
        self._ip_windows: dict = {}
        # Global sliding window: deque of request timestamps
        self._global_window: deque = deque()
        self._lock = Lock()

        # Track recently fired anomalies to avoid re-alerting every second
        # ip -> last_alert_time
        self._last_alert: dict = {}
        self._alert_cooldown: int = 30  # seconds between repeat alerts per IP

    def register_handler(self, handler: Callable[[AnomalyEvent], None]):
        self._handlers.append(handler)

    def _emit(self, event: AnomalyEvent):
        for handler in self._handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Anomaly handler error: {e}")

    def record(self, source_ip: str):
        """Record an incoming request for detection evaluation."""
        now = time.time()
        with self._lock:
            # Global window
            self._global_window.append(now)

            # Per-IP window
            if source_ip not in self._ip_windows:
                self._ip_windows[source_ip] = deque()
            self._ip_windows[source_ip].append(now)

    def _evict_old(self, window: deque, cutoff: float):
        """Remove timestamps older than cutoff from the left of the deque."""
        while window and window[0] < cutoff:
            window.popleft()

    def _get_rate(self, window: deque, cutoff: float) -> float:
        """Count entries in window after cutoff, return as per-second rate."""
        count = sum(1 for ts in window if ts >= cutoff)
        return count / self.window_seconds

    def evaluate(self):
        """
        Called periodically (every second) from the main loop.
        Evaluates current rates against the baseline and fires anomaly
        events as needed.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        mean, stddev = self._baseline.get_global_stats()
        err_mean, _ = self._baseline.get_error_stats()

        if stddev == 0:
            stddev = 0.5

        with self._lock:
            # Evict old global entries
            self._evict_old(self._global_window, cutoff)
            global_rate = len(self._global_window) / self.window_seconds

            # Evaluate per-IP
            for ip, window in list(self._ip_windows.items()):
                self._evict_old(window, cutoff)
                if not window:
                    continue

                ip_rate = len(window) / self.window_seconds
                ip_error_rate = self._baseline.get_ip_error_rate(ip)

                # Tighten thresholds if error surge detected
                tightened = False
                if err_mean > 0 and ip_error_rate >= self.error_rate_multiplier * err_mean:
                    effective_zscore_thresh = self.zscore_threshold * 0.5
                    effective_rate_mult = self.rate_multiplier * 0.5
                    tightened = True
                else:
                    effective_zscore_thresh = self.zscore_threshold
                    effective_rate_mult = self.rate_multiplier

                zscore = (ip_rate - mean) / stddev
                rate_breach = mean > 0 and ip_rate >= effective_rate_mult * mean

                if zscore > effective_zscore_thresh or rate_breach:
                    # Check cooldown
                    last = self._last_alert.get(ip, 0)
                    if now - last < self._alert_cooldown:
                        continue

                    self._last_alert[ip] = now
                    condition = (
                        f"z-score={zscore:.1f} (threshold={effective_zscore_thresh})"
                        if zscore > effective_zscore_thresh
                        else f"rate={ip_rate:.1f} >= {effective_rate_mult}x mean={mean:.1f}"
                    )
                    if tightened:
                        condition += " [thresholds tightened due to error surge]"

                    logger.warning(
                        f"IP anomaly: {ip} rate={ip_rate:.2f} "
                        f"mean={mean:.2f} z={zscore:.2f} | {condition}"
                    )
                    self._emit(AnomalyEvent(
                        kind="ip",
                        source_ip=ip,
                        current_rate=ip_rate,
                        baseline_mean=mean,
                        baseline_stddev=stddev,
                        zscore=zscore,
                        condition=condition,
                    ))

        # Evaluate global
        global_zscore = (global_rate - mean) / stddev
        global_rate_breach = mean > 0 and global_rate >= self.rate_multiplier * mean

        if global_zscore > self.zscore_threshold or global_rate_breach:
            last_global = self._last_alert.get("__global__", 0)
            if now - last_global >= self._alert_cooldown:
                self._last_alert["__global__"] = now
                condition = (
                    f"global z-score={global_zscore:.1f}"
                    if global_zscore > self.zscore_threshold
                    else f"global rate={global_rate:.1f} >= {self.rate_multiplier}x mean"
                )
                logger.warning(
                    f"GLOBAL anomaly: rate={global_rate:.2f} "
                    f"mean={mean:.2f} z={global_zscore:.2f}"
                )
                self._emit(AnomalyEvent(
                    kind="global",
                    source_ip="",
                    current_rate=global_rate,
                    baseline_mean=mean,
                    baseline_stddev=stddev,
                    zscore=global_zscore,
                    condition=condition,
                ))

    def get_global_rate(self) -> float:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            return sum(1 for ts in self._global_window if ts >= cutoff) / self.window_seconds
