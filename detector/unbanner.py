"""
unbanner.py - Background thread that checks for expired bans and releases them.
Sends a Slack notification on every unban.
"""

import time
import logging
import threading

logger = logging.getLogger(__name__)


class Unbanner(threading.Thread):
    """
    Runs as a daemon thread.
    Every 10 seconds, checks for bans whose duration has expired and
    removes them.
    """

    def __init__(self, blocker, notifier, audit_logger):
        super().__init__(daemon=True, name="unbanner")
        self._blocker = blocker
        self._notifier = notifier
        self._audit = audit_logger
        self._running = True

    def run(self):
        logger.info("Unbanner thread started")
        while self._running:
            try:
                self._check_expired()
            except Exception as e:
                logger.error(f"Unbanner error: {e}")
            time.sleep(10)

    def _check_expired(self):
        expired = self._blocker.get_expired_bans()
        for ip in expired:
            record = self._blocker.unban(ip)
            if record:
                offense = record.offense_count
                durations = self._blocker._durations
                next_idx = min(offense, len(durations) - 1)
                next_duration = durations[next_idx]
                next_str = (
                    "permanent"
                    if next_duration == -1
                    else f"{next_duration}s"
                )

                self._notifier.send_unban(
                    ip=ip,
                    ban_duration=record.duration,
                    offense_count=offense,
                    next_ban_duration=next_str,
                )
                self._audit.log_unban(
                    ip=ip,
                    condition=record.condition,
                    duration=record.duration,
                )

    def stop(self):
        self._running = False
