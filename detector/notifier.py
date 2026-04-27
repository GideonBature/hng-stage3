"""
notifier.py - Sends Slack alerts for bans, unbans, and global anomalies.
All messages include: condition, current rate, baseline, timestamp,
and ban duration where applicable.
"""

import time
import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class Notifier:
    def __init__(self, config: dict):
        self._webhook_url: str = config["slack"]["webhook_url"]
        self._enabled = bool(self._webhook_url and
                             self._webhook_url != "YOUR_SLACK_WEBHOOK_URL_HERE")
        if not self._enabled:
            logger.warning(
                "Slack webhook not configured. Notifications disabled."
            )

    def _ts(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _send(self, text: str):
        if not self._enabled:
            logger.info(f"[SLACK DISABLED] {text}")
            return
        try:
            resp = requests.post(
                self._webhook_url,
                json={"text": text},
                timeout=5,
            )
            if resp.status_code != 200:
                logger.error(
                    f"Slack webhook error: {resp.status_code} {resp.text}"
                )
        except Exception as e:
            logger.error(f"Slack send failed: {e}")

    def send_ban(
        self,
        ip: str,
        condition: str,
        current_rate: float,
        baseline_mean: float,
        duration: int,
    ):
        duration_str = "permanent" if duration == -1 else f"{duration}s"
        text = (
            f":rotating_light: *IP BANNED* :rotating_light:\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Current rate:* {current_rate:.2f} req/s\n"
            f"*Baseline mean:* {baseline_mean:.2f} req/s\n"
            f"*Ban duration:* {duration_str}\n"
            f"*Timestamp:* {self._ts()}"
        )
        self._send(text)

    def send_unban(
        self,
        ip: str,
        ban_duration: int,
        offense_count: int,
        next_ban_duration: str,
    ):
        duration_str = "permanent" if ban_duration == -1 else f"{ban_duration}s"
        text = (
            f":unlock: *IP UNBANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Served:* {duration_str} ban\n"
            f"*Offense count:* {offense_count}\n"
            f"*Next ban duration if re-offends:* {next_ban_duration}\n"
            f"*Timestamp:* {self._ts()}"
        )
        self._send(text)

    def send_global_alert(
        self,
        condition: str,
        current_rate: float,
        baseline_mean: float,
        baseline_stddev: float,
    ):
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"*Condition:* {condition}\n"
            f"*Current global rate:* {current_rate:.2f} req/s\n"
            f"*Baseline mean:* {baseline_mean:.2f} req/s\n"
            f"*Baseline stddev:* {baseline_stddev:.2f}\n"
            f"*Timestamp:* {self._ts()}"
        )
        self._send(text)
