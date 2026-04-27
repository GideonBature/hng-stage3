"""
blocker.py - Manages iptables DROP rules for banned IPs.

Ban state:
- Each IP tracks how many times it has been banned (offense_count)
- Ban duration follows a backoff schedule from config
- If offense_count exceeds the schedule length, the ban is permanent
- All state is kept in memory; iptables rules are the source of truth
  for active blocks
"""

import subprocess
import time
import logging
from threading import Lock
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BanRecord:
    ip: str
    banned_at: float
    duration: int       # seconds; -1 = permanent
    offense_count: int  # how many times this IP has been banned
    condition: str
    unban_at: float = field(init=False)

    def __post_init__(self):
        self.unban_at = (
            self.banned_at + self.duration
            if self.duration != -1
            else float("inf")
        )

    def is_permanent(self) -> bool:
        return self.duration == -1


class Blocker:
    """
    Adds and removes iptables DROP rules.
    Tracks ban history per IP for backoff scheduling.
    """

    def __init__(self, config: dict):
        self._durations: List[int] = config["blocking"]["ban_durations"]
        self._banned: Dict[str, BanRecord] = {}
        self._offense_counts: Dict[str, int] = {}
        self._lock = Lock()
        self._handlers = []  # unbanner callbacks

    def register_unban_handler(self, handler):
        self._handlers.append(handler)

    def ban(self, ip: str, condition: str) -> Optional[BanRecord]:
        """
        Add an iptables DROP rule for the IP and record the ban.
        Returns the BanRecord, or None if already banned.
        """
        with self._lock:
            if ip in self._banned:
                logger.debug(f"IP {ip} already banned, skipping")
                return None

            offense = self._offense_counts.get(ip, 0)
            duration_idx = min(offense, len(self._durations) - 1)
            duration = self._durations[duration_idx]

            record = BanRecord(
                ip=ip,
                banned_at=time.time(),
                duration=duration,
                offense_count=offense + 1,
                condition=condition,
            )
            self._banned[ip] = record
            self._offense_counts[ip] = offense + 1

        self._add_iptables_rule(ip)
        logger.warning(
            f"BANNED {ip}: duration={'permanent' if duration == -1 else f'{duration}s'} "
            f"offense={offense + 1} | {condition}"
        )
        return record

    def unban(self, ip: str) -> Optional[BanRecord]:
        """Remove the iptables rule and return the ban record."""
        with self._lock:
            record = self._banned.pop(ip, None)
        if record:
            self._remove_iptables_rule(ip)
            logger.info(f"UNBANNED {ip} after {record.duration}s")
        return record

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._banned

    def get_banned(self) -> Dict[str, BanRecord]:
        with self._lock:
            return dict(self._banned)

    def get_expired_bans(self) -> List[str]:
        """Return IPs whose non-permanent bans have expired."""
        now = time.time()
        with self._lock:
            return [
                ip for ip, rec in self._banned.items()
                if not rec.is_permanent() and now >= rec.unban_at
            ]

    def _add_iptables_rule(self, ip: str):
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
            )
            logger.info(f"iptables DROP rule added for {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Failed to add iptables rule for {ip}: {e.stderr.decode()}"
            )

    def _remove_iptables_rule(self, ip: str):
        # Remove all matching rules (there may be duplicates)
        while True:
            result = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
            )
            if result.returncode != 0:
                break
        logger.info(f"iptables DROP rule removed for {ip}")
