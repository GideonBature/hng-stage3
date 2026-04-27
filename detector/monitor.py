"""
monitor.py - Continuously tails the Nginx JSON access log and emits parsed
log entries to registered callbacks. Uses a tail-like approach with seek to
handle log rotation gracefully.
"""

import json
import os
import time
import logging
from typing import Callable, Dict, Any

logger = logging.getLogger(__name__)


class LogEntry:
    """Represents a single parsed Nginx access log line."""

    def __init__(self, raw: Dict[str, Any]):
        self.source_ip: str = raw.get("source_ip", "unknown")
        self.timestamp: str = raw.get("timestamp", "")
        self.method: str = raw.get("method", "")
        self.path: str = raw.get("path", "")
        self.status: int = int(raw.get("status", 0))
        self.response_size: int = int(raw.get("response_size", 0))
        self.time_epoch: float = time.time()

    def is_error(self) -> bool:
        return self.status >= 400


class LogMonitor:
    """
    Tails the Nginx access log line by line.
    Calls registered handlers for each parsed log entry.
    Handles log rotation by detecting file inode changes.
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._handlers: list[Callable[[LogEntry], None]] = []
        self._running = False
        self._current_inode = None
        self._file = None

    def register_handler(self, handler: Callable[[LogEntry], None]):
        """Register a callback that receives every parsed LogEntry."""
        self._handlers.append(handler)

    def _emit(self, entry: LogEntry):
        for handler in self._handlers:
            try:
                handler(entry)
            except Exception as e:
                logger.error(f"Handler error: {e}")

    def _parse_line(self, line: str):
        line = line.strip()
        if not line:
            return
        try:
            raw = json.loads(line)
            entry = LogEntry(raw)
            self._emit(entry)
        except json.JSONDecodeError:
            logger.debug(f"Non-JSON log line skipped: {line[:80]}")
        except Exception as e:
            logger.warning(f"Failed to parse log line: {e}")

    def _open_log(self):
        """Open the log file and seek to end for initial open."""
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
        self._file = open(self.log_path, "r")
        self._file.seek(0, 2)  # Seek to end
        stat = os.stat(self.log_path)
        self._current_inode = stat.st_ino
        logger.info(f"Opened log file: {self.log_path} (inode {self._current_inode})")

    def _check_rotation(self) -> bool:
        """Return True if the log file has been rotated."""
        try:
            stat = os.stat(self.log_path)
            return stat.st_ino != self._current_inode
        except FileNotFoundError:
            return True

    def run(self):
        """
        Main loop. Blocks forever, tailing the log file.
        Waits for the file to exist if it does not yet.
        """
        self._running = True
        logger.info(f"LogMonitor waiting for log file: {self.log_path}")

        while self._running:
            # Wait for log file to appear
            if not os.path.exists(self.log_path):
                time.sleep(1)
                continue

            try:
                self._open_log()
            except Exception as e:
                logger.error(f"Could not open log file: {e}")
                time.sleep(2)
                continue

            logger.info("LogMonitor started tailing log")

            while self._running:
                line = self._file.readline()
                if line:
                    self._parse_line(line)
                else:
                    # No new line — check for rotation
                    if self._check_rotation():
                        logger.info("Log rotation detected, reopening file")
                        break
                    time.sleep(0.05)  # 50ms poll interval

        if self._file:
            self._file.close()
        logger.info("LogMonitor stopped")

    def stop(self):
        self._running = False
