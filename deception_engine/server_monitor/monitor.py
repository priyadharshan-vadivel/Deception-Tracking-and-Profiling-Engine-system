"""
monitor.py
Server1 monitoring agent.

Watches Apache/Nginx access logs and auth logs for suspicious activity.
Parses detected events and forwards them to the Profiler via REST API.

Run this on Server1 (192.168.56.103) with:
    sudo python3 monitor.py

Requires: requests library
    pip3 install requests
"""

import re
import time
import logging
import os
import sys
import json
from datetime import datetime, timezone

# Import sibling modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from event_parser import EventParser
from event_sender import EventSender

# ──────────────────────────── CONFIG ──────────────────────────────────────────

CONFIG_PATH = os.environ.get(
    "PROFILER_CONFIG",
    os.path.join(os.path.dirname(__file__), "..", "config", "config.json")
)

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

LOG_FILES = {
    "/var/log/apache2/access.log": "apache_access",
    "/var/log/apache2/error.log": "apache_error",
    "/var/log/auth.log": "auth_log",
    "/var/log/syslog": "syslog",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("/var/log/deception_engine/server_monitor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("server_monitor")


class LogTailer:
    """
    Tails a log file and yields new lines as they are written.
    Handles log rotation by tracking file inode.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file = None
        self.inode = None
        self._open()

    def _open(self):
        """Open or reopen the log file."""
        try:
            self.file = open(self.filepath, "r")
            self.file.seek(0, 2)  # Seek to end of file
            self.inode = os.stat(self.filepath).st_ino
            logger.info(f"Tailing: {self.filepath}")
        except FileNotFoundError:
            logger.warning(f"Log file not found: {self.filepath}")
            self.file = None
            self.inode = None

    def readlines(self):
        """Return any new lines since last read. Handles rotation."""
        if not self.file:
            self._open()
            return []

        # Check for log rotation (inode changed)
        try:
            current_inode = os.stat(self.filepath).st_ino
            if current_inode != self.inode:
                logger.info(f"Log rotated detected: {self.filepath}")
                self.file.close()
                self._open()
        except FileNotFoundError:
            return []

        lines = []
        try:
            while True:
                line = self.file.readline()
                if not line:
                    break
                lines.append(line.rstrip())
        except Exception as e:
            logger.error(f"Error reading {self.filepath}: {e}")
        return lines


class ServerMonitor:
    """
    Main monitoring loop for Server1.
    Coordinates log tailing, event parsing, and event forwarding.
    """

    def __init__(self, config: dict):
        self.config = config
        self.parser = EventParser(config)
        self.sender = EventSender(config)
        self.tailers = {}
        self.poll_interval = 2  # seconds between log polls
        self._init_tailers()

    def _init_tailers(self):
        """Initialize a LogTailer for each monitored log file."""
        for path, log_type in LOG_FILES.items():
            if os.path.exists(path):
                self.tailers[path] = (LogTailer(path), log_type)
            else:
                logger.warning(f"Skipping missing log: {path}")

    def run(self):
        """Main monitoring loop."""
        logger.info("Server1 monitoring agent started")
        logger.info(f"Sending events to: {self.sender.profiler_url}")

        while True:
            for path, (tailer, log_type) in self.tailers.items():
                lines = tailer.readlines()
                for line in lines:
                    self._process_line(line, log_type)

            time.sleep(self.poll_interval)

    def _process_line(self, line: str, log_type: str):
        """Parse a log line and send an event if suspicious."""
        event = self.parser.parse_line(line, log_type)
        if event:
            logger.info(f"[DETECTED] {event['event_type']} from {event['src_ip']}")
            result = self.sender.send_event(event)
            if result:
                logger.info(f"[SENT] Event forwarded. Score: {result.get('new_score')}")
            else:
                logger.warning("[SEND FAILED] Event not delivered to profiler")


# ──────────────────────────── ENTRY POINT ─────────────────────────────────────

if __name__ == "__main__":
    os.makedirs("/var/log/deception_engine", exist_ok=True)
    monitor = ServerMonitor(CONFIG)
    try:
        monitor.run()
    except KeyboardInterrupt:
        logger.info("Monitor stopped by user")
