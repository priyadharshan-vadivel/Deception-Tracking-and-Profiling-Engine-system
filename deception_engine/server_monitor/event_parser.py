"""
event_parser.py
Parses raw log lines from Apache, auth logs, and syslog into
structured security event dictionaries ready for the Profiler API.
"""

import re
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class EventParser:
    """
    Detects suspicious patterns in log lines and converts them to
    normalized security events.
    """

    def __init__(self, config: dict):
        self.config = config
        self.weights = config["scoring"]["event_weights"]
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile all detection regex patterns."""

        # Apache access log format:
        # 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
        self.apache_access_re = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - .* "(?P<method>[A-Z]+) (?P<path>\S+) HTTP[^"]*" '
            r'(?P<status>\d+) (?P<size>\S+)'
        )

        # Auth log failed password pattern
        self.auth_failed_re = re.compile(
            r'Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        )

        # Auth log invalid user pattern
        self.auth_invalid_re = re.compile(
            r'Invalid user \S+ from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        )

        # Brute force detection: rapid successive failures tracked externally
        # For pattern matching, we check for hydra/medusa user-agent patterns
        self.hydra_ua_re = re.compile(r'(?i)(hydra|medusa|ncrack|brutus|burpsuite)')

        # Directory enumeration patterns (gobuster, dirb, dirbuster)
        self.dir_enum_re = re.compile(
            r'(?i)(gobuster|dirb|dirbuster|nikto|wfuzz|ffuf|feroxbuster)'
        )

        # Common enumeration path patterns
        self.suspicious_path_re = re.compile(
            r'(?i)(\.git|\.env|wp-admin|wp-config|\.htaccess|\.htpasswd|'
            r'etc/passwd|etc/shadow|/admin|/phpmyadmin|/manager|/console|'
            r'/actuator|/api/v1|backup|config\.php|web\.config)'
        )

        # SQL injection patterns
        self.sqli_re = re.compile(
            r"(?i)(union.+select|select.+from|insert.+into|'--|\bor\b.+\b1=1\b|"
            r"xp_cmdshell|exec\(|sleep\(|benchmark\()"
        )

        # XSS patterns
        self.xss_re = re.compile(
            r"(?i)(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)"
        )

        # nmap SYN scan user agent / patterns
        self.nmap_re = re.compile(r'(?i)(nmap|masscan)')

        # Honeytoken paths (fake sensitive files placed on server)
        self.honeytoken_paths = [
            "/secret-backup.zip",
            "/database-dump.sql",
            "/passwords.txt",
            "/admin-credentials.json",
            "/private-key.pem",
            "/config/database.yml",
            "/.env.backup",
            "/honeytokens/",
        ]

        # Track per-IP failure counts for brute force detection
        self._ip_failure_counts = {}
        self._ip_last_reset = {}

    def parse_line(self, line: str, log_type: str) -> dict | None:
        """
        Parse a single log line and return a security event dict, or None
        if the line contains no suspicious indicators.
        """
        if log_type in ("apache_access", "nginx_access"):
            return self._parse_apache_access(line)
        elif log_type in ("auth_log",):
            return self._parse_auth_log(line)
        elif log_type == "syslog":
            return self._parse_syslog(line)
        return None

    def _parse_apache_access(self, line: str) -> dict | None:
        """Parse an Apache/Nginx access log line."""
        m = self.apache_access_re.match(line)
        if not m:
            return None

        ip = m.group("ip")
        method = m.group("method")
        path = m.group("path")
        status = int(m.group("status"))

        # Skip localhost and known internal IPs
        if ip.startswith("127.") or ip.startswith("10.0.2."):
            return None

        # Detect honeytoken access (highest severity)
        for hpath in self.honeytoken_paths:
            if hpath in path:
                return self._make_event(
                    src_ip=ip,
                    event_type="honeytoken_access",
                    severity=self.weights.get("honeytoken_access", 25),
                    details=f"Honeytoken accessed: {path} [{status}]",
                    raw_line=line
                )

        # Detect SQL injection in URL
        if self.sqli_re.search(path):
            return self._make_event(
                src_ip=ip,
                event_type="sql_injection",
                severity=self.weights.get("sql_injection", 12),
                details=f"SQL injection attempt: {method} {path} [{status}]",
                raw_line=line
            )

        # Detect XSS in URL
        if self.xss_re.search(path):
            return self._make_event(
                src_ip=ip,
                event_type="xss_attempt",
                severity=self.weights.get("xss_attempt", 8),
                details=f"XSS attempt: {method} {path} [{status}]",
                raw_line=line
            )

        # Detect directory enumeration by user-agent
        if self.dir_enum_re.search(line):
            return self._make_event(
                src_ip=ip,
                event_type="directory_enumeration",
                severity=self.weights.get("directory_enumeration", 6),
                details=f"Directory enumeration detected: {method} {path} [{status}]",
                raw_line=line
            )

        # Detect suspicious path access
        if self.suspicious_path_re.search(path):
            return self._make_event(
                src_ip=ip,
                event_type="directory_enumeration",
                severity=self.weights.get("directory_enumeration", 6),
                details=f"Suspicious path probe: {method} {path} [{status}]",
                raw_line=line
            )

        # Detect nmap scanning via user agent
        if self.nmap_re.search(line):
            return self._make_event(
                src_ip=ip,
                event_type="syn_scan",
                severity=self.weights.get("syn_scan", 5),
                details=f"nmap/masscan detected via user-agent: {path}",
                raw_line=line
            )

        # Detect hydra/brute force via user agent
        if self.hydra_ua_re.search(line):
            return self._make_event(
                src_ip=ip,
                event_type="brute_force",
                severity=self.weights.get("brute_force", 15),
                details=f"Brute force tool detected in request: {path}",
                raw_line=line
            )

        # Track 404 sequences as potential scanning
        if status == 404:
            count = self._increment_probe_count(ip)
            if count >= 10:  # 10+ 404s = directory enumeration
                self._reset_probe_count(ip)
                return self._make_event(
                    src_ip=ip,
                    event_type="directory_enumeration",
                    severity=self.weights.get("directory_enumeration", 6),
                    details=f"Multiple 404 responses detected ({count} probes): {path}",
                    raw_line=line
                )

        # Track 401/403 sequences as authentication probing
        if status in (401, 403):
            count = self._increment_failure_count(ip)
            if count >= 5:
                self._reset_failure_count(ip)
                return self._make_event(
                    src_ip=ip,
                    event_type="brute_force",
                    severity=self.weights.get("brute_force", 15),
                    details=f"Repeated auth failures ({count}): {method} {path}",
                    raw_line=line
                )

        return None

    def _parse_auth_log(self, line: str) -> dict | None:
        """Parse /var/log/auth.log for SSH brute force attempts."""

        # Failed password attempt
        m = self.auth_failed_re.search(line)
        if m:
            ip = m.group("ip")
            count = self._increment_failure_count(ip)

            if count >= 5:
                self._reset_failure_count(ip)
                return self._make_event(
                    src_ip=ip,
                    event_type="brute_force",
                    severity=self.weights.get("brute_force", 15),
                    details=f"SSH brute force detected ({count} failures)",
                    raw_line=line
                )
            else:
                return self._make_event(
                    src_ip=ip,
                    event_type="failed_login",
                    severity=self.weights.get("failed_login", 3),
                    details=f"SSH login failure #{count}",
                    raw_line=line
                )

        # Invalid user attempt
        m = self.auth_invalid_re.search(line)
        if m:
            ip = m.group("ip")
            return self._make_event(
                src_ip=ip,
                event_type="ssh_attempt",
                severity=self.weights.get("ssh_attempt", 4),
                details="SSH invalid user attempt",
                raw_line=line
            )

        return None

    def _parse_syslog(self, line: str) -> dict | None:
        """Parse syslog for privilege escalation or unusual activity."""
        # sudo commands from non-standard sessions
        if "sudo" in line and "COMMAND" in line:
            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                return self._make_event(
                    src_ip=ip,
                    event_type="privilege_escalation",
                    severity=self.weights.get("privilege_escalation", 20),
                    details=f"Sudo command detected: {line[:100]}",
                    raw_line=line
                )
        return None

    # ─────────────────────────── HELPERS ──────────────────────────────────────

    def _make_event(self, src_ip: str, event_type: str, severity: float,
                     details: str, raw_line: str = "") -> dict:
        """Build a normalized event dictionary."""
        return {
            "src_ip": src_ip,
            "event_type": event_type,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
            "source": "server1"
        }

    def _increment_failure_count(self, ip: str) -> int:
        self._ip_failure_counts[ip] = self._ip_failure_counts.get(ip, 0) + 1
        return self._ip_failure_counts[ip]

    def _reset_failure_count(self, ip: str):
        self._ip_failure_counts[ip] = 0

    def _increment_probe_count(self, ip: str) -> int:
        key = f"probe_{ip}"
        self._ip_failure_counts[key] = self._ip_failure_counts.get(key, 0) + 1
        return self._ip_failure_counts[key]

    def _reset_probe_count(self, ip: str):
        self._ip_failure_counts[f"probe_{ip}"] = 0
