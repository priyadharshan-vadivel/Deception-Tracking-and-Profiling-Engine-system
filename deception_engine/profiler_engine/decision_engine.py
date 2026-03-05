"""
decision_engine.py
Evaluates risk thresholds and executes automated defensive responses.

Actions implemented:
  - mark_suspicious:   Update profile status
  - redirect_to_decoy: Insert iptables DNAT on Server1 so attacker traffic
                       is silently forwarded to Decoy (attacker never knows)
  - noise_injection:   Write fake log entries to confuse attacker
  - forensic_snapshot: Full JSON dump of attacker profile, events, and network state
"""

import subprocess
import json
import logging
import os
import threading
from datetime import datetime

logger = logging.getLogger(__name__)


class DecisionEngine:
    """
    Evaluates attacker risk scores against thresholds and executes
    appropriate defensive actions automatically.
    """

    def __init__(self, config: dict, db_manager):
        self.config = config
        self.db = db_manager
        self.network = config["network"]
        self.thresholds = config["thresholds"]
        self.forensic_dir = config["actions"]["forensic_snapshot_dir"]
        os.makedirs(self.forensic_dir, exist_ok=True)

    def process_actions(self, src_ip: str, score: float,
                        actions_to_trigger: list, profile: dict):
        """
        Execute each action in the provided list for the given attacker IP.
        """
        for action in actions_to_trigger:
            try:
                logger.info(f"[ACTION] Triggering '{action}' for {src_ip} (score={score:.2f})")
                success, details = self._execute_action(action, src_ip, score, profile)
                self.db.insert_action(src_ip, action, score, int(success), details)

                if success:
                    logger.info(f"[ACTION] '{action}' succeeded for {src_ip}: {details}")
                else:
                    logger.warning(f"[ACTION] '{action}' failed for {src_ip}: {details}")

            except Exception as e:
                logger.error(f"[ACTION] Exception executing '{action}' for {src_ip}: {e}")
                self.db.insert_action(src_ip, action, score, 0, str(e))

    def _execute_action(self, action: str, src_ip: str, score: float,
                        profile: dict) -> tuple:
        handlers = {
            "mark_suspicious":   self._action_mark_suspicious,
            "redirect_to_decoy": self._action_redirect_to_decoy,
            "noise_injection":   self._action_noise_injection,
            "forensic_snapshot": self._action_forensic_snapshot,
        }
        handler = handlers.get(action)
        if handler:
            return handler(src_ip, score, profile)
        return False, f"Unknown action: {action}"

    # ─────────────────────────── ACTION HANDLERS ──────────────────────────────

    def _action_mark_suspicious(self, src_ip: str, score: float,
                                 profile: dict) -> tuple:
        details = f"Attacker {src_ip} marked suspicious at score {score:.2f}"
        logger.warning(f"[SUSPICIOUS] {details}")
        return True, details

    def _action_redirect_to_decoy(self, src_ip: str, score: float,
                                   profile: dict) -> tuple:
        """
        Silently redirect attacker traffic from Server1 to the Decoy server
        using iptables DNAT rules.

        The attacker's browser still shows Server1 IP (192.168.56.103) but
        all HTTP responses come from the Decoy (192.168.56.106).
        The attacker has no idea they have been redirected.

        Method 1: Direct iptables (if this code runs ON Server1)
        Method 2: Run redirect.sh via subprocess (if on same machine)
        Method 3: SSH to Server1 (if running on Profiler)
        """
        decoy_ip   = self.network["decoy_ip"]
        server1_ip = self.network["server1_ip"]
        port       = self.config["actions"]["redirect_port"]

        # ── Try direct iptables first (works if running on Server1) ──
        try:
            # DNAT rule: redirect attacker packets to Decoy
            cmd_dnat = [
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-s", src_ip, "-p", "tcp", "--dport", str(port),
                "-j", "DNAT", "--to-destination", f"{decoy_ip}:{port}"
            ]
            # FORWARD rule: allow forwarded packets
            cmd_fwd = [
                "iptables", "-A", "FORWARD",
                "-s", src_ip, "-p", "tcp", "--dport", str(port),
                "-j", "ACCEPT"
            ]
            # MASQUERADE: fix return path so Decoy replies reach attacker
            cmd_masq = [
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-d", decoy_ip, "-p", "tcp", "--dport", str(port),
                "-j", "MASQUERADE"
            ]

            subprocess.run(cmd_dnat, check=True, capture_output=True, timeout=5)
            subprocess.run(cmd_fwd,  check=False, capture_output=True, timeout=5)
            subprocess.run(cmd_masq, check=False, capture_output=True, timeout=5)

            details = (
                f"iptables DNAT rule installed: {src_ip}:{port} -> {decoy_ip}:{port}. "
                f"Attacker sees Server1 but gets Decoy content."
            )
            logger.warning(f"[REDIRECT] {details}")
            return True, details

        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode().strip() if e.stderr else ""
            logger.warning(f"[REDIRECT] Direct iptables failed ({stderr}). Trying redirect script...")

        # ── Try redirect.sh script (alternative method) ──
        redirect_script = os.path.join(
            os.path.dirname(__file__), "..", "scripts", "redirect.sh"
        )
        redirect_script = os.path.abspath(redirect_script)

        if os.path.exists(redirect_script):
            try:
                result = subprocess.run(
                    ["bash", redirect_script, src_ip],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    details = f"Redirect via script: {src_ip} -> {decoy_ip}:{port}"
                    return True, details
            except Exception as e:
                logger.warning(f"[REDIRECT] Script method failed: {e}")

        # ── Fallback: log the manual command ──
        manual_cmd = (
            f"Run on Server1: sudo iptables -t nat -A PREROUTING "
            f"-s {src_ip} -p tcp --dport {port} "
            f"-j DNAT --to-destination {decoy_ip}:{port}"
        )
        logger.warning(f"[REDIRECT] Manual action required: {manual_cmd}")
        return False, f"iptables requires root on Server1. {manual_cmd}"

    def _action_noise_injection(self, src_ip: str, score: float,
                                 profile: dict) -> tuple:
        """
        Spawn a background thread that writes fake log entries to
        confuse forensic analysis by the attacker.
        """
        logger.warning(f"[NOISE] Enabling noise injection for {src_ip}")
        noise_thread = threading.Thread(
            target=self._noise_worker, args=(src_ip,), daemon=True
        )
        noise_thread.start()
        return True, f"Noise injection thread started for {src_ip}"

    def _noise_worker(self, src_ip: str):
        import time
        noise_entries = [
            f"[FAKE] User 'admin' logged in successfully from {src_ip}",
            f"[FAKE] Database backup started by session from {src_ip}",
            f"[FAKE] File /etc/shadow read from {src_ip}",
            f"[FAKE] New cronjob registered by {src_ip}",
            f"[FAKE] Sudo access granted to session from {src_ip}",
        ]
        noise_log = os.path.join(
            self.forensic_dir, f"noise_{src_ip.replace('.', '_')}.log"
        )
        with open(noise_log, "a") as f:
            for entry in noise_entries:
                f.write(f"[{datetime.utcnow().isoformat()}] {entry}\n")
                time.sleep(0.3)
        logger.info(f"[NOISE] Noise log written to {noise_log}")

    def _action_forensic_snapshot(self, src_ip: str, score: float,
                                   profile: dict) -> tuple:
        """
        Generate a full forensic snapshot:
        - Attacker profile
        - All recorded events
        - All triggered actions
        - Active network connections
        - iptables ruleset at time of capture
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        snapshot_file = os.path.join(
            self.forensic_dir,
            f"forensic_{src_ip.replace('.', '_')}_{timestamp}.json"
        )

        snapshot = {
            "snapshot_time":    datetime.utcnow().isoformat(),
            "attacker_ip":      src_ip,
            "score_at_capture": score,
            "profile":          profile,
            "events":           self.db.get_events_for_ip(src_ip, limit=500),
            "actions":          self.db.get_actions_for_ip(src_ip),
            "network_connections": self._capture_connections(src_ip),
            "iptables_nat_rules":  self._capture_iptables(),
        }

        try:
            with open(snapshot_file, "w") as f:
                json.dump(snapshot, f, indent=2, default=str)
            details = f"Forensic snapshot saved: {snapshot_file}"
            logger.critical(f"[FORENSIC] {details}")
            return True, details
        except IOError as e:
            return False, f"Failed to write snapshot: {e}"

    def _capture_connections(self, src_ip: str) -> str:
        try:
            result = subprocess.run(
                ["ss", "-tnp"],
                capture_output=True, text=True, timeout=5
            )
            lines = [l for l in result.stdout.splitlines() if src_ip in l]
            return "\n".join(lines) if lines else "No active connections found"
        except Exception as e:
            return f"Could not capture connections: {e}"

    def _capture_iptables(self) -> str:
        try:
            result = subprocess.run(
                ["iptables", "-t", "nat", "-L", "-n", "-v"],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout or "No iptables rules"
        except Exception as e:
            return f"Could not capture iptables: {e}"

    def remove_redirect_rule(self, src_ip: str) -> bool:
        """Remove a previously installed DNAT redirect rule."""
        decoy_ip = self.network["decoy_ip"]
        port     = self.config["actions"]["redirect_port"]
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-s", src_ip, "-p", "tcp", "--dport", str(port),
                "-j", "DNAT", "--to-destination", f"{decoy_ip}:{port}"
            ], check=True, capture_output=True, timeout=5)
            logger.info(f"[REDIRECT] Removed redirect rule for {src_ip}")
            return True
        except subprocess.CalledProcessError:
            return False
