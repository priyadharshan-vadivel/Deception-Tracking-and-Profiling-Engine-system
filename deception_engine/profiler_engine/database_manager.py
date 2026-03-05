"""
database_manager.py
Manages all SQLite database operations for the Deception Profiling Engine.
Handles attacker profiles, security events, and triggered actions.
"""

import sqlite3
import json
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Centralized database access layer using SQLite."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        # Ensure the directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._initialize_database()

    def _get_connection(self):
        """Return a new SQLite connection with row factory enabled."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for concurrency
        return conn

    def _initialize_database(self):
        """Create all required tables if they do not already exist."""
        schema = """
        CREATE TABLE IF NOT EXISTS attacker_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT UNIQUE NOT NULL,
            risk_score REAL DEFAULT 0.0,
            status TEXT DEFAULT 'unknown',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            event_count INTEGER DEFAULT 0,
            event_type_stats TEXT DEFAULT '{}',
            redirected INTEGER DEFAULT 0,
            noise_active INTEGER DEFAULT 0,
            forensic_captured INTEGER DEFAULT 0,
            notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity REAL NOT NULL,
            timestamp TEXT NOT NULL,
            details TEXT DEFAULT '',
            source_server TEXT DEFAULT 'unknown',
            processed INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS triggered_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT NOT NULL,
            action_type TEXT NOT NULL,
            triggered_at TEXT NOT NULL,
            score_at_trigger REAL NOT NULL,
            success INTEGER DEFAULT 0,
            details TEXT DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_events_src_ip ON security_events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_profiles_score ON attacker_profiles(risk_score DESC);
        """
        with self._get_connection() as conn:
            conn.executescript(schema)
            conn.commit()
        logger.info(f"Database initialized at {self.db_path}")

    # ─────────────────────────── ATTACKER PROFILES ────────────────────────────

    def upsert_attacker_profile(self, src_ip: str, risk_score: float,
                                 status: str, event_count: int,
                                 event_type_stats: dict,
                                 redirected: int = 0,
                                 noise_active: int = 0,
                                 forensic_captured: int = 0):
        """Insert a new attacker profile or update an existing one."""
        now = datetime.utcnow().isoformat()
        stats_json = json.dumps(event_type_stats)
        with self._get_connection() as conn:
            existing = conn.execute(
                "SELECT id, first_seen FROM attacker_profiles WHERE src_ip = ?",
                (src_ip,)
            ).fetchone()

            if existing:
                conn.execute("""
                    UPDATE attacker_profiles
                    SET risk_score=?, status=?, last_seen=?, event_count=?,
                        event_type_stats=?, redirected=?, noise_active=?,
                        forensic_captured=?
                    WHERE src_ip=?
                """, (risk_score, status, now, event_count, stats_json,
                      redirected, noise_active, forensic_captured, src_ip))
            else:
                conn.execute("""
                    INSERT INTO attacker_profiles
                    (src_ip, risk_score, status, first_seen, last_seen,
                     event_count, event_type_stats, redirected, noise_active,
                     forensic_captured)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (src_ip, risk_score, status, now, now, event_count,
                      stats_json, redirected, noise_active, forensic_captured))
            conn.commit()

    def get_attacker_profile(self, src_ip: str):
        """Retrieve attacker profile by IP. Returns dict or None."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM attacker_profiles WHERE src_ip = ?", (src_ip,)
            ).fetchone()
        if row:
            profile = dict(row)
            profile['event_type_stats'] = json.loads(profile.get('event_type_stats', '{}'))
            return profile
        return None

    def get_all_profiles(self, limit: int = 100, order_by: str = "risk_score DESC"):
        """Return all attacker profiles ordered by risk score."""
        with self._get_connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM attacker_profiles ORDER BY {order_by} LIMIT ?",
                (limit,)
            ).fetchall()
        profiles = []
        for row in rows:
            p = dict(row)
            p['event_type_stats'] = json.loads(p.get('event_type_stats', '{}'))
            profiles.append(p)
        return profiles

    def get_profile_count(self):
        """Return total number of tracked attackers."""
        with self._get_connection() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM attacker_profiles"
            ).fetchone()[0]

    # ──────────────────────────── SECURITY EVENTS ─────────────────────────────

    def insert_event(self, src_ip: str, event_type: str, severity: float,
                     timestamp: str, details: str = '', source_server: str = 'unknown'):
        """Store a new security event in the database."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO security_events
                (src_ip, event_type, severity, timestamp, details, source_server)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (src_ip, event_type, severity, timestamp, details, source_server))
            conn.commit()
            return cursor.lastrowid

    def get_events_for_ip(self, src_ip: str, limit: int = 50):
        """Return recent events for a specific IP address."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM security_events
                WHERE src_ip = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (src_ip, limit)).fetchall()
        return [dict(row) for row in rows]

    def get_recent_events(self, limit: int = 100):
        """Return the most recent events across all attackers."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM security_events
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(row) for row in rows]

    def get_event_count(self):
        """Return total event count."""
        with self._get_connection() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM security_events"
            ).fetchone()[0]

    # ──────────────────────────── TRIGGERED ACTIONS ───────────────────────────

    def insert_action(self, src_ip: str, action_type: str, score_at_trigger: float,
                      success: int = 1, details: str = ''):
        """Log a triggered defensive action."""
        now = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO triggered_actions
                (src_ip, action_type, triggered_at, score_at_trigger, success, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (src_ip, action_type, now, score_at_trigger, success, details))
            conn.commit()
            return cursor.lastrowid

    def get_actions_for_ip(self, src_ip: str):
        """Return all actions triggered against a specific IP."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM triggered_actions
                WHERE src_ip = ?
                ORDER BY triggered_at DESC
            """, (src_ip,)).fetchall()
        return [dict(row) for row in rows]

    def get_recent_actions(self, limit: int = 50):
        """Return the most recently triggered actions."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM triggered_actions
                ORDER BY triggered_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(row) for row in rows]

    def get_action_count(self):
        """Return total triggered actions count."""
        with self._get_connection() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM triggered_actions"
            ).fetchone()[0]

    # ──────────────────────────── STATISTICS ──────────────────────────────────

    def get_dashboard_stats(self):
        """Return aggregate statistics for the dashboard."""
        with self._get_connection() as conn:
            total_attackers = conn.execute(
                "SELECT COUNT(*) FROM attacker_profiles"
            ).fetchone()[0]

            total_events = conn.execute(
                "SELECT COUNT(*) FROM security_events"
            ).fetchone()[0]

            high_risk = conn.execute(
                "SELECT COUNT(*) FROM attacker_profiles WHERE risk_score >= 70"
            ).fetchone()[0]

            redirected = conn.execute(
                "SELECT COUNT(*) FROM attacker_profiles WHERE redirected = 1"
            ).fetchone()[0]

            total_actions = conn.execute(
                "SELECT COUNT(*) FROM triggered_actions"
            ).fetchone()[0]

        return {
            "total_attackers": total_attackers,
            "total_events": total_events,
            "high_risk_attackers": high_risk,
            "redirected_attackers": redirected,
            "total_actions": total_actions
        }
