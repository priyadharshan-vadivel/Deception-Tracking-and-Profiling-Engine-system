#!/usr/bin/env python3
"""
init_database.py
Initializes the SQLite database for the Deception Profiling Engine.
Run once during initial deployment.

Usage:
    python3 init_database.py
    python3 init_database.py --reset  (WARNING: deletes all data)
"""

import sqlite3
import json
import os
import sys
import argparse

CONFIG_PATH = os.environ.get(
    "PROFILER_CONFIG",
    os.path.join(os.path.dirname(__file__), "..", "config", "config.json")
)

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

DB_PATH = CONFIG["profiler"]["database_path"]


def init_db(reset=False):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"[!] Database reset: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

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

    conn.executescript(schema)
    conn.commit()
    conn.close()

    print(f"[OK] Database initialized: {DB_PATH}")
    print(f"     Tables: attacker_profiles, security_events, triggered_actions")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize Deception Engine database")
    parser.add_argument("--reset", action="store_true",
                        help="Drop and recreate all tables (DELETES ALL DATA)")
    args = parser.parse_args()

    if args.reset:
        confirm = input("WARNING: This will delete ALL profiling data. Type YES to confirm: ")
        if confirm != "YES":
            print("Aborted.")
            sys.exit(0)

    init_db(reset=args.reset)
