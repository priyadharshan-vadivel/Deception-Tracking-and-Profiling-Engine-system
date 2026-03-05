"""
profiler_api.py
Main Flask REST API for the Deception Tracking and Profiling Engine.

Endpoints:
  POST /api/event          - Ingest a security event from any monitored server
  GET  /api/profile/<ip>   - Get attacker profile by IP
  GET  /api/profiles       - List all attacker profiles
  GET  /api/events         - List recent events
  GET  /api/actions        - List recent triggered actions
  GET  /api/stats          - System statistics
  GET  /api/config/scoring - Return scoring rules (for admin inspection)
  DELETE /api/profile/<ip> - Reset an attacker profile (testing use)
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, abort

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database_manager import DatabaseManager
from scoring_engine import ScoringEngine
from decision_engine import DecisionEngine

# ──────────────────────────── CONFIGURATION ───────────────────────────────────

CONFIG_PATH = os.environ.get(
    "PROFILER_CONFIG",
    os.path.join(os.path.dirname(__file__), "..", "config", "config.json")
)

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

# ──────────────────────────── LOGGING SETUP ───────────────────────────────────

log_dir = os.path.dirname(CONFIG["profiler"]["log_path"])
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(CONFIG["profiler"]["log_path"]),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("profiler_api")

# ──────────────────────────── COMPONENT INIT ──────────────────────────────────

db = DatabaseManager(CONFIG["profiler"]["database_path"])
scoring = ScoringEngine(CONFIG)
decision = DecisionEngine(CONFIG, db)

app = Flask(__name__)
API_KEY = CONFIG["profiler"]["api_key"]

# ──────────────────────────── AUTH DECORATOR ──────────────────────────────────

def require_api_key(f):
    """Simple API key authentication for event sources."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY:
            logger.warning(f"Unauthorized API access attempt from {request.remote_addr}")
            abort(401, description="Invalid or missing API key")
        return f(*args, **kwargs)
    return decorated

# ──────────────────────────── EVENT INGESTION ─────────────────────────────────

@app.route("/api/event", methods=["POST"])
@require_api_key
def ingest_event():
    """
    Primary event ingestion endpoint.

    Expected JSON body:
    {
        "src_ip":     "192.168.56.102",
        "event_type": "syn_scan",
        "severity":   5.0,
        "timestamp":  "2024-01-15T10:30:00",   (optional, defaults to now)
        "details":    "nmap SYN scan detected", (optional)
        "source":     "server1"                 (optional, identifies the reporting server)
    }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    # Validate required fields
    src_ip = data.get("src_ip", "").strip()
    event_type = data.get("event_type", "").strip()
    severity = data.get("severity", 1.0)

    if not src_ip or not event_type:
        return jsonify({"error": "src_ip and event_type are required"}), 400

    # Use provided timestamp or current UTC time
    timestamp = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    details = data.get("details", "")
    source_server = data.get("source", "unknown")

    logger.info(f"[EVENT] Received: {event_type} from {src_ip} via {source_server}")

    # Store raw event
    db.insert_event(src_ip, event_type, float(severity), timestamp, details, source_server)

    # Load or initialize attacker profile
    profile = db.get_attacker_profile(src_ip)
    if profile:
        previous_score = profile["risk_score"]
        last_seen = profile["last_seen"]
        event_count = profile["event_count"] + 1
        event_type_stats = profile.get("event_type_stats", {})
        redirected = profile.get("redirected", 0)
        noise_active = profile.get("noise_active", 0)
        forensic_captured = profile.get("forensic_captured", 0)
    else:
        previous_score = 0.0
        last_seen = timestamp
        event_count = 1
        event_type_stats = {}
        redirected = 0
        noise_active = 0
        forensic_captured = 0

    # Update event type statistics
    event_type_stats[event_type] = event_type_stats.get(event_type, 0) + 1

    # Calculate new score (applies time decay then adds event weight)
    new_score = scoring.calculate_new_score(previous_score, last_seen, event_type, float(severity))

    # Determine updated status
    new_status = scoring.determine_status(new_score)

    # Evaluate which threshold actions need to be triggered
    current_flags = {
        "redirected": redirected,
        "noise_active": noise_active,
        "forensic_captured": forensic_captured
    }
    actions_to_trigger = scoring.evaluate_thresholds(new_score, previous_score, current_flags)

    # Update flags based on actions about to be triggered
    if "redirect_to_decoy" in actions_to_trigger:
        redirected = 1
    if "noise_injection" in actions_to_trigger:
        noise_active = 1
    if "forensic_snapshot" in actions_to_trigger:
        forensic_captured = 1

    # Persist updated profile
    db.upsert_attacker_profile(
        src_ip=src_ip,
        risk_score=new_score,
        status=new_status,
        event_count=event_count,
        event_type_stats=event_type_stats,
        redirected=redirected,
        noise_active=noise_active,
        forensic_captured=forensic_captured
    )

    # Execute defensive actions asynchronously
    if actions_to_trigger:
        updated_profile = db.get_attacker_profile(src_ip)
        decision.process_actions(src_ip, new_score, actions_to_trigger, updated_profile)

    response = {
        "status": "processed",
        "src_ip": src_ip,
        "event_type": event_type,
        "previous_score": round(previous_score, 2),
        "new_score": round(new_score, 2),
        "attacker_status": new_status,
        "actions_triggered": actions_to_trigger,
        "timestamp": timestamp
    }

    logger.info(
        f"[PROFILE] {src_ip} | score: {previous_score:.2f} -> {new_score:.2f} "
        f"| status: {new_status} | actions: {actions_to_trigger}"
    )

    return jsonify(response), 200

# ──────────────────────────── PROFILE ENDPOINTS ───────────────────────────────

@app.route("/api/profile/<src_ip>", methods=["GET"])
@require_api_key
def get_profile(src_ip):
    """Return full attacker profile for a specific IP address."""
    profile = db.get_attacker_profile(src_ip)
    if not profile:
        return jsonify({"error": f"No profile found for {src_ip}"}), 404

    # Attach event history and triggered actions
    profile["recent_events"] = db.get_events_for_ip(src_ip, limit=20)
    profile["triggered_actions"] = db.get_actions_for_ip(src_ip)
    return jsonify(profile), 200


@app.route("/api/profiles", methods=["GET"])
@require_api_key
def list_profiles():
    """Return all attacker profiles, sorted by risk score descending."""
    limit = min(int(request.args.get("limit", 100)), 500)
    profiles = db.get_all_profiles(limit=limit)
    return jsonify({"count": len(profiles), "profiles": profiles}), 200


@app.route("/api/profile/<src_ip>", methods=["DELETE"])
@require_api_key
def delete_profile(src_ip):
    """Reset/delete an attacker profile. Used for testing."""
    with db._get_connection() as conn:
        conn.execute("DELETE FROM attacker_profiles WHERE src_ip = ?", (src_ip,))
        conn.execute("DELETE FROM security_events WHERE src_ip = ?", (src_ip,))
        conn.execute("DELETE FROM triggered_actions WHERE src_ip = ?", (src_ip,))
        conn.commit()
    logger.info(f"Profile and data deleted for {src_ip}")
    return jsonify({"status": "deleted", "src_ip": src_ip}), 200

# ──────────────────────────── EVENTS & ACTIONS ────────────────────────────────

@app.route("/api/events", methods=["GET"])
@require_api_key
def list_events():
    """Return recent security events."""
    limit = min(int(request.args.get("limit", 100)), 1000)
    events = db.get_recent_events(limit=limit)
    return jsonify({"count": len(events), "events": events}), 200


@app.route("/api/actions", methods=["GET"])
@require_api_key
def list_actions():
    """Return recently triggered defensive actions."""
    limit = min(int(request.args.get("limit", 50)), 500)
    actions = db.get_recent_actions(limit=limit)
    return jsonify({"count": len(actions), "actions": actions}), 200

# ──────────────────────────── STATS & ADMIN ───────────────────────────────────

@app.route("/api/stats", methods=["GET"])
@require_api_key
def get_stats():
    """Return aggregate system statistics."""
    stats = db.get_dashboard_stats()
    return jsonify(stats), 200


@app.route("/api/config/scoring", methods=["GET"])
@require_api_key
def get_scoring_config():
    """Return the current scoring configuration."""
    return jsonify(scoring.get_threshold_summary()), 200


@app.route("/api/health", methods=["GET"])
def health_check():
    """Public health check endpoint (no auth required)."""
    return jsonify({
        "status": "running",
        "service": "Deception Profiling Engine",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

# ──────────────────────────── ERROR HANDLERS ──────────────────────────────────

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized", "message": str(e)}), 401


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# ──────────────────────────── ENTRY POINT ─────────────────────────────────────

if __name__ == "__main__":
    host = CONFIG["profiler"]["host"]
    port = CONFIG["profiler"]["port"]
    logger.info(f"Starting Deception Profiling Engine on {host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
