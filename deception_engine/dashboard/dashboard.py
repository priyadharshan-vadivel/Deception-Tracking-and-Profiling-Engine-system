"""
dashboard.py
Real-time web dashboard for the Deception Tracking and Profiling Engine.
Displays attacker profiles, risk scores, events, and triggered actions.

Run on the Profiler server:
    python3 dashboard.py

Access at: http://192.168.56.200:8080
"""

import json
import logging
import os
import sys
from datetime import datetime

from flask import Flask, render_template_string, jsonify, request

# Import database manager from profiler engine
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "profiler_engine"))
from database_manager import DatabaseManager

# ──────────────────────────── CONFIG & SETUP ──────────────────────────────────

CONFIG_PATH = os.environ.get(
    "PROFILER_CONFIG",
    os.path.join(os.path.dirname(__file__), "..", "config", "config.json")
)

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dashboard")

db = DatabaseManager(CONFIG["profiler"]["database_path"])
app = Flask(__name__)

# ──────────────────────────── HTML TEMPLATE ───────────────────────────────────

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Deception Tracking & Profiling Engine</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; }

    /* Header */
    header { background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
             border-bottom: 2px solid #e94560; padding: 15px 25px;
             display: flex; justify-content: space-between; align-items: center; }
    header h1 { color: #e94560; font-size: 20px; letter-spacing: 2px; }
    .system-status { display: flex; gap: 15px; align-items: center; }
    .status-dot { width: 10px; height: 10px; background: #39d353; border-radius: 50%;
                  animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:0.4;} }

    /* Stats row */
    .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px;
                  padding: 20px 25px; }
    .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                 padding: 20px; text-align: center; transition: border-color 0.3s; }
    .stat-card:hover { border-color: #e94560; }
    .stat-number { font-size: 36px; font-weight: bold; color: #e94560; }
    .stat-label { color: #8b949e; font-size: 12px; margin-top: 5px; text-transform: uppercase; }

    /* Main content */
    .main-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px;
                 padding: 0 25px 25px; }
    .full-width { grid-column: 1 / -1; }

    /* Cards */
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
    .card-header { background: #21262d; padding: 12px 20px; display: flex;
                   justify-content: space-between; align-items: center;
                   border-bottom: 1px solid #30363d; }
    .card-title { color: #e94560; font-size: 13px; letter-spacing: 1px; text-transform: uppercase; }
    .card-body { padding: 15px; max-height: 400px; overflow-y: auto; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { color: #8b949e; text-align: left; padding: 8px 12px; border-bottom: 1px solid #30363d;
         font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
    td { padding: 8px 12px; border-bottom: 1px solid #21262d; }
    tr:hover { background: #21262d; }
    tr:last-child td { border-bottom: none; }

    /* Risk score badges */
    .score-badge { padding: 3px 10px; border-radius: 12px; font-size: 12px;
                   font-weight: bold; display: inline-block; }
    .score-critical { background: #da3633; color: #fff; }
    .score-high     { background: #e85d04; color: #fff; }
    .score-medium   { background: #f0a500; color: #000; }
    .score-low      { background: #39d353; color: #000; }
    .score-minimal  { background: #30363d; color: #8b949e; }

    /* Status badges */
    .status-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; }
    .status-critical  { background: #da3633; color: #fff; }
    .status-high_risk { background: #e85d04; color: #fff; }
    .status-redirected{ background: #9f4dff; color: #fff; }
    .status-suspicious{ background: #f0a500; color: #000; }
    .status-monitoring{ background: #1f6feb; color: #fff; }
    .status-unknown   { background: #30363d; color: #8b949e; }

    /* Action badges */
    .action-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px;
                    background: #161b22; border: 1px solid #30363d; }
    .action-forensic_snapshot { border-color: #da3633; color: #da3633; }
    .action-redirect_to_decoy  { border-color: #9f4dff; color: #9f4dff; }
    .action-noise_injection    { border-color: #e85d04; color: #e85d04; }
    .action-mark_suspicious    { border-color: #f0a500; color: #f0a500; }

    /* Timeline */
    .event-timeline { display: flex; flex-direction: column; gap: 6px; }
    .event-item { background: #21262d; border-left: 3px solid #30363d;
                  padding: 8px 12px; border-radius: 0 4px 4px 0; font-size: 12px; }
    .event-item.high { border-left-color: #e94560; }
    .event-item.medium { border-left-color: #f0a500; }
    .event-item.low { border-left-color: #39d353; }
    .event-ip { color: #e94560; font-weight: bold; }
    .event-type { color: #79c0ff; margin: 0 8px; }
    .event-time { color: #8b949e; font-size: 11px; }

    /* Refresh button */
    .refresh-btn { background: #21262d; border: 1px solid #30363d; color: #8b949e;
                   padding: 5px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
    .refresh-btn:hover { border-color: #e94560; color: #e94560; }

    /* Threshold legend */
    .threshold-legend { display: flex; gap: 15px; flex-wrap: wrap; padding: 10px 25px;
                        background: #161b22; border-bottom: 1px solid #30363d; font-size: 12px; }
    .threshold-item { display: flex; align-items: center; gap: 6px; }
    .threshold-dot { width: 10px; height: 10px; border-radius: 50%; }

    /* Live indicator */
    .live-indicator { color: #39d353; font-size: 11px; animation: pulse 2s infinite; }
    .timestamp { color: #8b949e; font-size: 11px; }
    .no-data { color: #8b949e; text-align: center; padding: 30px; font-size: 13px; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>⚡ DECEPTION TRACKING & PROFILING ENGINE</h1>
      <div style="color:#8b949e; font-size:12px; margin-top:4px;">
        Behavioral Attacker Intelligence Platform | Lab Environment
      </div>
    </div>
    <div class="system-status">
      <div class="status-dot"></div>
      <span class="live-indicator">● LIVE</span>
      <span class="timestamp" id="last-update">--</span>
      <button class="refresh-btn" onclick="refreshAll()">↺ Refresh</button>
    </div>
  </header>

  <div class="threshold-legend">
    <span style="color:#8b949e; margin-right:5px;">THRESHOLDS:</span>
    <div class="threshold-item">
      <div class="threshold-dot" style="background:#f0a500;"></div>
      <span>≥20 Suspicious</span>
    </div>
    <div class="threshold-item">
      <div class="threshold-dot" style="background:#9f4dff;"></div>
      <span>≥40 Redirect to Decoy</span>
    </div>
    <div class="threshold-item">
      <div class="threshold-dot" style="background:#e85d04;"></div>
      <span>≥70 Noise Injection</span>
    </div>
    <div class="threshold-item">
      <div class="threshold-dot" style="background:#da3633;"></div>
      <span>≥100 Forensic Capture</span>
    </div>
  </div>

  <!-- Summary Stats -->
  <div class="stats-grid" id="stats-grid">
    <div class="stat-card">
      <div class="stat-number" id="stat-attackers">--</div>
      <div class="stat-label">Tracked Attackers</div>
    </div>
    <div class="stat-card">
      <div class="stat-number" id="stat-events">--</div>
      <div class="stat-label">Total Events</div>
    </div>
    <div class="stat-card">
      <div class="stat-number" id="stat-high-risk">--</div>
      <div class="stat-label">High Risk (≥70)</div>
    </div>
    <div class="stat-card">
      <div class="stat-number" id="stat-redirected">--</div>
      <div class="stat-label">Redirected</div>
    </div>
    <div class="stat-card">
      <div class="stat-number" id="stat-actions">--</div>
      <div class="stat-label">Actions Triggered</div>
    </div>
  </div>

  <div class="main-grid">
    <!-- Attacker Profiles Table -->
    <div class="card full-width">
      <div class="card-header">
        <span class="card-title">🎯 Attacker Profiles</span>
        <span class="timestamp" id="profiles-updated">--</span>
      </div>
      <div class="card-body">
        <table>
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Risk Score</th>
              <th>Status</th>
              <th>Events</th>
              <th>First Seen</th>
              <th>Last Seen</th>
              <th>Redirected</th>
              <th>Forensic</th>
            </tr>
          </thead>
          <tbody id="profiles-table-body">
            <tr><td colspan="8" class="no-data">Loading attacker profiles...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Live Event Feed -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">📡 Live Event Feed</span>
        <span class="timestamp" id="events-updated">--</span>
      </div>
      <div class="card-body" id="event-feed">
        <div class="no-data">Waiting for events...</div>
      </div>
    </div>

    <!-- Triggered Actions -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">⚡ Triggered Actions</span>
        <span class="timestamp" id="actions-updated">--</span>
      </div>
      <div class="card-body">
        <table>
          <thead>
            <tr><th>IP</th><th>Action</th><th>Score</th><th>Time</th><th>Result</th></tr>
          </thead>
          <tbody id="actions-table-body">
            <tr><td colspan="5" class="no-data">No actions yet</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const REFRESH_INTERVAL = {{ refresh_interval }} * 1000;

    function scoreClass(score) {
      if (score >= 100) return 'score-critical';
      if (score >= 70)  return 'score-high';
      if (score >= 40)  return 'score-medium';
      if (score >= 20)  return 'score-low';
      return 'score-minimal';
    }

    function formatTime(iso) {
      if (!iso) return '--';
      try {
        const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'));
        return d.toLocaleTimeString();
      } catch { return iso; }
    }

    function formatDate(iso) {
      if (!iso) return '--';
      try {
        const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'));
        return d.toLocaleString();
      } catch { return iso; }
    }

    async function loadStats() {
      try {
        const r = await fetch('/data/stats');
        const data = await r.json();
        document.getElementById('stat-attackers').textContent = data.total_attackers || 0;
        document.getElementById('stat-events').textContent = data.total_events || 0;
        document.getElementById('stat-high-risk').textContent = data.high_risk_attackers || 0;
        document.getElementById('stat-redirected').textContent = data.redirected_attackers || 0;
        document.getElementById('stat-actions').textContent = data.total_actions || 0;
      } catch(e) { console.error('Stats load failed:', e); }
    }

    async function loadProfiles() {
      try {
        const r = await fetch('/data/profiles');
        const data = await r.json();
        const tbody = document.getElementById('profiles-table-body');

        if (!data.profiles || data.profiles.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" class="no-data">No attackers tracked yet</td></tr>';
          return;
        }

        tbody.innerHTML = data.profiles.map(p => `
          <tr>
            <td style="color:#e94560; font-weight:bold;">${p.src_ip}</td>
            <td><span class="score-badge ${scoreClass(p.risk_score)}">${p.risk_score.toFixed(1)}</span></td>
            <td><span class="status-badge status-${p.status}">${p.status}</span></td>
            <td>${p.event_count}</td>
            <td class="timestamp">${formatDate(p.first_seen)}</td>
            <td class="timestamp">${formatDate(p.last_seen)}</td>
            <td>${p.redirected ? '<span style="color:#9f4dff;">YES</span>' : '<span style="color:#8b949e;">NO</span>'}</td>
            <td>${p.forensic_captured ? '<span style="color:#da3633;">YES</span>' : '<span style="color:#8b949e;">NO</span>'}</td>
          </tr>
        `).join('');

        document.getElementById('profiles-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
      } catch(e) { console.error('Profiles load failed:', e); }
    }

    async function loadEvents() {
      try {
        const r = await fetch('/data/events');
        const data = await r.json();
        const feed = document.getElementById('event-feed');

        if (!data.events || data.events.length === 0) {
          feed.innerHTML = '<div class="no-data">No events recorded yet</div>';
          return;
        }

        const getEventClass = (sev) => {
          if (sev >= 15) return 'high';
          if (sev >= 6) return 'medium';
          return 'low';
        };

        feed.innerHTML = '<div class="event-timeline">' +
          data.events.slice(0, 30).map(e => `
            <div class="event-item ${getEventClass(e.severity)}">
              <span class="event-ip">${e.src_ip}</span>
              <span class="event-type">[${e.event_type}]</span>
              <span style="color:#8b949e;">sev=${e.severity}</span>
              <span class="event-time" style="float:right;">${formatTime(e.timestamp)}</span>
              <br><span style="color:#6e7681; font-size:11px;">${(e.details || '').slice(0, 80)}</span>
            </div>
          `).join('') + '</div>';

        document.getElementById('events-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
      } catch(e) { console.error('Events load failed:', e); }
    }

    async function loadActions() {
      try {
        const r = await fetch('/data/actions');
        const data = await r.json();
        const tbody = document.getElementById('actions-table-body');

        if (!data.actions || data.actions.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" class="no-data">No actions triggered yet</td></tr>';
          return;
        }

        tbody.innerHTML = data.actions.map(a => `
          <tr>
            <td style="color:#e94560;">${a.src_ip}</td>
            <td><span class="action-badge action-${a.action_type}">${a.action_type.replace(/_/g,' ')}</span></td>
            <td>${a.score_at_trigger.toFixed(1)}</td>
            <td class="timestamp">${formatTime(a.triggered_at)}</td>
            <td>${a.success ? '<span style="color:#39d353;">OK</span>' : '<span style="color:#da3633;">FAIL</span>'}</td>
          </tr>
        `).join('');

        document.getElementById('actions-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
      } catch(e) { console.error('Actions load failed:', e); }
    }

    function refreshAll() {
      loadStats();
      loadProfiles();
      loadEvents();
      loadActions();
      document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
    }

    // Initial load
    refreshAll();

    // Auto-refresh
    setInterval(refreshAll, REFRESH_INTERVAL);
  </script>
</body>
</html>
"""

# ──────────────────────────── ROUTES ──────────────────────────────────────────

@app.route("/")
def dashboard():
    """Render the main dashboard."""
    refresh = CONFIG["dashboard"]["refresh_interval_seconds"]
    return render_template_string(DASHBOARD_HTML, refresh_interval=refresh)


@app.route("/data/stats")
def data_stats():
    return jsonify(db.get_dashboard_stats())


@app.route("/data/profiles")
def data_profiles():
    limit = int(request.args.get("limit", 100))
    profiles = db.get_all_profiles(limit=limit)
    return jsonify({"count": len(profiles), "profiles": profiles})


@app.route("/data/events")
def data_events():
    limit = int(request.args.get("limit", 50))
    events = db.get_recent_events(limit=limit)
    return jsonify({"count": len(events), "events": events})


@app.route("/data/actions")
def data_actions():
    limit = int(request.args.get("limit", 50))
    actions = db.get_recent_actions(limit=limit)
    return jsonify({"count": len(actions), "actions": actions})


@app.route("/api/health")
def health():
    return jsonify({"status": "running", "service": "dashboard"}), 200


# ──────────────────────────── ENTRY POINT ─────────────────────────────────────

if __name__ == "__main__":
    host = CONFIG["dashboard"]["host"]
    port = CONFIG["dashboard"]["port"]
    logger.info(f"Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
