"""
decoy_logger.py
Fake service that runs on the Decoy server (192.168.56.106).

Presents a convincing but fake web interface to attackers.
Logs ALL interactions and forwards high-severity events to the Profiler.

Deployed as a Flask application listening on port 80 of the Decoy server.
Run with: sudo python3 decoy_logger.py
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template_string, redirect

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server_monitor"))

from event_sender import EventSender

# ──────────────────────────── CONFIG & LOGGING ────────────────────────────────

CONFIG_PATH = os.environ.get(
    "PROFILER_CONFIG",
    os.path.join(os.path.dirname(__file__), "..", "config", "config.json")
)

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

os.makedirs("/var/log/deception_engine", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("/var/log/deception_engine/decoy.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("decoy_logger")

app = Flask(__name__)
sender = EventSender(CONFIG)

# ──────────────────────────── FAKE HTML TEMPLATES ─────────────────────────────

# Convincing but fake login page
FAKE_LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Internal Admin Portal - Acme Corp</title>
<style>
  body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; }
  .login-box { width: 350px; margin: 100px auto; padding: 30px;
               background: #16213e; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
  h2 { text-align: center; color: #e94560; }
  input { width: 100%; padding: 10px; margin: 10px 0;
          background: #0f3460; border: 1px solid #e94560; color: #fff; border-radius: 4px; }
  button { width: 100%; padding: 12px; background: #e94560;
           color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
  .notice { color: #aaa; font-size: 12px; text-align: center; margin-top: 15px; }
</style></head>
<body>
<div class="login-box">
  <h2>🔒 Admin Portal</h2>
  <p style="text-align:center; color:#aaa;">Acme Corporation - Internal Access Only</p>
  <form method="POST" action="/admin/login">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
  </form>
  <div class="notice">⚠️ Unauthorized access is monitored and prosecuted</div>
</div>
</body></html>
"""

# Fake database dump file content (honeytoken)
FAKE_DB_DUMP = """-- MySQL dump 10.13  Distrib 8.0.32
-- Host: localhost    Database: acme_prod
-- -----------------------------------------------
-- Server version 8.0.32

CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `email` varchar(255),
  `role` varchar(50) DEFAULT 'user',
  PRIMARY KEY (`id`)
);

INSERT INTO `users` VALUES (1,'admin','$2y$10$fakehash1234567890abcdef','admin@acme-corp.local','administrator');
INSERT INTO `users` VALUES (2,'jsmith','$2y$10$fakehash0987654321fedcba','j.smith@acme-corp.local','user');
INSERT INTO `users` VALUES (3,'dbbackup','$2y$10$fakehashXXXXXXXXXXXXXXXX','backup@acme-corp.local','backup');

-- CONFIDENTIAL: Contains production credentials
-- DO NOT DISTRIBUTE
"""

FAKE_ENV_CONTENT = """APP_ENV=production
DB_HOST=192.168.1.50
DB_PORT=3306
DB_NAME=acme_production
DB_USER=app_user
DB_PASSWORD=Sup3rS3cr3tP@ssw0rd!
JWT_SECRET=fakejwtsecret1234567890abcdef
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET=sk_test_HONEYTOKEN_NOT_A_REAL_KEY
ADMIN_EMAIL=admin@acme-corp.local
"""

# ──────────────────────────── HELPER: LOG AND REPORT ─────────────────────────

def log_and_report(event_type: str, severity: float, details: str):
    """Log an interaction and forward a security event to the Profiler."""
    src_ip = request.remote_addr
    path = request.path
    method = request.method
    ua = request.headers.get("User-Agent", "unknown")

    full_details = f"{details} | path={path} method={method} ua={ua}"
    logger.warning(f"[DECOY] {event_type} from {src_ip}: {full_details}")

    event = {
        "src_ip": src_ip,
        "event_type": event_type,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": full_details,
        "source": "decoy"
    }
    sender.send_event(event)


# ──────────────────────────── DECOY ROUTES ────────────────────────────────────

@app.before_request
def log_all_requests():
    """Log every request hitting the decoy server."""
    src_ip = request.remote_addr
    logger.info(f"[DECOY-HIT] {src_ip} -> {request.method} {request.path}")


@app.route("/")
def index():
    """Fake corporate homepage."""
    log_and_report("decoy_interaction", 10, "Attacker reached decoy landing page")
    return render_template_string(FAKE_LOGIN_HTML)


@app.route("/admin")
@app.route("/admin/")
def admin():
    """Fake admin portal."""
    log_and_report("decoy_interaction", 10, "Attacker accessed fake admin portal")
    return render_template_string(FAKE_LOGIN_HTML)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """
    Fake login form handler.
    Accepts any credentials and reports a brute force / login event.
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        log_and_report(
            "brute_force", 15,
            f"Fake admin login attempt: user={username} pass={password[:4]}***"
        )
        # Simulate a delay then fake error
        time.sleep(1)
        return render_template_string(FAKE_LOGIN_HTML.replace(
            "</div>",
            '<p style="color:red;text-align:center;">Invalid credentials</p></div>'
        ))
    return render_template_string(FAKE_LOGIN_HTML)


@app.route("/database-dump.sql")
def honeytoken_db_dump():
    """Honeytoken: fake database dump file."""
    log_and_report("honeytoken_access", 25, "HONEYTOKEN: Fake database dump accessed")
    return FAKE_DB_DUMP, 200, {"Content-Type": "text/plain"}


@app.route("/.env")
@app.route("/.env.backup")
@app.route("/config/.env")
def honeytoken_env():
    """Honeytoken: fake .env configuration file."""
    log_and_report("honeytoken_access", 25, "HONEYTOKEN: Fake .env file accessed")
    return FAKE_ENV_CONTENT, 200, {"Content-Type": "text/plain"}


@app.route("/passwords.txt")
@app.route("/secret-backup.zip")
@app.route("/admin-credentials.json")
def honeytoken_generic():
    """Honeytoken: generic sensitive file honeytokens."""
    log_and_report("honeytoken_access", 25, f"HONEYTOKEN: {request.path} accessed")
    return json.dumps({
        "note": "This is a fake credential store",
        "admin": "admin:P@ssw0rd123!",
        "backup": "backup:S3cur3B4ckup!"
    }), 200, {"Content-Type": "application/json"}


@app.route("/api/shell", methods=["POST"])
@app.route("/shell", methods=["POST"])
def fake_shell():
    """Fake remote code execution endpoint."""
    command = request.json.get("cmd", "") if request.is_json else request.form.get("cmd", "")
    log_and_report("fake_shell_command", 2, f"Fake shell command: {command[:100]}")
    # Return convincing but fake output
    fake_responses = {
        "whoami": "www-data",
        "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
        "ls": "index.php  config.php  database.sql  backup.tar.gz",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "uname -a": "Linux acme-web-01 5.15.0-fake-generic #1 SMP x86_64 GNU/Linux",
    }
    output = fake_responses.get(command.strip(), f"bash: {command}: command not found")
    return jsonify({"output": output, "exit_code": 0}), 200


@app.route("/phpmyadmin")
@app.route("/phpmyadmin/")
def phpmyadmin():
    """Fake phpMyAdmin (common target)."""
    log_and_report("directory_enumeration", 6, "Attacker probed /phpmyadmin")
    return render_template_string("""
    <html><head><title>phpMyAdmin</title></head>
    <body style="font-family:Arial;background:#f0f0f0;padding:20px;">
    <h2>phpMyAdmin 5.2.1</h2>
    <p>Server: 127.0.0.1  |  Database: acme_production</p>
    <form method="POST">
      Username: <input type="text" name="pma_username"><br>
      Password: <input type="password" name="pma_password"><br>
      <input type="submit" value="Go">
    </form></body></html>
    """)


@app.route("/<path:undefined_path>")
def catch_all(undefined_path):
    """Catch-all route to log any path enumeration."""
    log_and_report(
        "directory_enumeration", 6,
        f"Attacker probed unknown path: /{undefined_path}"
    )
    return jsonify({"error": "Not found", "path": f"/{undefined_path}"}), 404


@app.route("/api/health")
def health():
    return jsonify({"status": "running", "service": "decoy"}), 200


# ──────────────────────────── ENTRY POINT ─────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("DECOY_PORT", 80))
    logger.info(f"Starting Decoy Logger on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
