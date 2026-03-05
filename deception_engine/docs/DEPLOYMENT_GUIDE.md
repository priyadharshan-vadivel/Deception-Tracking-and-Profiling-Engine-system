# Deception Tracking & Profiling Engine
## Complete Lab Deployment & Operations Guide

---

## 1. Lab Environment

| VM       | Role                    | IP Address      | OS          | Services                          |
|----------|-------------------------|-----------------|-------------|-----------------------------------|
| Attacker | Simulates attacks       | 192.168.56.102  | Linux Mint  | nmap, gobuster, hydra, curl       |
| Server1  | Production web server   | 192.168.56.103  | Linux Mint  | Apache :8080, Proxy :80, Monitor  |
| Decoy    | Fake honeypot server    | 192.168.56.106  | Linux Mint  | Flask decoy :80                   |
| Profiler | Central engine          | 192.168.56.200  | Linux Mint  | Flask API :5000, Dashboard :8080  |

---

## 2. Project Directory Structure

```
/opt/deception_engine/
│
├── profiler_engine/
│   ├── profiler_api.py        # Flask REST API — receives all security events
│   ├── scoring_engine.py      # Risk score + time decay (score × 0.98/hr)
│   ├── decision_engine.py     # Threshold evaluation + automated actions
│   └── database_manager.py   # SQLite read/write layer
│
├── server_monitor/
│   ├── monitor.py             # Tails Apache + auth logs in real time
│   ├── event_parser.py        # Regex detection — nmap, gobuster, hydra
│   ├── event_sender.py        # HTTP client — POSTs events to Profiler API
│   └── deception_proxy.py    # TCP proxy — auto-redirects flagged IPs to Decoy
│
├── decoy_logger/
│   └── decoy_logger.py        # Flask honeypot — fake admin portal + honeytokens
│
├── dashboard/
│   └── dashboard.py           # Flask web UI — real-time attacker monitoring
│
├── config/
│   └── config.json            # All settings: IPs, scoring weights, thresholds
│
├── database/
│   ├── init_database.py       # Creates SQLite schema (run once on Profiler)
│   └── profiler.db            # SQLite database — auto-created at runtime
│
├── forensics/                 # Auto-generated forensic JSON snapshots
│
└── scripts/
    ├── deploy.sh                 # Role-based automated deployment script
    ├── redirect.sh               # Manually install iptables DNAT rule on Server1
    ├── remove_redirect.sh        # Remove iptables DNAT rule
    ├── setup_proxy.sh            # Move Apache to 8080, start proxy on 80
    ├── setup_server1_website.sh  # Deploy real corporate website + honeytokens
    ├── test_full_pipeline.sh     # End-to-end automated pipeline test
    └── simulate_attack.py        # Attack simulator for lab demonstration
```

---

## 3. How Automatic Attacker Detection Works

The attacker IP is **never configured manually**. It is detected automatically:

```
Attacker runs nmap / gobuster / hydra
          │
          ▼
Server1 Apache logs: 192.168.56.102 GET /.env 404
Server1 auth.log:    Failed password from 192.168.56.102
          │
          ▼
monitor.py reads log lines in real time
event_parser.py extracts source IP using regex
event_sender.py POSTs event to Profiler API
          │
          ▼
Profiler scores the IP
score >= 40 → deception_proxy.py redirects that IP to Decoy
          │
          ▼
Attacker hits 192.168.56.103 (Server1)
Proxy checks score → forwards to 192.168.56.106 (Decoy)
Attacker never knows they were redirected
```

---

## 4. Set Static IP Addresses — All VMs (Linux Mint)

Linux Mint uses NetworkManager. Run on **each VM**:

```bash
# Find your interface name
ip link show
```

```bash
# Set static IP — change IP per VM
# Profiler: 192.168.56.200
# Server1:  192.168.56.103
# Decoy:    192.168.56.106
# Attacker: 192.168.56.102

sudo nmcli con mod "Wired connection 1" \
  ipv4.addresses 192.168.56.200/24 \
  ipv4.gateway 192.168.56.1 \
  ipv4.dns "8.8.8.8" \
  ipv4.method manual

sudo nmcli con up "Wired connection 1"
```

Verify:
```bash
ip addr show
ping -c 2 192.168.56.200
```

---

## 5. Copy Project Files to All VMs

From your **host machine** where you have the project zip:

```bash
# Unzip first
unzip deception_engine.zip

# Copy to each VM
scp -r deception_engine/ profiler@192.168.56.200:/tmp/
scp -r deception_engine/ server1@192.168.56.103:/tmp/
scp -r deception_engine/ decoy@192.168.56.106:/tmp/
scp -r deception_engine/ attacker@192.168.56.102:/tmp/
```

On **each VM** after copying:
```bash
sudo mkdir -p /opt/deception_engine
sudo cp -r /tmp/deception_engine/* /opt/deception_engine/
```

---

## 6. PROFILER VM — Full Deployment (192.168.56.200)

SSH into Profiler and run every command in order:

```bash
ssh profiler@192.168.56.200
```

```bash
# Step 1 — Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip curl sqlite3 net-tools
```

```bash
# Step 2 — Install Python libraries
sudo pip3 install flask requests --break-system-packages
```

```bash
# Step 3 — Create all required directories
sudo mkdir -p /opt/deception_engine/{profiler_engine,server_monitor,decoy_logger,dashboard,config,database,forensics,scripts}
sudo mkdir -p /var/log/deception_engine
sudo chmod 777 /var/log/deception_engine
```

```bash
# Step 4 — Copy project files
sudo cp -r /tmp/deception_engine/* /opt/deception_engine/
```

```bash
# Step 5 — Verify config.json has correct IPs
cat /opt/deception_engine/config/config.json
```

Expected network section:
```json
"network": {
  "server1_ip": "192.168.56.103",
  "decoy_ip":   "192.168.56.106",
  "profiler_ip":"192.168.56.200"
}
```

```bash
# Step 6 — Initialize the SQLite database
sudo PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  python3 /opt/deception_engine/database/init_database.py
```

```bash
# Step 7 — Kill any old running instances
sudo pkill -f profiler_api.py 2>/dev/null || true
sudo pkill -f dashboard.py 2>/dev/null || true
sleep 2
```

```bash
# Step 8 — Start the Profiler API
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  nohup python3 /opt/deception_engine/profiler_engine/profiler_api.py \
  >> /var/log/deception_engine/profiler.log 2>&1 &'
echo "Profiler API started"
```

```bash
# Step 9 — Verify Profiler API is running
sleep 4
curl http://localhost:5000/api/health
```

Expected:
```json
{"service": "Deception Profiling Engine", "status": "running"}
```

```bash
# Step 10 — Start the Dashboard
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  nohup python3 /opt/deception_engine/dashboard/dashboard.py \
  >> /var/log/deception_engine/dashboard.log 2>&1 &'
echo "Dashboard started"
```

```bash
# Step 11 — Verify Dashboard is running
sleep 3
curl http://localhost:8080/api/health
```

```bash
# Step 12 — Open firewall ports
sudo ufw allow 5000/tcp
sudo ufw allow 8080/tcp
sudo ufw reload
```

```bash
# Step 13 — Confirm both ports are listening
ss -tlnp | grep -E "5000|8080"
```

```bash
# Step 14 — Send a test event to verify full pipeline
curl -X POST http://localhost:5000/api/event \
  -H "Content-Type: application/json" \
  -H "X-API-Key: deception-engine-secret-key-2024" \
  -d '{
    "src_ip": "192.168.56.102",
    "event_type": "syn_scan",
    "severity": 5,
    "details": "Pipeline test event"
  }'
```

```bash
# Step 15 — Verify attacker profile was created
curl "http://localhost:5000/api/profiles?api_key=deception-engine-secret-key-2024" \
  | python3 -m json.tool
```

```bash
# Step 16 — Auto-start on reboot
sudo tee /etc/rc.local << 'EOF'
#!/bin/bash
export PROFILER_CONFIG=/opt/deception_engine/config/config.json
sleep 5
bash -c 'nohup python3 /opt/deception_engine/profiler_engine/profiler_api.py \
  >> /var/log/deception_engine/profiler.log 2>&1 &'
sleep 4
bash -c 'nohup python3 /opt/deception_engine/dashboard/dashboard.py \
  >> /var/log/deception_engine/dashboard.log 2>&1 &'
exit 0
EOF
sudo chmod +x /etc/rc.local
```

**Open in browser on any VM:**
```
http://192.168.56.200:8080              ← Live Monitoring Dashboard
http://192.168.56.200:5000/api/health   ← API Health Check
```

---

## 7. SERVER1 VM — Full Deployment (192.168.56.103)

SSH into Server1 and run every command in order:

```bash
ssh server1@192.168.56.103
```

```bash
# Step 1 — Install dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip apache2 curl iptables net-tools
```

```bash
# Step 2 — Install Python libraries including Scapy for SYN detection
sudo pip3 install flask requests scapy --break-system-packages
```

```bash
# Step 3 — Create directories and fix permissions
sudo mkdir -p /opt/deception_engine
sudo mkdir -p /var/log/deception_engine
sudo chmod 777 /var/log/deception_engine
sudo touch /var/log/deception_engine/proxy.log
sudo touch /var/log/deception_engine/monitor.log
sudo chmod 666 /var/log/deception_engine/*.log
```

```bash
# Step 4 — Copy project files
sudo cp -r /tmp/deception_engine/* /opt/deception_engine/
```

```bash
# Step 5 — Deploy the real corporate website and honeytokens
sudo bash /opt/deception_engine/scripts/setup_server1_website.sh
```

```bash
# Step 6 — Verify website is up (Apache on port 80 for now)
curl http://localhost/
```

```bash
# Step 7 — Enable IP forwarding (required for traffic routing)
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || \
  echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
cat /proc/sys/net/ipv4/ip_forward
# Must print: 1
```

```bash
# Step 8 — Move Apache to port 8080 (proxy will take port 80)
sudo sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf
sudo sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' \
  /etc/apache2/sites-enabled/000-default.conf
sudo systemctl restart apache2
```

```bash
# Step 9 — Verify Apache moved to port 8080
ss -tlnp | grep 8080
curl http://localhost:8080/
```

```bash
# Step 10 — Open firewall
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 8080/tcp
sudo ufw reload
```

```bash
# Step 11 — Test connectivity to Profiler API
curl http://192.168.56.200:5000/api/health
# Must return: {"status": "running"}
```

```bash
# Step 12 — Kill any old instances
sudo pkill -f monitor.py 2>/dev/null || true
sudo pkill -f deception_proxy.py 2>/dev/null || true
sleep 1
```

```bash
# Step 13 — Start the log monitor agent
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  nohup python3 /opt/deception_engine/server_monitor/monitor.py \
  >> /var/log/deception_engine/monitor.log 2>&1 &'
echo "Monitor agent started"
```

```bash
# Step 14 — Start the Deception Proxy on port 80
# This proxy auto-detects attacker IPs and redirects them to Decoy
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  nohup python3 /opt/deception_engine/server_monitor/deception_proxy.py \
  >> /var/log/deception_engine/proxy.log 2>&1 &'
echo "Deception proxy started"
```

```bash
# Step 15 — Verify proxy is running on port 80
sleep 3
ss -tlnp | grep :80
```

```bash
# Step 16 — Verify both monitor and proxy are running
ps aux | grep -E "monitor.py|deception_proxy.py" | grep -v grep
```

```bash
# Step 17 — Send a test event to confirm monitor pipeline works
curl -X POST http://192.168.56.200:5000/api/event \
  -H "Content-Type: application/json" \
  -H "X-API-Key: deception-engine-secret-key-2024" \
  -d '{
    "src_ip": "192.168.56.102",
    "event_type": "syn_scan",
    "severity": 5,
    "details": "Test from Server1",
    "source": "server1"
  }'
```

```bash
# Step 18 — Watch proxy logs in real time
tail -f /var/log/deception_engine/proxy.log
```

```bash
# Step 19 — Auto-start on reboot
sudo tee -a /etc/rc.local << 'EOF'
#!/bin/bash
sleep 5
bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  nohup python3 /opt/deception_engine/server_monitor/monitor.py \
  >> /var/log/deception_engine/monitor.log 2>&1 &'
sleep 2
bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  nohup python3 /opt/deception_engine/server_monitor/deception_proxy.py \
  >> /var/log/deception_engine/proxy.log 2>&1 &'
exit 0
EOF
sudo chmod +x /etc/rc.local
```

**How redirection works on Server1:**
```
Any HTTP request to Server1:80
          │
          ▼
deception_proxy.py intercepts connection
          │
          ▼
Queries Profiler: "What is score for this IP?"
          │
    ┌─────┴──────┐
score < 40     score >= 40
    │                │
    ▼                ▼
Real Apache      Decoy server
localhost:8080   192.168.56.106:80
(real website)   (fake admin portal)
```

---

## 8. DECOY VM — Full Deployment (192.168.56.106)

SSH into Decoy and run every command in order:

```bash
ssh decoy@192.168.56.106
```

```bash
# Step 1 — Install dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip curl net-tools
```

```bash
# Step 2 — Install Python libraries
sudo pip3 install flask requests --break-system-packages
```

```bash
# Step 3 — Create directories and fix permissions
sudo mkdir -p /opt/deception_engine
sudo mkdir -p /var/log/deception_engine
sudo chmod 777 /var/log/deception_engine
sudo touch /var/log/deception_engine/decoy.log
sudo chmod 666 /var/log/deception_engine/decoy.log
```

```bash
# Step 4 — Copy project files
sudo cp -r /tmp/deception_engine/* /opt/deception_engine/
```

```bash
# Step 5 — Stop Apache (Flask decoy uses port 80)
sudo systemctl stop apache2 2>/dev/null || true
sudo systemctl disable apache2 2>/dev/null || true
```

```bash
# Step 6 — Open firewall
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw reload
```

```bash
# Step 7 — Test connectivity to Profiler
curl http://192.168.56.200:5000/api/health
# Must return: {"status": "running"}
```

```bash
# Step 8 — Kill any old instances
sudo pkill -f decoy_logger.py 2>/dev/null || true
sleep 1
```

```bash
# Step 9 — Start the Decoy Logger on port 80
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  DECOY_PORT=80 \
  nohup python3 /opt/deception_engine/decoy_logger/decoy_logger.py \
  >> /var/log/deception_engine/decoy.log 2>&1 &'
echo "Decoy started"
```

```bash
# Step 10 — Verify Decoy is running on port 80
sleep 3
ss -tlnp | grep :80
```

```bash
# Step 11 — Test health endpoint
curl http://localhost:80/api/health
```

Expected:
```json
{"status": "running", "service": "decoy"}
```

```bash
# Step 12 — Test all honeytoken routes
curl http://localhost:80/
curl http://localhost:80/admin
curl http://localhost:80/database-dump.sql
curl http://localhost:80/.env
curl http://localhost:80/passwords.txt
curl http://localhost:80/phpmyadmin
```

```bash
# Step 13 — Verify events are reaching Profiler
curl "http://192.168.56.200:5000/api/events?api_key=deception-engine-secret-key-2024" \
  | python3 -m json.tool | head -30
```

```bash
# Step 14 — Watch decoy logs in real time
tail -f /var/log/deception_engine/decoy.log
```

```bash
# Step 15 — Auto-start on reboot
sudo tee /etc/rc.local << 'EOF'
#!/bin/bash
sleep 5
bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  DECOY_PORT=80 \
  nohup python3 /opt/deception_engine/decoy_logger/decoy_logger.py \
  >> /var/log/deception_engine/decoy.log 2>&1 &'
exit 0
EOF
sudo chmod +x /etc/rc.local
```

---

## 9. ATTACKER VM — Setup (192.168.56.102)

SSH into Attacker and run:

```bash
ssh attacker@192.168.56.102
```

```bash
# Step 1 — Install attack tools
sudo apt-get update
sudo apt-get install -y nmap gobuster hydra curl python3 python3-pip
sudo pip3 install requests --break-system-packages
```

```bash
# Step 2 — Copy project scripts
sudo mkdir -p /opt/deception_engine
sudo cp -r /tmp/deception_engine/* /opt/deception_engine/
```

```bash
# Step 3 — Verify connectivity to all VMs
ping -c 2 192.168.56.103   # Server1
ping -c 2 192.168.56.106   # Decoy
ping -c 2 192.168.56.200   # Profiler
```

---

## 10. Simulating Attacks

### Option A — Direct Event Injection (Fastest — No Attack Tools Needed)

Run on Attacker VM or Profiler:

```bash
python3 /opt/deception_engine/scripts/simulate_attack.py \
  --direct-inject \
  --profiler 192.168.56.200 \
  --attacker-ip 192.168.56.102
```

Watch scores climb in real time on the dashboard:
```
http://192.168.56.200:8080
```

---

### Option B — Real Attack Tool Simulation

**Stage 1 — Reconnaissance (score reaches ~13)**
```bash
# SYN scan — detected by Scapy in deception_proxy.py
sudo nmap -sS -T4 -p 22,80,443,8080,3306 192.168.56.103

# Service version scan
nmap -sV -T3 192.168.56.103
```

**Stage 2 — Directory Enumeration (score reaches ~25)**
```bash
# Gobuster — detected by event_parser.py in Apache logs
gobuster dir -u http://192.168.56.103/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 20 -q

# Manual probing
for path in /admin /wp-admin /.env /phpmyadmin /backup /config.php /.git; do
  curl -s -o /dev/null -w "%{http_code} $path\n" http://192.168.56.103$path
done
```

**Stage 3 — Brute Force (score reaches ~40 — REDIRECT TRIGGERS HERE)**
```bash
# SSH brute force — detected by auth.log monitor
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  -t 4 -f 192.168.56.103 ssh

# HTTP brute force
for i in $(seq 1 10); do
  curl -s -X POST http://192.168.56.103/login \
    -d "username=admin&password=test$i" -o /dev/null
done
```

**Stage 4 — Honeytoken Access (score reaches ~70)**
```bash
# Access fake sensitive files — highest severity events
curl http://192.168.56.103/database-dump.sql
curl http://192.168.56.103/.env
curl http://192.168.56.103/passwords.txt
curl http://192.168.56.103/admin-credentials.json
```

**Stage 5 — Post-Redirect Decoy Interaction (score reaches 100)**

After score crosses 40, the proxy automatically redirects the attacker.
The attacker still uses Server1 IP but gets Decoy content:

```bash
# Attacker thinks they are on Server1 — actually getting Decoy
curl http://192.168.56.103/
curl http://192.168.56.103/admin
curl -X POST http://192.168.56.103/api/shell \
  -H "Content-Type: application/json" \
  -d '{"cmd": "whoami"}'
```

---

## 11. Verifying the Complete System

### Check all services are running
```bash
# On Profiler
ps aux | grep -E "profiler_api|dashboard" | grep -v grep

# On Server1
ps aux | grep -E "monitor|deception_proxy" | grep -v grep

# On Decoy
ps aux | grep decoy_logger | grep -v grep
```

### Verify event ingestion
```bash
curl -H "X-API-Key: deception-engine-secret-key-2024" \
  http://192.168.56.200:5000/api/events | python3 -m json.tool | head -40
```

### Verify attacker score
```bash
curl -H "X-API-Key: deception-engine-secret-key-2024" \
  http://192.168.56.200:5000/api/profile/192.168.56.102 | python3 -m json.tool
```

### Verify triggered actions
```bash
curl -H "X-API-Key: deception-engine-secret-key-2024" \
  http://192.168.56.200:5000/api/actions | python3 -m json.tool
```

### Verify proxy is redirecting (on Server1)
```bash
# Watch proxy logs — look for REDIRECT lines
tail -f /var/log/deception_engine/proxy.log
```

Expected output when redirection is active:
```
[REDIRECT] 192.168.56.102 score=45.0 status=redirected -> DECOY 192.168.56.106:80
[CONN] 192.168.56.102:54321 -> 192.168.56.106:80 (redirected_to_decoy)
```

### Verify attacker IP appears in Decoy logs (on Decoy)
```bash
grep "192.168.56.102" /var/log/deception_engine/decoy.log
```

### Verify forensic snapshots were saved (on Profiler)
```bash
ls -lh /opt/deception_engine/forensics/
```

### View live dashboard
```
http://192.168.56.200:8080
```

---

## 12. Risk Scoring Reference

| Event Type            | Score | Detected By                        |
|-----------------------|-------|------------------------------------|
| syn_scan              | +5    | Scapy SYN detector in proxy        |
| port_sweep            | +8    | Scapy — 20+ ports in 10 seconds    |
| directory_enumeration | +6    | Apache log — gobuster user-agent   |
| failed_login          | +3    | auth.log — SSH failure             |
| ssh_attempt           | +4    | auth.log — invalid user            |
| brute_force           | +15   | auth.log — 5+ failures from one IP |
| honeytoken_access     | +25   | Apache log — fake file accessed    |
| privilege_escalation  | +20   | syslog — sudo command detected     |
| c2_detection          | +30   | Apache log — C2 pattern detected   |
| decoy_interaction     | +10   | Decoy Flask — any request          |

### Decision Thresholds

| Score  | Status      | Automated Action                          |
|--------|-------------|-------------------------------------------|
| ≥ 20   | suspicious  | Profile flagged in database               |
| ≥ 40   | redirected  | Proxy forwards attacker to Decoy          |
| ≥ 70   | high_risk   | Noise injection thread started            |
| ≥ 100  | critical    | Forensic JSON snapshot generated          |

### Time Decay Formula

```
score = previous_score × (0.98 ^ hours_inactive)
```

Example: score=50, inactive 10 hours → `50 × (0.98^10) ≈ 40.8`

---

## 13. Troubleshooting

### Profiler API not starting
```bash
# Check for errors
tail -30 /var/log/deception_engine/profiler.log

# Install missing packages
sudo pip3 install flask requests --break-system-packages

# Reinitialize database
sudo PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  python3 /opt/deception_engine/database/init_database.py --reset
```

### Events not reaching Profiler
```bash
# Test connectivity
curl -v http://192.168.56.200:5000/api/health

# Open firewall on Profiler
sudo ufw allow 5000/tcp && sudo ufw reload

# Send manual test event
curl -X POST http://192.168.56.200:5000/api/event \
  -H "X-API-Key: deception-engine-secret-key-2024" \
  -H "Content-Type: application/json" \
  -d '{"src_ip":"192.168.56.102","event_type":"syn_scan","severity":5,"details":"test"}'
```

### Proxy not redirecting attacker
```bash
# Check proxy is running on Server1
ps aux | grep deception_proxy | grep -v grep
ss -tlnp | grep :80

# Check proxy logs
tail -30 /var/log/deception_engine/proxy.log

# Check Profiler returns profile for attacker IP
curl "http://192.168.56.200:5000/api/profile/192.168.56.102?api_key=deception-engine-secret-key-2024"

# Inject events manually to push score above 40
for event in syn_scan port_sweep brute_force; do
  curl -s -X POST http://192.168.56.200:5000/api/event \
    -H "X-API-Key: deception-engine-secret-key-2024" \
    -H "Content-Type: application/json" \
    -d "{\"src_ip\":\"192.168.56.102\",\"event_type\":\"$event\",\"severity\":10}"
done
```

### Permission denied on log files
```bash
sudo chmod 777 /var/log/deception_engine
sudo chmod 666 /var/log/deception_engine/*.log 2>/dev/null || true
```

### Apache not on port 8080
```bash
grep "Listen" /etc/apache2/ports.conf
sudo sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf
sudo systemctl restart apache2
ss -tlnp | grep 8080
```

### Dashboard not loading
```bash
ps aux | grep dashboard.py | grep -v grep
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  nohup python3 /opt/deception_engine/dashboard/dashboard.py \
  >> /var/log/deception_engine/dashboard.log 2>&1 &'
```

### Flask not found
```bash
sudo pip3 install flask requests scapy --break-system-packages
```

### Database errors
```bash
sqlite3 /opt/deception_engine/database/profiler.db ".tables"
sqlite3 /opt/deception_engine/database/profiler.db \
  "SELECT src_ip, risk_score, status FROM attacker_profiles;"
```

### Check all logs at once
```bash
tail -f /var/log/deception_engine/*.log
```

---

## 14. System Architecture — Complete Data Flow

```
Attacker (192.168.56.102)
    │
    ├── nmap -sS (SYN scan)
    ├── gobuster dir
    └── hydra SSH brute force
              │
              ▼
    ┌─────────────────────────┐
    │   Server1 (192.168.56.103)  │
    │                         │
    │  deception_proxy.py     │◄── All HTTP :80 connections intercepted
    │    checks Profiler API  │    proxy queries score for each source IP
    │    for source IP score  │
    │         │               │
    │   score < 40  score≥40  │
    │     │           │       │
    │     ▼           ▼       │
    │  Apache      Decoy      │
    │  :8080       :106:80    │
    │                         │
    │  monitor.py tails logs  │
    │  event_parser.py regex  │
    │  event_sender.py POST   │
    └────────────┬────────────┘
                 │
                 ▼
    ┌────────────────────────────┐
    │  Profiler (192.168.56.200) │
    │                            │
    │  profiler_api.py :5000     │
    │       │                    │
    │  scoring_engine.py         │
    │  S = S_prev × 0.98^Δt + W  │
    │       │                    │
    │  decision_engine.py        │
    │  score≥20 → suspicious     │
    │  score≥40 → redirect       │
    │  score≥70 → noise          │
    │  score≥100→ forensic       │
    │       │                    │
    │  database_manager.py       │
    │  SQLite storage            │
    │       │                    │
    │  dashboard.py :8080        │
    │  Real-time monitoring UI   │
    └────────────────────────────┘
                 │
                 ▼
    ┌────────────────────────────┐
    │  Decoy (192.168.56.106)    │
    │                            │
    │  decoy_logger.py :80       │
    │  Fake admin portal         │
    │  Honeytokens               │
    │  Fake shell endpoint       │
    │  Logs everything           │
    │  Sends events to Profiler  │
    └────────────────────────────┘
```

---

## 15. Quick Reference — All Service Start Commands

### Profiler VM
```bash
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json nohup python3 /opt/deception_engine/profiler_engine/profiler_api.py >> /var/log/deception_engine/profiler.log 2>&1 &'
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json nohup python3 /opt/deception_engine/dashboard/dashboard.py >> /var/log/deception_engine/dashboard.log 2>&1 &'
```

### Server1 VM
```bash
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json nohup python3 /opt/deception_engine/server_monitor/monitor.py >> /var/log/deception_engine/monitor.log 2>&1 &'
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json nohup python3 /opt/deception_engine/server_monitor/deception_proxy.py >> /var/log/deception_engine/proxy.log 2>&1 &'
```

### Decoy VM
```bash
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json DECOY_PORT=80 nohup python3 /opt/deception_engine/decoy_logger/decoy_logger.py >> /var/log/deception_engine/decoy.log 2>&1 &'
```

### Stop All Services
```bash
sudo pkill -f profiler_api.py
sudo pkill -f dashboard.py
sudo pkill -f monitor.py
sudo pkill -f deception_proxy.py
sudo pkill -f decoy_logger.py
```
