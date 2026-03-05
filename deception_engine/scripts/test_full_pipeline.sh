#!/bin/bash
# =============================================================
# test_full_pipeline.sh
# Full end-to-end pipeline test for the Deception Engine.
#
# Run this on the Profiler VM (192.168.56.200) to simulate a
# complete attack progression and verify all components work.
#
# Usage:
#   bash test_full_pipeline.sh
# =============================================================

PROFILER="http://localhost:5000"
API_KEY="deception-engine-secret-key-2024"
ATTACKER_IP="192.168.56.102"
SERVER1_IP="192.168.56.103"
DECOY_IP="192.168.56.106"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
info()   { echo -e "${CYAN}[*]${NC} $1"; }
section(){ echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

send_event() {
    local event_type="$1"
    local severity="$2"
    local details="$3"

    result=$(curl -s -X POST "$PROFILER/api/event" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "{
            \"src_ip\": \"$ATTACKER_IP\",
            \"event_type\": \"$event_type\",
            \"severity\": $severity,
            \"details\": \"$details\",
            \"source\": \"test\"
        }")

    score=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"{d.get('previous_score',0):.1f} -> {d.get('new_score',0):.1f}\")" 2>/dev/null)
    status=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('attacker_status','?'))" 2>/dev/null)
    actions=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('actions_triggered',[]))" 2>/dev/null)

    printf "  %-28s score: %-20s status: %-12s actions: %s\n" \
        "[$event_type]" "$score" "$status" "$actions"
    sleep 0.5
}

# ── STEP 1: Health checks ──
section "STEP 1: Health Checks"
info "Checking Profiler API..."
health=$(curl -s "$PROFILER/api/health")
if echo "$health" | grep -q "running"; then
    log "Profiler API: OK"
else
    echo -e "${RED}[ERROR]${NC} Profiler not responding. Start it first."
    exit 1
fi

info "Checking Dashboard..."
dash=$(curl -s "http://localhost:8080/api/health")
echo "$dash" | grep -q "running" && log "Dashboard: OK" || warn "Dashboard not running on 8080"

info "Checking Server1..."
curl -s --connect-timeout 3 "http://$SERVER1_IP/" > /dev/null && \
    log "Server1 Apache: OK" || warn "Server1 not reachable at $SERVER1_IP"

info "Checking Decoy..."
curl -s --connect-timeout 3 "http://$DECOY_IP/api/health" > /dev/null && \
    log "Decoy: OK" || warn "Decoy not reachable at $DECOY_IP"

# ── STEP 2: Reset attacker profile ──
section "STEP 2: Reset Attacker Profile"
curl -s -X DELETE "$PROFILER/api/profile/$ATTACKER_IP" \
    -H "X-API-Key: $API_KEY" > /dev/null
log "Profile reset for $ATTACKER_IP"

# ── STEP 3: Simulate attack progression ──
section "STEP 3: Simulating Attack Progression"
echo ""
printf "  %-28s %-20s %-12s %s\n" "Event" "Score" "Status" "Actions"
printf "  %s\n" "$(printf '─%.0s' {1..80})"

info "Stage 1: Reconnaissance (target score ~13)"
send_event "syn_scan"   5  "nmap SYN scan on ports 22,80,443"
send_event "port_sweep" 8  "nmap full port sweep -T4"

info "Stage 2: Directory Enumeration (target score ~25)"
send_event "directory_enumeration" 6 "gobuster scan /admin /config /.env"
send_event "directory_enumeration" 6 "Multiple 404 probes detected (15 requests)"

info "Stage 3: Credential Attacks (target score ~40 — REDIRECT TRIGGER)"
send_event "failed_login" 3  "SSH failed password attempt #1"
send_event "failed_login" 3  "SSH failed password attempt #2"
send_event "brute_force"  15 "SSH brute force: 5+ failures detected"

info "Stage 4: Decoy Interaction"
send_event "decoy_interaction" 10 "Attacker reached decoy landing page"
send_event "fake_shell_command" 2 "Fake shell: whoami"

info "Stage 5: Honeytoken Access (target score ~70+ — NOISE TRIGGER)"
send_event "honeytoken_access" 25 "HONEYTOKEN: /database-dump.sql accessed"

info "Stage 6: Privilege Escalation (target score ~100 — FORENSIC TRIGGER)"
send_event "privilege_escalation" 20 "Sudo command detected in session"
send_event "honeytoken_access"    25 "HONEYTOKEN: /.env accessed"

# ── STEP 4: Check final profile ──
section "STEP 4: Final Attacker Profile"
curl -s "$PROFILER/api/profile/$ATTACKER_IP?api_key=$API_KEY" | python3 -m json.tool

# ── STEP 5: Check triggered actions ──
section "STEP 5: Triggered Actions"
curl -s "$PROFILER/api/actions?api_key=$API_KEY" | python3 -m json.tool

# ── STEP 6: Check iptables redirect on this machine ──
section "STEP 6: iptables Redirect Rules"
sudo iptables -t nat -L PREROUTING -n -v 2>/dev/null || warn "Cannot read iptables (need root)"

# ── STEP 7: Test redirect from Server1 (manual reminder) ──
section "STEP 7: Apply Redirect on Server1"
warn "If profiler triggered redirect_to_decoy, run this on Server1:"
echo ""
echo "  sudo bash /opt/deception_engine/scripts/redirect.sh $ATTACKER_IP"
echo ""
warn "Then test from Attacker VM:"
echo "  curl http://$SERVER1_IP/    # Should return Decoy content"
echo "  curl http://$DECOY_IP/      # Direct Decoy access"

# ── STEP 8: Forensic snapshots ──
section "STEP 8: Forensic Snapshots"
FORENSIC_DIR="/opt/deception_engine/forensics"
if ls "$FORENSIC_DIR"/forensic_*.json 2>/dev/null | head -3; then
    log "Forensic snapshots generated successfully"
else
    warn "No forensic snapshots found yet in $FORENSIC_DIR"
fi

# ── Summary ──
section "TEST COMPLETE"
log "Dashboard: http://192.168.56.200:8080"
log "Profiles:  $PROFILER/api/profiles?api_key=$API_KEY"
log "Events:    $PROFILER/api/events?api_key=$API_KEY"
log "Actions:   $PROFILER/api/actions?api_key=$API_KEY"
