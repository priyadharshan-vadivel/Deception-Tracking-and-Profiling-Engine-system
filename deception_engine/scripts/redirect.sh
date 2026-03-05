#!/bin/bash
# =============================================================
# redirect.sh
# Installs iptables DNAT rule to silently redirect attacker
# HTTP traffic from Server1 to the Decoy server.
#
# The attacker's browser URL still shows Server1 IP but all
# content is served from the Decoy — attacker never knows.
#
# Usage:
#   sudo bash redirect.sh <attacker_ip>
#   sudo bash redirect.sh 192.168.56.102
# =============================================================

ATTACKER_IP="$1"
DECOY_IP="192.168.56.106"
REDIRECT_PORT="80"

if [[ -z "$ATTACKER_IP" ]]; then
    echo "[ERROR] Usage: $0 <attacker_ip>"
    exit 1
fi

echo "[*] Installing redirect: $ATTACKER_IP -> $DECOY_IP:$REDIRECT_PORT"

# Check if DNAT rule already exists — avoid duplicates
if sudo iptables -t nat -C PREROUTING \
    -s "$ATTACKER_IP" -p tcp --dport "$REDIRECT_PORT" \
    -j DNAT --to-destination "$DECOY_IP:$REDIRECT_PORT" 2>/dev/null; then
    echo "[!] Redirect rule already exists for $ATTACKER_IP — skipping."
    exit 0
fi

# Rule 1: DNAT — redirect incoming attacker packets to Decoy
sudo iptables -t nat -A PREROUTING \
    -s "$ATTACKER_IP" \
    -p tcp --dport "$REDIRECT_PORT" \
    -j DNAT --to-destination "$DECOY_IP:$REDIRECT_PORT"

# Rule 2: FORWARD — allow forwarding of redirected packets
sudo iptables -A FORWARD \
    -s "$ATTACKER_IP" \
    -p tcp --dport "$REDIRECT_PORT" \
    -j ACCEPT

# Rule 3: MASQUERADE — rewrite source so Decoy return traffic routes correctly
sudo iptables -t nat -A POSTROUTING \
    -d "$DECOY_IP" \
    -p tcp --dport "$REDIRECT_PORT" \
    -j MASQUERADE

echo "[+] Redirect rule installed successfully"
echo "[+] Attacker $ATTACKER_IP -> Server1:$REDIRECT_PORT -> Decoy $DECOY_IP:$REDIRECT_PORT"
echo ""
echo "[*] Current NAT rules:"
sudo iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E "DNAT|Chain"
