#!/bin/bash
# =============================================================
# remove_redirect.sh
# Removes a previously installed iptables DNAT redirect rule.
#
# Usage:
#   sudo bash remove_redirect.sh <attacker_ip>
#   sudo bash remove_redirect.sh 192.168.56.102
# =============================================================

ATTACKER_IP="$1"
DECOY_IP="192.168.56.106"
REDIRECT_PORT="80"

if [[ -z "$ATTACKER_IP" ]]; then
    echo "[ERROR] Usage: $0 <attacker_ip>"
    exit 1
fi

echo "[*] Removing redirect rules for $ATTACKER_IP"

# Remove DNAT rule
sudo iptables -t nat -D PREROUTING \
    -s "$ATTACKER_IP" -p tcp --dport "$REDIRECT_PORT" \
    -j DNAT --to-destination "$DECOY_IP:$REDIRECT_PORT" 2>/dev/null && \
    echo "[+] DNAT rule removed" || echo "[!] DNAT rule not found"

# Remove FORWARD rule
sudo iptables -D FORWARD \
    -s "$ATTACKER_IP" -p tcp --dport "$REDIRECT_PORT" \
    -j ACCEPT 2>/dev/null && \
    echo "[+] FORWARD rule removed" || echo "[!] FORWARD rule not found"

echo "[+] Done. Current NAT table:"
sudo iptables -t nat -L PREROUTING -n -v --line-numbers
