#!/bin/bash
# =============================================================
# setup_proxy.sh
# Sets up the deception proxy on Server1.
#
# What this does:
# 1. Moves Apache from port 80 to port 8080
# 2. Installs scapy
# 3. Starts the deception proxy on port 80
# 4. Proxy auto-detects attacker IP and redirects to Decoy
#
# Run on Server1:
#   sudo bash setup_proxy.sh
# =============================================================

echo "[+] Setting up Deception Proxy on Server1..."

# Step 1 — Install scapy
pip3 install scapy --break-system-packages --quiet
echo "[+] Scapy installed"

# Step 2 — Move Apache from port 80 to port 8080
echo "[+] Moving Apache to port 8080..."
sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf
sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' \
    /etc/apache2/sites-enabled/000-default.conf 2>/dev/null || true
systemctl restart apache2
echo "[+] Apache now on port 8080"

# Step 3 — Verify Apache is on 8080
sleep 2
ss -tlnp | grep 8080 && echo "[+] Apache confirmed on port 8080" || \
    echo "[!] Apache not found on 8080 — check manually"

# Step 4 — Open firewall
ufw allow 80/tcp 2>/dev/null || true
ufw allow 8080/tcp 2>/dev/null || true

# Step 5 — Kill any old proxy instances
pkill -f deception_proxy.py 2>/dev/null || true
sleep 1

# Step 6 — Create log file
mkdir -p /var/log/deception_engine
chmod 777 /var/log/deception_engine
touch /var/log/deception_engine/proxy.log
chmod 666 /var/log/deception_engine/proxy.log

# Step 7 — Start proxy
echo "[+] Starting Deception Proxy on port 80..."
sudo bash -c 'PROFILER_CONFIG=/opt/deception_engine/config/config.json \
  nohup python3 /opt/deception_engine/server_monitor/deception_proxy.py \
  >> /var/log/deception_engine/proxy.log 2>&1 &'

sleep 3
ss -tlnp | grep :80 && echo "[+] Proxy confirmed on port 80" || \
    echo "[!] Proxy not found on port 80"

echo ""
echo "[+] Setup complete!"
echo "[+] Real website: http://$(hostname -I | awk '{print $1}'):8080"
echo "[+] Proxy on:     http://$(hostname -I | awk '{print $1}'):80"
echo "[+] Proxy logs:   tail -f /var/log/deception_engine/proxy.log"
