#!/usr/bin/env python3
"""
deception_proxy.py
Transparent TCP proxy running on Server1 (192.168.56.103).

How it works:
1. Listens on port 80 (replaces Apache on port 80)
2. Apache moves to port 8080 (real website)
3. Every new connection checks the source IP risk score from Profiler API
4. If score >= 40 (redirected status) → forward to Decoy server
5. Otherwise → forward to real Apache on localhost:8080
6. Also runs Scapy SYN scan detector to send events to Profiler in real time

The attacker IP is detected AUTOMATICALLY — no manual configuration needed.
The attacker never knows they are being redirected.

Run with:
    sudo python3 deception_proxy.py
"""

import json
import logging
import os
import socket
import threading
import time
import requests

from scapy.all import sniff, IP, TCP

# ─────────────────────────── CONFIG ───────────────────────────────────────────

CONFIG_PATH = os.environ.get(
    "PROFILER_CONFIG",
    "/opt/deception_engine/config/config.json"
)

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

SERVER1_IP   = CONFIG["network"]["server1_ip"]    # 192.168.56.103
DECOY_IP     = CONFIG["network"]["decoy_ip"]       # 192.168.56.106
PROFILER_IP  = CONFIG["network"]["profiler_ip"]    # 192.168.56.200
API_KEY      = CONFIG["profiler"]["api_key"]

LISTEN_PORT        = 80      # Proxy listens here (public)
REAL_BACKEND_PORT  = 8080    # Apache moved here
DECOY_PORT         = 80      # Decoy Flask port

PROFILER_API       = f"http://{PROFILER_IP}:5000"
REDIRECT_THRESHOLD = CONFIG["thresholds"]["redirect"]   # 40

# SYN scan detection
PORT_THRESHOLD = 5    # distinct ports in time window
TIME_WINDOW    = 10   # seconds

# ─────────────────────────── LOGGING ──────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/deception_engine/proxy.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("deception_proxy")

# ─────────────────────────── STATE ────────────────────────────────────────────

# Local cache of flagged IPs to avoid hitting Profiler API on every packet
# Format: { ip: {"score": float, "status": str, "cached_at": float} }
ip_cache       = {}
cache_lock     = threading.Lock()
CACHE_TTL      = 10   # seconds — re-check Profiler every 10s

scan_stats     = {}   # for SYN scan detection
scan_lock      = threading.Lock()

# ─────────────────────────── PROFILER COMMUNICATION ──────────────────────────

def get_ip_score(src_ip: str) -> dict:
    """
    Query Profiler API for the current risk score of an IP.
    Uses local cache to avoid hammering the API.
    Returns dict with score and status.
    """
    now = time.time()

    with cache_lock:
        cached = ip_cache.get(src_ip)
        if cached and (now - cached["cached_at"]) < CACHE_TTL:
            return cached

    try:
        resp = requests.get(
            f"{PROFILER_API}/api/profile/{src_ip}",
            headers={"X-API-Key": API_KEY},
            timeout=2
        )
        if resp.status_code == 200:
            data = resp.json()
            result = {
                "score":     data.get("risk_score", 0),
                "status":    data.get("status", "unknown"),
                "cached_at": now
            }
        else:
            result = {"score": 0, "status": "unknown", "cached_at": now}
    except Exception:
        result = {"score": 0, "status": "unknown", "cached_at": now}

    with cache_lock:
        ip_cache[src_ip] = result

    return result


def send_event(src_ip: str, event_type: str, severity: float, details: str):
    """Send a security event to the Profiler API."""
    try:
        requests.post(
            f"{PROFILER_API}/api/event",
            headers={
                "X-API-Key": API_KEY,
                "Content-Type": "application/json"
            },
            json={
                "src_ip":     src_ip,
                "event_type": event_type,
                "severity":   severity,
                "details":    details,
                "source":     "proxy"
            },
            timeout=2
        )
    except Exception as e:
        logger.warning(f"Could not send event to Profiler: {e}")


def invalidate_cache(src_ip: str):
    """Force re-check of this IP on next connection."""
    with cache_lock:
        ip_cache.pop(src_ip, None)

# ─────────────────────────── BACKEND SELECTION ───────────────────────────────

def choose_backend(src_ip: str) -> tuple:
    """
    Decide where to forward this connection.
    Checks the Profiler API for the current risk score.

    Returns (host, port, reason)
    """
    profile = get_ip_score(src_ip)
    score  = profile["score"]
    status = profile["status"]

    if score >= REDIRECT_THRESHOLD or status in ("redirected", "high_risk", "critical"):
        logger.warning(
            f"[REDIRECT] {src_ip} score={score:.1f} status={status} "
            f"-> DECOY {DECOY_IP}:{DECOY_PORT}"
        )
        return (DECOY_IP, DECOY_PORT, "redirected_to_decoy")

    logger.info(
        f"[ALLOW] {src_ip} score={score:.1f} status={status} "
        f"-> REAL SERVER localhost:{REAL_BACKEND_PORT}"
    )
    return ("127.0.0.1", REAL_BACKEND_PORT, "allowed_real_server")

# ─────────────────────────── TCP PROXY ───────────────────────────────────────

def pipe(src: socket.socket, dst: socket.socket):
    """Copy bytes bidirectionally between two sockets."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_connection(client_sock: socket.socket, client_addr: tuple):
    """Handle a single incoming connection — forward to correct backend."""
    src_ip, src_port = client_addr
    backend_host, backend_port, reason = choose_backend(src_ip)

    logger.info(
        f"[CONN] {src_ip}:{src_port} -> {backend_host}:{backend_port} ({reason})"
    )

    try:
        server_sock = socket.create_connection(
            (backend_host, backend_port), timeout=5
        )
    except Exception as e:
        logger.error(f"[CONN] Failed to connect to backend {backend_host}:{backend_port}: {e}")
        client_sock.close()
        return

    # Bidirectional forwarding
    t1 = threading.Thread(target=pipe, args=(client_sock, server_sock), daemon=True)
    t2 = threading.Thread(target=pipe, args=(server_sock, client_sock), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    client_sock.close()
    server_sock.close()


def start_proxy():
    """Start the TCP proxy listener on port 80."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(100)
    logger.info(f"[*] Deception proxy listening on 0.0.0.0:{LISTEN_PORT}")
    logger.info(f"[*] Real backend: localhost:{REAL_BACKEND_PORT}")
    logger.info(f"[*] Decoy backend: {DECOY_IP}:{DECOY_PORT}")
    logger.info(f"[*] Redirect threshold: score >= {REDIRECT_THRESHOLD}")

    while True:
        try:
            client_sock, client_addr = server.accept()
            threading.Thread(
                target=handle_connection,
                args=(client_sock, client_addr),
                daemon=True
            ).start()
        except Exception as e:
            logger.error(f"[*] Accept error: {e}")

# ─────────────────────────── SYN SCAN DETECTOR ───────────────────────────────

def process_packet(pkt):
    """
    Scapy packet callback.
    Detects SYN scans and sends events to Profiler automatically.
    The attacker IP is extracted directly from the packet.
    """
    if IP not in pkt or TCP not in pkt:
        return

    ip_layer  = pkt[IP]
    tcp_layer = pkt[TCP]

    if ip_layer.dst != SERVER1_IP:
        return

    # SYN only (no ACK) — typical nmap -sS probe
    flags = int(tcp_layer.flags)
    if not (flags & 0x02) or (flags & 0x10):
        return

    src_ip = ip_layer.src
    dport  = int(tcp_layer.dport)
    now    = time.time()

    with scan_lock:
        entry = scan_stats.get(src_ip)
        if not entry:
            entry = {"ports": set(), "first_seen": now}
            scan_stats[src_ip] = entry

        # Reset window if expired
        if now - entry["first_seen"] > TIME_WINDOW:
            entry["ports"] = set()
            entry["first_seen"] = now

        entry["ports"].add(dport)
        port_count = len(entry["ports"])

        # Send event every 5 new ports detected
        if port_count % 5 == 0:
            logger.warning(
                f"[SCAN] SYN scan from {src_ip} — {port_count} ports scanned"
            )
            threading.Thread(
                target=send_event,
                args=(
                    src_ip,
                    "syn_scan" if port_count < 20 else "port_sweep",
                    5 if port_count < 20 else 8,
                    f"SYN scan detected: {port_count} ports in {TIME_WINDOW}s"
                ),
                daemon=True
            ).start()
            # Invalidate cache so next connection re-checks score
            invalidate_cache(src_ip)


def start_syn_detector():
    """Background thread — sniff packets and detect SYN scans."""
    logger.info(f"[*] Starting SYN scan detector for {SERVER1_IP}")
    bpf = f"tcp and dst host {SERVER1_IP}"
    sniff(filter=bpf, prn=process_packet, store=False)

# ─────────────────────────── MAIN ────────────────────────────────────────────

def main():
    logger.info("[*] Deception Proxy starting...")
    logger.info(f"[*] Server1: {SERVER1_IP}")
    logger.info(f"[*] Decoy:   {DECOY_IP}")
    logger.info(f"[*] Profiler API: {PROFILER_API}")

    # Start SYN scan detector in background
    t_sniff = threading.Thread(target=start_syn_detector, daemon=True)
    t_sniff.start()

    # Start TCP proxy (blocking)
    start_proxy()


if __name__ == "__main__":
    main()
