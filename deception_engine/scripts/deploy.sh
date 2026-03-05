#!/bin/bash
# ============================================================
# deploy.sh  —  Fixed version
# Deception Tracking and Profiling Engine
#
# Usage:
#   sudo ROLE=profiler bash deploy.sh
#   sudo ROLE=server1  bash deploy.sh
#   sudo ROLE=decoy    bash deploy.sh
# ============================================================

set -e

ROLE="${ROLE:-profiler}"
PROJECT_DIR="/opt/deception_engine"
CONFIG_FILE="$PROJECT_DIR/config/config.json"
LOG_DIR="/var/log/deception_engine"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error(){ echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    [[ $EUID -ne 0 ]] && error "Run as root: sudo ROLE=$ROLE bash deploy.sh"
}

install_base() {
    log "Updating package lists..."
    apt-get update -qq

    log "Installing system dependencies..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv \
        git curl wget net-tools \
        iptables iptables-persistent \
        apache2 nmap 2>/dev/null || true

    log "Installing Python dependencies..."
    pip3 install flask requests scapy \
        --break-system-packages --quiet 2>/dev/null || \
    pip3 install flask requests scapy --quiet || true

    log "Base packages installed."
}

setup_directories() {
    log "Creating project directories..."
    mkdir -p "$PROJECT_DIR"/{profiler_engine,server_monitor,decoy_logger,dashboard,config,scripts,database,forensics}
    mkdir -p "$LOG_DIR"
    chmod 755 "$PROJECT_DIR"
    chmod 755 "$LOG_DIR"
    log "Directories ready at $PROJECT_DIR"
}

copy_project_files() {
    log "Copying project source files..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SOURCE_DIR="$(dirname "$SCRIPT_DIR")"

    if [[ ! -d "$SOURCE_DIR/profiler_engine" ]]; then
        warn "Source not found at $SOURCE_DIR — files may already be in place, skipping copy."
        return
    fi

    # -n flag = no-clobber (skip if destination already exists — fixes "same file" errors)
    for dir in profiler_engine server_monitor decoy_logger dashboard config scripts database; do
        SRC="$SOURCE_DIR/$dir"
        DST="$PROJECT_DIR/$dir"
        if [[ "$SRC" != "$DST" ]] && [[ -d "$SRC" ]]; then
            cp -rn "$SRC/"* "$DST/" 2>/dev/null || true
        fi
    done

    log "Source files in place at $PROJECT_DIR"
}

deploy_profiler() {
    log "Deploying Profiler Engine..."

    systemctl stop deception-profiler deception-dashboard 2>/dev/null || true

    log "Initializing database..."
    PROFILER_CONFIG="$CONFIG_FILE" python3 "$PROJECT_DIR/database/init_database.py"

    ufw allow 5000/tcp 2>/dev/null || true
    ufw allow 8080/tcp 2>/dev/null || true

    cat > /etc/systemd/system/deception-profiler.service << EOF
[Unit]
Description=Deception Profiling Engine API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR/profiler_engine
Environment=PROFILER_CONFIG=$CONFIG_FILE
ExecStart=/usr/bin/python3 $PROJECT_DIR/profiler_engine/profiler_api.py
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/profiler.log
StandardError=append:$LOG_DIR/profiler_error.log

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/deception-dashboard.service << EOF
[Unit]
Description=Deception Engine Web Dashboard
After=network.target deception-profiler.service

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR/dashboard
Environment=PROFILER_CONFIG=$CONFIG_FILE
ExecStart=/usr/bin/python3 $PROJECT_DIR/dashboard/dashboard.py
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/dashboard.log
StandardError=append:$LOG_DIR/dashboard_error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable deception-profiler deception-dashboard
    systemctl start deception-profiler

    log "Waiting for Profiler API to start..."
    sleep 4

    if curl -s http://localhost:5000/api/health > /dev/null 2>&1; then
        log "Profiler API is up. Starting Dashboard..."
        systemctl start deception-dashboard
        sleep 2
        curl -s http://localhost:5000/api/health | python3 -m json.tool
    else
        warn "Profiler API did not respond on port 5000."
        warn "Check errors: tail -30 $LOG_DIR/profiler_error.log"
    fi

    log "Profiler API  -> http://$(hostname -I | awk '{print $1}'):5000/api/health"
    log "Dashboard     -> http://$(hostname -I | awk '{print $1}'):8080"
}

deploy_server1() {
    log "Deploying Server1 monitoring agent..."

    systemctl enable apache2 && systemctl start apache2

    log "Placing honeytoken files in web root..."
    echo "FAKE BACKUP HONEYTOKEN - ACCESS LOGGED"  > /var/www/html/secret-backup.zip
    echo "-- FAKE SQL DUMP HONEYTOKEN"              > /var/www/html/database-dump.sql
    echo "DB_PASSWORD=HONEYTOKEN_FAKE_PASSWORD"     > /var/www/html/.env

    log "Enabling IP forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || \
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p 2>/dev/null || true

    cat > /etc/systemd/system/deception-monitor.service << EOF
[Unit]
Description=Deception Engine Server Monitor
After=network.target apache2.service

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR/server_monitor
Environment=PROFILER_CONFIG=$CONFIG_FILE
ExecStart=/usr/bin/python3 $PROJECT_DIR/server_monitor/monitor.py
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/monitor.log
StandardError=append:$LOG_DIR/monitor_error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable deception-monitor
    systemctl start deception-monitor
    log "Server1 monitor started. Apache running."
}

deploy_decoy() {
    log "Deploying Decoy server..."

    systemctl stop apache2 2>/dev/null || true
    systemctl disable apache2 2>/dev/null || true

    cat > /etc/systemd/system/deception-decoy.service << EOF
[Unit]
Description=Deception Engine Decoy Logger
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR/decoy_logger
Environment=PROFILER_CONFIG=$CONFIG_FILE
Environment=DECOY_PORT=80
ExecStart=/usr/bin/python3 $PROJECT_DIR/decoy_logger/decoy_logger.py
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/decoy.log
StandardError=append:$LOG_DIR/decoy_error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable deception-decoy
    systemctl start deception-decoy
    sleep 2
    curl -s http://localhost:80/api/health | python3 -m json.tool || \
        warn "Decoy health check failed — check: tail -20 $LOG_DIR/decoy_error.log"
    log "Decoy server running on port 80"
}

show_status() {
    echo
    log "=== DEPLOYMENT STATUS ==="
    case $ROLE in
        profiler)
            systemctl status deception-profiler  --no-pager -l 2>/dev/null | head -12
            echo "---"
            systemctl status deception-dashboard --no-pager -l 2>/dev/null | head -12
            echo
            log "Profiler API : http://$(hostname -I | awk '{print $1}'):5000/api/health"
            log "Dashboard    : http://$(hostname -I | awk '{print $1}'):8080"
            log "Logs         : tail -f $LOG_DIR/profiler.log"
            ;;
        server1)
            systemctl status deception-monitor --no-pager -l 2>/dev/null | head -12
            systemctl status apache2           --no-pager -l 2>/dev/null | head -6
            ;;
        decoy)
            systemctl status deception-decoy --no-pager -l 2>/dev/null | head -12
            ;;
    esac
}

main() {
    log "Deception Tracking & Profiling Engine — Deploy Script"
    log "Role: $ROLE | OS: Ubuntu $(lsb_release -rs 2>/dev/null || echo unknown)"
    echo

    check_root
    install_base
    setup_directories
    copy_project_files

    case $ROLE in
        profiler) deploy_profiler ;;
        server1)  deploy_server1  ;;
        decoy)    deploy_decoy    ;;
        *)        error "Unknown role '$ROLE'. Use: profiler | server1 | decoy" ;;
    esac

    show_status

    echo
    log "=== DEPLOYMENT COMPLETE ==="
    log "Project : $PROJECT_DIR"
    log "Logs    : $LOG_DIR"
    log "Config  : $CONFIG_FILE"
}

main "$@"
