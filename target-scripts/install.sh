#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - Installation Script for Target Systems
# ============================================================================
# Installs monitoring collectors on target Linux systems
#
# Usage:
#   ./install.sh --api-url <URL> --api-key <KEY> --target-id <ID>
#
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/cybersheppard"
CONFIG_DIR="/etc/cybersheppard"
LOG_DIR="/var/log/cybersheppard"
SERVICE_NAME="cybersheppard-collector"

API_URL=""
API_KEY=""
TARGET_ID=""

# ============================================================================
# Functions
# ============================================================================
info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

check_root() {
    if [ "$(id -u)" != "0" ]; then
        error "This script must be run as root"
        exit 1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --api-url)
                API_URL="$2"
                shift 2
                ;;
            --api-key)
                API_KEY="$2"
                shift 2
                ;;
            --target-id)
                TARGET_ID="$2"
                shift 2
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    if [ -z "$API_URL" ] || [ -z "$API_KEY" ] || [ -z "$TARGET_ID" ]; then
        error "Missing required parameters"
        echo "Usage: $0 --api-url <URL> --api-key <KEY> --target-id <ID>"
        exit 1
    fi
}

create_directories() {
    info "Creating directories..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    chmod 750 "$INSTALL_DIR"
    chmod 750 "$CONFIG_DIR"
    chmod 750 "$LOG_DIR"
}

install_collectors() {
    info "Installing collector scripts..."

    # Copy main collector script
    cp cybersheppard-collector.sh "$INSTALL_DIR/"
    chmod 750 "$INSTALL_DIR/cybersheppard-collector.sh"

    # Copy individual collectors
    mkdir -p "$INSTALL_DIR/collectors"
    cp collectors/*.sh "$INSTALL_DIR/collectors/"
    chmod 750 "$INSTALL_DIR/collectors"/*.sh
}

create_config() {
    info "Creating configuration file..."

    cat > "$CONFIG_DIR/config.conf" <<EOF
# CyberSheppard Target Configuration
CYBERSHEPPARD_API_URL="$API_URL"
CYBERSHEPPARD_API_KEY="$API_KEY"
CYBERSHEPPARD_TARGET_ID="$TARGET_ID"
INTERVAL=30
VERBOSE=false
EOF

    chmod 640 "$CONFIG_DIR/config.conf"
}

create_systemd_service() {
    info "Creating systemd service..."

    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=CyberSheppard Monitoring Collector
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/cybersheppard-collector.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cybersheppard

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

enable_and_start() {
    info "Enabling and starting service..."
    systemctl enable ${SERVICE_NAME}.service
    systemctl start ${SERVICE_NAME}.service
}

verify_installation() {
    info "Verifying installation..."

    # Check if service is running
    if systemctl is-active --quiet ${SERVICE_NAME}.service; then
        info "Service is running ✓"
    else
        warn "Service is not running"
        systemctl status ${SERVICE_NAME}.service || true
    fi

    # Check if collectors are executable
    for script in "$INSTALL_DIR/collectors"/*.sh; do
        if [ -x "$script" ]; then
            info "$(basename "$script") is executable ✓"
        else
            warn "$(basename "$script") is not executable"
        fi
    done
}

# ============================================================================
# Main
# ============================================================================
main() {
    info "CyberSheppard Target Installation"
    info "=================================="

    check_root
    parse_args "$@"

    create_directories
    install_collectors
    create_config
    create_systemd_service
    enable_and_start
    verify_installation

    info ""
    info "Installation complete!"
    info "Service status: systemctl status ${SERVICE_NAME}"
    info "Logs: journalctl -u ${SERVICE_NAME} -f"
    info "Config: $CONFIG_DIR/config.conf"
}

main "$@"
