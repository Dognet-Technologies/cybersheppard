#!/bin/bash
# ============================================================================
# CyberSheppard Agent Uninstallation Script
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/cybersheppard-agent"
CONFIG_DIR="/etc/cybersheppard-agent"
LOG_DIR="/var/log/cybersheppard-agent"
SERVICE_NAME="cybersheppard-agent"

echo -e "${YELLOW}=== CyberSheppard Agent Uninstaller ===${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Stop and disable service
echo -e "${YELLOW}Stopping service...${NC}"
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
echo -e "${GREEN}✓ Service stopped${NC}"

# Remove systemd service
echo -e "${YELLOW}Removing systemd service...${NC}"
rm -f "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
echo -e "${GREEN}✓ Service removed${NC}"

# Remove directories
echo -e "${YELLOW}Removing files...${NC}"
rm -rf "$INSTALL_DIR"
rm -f "/etc/logrotate.d/$SERVICE_NAME"
echo -e "${GREEN}✓ Files removed${NC}"

# Ask about config and logs
read -p "Remove configuration ($CONFIG_DIR)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$CONFIG_DIR"
    echo -e "${GREEN}✓ Configuration removed${NC}"
fi

read -p "Remove logs ($LOG_DIR)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$LOG_DIR"
    echo -e "${GREEN}✓ Logs removed${NC}"
fi

echo ""
echo -e "${GREEN}=== Uninstallation Complete ===${NC}"
echo ""
