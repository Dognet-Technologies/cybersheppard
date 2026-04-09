#!/bin/bash
# ============================================================================
# CyberSheppard Agent Installation Script
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
BINARY_NAME="cybersheppard-agent"
SERVICE_NAME="cybersheppard-agent"

echo -e "${GREEN}=== CyberSheppard Agent Installer ===${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Check for required commands
for cmd in curl systemctl; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}Error: $cmd is required but not installed${NC}"
        exit 1
    fi
done

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Copy binary
echo -e "${YELLOW}Installing agent binary...${NC}"
if [ -f "./target/release/$BINARY_NAME" ]; then
    cp "./target/release/$BINARY_NAME" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    echo -e "${GREEN}✓ Binary installed${NC}"
else
    echo -e "${RED}Error: Binary not found. Run 'cargo build --release' first${NC}"
    exit 1
fi

# Copy configuration
echo -e "${YELLOW}Setting up configuration...${NC}"
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    if [ -f "./deploy/config.example.toml" ]; then
        cp "./deploy/config.example.toml" "$CONFIG_DIR/config.toml"
        echo -e "${GREEN}✓ Configuration template installed${NC}"
        echo -e "${YELLOW}  Please edit $CONFIG_DIR/config.toml with your settings${NC}"
    else
        echo -e "${RED}Error: config.example.toml not found${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}  Configuration already exists, skipping${NC}"
fi

# Create systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=CyberSheppard Monitoring Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$INSTALL_DIR/$BINARY_NAME $CONFIG_DIR/config.toml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}✓ Systemd service created${NC}"

# Reload systemd
systemctl daemon-reload

# Set up log rotation
echo -e "${YELLOW}Setting up log rotation...${NC}"
cat > "/etc/logrotate.d/$SERVICE_NAME" << EOF
$LOG_DIR/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}
EOF

echo -e "${GREEN}✓ Log rotation configured${NC}"

echo ""
echo -e "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit configuration: nano $CONFIG_DIR/config.toml"
echo "  2. Start agent: systemctl start $SERVICE_NAME"
echo "  3. Enable on boot: systemctl enable $SERVICE_NAME"
echo "  4. Check status: systemctl status $SERVICE_NAME"
echo "  5. View logs: journalctl -u $SERVICE_NAME -f"
echo ""
