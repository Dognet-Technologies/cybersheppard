#!/bin/bash
# ============================================================================
# CyberSheppard - Production Setup Script
# ============================================================================
# This script sets up CyberSheppard for production deployment
# Run with: sudo ./setup-production.sh

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
APP_USER="cybersheppard"
APP_GROUP="cybersheppard"
INSTALL_DIR="/opt/cybersheppard"
LOG_DIR="/var/log/cybersheppard"
DATA_DIR="/var/lib/cybersheppard"
BACKUP_DIR="/var/backups/cybersheppard"
NGINX_CONF="/etc/nginx/sites-available/cybersheppard"
SSL_DIR="/etc/nginx/ssl"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

create_user() {
    log_info "Creating application user..."
    if ! id "$APP_USER" &>/dev/null; then
        useradd -r -s /bin/bash -d "$INSTALL_DIR" -m "$APP_USER"
        log_info "User $APP_USER created"
    else
        log_warn "User $APP_USER already exists"
    fi
}

create_directories() {
    log_info "Creating application directories..."
    mkdir -p "$LOG_DIR" "$DATA_DIR" "$BACKUP_DIR" "$SSL_DIR"
    chown -R "$APP_USER:$APP_GROUP" "$LOG_DIR" "$DATA_DIR" "$BACKUP_DIR"
    chmod 750 "$LOG_DIR" "$DATA_DIR" "$BACKUP_DIR"
    log_info "Directories created"
}

install_dependencies() {
    log_info "Installing system dependencies..."
    apt-get update -qq
    apt-get install -y \
        postgresql postgresql-contrib \
        influxdb influxdb-client \
        nginx \
        python3 python3-pip python3-venv \
        build-essential \
        curl wget git \
        certbot python3-certbot-nginx \
        logrotate \
        ufw
    log_info "Dependencies installed"
}

setup_postgresql() {
    log_info "Setting up PostgreSQL..."
    systemctl enable postgresql
    systemctl start postgresql

    # Create database and user (if not exists)
    sudo -u postgres psql <<EOF
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = 'cybersheppard') THEN
        CREATE USER cybersheppard WITH PASSWORD 'CHANGE_ME';
    END IF;
END \$\$;

DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cybersheppard') THEN
        CREATE DATABASE cybersheppard OWNER cybersheppard;
    END IF;
END \$\$;

GRANT ALL PRIVILEGES ON DATABASE cybersheppard TO cybersheppard;
EOF

    log_info "PostgreSQL setup complete"
}

setup_influxdb() {
    log_info "Setting up InfluxDB..."
    systemctl enable influxdb
    systemctl start influxdb

    log_warn "Please configure InfluxDB manually:"
    log_warn "  1. Run: influx setup"
    log_warn "  2. Create org: cybersheppard"
    log_warn "  3. Create buckets: metrics, logs, correlations"
    log_warn "  4. Generate API token and update .env"
}

generate_ssl_cert() {
    log_info "Generating self-signed SSL certificate..."
    if [[ ! -f "$SSL_DIR/cybersheppard.crt" ]]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
            -keyout "$SSL_DIR/cybersheppard.key" \
            -out "$SSL_DIR/cybersheppard.crt" \
            -subj "/C=IT/ST=Italy/L=Rome/O=CyberSheppard/CN=cybersheppard.local"

        openssl dhparam -out "$SSL_DIR/dhparam.pem" 2048

        chmod 600 "$SSL_DIR/cybersheppard.key"
        chmod 644 "$SSL_DIR/cybersheppard.crt"

        log_info "Self-signed certificate generated"
        log_warn "For production, replace with Let's Encrypt certificate:"
        log_warn "  certbot --nginx -d your-domain.com"
    else
        log_warn "SSL certificate already exists"
    fi
}

setup_nginx() {
    log_info "Setting up Nginx..."

    # Copy nginx config
    cp "$(dirname "$0")/nginx/cybersheppard.conf" "$NGINX_CONF"
    ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/cybersheppard

    # Test nginx config
    nginx -t

    # Enable and restart nginx
    systemctl enable nginx
    systemctl restart nginx

    log_info "Nginx configured"
}

setup_systemd_services() {
    log_info "Setting up systemd services..."

    cp "$(dirname "$0")/systemd/cybersheppard-rust.service" /etc/systemd/system/
    cp "$(dirname "$0")/systemd/cybersheppard-django.service" /etc/systemd/system/

    systemctl daemon-reload
    systemctl enable cybersheppard-rust
    systemctl enable cybersheppard-django

    log_info "Systemd services configured (not started yet)"
}

setup_logrotate() {
    log_info "Setting up log rotation..."
    cat > /etc/logrotate.d/cybersheppard <<'EOF'
/var/log/cybersheppard/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 cybersheppard cybersheppard
    sharedscripts
    postrotate
        systemctl reload cybersheppard-rust || true
        systemctl reload cybersheppard-django || true
    endscript
}
EOF
    log_info "Log rotation configured"
}

setup_firewall() {
    log_info "Configuring firewall..."

    # Allow SSH, HTTP, HTTPS
    ufw allow 22/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'

    # Deny direct access to backend ports
    ufw deny 8080/tcp comment 'Rust backend (use nginx)'
    ufw deny 8001/tcp comment 'Django backend (use nginx)'

    log_warn "Firewall rules configured but NOT enabled"
    log_warn "To enable: ufw enable"
}

copy_env_file() {
    log_info "Creating .env file..."
    if [[ ! -f "$INSTALL_DIR/.env" ]]; then
        cp "$(dirname "$0")/.env.production.example" "$INSTALL_DIR/.env"
        chown "$APP_USER:$APP_GROUP" "$INSTALL_DIR/.env"
        chmod 600 "$INSTALL_DIR/.env"

        log_warn "IMPORTANT: Edit $INSTALL_DIR/.env and set all CHANGE_ME values!"
    else
        log_warn ".env file already exists, skipping"
    fi
}

print_next_steps() {
    echo ""
    echo "=========================================="
    log_info "Production setup complete!"
    echo "=========================================="
    echo ""
    echo "Next steps:"
    echo "  1. Edit $INSTALL_DIR/.env with your configuration"
    echo "  2. Generate secure secrets:"
    echo "       openssl rand -hex 32"
    echo "  3. Setup InfluxDB (see instructions above)"
    echo "  4. Build Rust backend:"
    echo "       cd $INSTALL_DIR/backend-rust"
    echo "       cargo build --release"
    echo "  5. Setup Django backend:"
    echo "       cd $INSTALL_DIR/backend-django"
    echo "       python3 -m venv venv"
    echo "       source venv/bin/activate"
    echo "       pip install -r requirements.txt"
    echo "       python manage.py migrate"
    echo "  6. Build frontend:"
    echo "       cd $INSTALL_DIR/frontend-react"
    echo "       npm install && npm run build"
    echo "       cp -r dist/* /var/www/cybersheppard/frontend/"
    echo "  7. Start services:"
    echo "       systemctl start cybersheppard-rust"
    echo "       systemctl start cybersheppard-django"
    echo "  8. Enable firewall:"
    echo "       ufw enable"
    echo "  9. Get Let's Encrypt certificate (optional):"
    echo "       certbot --nginx -d your-domain.com"
    echo ""
    echo "Logs:"
    echo "  - Application: $LOG_DIR/"
    echo "  - Nginx: /var/log/nginx/"
    echo "  - Systemd: journalctl -u cybersheppard-rust -f"
    echo ""
}

# Main execution
main() {
    log_info "Starting CyberSheppard production setup..."

    check_root
    create_user
    create_directories
    install_dependencies
    setup_postgresql
    setup_influxdb
    generate_ssl_cert
    setup_nginx
    setup_systemd_services
    setup_logrotate
    setup_firewall
    copy_env_file
    print_next_steps
}

main
