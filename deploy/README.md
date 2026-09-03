# CyberSheppard - Production Deployment Guide

This directory contains all files needed for production deployment of CyberSheppard.

## 📁 Contents

```
deploy/
├── audit/
│   ├── 10-cybersheppard-base.rules   # auditd: BASE (unico -D + settaggi globali)
│   ├── 50-cybersheppard-detect.rules # auditd: watch/regole di detection
│   └── README.md                     # come installare e PERSONALIZZARE le regole
├── nginx/
│   └── cybersheppard.conf          # Nginx reverse proxy configuration
├── systemd/
│   ├── cybersheppard-rust.service   # Rust backend service
│   └── cybersheppard-django.service # Django backend service
├── .env.production.example          # Environment variables template
├── setup-production.sh              # Automated setup script
└── README.md                        # This file
```

> **Regole auditd e regole proprie del cliente:** la raccolta eventi passa da
> auditd → Laurel → agent. Per installare le regole e soprattutto per **aggiungere
> le proprie in sicurezza** (ordine di caricamento, il tranello del `-D`, cosa non
> sopprimere), vedi **[`audit/README.md`](audit/README.md)**.

## 🚀 Quick Start (Automated)

```bash
# 1. Clone repository to /opt/cybersheppard
sudo git clone https://github.com/Dognet-Technologies/cybersheppard.git /opt/cybersheppard

# 2. Run setup script
cd /opt/cybersheppard/deploy
sudo ./setup-production.sh

# 3. Follow the post-installation steps printed by the script
```

## 📋 Manual Installation Steps

### 1. System Preparation

```bash
# Create application user
sudo useradd -r -s /bin/bash -d /opt/cybersheppard -m cybersheppard

# Create directories
sudo mkdir -p /var/log/cybersheppard
sudo mkdir -p /var/lib/cybersheppard
sudo mkdir -p /var/backups/cybersheppard
sudo chown -R cybersheppard:cybersheppard /var/log/cybersheppard /var/lib/cybersheppard /var/backups/cybersheppard
```

### 2. Install Dependencies

```bash
sudo apt-get update
sudo apt-get install -y \
    postgresql postgresql-contrib \
    influxdb influxdb-client \
    nginx \
    python3 python3-pip python3-venv \
    build-essential curl wget git \
    certbot python3-certbot-nginx
```

### 3. Database Setup

**PostgreSQL:**
```bash
sudo systemctl enable postgresql
sudo systemctl start postgresql

sudo -u postgres psql <<EOF
CREATE USER cybersheppard WITH PASSWORD 'your_secure_password';
CREATE DATABASE cybersheppard OWNER cybersheppard;
GRANT ALL PRIVILEGES ON DATABASE cybersheppard TO cybersheppard;
EOF

# Run migrations
cd /opt/cybersheppard
psql -U cybersheppard -d cybersheppard -f database/postgresql/migrations/001_initial_schema.sql
psql -U cybersheppard -d cybersheppard -f database/postgresql/migrations/002_compliance_system.sql
```

**InfluxDB:**
```bash
sudo systemctl enable influxdb
sudo systemctl start influxdb

# Setup InfluxDB
influx setup
# - Org: cybersheppard
# - Buckets: metrics, logs, correlations
# - Generate API token and save it
```

### 4. Application Setup

**Rust Backend:**
```bash
cd /opt/cybersheppard/backend-rust
cargo build --release
```

**Django Backend:**
```bash
cd /opt/cybersheppard/backend-django
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn
python manage.py migrate
python manage.py collectstatic
deactivate
```

**Frontend:**
```bash
cd /opt/cybersheppard/frontend-react
npm install
npm run build

# Deploy to web root
sudo mkdir -p /var/www/cybersheppard/frontend
sudo cp -r dist/* /var/www/cybersheppard/frontend/
sudo chown -R www-data:www-data /var/www/cybersheppard
```

### 5. Configuration

**Environment Variables:**
```bash
# Copy and edit .env
cd /opt/cybersheppard
cp deploy/.env.production.example .env
nano .env  # Edit all CHANGE_ME values

# Generate secrets
openssl rand -hex 32  # For JWT_SECRET
openssl rand -hex 32  # For CSRF_SECRET
openssl rand -hex 32  # For DJANGO_SECRET_KEY
openssl rand -base64 32  # For ENCRYPTION_KEY
```

**SSL Certificate:**
```bash
# Option 1: Self-signed (development/testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout /etc/nginx/ssl/cybersheppard.key \
    -out /etc/nginx/ssl/cybersheppard.crt

# Option 2: Let's Encrypt (production)
sudo certbot --nginx -d your-domain.com
```

**Nginx:**
```bash
# Copy configuration
sudo cp deploy/nginx/cybersheppard.conf /etc/nginx/sites-available/cybersheppard
sudo ln -s /etc/nginx/sites-available/cybersheppard /etc/nginx/sites-enabled/

# Test and restart
sudo nginx -t
sudo systemctl restart nginx
```

**Systemd Services:**
```bash
# Install services
sudo cp deploy/systemd/cybersheppard-rust.service /etc/systemd/system/
sudo cp deploy/systemd/cybersheppard-django.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable cybersheppard-rust cybersheppard-django
sudo systemctl start cybersheppard-rust cybersheppard-django

# Check status
sudo systemctl status cybersheppard-rust
sudo systemctl status cybersheppard-django
```

### 6. Firewall Configuration

```bash
# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp  # SSH

# Deny direct backend access
sudo ufw deny 8080/tcp
sudo ufw deny 8001/tcp

# Enable firewall
sudo ufw enable
```

## 📊 Monitoring & Logs

**View Logs:**
```bash
# Rust backend
sudo journalctl -u cybersheppard-rust -f

# Django backend
sudo journalctl -u cybersheppard-django -f

# Nginx
sudo tail -f /var/log/nginx/cybersheppard_access.log
sudo tail -f /var/log/nginx/cybersheppard_error.log

# Application logs
sudo tail -f /var/log/cybersheppard/app.log
```

**Service Management:**
```bash
# Restart services
sudo systemctl restart cybersheppard-rust
sudo systemctl restart cybersheppard-django
sudo systemctl restart nginx

# Stop services
sudo systemctl stop cybersheppard-rust
sudo systemctl stop cybersheppard-django

# Check status
sudo systemctl status cybersheppard-rust
sudo systemctl status cybersheppard-django
```

## 🔒 Security Checklist

- [ ] Changed all default passwords in .env
- [ ] Generated unique JWT/CSRF secrets
- [ ] Configured SSL/TLS certificates
- [ ] Enabled firewall (ufw)
- [ ] Configured rate limiting in Nginx
- [ ] Set proper file permissions (600 for .env, 750 for directories)
- [ ] Disabled DEBUG mode in Django
- [ ] Configured CORS allowed origins
- [ ] Set up log rotation
- [ ] Configured automated backups
- [ ] Reviewed and hardened systemd service files
- [ ] Set strong PostgreSQL password
- [ ] Secured InfluxDB API token

## 🔄 Backup & Recovery

**Database Backup:**
```bash
# PostgreSQL
pg_dump -U cybersheppard cybersheppard > /var/backups/cybersheppard/db_$(date +%Y%m%d).sql

# InfluxDB
influx backup /var/backups/cybersheppard/influx_$(date +%Y%m%d)
```

**Automated Backups:**
```bash
# Add to crontab
sudo crontab -e

# Daily backup at 2 AM
0 2 * * * /opt/cybersheppard/scripts/backup.sh
```

## 🆘 Troubleshooting

**Service won't start:**
```bash
# Check logs
sudo journalctl -u cybersheppard-rust -n 50
sudo journalctl -u cybersheppard-django -n 50

# Check configuration
sudo nginx -t
cargo check --release  # in backend-rust/
```

**Database connection errors:**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql
sudo -u postgres psql -c "\l"  # List databases

# Check InfluxDB status
sudo systemctl status influxdb
influx ping
```

**Permission errors:**
```bash
# Fix ownership
sudo chown -R cybersheppard:cybersheppard /opt/cybersheppard
sudo chown -R cybersheppard:cybersheppard /var/log/cybersheppard
sudo chown -R cybersheppard:cybersheppard /var/lib/cybersheppard
```

## 📞 Support

For issues or questions:
- GitHub Issues: https://github.com/Dognet-Technologies/cybersheppard/issues
- Documentation: `/docs/`

## 📝 License

See LICENSE file in repository root.
