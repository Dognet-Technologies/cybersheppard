# CyberSheppard (MicroSIEM) - Installation Guide

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [Prerequisites](#prerequisites)
3. [Installation Methods](#installation-methods)
4. [Post-Installation Configuration](#post-installation-configuration)
5. [First Run](#first-run)
6. [Troubleshooting](#troubleshooting)

---

## 📦 System Requirements

### Minimum Requirements

- **CPU**: 4 cores
- **RAM**: 8 GB
- **Storage**: 100 GB SSD
- **OS**: Ubuntu 22.04 LTS / Debian 12 / RHEL 9 / Rocky Linux 9

### Recommended for Production

- **CPU**: 8+ cores
- **RAM**: 16+ GB
- **Storage**: 500 GB SSD (NVMe preferred)
- **Network**: 1 Gbps
- **OS**: Ubuntu 22.04 LTS (tested and recommended)

---

## 🔧 Prerequisites

### Required Software

Install the following on your server:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker & Docker Compose
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.23.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Git
sudo apt install -y git

# Install PostgreSQL client (for administration)
sudo apt install -y postgresql-client

# Install nginx (for reverse proxy)
sudo apt install -y nginx certbot python3-certbot-nginx
```

### Network Requirements

Open the following ports:

- **443** (HTTPS) - Main web interface
- **80** (HTTP) - Redirect to HTTPS
- **5432** (PostgreSQL) - Database (internal/VPN only)
- **8086** (InfluxDB) - Time-series database (internal/VPN only)

---

## 🚀 Installation Methods

### Method 1: Quick Install with Docker Compose (Recommended)

#### Step 1: Clone the repository

```bash
# Create application directory
sudo mkdir -p /opt/cybersheppard
sudo chown $USER:$USER /opt/cybersheppard
cd /opt/cybersheppard

# Clone repository
git clone https://github.com/Dognet-Technologies/cybersheppard.git .
```

#### Step 2: Configure environment

```bash
# Copy production environment template
cp deploy/.env.production.example .env

# Edit configuration
nano .env
```

**Required Configuration Values**:

```env
# Database
DATABASE_URL=postgresql://cybersheppard:CHANGE_ME@postgres:5432/cybersheppard
POSTGRES_PASSWORD=CHANGE_ME_STRONG_PASSWORD

# InfluxDB
INFLUXDB_TOKEN=CHANGE_ME_RANDOM_TOKEN_64_CHARS
INFLUXDB_ORG=cybersheppard
INFLUXDB_BUCKET=metrics

# JWT Authentication
JWT_SECRET=CHANGE_ME_RANDOM_SECRET_64_CHARS
JWT_EXPIRATION=24h

# SMTP Email (optional but recommended)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=cybersheppard@example.com
SMTP_PASSWORD=email_password
SMTP_FROM_EMAIL=noreply@cybersheppard.example.com
EMAIL_RECIPIENTS=["admin@example.com","security-team@example.com"]

# Slack Notifications (optional)
SLACK_ENABLED=false
SLACK_WEBHOOK_URL=

# Discord Notifications (optional)
DISCORD_ENABLED=false
DISCORD_WEBHOOK_URL=
```

#### Step 3: Generate secrets

```bash
# Generate strong random secrets
openssl rand -base64 48

# Use output for DATABASE_URL password, JWT_SECRET, and INFLUXDB_TOKEN
```

#### Step 4: Run the automated setup script

```bash
# Make setup script executable
chmod +x deploy/setup-production.sh

# Run setup (will create directories, configure services)
sudo ./deploy/setup-production.sh
```

#### Step 5: Start services

```bash
# Start all services
docker-compose up -d

# Verify all containers are running
docker-compose ps

# Check logs
docker-compose logs -f
```

#### Step 6: Initialize database

```bash
# Run PostgreSQL migrations
docker-compose exec backend-rust sqlx migrate run

# Run Django migrations
docker-compose exec backend-django python manage.py migrate

# Create superuser
docker-compose exec backend-rust cargo run --bin create-admin
```

---

### Method 2: Manual Installation (Advanced)

#### Install Rust Backend

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Build backend
cd backend-rust
cargo build --release

# Copy binary
sudo cp target/release/cybersheppard-backend /usr/local/bin/

# Create systemd service
sudo cp ../deploy/systemd/cybersheppard-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cybersheppard-backend
sudo systemctl start cybersheppard-backend
```

#### Install Django Backend

```bash
# Install Python dependencies
cd backend-django
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Create systemd service
sudo cp ../deploy/systemd/cybersheppard-django.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cybersheppard-django
sudo systemctl start cybersheppard-django
```

#### Install Frontend

```bash
# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Build frontend
cd frontend
npm ci
npm run build

# Copy to nginx
sudo cp -r dist/* /var/www/cybersheppard/
```

#### Install PostgreSQL

```bash
# Install PostgreSQL
sudo apt install -y postgresql-16

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE cybersheppard;
CREATE USER cybersheppard WITH PASSWORD 'your_strong_password';
GRANT ALL PRIVILEGES ON DATABASE cybersheppard TO cybersheppard;
ALTER USER cybersheppard WITH SUPERUSER;
EOF
```

#### Install InfluxDB

```bash
# Add InfluxDB repository
wget -q https://repos.influxdata.com/influxdata-archive_compat.key
echo '23a1c8836f0afc5ed24e0486339d7cc8f6790b83886c4c96995b88a061c5bb5d influxdata-archive_compat.key' | sha256sum -c && cat influxdata-archive_compat.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null

echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | sudo tee /etc/apt/sources.list.d/influxdata.list

# Install InfluxDB
sudo apt update
sudo apt install -y influxdb2

# Start service
sudo systemctl enable influxdb
sudo systemctl start influxdb

# Initialize InfluxDB
influx setup \
  --username admin \
  --password your_admin_password \
  --org cybersheppard \
  --bucket metrics \
  --retention 90d \
  --force
```

#### Configure Nginx

```bash
# Copy nginx configuration
sudo cp deploy/nginx/cybersheppard.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/cybersheppard.conf /etc/nginx/sites-enabled/

# Generate SSL certificate (Let's Encrypt)
sudo certbot --nginx -d cybersheppard.example.com

# Test configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

---

## ⚙️ Post-Installation Configuration

### Configure SSL/TLS

```bash
# Generate self-signed certificate (for testing)
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /etc/nginx/ssl/cybersheppard.key \
  -out /etc/nginx/ssl/cybersheppard.crt

# Or use Let's Encrypt (production)
sudo certbot --nginx -d cybersheppard.example.com
```

### Configure Firewall

```bash
# Allow HTTPS, SSH only
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### Create Admin User

```bash
# Via Docker
docker-compose exec backend-rust cargo run --bin create-admin

# Or directly
cd backend-rust
cargo run --bin create-admin -- \
  --username admin \
  --email admin@example.com \
  --password SecurePassword123!
```

---

## 🎉 First Run

### Access the Web Interface

1. Open your browser: `https://your-server-ip`
2. Login with admin credentials
3. Complete the setup wizard:
   - Configure notification settings
   - Add integrations (optional)
   - Add your first target server

### Add Target Servers

#### Install Collector on Target

```bash
# On each target server
curl -fsSL https://your-cybersheppard-server/install-collector.sh | sudo bash

# Or manually
sudo mkdir -p /opt/cybersheppard-collector
cd /opt/cybersheppard-collector

# Copy collector scripts
scp your-cybersheppard-server:/opt/cybersheppard/collectors/*.sh .

# Configure
sudo nano config.env

# Add:
CYBERSHEPPARD_API_URL=https://your-cybersheppard-server
CYBERSHEPPARD_API_KEY=your_api_key_from_ui
TARGET_ID=1

# Install systemd service
sudo cp cybersheppard-collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cybersheppard-collector
sudo systemctl start cybersheppard-collector
```

---

## 🐛 Troubleshooting

### Services Not Starting

```bash
# Check Docker logs
docker-compose logs -f

# Check specific service
docker-compose logs backend-rust

# Restart services
docker-compose restart
```

### Database Connection Issues

```bash
# Test PostgreSQL connection
docker-compose exec postgres psql -U cybersheppard -d cybersheppard

# Check database URL in .env
grep DATABASE_URL .env

# Verify PostgreSQL is running
docker-compose ps postgres
```

### InfluxDB Issues

```bash
# Check InfluxDB status
docker-compose exec influxdb influx ping

# Verify token
docker-compose exec influxdb influx auth list

# Check buckets
docker-compose exec influxdb influx bucket list
```

### Nginx 502 Bad Gateway

```bash
# Check backend is running
docker-compose ps backend-rust

# Check nginx logs
sudo tail -f /var/log/nginx/error.log

# Test backend directly
curl http://localhost:8080/api/health
```

### Collector Not Sending Data

```bash
# On target server, check collector logs
sudo journalctl -u cybersheppard-collector -f

# Test manual collection
sudo /opt/cybersheppard-collector/cybersheppard-collector.sh

# Verify network connectivity
curl -k https://your-cybersheppard-server/api/health
```

---

## 📞 Getting Help

- **Documentation**: https://docs.cybersheppard.io
- **GitHub Issues**: https://github.com/Dognet-Technologies/cybersheppard/issues
- **Community Forum**: https://community.cybersheppard.io
- **Email Support**: support@cybersheppard.io

---

## 🔄 Upgrading

```bash
# Pull latest changes
cd /opt/cybersheppard
git pull origin main

# Rebuild containers
docker-compose down
docker-compose build
docker-compose up -d

# Run migrations
docker-compose exec backend-rust sqlx migrate run
docker-compose exec backend-django python manage.py migrate
```

---

## 📝 Next Steps

- Read the [User Manual](./USER_MANUAL.md)
- Configure [Hardening Models](./HARDENING_MODELS.md)
- Set up [Integrations](./INTEGRATION_SPEC.md)
- Review [Security Best Practices](./SECURITY.md)
