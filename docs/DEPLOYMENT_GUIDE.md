# CyberSheppard - Deployment Guide

## 📋 Document Overview

**Version**: 1.0.0  
**Last Updated**: 2024-11-28  
**Status**: Production Ready  
**Target Audience**: System Administrators, DevOps Engineers

---

## 🎯 Deployment Scenarios

CyberSheppard supports three deployment scenarios:

1. **LXC Container** (Recommended for Proxmox)
2. **Docker/Docker Compose** (Recommended for general use)
3. **Virtual Machine** (Full isolation)

### Scenario Comparison

| Feature | LXC | Docker | VM |
|---------|-----|--------|-----|
| Resource Overhead | Low | Low | High |
| Isolation | Good | Good | Excellent |
| Management | Proxmox UI | Docker CLI | Hypervisor |
| Network Performance | Excellent | Good | Good |
| Storage Overhead | Minimal | Minimal | Significant |
| Recommended For | Proxmox environments | General deployment | Maximum isolation |

---

## 🔧 System Requirements

### Minimum Requirements

**CyberSheppard Server**:
```yaml
CPU: 4 cores
RAM: 8 GB
Disk: 100 GB SSD
Network: 1 Gbps
OS: Debian 12 / Ubuntu 22.04 LTS
```

**Target Systems**:
```yaml
CPU: 1 core (minimal overhead)
RAM: 512 MB for monitoring
Disk: 1 GB for logs/data
Network: 100 Mbps
OS: Debian 11/12, Ubuntu 20.04/22.04
```

### Recommended Production Requirements

**CyberSheppard Server**:
```yaml
CPU: 8 cores
RAM: 16 GB
Disk: 500 GB NVMe SSD
Network: 10 Gbps
OS: Debian 12 (stable)
```

### Network Requirements

**Ports Used**:
```yaml
# CyberSheppard Server
443/tcp   - HTTPS (frontend)
5433/tcp  - PostgreSQL (internal)
8086/tcp  - InfluxDB (internal)
22/tcp    - SSH (management)

# Target Systems
22/tcp    - SSH (from CyberSheppard only)
```

**Network Topology**:
```
┌─────────────────────────────────────────────┐
│         Management Network (Admin)          │
│              192.168.1.0/24                 │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────────┐                      │
│  │ CyberSheppard    │                      │
│  │ 192.168.1.10     │                      │
│  └────────┬─────────┘                      │
│           │                                 │
│           │ SSH (port 22)                   │
│           ▼                                 │
│  ┌──────────────────┐                      │
│  │ Target Systems   │                      │
│  │ 192.168.1.20-254 │                      │
│  └──────────────────┘                      │
│                                             │
└─────────────────────────────────────────────┘
```

---

## 📦 Deployment Option 1: LXC Container (Proxmox)

### Prerequisites

```bash
# On Proxmox host
apt update
apt install -y pve-container

# Verify Proxmox version
pveversion
```

### Step 1: Create LXC Container

**Via Proxmox Web UI**:

1. Navigate to: Datacenter → Node → Create CT
2. Configure:
   ```yaml
   General:
     CT ID: 100 (or next available)
     Hostname: cybersheppard
     Unprivileged: Yes
     Password: [set strong password]
   
   Template:
     Storage: local
     Template: debian-12-standard
   
   Resources:
     Cores: 4
     Memory: 8192 MB
     Swap: 2048 MB
   
   Network:
     Bridge: vmbr0
     IPv4: Static (192.168.1.10/24)
     Gateway: 192.168.1.1
     IPv6: DHCP (or static)
   
   DNS:
     DNS: 8.8.8.8 1.1.1.1
     Domain: local
   
   Storage:
     Root: local-lvm
     Size: 100 GB
   ```

3. Enable Features:
   - ☑ Nesting (for Docker inside LXC if needed)
   - ☑ Keyctl (for systemd)

**Via CLI**:

```bash
# Download Debian 12 template
pveam update
pveam download local debian-12-standard_12.2-1_amd64.tar.zst

# Create container
pct create 100 local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst \
  --hostname cybersheppard \
  --memory 8192 \
  --swap 2048 \
  --cores 4 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.1.10/24,gw=192.168.1.1 \
  --storage local-lvm \
  --rootfs local-lvm:100 \
  --unprivileged 1 \
  --features nesting=1,keyctl=1 \
  --password

# Start container
pct start 100
```

### Step 2: Initial LXC Configuration

```bash
# Enter container
pct enter 100

# Update system
apt update && apt upgrade -y

# Install base requirements
apt install -y \
  curl wget git \
  build-essential \
  pkg-config libssl-dev \
  postgresql-client \
  python3 python3-pip python3-venv \
  openssh-client

# Set timezone
timedatectl set-timezone Europe/Rome

# Configure SSH
systemctl enable ssh
systemctl start ssh
```

### Step 3: Install Rust

```bash
# Install Rust (as root or regular user)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Verify
rustc --version
cargo --version
```

### Step 4: Install Databases

**PostgreSQL**:

```bash
# Install PostgreSQL 15
apt install -y postgresql-15 postgresql-client-15

# Start service
systemctl enable postgresql
systemctl start postgresql

# Create database and user
sudo -u postgres psql <<EOF
CREATE DATABASE cybersheppard;
CREATE USER cybershep WITH ENCRYPTED PASSWORD 'CHANGE_THIS_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE cybersheppard TO cybershep;
\q
EOF
```

**InfluxDB**:

```bash
# Add InfluxDB repository
wget -q https://repos.influxdata.com/influxdata-archive_compat.key
echo '393e8779c89ac8d958f81f942f9ad7fb82a25e133faddaf92e15b16e6ac9ce4c influxdata-archive_compat.key' | sha256sum -c && cat influxdata-archive_compat.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | tee /etc/apt/sources.list.d/influxdata.list

# Install InfluxDB
apt update
apt install -y influxdb2

# Start service
systemctl enable influxdb
systemctl start influxdb

# Initial setup
influx setup \
  --username admin \
  --password CHANGE_THIS_PASSWORD \
  --org dognet \
  --bucket metrics \
  --retention 90d \
  --force
```

### Step 5: Deploy CyberSheppard

```bash
# Create directory structure
mkdir -p /opt/cybersheppard/{backend,frontend,config,logs,data}
cd /opt/cybersheppard

# Clone repository (or copy files)
git clone https://github.com/yourorg/cybersheppard.git .

# Backend setup
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Build Rust components
cd rust_modules/hardening_engine
cargo build --release
cp target/release/hardening_engine /opt/cybersheppard/backend/

cd ../monitoring_engine
cargo build --release
cp target/release/monitoring_engine /opt/cybersheppard/backend/

# Frontend setup (if serving from same container)
cd /opt/cybersheppard/frontend
# Build frontend (see Frontend Build section)
```

### Step 6: Configure Services

**Systemd Service for Backend**:

```bash
cat > /etc/systemd/system/cybersheppard-backend.service <<'EOF'
[Unit]
Description=CyberSheppard Backend Service
After=network.target postgresql.service influxdb.service

[Service]
Type=simple
User=cybershep
Group=cybershep
WorkingDirectory=/opt/cybersheppard/backend
Environment="PATH=/opt/cybersheppard/backend/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/cybersheppard/backend/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cybersheppard-backend
systemctl start cybersheppard-backend
```

**Nginx Configuration**:

```bash
# Install Nginx
apt install -y nginx

# Configure
cat > /etc/nginx/sites-available/cybersheppard <<'EOF'
server {
    listen 80;
    server_name cybersheppard.local;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name cybersheppard.local;
    
    ssl_certificate /etc/ssl/certs/cybersheppard.crt;
    ssl_certificate_key /etc/ssl/private/cybersheppard.key;
    
    # SSL configuration
    ssl_protocols TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # Frontend static files
    location / {
        root /opt/cybersheppard/frontend/dist;
        try_files $uri $uri/ /index.html;
    }
    
    # Backend API
    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # WebSocket
    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

# Enable site
ln -s /etc/nginx/sites-available/cybersheppard /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
```

---

## 🐳 Deployment Option 2: Docker Compose

### Prerequisites

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
apt install -y docker-compose-plugin

# Verify
docker --version
docker compose version
```

### Directory Structure

```bash
mkdir -p cybersheppard/{backend,frontend,config,data/postgres,data/influx}
cd cybersheppard
```

### Docker Compose Configuration

**docker-compose.yml**:

```yaml
version: '3.8'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    container_name: cybershep-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: cybersheppard
      POSTGRES_USER: cybershep
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    networks:
      - cybershep-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cybershep"]
      interval: 10s
      timeout: 5s
      retries: 5

  # InfluxDB Time-Series Database
  influxdb:
    image: influxdb:2.7-alpine
    container_name: cybershep-influxdb
    restart: unless-stopped
    environment:
      DOCKER_INFLUXDB_INIT_MODE: setup
      DOCKER_INFLUXDB_INIT_USERNAME: admin
      DOCKER_INFLUXDB_INIT_PASSWORD: ${INFLUX_PASSWORD}
      DOCKER_INFLUXDB_INIT_ORG: dognet
      DOCKER_INFLUXDB_INIT_BUCKET: metrics
      DOCKER_INFLUXDB_INIT_RETENTION: 90d
      DOCKER_INFLUXDB_INIT_ADMIN_TOKEN: ${INFLUX_TOKEN}
    volumes:
      - ./data/influx:/var/lib/influxdb2
    networks:
      - cybershep-network
    healthcheck:
      test: ["CMD", "influx", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # CyberSheppard Backend
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: cybershep-backend
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      influxdb:
        condition: service_healthy
    environment:
      # Database
      DATABASE_URL: postgresql://cybershep:${POSTGRES_PASSWORD}@postgres:5432/cybersheppard
      INFLUX_URL: http://influxdb:8086
      INFLUX_TOKEN: ${INFLUX_TOKEN}
      INFLUX_ORG: dognet
      INFLUX_BUCKET: metrics
      
      # Security
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      
      # SSH
      SSH_KEY_PATH: /app/keys/cybershep_ed25519
    volumes:
      - ./config:/app/config:ro
      - ./data/ssh_keys:/app/keys:ro
      - ./logs:/app/logs
    networks:
      - cybershep-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Nginx Reverse Proxy
  nginx:
    image: nginx:alpine
    container_name: cybershep-nginx
    restart: unless-stopped
    depends_on:
      - backend
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./frontend/dist:/usr/share/nginx/html:ro
      - ./config/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./config/ssl:/etc/ssl:ro
    networks:
      - cybershep-network
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  cybershep-network:
    driver: bridge

volumes:
  postgres_data:
  influx_data:
```

### Backend Dockerfile

**backend/Dockerfile**:

```dockerfile
# Multi-stage build
FROM rust:1.75-slim as rust-builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Rust projects
COPY rust_modules ./rust_modules

# Build hardening engine
WORKDIR /build/rust_modules/hardening_engine
RUN cargo build --release

# Build monitoring engine
WORKDIR /build/rust_modules/monitoring_engine
RUN cargo build --release

# Python stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app ./app
COPY hardening_models ./hardening_models
COPY monitoring_scripts ./monitoring_scripts

# Copy Rust binaries
COPY --from=rust-builder /build/rust_modules/hardening_engine/target/release/hardening_engine /usr/local/bin/
COPY --from=rust-builder /build/rust_modules/monitoring_engine/target/release/monitoring_engine /usr/local/bin/

# Create non-root user
RUN useradd -m -u 1000 cybershep && \
    chown -R cybershep:cybershep /app

USER cybershep

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Environment Configuration

**.env**:

```bash
# Database
POSTGRES_PASSWORD=CHANGE_THIS_SECURE_PASSWORD
INFLUX_PASSWORD=CHANGE_THIS_SECURE_PASSWORD
INFLUX_TOKEN=CHANGE_THIS_LONG_RANDOM_TOKEN

# Security
JWT_SECRET_KEY=CHANGE_THIS_LONG_RANDOM_SECRET

# Optional
COMPOSE_PROJECT_NAME=cybershep
```

### Deployment Commands

```bash
# Generate secrets
echo "POSTGRES_PASSWORD=$(openssl rand -base64 32)" >> .env
echo "INFLUX_PASSWORD=$(openssl rand -base64 32)" >> .env
echo "INFLUX_TOKEN=$(openssl rand -base64 64)" >> .env
echo "JWT_SECRET_KEY=$(openssl rand -base64 64)" >> .env

# Start services
docker compose up -d

# View logs
docker compose logs -f

# Check status
docker compose ps

# Stop services
docker compose down

# Update services
docker compose pull
docker compose up -d --build
```

---

## 💻 Deployment Option 3: Virtual Machine

### Step 1: Create VM

**Proxmox Example**:

```bash
# Download Debian 12 ISO
cd /var/lib/vz/template/iso
wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.2.0-amd64-netinst.iso

# Create VM via CLI
qm create 200 \
  --name cybersheppard \
  --memory 8192 \
  --cores 4 \
  --net0 virtio,bridge=vmbr0 \
  --ide2 local:iso/debian-12.2.0-amd64-netinst.iso,media=cdrom \
  --scsi0 local-lvm:100 \
  --ostype l26 \
  --boot order=scsi0

# Start VM
qm start 200
```

### Step 2: Install Debian

1. Boot from ISO
2. Install Debian 12 (minimal + SSH server)
3. Configure network:
   ```bash
   auto eth0
   iface eth0 inet static
       address 192.168.1.10
       netmask 255.255.255.0
       gateway 192.168.1.1
       dns-nameservers 8.8.8.8 1.1.1.1
   ```

### Step 3: Post-Install Configuration

```bash
# Update system
apt update && apt upgrade -y

# Install essentials
apt install -y \
  curl wget git vim \
  build-essential pkg-config libssl-dev \
  postgresql-15 influxdb2 \
  python3 python3-pip python3-venv \
  nginx

# Follow same steps as LXC deployment
```

---

## 🔐 Security Hardening Post-Deployment

### Firewall Configuration

**Using iptables**:

```bash
# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from management network
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -j ACCEPT

# Allow HTTPS
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Save rules
apt install iptables-persistent
netfilter-persistent save
```

**Using nftables** (Debian 12 default):

```bash
cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow loopback
        iif lo accept
        
        # Allow established
        ct state established,related accept
        
        # Allow SSH from management
        ip saddr 192.168.1.0/24 tcp dport 22 accept
        
        # Allow HTTPS
        tcp dport 443 accept
        
        # Drop invalid
        ct state invalid drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

systemctl enable nftables
systemctl start nftables
```

### SSH Hardening

```bash
# Generate ED25519 key for microsiem user
ssh-keygen -t ed25519 -C "cybersheppard@system" -f /root/.ssh/cybershep_ed25519 -N ""

# Configure SSH
cat >> /etc/ssh/sshd_config <<'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

systemctl restart sshd
```

### SSL/TLS Certificate

**Self-Signed for Testing**:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /etc/ssl/private/cybersheppard.key \
  -out /etc/ssl/certs/cybersheppard.crt \
  -subj "/C=IT/ST=Lombardy/L=Pieve Fissiraga/O=Dognet/CN=cybersheppard.local"
```

**Let's Encrypt for Production**:

```bash
apt install -y certbot python3-certbot-nginx
certbot --nginx -d cybersheppard.yourdomain.com
```

---

## 🎯 Target System Setup

### Automated Setup Script

**setup_target.sh**:

```bash
#!/bin/bash
set -e

TARGET_HOST="$1"
TARGET_USER="root"
MICROSIEM_USER="microsiem"
PUBLIC_KEY_PATH="/opt/cybersheppard/keys/cybershep_ed25519.pub"

if [ -z "$TARGET_HOST" ]; then
    echo "Usage: $0 <target_host>"
    exit 1
fi

echo "Setting up target: $TARGET_HOST"

# Create microsiem user
ssh "${TARGET_USER}@${TARGET_HOST}" "
useradd -m -s /bin/bash ${MICROSIEM_USER} || true
mkdir -p /home/${MICROSIEM_USER}/.ssh
chmod 700 /home/${MICROSIEM_USER}/.ssh
"

# Copy SSH key
cat "$PUBLIC_KEY_PATH" | ssh "${TARGET_USER}@${TARGET_HOST}" \
  "cat >> /home/${MICROSIEM_USER}/.ssh/authorized_keys"

ssh "${TARGET_USER}@${TARGET_HOST}" "
chmod 600 /home/${MICROSIEM_USER}/.ssh/authorized_keys
chown -R ${MICROSIEM_USER}:${MICROSIEM_USER} /home/${MICROSIEM_USER}/.ssh
"

# Install monitoring dependencies
ssh "${TARGET_USER}@${TARGET_HOST}" "
apt update
apt install -y auditd python3 jq
systemctl enable auditd
systemctl start auditd
"

# Create monitoring directory
ssh "${TARGET_USER}@${TARGET_HOST}" "
mkdir -p /opt/microsiem/{collectors,scripts,output}
chown -R ${MICROSIEM_USER}:${MICROSIEM_USER} /opt/microsiem
"

# Copy monitoring scripts
scp -r /opt/cybersheppard/monitoring_scripts/* \
  "${TARGET_USER}@${TARGET_HOST}:/opt/microsiem/scripts/"

# Setup sudoers
ssh "${TARGET_USER}@${TARGET_HOST}" "
cat > /etc/sudoers.d/microsiem <<'SUDO'
microsiem ALL=(root) NOPASSWD: /usr/bin/systemctl status *
microsiem ALL=(root) NOPASSWD: /usr/sbin/netstat
microsiem ALL=(root) NOPASSWD: /usr/bin/ss
microsiem ALL=(root) NOPASSWD: /usr/bin/lsof
microsiem ALL=(ALL) !ALL
SUDO
chmod 440 /etc/sudoers.d/microsiem
"

# Setup cron
ssh "${TARGET_USER}@${TARGET_HOST}" "
cat > /etc/cron.d/microsiem <<'CRON'
*/1 * * * * microsiem /opt/microsiem/scripts/monitoring.sh > /dev/null 2>&1
CRON
"

echo "✅ Target setup complete: $TARGET_HOST"
```

---

## 📊 Monitoring & Maintenance

### Health Checks

```bash
# Check backend
curl http://localhost:8000/api/health

# Check databases
systemctl status postgresql
systemctl status influxdb

# Check logs
journalctl -u cybersheppard-backend -f
tail -f /opt/cybersheppard/logs/application.log
```

### Backup Strategy

**Database Backups**:

```bash
#!/bin/bash
# /opt/cybersheppard/scripts/backup.sh

BACKUP_DIR="/backup/cybersheppard"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# PostgreSQL backup
sudo -u postgres pg_dump cybersheppard | gzip > \
  "$BACKUP_DIR/postgres_${DATE}.sql.gz"

# InfluxDB backup
influx backup "$BACKUP_DIR/influx_${DATE}" \
  --host http://localhost:8086 \
  --token YOUR_ADMIN_TOKEN

# Retain last 30 days
find "$BACKUP_DIR" -type f -mtime +30 -delete

echo "Backup completed: $DATE"
```

**Add to crontab**:

```bash
0 2 * * * /opt/cybersheppard/scripts/backup.sh
```

### Update Procedure

```bash
# Stop services
systemctl stop cybersheppard-backend
systemctl stop nginx

# Backup current version
cp -r /opt/cybersheppard /opt/cybersheppard.backup.$(date +%Y%m%d)

# Pull updates
cd /opt/cybersheppard
git pull

# Update dependencies
cd backend
source venv/bin/activate
pip install -r requirements.txt

# Rebuild Rust components
cd rust_modules/hardening_engine
cargo build --release

# Restart services
systemctl start cybersheppard-backend
systemctl start nginx

# Verify
curl http://localhost:8000/api/health
```

---

## 🐛 Troubleshooting

### Common Issues

**Backend won't start**:

```bash
# Check logs
journalctl -u cybersheppard-backend -n 50

# Check database connection
psql -U cybershep -h localhost -d cybersheppard

# Check InfluxDB
influx ping
```

**SSH to targets failing**:

```bash
# Test manual connection
ssh -i /opt/cybersheppard/keys/cybershep_ed25519 microsiem@target_ip

# Check key permissions
ls -la /opt/cybersheppard/keys/

# Verify microsiem user on target
ssh root@target_ip "id microsiem"
```

**High memory usage**:

```bash
# Check services
systemctl status postgresql influxdb cybersheppard-backend

# Monitor resources
htop

# Check InfluxDB retention
influx bucket list
```

### Log Locations

```bash
Application:      /opt/cybersheppard/logs/application.log
Nginx Access:     /var/log/nginx/access.log
Nginx Error:      /var/log/nginx/error.log
PostgreSQL:       /var/log/postgresql/postgresql-15-main.log
InfluxDB:         /var/log/influxdb/influxd.log
System:           journalctl -u cybersheppard-backend
```

---

## 📋 Post-Deployment Checklist

### Initial Setup

- [ ] System fully updated
- [ ] Firewall configured
- [ ] SSL/TLS certificates installed
- [ ] Database initialized
- [ ] Admin user created
- [ ] SSH keys generated

### Security

- [ ] Strong passwords set
- [ ] SSH hardened
- [ ] Firewall rules verified
- [ ] Audit logging enabled
- [ ] Backup strategy implemented

### Testing

- [ ] Web UI accessible
- [ ] API endpoints responding
- [ ] Database connections working
- [ ] Can connect to test target
- [ ] Monitoring data collection working

### Production Readiness

- [ ] Monitoring configured
- [ ] Alerting configured
- [ ] Backup tested
- [ ] Update procedure documented
- [ ] Disaster recovery plan created

---

## 🔗 Additional Resources

- **Project Documentation**: `/opt/cybersheppard/docs/`
- **API Documentation**: `https://cybersheppard.local/api/docs`
- **Hardening Models**: `/opt/cybersheppard/hardening_models/`
- **Support**: Contact system administrator

---

**Document Version**: 1.0.0  
**Last Updated**: 2024-11-28  
**Maintained By**: Dognet Technologies - CyberSheppard Team
