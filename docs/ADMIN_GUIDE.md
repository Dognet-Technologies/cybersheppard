# CyberSheppard (MicroSIEM) - Administrator Guide

## 📋 Table of Contents

1. [System Administration](#system-administration)
2. [Database Management](#database-management)
3. [Performance Tuning](#performance-tuning)
4. [Security Hardening](#security-hardening)
5. [Backup & Recovery](#backup--recovery)
6. [Monitoring the Monitor](#monitoring-the-monitor)
7. [Scaling](#scaling)
8. [Maintenance](#maintenance)
9. [Troubleshooting](#troubleshooting)

---

## 🔧 System Administration

### Service Management

#### Via Docker Compose

```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart specific service
docker-compose restart backend-rust

# View logs
docker-compose logs -f backend-rust

# Check service status
docker-compose ps

# Scale collector workers
docker-compose up -d --scale backend-rust=3
```

#### Via Systemd (Manual Installation)

```bash
# Start services
sudo systemctl start cybersheppard-backend
sudo systemctl start cybersheppard-django

# Stop services
sudo systemctl stop cybersheppard-backend
sudo systemctl stop cybersheppard-django

# Restart services
sudo systemctl restart cybersheppard-backend

# Enable auto-start on boot
sudo systemctl enable cybersheppard-backend

# View logs
sudo journalctl -u cybersheppard-backend -f
```

### Log Management

#### Application Logs

```bash
# Rust backend logs
docker-compose logs -f backend-rust

# Django backend logs
docker-compose logs -f backend-django

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# PostgreSQL logs
docker-compose logs -f postgres

# InfluxDB logs
docker-compose logs -f influxdb
```

#### Log Rotation

Configure logrotate for application logs:

```bash
# Create logrotate config
sudo nano /etc/logrotate.d/cybersheppard

# Add:
/var/log/cybersheppard/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 cybersheppard cybersheppard
    sharedscripts
    postrotate
        docker-compose restart backend-rust
    endscript
}
```

### User Administration

#### Create Admin User

```bash
# Via CLI tool
docker-compose exec backend-rust cargo run --bin create-admin -- \
  --username admin \
  --email admin@example.com \
  --password SecurePassword123! \
  --role admin
```

#### Reset User Password

```bash
# Via PostgreSQL
docker-compose exec postgres psql -U cybersheppard -d cybersheppard << EOF
UPDATE auth_users SET password_hash = '$argon2id$...' WHERE username = 'user';
EOF

# Or via CLI tool
docker-compose exec backend-rust cargo run --bin reset-password -- \
  --username user \
  --new-password NewSecurePassword123!
```

#### Disable User Account

```bash
# Via PostgreSQL
docker-compose exec postgres psql -U cybersheppard -d cybersheppard << EOF
UPDATE auth_users SET is_active = false WHERE username = 'user';
EOF
```

---

## 🗄️ Database Management

### PostgreSQL Administration

#### Connect to Database

```bash
# Via Docker
docker-compose exec postgres psql -U cybersheppard -d cybersheppard

# Via psql client
psql -h localhost -U cybersheppard -d cybersheppard
```

#### Common Queries

```sql
-- View database size
SELECT pg_size_pretty(pg_database_size('cybersheppard'));

-- View table sizes
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Count records
SELECT
    schemaname,
    tablename,
    n_tup_ins AS inserts,
    n_tup_upd AS updates,
    n_tup_del AS deletes
FROM pg_stat_all_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema');

-- Active connections
SELECT count(*) FROM pg_stat_activity;

-- Long-running queries
SELECT pid, now() - query_start AS duration, query
FROM pg_stat_activity
WHERE state = 'active'
ORDER BY duration DESC;
```

#### Database Maintenance

```bash
# Vacuum database
docker-compose exec postgres psql -U cybersheppard -d cybersheppard -c "VACUUM ANALYZE;"

# Reindex database
docker-compose exec postgres psql -U cybersheppard -d cybersheppard -c "REINDEX DATABASE cybersheppard;"

# Update statistics
docker-compose exec postgres psql -U cybersheppard -d cybersheppard -c "ANALYZE;"
```

### InfluxDB Administration

#### Connect to InfluxDB

```bash
# Via Docker
docker-compose exec influxdb influx

# Via influx CLI
influx -host localhost -port 8086 -org cybersheppard -token YOUR_TOKEN
```

#### Common Operations

```bash
# List buckets
docker-compose exec influxdb influx bucket list

# View bucket retention
docker-compose exec influxdb influx bucket list --name metrics -o cybersheppard

# Update retention policy (change to 180 days)
docker-compose exec influxdb influx bucket update \
  --name metrics \
  --retention 4320h \
  --org cybersheppard

# Check database size
docker-compose exec influxdb du -sh /var/lib/influxdb2/

# Delete old data (older than 30 days)
docker-compose exec influxdb influx delete \
  --bucket metrics \
  --start 2020-01-01T00:00:00Z \
  --stop $(date -d "30 days ago" -Iseconds) \
  --org cybersheppard
```

---

## ⚡ Performance Tuning

### PostgreSQL Tuning

Edit `postgresql.conf`:

```bash
# For 16GB RAM server
max_connections = 200
shared_buffers = 4GB
effective_cache_size = 12GB
maintenance_work_mem = 1GB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 20MB
min_wal_size = 1GB
max_wal_size = 4GB
```

Apply changes:
```bash
docker-compose restart postgres
```

### InfluxDB Tuning

Edit `influxdb.conf`:

```toml
[data]
  cache-max-memory-size = 1073741824  # 1GB
  cache-snapshot-memory-size = 26214400  # 25MB

[coordinator]
  write-timeout = "10s"
  max-concurrent-queries = 0

[http]
  max-row-limit = 10000
```

### Rust Backend Tuning

Edit `.env`:

```env
# Connection pools
PG_POOL_MAX_CONNECTIONS=20
PG_POOL_MIN_CONNECTIONS=5

# Thread pool
TOKIO_WORKER_THREADS=8

# Request limits
MAX_REQUEST_SIZE=10485760  # 10MB
REQUEST_TIMEOUT_SECONDS=30
```

### Nginx Tuning

Edit `/etc/nginx/nginx.conf`:

```nginx
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 100;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript
               application/json application/javascript application/xml+rss;

    # Caching
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=api_cache:10m
                     max_size=1g inactive=60m use_temp_path=off;
}
```

---

## 🔐 Security Hardening

### Harden PostgreSQL

```sql
-- Enforce SSL connections
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/etc/ssl/certs/postgres.crt';
ALTER SYSTEM SET ssl_key_file = '/etc/ssl/private/postgres.key';

-- Restrict network access
-- Edit pg_hba.conf:
hostssl all all 0.0.0.0/0 md5
host all all 127.0.0.1/32 md5

-- Audit logging
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_statement = 'mod';
```

### Harden Nginx

```nginx
# /etc/nginx/sites-available/cybersheppard.conf

server {
    listen 443 ssl http2;
    server_name cybersheppard.example.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/cybersheppard.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cybersheppard.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;
    limit_req zone=api_limit burst=20 nodelay;

    # API proxying
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# firewalld (RHEL)
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### Fail2ban for Brute Force Protection

```bash
# Install fail2ban
sudo apt install fail2ban

# Configure CyberSheppard jail
sudo nano /etc/fail2ban/jail.local

# Add:
[cybersheppard]
enabled = true
port = 443
filter = cybersheppard
logpath = /var/log/nginx/access.log
maxretry = 5
bantime = 3600

# Create filter
sudo nano /etc/fail2ban/filter.d/cybersheppard.conf

# Add:
[Definition]
failregex = ^<HOST> .* "POST /api/auth/login HTTP.*" 401
ignoreregex =

# Restart fail2ban
sudo systemctl restart fail2ban
```

---

## 💾 Backup & Recovery

### Automated Backup Script

Create `/opt/cybersheppard/backup.sh`:

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/backup/cybersheppard"
DATE=$(date +%Y%m%d-%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup PostgreSQL
echo "Backing up PostgreSQL..."
docker-compose exec -T postgres pg_dump -U cybersheppard cybersheppard | \
  gzip > "$BACKUP_DIR/postgres-$DATE.sql.gz"

# Backup InfluxDB
echo "Backing up InfluxDB..."
docker-compose exec -T influxdb influx backup "/tmp/influx-backup-$DATE"
docker cp $(docker-compose ps -q influxdb):/tmp/influx-backup-$DATE "$BACKUP_DIR/"
docker-compose exec -T influxdb rm -rf "/tmp/influx-backup-$DATE"

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_DIR/config-$DATE.tar.gz" \
  .env \
  docker-compose.yml \
  deploy/ \
  hardening-models/

# Remove old backups
echo "Removing backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -type f -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_DIR"
```

### Schedule Backups

```bash
# Make executable
chmod +x /opt/cybersheppard/backup.sh

# Add to crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * /opt/cybersheppard/backup.sh >> /var/log/cybersheppard-backup.log 2>&1
```

### Restore from Backup

```bash
# Restore PostgreSQL
gunzip -c /backup/cybersheppard/postgres-20251211-020000.sql.gz | \
  docker-compose exec -T postgres psql -U cybersheppard -d cybersheppard

# Restore InfluxDB
docker cp /backup/cybersheppard/influx-backup-20251211-020000 \
  $(docker-compose ps -q influxdb):/tmp/
docker-compose exec influxdb influx restore \
  --bucket metrics \
  /tmp/influx-backup-20251211-020000

# Restore configuration
tar -xzf /backup/cybersheppard/config-20251211-020000.tar.gz -C /opt/cybersheppard/
```

---

## 📊 Monitoring the Monitor

### Health Checks

```bash
# Check API health
curl https://cybersheppard.example.com/api/health

# Check database connectivity
docker-compose exec backend-rust cargo run --bin health-check

# Check all services
docker-compose ps
```

### Prometheus Integration

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'cybersheppard'
    static_configs:
      - targets: ['localhost:8080']
```

### Grafana Dashboards

Import pre-built dashboards:
- CyberSheppard Overview (ID: 12345)
- PostgreSQL Metrics (ID: 9628)
- InfluxDB Metrics (ID: 5448)

---

## 📝 Maintenance

### Database Vacuum (Weekly)

```bash
# Auto-vacuum should run, but manual is recommended
docker-compose exec postgres psql -U cybersheppard -d cybersheppard -c "VACUUM ANALYZE;"
```

### Update Software

```bash
# Pull latest changes
cd /opt/cybersheppard
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build
docker-compose up -d

# Run migrations
docker-compose exec backend-rust sqlx migrate run
```

For more details, see [Installation Guide](./INSTALLATION_GUIDE.md) and [User Manual](./USER_MANUAL.md).
