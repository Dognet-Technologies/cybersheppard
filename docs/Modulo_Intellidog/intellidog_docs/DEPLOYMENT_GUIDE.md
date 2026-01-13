# Intellidog Deployment Guide

## Overview

Complete deployment guide for Intellidog threat intelligence module integration into CyberSheppard.

**Target Environment**: Production  
**OS**: Debian 11/12 or Ubuntu 20.04/22.04 LTS  
**Deployment Method**: Manual installation (Docker optional)  
**Prerequisites**: Existing CyberSheppard, Firedog, and Sentinel Core installations

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Database Setup](#database-setup)
3. [Backend Installation](#backend-installation)
4. [Frontend Installation](#frontend-installation)
5. [Celery Configuration](#celery-configuration)
6. [License Installation](#license-installation)
7. [Orchestration Setup](#orchestration-setup)
8. [Post-Deployment](#post-deployment)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**CyberSheppard Server**:
- CPU: 4 cores minimum (8 cores recommended)
- RAM: 8GB minimum (16GB recommended)
- Disk: 100GB SSD
- OS: Debian 11/12 or Ubuntu 22.04 LTS

**Network Requirements**:
- Outbound HTTPS (443) for threat feed updates
- Bidirectional HTTPS to Firedog and Sentinel Core
- Static IP address recommended

### Software Requirements

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    postgresql-15 \
    postgresql-client-15 \
    redis-server \
    nginx \
    git \
    build-essential \
    libpq-dev \
    gnupg2

# Install Node.js (for frontend build)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

### Verify Installations

```bash
# Check Python version
python3.11 --version  # Should be 3.11.x

# Check PostgreSQL
sudo systemctl status postgresql
psql --version  # Should be 15.x

# Check Redis
sudo systemctl status redis-server
redis-cli ping  # Should return PONG

# Check Node.js
node --version  # Should be 18.x
npm --version   # Should be 9.x or 10.x
```

---

## Database Setup

### Step 1: Create Intellidog Schema

```bash
# Login as postgres user
sudo -u postgres psql

# Connect to cybersheppard database
\c cybersheppard
```

```sql
-- Create intellidog schema
CREATE SCHEMA IF NOT EXISTS intellidog;

-- Grant permissions to vlnman user
GRANT USAGE ON SCHEMA intellidog TO vlnman;
GRANT CREATE ON SCHEMA intellidog TO vlnman;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA intellidog TO vlnman;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA intellidog TO vlnman;

-- Set default privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA intellidog 
    GRANT ALL PRIVILEGES ON TABLES TO vlnman;
ALTER DEFAULT PRIVILEGES IN SCHEMA intellidog 
    GRANT ALL PRIVILEGES ON SEQUENCES TO vlnman;

\q
```

### Step 2: Run Migrations

```bash
# Navigate to backend directory
cd /opt/cybersheppard/backend

# Activate virtual environment
source venv/bin/activate

# Run Alembic migrations
alembic upgrade head

# Verify tables created
psql -U vlnman -d cybersheppard -c "\dt intellidog.*"
```

**Expected Output**:
```
                     List of relations
  Schema    |              Name               | Type  | Owner  
------------+---------------------------------+-------+--------
 intellidog | intellidog_correlation_cache    | table | vlnman
 intellidog | intellidog_detections          | table | vlnman
 intellidog | intellidog_feed_update_logs    | table | vlnman
 intellidog | intellidog_feeds               | table | vlnman
 intellidog | intellidog_hunting_queries     | table | vlnman
 intellidog | intellidog_hunting_results     | table | vlnman
 intellidog | intellidog_iocs                | table | vlnman
 intellidog | intellidog_licenses            | table | vlnman
 intellidog | intellidog_virtual_patches     | table | vlnman
```

### Step 3: Verify Triggers

```bash
# Check triggers
psql -U vlnman -d cybersheppard -c "
SELECT 
    trigger_schema,
    trigger_name,
    event_object_table,
    action_statement
FROM information_schema.triggers
WHERE trigger_schema = 'intellidog'
ORDER BY event_object_table, trigger_name;
"
```

**Expected Triggers**:
- `trg_set_created_at` on all tables
- `trg_set_updated_at` on all tables
- `trg_calculate_ioc_hash` on intellidog_iocs
- `trg_calculate_risk_score` on intellidog_detections

---

## Backend Installation

### Step 1: Install Python Dependencies

```bash
# Navigate to backend
cd /opt/cybersheppard/backend

# Activate virtual environment
source venv/bin/activate

# Install Intellidog dependencies
pip install --upgrade pip setuptools wheel

# Install core dependencies
pip install \
    python-gnupg==0.5.1 \
    httpx==0.25.0 \
    celery==5.3.4 \
    redis==5.0.1 \
    pymisp==2.4.175 \
    stix2==3.0.1

# Verify installations
pip list | grep -E "(gnupg|celery|redis|pymisp|stix2)"
```

### Step 2: Install Intellidog Module

```bash
# Create Intellidog module directory
mkdir -p /opt/cybersheppard/backend/app/modules/intellidog

# Copy module files (assuming files are in deployment package)
cp -r /tmp/intellidog-deployment/backend/app/modules/intellidog/* \
      /opt/cybersheppard/backend/app/modules/intellidog/

# Verify structure
tree /opt/cybersheppard/backend/app/modules/intellidog -L 2
```

**Expected Structure**:
```
intellidog/
├── __init__.py
├── models/
│   ├── __init__.py
│   ├── license.py
│   ├── feed.py
│   ├── ioc.py
│   ├── detection.py
│   ├── virtual_patch.py
│   ├── hunting_query.py
│   └── correlation_cache.py
├── schemas/
│   ├── __init__.py
│   ├── license.py
│   ├── feed.py
│   ├── ioc.py
│   ├── detection.py
│   └── virtual_patch.py
├── api/
│   ├── __init__.py
│   ├── license.py
│   ├── feeds.py
│   ├── iocs.py
│   ├── detections.py
│   └── virtual_patches.py
├── services/
│   ├── __init__.py
│   ├── license_validator.py
│   ├── correlation_engine.py
│   ├── virtual_patcher.py
│   ├── firedog_client.py
│   └── feed_parsers/
└── tasks/
    ├── __init__.py
    ├── correlation_job.py
    ├── feed_updater.py
    ├── license_check.py
    └── cache_cleanup.py
```

### Step 3: Install GPG Public Key

```bash
# Create keys directory
sudo mkdir -p /opt/cybersheppard/keys
sudo chown cybersheppard:cybersheppard /opt/cybersheppard/keys
sudo chmod 700 /opt/cybersheppard/keys

# Download Dognet public key
curl -o /tmp/dognet-licensing-public.key \
    https://licensing.dognet.tech/public-keys/intellidog-2025.asc

# Verify fingerprint
gpg --with-fingerprint /tmp/dognet-licensing-public.key

# Expected fingerprint (verify with Dognet)
# Key fingerprint = 1234 5678 90AB CDEF 1234  5678 90AB CDEF 1234 5678

# Import key
gpg --import /tmp/dognet-licensing-public.key

# Copy to keys directory
cp /tmp/dognet-licensing-public.key \
   /opt/cybersheppard/keys/dognet-licensing-public.key

# Secure permissions
chmod 600 /opt/cybersheppard/keys/dognet-licensing-public.key

# Cleanup
rm /tmp/dognet-licensing-public.key
```

### Step 4: Configure Environment Variables

```bash
# Edit .env file
nano /opt/cybersheppard/backend/.env
```

**Add these variables**:
```bash
# Intellidog Configuration
INTELLIDOG_ENABLED=true
INTELLIDOG_LICENSE_PUBLIC_KEY_PATH=/opt/cybersheppard/keys/dognet-licensing-public.key

# Correlation Engine
INTELLIDOG_CORRELATION_INTERVAL_MINUTES=5
INTELLIDOG_DETECTION_WINDOW_HOURS=24
INTELLIDOG_MIN_CONFIDENCE_THRESHOLD=30
INTELLIDOG_AUTO_PATCH_ENABLED=true
INTELLIDOG_AUTO_PATCH_APPROVAL_REQUIRED=true

# Feed Updater
INTELLIDOG_FEED_UPDATE_INTERVAL_MINUTES=60
INTELLIDOG_FEED_FETCH_TIMEOUT_SECONDS=60

# Celery
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Firedog Integration (configure after orchestration)
FIREDOG_API_URL=
FIREDOG_API_KEY=

# Sentinel Integration (configure after orchestration)
SENTINEL_API_URL=
SENTINEL_API_KEY=
```

### Step 5: Register API Routes

```bash
# Edit main FastAPI app
nano /opt/cybersheppard/backend/app/main.py
```

**Add Intellidog routes**:
```python
# Add at the top with other imports
from app.modules.intellidog.api import (
    license as intellidog_license,
    feeds as intellidog_feeds,
    iocs as intellidog_iocs,
    detections as intellidog_detections,
    virtual_patches as intellidog_patches
)

# Add after existing route registrations
# Intellidog Routes (license-gated)
app.include_router(intellidog_license.router)
app.include_router(intellidog_feeds.router)
app.include_router(intellidog_iocs.router)
app.include_router(intellidog_detections.router)
app.include_router(intellidog_patches.router)
```

### Step 6: Restart Backend

```bash
# Restart backend service
sudo systemctl restart cybersheppard-backend

# Check status
sudo systemctl status cybersheppard-backend

# Check logs
sudo journalctl -u cybersheppard-backend -f
```

**Verify API Available**:
```bash
# Test health endpoint
curl http://localhost:8000/api/health

# Test Intellidog license endpoint (should return 402 Payment Required)
curl http://localhost:8000/api/intellidog/license/current
```

---

## Frontend Installation

### Step 1: Install Frontend Dependencies

```bash
# Navigate to frontend
cd /opt/cybersheppard/frontend

# Install Intellidog dependencies
npm install \
    @tanstack/react-query@5.8.4 \
    date-fns@2.30.0 \
    recharts@2.10.3 \
    lucide-react@0.292.0

# Verify installations
npm list | grep -E "(react-query|recharts|lucide)"
```

### Step 2: Copy Frontend Files

```bash
# Copy Intellidog frontend files
cp -r /tmp/intellidog-deployment/frontend/src/pages/ThreatIntel \
      /opt/cybersheppard/frontend/src/pages/

cp -r /tmp/intellidog-deployment/frontend/src/components/intellidog \
      /opt/cybersheppard/frontend/src/components/

cp -r /tmp/intellidog-deployment/frontend/src/hooks/intellidog \
      /opt/cybersheppard/frontend/src/hooks/

cp -r /tmp/intellidog-deployment/frontend/src/services/intellidog \
      /opt/cybersheppard/frontend/src/services/

cp -r /tmp/intellidog-deployment/frontend/src/types/intellidog \
      /opt/cybersheppard/frontend/src/types/
```

### Step 3: Update Router

```bash
# Edit App.tsx
nano /opt/cybersheppard/frontend/src/App.tsx
```

**Add Intellidog routes**:
```typescript
// Add imports at top
import { OverviewPage } from './pages/ThreatIntel/Overview';
import { FeedsPage } from './pages/ThreatIntel/Feeds';
import { IOCBrowserPage } from './pages/ThreatIntel/IOCBrowser';
import { DetectionsPage } from './pages/ThreatIntel/Detections';
import { VirtualPatchesPage } from './pages/ThreatIntel/VirtualPatches';
import { ThreatHuntingPage } from './pages/ThreatIntel/ThreatHunting';

// Add routes in the router
<Route path="/threat-intel">
  <Route index element={<OverviewPage />} />
  <Route path="feeds" element={<FeedsPage />} />
  <Route path="iocs" element={<IOCBrowserPage />} />
  <Route path="detections" element={<DetectionsPage />} />
  <Route path="virtual-patches" element={<VirtualPatchesPage />} />
  <Route path="hunting" element={<ThreatHuntingPage />} />
</Route>
```

### Step 4: Update Navigation

```bash
# Edit navigation component
nano /opt/cybersheppard/frontend/src/components/Navigation.tsx
```

**Add Threat Intel menu item**:
```typescript
// Add to navigation items
{
  label: 'Threat Intel',
  icon: <Shield className="h-5 w-5" />,
  href: '/threat-intel',
  badge: hasActiveLicense ? null : { text: 'License Required', color: 'yellow' }
}
```

### Step 5: Build Frontend

```bash
# Navigate to frontend directory
cd /opt/cybersheppard/frontend

# Build production bundle
npm run build

# Verify build
ls -lh dist/
```

### Step 6: Deploy Build

```bash
# Copy build to nginx directory
sudo rm -rf /var/www/cybersheppard/html/*
sudo cp -r /opt/cybersheppard/frontend/dist/* /var/www/cybersheppard/html/

# Set permissions
sudo chown -R www-data:www-data /var/www/cybersheppard/html
sudo chmod -R 755 /var/www/cybersheppard/html

# Restart nginx
sudo systemctl restart nginx

# Verify
curl -I http://localhost
```

---

## Celery Configuration

### Step 1: Create Celery Service Files

**Worker Service**:
```bash
sudo nano /etc/systemd/system/celery-worker.service
```

```ini
[Unit]
Description=Celery Worker Service
After=network.target redis.service postgresql.service

[Service]
Type=forking
User=cybersheppard
Group=cybersheppard
WorkingDirectory=/opt/cybersheppard/backend
EnvironmentFile=/opt/cybersheppard/backend/.env

ExecStart=/opt/cybersheppard/backend/venv/bin/celery -A app.core.celery_config:celery_app worker \
    --loglevel=INFO \
    --concurrency=4 \
    --max-tasks-per-child=1000 \
    --pidfile=/var/run/celery/worker.pid \
    --logfile=/var/log/celery/worker.log

ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

**Beat Service**:
```bash
sudo nano /etc/systemd/system/celery-beat.service
```

```ini
[Unit]
Description=Celery Beat Service
After=network.target redis.service postgresql.service

[Service]
Type=simple
User=cybersheppard
Group=cybersheppard
WorkingDirectory=/opt/cybersheppard/backend
EnvironmentFile=/opt/cybersheppard/backend/.env

ExecStart=/opt/cybersheppard/backend/venv/bin/celery -A app.core.celery_config:celery_app beat \
    --loglevel=INFO \
    --pidfile=/var/run/celery/beat.pid \
    --logfile=/var/log/celery/beat.log

ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

### Step 2: Create Directories

```bash
# Create runtime directory
sudo mkdir -p /var/run/celery
sudo chown cybersheppard:cybersheppard /var/run/celery

# Create log directory
sudo mkdir -p /var/log/celery
sudo chown cybersheppard:cybersheppard /var/log/celery
```

### Step 3: Enable and Start Services

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable celery-worker
sudo systemctl enable celery-beat

# Start services
sudo systemctl start celery-worker
sudo systemctl start celery-beat

# Check status
sudo systemctl status celery-worker
sudo systemctl status celery-beat

# Check logs
sudo journalctl -u celery-worker -f
sudo journalctl -u celery-beat -f
```

### Step 4: Verify Celery Tasks

```bash
# Check registered tasks
cd /opt/cybersheppard/backend
source venv/bin/activate
celery -A app.core.celery_config:celery_app inspect registered

# Expected output should include:
# - intellidog.correlation_job
# - intellidog.feed_update_job
# - intellidog.license_check
# - intellidog.cache_cleanup
# - intellidog.expire_virtual_patches
```

---

## License Installation

### Step 1: Obtain License File

Contact Dognet Technologies to obtain your `.lic` file:
- Email: licensing@dognet.tech
- Provide: Company name, number of machines, support level

You will receive: `INTL-2025-COMPANY-XXXX.lic`

### Step 2: Upload License via UI

1. Login to CyberSheppard as admin
2. Navigate to **Settings → License** (or `/threat-intel`)
3. Click **Upload License**
4. Select your `.lic` file
5. Click **Upload**

**Expected Result**:
- Green success message
- License details displayed (customer, expiry, features)
- Threat Intel menu becomes accessible

### Step 3: Verify License via CLI

```bash
# Check license in database
psql -U vlnman -d cybersheppard -c "
SELECT 
    license_key,
    customer,
    expires_at,
    max_machines,
    features,
    is_active
FROM intellidog.intellidog_licenses
WHERE is_active = true;
"
```

### Step 4: Test License Validation

```bash
# Test API endpoint
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8000/api/intellidog/license/current
```

**Expected Response**:
```json
{
  "success": true,
  "data": {
    "license_key": "INTL-2025-COMPANY-XXXX",
    "customer": "Your Company",
    "expires_at": "2026-01-01T23:59:59Z",
    "max_machines": 250,
    "features": ["threat_intel_feeds", "correlation", "virtual_patching"],
    "is_active": true
  }
}
```

---

## Orchestration Setup

### Step 1: Configure CyberSheppard API Key

1. Navigate to **Settings → Orchestrazione** in CyberSheppard UI
2. Click **Generate API Key**
3. Copy the generated API key (save securely)

### Step 2: Configure Firedog Connection

**On CyberSheppard**:
1. Settings → Orchestrazione → Firedog Connection
2. Hostname: `firedog.yourdomain.com` (or IP)
3. Port: `8443`
4. API Key: (get from Firedog - see below)
5. Click **Test Connection**
6. Click **Save Configuration**

**On Firedog**:
1. Login to Firedog
2. Settings → Orchestrazione → CyberSheppard
3. Hostname: `cybersheppard.yourdomain.com`
4. Port: `8000`
5. API Key: (paste CyberSheppard API key from Step 1)
6. Click **Test Connection**
7. Click **Save Configuration**
8. Copy Firedog API key

**Back on CyberSheppard**:
1. Paste Firedog API key into Firedog Connection section
2. Click **Save Configuration**

### Step 3: Configure Sentinel Connection

Repeat the same process for Sentinel Core.

### Step 4: Install Replication Plugins

**On Firedog**:
```bash
# Navigate to plugins directory
cd /opt/firedog/plugins

# Install replication plugin
git clone https://github.com/dognet-tech/firedog-replication-plugin.git

# Install dependencies
cd firedog-replication-plugin
pip install -r requirements.txt

# Configure plugin
cp config.example.yaml config.yaml
nano config.yaml

# Edit config.yaml:
cybersheppard:
  url: https://cybersheppard.yourdomain.com:8000
  api_key: YOUR_CYBERSHEPPARD_API_KEY
  
replication:
  tables:
    - firewall_rules
    - firewall_logs
    - connections
  interval_seconds: 30

# Restart Firedog
sudo systemctl restart firedog
```

**On Sentinel Core**:
```bash
# Similar process for Sentinel
cd /opt/sentinel/plugins
git clone https://github.com/dognet-tech/sentinel-replication-plugin.git
# ... (follow same steps as Firedog)
```

### Step 5: Verify Replication

```bash
# Check replicated data in CyberSheppard
psql -U vlnman -d cybersheppard

# Check Firedog replica tables
\dt firedog_replica.*

# Check Sentinel replica tables
\dt sentinel_replica.*

# Check data exists
SELECT count(*) FROM firedog_replica.firewall_logs;
SELECT count(*) FROM sentinel_replica.vulnerabilities;
```

---

## Post-Deployment

### Step 1: Add First Threat Feed

1. Navigate to **Threat Intel → Feeds**
2. Click **Add Feed**
3. Configure feed:
   - Name: `AlienVault OTX`
   - Type: `otx`
   - URL: `https://otx.alienvault.com/api/v1`
   - API Key: (your OTX API key)
   - Auto Update: ✓
   - Update Interval: 60 minutes
4. Click **Save**
5. Click **Update Now** (or wait for automatic update)

### Step 2: Monitor First Correlation

```bash
# Watch correlation job logs
sudo journalctl -u celery-worker -f | grep correlation

# Check detections in database
psql -U vlnman -d cybersheppard -c "
SELECT count(*) FROM intellidog.intellidog_detections;
"
```

### Step 3: Create Test Alert

```bash
# Add a test IOC (malicious IP)
psql -U vlnman -d cybersheppard

INSERT INTO intellidog.intellidog_iocs (
    feed_id, ioc_type, value, severity, confidence_score,
    threat_type, description, tags, first_seen, last_seen
) VALUES (
    1, 'ip', '192.0.2.1', 'critical', 90,
    'C2 Server', 'Test malicious IP', ARRAY['test', 'malware'],
    now(), now()
);

# Wait 5 minutes for correlation job
# Check if detection created
SELECT * FROM intellidog.intellidog_detections 
WHERE ioc_id = (SELECT id FROM intellidog.intellidog_iocs WHERE value = '192.0.2.1');
```

### Step 4: Verify Virtual Patching

1. Navigate to **Threat Intel → Virtual Patches**
2. You should see auto-generated patches for critical detections
3. Click **Approve** on a pending patch
4. Verify rule deployed in Firedog

### Step 5: Configure Alerts

1. Navigate to **Settings → Alerts**
2. Add email alert:
   - Recipients: `security@yourcompany.com`
   - Triggers: Critical/High detections
3. Test alert
4. Add Slack/Telegram webhooks if desired

---

## Verification Checklist

```bash
# Run this comprehensive check script
bash /opt/cybersheppard/scripts/verify-intellidog.sh
```

**Manual Checklist**:

- [ ] Database schema `intellidog` created
- [ ] All 10 tables present with correct structure
- [ ] Triggers installed and functional
- [ ] Backend API endpoints responding
- [ ] Frontend pages accessible
- [ ] License uploaded and validated
- [ ] Celery worker running
- [ ] Celery beat running
- [ ] Redis accessible
- [ ] Firedog connection working
- [ ] Sentinel connection working
- [ ] Replication active (data flowing)
- [ ] First feed added and updated
- [ ] Correlation job running (check logs)
- [ ] At least 1 detection created
- [ ] Virtual patches generated
- [ ] Alerts configured
- [ ] GPG public key installed
- [ ] All environment variables set

---

## Troubleshooting

### Database Connection Issues

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test connection
psql -U vlnman -d cybersheppard -c "SELECT version();"

# Check permissions
psql -U vlnman -d cybersheppard -c "\dn+ intellidog"
```

### Celery Not Starting

```bash
# Check Redis
redis-cli ping

# Check Celery logs
sudo journalctl -u celery-worker -n 100 --no-pager

# Test Celery connection manually
cd /opt/cybersheppard/backend
source venv/bin/activate
celery -A app.core.celery_config:celery_app inspect ping
```

### License Validation Failing

```bash
# Check GPG key
gpg --list-keys

# Verify public key file
cat /opt/cybersheppard/keys/dognet-licensing-public.key

# Test license file manually
cd /opt/cybersheppard/backend
source venv/bin/activate
python -c "
from app.modules.intellidog.services.license_validator import LicenseValidator
from app.database import get_db_session

with get_db_session() as db:
    validator = LicenseValidator(db)
    with open('/path/to/license.lic') as f:
        result = validator.validate_and_store(f.read(), user_id=1)
    print(result)
"
```

### Feed Updates Not Working

```bash
# Check feed update logs
sudo journalctl -u celery-worker | grep feed_update

# Manually trigger feed update
cd /opt/cybersheppard/backend
source venv/bin/activate
python -c "
from app.modules.intellidog.tasks.feed_updater import update_feeds_task
result = update_feeds_task.apply(kwargs={'force': True})
print(result.get())
"

# Check network connectivity
curl -I https://otx.alienvault.com/api/v1
```

### Correlation Not Finding Detections

```bash
# Check if IOCs exist
psql -U vlnman -d cybersheppard -c "
SELECT count(*), is_active FROM intellidog.intellidog_iocs 
GROUP BY is_active;
"

# Check if replica data exists
psql -U vlnman -d cybersheppard -c "
SELECT count(*) FROM firedog_replica.firewall_logs 
WHERE timestamp > now() - interval '24 hours';
"

# Manually run correlation
cd /opt/cybersheppard/backend
source venv/bin/activate
python -c "
from app.modules.intellidog.tasks.correlation_job import run_correlation_job
result = run_correlation_job.apply()
print(result.get())
"
```

### Virtual Patches Not Deploying

```bash
# Check Firedog connection
curl -H "Authorization: Bearer FIREDOG_API_KEY" \
     https://firedog.yourdomain.com:8443/api/health

# Check virtual patch logs
sudo journalctl -u celery-worker | grep virtual_patch

# Test Firedog client manually
cd /opt/cybersheppard/backend
source venv/bin/activate
python -c "
from app.modules.intellidog.services.firedog_client import FiredogClient
client = FiredogClient()
print(client.test_connection())
"
```

---

## Rollback Procedure

If deployment fails and rollback is needed:

```bash
# Stop services
sudo systemctl stop celery-worker
sudo systemctl stop celery-beat
sudo systemctl stop cybersheppard-backend

# Rollback database
psql -U vlnman -d cybersheppard
DROP SCHEMA intellidog CASCADE;

# Remove backend files
rm -rf /opt/cybersheppard/backend/app/modules/intellidog

# Remove frontend files
rm -rf /opt/cybersheppard/frontend/src/pages/ThreatIntel
rm -rf /opt/cybersheppard/frontend/src/components/intellidog
rm -rf /opt/cybersheppard/frontend/src/hooks/intellidog
rm -rf /opt/cybersheppard/frontend/src/services/intellidog
rm -rf /opt/cybersheppard/frontend/src/types/intellidog

# Rebuild frontend (without Intellidog)
cd /opt/cybersheppard/frontend
npm run build
sudo cp -r dist/* /var/www/cybersheppard/html/

# Restart services
sudo systemctl start cybersheppard-backend
sudo systemctl restart nginx
```

---

## Performance Tuning

### Database Optimization

```sql
-- Add indexes for better performance
CREATE INDEX CONCURRENTLY idx_iocs_value_hash 
    ON intellidog.intellidog_iocs(value_hash);

CREATE INDEX CONCURRENTLY idx_iocs_feed_active 
    ON intellidog.intellidog_iocs(feed_id, is_active);

CREATE INDEX CONCURRENTLY idx_detections_machine_severity 
    ON intellidog.intellidog_detections(machine_id, severity);

CREATE INDEX CONCURRENTLY idx_detections_status 
    ON intellidog.intellidog_detections(status);

-- Analyze tables
ANALYZE intellidog.intellidog_iocs;
ANALYZE intellidog.intellidog_detections;
```

### Celery Worker Scaling

```bash
# Increase worker concurrency
sudo nano /etc/systemd/system/celery-worker.service

# Change --concurrency=4 to --concurrency=8 (if CPU allows)
# Restart worker
sudo systemctl daemon-reload
sudo systemctl restart celery-worker
```

### Redis Optimization

```bash
# Edit Redis config
sudo nano /etc/redis/redis.conf

# Increase max memory
maxmemory 2gb
maxmemory-policy allkeys-lru

# Restart Redis
sudo systemctl restart redis-server
```

---

## Backup Strategy

### Database Backup

```bash
# Create backup script
sudo nano /opt/cybersheppard/scripts/backup-intellidog.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/backup/intellidog"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup Intellidog schema
pg_dump -U vlnman -d cybersheppard -n intellidog \
    --format=custom \
    --file="$BACKUP_DIR/intellidog_$DATE.dump"

# Compress
gzip "$BACKUP_DIR/intellidog_$DATE.dump"

# Keep last 30 days
find $BACKUP_DIR -name "intellidog_*.dump.gz" -mtime +30 -delete
```

```bash
# Make executable
sudo chmod +x /opt/cybersheppard/scripts/backup-intellidog.sh

# Add to crontab (daily at midnight)
sudo crontab -e
0 0 * * * /opt/cybersheppard/scripts/backup-intellidog.sh
```

---

## Support

**Documentation**: https://docs.dognet.tech/intellidog  
**Support Email**: support@dognet.tech  
**Emergency**: +39-XXX-XXX-XXXX (24/7 for Enterprise customers)

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-01-02  
**Author**: Dognet Technologies
