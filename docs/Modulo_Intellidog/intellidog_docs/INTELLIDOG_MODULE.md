# Intellidog Module - Activation & Usage Guide

## Overview

Intellidog is a **premium threat intelligence module** for CyberSheppard that correlates data from Firedog (firewall) and Sentinel Core (vulnerabilities) with global threat intelligence feeds to provide advanced security insights.

**Prerequisites**:
- ✅ CyberSheppard installed and operational
- ✅ Orchestration configured (see `ORCHESTRATION_SETUP.md`)
- ✅ Replication plugins installed (see `REPLICATION_PLUGINS.md`)
- ✅ Valid Intellidog license file

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Intellidog Module                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Data Sources:                                              │
│  ├─ firedog_replica schema (firewall rules, connections)    │
│  ├─ sentinel_replica schema (vulnerabilities, CVEs)         │
│  ├─ public schema (CyberSheppard machines, users)           │
│  └─ External APIs (MISP, AlienVault OTX, VirusTotal)        │
│                                                              │
│  Processing:                                                │
│  ├─ Threat Intelligence Feeds (IOCs, TTPs, campaigns)       │
│  ├─ Correlation Engine (match IOCs with firewall/vulns)     │
│  ├─ Risk Scoring (calculate threat levels)                  │
│  ├─ Virtual Patching (auto-generate firewall rules)         │
│  └─ Threat Hunting (custom queries across all data)         │
│                                                              │
│  Outputs:                                                   │
│  ├─ Real-time threat detections                             │
│  ├─ Virtual patches for Firedog                             │
│  ├─ Executive dashboards                                    │
│  └─ Automated alerts                                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## License Management

### Obtaining a License

**Contact**: licensing@dognet.tech

**License includes**:
- Customer name
- Max machines allowed
- Expiration date
- Enabled features
- GPG signature

**License File Format** (`.lic`):
```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

{
  "customer": "ACME Corporation",
  "license_key": "INTL-XXXX-XXXX-XXXX-XXXX",
  "issued_at": "2025-01-01T00:00:00Z",
  "expires_at": "2026-01-01T00:00:00Z",
  "max_machines": 100,
  "features": ["threat_intel_feeds", "correlation", "virtual_patching", "hunting"],
  "support_level": "enterprise"
}
-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----
```

---

## Installation & Activation

### Step 1: Access Plugin Manager

```
CyberSheppard UI → Settings → Plugins
```

### Step 2: Locate Intellidog Module

```
[Available Plugins Tab]

┌──────────────────────────────────────────────────────┐
│ 🛡️ Intellidog - Threat Intelligence Module           │
├──────────────────────────────────────────────────────┤
│ Version: 1.0.0                                       │
│ Author: Dognet Technologies                          │
│ Category: Security Intelligence                      │
│ License: Commercial (License Required)               │
│                                                      │
│ Description:                                         │
│ Advanced threat intelligence platform that          │
│ correlates firewall, vulnerability, and global      │
│ threat data to provide actionable security          │
│ insights.                                            │
│                                                      │
│ Requires:                                            │
│ ✅ Firedog Replication Plugin                        │
│ ✅ Sentinel Replication Plugin                       │
│ ✅ Valid Intellidog license file                     │
│                                                      │
│ [Attiva]                                             │
└──────────────────────────────────────────────────────┘
```

### Step 3: Click "Attiva"

**License Upload Dialog**:

```
[License Upload]

┌──────────────────────────────────────────────────────┐
│ Intellidog License Required                          │
├──────────────────────────────────────────────────────┤
│                                                      │
│ Upload your Intellidog license file (.lic)          │
│                                                      │
│ ┌──────────────────────────────────────────┐        │
│ │  [Drag & Drop .lic file here]            │        │
│ │                                           │        │
│ │  or                                       │        │
│ │                                           │        │
│ │  [Browse Files...]                        │        │
│ └──────────────────────────────────────────┘        │
│                                                      │
│ Don't have a license?                                │
│ Contact: licensing@dognet.tech                       │
│                                                      │
│ [Cancel]                                             │
└──────────────────────────────────────────────────────┘
```

### Step 4: License Validation

**After uploading `intellidog.lic`**:

```
[Validating License...]

✅ File format: Valid
✅ GPG signature: Verified (Dognet Technologies)
✅ License key: INTL-XXXX-XXXX-XXXX-XXXX
✅ Expiration: 2026-01-01 (364 days remaining)

[License Details]

Customer:        ACME Corporation
Max Machines:    100
Current Usage:   45 machines (55 available)
Support Level:   Enterprise
Enabled Features:
  ✅ Threat Intelligence Feeds
  ✅ Correlation Engine
  ✅ Virtual Patching
  ✅ Threat Hunting Queries
  ✅ Executive Dashboards

[Activate Module]  [Cancel]
```

### Step 5: Module Installation

**Click "Activate Module"**:

```
[Installation Progress]

Installing Intellidog Module...

✅ License validated and stored
✅ Downloading module from GitHub
✅ Verifying SHA256 checksum
✅ Extracting module files

Creating database schema...
✅ Schema 'intellidog' created

Creating tables...
✅ intellidog_feeds (threat intelligence sources)
✅ intellidog_iocs (indicators of compromise)
✅ intellidog_detections (threat detections)
✅ intellidog_virtual_patches (auto-generated firewall rules)
✅ intellidog_hunting_queries (custom threat hunting)
✅ intellidog_license (license management)

Granting permissions...
✅ vlnman granted access to intellidog schema

Initializing threat feeds...
✅ AlienVault OTX feed configured
✅ MISP feed configured
✅ Custom feeds ready

Creating background tasks...
✅ Feed update job (every 1 hour)
✅ Correlation job (every 5 minutes)
✅ License check job (daily)

Registering API routes...
✅ /api/intellidog/feeds
✅ /api/intellidog/iocs
✅ /api/intellidog/detections
✅ /api/intellidog/virtual-patches
✅ /api/intellidog/hunting

Registering UI components...
✅ Navigation menu: "Threat Intelligence"
✅ Dashboard widgets
✅ Pages: Feeds, Detections, Virtual Patches, Hunting

============================================================
Installation Complete!
============================================================

Intellidog is now active and ready to use.

Access: Main Menu → Threat Intelligence

[View Dashboard]  [Close]
```

---

## User Interface Tour

### Main Navigation

After activation, new menu appears:

```
Main Menu
├─ Dashboard
├─ Machines
├─ Hardening
├─ Monitoring
├─ 🆕 Threat Intelligence  ← NEW!
│   ├─ Overview
│   ├─ Threat Feeds
│   ├─ IOC Browser
│   ├─ Detections
│   ├─ Virtual Patches
│   └─ Threat Hunting
├─ Compliance
├─ Alerts
└─ Settings
```

### Threat Intelligence Overview

**Page**: Threat Intelligence → Overview

```
┌─────────────────────────────────────────────────────────┐
│ Threat Intelligence Dashboard                           │
├─────────────────────────────────────────────────────────┤
│                                                          │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│ │  Active  │ │ Critical │ │ Virtual  │ │  Feeds   │   │
│ │   IOCs   │ │Detection │ │ Patches  │ │  Active  │   │
│ │  12,456  │ │    23    │ │    45    │ │    8     │   │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│                                                          │
│ Recent Detections (Last 24h)                            │
│ ┌────────────────────────────────────────────────────┐ │
│ │ 🔴 Critical: Exploit attempt detected               │ │
│ │    Machine: web-server-01 (192.168.1.10)           │ │
│ │    IOC: CVE-2024-12345 exploit traffic             │ │
│ │    Action: Virtual patch created and applied       │ │
│ │    Time: 2 minutes ago                              │ │
│ ├────────────────────────────────────────────────────┤ │
│ │ 🟡 Medium: Suspicious IP connection                │ │
│ │    Machine: database-01 (192.168.1.20)             │ │
│ │    IOC: Known malicious IP 203.0.113.45            │ │
│ │    Action: Connection blocked by firewall          │ │
│ │    Time: 15 minutes ago                             │ │
│ └────────────────────────────────────────────────────┘ │
│                                                          │
│ Threat Landscape                                        │
│ [Chart: IOC types distribution (IP, Domain, Hash)]      │
│ [Chart: Detections by severity over time]              │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Threat Feeds Management

**Page**: Threat Intelligence → Threat Feeds

```
┌─────────────────────────────────────────────────────────┐
│ Threat Intelligence Feeds                               │
├─────────────────────────────────────────────────────────┤
│                                                          │
│ [Add Feed]  [Refresh All]  [Settings]                   │
│                                                          │
│ ┌──────────────────────────────────────────────────┐   │
│ │ 🟢 AlienVault OTX                                │   │
│ │    Status: Active                                 │   │
│ │    IOCs: 8,234                                    │   │
│ │    Last Update: 5 minutes ago                     │   │
│ │    Next Update: in 55 minutes                     │   │
│ │    [Configure]  [Pause]                           │   │
│ ├──────────────────────────────────────────────────┤   │
│ │ 🟢 MISP Community Feed                           │   │
│ │    Status: Active                                 │   │
│ │    IOCs: 3,456                                    │   │
│ │    Last Update: 12 minutes ago                    │   │
│ │    [Configure]  [Pause]                           │   │
│ ├──────────────────────────────────────────────────┤   │
│ │ 🔴 Custom Feed - Internal SOC                    │   │
│ │    Status: Error (Authentication failed)          │   │
│ │    IOCs: 0                                        │   │
│ │    Last Update: Never                             │   │
│ │    [Configure]  [Retry]                           │   │
│ └──────────────────────────────────────────────────┘   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Detections Dashboard

**Page**: Threat Intelligence → Detections

```
┌─────────────────────────────────────────────────────────┐
│ Threat Detections                                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│ Filters: [All] [Critical] [High] [Medium] [Low]         │
│ Machine: [All Machines ▼]   Time: [Last 7 days ▼]       │
│                                                          │
│ ┌────────────────────────────────────────────────────┐ │
│ │ Severity │ Machine      │ Detection          │Time │ │
│ ├──────────┼──────────────┼────────────────────┼─────┤ │
│ │ 🔴 CRIT  │ web-01       │ CVE-2024-12345     │ 2m  │ │
│ │          │ 192.168.1.10 │ Exploit traffic    │     │ │
│ │          │              │ [Details] [Patch]  │     │ │
│ ├──────────┼──────────────┼────────────────────┼─────┤ │
│ │ 🟡 MED   │ db-01        │ Malicious IP       │ 15m │ │
│ │          │ 192.168.1.20 │ 203.0.113.45       │     │ │
│ │          │              │ [Details] [Block]  │     │ │
│ ├──────────┼──────────────┼────────────────────┼─────┤ │
│ │ 🟢 LOW   │ gateway-01   │ Outdated software  │ 1h  │ │
│ │          │ 192.168.1.1  │ Update available   │     │ │
│ │          │              │ [Details]          │     │ │
│ └────────────────────────────────────────────────────┘ │
│                                                          │
│ [Export CSV]  [Generate Report]                         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Virtual Patching

**Page**: Threat Intelligence → Virtual Patches

```
┌─────────────────────────────────────────────────────────┐
│ Virtual Patches                                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│ Auto-generated firewall rules based on threat intel     │
│                                                          │
│ ┌────────────────────────────────────────────────────┐ │
│ │ Status │ Patch Name         │ Machines │ Created  │ │
│ ├────────┼────────────────────┼──────────┼──────────┤ │
│ │ ✅ ACT │ Block CVE-2024-123 │ 5        │ 2m ago   │ │
│ │        │ DROP tcp:8080      │          │          │ │
│ │        │ [Details] [Deploy] │          │          │ │
│ ├────────┼────────────────────┼──────────┼──────────┤ │
│ │ ⏸️ PEND│ Block Malicious IP │ 12       │ 15m ago  │ │
│ │        │ 203.0.113.45       │          │          │ │
│ │        │ [Approve] [Reject] │          │          │ │
│ ├────────┼────────────────────┼──────────┼──────────┤ │
│ │ ✅ ACT │ Rate limit SSH     │ All      │ 1h ago   │ │
│ │        │ Max 5/min          │          │          │ │
│ │        │ [Details] [Remove] │          │          │ │
│ └────────────────────────────────────────────────────┘ │
│                                                          │
│ [Create Manual Patch]  [Settings]                       │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Threat Hunting

**Page**: Threat Intelligence → Threat Hunting

```
┌─────────────────────────────────────────────────────────┐
│ Threat Hunting                                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│ Custom queries across all threat data                   │
│                                                          │
│ ┌────────────────────────────────────────────────────┐ │
│ │ Query Builder                                      │ │
│ ├────────────────────────────────────────────────────┤ │
│ │                                                    │ │
│ │ Find: [IOC Type ▼] [equals ▼] [malicious_ip]      │ │
│ │                                                    │ │
│ │ AND  Machine: [All ▼]                              │ │
│ │ AND  Severity: [Critical, High ▼]                  │ │
│ │ AND  Time Range: [Last 30 days ▼]                  │ │
│ │                                                    │ │
│ │ [Run Query]  [Save]  [Load Saved]                  │ │
│ └────────────────────────────────────────────────────┘ │
│                                                          │
│ Results (23 matches):                                   │
│ ┌────────────────────────────────────────────────────┐ │
│ │ IOC              │ Machine    │ First Seen │ Count │ │
│ ├──────────────────┼────────────┼────────────┼───────┤ │
│ │ 203.0.113.45     │ web-01     │ 2025-01-15 │ 127   │ │
│ │ 198.51.100.23    │ db-01      │ 2025-01-14 │ 45    │ │
│ │ ...              │ ...        │ ...        │ ...   │ │
│ └────────────────────────────────────────────────────┘ │
│                                                          │
│ [Export]  [Create Alert Rule]  [Generate Report]        │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## Database Schema (intellidog)

### Tables Created

```sql
-- Threat Intelligence Feeds
CREATE TABLE intellidog.intellidog_feeds (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    url TEXT,
    feed_type VARCHAR(50),  -- 'misp', 'otx', 'stix', 'custom'
    is_active BOOLEAN DEFAULT TRUE,
    update_interval_minutes INTEGER DEFAULT 60,
    last_update TIMESTAMP,
    next_update TIMESTAMP,
    ioc_count INTEGER DEFAULT 0,
    credentials_encrypted TEXT,  -- API keys, encrypted
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indicators of Compromise
CREATE TABLE intellidog.intellidog_iocs (
    id SERIAL PRIMARY KEY,
    feed_id INTEGER REFERENCES intellidog.intellidog_feeds(id),
    ioc_type VARCHAR(50),  -- 'ip', 'domain', 'hash', 'url', 'email'
    value TEXT NOT NULL,
    severity VARCHAR(20),  -- 'critical', 'high', 'medium', 'low'
    threat_type VARCHAR(50),  -- 'malware', 'phishing', 'c2', 'exploit'
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    confidence_score INTEGER,  -- 0-100
    metadata JSONB,  -- Additional context
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Threat Detections (Correlations)
CREATE TABLE intellidog.intellidog_detections (
    id SERIAL PRIMARY KEY,
    machine_id INTEGER REFERENCES machines(id),
    ioc_id INTEGER REFERENCES intellidog.intellidog_iocs(id),
    detection_type VARCHAR(50),  -- 'firewall_match', 'vuln_correlation', 'behavior'
    severity VARCHAR(20),
    source_data JSONB,  -- Firewall log, vuln scan result, etc.
    status VARCHAR(20) DEFAULT 'new',  -- 'new', 'investigating', 'resolved', 'false_positive'
    auto_patched BOOLEAN DEFAULT FALSE,
    virtual_patch_id INTEGER,
    assigned_to INTEGER REFERENCES users(id),
    notes TEXT,
    detected_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP
);

-- Virtual Patches (Auto-generated Firewall Rules)
CREATE TABLE intellidog.intellidog_virtual_patches (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    ioc_id INTEGER REFERENCES intellidog.intellidog_iocs(id),
    patch_type VARCHAR(50),  -- 'block_ip', 'block_port', 'rate_limit'
    firewall_rule_template JSONB,
    target_machines INTEGER[],  -- Array of machine IDs
    status VARCHAR(20) DEFAULT 'pending',  -- 'pending', 'approved', 'deployed', 'rejected'
    auto_approve BOOLEAN DEFAULT FALSE,
    deployed_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Threat Hunting Queries
CREATE TABLE intellidog.intellidog_hunting_queries (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    query_json JSONB NOT NULL,  -- Query parameters
    created_by INTEGER REFERENCES users(id),
    is_scheduled BOOLEAN DEFAULT FALSE,
    schedule_cron VARCHAR(50),
    last_run TIMESTAMP,
    result_count INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- License Management
CREATE TABLE intellidog.intellidog_license (
    id SERIAL PRIMARY KEY,
    license_key VARCHAR(100) UNIQUE NOT NULL,
    customer_name VARCHAR(200),
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    max_machines INTEGER,
    features JSONB,
    support_level VARCHAR(50),
    license_file_content TEXT,  -- Full .lic file content
    gpg_signature_valid BOOLEAN,
    last_validated TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Indexes

```sql
-- Performance indexes
CREATE INDEX idx_iocs_value ON intellidog.intellidog_iocs(value);
CREATE INDEX idx_iocs_type ON intellidog.intellidog_iocs(ioc_type);
CREATE INDEX idx_iocs_severity ON intellidog.intellidog_iocs(severity);
CREATE INDEX idx_detections_machine ON intellidog.intellidog_detections(machine_id);
CREATE INDEX idx_detections_status ON intellidog.intellidog_detections(status);
CREATE INDEX idx_detections_detected_at ON intellidog.intellidog_detections(detected_at);
```

---

## How Intellidog Accesses Data

### Connection Details

```python
# backend/app/modules/intellidog/services/data_access.py

from app.database import db  # Standard connection (vlnman/DogNET)

class IntellidogDataAccess:
    """
    Intellidog accesses data using the standard vlnman user.
    No special user or connection needed.
    """
    
    def get_firewall_rules(self):
        """Query Firedog replica"""
        return db.execute("""
            SELECT * FROM firedog_replica.firewall_rules
            WHERE status = 'active'
        """).fetchall()
    
    def get_vulnerabilities(self):
        """Query Sentinel replica"""
        return db.execute("""
            SELECT * FROM sentinel_replica.vulnerabilities
            WHERE severity IN ('critical', 'high')
        """).fetchall()
    
    def get_machines(self):
        """Query CyberSheppard native tables"""
        return db.execute("""
            SELECT * FROM public.machines
            WHERE status = 'active'
        """).fetchall()
    
    def get_iocs(self):
        """Query Intellidog native tables"""
        return db.execute("""
            SELECT * FROM intellidog.intellidog_iocs
            WHERE is_active = TRUE
        """).fetchall()
```

**User Used**: `vlnman` (from `.env`, password: DogNET)

**NO `intellirep`**: That user is only for PostgreSQL replication subsystem, not for application code.

---

## Correlation Engine

### How It Works

```python
# backend/app/modules/intellidog/services/correlation_engine.py

class CorrelationEngine:
    """
    Correlates IOCs with Firedog and Sentinel data to detect threats.
    Runs every 5 minutes via Celery task.
    """
    
    def run_correlation(self):
        # 1. Get active IOCs
        iocs = self.get_active_iocs()
        
        # 2. Get recent firewall logs
        firewall_logs = self.get_recent_firewall_logs()
        
        # 3. Get active vulnerabilities
        vulnerabilities = self.get_active_vulnerabilities()
        
        # 4. Correlate IOCs with firewall
        for ioc in iocs:
            if ioc.type == 'ip':
                matches = self.match_ip_in_firewall(ioc, firewall_logs)
                for match in matches:
                    self.create_detection(ioc, match)
        
        # 5. Correlate IOCs with vulnerabilities
        for ioc in iocs:
            if ioc.type == 'cve':
                matches = self.match_cve_in_vulnerabilities(ioc, vulnerabilities)
                for match in matches:
                    self.create_detection(ioc, match)
        
        # 6. Generate virtual patches for critical detections
        self.generate_virtual_patches()
```

**Runs**: Every 5 minutes (configurable in Settings)

---

## Uninstalling Intellidog

### Deactivation Process

```
Settings → Plugins → Intellidog → Deactivate

[Confirmation Dialog]

⚠️  Deactivating Intellidog will:
  • Remove "Threat Intelligence" menu
  • Stop all correlation jobs
  • Stop feed updates
  • Keep all data in database (not deleted)

To fully remove data, use "Uninstall" instead.

[Deactivate]  [Cancel]
```

### Full Uninstall

```
Settings → Plugins → Intellidog → Uninstall

[Confirmation Dialog]

🚨 WARNING: This will permanently delete:
  • All threat intelligence feeds
  • All IOCs (12,456 indicators)
  • All detections (234 detections)
  • All virtual patches
  • All hunting queries
  • License information

Replication data (firedog_replica, sentinel_replica) will NOT be deleted.

Type "DELETE INTELLIDOG" to confirm: ___________

[Uninstall]  [Cancel]
```

**Result**: `intellidog` schema and all tables dropped.

---

## License Renewal

### Checking License Status

```
Settings → Plugins → Intellidog → License

[License Information]

Status: ✅ Active
Customer: ACME Corporation
License Key: INTL-XXXX-XXXX-XXXX-XXXX
Issued: 2025-01-01
Expires: 2026-01-01 (364 days remaining)

Usage:
  Machines: 45 / 100 (45% used)
  
Features:
  ✅ Threat Intelligence Feeds
  ✅ Correlation Engine
  ✅ Virtual Patching
  ✅ Threat Hunting
  ✅ Executive Dashboards

Support Level: Enterprise
Support Contact: support@dognet.tech

[Renew License]  [Update License]
```

### License Expiration Warning

**30 days before expiration**:
```
⚠️  License Warning

Your Intellidog license will expire in 30 days (2026-01-01).

Contact licensing@dognet.tech to renew.

[Dismiss]  [Contact Sales]
```

**After expiration**:
```
🚨 License Expired

Your Intellidog license expired on 2026-01-01.

Module is now in read-only mode:
  ✅ View existing data
  ❌ Feed updates disabled
  ❌ Correlation engine disabled
  ❌ Virtual patching disabled

Contact licensing@dognet.tech to renew immediately.

[Upload New License]  [Contact Sales]
```

---

## Support & Troubleshooting

### Common Issues

**Issue**: "License validation failed"

**Solution**:
1. Verify `.lic` file is not corrupted (re-download from email)
2. Check system date/time is correct
3. Contact licensing@dognet.tech for re-issue

**Issue**: "No detections appearing"

**Solution**:
1. Verify replication is active:
   ```sql
   SELECT * FROM pg_stat_subscription;
   ```
2. Check correlation job is running:
   ```bash
   systemctl status cybersheppard-celery
   ```
3. Verify IOCs loaded:
   ```sql
   SELECT COUNT(*) FROM intellidog.intellidog_iocs;
   ```

**Issue**: "Virtual patches not deploying to Firedog"

**Solution**:
1. Check Firedog API key in Settings → Orchestration
2. Test Firedog API connectivity:
   ```bash
   curl -H "X-API-Key: <key>" http://192.168.1.50:8000/api/rules
   ```
3. Check Intellidog logs:
   ```bash
   tail -f /var/log/cybersheppard/intellidog.log
   ```

---

## Next Steps

After activating Intellidog:

1. ✅ **Configure Threat Feeds**
   - Add MISP, OTX, or custom feeds
   - Configure update intervals

2. ✅ **Review Detections**
   - Triage critical detections
   - Approve virtual patches

3. ✅ **Create Hunting Queries**
   - Build custom threat hunting queries
   - Schedule automated runs

4. ✅ **Integrate with Alerts**
   - Configure email/Slack alerts for critical detections

5. ✅ **Explore Database Architecture**
   - See: `DATABASE_ARCHITECTURE.md`

---

## Summary

**What You've Activated**:
- ✅ Intellidog Module installed and licensed
- ✅ Threat intelligence feeds active
- ✅ Correlation engine running
- ✅ Virtual patching ready
- ✅ New "Threat Intelligence" menu available

**Database State**:
```
CyberSheppard PostgreSQL
├─ Schema: public (CyberSheppard tables)
├─ Schema: firedog_replica (from Firedog)
├─ Schema: sentinel_replica (from Sentinel)
└─ Schema: intellidog (Intellidog tables) ← NEW!
```

**Access**:
- User: `vlnman`
- Password: `DogNET` (from `.env`)
- All schemas accessible with SELECT permission

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-12-31  
**Author**: Dognet Technologies
