# Replication Plugins Installation Guide

## Overview

This guide explains how to install and activate the three **Replication Plugins** that enable PostgreSQL logical replication between Firedog, Sentinel Core, and CyberSheppard for Intellidog threat intelligence.

**Prerequisites**:
- ✅ Orchestration configured on all three tools (see `ORCHESTRATION_SETUP.md`)
- ✅ PostgreSQL 12+ on all systems
- ✅ Network connectivity verified

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│                   Replication Flow                              │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Firedog (Publisher)                                           │
│  ├─ Plugin: "Firedog Replication Plugin"                       │
│  ├─ Creates: User intellirep                                   │
│  ├─ Creates: Publication firedog_to_intellidog                 │
│  └─ Updates: pg_hba.conf (allow CyberSheppard)                 │
│         │                                                       │
│         │ Async Replication                                    │
│         ▼                                                       │
│  CyberSheppard (Subscriber)                                    │
│  ├─ Plugin: "CyberSheppard Replication Plugin"                 │
│  ├─ Creates: Schema firedog_replica                            │
│  └─ Creates: Subscription firedog_sub                          │
│                                                                 │
│  Sentinel (Publisher)                                          │
│  ├─ Plugin: "Sentinel Replication Plugin"                      │
│  ├─ Creates: User intellirep                                   │
│  ├─ Creates: Publication sentinel_to_intellidog                │
│  └─ Updates: pg_hba.conf (allow CyberSheppard)                 │
│         │                                                       │
│         │ Async Replication                                    │
│         ▼                                                       │
│  CyberSheppard (Subscriber)                                    │
│  ├─ Creates: Schema sentinel_replica                           │
│  └─ Creates: Subscription sentinel_sub                         │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

---

## Plugin 1: Firedog Replication Plugin

### 1.1 Access Plugin Manager

```
Firedog UI → Settings → Plugins
```

### 1.2 Locate Plugin

```
[Available Plugins Tab]

┌──────────────────────────────────────────────────────┐
│ Firedog Replication Plugin                           │
├──────────────────────────────────────────────────────┤
│ Version: 1.0.0                                       │
│ Author: Dognet Technologies                          │
│ Category: Replication                                │
│                                                      │
│ Description:                                         │
│ Configure PostgreSQL logical replication from       │
│ Firedog to CyberSheppard for Intellidog threat      │
│ intelligence integration.                            │
│                                                      │
│ [Attiva]                                             │
└──────────────────────────────────────────────────────┘
```

### 1.3 Click "Attiva"

**Installation Process** (automatic):

```
[Installation Dialog]

Installing Firedog Replication Plugin...

✅ Downloading plugin from GitHub
✅ Verifying SHA256 checksum
✅ Extracting plugin files
▶️  Running installation script...

[Log Output]
============================================================
Firedog Replication Plugin - Installation
============================================================

Reading orchestration settings...
✅ CyberSheppard IP: 192.168.1.100
✅ CyberSheppard API Key: cyber_***

Creating PostgreSQL replication user...
✅ User 'intellirep' created
✅ Password: <cybersheppard_api_key>
✅ REPLICATION privilege granted

Creating publication...
✅ Publication 'firedog_to_intellidog' created
✅ Tables: firewall_rules, machines, rule_stats, rule_logs

Updating pg_hba.conf...
✅ Added: host replication intellirep 192.168.1.100/32 scram-sha-256

Reloading PostgreSQL...
✅ PostgreSQL reloaded

============================================================
Installation Complete!
============================================================

Next step: Install CyberSheppard Replication Plugin
```

### 1.4 Verify Installation

**Check plugin status**:
```
Settings → Plugins → Installed Plugins

[Installed]
├─ Firedog Replication Plugin
│  ├─ Status: ✅ Active
│  ├─ Version: 1.0.0
│  └─ Last run: Just now
```

**Verify PostgreSQL user**:
```bash
# SSH to Firedog
ssh admin@192.168.1.50

# Check user exists
sudo -u postgres psql -c "\du intellirep"

# Expected output:
#                 List of roles
# Role name  | Attributes      | Member of
#------------+-----------------+-----------
# intellirep | Replication     | {}
```

**Verify publication**:
```bash
sudo -u postgres psql -d firedog -c "\dRp"

# Expected output:
#           Publication firedog_to_intellidog
# Owner | All tables | Inserts | Updates | Deletes | Truncates
#-------+------------+---------+---------+---------+-----------
# ...   | f          | t       | t       | t       | t
```

---

## Plugin 2: Sentinel Replication Plugin

### 2.1 Access Plugin Manager

```
Sentinel UI → Settings → Plugins
```

### 2.2 Locate Plugin

```
[Available Plugins Tab]

┌──────────────────────────────────────────────────────┐
│ Sentinel Replication Plugin                          │
├──────────────────────────────────────────────────────┤
│ Version: 1.0.0                                       │
│ Author: Dognet Technologies                          │
│ Category: Replication                                │
│                                                      │
│ Description:                                         │
│ Configure PostgreSQL logical replication from       │
│ Sentinel Core to CyberSheppard for Intellidog       │
│ threat intelligence integration.                     │
│                                                      │
│ [Attiva]                                             │
└──────────────────────────────────────────────────────┘
```

### 2.3 Click "Attiva"

**Installation Process** (automatic):

```
[Installation Dialog]

Installing Sentinel Replication Plugin...

✅ Downloading plugin from GitHub
✅ Verifying SHA256 checksum
✅ Extracting plugin files
▶️  Running installation script...

[Log Output]
============================================================
Sentinel Replication Plugin - Installation
============================================================

Reading orchestration settings...
✅ CyberSheppard IP: 192.168.1.100
✅ CyberSheppard API Key: cyber_***

Creating PostgreSQL replication user...
✅ User 'intellirep' created
✅ Password: <cybersheppard_api_key>
✅ REPLICATION privilege granted

Creating publication...
✅ Publication 'sentinel_to_intellidog' created
✅ Tables: vulnerabilities, cves, machines, scan_results
✅ Optional tables (if exist): epss_scores, cve_exploits

Updating pg_hba.conf...
✅ Added: host replication intellirep 192.168.1.100/32 scram-sha-256

Reloading PostgreSQL...
✅ PostgreSQL reloaded

============================================================
Installation Complete!
============================================================

Next step: Install CyberSheppard Replication Plugin
```

### 2.4 Verify Installation

**Verify publication**:
```bash
# SSH to Sentinel
ssh admin@192.168.1.51

sudo -u postgres psql -d sentinel -c "\dRp"

# Expected output shows sentinel_to_intellidog publication
```

---

## Plugin 3: CyberSheppard Replication Plugin

### 3.1 Access Plugin Manager

```
CyberSheppard UI → Settings → Plugins
```

### 3.2 Locate Plugin

```
[Available Plugins Tab]

┌──────────────────────────────────────────────────────┐
│ CyberSheppard Replication Plugin                     │
├──────────────────────────────────────────────────────┤
│ Version: 1.0.0                                       │
│ Author: Dognet Technologies                          │
│ Category: Replication                                │
│                                                      │
│ Description:                                         │
│ Configure CyberSheppard as PostgreSQL replication   │
│ subscriber from Firedog and Sentinel Core.          │
│                                                      │
│ Requires: Firedog and Sentinel plugins installed    │
│                                                      │
│ [Attiva]                                             │
└──────────────────────────────────────────────────────┘
```

### 3.3 Click "Attiva"

**Installation Process** (automatic):

```
[Installation Dialog]

Installing CyberSheppard Replication Plugin...

✅ Downloading plugin from GitHub
✅ Verifying SHA256 checksum
✅ Extracting plugin files
▶️  Running installation script...

[Log Output]
============================================================
CyberSheppard Replication Plugin - Installation
============================================================

Checking prerequisites...
✅ Firedog configured in orchestration
✅ Sentinel configured in orchestration
✅ PostgreSQL logical replication enabled (wal_level=logical)

Creating replica schemas...
✅ Schema 'firedog_replica' created
✅ Schema 'sentinel_replica' created

Creating subscription to Firedog...
Connection: host=192.168.1.50 dbname=firedog user=intellirep password=***
✅ Subscription 'firedog_sub' created
✅ Replication slot 'firedog_sub' created on source
▶️  Initial sync started (this may take several minutes)...

Creating subscription to Sentinel...
Connection: host=192.168.1.51 dbname=sentinel user=intellirep password=***
✅ Subscription 'sentinel_sub' created
✅ Replication slot 'sentinel_sub' created on source
▶️  Initial sync started (this may take several minutes)...

Waiting for initial sync to complete...
[Progress bar showing table sync status]

firedog_replica.firewall_rules    ████████████ 100% (1,234 rows)
firedog_replica.machines          ████████████ 100% (45 rows)
firedog_replica.rule_stats        ████████████ 100% (5,678 rows)
firedog_replica.rule_logs         ████████████ 100% (12,345 rows)

sentinel_replica.vulnerabilities  ████████████ 100% (8,901 rows)
sentinel_replica.cves             ████████████ 100% (15,234 rows)
sentinel_replica.machines         ████████████ 100% (45 rows)
sentinel_replica.scan_results     ████████████ 100% (3,456 rows)

✅ Initial sync complete!

Creating monitoring views...
✅ View 'intellidog_replication_status' created
✅ Function 'check_replication_health()' created

Granting permissions to vlnman...
✅ vlnman granted SELECT on firedog_replica schema
✅ vlnman granted SELECT on sentinel_replica schema

============================================================
Installation Complete!
============================================================

Replication is now active and streaming changes from:
  • Firedog (192.168.1.50)
  • Sentinel Core (192.168.1.51)

Monitor replication:
  Settings → Plugins → CyberSheppard Replication → Monitor

or via SQL:
  SELECT * FROM intellidog_replication_status;
```

### 3.4 Monitor Replication Status

**Via UI**:
```
Settings → Plugins → CyberSheppard Replication Plugin → Monitor

[Replication Status Dashboard]

Firedog Subscription (firedog_sub)
├─ Status: ✅ Active
├─ Replication Lag: 0.32 seconds
├─ Tables Replicated: 4
├─ Last Sync: 2 seconds ago
└─ Worker PID: 12345

Sentinel Subscription (sentinel_sub)
├─ Status: ✅ Active
├─ Replication Lag: 0.18 seconds
├─ Tables Replicated: 6
├─ Last Sync: 1 second ago
└─ Worker PID: 12346

[Refresh Status]
```

**Via SQL**:
```sql
-- Connect to CyberSheppard database
psql -U vlnman -d cybersheppard -W

-- Password: DogNET

-- Check replication status
SELECT * FROM intellidog_replication_status;

-- Expected output:
-- subscription_name | enabled | pid   | lag_seconds | status
-- ------------------+---------+-------+-------------+--------
-- firedog_sub       | t       | 12345 | 0.32        | active
-- sentinel_sub      | t       | 12346 | 0.18        | active
```

---

## Verification & Testing

### Test 1: Verify Replicated Data

```sql
-- On CyberSheppard
psql -U vlnman -d cybersheppard

-- Check Firedog replica
SELECT COUNT(*) FROM firedog_replica.firewall_rules;
SELECT COUNT(*) FROM firedog_replica.machines;

-- Check Sentinel replica
SELECT COUNT(*) FROM sentinel_replica.vulnerabilities;
SELECT COUNT(*) FROM sentinel_replica.cves;

-- Verify data is recent
SELECT MAX(updated_at) FROM firedog_replica.firewall_rules;
SELECT MAX(created_at) FROM sentinel_replica.vulnerabilities;
```

### Test 2: Real-time Replication

**On Firedog**:
```sql
-- Insert a test rule
INSERT INTO firewall_rules (name, action, protocol, port, created_at)
VALUES ('test-intellidog-replication', 'ACCEPT', 'tcp', 9999, NOW());
```

**On CyberSheppard** (wait ~1 second):
```sql
-- Verify it replicated
SELECT * FROM firedog_replica.firewall_rules 
WHERE name = 'test-intellidog-replication';

-- Should return the inserted row within seconds!
```

### Test 3: Check Replication Lag

```sql
-- On CyberSheppard
SELECT 
    subname,
    EXTRACT(EPOCH FROM (NOW() - latest_end_time)) as lag_seconds
FROM pg_stat_subscription;

-- Expected: lag_seconds < 5 (good performance)
-- Warning if: lag_seconds > 30
-- Critical if: lag_seconds > 300
```

---

## Troubleshooting

### Issue: Subscription Not Active

**Symptom**: `SELECT * FROM pg_stat_subscription;` shows `pid` is NULL

**Checks**:
```sql
-- Check subscription status
SELECT subname, subenabled FROM pg_subscription;

-- Check for errors in logs
sudo tail -f /var/log/postgresql/postgresql-*.log | grep intellidog
```

**Solutions**:
1. Verify pg_hba.conf allows connection from CyberSheppard
2. Test network connectivity:
   ```bash
   psql "host=192.168.1.50 port=5432 dbname=firedog user=intellirep password=<api_key>"
   ```
3. Check if publication exists on source:
   ```bash
   # On Firedog
   sudo -u postgres psql -d firedog -c "\dRp"
   ```

### Issue: High Replication Lag

**Symptom**: Lag > 30 seconds consistently

**Checks**:
```sql
-- Check WAL sender activity on source
-- On Firedog/Sentinel
SELECT * FROM pg_stat_replication;

-- Check network bandwidth
iftop -i eth0
```

**Solutions**:
1. Increase `max_wal_senders` on source:
   ```sql
   ALTER SYSTEM SET max_wal_senders = 10;
   SELECT pg_reload_conf();
   ```
2. Increase `max_replication_slots`:
   ```sql
   ALTER SYSTEM SET max_replication_slots = 10;
   ```
3. Check disk I/O on subscriber (CyberSheppard)

### Issue: Initial Sync Stuck

**Symptom**: Tables show 0% progress for >10 minutes

**Checks**:
```sql
-- Check table sync status
SELECT * FROM pg_subscription_rel;
```

**Solutions**:
1. Drop and recreate subscription:
   ```sql
   DROP SUBSCRIPTION firedog_sub;
   -- Re-run plugin installation
   ```
2. Check PostgreSQL logs for errors
3. Verify source tables are not locked

### Issue: Permission Denied

**Symptom**: `ERROR: permission denied for schema firedog_replica`

**Solution**:
```sql
-- Grant permissions to vlnman
GRANT USAGE ON SCHEMA firedog_replica TO vlnman;
GRANT SELECT ON ALL TABLES IN SCHEMA firedog_replica TO vlnman;

GRANT USAGE ON SCHEMA sentinel_replica TO vlnman;
GRANT SELECT ON ALL TABLES IN SCHEMA sentinel_replica TO vlnman;
```

---

## Performance Tuning

### Optimize for Low Latency

```sql
-- On CyberSheppard
ALTER SUBSCRIPTION firedog_sub SET (synchronous_commit = off);
ALTER SUBSCRIPTION sentinel_sub SET (synchronous_commit = off);
```

**Effect**: Reduces lag from ~500ms to ~100ms, but increases risk of data loss in crash.

### Optimize for High Throughput

```sql
-- Increase parallel workers
ALTER SYSTEM SET max_sync_workers_per_subscription = 4;
SELECT pg_reload_conf();
```

**Effect**: Faster initial sync, but higher CPU usage.

### Disk Space Management

```sql
-- Monitor replication slot disk usage
SELECT 
    slot_name,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) as replication_lag_bytes
FROM pg_replication_slots;

-- If lag_bytes > 10GB, investigate subscriber lag
```

---

## Uninstalling Plugins

### Uninstall CyberSheppard Plugin

```
Settings → Plugins → CyberSheppard Replication → Uninstall

[Confirmation Dialog]
⚠️  This will:
  • Drop subscriptions (firedog_sub, sentinel_sub)
  • Drop schemas (firedog_replica, sentinel_replica)
  • Remove all replicated data

Type "CONFIRM" to proceed: ___________

[Uninstall]  [Cancel]
```

**Result**: Subscriptions and schemas removed, replication stopped.

### Uninstall Firedog/Sentinel Plugins

```
[On Firedog]
Settings → Plugins → Firedog Replication → Uninstall

⚠️  This will:
  • Drop publication (firedog_to_intellidog)
  • Drop user (intellirep)
  • Revert pg_hba.conf changes

[Uninstall]
```

---

## Next Steps

After successful replication setup:

1. ✅ **Activate Intellidog Module**
   - See: `INTELLIDOG_MODULE.md`

2. ✅ **Explore Database Architecture**
   - See: `DATABASE_ARCHITECTURE.md`

3. ✅ **Monitor Replication Health**
   - Use built-in monitoring dashboard
   - Setup alerts for high lag

---

## Summary

**What You've Installed**:
- ✅ Firedog Replication Plugin → Creates publication on Firedog
- ✅ Sentinel Replication Plugin → Creates publication on Sentinel
- ✅ CyberSheppard Replication Plugin → Creates subscriptions on CyberSheppard

**What's Happening Now**:
- 📊 Firedog tables streaming to `firedog_replica` schema
- 📊 Sentinel tables streaming to `sentinel_replica` schema
- ⚡ Real-time replication (<1 second lag)
- 🔒 Secure (encrypted API key authentication)

**Database State**:
```
CyberSheppard PostgreSQL
├─ Schema: public (CyberSheppard native tables)
├─ Schema: firedog_replica (replicated from Firedog)
├─ Schema: sentinel_replica (replicated from Sentinel)
└─ Ready for: Intellidog schema (next step!)
```

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-12-31  
**Author**: Dognet Technologies
