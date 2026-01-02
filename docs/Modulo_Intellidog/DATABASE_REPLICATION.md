# Database Replication Setup Guide

**Version**: 1.0.0  
**Last Updated**: 2025-01-15  
**Author**: Dognet Technologies  
**Audience**: System Administrators

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Plugin-Based Setup](#plugin-based-setup)
5. [Manual Setup (Advanced)](#manual-setup-advanced)
6. [Monitoring & Troubleshooting](#monitoring--troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup & Disaster Recovery](#backup--disaster-recovery)

---

## Overview

### What is Database Replication?

Intellidog uses **PostgreSQL Logical Replication** to synchronize data from Firedog and Sentinel Core databases in real-time. This provides:

- ✅ **Zero API overhead**: Local queries instead of remote API calls
- ✅ **Sub-second latency**: Typical lag <500ms
- ✅ **Offline resilience**: Intellidog works even if source systems are down
- ✅ **Complex joins**: Native SQL joins across replicated data
- ✅ **Scalability**: No API rate limits

### Why Replication Instead of API?

| Approach | Latency | Availability | Join Support | Rate Limits |
|----------|---------|--------------|--------------|-------------|
| **API Queries** | 50-200ms | Requires source online | No (multiple requests) | Yes (1000/day typical) |
| **Database Replication** | <1ms | Works offline | Yes (native SQL) | No |

**Performance Example**:
```sql
-- API approach (3 separate requests, 150ms total)
GET /api/firedog/machines/{id}          -- 50ms
GET /api/sentinel/vulnerabilities/{id}  -- 50ms  
GET /api/microsiem/detections/{id}      -- 50ms

-- Replication approach (single query, 5ms)
SELECT * FROM intellidog_detections d
JOIN sentinel_replica.vulnerabilities v ON d.cve_id = v.cve_id
JOIN firedog_replica.machines m ON d.machine_id = m.id
WHERE d.id = 123;
-- Query time: 5ms
```

---

## Architecture

### Replication Topology

```
┌─────────────────────────────────────────────────────────────────┐
│ LOGICAL REPLICATION ARCHITECTURE                                │
└─────────────────────────────────────────────────────────────────┘

     SOURCE DATABASES                   SUBSCRIBER DATABASE
     (Publishers)                       (Intellidog)

┌──────────────────────┐
│ Firedog PostgreSQL   │
│ Database: firedog    │               ┌────────────────────────┐
│ Port: 5432           │               │ Intellidog PostgreSQL  │
├──────────────────────┤               │ Database: microsiem    │
│ Publication:         │──────────────▶│ (or intellidog)        │
│ firedog_to_intellidog│   Async       ├────────────────────────┤
│                      │   Streaming   │                        │
│ Tables:              │               │ Schema:                │
│ • firewall_rules     │               │ firedog_replica        │
│ • machines           │               │ ├─ firewall_rules      │
│ • rule_stats         │               │ ├─ machines            │
│ • rule_logs          │               │ └─ rule_stats          │
└──────────────────────┘               │                        │
                                       │                        │
┌──────────────────────┐               │ Schema:                │
│ Sentinel PostgreSQL  │               │ sentinel_replica       │
│ Database: sentinel   │               │ ├─ vulnerabilities     │
│ Port: 5432           │               │ ├─ cves                │
├──────────────────────┤               │ ├─ machines            │
│ Publication:         │──────────────▶│ ├─ scan_results        │
│ sentinel_to_intellidog│  Async       │ └─ epss_scores         │
│                      │   Streaming   │                        │
│ Tables:              │               │ Subscription Status:   │
│ • vulnerabilities    │               │ ├─ firedog_sub: ACTIVE │
│ • cves               │               │ └─ sentinel_sub: ACTIVE│
│ • machines           │               │                        │
│ • scan_results       │               │ Replication Lag:       │
│ • epss_scores        │               │ ├─ Firedog: 0.3s       │
└──────────────────────┘               │ └─ Sentinel: 0.5s      │
                                       └────────────────────────┘
```

### Data Flow

```
[Source DB] → Write to table
     ↓
[WAL (Write-Ahead Log)] → Changes recorded
     ↓
[Logical Decoding] → Convert WAL to logical changes
     ↓
[Replication Slot] → Stream changes to subscriber
     ↓
[Network] → SSL/TLS encrypted transfer
     ↓
[Subscriber] → Apply changes to replica tables
     ↓
[Intellidog Queries] → Read from local replica (<5ms)
```

**Key Concepts**:
- **Publication**: List of tables to replicate (defined on source)
- **Subscription**: Connection to publication (defined on subscriber)
- **Replication Slot**: Persistent stream position (prevents data loss)
- **WAL Level**: Must be `logical` (not `replica` or `minimal`)

---

## Prerequisites

### System Requirements

**Source Databases (Firedog & Sentinel Core)**:
- PostgreSQL 12.0 or higher
- `wal_level = logical` (requires PostgreSQL restart)
- Sufficient disk space for WAL retention (~10-20GB recommended)
- Network connectivity to Intellidog server (port 5432)
- Superuser access (for initial setup only)

**Subscriber Database (Intellidog/MicroSIEM)**:
- PostgreSQL 12.0 or higher
- Network connectivity to source databases
- Disk space for replicated data (~50% of source database size)
- Replication credentials from source systems

### Network Requirements

**Firewall Rules**:
```bash
# On Firedog server
sudo ufw allow from <INTELLIDOG_IP> to any port 5432 proto tcp comment "PostgreSQL replication from Intellidog"

# On Sentinel Core server
sudo ufw allow from <INTELLIDOG_IP> to any port 5432 proto tcp comment "PostgreSQL replication from Intellidog"

# Verify connectivity from Intellidog server
telnet firedog-server 5432
telnet sentinel-server 5432
```

**DNS Resolution** (optional but recommended):
```bash
# Add to /etc/hosts on Intellidog server
192.168.1.50  firedog-db
192.168.1.51  sentinel-db
```

### Pre-Installation Checklist

- [ ] PostgreSQL 12+ installed on all systems
- [ ] Network connectivity verified (Intellidog → Firedog, Sentinel)
- [ ] Superuser access to all PostgreSQL instances
- [ ] ~20GB free disk space on source databases (WAL retention)
- [ ] ~50GB free disk space on Intellidog (replicated data)
- [ ] Backup of all databases completed
- [ ] Maintenance window scheduled (PostgreSQL restart required on sources)

---

## Plugin-Based Setup

### Overview

The **recommended** approach uses dedicated replication plugins that automate the setup process:

1. **firedog-replication-plugin** (install on Firedog server)
2. **sentinelcore-replication-plugin** (install on Sentinel Core server)
3. **cybersheppard-replication-plugin** (install on Intellidog/MicroSIEM server)

### Step 1: Install Firedog Replication Plugin

**On Firedog Server**:

```bash
# Navigate to Firedog plugins directory
cd /opt/firedog/plugins

# Download plugin (or use plugin manager)
sudo ./plugin-manager install firedog-replication-plugin

# Verify plugin installed
ls -la /opt/firedog/plugins/firedog-replication-plugin

# Expected output:
# drwxr-xr-x 5 firedog firedog 4096 Jan 15 10:00 firedog-replication-plugin
```

**Run Installation Script**:

```bash
cd /opt/firedog/plugins/firedog-replication-plugin
sudo ./scripts/install.sh
```

**Installation Wizard Output**:

```
=====================================================================
 Firedog Replication Plugin - Installation
=====================================================================

[1/8] Checking prerequisites...
✅ PostgreSQL version: 14.2 (meets requirement 12+)
✅ Running as postgres user

[2/8] Configuration...
Enter Intellidog server IP address: 192.168.1.100
✅ IP address validated

[3/8] Generating replication credentials...
✅ Replication password generated: [hidden]

[4/8] Checking PostgreSQL configuration...
⚠️  WARNING: wal_level is currently 'replica' (needs 'logical')
Setting wal_level to 'logical'...
✅ Configuration updated

⚠️  IMPORTANT: PostgreSQL restart required!
   Run: sudo systemctl restart postgresql

Press Enter after restarting PostgreSQL...
```

**Restart PostgreSQL**:

```bash
# In another terminal
sudo systemctl restart postgresql

# Wait for PostgreSQL to come back up
sudo systemctl status postgresql

# Press Enter in installation wizard terminal
```

**Wizard Continues**:

```
[5/8] Creating publication and replication user...
✅ Replication user 'firedog_replication' created
✅ Publication 'firedog_to_intellidog' created
✅ Tables added to publication:
   • firewall_rules
   • machines
   • rule_stats
   • rule_logs

[6/8] Updating pg_hba.conf...
✅ Backup created: /var/lib/postgresql/data/pg_hba.conf.backup.20250115_100530
✅ Replication access granted to 192.168.1.100

[7/8] Reloading PostgreSQL configuration...
✅ Configuration reloaded

[8/8] Verifying setup...
✅ Publication created successfully
✅ Replication slot ready

=====================================================================
 Installation Complete!
=====================================================================

Credentials saved to: /opt/firedog/plugins/firedog-replication-plugin/credentials.txt

Next steps:
  1. Securely share credentials with Intellidog administrator
  2. Verify connection from Intellidog server:
     psql 'postgresql://firedog_replication:***@192.168.1.50:5432/firedog'
  3. Configure Intellidog subscription (see Intellidog documentation)

To uninstall: /opt/firedog/plugins/firedog-replication-plugin/scripts/uninstall.sh
```

**Retrieve Credentials**:

```bash
# View credentials (secure file, 600 permissions)
sudo cat /opt/firedog/plugins/firedog-replication-plugin/credentials.txt
```

**Example credentials.txt**:

```
# Firedog Replication Credentials
# ================================
# Created: 2025-01-15 10:05:30

Share these credentials with Intellidog administrator:

Replication User: firedog_replication
Replication Password: xK9mP3nQ8vL2wR7tY5jH1sF4dG6aB0cE
Database Host: 192.168.1.50
Database Port: 5432
Database Name: firedog
Publication Name: firedog_to_intellidog

Connection string for Intellidog subscription:
postgresql://firedog_replication:xK9mP3nQ8vL2wR7tY5jH1sF4dG6aB0cE@192.168.1.50:5432/firedog
```

**⚠️ Security**: Securely transfer credentials to Intellidog administrator (encrypted email, password manager, etc.)

---

### Step 2: Install Sentinel Core Replication Plugin

**On Sentinel Core Server**:

```bash
cd /opt/sentinel/plugins
sudo ./plugin-manager install sentinelcore-replication-plugin
cd /opt/sentinel/plugins/sentinelcore-replication-plugin
sudo ./scripts/install.sh
```

**Process is identical to Firedog plugin** (substitute "Sentinel" for "Firedog" in wizard prompts).

**Expected Credentials Output**:

```
Replication User: sentinel_replication
Replication Password: aB8cD4eF9gH2iJ6kL1mN5oP7qR3sT0uV
Database Host: 192.168.1.51
Database Port: 5432
Database Name: sentinel
Publication Name: sentinel_to_intellidog

Connection string:
postgresql://sentinel_replication:aB8cD4eF9gH2iJ6kL1mN5oP7qR3sT0uV@192.168.1.51:5432/sentinel
```

---

### Step 3: Configure Intellidog Subscription

**On Intellidog/MicroSIEM Server**:

```bash
cd /opt/microsiem/plugins
sudo ./plugin-manager install cybersheppard-replication-plugin
cd /opt/microsiem/plugins/cybersheppard-replication-plugin
sudo ./scripts/configure_subscription.py
```

**Interactive Configuration Wizard**:

```
======================================================================
 CyberSheppard Replication Plugin - Subscription Configuration
======================================================================

[1/2] Firedog Configuration
----------------------------------------------------------------------
Configure Firedog replication? (y/n): y

  Firedog PostgreSQL host: 192.168.1.50
  Firedog PostgreSQL port [5432]: 
  Firedog database name [firedog]: 
  Replication user [firedog_replication]: 
  Replication password: [paste from credentials.txt]
  
  Testing connection... ✅ Success

[2/2] Sentinel Core Configuration
----------------------------------------------------------------------
Configure Sentinel Core replication? (y/n): y

  Sentinel PostgreSQL host: 192.168.1.51
  Sentinel PostgreSQL port [5432]: 
  Sentinel database name [sentinel]: 
  Replication user [sentinel_replication]: 
  Replication password: [paste from credentials.txt]
  
  Testing connection... ✅ Success

======================================================================
 Creating Subscriptions
======================================================================

Enter local PostgreSQL password (postgres user): [your_local_password]

Creating subscription for firedog...
  ✅ Subscription 'firedog_sub' created

Creating subscription for sentinel_core...
  ✅ Subscription 'sentinel_sub' created

======================================================================
 Configuration Complete!
======================================================================

Initial data sync is in progress.
This may take several minutes depending on database size.

Monitor replication status:
  psql -d microsiem -c 'SELECT * FROM intellidog_replication_status;'

To test replication:
  ./scripts/test_replication.py
```

**Monitor Initial Sync**:

```bash
# Watch replication status (updates every 5 seconds)
watch -n 5 "psql -d microsiem -c 'SELECT * FROM intellidog_replication_status;'"
```

**Expected Output**:

```
 subscription_name | enabled | pid   | latest_end_time          | status
-------------------+---------+-------+--------------------------+--------
 firedog_sub       | t       | 12345 | 2025-01-15 10:15:23.456  | active
 sentinel_sub      | t       | 12346 | 2025-01-15 10:15:24.123  | active
(2 rows)
```

**Verify Data Replicated**:

```bash
cd /opt/microsiem/plugins/cybersheppard-replication-plugin
sudo ./scripts/test_replication.py
```

**Test Output**:

```
======================================================================
 Testing Replication Status
======================================================================

[1/3] Subscription Status
----------------------------------------------------------------------
  firedog_sub:
    Enabled: True
    Status: active
    PID: 12345
    Last update: 2025-01-15 10:15:23.456

  sentinel_sub:
    Enabled: True
    Status: active
    PID: 12346
    Last update: 2025-01-15 10:15:24.123

[2/3] Replicated Tables
----------------------------------------------------------------------

  firedog_replica:
    firewall_rules: 1,247 rows
    machines: 50 rows
    rule_stats: 15,392 rows

  sentinel_replica:
    vulnerabilities: 892 rows
    cves: 23,456 rows
    machines: 50 rows
    scan_results: 3,421 rows

[3/3] Replication Lag
----------------------------------------------------------------------
  firedog_sub: 0.32 seconds
  sentinel_sub: 0.51 seconds

======================================================================
 Test Complete
======================================================================

✅ All subscriptions active
✅ Data replicated successfully
✅ Replication lag within acceptable range (<1s)
```

---

## Manual Setup (Advanced)

For system administrators who prefer manual configuration or need custom setup.

### Step 1: Configure Source Database (Firedog)

**1.1. Enable Logical Replication**:

```bash
# Edit postgresql.conf
sudo nano /var/lib/postgresql/data/postgresql.conf

# Add/modify these parameters
wal_level = logical
max_replication_slots = 10
max_wal_senders = 10
```

**1.2. Restart PostgreSQL**:

```bash
sudo systemctl restart postgresql
sudo systemctl status postgresql
```

**1.3. Create Replication User**:

```sql
-- Connect as superuser
sudo -u postgres psql -d firedog

-- Create replication role
CREATE ROLE firedog_replication WITH REPLICATION LOGIN PASSWORD 'your_secure_password_here';

-- Grant SELECT on tables to replicate
GRANT SELECT ON TABLE firewall_rules TO firedog_replication;
GRANT SELECT ON TABLE machines TO firedog_replication;
GRANT SELECT ON TABLE rule_stats TO firedog_replication;
GRANT SELECT ON TABLE rule_logs TO firedog_replication;
```

**1.4. Create Publication**:

```sql
-- Drop if exists (for re-configuration)
DROP PUBLICATION IF EXISTS firedog_to_intellidog;

-- Create publication with selected tables
CREATE PUBLICATION firedog_to_intellidog FOR TABLE
    firewall_rules,
    machines,
    rule_stats,
    rule_logs;

-- Verify publication created
SELECT * FROM pg_publication WHERE pubname = 'firedog_to_intellidog';

-- Check which tables are in publication
SELECT * FROM pg_publication_tables WHERE pubname = 'firedog_to_intellidog';
```

**1.5. Configure pg_hba.conf**:

```bash
# Edit pg_hba.conf
sudo nano /var/lib/postgresql/data/pg_hba.conf

# Add these lines (replace <INTELLIDOG_IP> with actual IP)
# TYPE  DATABASE        USER                    ADDRESS                 METHOD
host    replication     firedog_replication     <INTELLIDOG_IP>/32      scram-sha-256
host    firedog         firedog_replication     <INTELLIDOG_IP>/32      scram-sha-256

# Example:
# host    replication     firedog_replication     192.168.1.100/32        scram-sha-256
# host    firedog         firedog_replication     192.168.1.100/32        scram-sha-256
```

**1.6. Reload PostgreSQL Configuration**:

```bash
sudo systemctl reload postgresql
```

**1.7. Test Connection from Intellidog**:

```bash
# On Intellidog server
psql "host=firedog-server port=5432 dbname=firedog user=firedog_replication password=your_password sslmode=prefer"

# If successful, you'll see:
# psql (14.2)
# Type "help" for help.
# firedog=>

# Test replication connection
psql "host=firedog-server port=5432 dbname=replication user=firedog_replication password=your_password replication=database sslmode=prefer"
```

---

### Step 2: Configure Subscriber Database (Intellidog)

**2.1. Create Schemas**:

```sql
-- Connect to Intellidog database
psql -d microsiem

-- Create schemas for replicated data
CREATE SCHEMA IF NOT EXISTS firedog_replica;
CREATE SCHEMA IF NOT EXISTS sentinel_replica;

-- Grant usage to application role
GRANT USAGE ON SCHEMA firedog_replica TO microsiem_app;
GRANT USAGE ON SCHEMA sentinel_replica TO microsiem_app;
```

**2.2. Create Subscription (Firedog)**:

```sql
-- Create subscription
CREATE SUBSCRIPTION firedog_sub
    CONNECTION 'host=192.168.1.50 port=5432 dbname=firedog user=firedog_replication password=your_password sslmode=require'
    PUBLICATION firedog_to_intellidog
    WITH (
        copy_data = true,           -- Copy existing data initially
        create_slot = true,         -- Create replication slot on source
        slot_name = 'intellidog_firedog_slot',
        synchronous_commit = off    -- Async replication for performance
    );

-- Verify subscription created
SELECT * FROM pg_subscription WHERE subname = 'firedog_sub';

-- Monitor initial sync progress
SELECT * FROM pg_stat_subscription WHERE subname = 'firedog_sub';
```

**2.3. Create Subscription (Sentinel Core)**:

```sql
-- Create subscription
CREATE SUBSCRIPTION sentinel_sub
    CONNECTION 'host=192.168.1.51 port=5432 dbname=sentinel user=sentinel_replication password=your_password sslmode=require'
    PUBLICATION sentinel_to_intellidog
    WITH (
        copy_data = true,
        create_slot = true,
        slot_name = 'intellidog_sentinel_slot',
        synchronous_commit = off
    );

-- Verify
SELECT * FROM pg_subscription WHERE subname = 'sentinel_sub';
```

**2.4. Wait for Initial Sync**:

```sql
-- Check sync status (run periodically)
SELECT 
    subname,
    pid,
    received_lsn,
    latest_end_lsn,
    latest_end_time
FROM pg_stat_subscription;

-- When pid is not NULL and latest_end_time is recent, sync is active
```

**2.5. Grant Permissions on Replicated Tables**:

```sql
-- After initial sync completes, grant SELECT on all replicated tables
DO $$
DECLARE
    table_name TEXT;
BEGIN
    -- Firedog replica tables
    FOR table_name IN 
        SELECT tablename FROM pg_tables 
        WHERE schemaname = 'firedog_replica'
    LOOP
        EXECUTE format('GRANT SELECT ON TABLE firedog_replica.%I TO microsiem_app', table_name);
    END LOOP;
    
    -- Sentinel replica tables
    FOR table_name IN 
        SELECT tablename FROM pg_tables 
        WHERE schemaname = 'sentinel_replica'
    LOOP
        EXECUTE format('GRANT SELECT ON TABLE sentinel_replica.%I TO microsiem_app', table_name);
    END LOOP;
END $$;
```

---

## Monitoring & Troubleshooting

### Monitoring Replication Status

**1. Subscription Status (Subscriber)**:

```sql
-- Quick status check
SELECT * FROM intellidog_replication_status;

-- Detailed status
SELECT 
    subname AS subscription_name,
    subenabled AS enabled,
    pid,
    latest_end_lsn,
    latest_end_time,
    EXTRACT(EPOCH FROM (NOW() - latest_end_time)) AS lag_seconds,
    CASE 
        WHEN pid IS NOT NULL THEN 'active'
        ELSE 'inactive'
    END AS status
FROM pg_subscription
LEFT JOIN pg_stat_subscription USING (subname)
WHERE subname IN ('firedog_sub', 'sentinel_sub');
```

**Expected Output**:

```
 subscription_name | enabled | pid   | lag_seconds | status
-------------------+---------+-------+-------------+--------
 firedog_sub       | t       | 12345 | 0.3         | active
 sentinel_sub      | t       | 12346 | 0.5         | active
```

**2. Replication Lag**:

```sql
-- Check replication lag (should be <1 second)
SELECT 
    subname,
    NOW() - latest_end_time AS replication_lag
FROM pg_stat_subscription
WHERE subname IN ('firedog_sub', 'sentinel_sub');
```

**Lag Thresholds**:
- ✅ **Healthy**: <1 second
- ⚠️ **Warning**: 1-5 seconds (investigate)
- 🔴 **Critical**: >5 seconds (action required)

**3. Replication Slot Status (Source)**:

```sql
-- On Firedog/Sentinel database
SELECT 
    slot_name,
    plugin,
    slot_type,
    database,
    active,
    restart_lsn,
    confirmed_flush_lsn,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn)) AS lag_size
FROM pg_replication_slots
WHERE slot_name LIKE 'intellidog%';
```

**4. Table Row Counts**:

```sql
-- Verify data is replicating (run on subscriber)
SELECT 
    schemaname,
    tablename,
    n_live_tup AS row_count
FROM pg_stat_user_tables
WHERE schemaname IN ('firedog_replica', 'sentinel_replica')
ORDER BY schemaname, tablename;
```

### Common Issues & Solutions

#### Issue 1: Subscription Shows as Inactive (pid IS NULL)

**Symptoms**:
```sql
SELECT * FROM pg_stat_subscription;
-- pid column is NULL
```

**Causes**:
1. Network connectivity issue
2. Authentication failure
3. Source database not responding

**Diagnosis**:

```bash
# Test network connectivity
telnet firedog-server 5432

# Test authentication
psql "host=firedog-server dbname=firedog user=firedog_replication password=***"

# Check PostgreSQL logs on subscriber
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

**Solution**:

```sql
-- Refresh subscription
ALTER SUBSCRIPTION firedog_sub REFRESH PUBLICATION;

-- If still failing, drop and recreate
DROP SUBSCRIPTION firedog_sub;
CREATE SUBSCRIPTION firedog_sub ...;
```

---

#### Issue 2: High Replication Lag (>5 seconds)

**Symptoms**:
```sql
SELECT NOW() - latest_end_time FROM pg_stat_subscription;
-- Result: 00:00:15 (15 seconds lag)
```

**Causes**:
1. Network bandwidth limitation
2. Subscriber CPU overload
3. Large transaction on source

**Diagnosis**:

```bash
# Check network bandwidth
iperf3 -s  # On Intellidog server
iperf3 -c intellidog-server  # On Firedog server

# Check subscriber CPU
top
# Look for postgres processes consuming high CPU

# Check source WAL generation rate
sudo -u postgres psql -c "SELECT pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')) AS wal_size;"
```

**Solution**:

```sql
-- Increase subscriber resources (if CPU-bound)
-- Optimize subscriber queries
-- Consider batching writes on source

-- Temporarily pause non-critical subscriptions
ALTER SUBSCRIPTION sentinel_sub DISABLE;
-- Wait for firedog_sub to catch up
ALTER SUBSCRIPTION sentinel_sub ENABLE;
```

---

#### Issue 3: Replication Slot Filling Disk (Source)

**Symptoms**:
```bash
# On Firedog server
df -h /var/lib/postgresql
# Disk usage 90%+
```

**Causes**:
1. Subscriber offline (WAL retention)
2. Replication slot inactive

**Diagnosis**:

```sql
-- Check replication slot disk usage
SELECT 
    slot_name,
    active,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained_wal
FROM pg_replication_slots
WHERE slot_name LIKE 'intellidog%';
```

**Solution**:

```sql
-- If subscriber will be offline long-term, drop slot
SELECT pg_drop_replication_slot('intellidog_firedog_slot');

-- Clean up WAL files
-- (PostgreSQL will auto-clean after slot removed)

-- When subscriber returns online, recreate subscription
-- (will perform full initial sync again)
```

---

#### Issue 4: Tables Not Appearing in Replica Schema

**Symptoms**:
```sql
SELECT * FROM pg_tables WHERE schemaname = 'firedog_replica';
-- Returns 0 rows
```

**Causes**:
1. Initial sync still in progress
2. Publication doesn't include tables
3. Schema doesn't exist

**Diagnosis**:

```sql
-- Check if subscription is syncing
SELECT * FROM pg_stat_subscription WHERE subname = 'firedog_sub';
-- Look for pid (should be not NULL)

-- Check publication on source
-- On Firedog database:
SELECT * FROM pg_publication_tables WHERE pubname = 'firedog_to_intellidog';
```

**Solution**:

```sql
-- Wait for initial sync to complete (can take 5-30 minutes for large databases)

-- Force refresh
ALTER SUBSCRIPTION firedog_sub REFRESH PUBLICATION;

-- If still failing, check schema exists
CREATE SCHEMA IF NOT EXISTS firedog_replica;

-- Drop and recreate subscription with correct schema
DROP SUBSCRIPTION firedog_sub;
CREATE SUBSCRIPTION firedog_sub ...;
```

---

#### Issue 5: Authentication Failures

**Symptoms**:
```
ERROR:  could not connect to the publisher: FATAL:  password authentication failed
```

**Diagnosis**:

```bash
# Test connection manually
psql "host=firedog-server dbname=firedog user=firedog_replication password=***"

# Check pg_hba.conf on source
sudo cat /var/lib/postgresql/data/pg_hba.conf | grep firedog_replication
```

**Solution**:

```bash
# Verify pg_hba.conf has correct entry
# On Firedog server:
sudo nano /var/lib/postgresql/data/pg_hba.conf

# Add:
host    firedog         firedog_replication     192.168.1.100/32        scram-sha-256

# Reload PostgreSQL
sudo systemctl reload postgresql

# Update subscription with correct password
ALTER SUBSCRIPTION firedog_sub CONNECTION 'host=... password=correct_password';
```

---

### Performance Monitoring

**1. Replication Throughput**:

```sql
-- Bytes replicated per second
SELECT 
    subname,
    (pg_wal_lsn_diff(latest_end_lsn, '0/0') / 
     EXTRACT(EPOCH FROM (NOW() - pg_postmaster_start_time()))) / 1024 / 1024 AS mb_per_second
FROM pg_stat_subscription;
```

**2. Table Sync Progress**:

```sql
-- Monitor individual table sync (during initial sync)
SELECT 
    srsubid,
    srrelid::regclass AS table_name,
    srsubstate AS state,
    srsublsn AS lsn
FROM pg_subscription_rel
WHERE srsubid IN (
    SELECT oid FROM pg_subscription WHERE subname IN ('firedog_sub', 'sentinel_sub')
);

-- States:
-- 'i' = Initializing
-- 'd' = Data is being copied
-- 's' = Synchronized
-- 'r' = Ready
```

**3. Network Latency**:

```bash
# Ping test
ping -c 10 firedog-server

# PostgreSQL connection latency
time psql "host=firedog-server dbname=firedog user=firedog_replication" -c "SELECT 1;"
```

---

## Security Considerations

### 1. Authentication & Authorization

**Principle of Least Privilege**:

```sql
-- Replication user should only have SELECT
-- ❌ BAD (too permissive)
GRANT ALL PRIVILEGES ON DATABASE firedog TO firedog_replication;

-- ✅ GOOD (minimal permissions)
GRANT SELECT ON TABLE firewall_rules TO firedog_replication;
GRANT SELECT ON TABLE machines TO firedog_replication;
-- No INSERT, UPDATE, DELETE, or DDL permissions
```

**Password Policy**:
- Minimum 32 characters
- Use `openssl rand -base64 32` to generate
- Rotate passwords annually
- Store in password manager (not plaintext files)

### 2. Network Security

**SSL/TLS Encryption** (recommended):

```sql
-- Force SSL on source database
-- Edit postgresql.conf:
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'

-- Update subscription to require SSL
ALTER SUBSCRIPTION firedog_sub 
    CONNECTION 'host=firedog-server dbname=firedog user=firedog_replication password=*** sslmode=require';
```

**IP Whitelisting**:

```bash
# pg_hba.conf - Only allow from Intellidog IP
host    firedog         firedog_replication     192.168.1.100/32        scram-sha-256

# ❌ BAD (allows from anywhere)
# host    firedog         firedog_replication     0.0.0.0/0               scram-sha-256
```

### 3. Credential Management

**Secure Storage**:

```bash
# ❌ BAD (credentials in plaintext file)
echo "password=secret123" > /tmp/credentials.txt

# ✅ GOOD (use .pgpass file with restricted permissions)
echo "firedog-server:5432:firedog:firedog_replication:secret123" > ~/.pgpass
chmod 600 ~/.pgpass

# ✅ BETTER (use environment variables)
export PGPASSWORD="secret123"
psql -h firedog-server -U firedog_replication -d firedog

# ✅ BEST (use password manager or vault)
PGPASSWORD=$(vault kv get -field=password secret/replication/firedog) psql ...
```

### 4. Audit Logging

**Enable Connection Logging**:

```bash
# postgresql.conf on source
log_connections = on
log_disconnections = on
log_line_prefix = '%t [%p]: user=%u,db=%d,app=%a,client=%h '

# Monitor replication connections
sudo tail -f /var/log/postgresql/postgresql-14-main.log | grep firedog_replication
```

---

## Performance Tuning

### 1. Source Database (Publisher)

**WAL Configuration**:

```sql
-- postgresql.conf
wal_level = logical
max_wal_size = 2GB               -- Increase if high write volume
min_wal_size = 1GB
wal_keep_size = 1GB              -- Retain WAL for subscriber catch-up

-- Checkpoint configuration (reduce I/O spikes)
checkpoint_timeout = 15min
checkpoint_completion_target = 0.9
```

**Replication Slot Limits**:

```sql
-- postgresql.conf
max_replication_slots = 10       -- One per subscriber
max_wal_senders = 10             -- Must be >= max_replication_slots
```

### 2. Subscriber Database

**Worker Processes**:

```sql
-- postgresql.conf
max_logical_replication_workers = 8   -- Increase for parallel table sync
max_sync_workers_per_subscription = 4 -- Parallel sync of tables
```

**Synchronous Commit**:

```sql
-- For async replication (better performance)
ALTER SUBSCRIPTION firedog_sub SET (synchronous_commit = off);
ALTER SUBSCRIPTION sentinel_sub SET (synchronous_commit = off);

-- For sync replication (better durability, slower)
ALTER SUBSCRIPTION firedog_sub SET (synchronous_commit = on);
```

### 3. Network Optimization

**TCP Keepalive** (prevent connection timeouts):

```sql
-- postgresql.conf
tcp_keepalives_idle = 60
tcp_keepalives_interval = 10
tcp_keepalives_count = 5
```

**Connection Pooling**:

If many subscriptions, use PgBouncer on subscriber to manage connections.

---

## Backup & Disaster Recovery

### Backup Strategy

**Source Databases**:
- Continue normal backup procedures (pg_dump, WAL archiving)
- Replication does not replace backups

**Subscriber Database**:
- Backup replicated schemas: `pg_dump -n firedog_replica -n sentinel_replica`
- Backup subscription metadata: `pg_dumpall --globals-only`

**Backup Script Example**:

```bash
#!/bin/bash
# Backup Intellidog replicated data

BACKUP_DIR="/backup/intellidog"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup replicated schemas
pg_dump -d microsiem \
    -n firedog_replica \
    -n sentinel_replica \
    -F custom \
    -f "${BACKUP_DIR}/intellidog_replicas_${DATE}.dump"

# Backup subscription config
pg_dumpall --globals-only > "${BACKUP_DIR}/globals_${DATE}.sql"

echo "Backup completed: ${BACKUP_DIR}/intellidog_replicas_${DATE}.dump"
```

### Disaster Recovery Scenarios

#### Scenario 1: Source Database Failure (Firedog/Sentinel Offline)

**Impact**:
- Replication stops (lag increases)
- Intellidog continues working with last replicated data
- No new data until source recovers

**Action**:
1. Monitor replication lag: `SELECT NOW() - latest_end_time FROM pg_stat_subscription;`
2. Intellidog remains functional (reads from replica)
3. When source recovers, replication auto-resumes
4. If downtime >24h, consider manual data sync

**Recovery**:

```sql
-- After source recovers, check sync status
SELECT * FROM pg_stat_subscription;

-- If lag is high, refresh publication
ALTER SUBSCRIPTION firedog_sub REFRESH PUBLICATION;
```

---

#### Scenario 2: Subscriber Database Failure (Intellidog Offline)

**Impact**:
- Replication slot on source retains WAL (disk fills up)
- Firedog/Sentinel unaffected

**Action**:
1. Restore subscriber from backup
2. Drop and recreate subscriptions (full initial sync)
3. OR continue from last position (if WAL retained)

**Recovery**:

```bash
# Restore subscriber database
pg_restore -d microsiem intellidog_replicas_latest.dump

# Recreate subscriptions
psql -d microsiem <<EOF
CREATE SUBSCRIPTION firedog_sub
    CONNECTION 'host=firedog-server ...'
    PUBLICATION firedog_to_intellidog
    WITH (copy_data = true);
EOF
```

---

#### Scenario 3: Network Partition (Source and Subscriber Isolated)

**Impact**:
- Replication stops
- Intellidog uses stale data

**Action**:
1. Monitor network connectivity
2. Intellidog degrades gracefully (stale data better than no data)
3. Alert on high replication lag

**Recovery**:

```bash
# When network restored, replication auto-resumes
# No manual intervention needed

# Verify resumption
psql -d microsiem -c "SELECT * FROM pg_stat_subscription;"
```

---

## Appendix

### A. Complete Configuration Checklist

**Source Database (Firedog)**:
- [ ] `wal_level = logical` in postgresql.conf
- [ ] `max_replication_slots = 10` in postgresql.conf
- [ ] `max_wal_senders = 10` in postgresql.conf
- [ ] PostgreSQL restarted after config changes
- [ ] Replication user `firedog_replication` created
- [ ] Publication `firedog_to_intellidog` created
- [ ] pg_hba.conf updated to allow Intellidog IP
- [ ] PostgreSQL configuration reloaded
- [ ] Connection tested from Intellidog server

**Source Database (Sentinel Core)**:
- [ ] (Same checklist as Firedog)

**Subscriber Database (Intellidog)**:
- [ ] Schemas `firedog_replica`, `sentinel_replica` created
- [ ] Subscription `firedog_sub` created
- [ ] Subscription `sentinel_sub` created
- [ ] Initial sync completed (all tables replicated)
- [ ] Permissions granted on replicated tables
- [ ] Replication lag <1 second
- [ ] Monitoring view `intellidog_replication_status` functional

---

### B. SQL Reference Commands

**Check Replication Status**:
```sql
-- Quick status
SELECT * FROM intellidog_replication_status;

-- Detailed status
SELECT * FROM pg_stat_subscription;

-- Replication lag
SELECT subname, NOW() - latest_end_time AS lag FROM pg_stat_subscription;
```

**Manage Subscriptions**:
```sql
-- Enable subscription
ALTER SUBSCRIPTION firedog_sub ENABLE;

-- Disable subscription
ALTER SUBSCRIPTION firedog_sub DISABLE;

-- Refresh publication (reload table list)
ALTER SUBSCRIPTION firedog_sub REFRESH PUBLICATION;

-- Update connection string
ALTER SUBSCRIPTION firedog_sub CONNECTION 'new_connection_string';

-- Drop subscription
DROP SUBSCRIPTION firedog_sub;
```

**Check Replicated Tables**:
```sql
-- List tables in replica schema
SELECT tablename FROM pg_tables WHERE schemaname = 'firedog_replica';

-- Row counts
SELECT schemaname, tablename, n_live_tup 
FROM pg_stat_user_tables 
WHERE schemaname IN ('firedog_replica', 'sentinel_replica');
```

---

### C. Troubleshooting Decision Tree

```
Replication Not Working?
│
├─ Subscription shows inactive (pid IS NULL)?
│  ├─ YES → Check network connectivity
│  │        Check authentication (pg_hba.conf)
│  │        Review PostgreSQL logs
│  │        → ALTER SUBSCRIPTION ... REFRESH PUBLICATION
│  │
│  └─ NO → Continue
│
├─ High replication lag (>5 seconds)?
│  ├─ YES → Check subscriber CPU usage
│  │        Check network bandwidth
│  │        Check source WAL generation rate
│  │        → Optimize subscriber resources
│  │
│  └─ NO → Continue
│
├─ Tables not appearing in replica schema?
│  ├─ YES → Wait for initial sync (check pg_stat_subscription)
│  │        Verify publication includes tables
│  │        → ALTER SUBSCRIPTION ... REFRESH PUBLICATION
│  │
│  └─ NO → Continue
│
├─ Source disk filling up?
│  ├─ YES → Check replication slot status
│  │        → DROP inactive replication slots
│  │
│  └─ NO → Replication working! ✅
```

---

### D. Performance Benchmarks

**Typical Performance** (based on testing):

| Metric | Value | Notes |
|--------|-------|-------|
| Replication Lag | 200-500ms | Async replication |
| Initial Sync Time (100k rows) | 5-10 minutes | Depends on network |
| Query Performance (local replica) | <5ms | vs 50-200ms API |
| Network Bandwidth | 1-10 Mbps | Depends on write volume |
| Disk Space (source WAL) | 10-20 GB | 24-hour retention |
| Disk Space (subscriber replica) | ~50% of source | Compressed |

---

### E. References & Further Reading

- [PostgreSQL Logical Replication Official Docs](https://www.postgresql.org/docs/current/logical-replication.html)
- [pg_stat_subscription Reference](https://www.postgresql.org/docs/current/monitoring-stats.html#MONITORING-PG-STAT-SUBSCRIPTION-VIEW)
- [Replication Slot Management](https://www.postgresql.org/docs/current/warm-standby.html#STREAMING-REPLICATION-SLOTS)
- [pg_hba.conf Authentication](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html)

---

**End of Database Replication Setup Guide**
