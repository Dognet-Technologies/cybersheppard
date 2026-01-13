# Database Architecture - Complete Reference

## Overview

This document provides a complete reference for the database architecture supporting Firedog, Sentinel Core, CyberSheppard, and Intellidog integration.

---

## High-Level Architecture

```
┌────────────────────────────────────────────────────────────┐
│                   Database Topology                         │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  Firedog VM (192.168.1.50)                                 │
│  └─► PostgreSQL Database: firedog                          │
│      ├─ Owner: vlnman / DogNET (.env)                      │
│      ├─ Replication: intellirep / <cyber_api_key>          │
│      ├─ Tables: firewall_rules, machines, rule_stats, ...  │
│      └─ Publication: firedog_to_intellidog                 │
│                    │                                        │
│                    │ Logical Replication (async)            │
│                    ▼                                        │
│  CyberSheppard VM (192.168.1.100)                          │
│  └─► PostgreSQL Database: cybersheppard                    │
│      ├─ Owner: vlnman / DogNET (.env)                      │
│      ├─ Schemas:                                           │
│      │  ├─ public (CyberSheppard native)                   │
│      │  ├─ firedog_replica (from Firedog)                  │
│      │  ├─ sentinel_replica (from Sentinel)                │
│      │  └─ intellidog (Intellidog native)                  │
│      └─ Subscriptions:                                     │
│         ├─ firedog_sub → Firedog                           │
│         └─ sentinel_sub → Sentinel                         │
│                    ▲                                        │
│                    │ Logical Replication (async)            │
│                    │                                        │
│  Sentinel VM (192.168.1.51)                                │
│  └─► PostgreSQL Database: sentinel                         │
│      ├─ Owner: vlnman / DogNET (.env)                      │
│      ├─ Replication: intellirep / <cyber_api_key>          │
│      ├─ Tables: vulnerabilities, cves, machines, ...       │
│      └─ Publication: sentinel_to_intellidog                │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

---

## User Management

### Application Users (vlnman)

**Purpose**: Standard application access

```sql
-- Created on ALL three databases
CREATE USER vlnman WITH PASSWORD 'DogNET';

-- Permissions
GRANT ALL PRIVILEGES ON DATABASE firedog TO vlnman;      -- Firedog
GRANT ALL PRIVILEGES ON DATABASE sentinel TO vlnman;     -- Sentinel
GRANT ALL PRIVILEGES ON DATABASE cybersheppard TO vlnman; -- CyberSheppard

-- Schema-specific grants (CyberSheppard only)
GRANT USAGE ON SCHEMA public TO vlnman;
GRANT USAGE ON SCHEMA firedog_replica TO vlnman;
GRANT USAGE ON SCHEMA sentinel_replica TO vlnman;
GRANT USAGE ON SCHEMA intellidog TO vlnman;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vlnman;
GRANT SELECT ON ALL TABLES IN SCHEMA firedog_replica TO vlnman;  -- Read-only replica
GRANT SELECT ON ALL TABLES IN SCHEMA sentinel_replica TO vlnman; -- Read-only replica
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA intellidog TO vlnman;
```

**Usage**:
- Firedog application connects as `vlnman`
- Sentinel application connects as `vlnman`
- CyberSheppard application connects as `vlnman`
- Intellidog module connects as `vlnman`

**Connection String** (all tools):
```bash
# From .env file
DATABASE_URL=postgresql://vlnman:DogNET@localhost:5432/cybersheppard
```

### Replication Users (intellirep)

**Purpose**: PostgreSQL logical replication ONLY

```sql
-- Created on Firedog and Sentinel (NOT on CyberSheppard)
CREATE USER intellirep WITH REPLICATION PASSWORD '<cybersheppard_api_key>';

-- Permissions (minimal, read-only)
GRANT SELECT ON ALL TABLES IN SCHEMA public TO intellirep;

-- NOT USED BY APPLICATION CODE!
-- Used only by PostgreSQL subscription worker process
```

**Password Source**: CyberSheppard API key (from Settings → Orchestration)

**Example**:
```
CyberSheppard generates API key: cyber_abc123xyz

→ Firedog creates: intellirep / cyber_abc123xyz
→ Sentinel creates: intellirep / cyber_abc123xyz
→ CyberSheppard subscribes using this password
```

**⚠️ CRITICAL**: Application code (Python, Rust) NEVER uses `intellirep`. Only PostgreSQL's internal subscription worker uses it.

---

## CyberSheppard Database Schemas

### Schema: public

**Purpose**: CyberSheppard native tables

**Tables**:
```sql
-- User management
users
audit_logs

-- Machine management
machines
ssh_keys

-- Hardening
hardening_models
applied_hardening

-- Monitoring
(InfluxDB - not in PostgreSQL)

-- Alerts
alert_configs

-- System integrations
system_integrations  -- NEW (API keys for Firedog/Sentinel)
system_config        -- NEW (vlnman password hash, etc.)

-- Plugin system
plugin_repositories
plugin_registry
installed_plugins
plugin_executions
plugin_permissions
```

**Owner**: `vlnman`

**Access**:
```python
# CyberSheppard application
from app.database import db

# Query native tables
machines = db.execute("SELECT * FROM machines").fetchall()
users = db.execute("SELECT * FROM users").fetchall()
```

### Schema: firedog_replica

**Purpose**: Replicated tables from Firedog (read-only)

**Tables**:
```sql
-- Firewall management
firewall_rules
machines (Firedog's machines, separate from CyberSheppard's)
rule_stats
rule_logs
firewall_zones
firewall_policies

-- Replication metadata
_pg_replication_origin_status  -- Internal PostgreSQL table
```

**Owner**: `postgres` (created by subscription)

**Permissions**: `vlnman` has SELECT only (read-only)

**Access**:
```python
# Intellidog correlation engine
firewall_rules = db.execute("""
    SELECT * FROM firedog_replica.firewall_rules
    WHERE status = 'active'
""").fetchall()
```

**Replication Lag**: Typically < 1 second

**Check Lag**:
```sql
SELECT 
    subname,
    EXTRACT(EPOCH FROM (NOW() - latest_end_time)) as lag_seconds
FROM pg_stat_subscription
WHERE subname = 'firedog_sub';
```

### Schema: sentinel_replica

**Purpose**: Replicated tables from Sentinel Core (read-only)

**Tables**:
```sql
-- Vulnerability management
vulnerabilities
cves
machines (Sentinel's machines)
scan_results
scan_configurations

-- Exploit intelligence
epss_scores      -- Exploit Prediction Scoring System
cve_exploits     -- Known exploits

-- Advisory data
security_advisories
vendor_patches
```

**Owner**: `postgres` (created by subscription)

**Permissions**: `vlnman` has SELECT only (read-only)

**Access**:
```python
# Intellidog correlation engine
critical_vulns = db.execute("""
    SELECT * FROM sentinel_replica.vulnerabilities
    WHERE severity = 'critical' AND status = 'open'
""").fetchall()
```

### Schema: intellidog

**Purpose**: Intellidog native tables

**Tables**:
```sql
-- Threat intelligence
intellidog_feeds
intellidog_iocs
intellidog_detections
intellidog_virtual_patches
intellidog_hunting_queries
intellidog_license

-- Correlation results
intellidog_correlation_cache  -- Performance optimization
```

**Owner**: `vlnman`

**Access**:
```python
# Intellidog module
iocs = db.execute("""
    SELECT * FROM intellidog.intellidog_iocs
    WHERE is_active = TRUE
""").fetchall()
```

---

## PostgreSQL Logical Replication

### Configuration

**On All Databases** (`postgresql.conf`):
```ini
# Enable logical replication
wal_level = logical

# Replication slots
max_replication_slots = 10
max_wal_senders = 10

# Subscription workers
max_logical_replication_workers = 4
max_worker_processes = 16
max_sync_workers_per_subscription = 2
```

**On Firedog** (`pg_hba.conf`):
```
# Allow CyberSheppard to connect for replication
host    replication    intellirep    192.168.1.100/32    scram-sha-256
```

**On Sentinel** (`pg_hba.conf`):
```
# Allow CyberSheppard to connect for replication
host    replication    intellirep    192.168.1.100/32    scram-sha-256
```

### Publications (Source Databases)

**Firedog Publication**:
```sql
-- Created by Firedog Replication Plugin
CREATE PUBLICATION firedog_to_intellidog 
FOR TABLE 
    firewall_rules,
    machines,
    rule_stats,
    rule_logs,
    firewall_zones,
    firewall_policies;
```

**Sentinel Publication**:
```sql
-- Created by Sentinel Replication Plugin
CREATE PUBLICATION sentinel_to_intellidog
FOR TABLE 
    vulnerabilities,
    cves,
    machines,
    scan_results,
    scan_configurations,
    epss_scores,
    cve_exploits,
    security_advisories,
    vendor_patches;
```

**Check Publications**:
```sql
-- On Firedog or Sentinel
SELECT * FROM pg_publication;
SELECT * FROM pg_publication_tables;
```

### Subscriptions (CyberSheppard)

**Firedog Subscription**:
```sql
-- Created by CyberSheppard Replication Plugin
CREATE SUBSCRIPTION firedog_sub
CONNECTION 'host=192.168.1.50 port=5432 dbname=firedog user=intellirep password=<cyber_api_key>'
PUBLICATION firedog_to_intellidog
WITH (
    create_slot = true,
    enabled = true,
    copy_data = true,
    slot_name = 'firedog_sub'
);
```

**Sentinel Subscription**:
```sql
-- Created by CyberSheppard Replication Plugin
CREATE SUBSCRIPTION sentinel_sub
CONNECTION 'host=192.168.1.51 port=5432 dbname=sentinel user=intellirep password=<cyber_api_key>'
PUBLICATION sentinel_to_intellidog
WITH (
    create_slot = true,
    enabled = true,
    copy_data = true,
    slot_name = 'sentinel_sub'
);
```

**Check Subscriptions**:
```sql
-- On CyberSheppard
SELECT * FROM pg_subscription;
SELECT * FROM pg_stat_subscription;
```

---

## Monitoring Replication Health

### Real-Time Status View

```sql
-- On CyberSheppard
CREATE OR REPLACE VIEW intellidog_replication_status AS
SELECT 
    sub.subname AS subscription_name,
    sub.subenabled AS enabled,
    st.pid,
    EXTRACT(EPOCH FROM (NOW() - st.latest_end_time)) AS lag_seconds,
    st.received_lsn,
    st.latest_end_lsn,
    CASE 
        WHEN st.pid IS NULL THEN 'inactive'
        WHEN EXTRACT(EPOCH FROM (NOW() - st.latest_end_time)) > 30 THEN 'lagging'
        ELSE 'active'
    END AS status
FROM pg_subscription sub
LEFT JOIN pg_stat_subscription st ON sub.oid = st.subid
WHERE sub.subname IN ('firedog_sub', 'sentinel_sub');

-- Usage
SELECT * FROM intellidog_replication_status;
```

**Expected Output**:
```
 subscription_name | enabled |  pid  | lag_seconds | status
-------------------+---------+-------+-------------+--------
 firedog_sub       | t       | 12345 |        0.32 | active
 sentinel_sub      | t       | 12346 |        0.18 | active
```

### Check Replication Slots (Source)

```sql
-- On Firedog or Sentinel
SELECT 
    slot_name,
    plugin,
    slot_type,
    database,
    active,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS replication_lag_bytes
FROM pg_replication_slots;
```

**Expected Output**:
```
  slot_name  |     plugin     | slot_type | database | active | replication_lag_bytes
-------------+----------------+-----------+----------+--------+-----------------------
 firedog_sub | pgoutput       | logical   | firedog  | t      | 16 kB
```

### Table-Level Sync Status

```sql
-- On CyberSheppard
SELECT 
    subname,
    schemaname || '.' || tablename AS table_name,
    CASE 
        WHEN srsubstate = 'r' THEN 'ready'
        WHEN srsubstate = 'd' THEN 'data copying'
        WHEN srsubstate = 's' THEN 'synchronized'
        WHEN srsubstate = 'i' THEN 'initializing'
        ELSE 'unknown'
    END AS sync_state
FROM pg_subscription_rel sr
JOIN pg_subscription s ON sr.srsubid = s.oid
JOIN pg_class c ON sr.srrelid = c.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
ORDER BY subname, table_name;
```

---

## Database Connection Flow

### Firedog Application

```
Firedog Application
    │
    ├─ Connection: postgresql://vlnman:DogNET@localhost:5432/firedog
    │
    └─ Operations:
       ├─ INSERT INTO firewall_rules (...)
       ├─ UPDATE firewall_rules SET status = 'active' WHERE id = 123
       └─ SELECT * FROM firewall_rules WHERE machine_id = 5
```

**Replication Side Effect**:
```
Firedog INSERT → WAL → Publication → Network → Subscription → CyberSheppard
                                                               │
                                                               ▼
                                              INSERT INTO firedog_replica.firewall_rules
```

### Intellidog Module

```
Intellidog Correlation Engine
    │
    ├─ Connection: postgresql://vlnman:DogNET@localhost:5432/cybersheppard
    │
    └─ Operations (across multiple schemas):
       │
       ├─ SELECT * FROM firedog_replica.firewall_rules
       │  WHERE source_ip = '203.0.113.45'
       │
       ├─ SELECT * FROM sentinel_replica.vulnerabilities
       │  WHERE cve_id = 'CVE-2024-12345'
       │
       ├─ SELECT * FROM intellidog.intellidog_iocs
       │  WHERE value = '203.0.113.45'
       │
       └─ INSERT INTO intellidog.intellidog_detections (...)
```

**Key Point**: All operations use `vlnman` user. No `intellirep` in application code.

---

## Data Flow Example

### Scenario: Firewall Rule Creation → Detection

**Step 1**: Admin creates firewall rule in Firedog

```sql
-- On Firedog database (via Firedog UI)
INSERT INTO firewall_rules (
    name, action, protocol, source_ip, port, created_at
) VALUES (
    'block-suspicious-ip', 'DROP', 'tcp', '203.0.113.45', 443, NOW()
);
```

**Step 2**: PostgreSQL replication (automatic, ~500ms)

```
Firedog PostgreSQL
    ├─ INSERT committed
    ├─ WAL record written
    ├─ Publication firedog_to_intellidog notified
    └─ WAL sender streams to CyberSheppard
                    │
                    ▼
CyberSheppard PostgreSQL
    ├─ Subscription firedog_sub receives WAL
    ├─ Logical decoder translates to INSERT
    └─ INSERT INTO firedog_replica.firewall_rules (...)
```

**Step 3**: Intellidog correlation (next 5-minute job)

```python
# Intellidog correlation engine (Python)
from app.database import db

# Check for IOC match
ioc = db.execute("""
    SELECT * FROM intellidog.intellidog_iocs
    WHERE value = '203.0.113.45' AND is_active = TRUE
""").fetchone()

if ioc:
    # Found matching IOC! Create detection
    db.execute("""
        INSERT INTO intellidog.intellidog_detections (
            machine_id, ioc_id, detection_type, severity, source_data
        ) VALUES (
            (SELECT id FROM firedog_replica.machines WHERE ip = '192.168.1.10'),
            :ioc_id,
            'firewall_match',
            'high',
            '{"rule_name": "block-suspicious-ip", "action": "DROP"}'
        )
    """, {"ioc_id": ioc.id})
```

**Step 4**: Alert sent (automatic)

```
Detection Created → Alert Rule Matches → Email Sent
                                      → Slack Notification
                                      → Dashboard Updated
```

**Total Time**: Rule creation → Detection alert ≈ 5-6 minutes (next correlation run)

---

## Performance Considerations

### Replication Lag Factors

**Network Latency**:
- LAN: ~0.1-1 second typical
- WAN: Can be 1-10 seconds
- VPN: Variable, monitor closely

**Source Database Load**:
- High write volume → more WAL → higher lag
- Solution: Increase `max_wal_senders`, optimize queries

**Subscriber Processing**:
- Slow disk I/O on CyberSheppard → lag increases
- Solution: SSD storage, increase `max_sync_workers_per_subscription`

**Table Bloat**:
- Large initial sync can take hours for millions of rows
- Solution: Use `copy_data = false` and sync manually if needed

### Optimization Tips

**Reduce Lag**:
```sql
-- Disable synchronous_commit on subscription (faster, slight risk)
ALTER SUBSCRIPTION firedog_sub SET (synchronous_commit = off);
```

**Increase Parallelism**:
```sql
-- Allow more parallel workers for initial sync
ALTER SYSTEM SET max_sync_workers_per_subscription = 4;
SELECT pg_reload_conf();
```

**Monitor WAL Size**:
```sql
-- Check WAL accumulation on source
SELECT 
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) 
FROM pg_replication_slots;

-- If > 1GB, investigate subscriber lag
```

---

## Backup & Recovery

### Backup Strategy

**Firedog**:
```bash
# Daily backup (native tables only)
pg_dump -U vlnman -d firedog -F c -f firedog_backup_$(date +%Y%m%d).dump
```

**Sentinel**:
```bash
# Daily backup
pg_dump -U vlnman -d sentinel -F c -f sentinel_backup_$(date +%Y%m%d).dump
```

**CyberSheppard**:
```bash
# Backup native schemas (public, intellidog)
# Skip replica schemas (they'll re-sync from sources)
pg_dump -U vlnman -d cybersheppard \
    -n public -n intellidog \
    -F c -f cybersheppard_backup_$(date +%Y%m%d).dump
```

**⚠️ DO NOT backup replica schemas**: They're replicated from sources, will auto-populate on restore.

### Recovery

**Restore CyberSheppard**:
```bash
# 1. Restore native schemas
pg_restore -U vlnman -d cybersheppard -c cybersheppard_backup_20251231.dump

# 2. Recreate replica schemas
psql -U vlnman -d cybersheppard -c "CREATE SCHEMA firedog_replica;"
psql -U vlnman -d cybersheppard -c "CREATE SCHEMA sentinel_replica;"

# 3. Recreate subscriptions (will auto-populate tables)
# Run CyberSheppard Replication Plugin installation again
```

**Initial Sync Duration**:
- Small dataset (< 10K rows): ~1 minute
- Medium dataset (10K-100K rows): ~5-10 minutes
- Large dataset (> 100K rows): ~30-60 minutes

---

## Troubleshooting

### Issue: Replication Stopped

**Symptoms**:
```sql
SELECT * FROM pg_stat_subscription;
-- pid is NULL
```

**Checks**:
1. Subscription enabled?
   ```sql
   SELECT subname, subenabled FROM pg_subscription;
   ```
2. Network connectivity?
   ```bash
   telnet 192.168.1.50 5432
   ```
3. pg_hba.conf allows connection?
4. Publication still exists on source?

**Solution**:
```sql
-- Re-enable subscription
ALTER SUBSCRIPTION firedog_sub ENABLE;

-- Or recreate
DROP SUBSCRIPTION firedog_sub;
-- Re-run plugin installation
```

### Issue: High Lag

**Symptoms**:
```sql
SELECT * FROM intellidog_replication_status;
-- lag_seconds > 30
```

**Checks**:
1. Network bandwidth:
   ```bash
   iftop -i eth0
   ```
2. Disk I/O on subscriber:
   ```bash
   iostat -x 1
   ```
3. WAL sender activity on source:
   ```sql
   SELECT * FROM pg_stat_replication;
   ```

**Solutions**:
- Increase `max_wal_senders` on source
- Add more disk I/O capacity to subscriber
- Disable `synchronous_commit` on subscription

### Issue: Tables Not Syncing

**Symptoms**:
```sql
SELECT * FROM firedog_replica.firewall_rules;
-- Returns 0 rows, but Firedog has data
```

**Checks**:
```sql
SELECT * FROM pg_subscription_rel;
-- Check srsubstate for each table
```

**Solutions**:
1. Refresh subscription:
   ```sql
   ALTER SUBSCRIPTION firedog_sub REFRESH PUBLICATION;
   ```
2. Drop and recreate subscription (will re-sync all data)

---

## Security Considerations

### Password Management

**vlnman Password**:
- Default: `DogNET`
- Change in `.env` file on ALL three VMs
- Restart applications after change

**intellirep Password**:
- Automatically set to CyberSheppard API key
- Rotate by regenerating API key in Settings → Orchestration
- Plugin will auto-update PostgreSQL user

### Network Security

**Firewall Rules**:
```bash
# On Firedog - allow PostgreSQL only from CyberSheppard
iptables -A INPUT -p tcp -s 192.168.1.100 --dport 5432 -j ACCEPT
iptables -A INPUT -p tcp --dport 5432 -j DROP

# On Sentinel - allow PostgreSQL only from CyberSheppard
iptables -A INPUT -p tcp -s 192.168.1.100 --dport 5432 -j ACCEPT
iptables -A INPUT -p tcp --dport 5432 -j DROP

# On CyberSheppard - no external PostgreSQL access
iptables -A INPUT -p tcp --dport 5432 -j DROP
```

**SSL/TLS** (recommended for production):
```sql
-- Enable SSL in postgresql.conf
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'

-- Require SSL in pg_hba.conf
hostssl replication intellirep 192.168.1.100/32 scram-sha-256
```

---

## Summary

**Database Topology**:
- 3 separate PostgreSQL databases (firedog, sentinel, cybersheppard)
- Each with own `.env` configuration
- Logical replication from sources to CyberSheppard

**User Strategy**:
- `vlnman`: Application user (all databases)
- `intellirep`: Replication user (Firedog, Sentinel only)

**Schema Organization** (CyberSheppard):
- `public`: Native CyberSheppard tables
- `firedog_replica`: Replicated from Firedog (read-only)
- `sentinel_replica`: Replicated from Sentinel (read-only)
- `intellidog`: Intellidog native tables

**Replication Performance**:
- Typical lag: < 1 second
- Warning threshold: 30 seconds
- Critical threshold: 300 seconds (5 minutes)

**Access Pattern**:
```python
# All Intellidog code uses vlnman
db = connect('postgresql://vlnman:DogNET@localhost/cybersheppard')

# Query across schemas
firedog_data = db.execute("SELECT * FROM firedog_replica.firewall_rules")
sentinel_data = db.execute("SELECT * FROM sentinel_replica.vulnerabilities")
iocs = db.execute("SELECT * FROM intellidog.intellidog_iocs")
```

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-12-31  
**Author**: Dognet Technologies
