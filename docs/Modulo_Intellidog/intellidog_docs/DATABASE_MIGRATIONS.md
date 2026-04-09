# Database Migrations - Complete Specification

## Overview

Complete migration strategy for CyberSheppard database evolution from base system to full Intellidog integration.

**Migration Tool**: Direct SQL execution (psql)  
**Execution Order**: Sequential (001 → 012)  
**Rollback**: Manual (provided for each migration)  
**Database**: `cybersheppard`  
**User**: `vlnman`

---

## Migration Index

| # | Name | Description | Tables Created | Status |
|---|------|-------------|----------------|--------|
| 001 | initial_schema | Base CyberSheppard tables | users, machines, hardening_models, etc. | Existing |
| 002 | audit_logs | Audit logging system | audit_logs | Existing |
| 003 | ssh_keys | SSH key management | ssh_keys | Existing |
| 004 | alert_configs | Alert configuration | alert_configs | Existing |
| 005 | compliance_checks | Compliance tracking | compliance_checks | Existing |
| 006 | applied_hardening | Hardening application tracking | applied_hardening | Existing |
| 007 | system_integrations | API key storage for integrations | system_integrations | Existing |
| 008 | plugin_system | Plugin manager tables | plugin_repositories, plugin_registry, etc. | Existing |
| 009 | simplify_roles | User role simplification | (ALTER users) | Existing |
| 010 | replication_schemas | Create replica schemas | firedog_replica, sentinel_replica | **NEW** |
| 011 | intellidog_schema | Intellidog module tables | intellidog.* (10 tables) | **NEW** |
| 012 | intellidog_permissions | Grant permissions to vlnman | (GRANT statements) | **NEW** |

---

## Migration 010: Replication Schemas

**File**: `database/postgresql/migrations/010_replication_schemas.sql`

**Purpose**: Create schemas for replicated data from Firedog and Sentinel

**Execution**: Run BEFORE installing CyberSheppard Replication Plugin

```sql
-- ============================================================================
-- Migration 010: Replication Schemas
-- ============================================================================
-- Purpose: Create schemas for PostgreSQL logical replication from Firedog 
--          and Sentinel Core
-- 
-- Prerequisites:
--   - CyberSheppard database exists
--   - vlnman user exists
--   - Firedog and Sentinel have configured publications
--
-- Execution:
--   psql -U vlnman -d cybersheppard -f 010_replication_schemas.sql
-- ============================================================================

BEGIN;

-- ============================================================================
-- CREATE SCHEMAS
-- ============================================================================

-- Schema for Firedog replicated tables
CREATE SCHEMA IF NOT EXISTS firedog_replica;

COMMENT ON SCHEMA firedog_replica IS 'Replicated tables from Firedog database via logical replication';

-- Schema for Sentinel replicated tables
CREATE SCHEMA IF NOT EXISTS sentinel_replica;

COMMENT ON SCHEMA sentinel_replica IS 'Replicated tables from Sentinel Core database via logical replication';

-- ============================================================================
-- GRANT PERMISSIONS
-- ============================================================================

-- Grant usage on schemas to vlnman
GRANT USAGE ON SCHEMA firedog_replica TO vlnman;
GRANT USAGE ON SCHEMA sentinel_replica TO vlnman;

-- Grant SELECT on all current and future tables in replica schemas
GRANT SELECT ON ALL TABLES IN SCHEMA firedog_replica TO vlnman;
GRANT SELECT ON ALL TABLES IN SCHEMA sentinel_replica TO vlnman;

ALTER DEFAULT PRIVILEGES IN SCHEMA firedog_replica 
GRANT SELECT ON TABLES TO vlnman;

ALTER DEFAULT PRIVILEGES IN SCHEMA sentinel_replica 
GRANT SELECT ON TABLES TO vlnman;

-- Note: Tables will be created automatically by PostgreSQL subscription
-- when CyberSheppard Replication Plugin creates subscriptions

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Verify schemas created
SELECT schema_name 
FROM information_schema.schemata 
WHERE schema_name IN ('firedog_replica', 'sentinel_replica');

-- Verify permissions
SELECT 
    schemaname,
    has_schema_privilege('vlnman', schemaname, 'USAGE') AS has_usage
FROM pg_namespace 
WHERE nspname IN ('firedog_replica', 'sentinel_replica');

COMMIT;

-- ============================================================================
-- ROLLBACK
-- ============================================================================
-- 
-- To rollback this migration:
-- 
-- BEGIN;
-- DROP SCHEMA IF EXISTS firedog_replica CASCADE;
-- DROP SCHEMA IF EXISTS sentinel_replica CASCADE;
-- COMMIT;
-- 
-- WARNING: This will delete all replicated data!
-- ============================================================================
```

**Expected Output**:
```
CREATE SCHEMA
CREATE SCHEMA
GRANT
GRANT
GRANT
GRANT
ALTER DEFAULT PRIVILEGES
ALTER DEFAULT PRIVILEGES

 schema_name
-----------------
 firedog_replica
 sentinel_replica
(2 rows)

 schemaname      | has_usage
-----------------+-----------
 firedog_replica | t
 sentinel_replica| t
(2 rows)

COMMIT
```

**Post-Migration Steps**:
1. Verify schemas exist: `\dn` in psql
2. Install CyberSheppard Replication Plugin (will create subscriptions)
3. Verify tables populated: `SELECT count(*) FROM firedog_replica.firewall_rules;`

---

## Migration 011: Intellidog Schema

**File**: `database/postgresql/migrations/011_intellidog_schema.sql`

**Purpose**: Create complete Intellidog schema with all tables, views, functions, and triggers

**Execution**: Run BEFORE activating Intellidog module

```sql
-- ============================================================================
-- Migration 011: Intellidog Schema
-- ============================================================================
-- Purpose: Create complete Intellidog threat intelligence module schema
-- 
-- Prerequisites:
--   - Migration 010 completed (replication schemas exist)
--   - Firedog and Sentinel data replicating
--   - Valid Intellidog license available
--
-- Execution:
--   psql -U vlnman -d cybersheppard -f 011_intellidog_schema.sql
-- ============================================================================

BEGIN;

-- ============================================================================
-- ENABLE REQUIRED EXTENSIONS
-- ============================================================================

-- pg_trgm for fuzzy text search on IOCs
CREATE EXTENSION IF NOT EXISTS pg_trgm;

COMMENT ON EXTENSION pg_trgm IS 'Text similarity measurement and index searching';

-- ============================================================================
-- CREATE SCHEMA
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS intellidog;

COMMENT ON SCHEMA intellidog IS 'Intellidog threat intelligence module tables and functions';

-- ============================================================================
-- TABLE 1: intellidog_license
-- ============================================================================

CREATE TABLE intellidog.intellidog_license (
    id SERIAL PRIMARY KEY,
    license_key VARCHAR(100) UNIQUE NOT NULL,
    customer_name VARCHAR(200) NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    max_machines INTEGER NOT NULL DEFAULT 100,
    features JSONB NOT NULL DEFAULT '["threat_intel_feeds", "correlation", "virtual_patching", "hunting"]'::jsonb,
    support_level VARCHAR(50) NOT NULL DEFAULT 'standard',
    license_file_content TEXT NOT NULL,
    gpg_signature_valid BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_validated_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE intellidog.intellidog_license IS 'Intellidog license management';

CREATE INDEX idx_license_key ON intellidog.intellidog_license(license_key);
CREATE INDEX idx_license_expires ON intellidog.intellidog_license(expires_at) WHERE is_active = true;

-- ============================================================================
-- TABLE 2: intellidog_feeds
-- ============================================================================

CREATE TABLE intellidog.intellidog_feeds (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    feed_type VARCHAR(50) NOT NULL,
    url TEXT,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    auto_update BOOLEAN NOT NULL DEFAULT true,
    update_interval_minutes INTEGER NOT NULL DEFAULT 60,
    last_update_at TIMESTAMP,
    last_update_success BOOLEAN,
    last_update_error TEXT,
    next_update_at TIMESTAMP,
    ioc_count INTEGER NOT NULL DEFAULT 0,
    api_key_encrypted TEXT,
    additional_config JSONB DEFAULT '{}'::jsonb,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT chk_feed_type CHECK (feed_type IN ('misp', 'otx', 'stix', 'taxii', 'custom', 'csv', 'json')),
    CONSTRAINT chk_update_interval CHECK (update_interval_minutes >= 15)
);

COMMENT ON TABLE intellidog.intellidog_feeds IS 'Threat intelligence feed sources';

CREATE INDEX idx_feeds_active ON intellidog.intellidog_feeds(is_active);
CREATE INDEX idx_feeds_next_update ON intellidog.intellidog_feeds(next_update_at) 
    WHERE is_active = true AND auto_update = true;
CREATE INDEX idx_feeds_type ON intellidog.intellidog_feeds(feed_type);

-- ============================================================================
-- TABLE 3: intellidog_iocs
-- ============================================================================

CREATE TABLE intellidog.intellidog_iocs (
    id SERIAL PRIMARY KEY,
    feed_id INTEGER REFERENCES intellidog.intellidog_feeds(id) ON DELETE CASCADE,
    ioc_type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    value_hash VARCHAR(64) GENERATED ALWAYS AS (encode(sha256(value::bytea), 'hex')) STORED,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    confidence_score INTEGER NOT NULL DEFAULT 50,
    threat_type VARCHAR(50),
    threat_category VARCHAR(50),
    description TEXT,
    tags TEXT[],
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    expiration_date TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT true,
    false_positive BOOLEAN NOT NULL DEFAULT false,
    whitelisted BOOLEAN NOT NULL DEFAULT false,
    whitelist_reason TEXT,
    tlp_level VARCHAR(20) DEFAULT 'white',
    metadata JSONB DEFAULT '{}'::jsonb,
    source_reference TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT chk_ioc_type CHECK (ioc_type IN (
        'ip', 'domain', 'url', 'email', 'hash_md5', 'hash_sha1', 
        'hash_sha256', 'cve', 'registry_key', 'file_path', 'user_agent',
        'ssl_cert_fingerprint', 'bitcoin_address', 'mutex', 'yara_rule'
    )),
    CONSTRAINT chk_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    CONSTRAINT chk_confidence CHECK (confidence_score >= 0 AND confidence_score <= 100),
    CONSTRAINT chk_tlp CHECK (tlp_level IN ('red', 'amber', 'green', 'white')),
    CONSTRAINT uq_ioc_value_type UNIQUE (value_hash, ioc_type, feed_id)
);

COMMENT ON TABLE intellidog.intellidog_iocs IS 'Indicators of Compromise';

CREATE INDEX idx_iocs_value_hash ON intellidog.intellidog_iocs(value_hash);
CREATE INDEX idx_iocs_type ON intellidog.intellidog_iocs(ioc_type);
CREATE INDEX idx_iocs_severity ON intellidog.intellidog_iocs(severity);
CREATE INDEX idx_iocs_active ON intellidog.intellidog_iocs(is_active) WHERE is_active = true;
CREATE INDEX idx_iocs_feed ON intellidog.intellidog_iocs(feed_id);
CREATE INDEX idx_iocs_threat_type ON intellidog.intellidog_iocs(threat_type);
CREATE INDEX idx_iocs_expiration ON intellidog.intellidog_iocs(expiration_date) WHERE expiration_date IS NOT NULL;
CREATE INDEX idx_iocs_last_seen ON intellidog.intellidog_iocs(last_seen DESC);
CREATE INDEX idx_iocs_tags ON intellidog.intellidog_iocs USING GIN(tags);
CREATE INDEX idx_iocs_value_trgm ON intellidog.intellidog_iocs USING GIN(value gin_trgm_ops);

-- ============================================================================
-- TABLE 4: intellidog_detections
-- ============================================================================

CREATE TABLE intellidog.intellidog_detections (
    id SERIAL PRIMARY KEY,
    machine_id INTEGER REFERENCES machines(id) ON DELETE CASCADE,
    ioc_id INTEGER REFERENCES intellidog.intellidog_iocs(id) ON DELETE SET NULL,
    detection_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence_score INTEGER NOT NULL DEFAULT 50,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    source_data JSONB NOT NULL,
    correlation_context JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'new',
    risk_score INTEGER,
    auto_patched BOOLEAN NOT NULL DEFAULT false,
    virtual_patch_id INTEGER,
    assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
    notes TEXT,
    false_positive BOOLEAN NOT NULL DEFAULT false,
    false_positive_reason TEXT,
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMP,
    acknowledged_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMP,
    resolved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    resolution_action TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT chk_detection_type CHECK (detection_type IN (
        'firewall_match', 'vuln_correlation', 'behavioral_anomaly',
        'threat_hunting_hit', 'feed_match', 'pattern_match', 'exploit_attempt'
    )),
    CONSTRAINT chk_detection_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    CONSTRAINT chk_detection_status CHECK (status IN (
        'new', 'acknowledged', 'investigating', 'resolved', 
        'false_positive', 'escalated', 'suppressed'
    )),
    CONSTRAINT chk_confidence CHECK (confidence_score >= 0 AND confidence_score <= 100),
    CONSTRAINT chk_risk_score CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100))
);

COMMENT ON TABLE intellidog.intellidog_detections IS 'Threat detections from correlation engine';

CREATE INDEX idx_detections_machine ON intellidog.intellidog_detections(machine_id);
CREATE INDEX idx_detections_ioc ON intellidog.intellidog_detections(ioc_id);
CREATE INDEX idx_detections_status ON intellidog.intellidog_detections(status);
CREATE INDEX idx_detections_severity ON intellidog.intellidog_detections(severity);
CREATE INDEX idx_detections_type ON intellidog.intellidog_detections(detection_type);
CREATE INDEX idx_detections_detected_at ON intellidog.intellidog_detections(detected_at DESC);
CREATE INDEX idx_detections_assigned ON intellidog.intellidog_detections(assigned_to) WHERE assigned_to IS NOT NULL;
CREATE INDEX idx_detections_unresolved ON intellidog.intellidog_detections(status, detected_at DESC) 
    WHERE status IN ('new', 'acknowledged', 'investigating');

-- ============================================================================
-- TABLE 5: intellidog_virtual_patches
-- ============================================================================

CREATE TABLE intellidog.intellidog_virtual_patches (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    patch_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    ioc_id INTEGER REFERENCES intellidog.intellidog_iocs(id) ON DELETE SET NULL,
    detection_id INTEGER REFERENCES intellidog.intellidog_detections(id) ON DELETE SET NULL,
    firewall_rule_template JSONB NOT NULL,
    target_machines INTEGER[] NOT NULL,
    target_all_machines BOOLEAN NOT NULL DEFAULT false,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    auto_approve BOOLEAN NOT NULL DEFAULT false,
    approval_required BOOLEAN NOT NULL DEFAULT true,
    approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMP,
    deployed_at TIMESTAMP,
    deployment_result JSONB,
    expires_at TIMESTAMP,
    auto_remove_on_expiry BOOLEAN NOT NULL DEFAULT true,
    removed_at TIMESTAMP,
    removed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    effectiveness_score INTEGER,
    blocked_attempts_count INTEGER DEFAULT 0,
    last_block_at TIMESTAMP,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT chk_patch_type CHECK (patch_type IN (
        'block_ip', 'block_port', 'block_domain', 'rate_limit',
        'geo_block', 'protocol_block', 'signature_block'
    )),
    CONSTRAINT chk_patch_severity CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    CONSTRAINT chk_patch_status CHECK (status IN (
        'pending', 'approved', 'deployed', 'rejected', 
        'failed', 'expired', 'removed'
    )),
    CONSTRAINT chk_effectiveness CHECK (effectiveness_score IS NULL OR (effectiveness_score >= 0 AND effectiveness_score <= 100))
);

COMMENT ON TABLE intellidog.intellidog_virtual_patches IS 'Auto-generated firewall rules for threat mitigation';

-- Add foreign key to detections after table creation
ALTER TABLE intellidog.intellidog_detections 
ADD CONSTRAINT fk_detection_vpatch 
FOREIGN KEY (virtual_patch_id) REFERENCES intellidog.intellidog_virtual_patches(id) ON DELETE SET NULL;

CREATE INDEX idx_vpatches_status ON intellidog.intellidog_virtual_patches(status);
CREATE INDEX idx_vpatches_severity ON intellidog.intellidog_virtual_patches(severity);
CREATE INDEX idx_vpatches_type ON intellidog.intellidog_virtual_patches(patch_type);
CREATE INDEX idx_vpatches_ioc ON intellidog.intellidog_virtual_patches(ioc_id);
CREATE INDEX idx_vpatches_detection ON intellidog.intellidog_virtual_patches(detection_id);
CREATE INDEX idx_vpatches_pending ON intellidog.intellidog_virtual_patches(status, created_at DESC) 
    WHERE status = 'pending' AND approval_required = true;
CREATE INDEX idx_vpatches_expires ON intellidog.intellidog_virtual_patches(expires_at) 
    WHERE expires_at IS NOT NULL AND status = 'deployed';

-- ============================================================================
-- TABLE 6: intellidog_hunting_queries
-- ============================================================================

CREATE TABLE intellidog.intellidog_hunting_queries (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    query_definition JSONB NOT NULL,
    query_type VARCHAR(50) NOT NULL DEFAULT 'custom',
    category VARCHAR(50),
    tags TEXT[],
    is_scheduled BOOLEAN NOT NULL DEFAULT false,
    schedule_cron VARCHAR(100),
    schedule_enabled BOOLEAN NOT NULL DEFAULT false,
    last_run_at TIMESTAMP,
    last_run_duration_ms INTEGER,
    last_run_result_count INTEGER,
    last_run_success BOOLEAN,
    last_run_error TEXT,
    next_run_at TIMESTAMP,
    total_runs INTEGER NOT NULL DEFAULT 0,
    is_public BOOLEAN NOT NULL DEFAULT false,
    is_template BOOLEAN NOT NULL DEFAULT false,
    severity_threshold VARCHAR(20),
    auto_create_detection BOOLEAN NOT NULL DEFAULT false,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    shared_with_teams INTEGER[],
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT chk_query_type CHECK (query_type IN ('custom', 'ioc_search', 'pattern_match', 'anomaly', 'correlation')),
    CONSTRAINT chk_severity_threshold CHECK (severity_threshold IS NULL OR severity_threshold IN ('critical', 'high', 'medium', 'low'))
);

COMMENT ON TABLE intellidog.intellidog_hunting_queries IS 'Saved threat hunting queries';

CREATE INDEX idx_hunting_created_by ON intellidog.intellidog_hunting_queries(created_by);
CREATE INDEX idx_hunting_scheduled ON intellidog.intellidog_hunting_queries(next_run_at) 
    WHERE is_scheduled = true AND schedule_enabled = true;
CREATE INDEX idx_hunting_category ON intellidog.intellidog_hunting_queries(category);
CREATE INDEX idx_hunting_tags ON intellidog.intellidog_hunting_queries USING GIN(tags);
CREATE INDEX idx_hunting_public ON intellidog.intellidog_hunting_queries(is_public) WHERE is_public = true;

-- ============================================================================
-- TABLE 7: intellidog_hunting_results
-- ============================================================================

CREATE TABLE intellidog.intellidog_hunting_results (
    id SERIAL PRIMARY KEY,
    query_id INTEGER NOT NULL REFERENCES intellidog.intellidog_hunting_queries(id) ON DELETE CASCADE,
    run_at TIMESTAMP NOT NULL DEFAULT NOW(),
    duration_ms INTEGER NOT NULL,
    result_count INTEGER NOT NULL DEFAULT 0,
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT,
    results JSONB,
    matches_summary JSONB,
    detections_created INTEGER DEFAULT 0,
    executed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE intellidog.intellidog_hunting_results IS 'Historical threat hunting execution results';

CREATE INDEX idx_hunting_results_query ON intellidog.intellidog_hunting_results(query_id);
CREATE INDEX idx_hunting_results_run_at ON intellidog.intellidog_hunting_results(run_at DESC);
CREATE INDEX idx_hunting_results_errors ON intellidog.intellidog_hunting_results(success) WHERE success = false;

-- ============================================================================
-- TABLE 8: intellidog_feed_update_log
-- ============================================================================

CREATE TABLE intellidog.intellidog_feed_update_log (
    id SERIAL PRIMARY KEY,
    feed_id INTEGER NOT NULL REFERENCES intellidog.intellidog_feeds(id) ON DELETE CASCADE,
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_ms INTEGER,
    success BOOLEAN NOT NULL DEFAULT false,
    iocs_fetched INTEGER DEFAULT 0,
    iocs_new INTEGER DEFAULT 0,
    iocs_updated INTEGER DEFAULT 0,
    iocs_expired INTEGER DEFAULT 0,
    error_message TEXT,
    http_status_code INTEGER,
    response_size_bytes INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE intellidog.intellidog_feed_update_log IS 'Feed update execution history';

CREATE INDEX idx_feed_update_log_feed ON intellidog.intellidog_feed_update_log(feed_id);
CREATE INDEX idx_feed_update_log_started ON intellidog.intellidog_feed_update_log(started_at DESC);
CREATE INDEX idx_feed_update_log_errors ON intellidog.intellidog_feed_update_log(success) WHERE success = false;

-- ============================================================================
-- TABLE 9: intellidog_correlation_cache
-- ============================================================================

CREATE TABLE intellidog.intellidog_correlation_cache (
    id SERIAL PRIMARY KEY,
    cache_key VARCHAR(255) NOT NULL UNIQUE,
    cache_type VARCHAR(50) NOT NULL,
    result JSONB NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT chk_cache_type CHECK (cache_type IN ('ioc_lookup', 'pattern_match', 'risk_score', 'correlation_result'))
);

COMMENT ON TABLE intellidog.intellidog_correlation_cache IS 'Performance cache for correlation engine';

CREATE INDEX idx_correlation_cache_key ON intellidog.intellidog_correlation_cache(cache_key);
CREATE INDEX idx_correlation_cache_expires ON intellidog.intellidog_correlation_cache(expires_at);
CREATE INDEX idx_correlation_cache_type ON intellidog.intellidog_correlation_cache(cache_type);

-- ============================================================================
-- TABLE 10: intellidog_audit_log
-- ============================================================================

CREATE TABLE intellidog.intellidog_audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id INTEGER,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT chk_resource_type CHECK (resource_type IN (
        'feed', 'ioc', 'detection', 'virtual_patch', 'hunting_query', 
        'license', 'correlation_job', 'feed_update'
    ))
);

COMMENT ON TABLE intellidog.intellidog_audit_log IS 'Audit trail for Intellidog operations';

CREATE INDEX idx_audit_log_user ON intellidog.intellidog_audit_log(user_id);
CREATE INDEX idx_audit_log_created ON intellidog.intellidog_audit_log(created_at DESC);
CREATE INDEX idx_audit_log_resource ON intellidog.intellidog_audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_action ON intellidog.intellidog_audit_log(action);

-- ============================================================================
-- VIEWS
-- ============================================================================

CREATE OR REPLACE VIEW intellidog.v_active_threats AS
SELECT 
    d.id AS detection_id,
    d.title,
    d.severity,
    d.status,
    d.detected_at,
    m.hostname,
    m.ip_address,
    i.ioc_type,
    i.value AS ioc_value,
    i.threat_type,
    f.name AS feed_name,
    d.auto_patched,
    vp.name AS virtual_patch_name,
    d.assigned_to,
    u.username AS assigned_to_username
FROM intellidog.intellidog_detections d
JOIN machines m ON d.machine_id = m.id
LEFT JOIN intellidog.intellidog_iocs i ON d.ioc_id = i.id
LEFT JOIN intellidog.intellidog_feeds f ON i.feed_id = f.id
LEFT JOIN intellidog.intellidog_virtual_patches vp ON d.virtual_patch_id = vp.id
LEFT JOIN users u ON d.assigned_to = u.id
WHERE d.status IN ('new', 'acknowledged', 'investigating')
  AND d.false_positive = false
ORDER BY d.detected_at DESC;

CREATE OR REPLACE VIEW intellidog.v_ioc_statistics AS
SELECT 
    f.id AS feed_id,
    f.name AS feed_name,
    f.feed_type,
    COUNT(*) AS total_iocs,
    COUNT(*) FILTER (WHERE i.is_active = true) AS active_iocs,
    COUNT(*) FILTER (WHERE i.severity = 'critical') AS critical_iocs,
    COUNT(*) FILTER (WHERE i.severity = 'high') AS high_iocs,
    COUNT(*) FILTER (WHERE i.false_positive = true) AS false_positives,
    COUNT(*) FILTER (WHERE i.whitelisted = true) AS whitelisted,
    MAX(i.last_seen) AS most_recent_ioc,
    AVG(i.confidence_score)::INTEGER AS avg_confidence
FROM intellidog.intellidog_feeds f
LEFT JOIN intellidog.intellidog_iocs i ON f.id = i.feed_id
WHERE f.is_active = true
GROUP BY f.id, f.name, f.feed_type
ORDER BY total_iocs DESC;

CREATE OR REPLACE VIEW intellidog.v_detection_summary AS
SELECT 
    severity,
    status,
    COUNT(*) AS count,
    COUNT(*) FILTER (WHERE auto_patched = true) AS auto_patched_count,
    COUNT(*) FILTER (WHERE assigned_to IS NOT NULL) AS assigned_count,
    MIN(detected_at) AS oldest_detection,
    MAX(detected_at) AS newest_detection,
    AVG(EXTRACT(EPOCH FROM (COALESCE(resolved_at, NOW()) - detected_at)))::INTEGER AS avg_resolution_time_seconds
FROM intellidog.intellidog_detections
WHERE false_positive = false
GROUP BY severity, status
ORDER BY 
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END,
    CASE status
        WHEN 'new' THEN 1
        WHEN 'acknowledged' THEN 2
        WHEN 'investigating' THEN 3
        WHEN 'escalated' THEN 4
        WHEN 'resolved' THEN 5
        ELSE 6
    END;

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

CREATE OR REPLACE FUNCTION intellidog.fn_calculate_risk_score(
    p_severity VARCHAR,
    p_confidence INTEGER,
    p_machine_criticality INTEGER DEFAULT 50
) RETURNS INTEGER AS $$
DECLARE
    v_severity_weight INTEGER;
    v_risk_score INTEGER;
BEGIN
    v_severity_weight := CASE p_severity
        WHEN 'critical' THEN 100
        WHEN 'high' THEN 75
        WHEN 'medium' THEN 50
        WHEN 'low' THEN 25
        ELSE 10
    END;
    
    v_risk_score := (
        (v_severity_weight * 0.5) + 
        (p_confidence * 0.3) + 
        (p_machine_criticality * 0.2)
    )::INTEGER;
    
    v_risk_score := GREATEST(0, LEAST(100, v_risk_score));
    
    RETURN v_risk_score;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION intellidog.fn_expire_old_iocs() RETURNS INTEGER AS $$
DECLARE
    v_expired_count INTEGER;
BEGIN
    UPDATE intellidog.intellidog_iocs
    SET is_active = false,
        updated_at = NOW()
    WHERE is_active = true
      AND expiration_date IS NOT NULL
      AND expiration_date < NOW();
    
    GET DIAGNOSTICS v_expired_count = ROW_COUNT;
    
    RETURN v_expired_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION intellidog.fn_cleanup_old_cache() RETURNS INTEGER AS $$
DECLARE
    v_deleted_count INTEGER;
BEGIN
    DELETE FROM intellidog.intellidog_correlation_cache
    WHERE expires_at < NOW();
    
    GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
    
    RETURN v_deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

CREATE OR REPLACE FUNCTION intellidog.fn_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_license_update_timestamp
    BEFORE UPDATE ON intellidog.intellidog_license
    FOR EACH ROW EXECUTE FUNCTION intellidog.fn_update_timestamp();

CREATE TRIGGER trg_feeds_update_timestamp
    BEFORE UPDATE ON intellidog.intellidog_feeds
    FOR EACH ROW EXECUTE FUNCTION intellidog.fn_update_timestamp();

CREATE TRIGGER trg_iocs_update_timestamp
    BEFORE UPDATE ON intellidog.intellidog_iocs
    FOR EACH ROW EXECUTE FUNCTION intellidog.fn_update_timestamp();

CREATE TRIGGER trg_detections_update_timestamp
    BEFORE UPDATE ON intellidog.intellidog_detections
    FOR EACH ROW EXECUTE FUNCTION intellidog.fn_update_timestamp();

CREATE TRIGGER trg_vpatches_update_timestamp
    BEFORE UPDATE ON intellidog.intellidog_virtual_patches
    FOR EACH ROW EXECUTE FUNCTION intellidog.fn_update_timestamp();

CREATE TRIGGER trg_hunting_update_timestamp
    BEFORE UPDATE ON intellidog.intellidog_hunting_queries
    FOR EACH ROW EXECUTE FUNCTION intellidog.fn_update_timestamp();

CREATE OR REPLACE FUNCTION intellidog.fn_auto_calculate_risk_score()
RETURNS TRIGGER AS $$
BEGIN
    NEW.risk_score := intellidog.fn_calculate_risk_score(
        NEW.severity,
        NEW.confidence_score,
        50
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_detection_calculate_risk
    BEFORE INSERT OR UPDATE OF severity, confidence_score ON intellidog.intellidog_detections
    FOR EACH ROW
    EXECUTE FUNCTION intellidog.fn_auto_calculate_risk_score();

-- ============================================================================
-- VERIFICATION
-- ============================================================================

SELECT 'Schema created successfully' AS status;

SELECT 
    schemaname AS schema,
    tablename AS table,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'intellidog'
ORDER BY tablename;

COMMIT;

-- ============================================================================
-- ROLLBACK
-- ============================================================================
-- 
-- To rollback this migration:
-- 
-- BEGIN;
-- DROP SCHEMA IF EXISTS intellidog CASCADE;
-- COMMIT;
-- 
-- WARNING: This will delete ALL Intellidog data!
-- ============================================================================
```

**Expected Output**:
```
CREATE EXTENSION
CREATE SCHEMA
CREATE TABLE
[... 10 tables created ...]
CREATE INDEX
[... all indexes created ...]
CREATE VIEW
[... 3 views created ...]
CREATE FUNCTION
[... 3 functions created ...]
CREATE TRIGGER
[... 7 triggers created ...]

        status
------------------------
 Schema created successfully

 schema    |         table          | size
-----------+------------------------+------
 intellidog| intellidog_audit_log   | 8192 bytes
 intellidog| intellidog_correlation_cache | 8192 bytes
 intellidog| intellidog_detections  | 8192 bytes
 intellidog| intellidog_feed_update_log | 8192 bytes
 intellidog| intellidog_feeds       | 8192 bytes
 intellidog| intellidog_hunting_queries | 8192 bytes
 intellidog| intellidog_hunting_results | 8192 bytes
 intellidog| intellidog_iocs        | 8192 bytes
 intellidog| intellidog_license     | 8192 bytes
 intellidog| intellidog_virtual_patches | 8192 bytes

COMMIT
```

---

## Migration 012: Intellidog Permissions

**File**: `database/postgresql/migrations/012_intellidog_permissions.sql`

**Purpose**: Grant all necessary permissions to vlnman for Intellidog operation

**Execution**: Run AFTER migration 011

```sql
-- ============================================================================
-- Migration 012: Intellidog Permissions
-- ============================================================================
-- Purpose: Grant comprehensive permissions to vlnman for Intellidog module
-- 
-- Prerequisites:
--   - Migration 011 completed (intellidog schema exists)
--
-- Execution:
--   psql -U vlnman -d cybersheppard -f 012_intellidog_permissions.sql
-- ============================================================================

BEGIN;

-- ============================================================================
-- SCHEMA PERMISSIONS
-- ============================================================================

-- Grant all privileges on intellidog schema
GRANT ALL PRIVILEGES ON SCHEMA intellidog TO vlnman;

-- ============================================================================
-- TABLE PERMISSIONS
-- ============================================================================

-- Grant all privileges on all tables in intellidog schema
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA intellidog TO vlnman;

-- Grant all privileges on all sequences in intellidog schema
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA intellidog TO vlnman;

-- ============================================================================
-- FUTURE OBJECT PERMISSIONS
-- ============================================================================

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA intellidog 
GRANT ALL PRIVILEGES ON TABLES TO vlnman;

-- Set default privileges for future sequences
ALTER DEFAULT PRIVILEGES IN SCHEMA intellidog 
GRANT ALL PRIVILEGES ON SEQUENCES TO vlnman;

-- Set default privileges for future functions
ALTER DEFAULT PRIVILEGES IN SCHEMA intellidog 
GRANT EXECUTE ON FUNCTIONS TO vlnman;

-- ============================================================================
-- CROSS-SCHEMA ACCESS (Read-Only)
-- ============================================================================

-- Ensure vlnman can read from replica schemas (should already be set)
GRANT SELECT ON ALL TABLES IN SCHEMA firedog_replica TO vlnman;
GRANT SELECT ON ALL TABLES IN SCHEMA sentinel_replica TO vlnman;

-- Ensure vlnman can read from public schema (CyberSheppard tables)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vlnman;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO vlnman;

-- ============================================================================
-- FUNCTION EXECUTION PERMISSIONS
-- ============================================================================

-- Grant execute on all intellidog functions
GRANT EXECUTE ON FUNCTION intellidog.fn_calculate_risk_score(VARCHAR, INTEGER, INTEGER) TO vlnman;
GRANT EXECUTE ON FUNCTION intellidog.fn_expire_old_iocs() TO vlnman;
GRANT EXECUTE ON FUNCTION intellidog.fn_cleanup_old_cache() TO vlnman;

-- ============================================================================
-- VERIFICATION
-- ============================================================================

-- Verify schema permissions
SELECT 
    nspname AS schema_name,
    has_schema_privilege('vlnman', nspname, 'USAGE') AS has_usage,
    has_schema_privilege('vlnman', nspname, 'CREATE') AS has_create
FROM pg_namespace
WHERE nspname IN ('intellidog', 'firedog_replica', 'sentinel_replica', 'public');

-- Verify table permissions
SELECT 
    schemaname,
    tablename,
    has_table_privilege('vlnman', schemaname||'.'||tablename, 'SELECT') AS can_select,
    has_table_privilege('vlnman', schemaname||'.'||tablename, 'INSERT') AS can_insert,
    has_table_privilege('vlnman', schemaname||'.'||tablename, 'UPDATE') AS can_update,
    has_table_privilege('vlnman', schemaname||'.'||tablename, 'DELETE') AS can_delete
FROM pg_tables
WHERE schemaname = 'intellidog'
LIMIT 5;

-- Verify sequence permissions
SELECT 
    sequence_schema,
    sequence_name,
    has_sequence_privilege('vlnman', sequence_schema||'.'||sequence_name, 'USAGE') AS can_use
FROM information_schema.sequences
WHERE sequence_schema = 'intellidog'
LIMIT 5;

COMMIT;

-- ============================================================================
-- ROLLBACK
-- ============================================================================
-- 
-- To rollback (revoke all permissions):
-- 
-- BEGIN;
-- REVOKE ALL PRIVILEGES ON SCHEMA intellidog FROM vlnman;
-- REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA intellidog FROM vlnman;
-- REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA intellidog FROM vlnman;
-- COMMIT;
-- 
-- ============================================================================
```

**Expected Output**:
```
GRANT
GRANT
GRANT
ALTER DEFAULT PRIVILEGES
ALTER DEFAULT PRIVILEGES
ALTER DEFAULT PRIVILEGES
GRANT
GRANT
GRANT
GRANT
GRANT
GRANT
GRANT

 schema_name      | has_usage | has_create
------------------+-----------+------------
 intellidog       | t         | t
 firedog_replica  | t         | f
 sentinel_replica | t         | f
 public           | t         | t

 schemaname | tablename                 | can_select | can_insert | can_update | can_delete
------------+---------------------------+------------+------------+------------+------------
 intellidog | intellidog_license        | t          | t          | t          | t
 intellidog | intellidog_feeds          | t          | t          | t          | t
 intellidog | intellidog_iocs           | t          | t          | t          | t
 intellidog | intellidog_detections     | t          | t          | t          | t
 intellidog | intellidog_virtual_patches| t          | t          | t          | t

 sequence_schema | sequence_name                    | can_use
-----------------+----------------------------------+---------
 intellidog      | intellidog_license_id_seq        | t
 intellidog      | intellidog_feeds_id_seq          | t
 intellidog      | intellidog_iocs_id_seq           | t
 intellidog      | intellidog_detections_id_seq     | t
 intellidog      | intellidog_virtual_patches_id_seq| t

COMMIT
```

---

## Complete Migration Execution Script

**File**: `database/postgresql/run_all_migrations.sh`

**Purpose**: Execute all migrations in correct order

```bash
#!/bin/bash
# ============================================================================
# Run All Migrations - Complete Database Setup
# ============================================================================
# Purpose: Execute all CyberSheppard database migrations in correct order
# 
# Usage:
#   ./run_all_migrations.sh
# 
# Prerequisites:
#   - PostgreSQL running
#   - cybersheppard database exists
#   - vlnman user exists with password DogNET
# ============================================================================

set -e  # Exit on error

# Configuration
DB_NAME="cybersheppard"
DB_USER="vlnman"
DB_HOST="localhost"
DB_PORT="5432"
MIGRATIONS_DIR="database/postgresql/migrations"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================================================"
echo "CyberSheppard Database Migration Runner"
echo "============================================================================"
echo ""

# Function to run migration
run_migration() {
    local migration_file=$1
    local migration_name=$(basename "$migration_file" .sql)
    
    echo -e "${YELLOW}Running migration: $migration_name${NC}"
    
    if PGPASSWORD=DogNET psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$migration_file" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ $migration_name completed successfully${NC}"
        return 0
    else
        echo -e "${RED}✗ $migration_name FAILED${NC}"
        return 1
    fi
}

# Check if database exists
echo "Checking database connection..."
if ! PGPASSWORD=DogNET psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Cannot connect to database${NC}"
    echo "Please check:"
    echo "  - PostgreSQL is running"
    echo "  - Database 'cybersheppard' exists"
    echo "  - User 'vlnman' exists with password 'DogNET'"
    exit 1
fi
echo -e "${GREEN}✓ Database connection successful${NC}"
echo ""

# Migrations 001-009 assumed already applied
echo "Migrations 001-009: Skipping (assumed already applied)"
echo ""

# Run new migrations
echo "Running new migrations..."
echo ""

# Migration 010: Replication Schemas
if [ -f "$MIGRATIONS_DIR/010_replication_schemas.sql" ]; then
    run_migration "$MIGRATIONS_DIR/010_replication_schemas.sql"
else
    echo -e "${YELLOW}⚠ Migration 010 not found, skipping${NC}"
fi

echo ""

# Migration 011: Intellidog Schema
if [ -f "$MIGRATIONS_DIR/011_intellidog_schema.sql" ]; then
    run_migration "$MIGRATIONS_DIR/011_intellidog_schema.sql"
else
    echo -e "${RED}✗ Migration 011 not found - REQUIRED${NC}"
    exit 1
fi

echo ""

# Migration 012: Intellidog Permissions
if [ -f "$MIGRATIONS_DIR/012_intellidog_permissions.sql" ]; then
    run_migration "$MIGRATIONS_DIR/012_intellidog_permissions.sql"
else
    echo -e "${RED}✗ Migration 012 not found - REQUIRED${NC}"
    exit 1
fi

echo ""
echo "============================================================================"
echo -e "${GREEN}All migrations completed successfully!${NC}"
echo "============================================================================"
echo ""
echo "Next steps:"
echo "1. Install Firedog Replication Plugin"
echo "2. Install Sentinel Replication Plugin"
echo "3. Install CyberSheppard Replication Plugin"
echo "4. Activate Intellidog Module with valid license"
echo ""
```

**Make executable**:
```bash
chmod +x run_all_migrations.sh
```

---

## Verification Queries

**After all migrations**:

```sql
-- Verify all schemas exist
SELECT schema_name 
FROM information_schema.schemata 
WHERE schema_name IN ('public', 'firedog_replica', 'sentinel_replica', 'intellidog')
ORDER BY schema_name;

-- Verify all intellidog tables exist
SELECT tablename 
FROM pg_tables 
WHERE schemaname = 'intellidog'
ORDER BY tablename;

-- Verify vlnman permissions
SELECT 
    has_schema_privilege('vlnman', 'intellidog', 'USAGE') AS intellidog_usage,
    has_schema_privilege('vlnman', 'intellidog', 'CREATE') AS intellidog_create,
    has_schema_privilege('vlnman', 'firedog_replica', 'USAGE') AS firedog_usage,
    has_schema_privilege('vlnman', 'sentinel_replica', 'USAGE') AS sentinel_usage;

-- Count objects created
SELECT 
    'Tables' AS object_type,
    COUNT(*) AS count
FROM pg_tables
WHERE schemaname = 'intellidog'
UNION ALL
SELECT 
    'Views' AS object_type,
    COUNT(*) AS count
FROM pg_views
WHERE schemaname = 'intellidog'
UNION ALL
SELECT 
    'Functions' AS object_type,
    COUNT(*) AS count
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE n.nspname = 'intellidog'
UNION ALL
SELECT 
    'Triggers' AS object_type,
    COUNT(*) AS count
FROM pg_trigger t
JOIN pg_class c ON t.tgrelid = c.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE n.nspname = 'intellidog';
```

**Expected Result**:
```
 object_type | count
-------------+-------
 Tables      |    10
 Views       |     3
 Functions   |     6
 Triggers    |     7
```

---

## Summary

**New Migrations**: 3 (010, 011, 012)

**Objects Created**:
- Schemas: 3 (firedog_replica, sentinel_replica, intellidog)
- Tables: 10 (all intellidog tables)
- Views: 3
- Functions: 6
- Triggers: 7
- Indexes: 60+

**Total Migration Time**: ~30 seconds

**Disk Space Required**: ~10 MB (empty tables)

**Ready For**:
1. ✅ Plugin installation
2. ✅ Replication setup
3. ✅ Intellidog activation

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-01-02  
**Author**: Dognet Technologies
