# Intellidog Database Schema - Complete Specification

## Overview

Complete production-ready database schema for Intellidog threat intelligence module on CyberSheppard.

**Database**: `cybersheppard`  
**Schema**: `intellidog`  
**Owner**: `vlnman`  
**Access**: Read/Write for Intellidog module, Read-only for other schemas (firedog_replica, sentinel_replica)

---

## Schema Creation

```sql
-- Create intellidog schema
CREATE SCHEMA IF NOT EXISTS intellidog;

-- Grant permissions to vlnman
GRANT ALL PRIVILEGES ON SCHEMA intellidog TO vlnman;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA intellidog TO vlnman;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA intellidog TO vlnman;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA intellidog 
GRANT ALL PRIVILEGES ON TABLES TO vlnman;

ALTER DEFAULT PRIVILEGES IN SCHEMA intellidog 
GRANT ALL PRIVILEGES ON SEQUENCES TO vlnman;
```

---

## Tables

### 1. intellidog_license

**Purpose**: License management and validation

```sql
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
COMMENT ON COLUMN intellidog.intellidog_license.license_key IS 'Unique license key (INTL-XXXX-XXXX-XXXX-XXXX format)';
COMMENT ON COLUMN intellidog.intellidog_license.features IS 'JSON array of enabled features';
COMMENT ON COLUMN intellidog.intellidog_license.support_level IS 'Support tier: standard, professional, enterprise';
COMMENT ON COLUMN intellidog.intellidog_license.license_file_content IS 'Complete .lic file content with GPG signature';
COMMENT ON COLUMN intellidog.intellidog_license.gpg_signature_valid IS 'GPG signature verification result';

CREATE INDEX idx_license_key ON intellidog.intellidog_license(license_key);
CREATE INDEX idx_license_expires ON intellidog.intellidog_license(expires_at) WHERE is_active = true;
```

---

### 2. intellidog_feeds

**Purpose**: Threat intelligence feed sources

```sql
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

COMMENT ON TABLE intellidog.intellidog_feeds IS 'Threat intelligence feed sources configuration';
COMMENT ON COLUMN intellidog.intellidog_feeds.feed_type IS 'Type: misp, otx, stix, taxii, custom, csv, json';
COMMENT ON COLUMN intellidog.intellidog_feeds.api_key_encrypted IS 'Encrypted API key (Fernet encryption)';
COMMENT ON COLUMN intellidog.intellidog_feeds.additional_config IS 'Feed-specific configuration (JSON)';

CREATE INDEX idx_feeds_active ON intellidog.intellidog_feeds(is_active);
CREATE INDEX idx_feeds_next_update ON intellidog.intellidog_feeds(next_update_at) WHERE is_active = true AND auto_update = true;
CREATE INDEX idx_feeds_type ON intellidog.intellidog_feeds(feed_type);
```

---

### 3. intellidog_iocs

**Purpose**: Indicators of Compromise storage

```sql
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

COMMENT ON TABLE intellidog.intellidog_iocs IS 'Indicators of Compromise from all feeds';
COMMENT ON COLUMN intellidog.intellidog_iocs.value_hash IS 'SHA256 hash of value for fast lookups';
COMMENT ON COLUMN intellidog.intellidog_iocs.confidence_score IS 'Confidence level 0-100';
COMMENT ON COLUMN intellidog.intellidog_iocs.tlp_level IS 'Traffic Light Protocol level';
COMMENT ON COLUMN intellidog.intellidog_iocs.tags IS 'Array of classification tags';

CREATE INDEX idx_iocs_value_hash ON intellidog.intellidog_iocs(value_hash);
CREATE INDEX idx_iocs_type ON intellidog.intellidog_iocs(ioc_type);
CREATE INDEX idx_iocs_severity ON intellidog.intellidog_iocs(severity);
CREATE INDEX idx_iocs_active ON intellidog.intellidog_iocs(is_active) WHERE is_active = true;
CREATE INDEX idx_iocs_feed ON intellidog.intellidog_iocs(feed_id);
CREATE INDEX idx_iocs_threat_type ON intellidog.intellidog_iocs(threat_type);
CREATE INDEX idx_iocs_expiration ON intellidog.intellidog_iocs(expiration_date) WHERE expiration_date IS NOT NULL;
CREATE INDEX idx_iocs_last_seen ON intellidog.intellidog_iocs(last_seen DESC);

-- GIN index for array tags
CREATE INDEX idx_iocs_tags ON intellidog.intellidog_iocs USING GIN(tags);

-- Full-text search on value (for partial matching)
CREATE INDEX idx_iocs_value_trgm ON intellidog.intellidog_iocs USING GIN(value gin_trgm_ops);
```

---

### 4. intellidog_detections

**Purpose**: Threat detections from correlation engine

```sql
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
    virtual_patch_id INTEGER REFERENCES intellidog.intellidog_virtual_patches(id) ON DELETE SET NULL,
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
COMMENT ON COLUMN intellidog.intellidog_detections.source_data IS 'Original data that triggered detection (firewall log, vuln scan, etc)';
COMMENT ON COLUMN intellidog.intellidog_detections.correlation_context IS 'Additional context from correlation analysis';
COMMENT ON COLUMN intellidog.intellidog_detections.risk_score IS 'Calculated risk score based on severity, confidence, and impact';

CREATE INDEX idx_detections_machine ON intellidog.intellidog_detections(machine_id);
CREATE INDEX idx_detections_ioc ON intellidog.intellidog_detections(ioc_id);
CREATE INDEX idx_detections_status ON intellidog.intellidog_detections(status);
CREATE INDEX idx_detections_severity ON intellidog.intellidog_detections(severity);
CREATE INDEX idx_detections_type ON intellidog.intellidog_detections(detection_type);
CREATE INDEX idx_detections_detected_at ON intellidog.intellidog_detections(detected_at DESC);
CREATE INDEX idx_detections_assigned ON intellidog.intellidog_detections(assigned_to) WHERE assigned_to IS NOT NULL;
CREATE INDEX idx_detections_unresolved ON intellidog.intellidog_detections(status, detected_at DESC) 
    WHERE status IN ('new', 'acknowledged', 'investigating');
```

---

### 5. intellidog_virtual_patches

**Purpose**: Auto-generated firewall rules for threat mitigation

```sql
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
COMMENT ON COLUMN intellidog.intellidog_virtual_patches.firewall_rule_template IS 'Firedog-compatible rule definition (JSON)';
COMMENT ON COLUMN intellidog.intellidog_virtual_patches.target_machines IS 'Array of machine IDs to apply patch';
COMMENT ON COLUMN intellidog.intellidog_virtual_patches.effectiveness_score IS 'Calculated effectiveness based on blocked attempts';

CREATE INDEX idx_vpatches_status ON intellidog.intellidog_virtual_patches(status);
CREATE INDEX idx_vpatches_severity ON intellidog.intellidog_virtual_patches(severity);
CREATE INDEX idx_vpatches_type ON intellidog.intellidog_virtual_patches(patch_type);
CREATE INDEX idx_vpatches_ioc ON intellidog.intellidog_virtual_patches(ioc_id);
CREATE INDEX idx_vpatches_detection ON intellidog.intellidog_virtual_patches(detection_id);
CREATE INDEX idx_vpatches_pending ON intellidog.intellidog_virtual_patches(status, created_at DESC) 
    WHERE status = 'pending' AND approval_required = true;
CREATE INDEX idx_vpatches_expires ON intellidog.intellidog_virtual_patches(expires_at) 
    WHERE expires_at IS NOT NULL AND status = 'deployed';
```

---

### 6. intellidog_hunting_queries

**Purpose**: Saved threat hunting queries

```sql
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
COMMENT ON COLUMN intellidog.intellidog_hunting_queries.query_definition IS 'Query parameters and filters (JSON)';
COMMENT ON COLUMN intellidog.intellidog_hunting_queries.schedule_cron IS 'Cron expression for scheduled execution';
COMMENT ON COLUMN intellidog.intellidog_hunting_queries.auto_create_detection IS 'Automatically create detection for matches';

CREATE INDEX idx_hunting_created_by ON intellidog.intellidog_hunting_queries(created_by);
CREATE INDEX idx_hunting_scheduled ON intellidog.intellidog_hunting_queries(next_run_at) 
    WHERE is_scheduled = true AND schedule_enabled = true;
CREATE INDEX idx_hunting_category ON intellidog.intellidog_hunting_queries(category);
CREATE INDEX idx_hunting_tags ON intellidog.intellidog_hunting_queries USING GIN(tags);
CREATE INDEX idx_hunting_public ON intellidog.intellidog_hunting_queries(is_public) WHERE is_public = true;
```

---

### 7. intellidog_hunting_results

**Purpose**: Results from threat hunting query executions

```sql
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

COMMENT ON TABLE intellidog.intellidog_hunting_results IS 'Historical results from threat hunting executions';
COMMENT ON COLUMN intellidog.intellidog_hunting_results.results IS 'Full result set (limited to top 1000 matches)';
COMMENT ON COLUMN intellidog.intellidog_hunting_results.matches_summary IS 'Summary statistics of matches';

CREATE INDEX idx_hunting_results_query ON intellidog.intellidog_hunting_results(query_id);
CREATE INDEX idx_hunting_results_run_at ON intellidog.intellidog_hunting_results(run_at DESC);
CREATE INDEX idx_hunting_results_errors ON intellidog.intellidog_hunting_results(success) WHERE success = false;
```

---

### 8. intellidog_feed_update_log

**Purpose**: Feed update history and debugging

```sql
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
```

---

### 9. intellidog_correlation_cache

**Purpose**: Cache for expensive correlation calculations

```sql
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
COMMENT ON COLUMN intellidog.intellidog_correlation_cache.cache_key IS 'Unique cache key (hash of input parameters)';

CREATE INDEX idx_correlation_cache_key ON intellidog.intellidog_correlation_cache(cache_key);
CREATE INDEX idx_correlation_cache_expires ON intellidog.intellidog_correlation_cache(expires_at);
CREATE INDEX idx_correlation_cache_type ON intellidog.intellidog_correlation_cache(cache_type);
```

---

### 10. intellidog_audit_log

**Purpose**: Audit trail for Intellidog operations

```sql
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

COMMENT ON TABLE intellidog.intellidog_audit_log IS 'Audit trail for all Intellidog operations';

CREATE INDEX idx_audit_log_user ON intellidog.intellidog_audit_log(user_id);
CREATE INDEX idx_audit_log_created ON intellidog.intellidog_audit_log(created_at DESC);
CREATE INDEX idx_audit_log_resource ON intellidog.intellidog_audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_action ON intellidog.intellidog_audit_log(action);
```

---

## Views

### v_active_threats

**Purpose**: Current active threats across all sources

```sql
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

COMMENT ON VIEW intellidog.v_active_threats IS 'Current active unresolved threats';
```

---

### v_ioc_statistics

**Purpose**: IOC statistics by feed and type

```sql
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

COMMENT ON VIEW intellidog.v_ioc_statistics IS 'IOC statistics aggregated by feed';
```

---

### v_detection_summary

**Purpose**: Detection summary by severity and status

```sql
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

COMMENT ON VIEW intellidog.v_detection_summary IS 'Detection summary statistics';
```

---

## Functions

### fn_calculate_risk_score

**Purpose**: Calculate risk score for detections

```sql
CREATE OR REPLACE FUNCTION intellidog.fn_calculate_risk_score(
    p_severity VARCHAR,
    p_confidence INTEGER,
    p_machine_criticality INTEGER DEFAULT 50
) RETURNS INTEGER AS $$
DECLARE
    v_severity_weight INTEGER;
    v_risk_score INTEGER;
BEGIN
    -- Severity weights
    v_severity_weight := CASE p_severity
        WHEN 'critical' THEN 100
        WHEN 'high' THEN 75
        WHEN 'medium' THEN 50
        WHEN 'low' THEN 25
        ELSE 10
    END;
    
    -- Calculate risk score (weighted average)
    v_risk_score := (
        (v_severity_weight * 0.5) + 
        (p_confidence * 0.3) + 
        (p_machine_criticality * 0.2)
    )::INTEGER;
    
    -- Clamp to 0-100
    v_risk_score := GREATEST(0, LEAST(100, v_risk_score));
    
    RETURN v_risk_score;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION intellidog.fn_calculate_risk_score IS 'Calculate risk score based on severity, confidence, and machine criticality';
```

---

### fn_expire_old_iocs

**Purpose**: Expire old IOCs automatically

```sql
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

COMMENT ON FUNCTION intellidog.fn_expire_old_iocs IS 'Expire IOCs past their expiration date';
```

---

### fn_cleanup_old_cache

**Purpose**: Cleanup expired cache entries

```sql
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

COMMENT ON FUNCTION intellidog.fn_cleanup_old_cache IS 'Delete expired cache entries';
```

---

## Triggers

### trg_update_timestamp

**Purpose**: Auto-update updated_at timestamp

```sql
CREATE OR REPLACE FUNCTION intellidog.fn_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to all tables with updated_at column
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
```

---

### trg_calculate_detection_risk_score

**Purpose**: Auto-calculate risk score on detection insert/update

```sql
CREATE OR REPLACE FUNCTION intellidog.fn_auto_calculate_risk_score()
RETURNS TRIGGER AS $$
BEGIN
    -- Get machine criticality (default to 50 if not set)
    -- Assuming machines table has a criticality column, otherwise use 50
    NEW.risk_score := intellidog.fn_calculate_risk_score(
        NEW.severity,
        NEW.confidence_score,
        50  -- Default machine criticality
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_detection_calculate_risk
    BEFORE INSERT OR UPDATE OF severity, confidence_score ON intellidog.intellidog_detections
    FOR EACH ROW
    EXECUTE FUNCTION intellidog.fn_auto_calculate_risk_score();
```

---

## Maintenance Jobs

### Daily Maintenance

```sql
-- Run daily at 02:00
-- Expire old IOCs
SELECT intellidog.fn_expire_old_iocs();

-- Cleanup old cache
SELECT intellidog.fn_cleanup_old_cache();

-- Delete old hunting results (keep 90 days)
DELETE FROM intellidog.intellidog_hunting_results 
WHERE created_at < NOW() - INTERVAL '90 days';

-- Delete old feed update logs (keep 30 days)
DELETE FROM intellidog.intellidog_feed_update_log 
WHERE created_at < NOW() - INTERVAL '30 days';

-- Vacuum analyze
VACUUM ANALYZE intellidog.intellidog_iocs;
VACUUM ANALYZE intellidog.intellidog_detections;
VACUUM ANALYZE intellidog.intellidog_correlation_cache;
```

---

## Performance Optimization

### Partitioning Strategy (for large deployments)

```sql
-- Partition intellidog_detections by month
CREATE TABLE intellidog.intellidog_detections_2025_01 
PARTITION OF intellidog.intellidog_detections
FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE TABLE intellidog.intellidog_detections_2025_02 
PARTITION OF intellidog.intellidog_detections
FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');

-- ... continue for each month
```

### Statistics Configuration

```sql
-- Increase statistics target for frequently queried columns
ALTER TABLE intellidog.intellidog_iocs ALTER COLUMN value_hash SET STATISTICS 1000;
ALTER TABLE intellidog.intellidog_iocs ALTER COLUMN ioc_type SET STATISTICS 1000;
ALTER TABLE intellidog.intellidog_detections ALTER COLUMN machine_id SET STATISTICS 1000;
ALTER TABLE intellidog.intellidog_detections ALTER COLUMN status SET STATISTICS 1000;
```

---

## Summary

**Total Tables**: 10
**Total Views**: 3
**Total Functions**: 3
**Total Triggers**: 7

**Estimated Storage** (for 100 machines, 1 year):
- IOCs: ~500 MB (100K IOCs)
- Detections: ~200 MB (50K detections)
- Virtual Patches: ~50 MB (5K patches)
- Hunting Results: ~100 MB
- Audit Log: ~150 MB
- **Total**: ~1 GB

**Performance Targets**:
- IOC lookup: < 10ms
- Detection creation: < 50ms
- Dashboard load: < 500ms
- Correlation job: < 5 minutes (100K IOCs)

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-01-02  
**Author**: Dognet Technologies
