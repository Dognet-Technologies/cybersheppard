-- ============================================================================
-- CYBERSHEPPARD - Plugin Management System
-- ============================================================================

-- Plugin repositories (sources for plugins)
CREATE TABLE IF NOT EXISTS plugin_repositories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    url VARCHAR(500) NOT NULL UNIQUE,
    repository_type VARCHAR(50) DEFAULT 'git', -- git, github, gitlab
    branch VARCHAR(100) DEFAULT 'main',

    -- Trust level
    trust_level VARCHAR(50) NOT NULL, -- official, community, private
    is_official BOOLEAN DEFAULT false,
    verified_owner BOOLEAN DEFAULT false,

    -- Auto-update settings
    auto_fetch BOOLEAN DEFAULT true,
    fetch_interval_hours INTEGER DEFAULT 24,
    last_fetched_at TIMESTAMP,
    fetch_status VARCHAR(50), -- success, error, pending
    last_fetch_error TEXT,

    -- Security
    require_checksum BOOLEAN DEFAULT true,
    allowed_stability_levels TEXT[] DEFAULT ARRAY['stable'], -- stable, unstable

    -- Metadata
    description TEXT,
    owner_name VARCHAR(200),
    contact_email VARCHAR(200),

    added_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    CONSTRAINT valid_trust_level CHECK (trust_level IN ('official', 'community', 'private'))
);

-- Plugin registry (available plugins from all repositories)
CREATE TABLE IF NOT EXISTS plugin_registry (
    id SERIAL PRIMARY KEY,
    repository_id INTEGER REFERENCES plugin_repositories(id) ON DELETE CASCADE,

    -- Plugin metadata (from manifest.json)
    plugin_name VARCHAR(200) NOT NULL,
    version VARCHAR(50) NOT NULL,
    stato VARCHAR(50), -- stable, unstable
    stability_level VARCHAR(50), -- alpha, beta, complete
    description TEXT,
    owner VARCHAR(200),
    language VARCHAR(50), -- python, rust, javascript
    runtime_version VARCHAR(50), -- python3.11, node18, etc
    quality VARCHAR(50), -- scarsa, buona, ottima, eccellente
    license VARCHAR(100),

    -- Compatibility
    min_cybersheppard_version VARCHAR(50),
    max_cybersheppard_version VARCHAR(50),

    -- Security
    checksum_sha256 VARCHAR(64),
    signature TEXT,

    -- Permissions required
    permissions JSONB DEFAULT '[]'::jsonb,

    -- Resource limits
    max_memory_mb INTEGER DEFAULT 128,
    max_cpu_percent INTEGER DEFAULT 10,
    max_execution_time_ms INTEGER DEFAULT 5000,

    -- Events
    subscribes_to_events TEXT[],
    publishes_events TEXT[],

    -- Dependencies
    dependencies JSONB DEFAULT '{}'::jsonb,

    -- Files and URLs
    manifest_url TEXT,
    download_url TEXT,
    documentation_url TEXT,
    repository_url TEXT,

    -- Configuration schema
    configuration_schema JSONB,

    -- Metadata
    metadata JSONB,
    fetched_at TIMESTAMP DEFAULT NOW(),
    is_available BOOLEAN DEFAULT true,

    UNIQUE(repository_id, plugin_name, version)
);

-- Installed plugins (locally installed and configured)
CREATE TABLE IF NOT EXISTS installed_plugins (
    id SERIAL PRIMARY KEY,
    registry_id INTEGER REFERENCES plugin_registry(id),

    plugin_name VARCHAR(200) NOT NULL,
    version VARCHAR(50) NOT NULL,
    installed_path TEXT,

    -- Status
    status VARCHAR(50) DEFAULT 'installed', -- installed, enabled, disabled, error, updating
    is_enabled BOOLEAN DEFAULT false,

    -- Configuration (per-plugin settings)
    configuration JSONB DEFAULT '{}'::jsonb,

    -- Runtime information
    process_id INTEGER,
    last_started_at TIMESTAMP,
    last_stopped_at TIMESTAMP,
    last_execution_at TIMESTAMP,

    -- Statistics
    execution_count BIGINT DEFAULT 0,
    error_count BIGINT DEFAULT 0,
    success_count BIGINT DEFAULT 0,
    last_error TEXT,
    last_error_at TIMESTAMP,

    -- Performance metrics
    avg_execution_time_ms DECIMAL(10,2),
    max_execution_time_ms DECIMAL(10,2),
    min_execution_time_ms DECIMAL(10,2),
    total_events_processed BIGINT DEFAULT 0,

    -- Resource usage
    avg_memory_mb DECIMAL(10,2),
    max_memory_mb DECIMAL(10,2),
    avg_cpu_percent DECIMAL(5,2),
    max_cpu_percent DECIMAL(5,2),

    installed_by INTEGER REFERENCES users(id),
    installed_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(plugin_name, version)
);

-- Plugin execution log (for debugging and monitoring)
CREATE TABLE IF NOT EXISTS plugin_executions (
    id BIGSERIAL PRIMARY KEY,
    plugin_id INTEGER REFERENCES installed_plugins(id) ON DELETE CASCADE,

    event_type VARCHAR(200),
    event_data JSONB,

    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    execution_time_ms INTEGER,

    status VARCHAR(50), -- running, success, error, timeout
    result JSONB,
    error_message TEXT,
    stack_trace TEXT,

    -- Resources used
    memory_mb DECIMAL(10,2),
    cpu_percent DECIMAL(5,2),

    created_at TIMESTAMP DEFAULT NOW()
);

-- Plugin permissions (approved permissions per plugin)
CREATE TABLE IF NOT EXISTS plugin_permissions (
    id SERIAL PRIMARY KEY,
    plugin_id INTEGER REFERENCES installed_plugins(id) ON DELETE CASCADE,

    permission VARCHAR(200) NOT NULL,
    granted BOOLEAN DEFAULT false,
    granted_by INTEGER REFERENCES users(id),
    granted_at TIMESTAMP,

    notes TEXT,

    created_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(plugin_id, permission)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_plugin_repos_trust_level ON plugin_repositories(trust_level);
CREATE INDEX IF NOT EXISTS idx_plugin_repos_official ON plugin_repositories(is_official);
CREATE INDEX IF NOT EXISTS idx_plugin_registry_repo ON plugin_registry(repository_id);
CREATE INDEX IF NOT EXISTS idx_plugin_registry_name ON plugin_registry(plugin_name);
CREATE INDEX IF NOT EXISTS idx_plugin_registry_language ON plugin_registry(language);
CREATE INDEX IF NOT EXISTS idx_plugin_registry_stato ON plugin_registry(stato);
CREATE INDEX IF NOT EXISTS idx_installed_plugins_status ON installed_plugins(status);
CREATE INDEX IF NOT EXISTS idx_installed_plugins_enabled ON installed_plugins(is_enabled);
CREATE INDEX IF NOT EXISTS idx_plugin_executions_plugin ON plugin_executions(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_executions_status ON plugin_executions(status);
CREATE INDEX IF NOT EXISTS idx_plugin_executions_created ON plugin_executions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_plugin_permissions_plugin ON plugin_permissions(plugin_id);

-- Views for easy querying

-- Active plugins (enabled and running)
CREATE OR REPLACE VIEW active_plugins AS
SELECT
    ip.id,
    ip.plugin_name,
    ip.version,
    ip.status,
    ip.configuration,
    ip.last_execution_at,
    ip.execution_count,
    ip.error_count,
    ip.avg_execution_time_ms,
    pr.plugin_name as registry_name,
    pr.description,
    pr.language,
    pr.quality,
    repo.name as repository_name,
    repo.trust_level
FROM installed_plugins ip
LEFT JOIN plugin_registry pr ON ip.registry_id = pr.id
LEFT JOIN plugin_repositories repo ON pr.repository_id = repo.id
WHERE ip.is_enabled = true
  AND ip.status = 'enabled'
ORDER BY ip.last_execution_at DESC;

-- Available plugins (from registry, not yet installed)
CREATE OR REPLACE VIEW available_plugins AS
SELECT
    pr.id,
    pr.plugin_name,
    pr.version,
    pr.description,
    pr.language,
    pr.quality,
    pr.stability_level,
    pr.stato,
    pr.license,
    pr.permissions,
    pr.download_url,
    pr.documentation_url,
    repo.name as repository_name,
    repo.trust_level,
    repo.is_official,
    CASE
        WHEN ip.id IS NOT NULL THEN true
        ELSE false
    END as is_installed
FROM plugin_registry pr
LEFT JOIN plugin_repositories repo ON pr.repository_id = repo.id
LEFT JOIN installed_plugins ip ON pr.plugin_name = ip.plugin_name AND pr.version = ip.version
WHERE pr.is_available = true
ORDER BY
    repo.is_official DESC,
    pr.quality DESC,
    pr.plugin_name ASC;

-- Plugin statistics summary
CREATE OR REPLACE VIEW plugin_stats_summary AS
SELECT
    ip.id,
    ip.plugin_name,
    ip.version,
    ip.status,
    ip.execution_count,
    ip.error_count,
    ip.success_count,
    CASE
        WHEN ip.execution_count > 0
        THEN ROUND((ip.success_count::decimal / ip.execution_count::decimal) * 100, 2)
        ELSE 0
    END as success_rate_percent,
    ip.avg_execution_time_ms,
    ip.total_events_processed,
    ip.avg_memory_mb,
    ip.avg_cpu_percent,
    COUNT(pe.id) as total_executions_logged,
    COUNT(pe.id) FILTER (WHERE pe.status = 'error') as recent_errors,
    MAX(pe.created_at) as last_execution_logged
FROM installed_plugins ip
LEFT JOIN plugin_executions pe ON ip.id = pe.plugin_id
    AND pe.created_at > NOW() - INTERVAL '24 hours'
GROUP BY ip.id, ip.plugin_name, ip.version, ip.status,
         ip.execution_count, ip.error_count, ip.success_count,
         ip.avg_execution_time_ms, ip.total_events_processed,
         ip.avg_memory_mb, ip.avg_cpu_percent;

-- Triggers

-- Update timestamp on update
CREATE OR REPLACE FUNCTION update_plugin_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER plugin_repositories_updated
    BEFORE UPDATE ON plugin_repositories
    FOR EACH ROW
    EXECUTE FUNCTION update_plugin_timestamp();

CREATE TRIGGER installed_plugins_updated
    BEFORE UPDATE ON installed_plugins
    FOR EACH ROW
    EXECUTE FUNCTION update_plugin_timestamp();

-- Auto-update plugin statistics on execution completion
CREATE OR REPLACE FUNCTION update_plugin_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'success' AND OLD.status = 'running' THEN
        UPDATE installed_plugins
        SET
            execution_count = execution_count + 1,
            success_count = success_count + 1,
            last_execution_at = NEW.completed_at,
            avg_execution_time_ms =
                CASE
                    WHEN avg_execution_time_ms IS NULL THEN NEW.execution_time_ms
                    ELSE (avg_execution_time_ms * 0.9) + (NEW.execution_time_ms * 0.1)
                END,
            max_execution_time_ms = GREATEST(COALESCE(max_execution_time_ms, 0), NEW.execution_time_ms),
            min_execution_time_ms = LEAST(COALESCE(min_execution_time_ms, NEW.execution_time_ms), NEW.execution_time_ms),
            total_events_processed = total_events_processed + 1,
            avg_memory_mb =
                CASE
                    WHEN avg_memory_mb IS NULL THEN NEW.memory_mb
                    ELSE (avg_memory_mb * 0.9) + (NEW.memory_mb * 0.1)
                END,
            max_memory_mb = GREATEST(COALESCE(max_memory_mb, 0), NEW.memory_mb),
            avg_cpu_percent =
                CASE
                    WHEN avg_cpu_percent IS NULL THEN NEW.cpu_percent
                    ELSE (avg_cpu_percent * 0.9) + (NEW.cpu_percent * 0.1)
                END,
            max_cpu_percent = GREATEST(COALESCE(max_cpu_percent, 0), NEW.cpu_percent)
        WHERE id = NEW.plugin_id;
    ELSIF NEW.status = 'error' AND OLD.status = 'running' THEN
        UPDATE installed_plugins
        SET
            execution_count = execution_count + 1,
            error_count = error_count + 1,
            last_error = NEW.error_message,
            last_error_at = NEW.completed_at
        WHERE id = NEW.plugin_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER plugin_execution_stats
    AFTER UPDATE ON plugin_executions
    FOR EACH ROW
    EXECUTE FUNCTION update_plugin_stats();

-- Function to cleanup old execution logs
CREATE OR REPLACE FUNCTION cleanup_old_plugin_executions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM plugin_executions
    WHERE created_at < NOW() - INTERVAL '30 days'
      AND status IN ('success', 'error');

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Insert default official repository
INSERT INTO plugin_repositories (
    name, url, repository_type, branch, trust_level,
    is_official, verified_owner, description
) VALUES (
    'CyberSheppard Official',
    'https://github.com/cybersheppard/plugins',
    'github',
    'main',
    'official',
    true,
    true,
    'Official CyberSheppard plugin repository with verified and tested plugins'
) ON CONFLICT (url) DO NOTHING;

COMMENT ON TABLE plugin_repositories IS 'Plugin source repositories (GitHub, GitLab, etc)';
COMMENT ON TABLE plugin_registry IS 'Available plugins fetched from repositories';
COMMENT ON TABLE installed_plugins IS 'Locally installed and configured plugins';
COMMENT ON TABLE plugin_executions IS 'Plugin execution history and logs';
COMMENT ON TABLE plugin_permissions IS 'Approved permissions for each plugin';
