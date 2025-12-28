// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - InfluxDB Writer for Collected Data
// ============================================================================
// Writes collected monitoring data to InfluxDB time-series database

use influxdb::{InfluxDbWriteable, Timestamp};
use chrono::{DateTime, Utc};
use crate::services::collector::*;
use crate::db::influxdb::InfluxDbClient;
use anyhow::Result;
use tracing::{info, warn};

// ============================================================================
// InfluxDB Point Structures
// ============================================================================

#[derive(InfluxDbWriteable)]
struct FileIntegrityPoint {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(tag)]
    file_path: String,
    #[influxdb(tag)]
    status: String,  // new/modified/unchanged
    #[influxdb(field)]
    hash: String,
    #[influxdb(field)]
    permissions: String,
    #[influxdb(field)]
    owner: String,
    #[influxdb(field)]
    size: i64,
}

#[derive(InfluxDbWriteable)]
struct SuidBinaryPoint {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(tag)]
    file_path: String,
    #[influxdb(field)]
    permissions: String,
    #[influxdb(field)]
    owner: String,
    #[influxdb(field)]
    size: i64,
}

#[derive(InfluxDbWriteable)]
struct WorldWritablePoint {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(tag)]
    file_path: String,
    #[influxdb(field)]
    permissions: String,
    #[influxdb(field)]
    owner: String,
    #[influxdb(field)]
    size: i64,
}

#[derive(InfluxDbWriteable)]
struct PackagePoint {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(tag)]
    package_name: String,
    #[influxdb(tag)]
    manager: String,
    #[influxdb(field)]
    version: String,
    #[influxdb(field)]
    architecture: String,
    #[influxdb(field)]
    security_update_available: bool,
}

#[derive(InfluxDbWriteable)]
struct UserAccountPoint {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(tag)]
    username: String,
    #[influxdb(field)]
    uid: i32,
    #[influxdb(field)]
    gid: i32,
    #[influxdb(field)]
    has_sudo: bool,
    #[influxdb(field)]
    is_locked: bool,
    #[influxdb(field)]
    shell: String,
}

#[derive(InfluxDbWriteable)]
struct ActiveSessionPoint {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(tag)]
    user: String,
    #[influxdb(tag)]
    from_address: String,
    #[influxdb(field)]
    tty: String,
    #[influxdb(field)]
    login_time: String,
    #[influxdb(field)]
    idle: String,
}

#[derive(InfluxDbWriteable)]
struct FailedLoginPoint {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(tag)]
    user: String,
    #[influxdb(tag)]
    from_address: String,
    #[influxdb(field)]
    timestamp_str: String,
}

#[derive(InfluxDbWriteable)]
struct SudoCommandPoint {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(tag)]
    user: String,
    #[influxdb(field)]
    command: String,
    #[influxdb(field)]
    timestamp_str: String,
}

#[derive(InfluxDbWriteable)]
struct SystemdServicePoint {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(tag)]
    service_name: String,
    #[influxdb(tag)]
    active: String,
    #[influxdb(tag)]
    enabled: String,
    #[influxdb(field)]
    load: String,
    #[influxdb(field)]
    sub: String,
    #[influxdb(field)]
    description: String,
    #[influxdb(field)]
    pid: i32,
}

#[derive(InfluxDbWriteable)]
struct ListeningPortPoint {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(tag)]
    protocol: String,
    #[influxdb(tag)]
    local_address: String,
    #[influxdb(field)]
    local_port: i32,
    #[influxdb(field)]
    process: String,
}

// ============================================================================
// Metrics Summary Points (for dashboards)
// ============================================================================

#[derive(InfluxDbWriteable)]
struct FileIntegritySummary {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(field)]
    critical_files_count: i64,
    #[influxdb(field)]
    suid_binaries_count: i64,
    #[influxdb(field)]
    world_writable_count: i64,
    #[influxdb(field)]
    files_modified: i64,
    #[influxdb(field)]
    files_new: i64,
}

#[derive(InfluxDbWriteable)]
struct PackageSummary {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(field)]
    total_packages: i64,
    #[influxdb(field)]
    security_updates_available: i64,
}

#[derive(InfluxDbWriteable)]
struct UserActivitySummary {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(field)]
    total_accounts: i64,
    #[influxdb(field)]
    sudo_accounts: i64,
    #[influxdb(field)]
    locked_accounts: i64,
    #[influxdb(field)]
    active_sessions: i64,
    #[influxdb(field)]
    failed_logins: i64,
    #[influxdb(field)]
    sudo_commands: i64,
}

#[derive(InfluxDbWriteable)]
struct ServicesSummary {
    time: DateTime<Utc>,
    #[influxdb(tag)]
    target_id: String,
    #[influxdb(tag)]
    target_hostname: String,
    #[influxdb(field)]
    total_services: i64,
    #[influxdb(field)]
    active_services: i64,
    #[influxdb(field)]
    failed_services: i64,
    #[influxdb(field)]
    listening_ports: i64,
    #[influxdb(field)]
    docker_containers: i64,
}

// ============================================================================
// Writer Functions
// ============================================================================

/// Write all collected data to InfluxDB
pub async fn write_collected_data(
    influx: &InfluxDbClient,
    data: &CollectedData,
) -> Result<()> {
    info!("📝 Writing collected data to InfluxDB for target {}", data.target_id);

    let target_id_str = data.target_id.to_string();

    // Write file integrity data
    if let Some(ref files) = data.files {
        write_file_integrity_data(influx, &target_id_str, &data.target_hostname, data.timestamp, files).await?;
    }

    // Write package data
    if let Some(ref packages) = data.packages {
        write_package_data(influx, &target_id_str, &data.target_hostname, data.timestamp, packages).await?;
    }

    // Write user activity data
    if let Some(ref users) = data.users {
        write_user_activity_data(influx, &target_id_str, &data.target_hostname, data.timestamp, users).await?;
    }

    // Write services data
    if let Some(ref services) = data.services {
        write_services_data(influx, &target_id_str, &data.target_hostname, data.timestamp, services).await?;
    }

    info!("✅ InfluxDB write completed for target {}", data.target_id);

    Ok(())
}

/// Write file integrity data to InfluxDB
async fn write_file_integrity_data(
    influx: &InfluxDbClient,
    target_id: &str,
    target_hostname: &str,
    timestamp: DateTime<Utc>,
    data: &FileIntegrityData,
) -> Result<()> {
    // Write individual critical files
    for file in &data.critical_files {
        if let Some(ref hash) = file.hash {
            let point = FileIntegrityPoint {
                time: timestamp,
                target_id: target_id.to_string(),
                target_hostname: target_hostname.to_string(),
                file_path: file.path.clone(),
                status: file.status.clone().unwrap_or_else(|| "unknown".to_string()),
                hash: hash.clone(),
                permissions: file.permissions.clone(),
                owner: file.owner.clone(),
                size: file.size,
            };
            influx.write_metrics(point).await?;
        }
    }

    // Write SUID binaries (security risk)
    for file in &data.suid_binaries {
        let point = SuidBinaryPoint {
            time: timestamp,
            target_id: target_id.to_string(),
            target_hostname: target_hostname.to_string(),
            file_path: file.path.clone(),
            permissions: file.permissions.clone(),
            owner: file.owner.clone(),
            size: file.size,
        };
        influx.write_metrics(point).await?;
    }

    // Write world-writable files (critical risk)
    for file in &data.world_writable {
        let point = WorldWritablePoint {
            time: timestamp,
            target_id: target_id.to_string(),
            target_hostname: target_hostname.to_string(),
            file_path: file.path.clone(),
            permissions: file.permissions.clone(),
            owner: file.owner.clone(),
            size: file.size,
        };
        influx.write_metrics(point).await?;
    }

    // Write summary
    let modified_count = data.critical_files.iter()
        .filter(|f| f.status.as_ref().map(|s| s == "modified").unwrap_or(false))
        .count() as i64;
    let new_count = data.critical_files.iter()
        .filter(|f| f.status.as_ref().map(|s| s == "new").unwrap_or(false))
        .count() as i64;

    let summary = FileIntegritySummary {
        time: timestamp,
        target_id: target_id.to_string(),
        target_hostname: target_hostname.to_string(),
        critical_files_count: data.critical_files.len() as i64,
        suid_binaries_count: data.suid_binaries.len() as i64,
        world_writable_count: data.world_writable.len() as i64,
        files_modified: modified_count,
        files_new: new_count,
    };
    influx.write_metrics(summary).await?;

    info!("  📂 File integrity: {} files, {} SUID, {} world-writable",
          data.critical_files.len(), data.suid_binaries.len(), data.world_writable.len());

    Ok(())
}

/// Write package data to InfluxDB
async fn write_package_data(
    influx: &InfluxDbClient,
    target_id: &str,
    target_hostname: &str,
    timestamp: DateTime<Utc>,
    packages: &[PackageData],
) -> Result<()> {
    // Write individual packages (sample to avoid overwhelming InfluxDB)
    // Only write packages with security updates or first 100
    let mut written = 0;
    for pkg in packages {
        if pkg.security_update_available || written < 100 {
            let point = PackagePoint {
                time: timestamp,
                target_id: target_id.to_string(),
                target_hostname: target_hostname.to_string(),
                package_name: pkg.name.clone(),
                manager: pkg.manager.clone(),
                version: pkg.version.clone(),
                architecture: pkg.architecture.clone(),
                security_update_available: pkg.security_update_available,
            };
            influx.write_metrics(point).await?;
            written += 1;
        }
    }

    // Write summary
    let security_updates = packages.iter().filter(|p| p.security_update_available).count() as i64;
    let summary = PackageSummary {
        time: timestamp,
        target_id: target_id.to_string(),
        target_hostname: target_hostname.to_string(),
        total_packages: packages.len() as i64,
        security_updates_available: security_updates,
    };
    influx.write_metrics(summary).await?;

    info!("  📦 Packages: {} total, {} security updates", packages.len(), security_updates);

    Ok(())
}

/// Write user activity data to InfluxDB
async fn write_user_activity_data(
    influx: &InfluxDbClient,
    target_id: &str,
    target_hostname: &str,
    timestamp: DateTime<Utc>,
    data: &UserActivityData,
) -> Result<()> {
    // Write user accounts
    for account in &data.user_accounts {
        let point = UserAccountPoint {
            time: timestamp,
            target_id: target_id.to_string(),
            target_hostname: target_hostname.to_string(),
            username: account.username.clone(),
            uid: account.uid,
            gid: account.gid,
            has_sudo: account.has_sudo,
            is_locked: account.is_locked,
            shell: account.shell.clone(),
        };
        influx.write_metrics(point).await?;
    }

    // Write active sessions
    for session in &data.active_sessions {
        let point = ActiveSessionPoint {
            time: timestamp,
            target_id: target_id.to_string(),
            target_hostname: target_hostname.to_string(),
            user: session.user.clone(),
            from_address: session.from.clone(),
            tty: session.tty.clone(),
            login_time: session.login_time.clone(),
            idle: session.idle.clone(),
        };
        influx.write_metrics(point).await?;
    }

    // Write failed logins (SECURITY CRITICAL)
    for failed in &data.failed_logins {
        let point = FailedLoginPoint {
            time: timestamp,
            target_id: target_id.to_string(),
            target_hostname: target_hostname.to_string(),
            user: failed.user.clone(),
            from_address: failed.from.clone(),
            timestamp_str: failed.timestamp.clone(),
        };
        influx.write_metrics(point).await?;
    }

    // Write sudo commands
    for sudo in &data.sudo_commands {
        let point = SudoCommandPoint {
            time: timestamp,
            target_id: target_id.to_string(),
            target_hostname: target_hostname.to_string(),
            user: sudo.user.clone(),
            command: sudo.command.clone(),
            timestamp_str: sudo.timestamp.clone(),
        };
        influx.write_metrics(point).await?;
    }

    // Write summary
    let sudo_accounts = data.user_accounts.iter().filter(|u| u.has_sudo).count() as i64;
    let locked_accounts = data.user_accounts.iter().filter(|u| u.is_locked).count() as i64;

    let summary = UserActivitySummary {
        time: timestamp,
        target_id: target_id.to_string(),
        target_hostname: target_hostname.to_string(),
        total_accounts: data.user_accounts.len() as i64,
        sudo_accounts,
        locked_accounts,
        active_sessions: data.active_sessions.len() as i64,
        failed_logins: data.failed_logins.len() as i64,
        sudo_commands: data.sudo_commands.len() as i64,
    };
    influx.write_metrics(summary).await?;

    info!("  👤 Users: {} accounts, {} sessions, {} failed logins, {} sudo cmds",
          data.user_accounts.len(), data.active_sessions.len(),
          data.failed_logins.len(), data.sudo_commands.len());

    Ok(())
}

/// Write services data to InfluxDB
async fn write_services_data(
    influx: &InfluxDbClient,
    target_id: &str,
    target_hostname: &str,
    timestamp: DateTime<Utc>,
    data: &ServicesData,
) -> Result<()> {
    // Write systemd services
    for service in &data.systemd_services {
        let point = SystemdServicePoint {
            time: timestamp,
            target_id: target_id.to_string(),
            target_hostname: target_hostname.to_string(),
            service_name: service.name.clone(),
            active: service.active.clone(),
            enabled: service.enabled.clone(),
            load: service.load.clone(),
            sub: service.sub.clone(),
            description: service.description.clone(),
            pid: service.pid.unwrap_or(0),
        };
        influx.write_metrics(point).await?;
    }

    // Write listening ports
    for port in &data.listening_ports {
        let point = ListeningPortPoint {
            time: timestamp,
            target_id: target_id.to_string(),
            target_hostname: target_hostname.to_string(),
            protocol: port.protocol.clone(),
            local_address: port.local_address.clone(),
            local_port: port.local_port,
            process: port.process.clone(),
        };
        influx.write_metrics(point).await?;
    }

    // Write summary
    let active_services = data.systemd_services.iter().filter(|s| s.active == "active").count() as i64;
    let failed_services = data.systemd_services.iter().filter(|s| s.active == "failed").count() as i64;

    let summary = ServicesSummary {
        time: timestamp,
        target_id: target_id.to_string(),
        target_hostname: target_hostname.to_string(),
        total_services: data.systemd_services.len() as i64,
        active_services,
        failed_services,
        listening_ports: data.listening_ports.len() as i64,
        docker_containers: data.docker_containers.len() as i64,
    };
    influx.write_metrics(summary).await?;

    info!("  ⚙️  Services: {} services ({} active, {} failed), {} ports",
          data.systemd_services.len(), active_services, failed_services,
          data.listening_ports.len());

    Ok(())
}
