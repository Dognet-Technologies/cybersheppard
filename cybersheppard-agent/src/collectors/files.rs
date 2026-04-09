// ============================================================================
// Files Metrics Collector - File Integrity, SUID, World-writable
// ============================================================================

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesMetrics {
    pub critical_files: Vec<FileInfo>,
    pub suid_binaries: Vec<FileInfo>,
    pub world_writable: Vec<FileInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub permissions: u32,
    pub hash: String,
    pub modified_at: i64,
}

pub async fn collect() -> Result<FilesMetrics> {
    let critical_files = collect_critical_files().await?;
    let suid_binaries = collect_suid_binaries().await?;
    let world_writable = collect_world_writable().await?;

    Ok(FilesMetrics {
        critical_files,
        suid_binaries,
        world_writable,
    })
}

async fn collect_critical_files() -> Result<Vec<FileInfo>> {
    let critical_paths = vec![
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config",
        "/etc/sudoers",
        "/etc/hosts",
        "/etc/crontab",
    ];

    let mut files = Vec::new();

    for path in critical_paths {
        if let Ok(info) = get_file_info(path).await {
            files.push(info);
        }
    }

    Ok(files)
}

async fn collect_suid_binaries() -> Result<Vec<FileInfo>> {
    let mut binaries = Vec::new();

    // Search common directories for SUID binaries
    for dir in ["/bin", "/sbin", "/usr/bin", "/usr/sbin"] {
        for entry in WalkDir::new(dir).max_depth(3).into_iter().filter_map(|e| e.ok()) {
            if let Ok(metadata) = entry.metadata() {
                let mode = metadata.permissions().mode();
                // Check for SUID bit (04000)
                if mode & 0o4000 != 0 {
                    if let Ok(info) = get_file_info(entry.path().to_str().unwrap()).await {
                        binaries.push(info);
                    }
                }
            }
        }
    }

    Ok(binaries)
}

async fn collect_world_writable() -> Result<Vec<FileInfo>> {
    let mut files = Vec::new();

    // Check /etc directory for world-writable files
    for entry in WalkDir::new("/etc").max_depth(2).into_iter().filter_map(|e| e.ok()) {
        if let Ok(metadata) = entry.metadata() {
            let mode = metadata.permissions().mode();
            // Check for world-writable (0002)
            if mode & 0o002 != 0 {
                if let Ok(info) = get_file_info(entry.path().to_str().unwrap()).await {
                    files.push(info);
                }
            }
        }
    }

    Ok(files)
}

async fn get_file_info(path: &str) -> Result<FileInfo> {
    let metadata = tokio::fs::metadata(path).await?;
    let permissions = metadata.permissions().mode();
    let size = metadata.len();

    let modified_at = metadata.modified()?
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    // Calculate SHA256 hash
    let content = tokio::fs::read(path).await?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = format!("{:x}", hasher.finalize());

    Ok(FileInfo {
        path: path.to_string(),
        size,
        permissions,
        hash,
        modified_at,
    })
}
