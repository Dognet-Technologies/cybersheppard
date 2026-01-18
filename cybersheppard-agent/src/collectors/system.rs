// ============================================================================
// System Metrics Collector - CPU, Memory, Disk, Uptime
// ============================================================================

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    // CPU
    pub cpu_usage: f32,
    pub cpu_count: usize,
    pub load_average: (f64, f64, f64),

    // Memory
    pub memory_total: u64,
    pub memory_used: u64,
    pub memory_available: u64,
    pub memory_percent: f32,

    // Swap
    pub swap_total: u64,
    pub swap_used: u64,

    // Disk
    pub disk_total: u64,
    pub disk_used: u64,
    pub disk_available: u64,
    pub disk_percent: f32,

    // System
    pub uptime: u64,
    pub boot_time: u64,
}

pub async fn collect() -> Result<SystemMetrics> {
    let mut sys = System::new_all();
    sys.refresh_all();

    // CPU
    let cpu_usage = sys.global_cpu_info().cpu_usage();
    let cpu_count = sys.cpus().len();
    let load_average = System::load_average();

    // Memory
    let memory_total = sys.total_memory();
    let memory_used = sys.used_memory();
    let memory_available = sys.available_memory();
    let memory_percent = (memory_used as f32 / memory_total as f32) * 100.0;

    // Swap
    let swap_total = sys.total_swap();
    let swap_used = sys.used_swap();

    // Disk (root filesystem)
    let (disk_total, disk_used, disk_available, disk_percent) = get_disk_usage().await?;

    // System
    let uptime = System::uptime();
    let boot_time = System::boot_time();

    Ok(SystemMetrics {
        cpu_usage,
        cpu_count,
        load_average: (load_average.one, load_average.five, load_average.fifteen),
        memory_total,
        memory_used,
        memory_available,
        memory_percent,
        swap_total,
        swap_used,
        disk_total,
        disk_used,
        disk_available,
        disk_percent,
        uptime,
        boot_time,
    })
}

async fn get_disk_usage() -> Result<(u64, u64, u64, f32)> {
    // Parse /proc/mounts to find root filesystem
    let mounts = tokio::fs::read_to_string("/proc/mounts").await?;

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == "/" {
            // Use statvfs to get disk stats
            if let Ok(stat) = nix::sys::statvfs::statvfs("/") {
                let total = stat.blocks() * stat.block_size();
                let available = stat.blocks_available() * stat.block_size();
                let used = total - available;
                let percent = (used as f32 / total as f32) * 100.0;

                return Ok((total, used, available, percent));
            }
        }
    }

    // Fallback
    Ok((0, 0, 0, 0.0))
}
