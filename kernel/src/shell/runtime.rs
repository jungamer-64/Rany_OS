extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::security::capability::CAP_SYS_PTRACE;
use kernel_api::shell::{
    CpuIdleInfo, DirEntry, DomainInfo, DomainMonitorInfo, DomainState, FileAttributes, FileType,
    MemoryMonitorInfo, MemoryStats, MonitorInfo, NetworkMonitorInfo, PowerInfo, ShellSystemInfo,
    TaskMonitorInfo, ThermalInfo, ThermalSensorInfo, WatchdogInfo,
};

fn map_domain_state(state: crate::domain::DomainState) -> DomainState {
    match state {
        crate::domain::DomainState::Initializing => DomainState::Initializing,
        crate::domain::DomainState::Running => DomainState::Running,
        crate::domain::DomainState::Suspended => DomainState::Suspended,
        crate::domain::DomainState::Stopped => DomainState::Stopped,
        crate::domain::DomainState::Terminated => DomainState::Terminated,
    }
}

fn ensure_domain_control(target: crate::domain::DomainId) -> Result<(), &'static str> {
    let subject = crate::task::current_subject();
    if subject.domain == target {
        return Ok(());
    }
    if subject
        .caps
        .has_capability(crate::security::capability::CAP_KILL)
    {
        return Ok(());
    }
    Err("Permission denied: owner or CAP_KILL required")
}

pub fn memory_stats() -> MemoryStats {
    MemoryStats {
        total_kb: crate::heap::total_memory_kb() as usize,
        free_kb: crate::heap::free_memory_kb() as usize,
        used_kb: crate::heap::used_memory_kb() as usize,
    }
}

pub fn current_tick() -> u64 {
    crate::task::current_tick()
}

pub fn current_domain_id() -> u64 {
    crate::task::current_subject().domain.as_u64()
}

pub fn list_domains() -> Vec<DomainInfo> {
    let subject = crate::task::current_subject();
    if subject.caps.has_capability(CAP_SYS_PTRACE) {
        return crate::domain::list_domain_snapshots()
            .into_iter()
            .map(|snap| DomainInfo {
                id: snap.id.as_u64(),
                name: snap.name,
                state: map_domain_state(snap.state),
                tasks: snap.tasks,
                memory_kb: (snap.memory_bytes / 1024) as usize,
                rrefs: snap.rrefs,
                last_error: snap.last_error,
            })
            .collect();
    }

    crate::domain::get_domain_snapshot(subject.domain)
        .map(|snap| {
            alloc::vec![DomainInfo {
                id: snap.id.as_u64(),
                name: snap.name,
                state: map_domain_state(snap.state),
                tasks: snap.tasks,
                memory_kb: (snap.memory_bytes / 1024) as usize,
                rrefs: snap.rrefs,
                last_error: snap.last_error,
            }]
        })
        .unwrap_or_default()
}

pub fn get_domain(id: u64) -> Option<DomainInfo> {
    let subject = crate::task::current_subject();
    let target = crate::domain::DomainId::new(id);
    if target != subject.domain && !subject.caps.has_capability(CAP_SYS_PTRACE) {
        return None;
    }

    crate::domain::get_domain_snapshot(target).map(|snap| DomainInfo {
        id: snap.id.as_u64(),
        name: snap.name,
        state: map_domain_state(snap.state),
        tasks: snap.tasks,
        memory_kb: (snap.memory_bytes / 1024) as usize,
        rrefs: snap.rrefs,
        last_error: snap.last_error,
    })
}

pub fn terminate_domain(id: u64) -> Result<(), &'static str> {
    let target = crate::domain::DomainId::new(id);
    ensure_domain_control(target)?;
    crate::domain::terminate_domain(target)
}

pub fn stop_domain(id: u64) -> Result<(), &'static str> {
    let target = crate::domain::DomainId::new(id);
    ensure_domain_control(target)?;
    crate::domain::stop_domain(target)
}

pub fn resume_domain(id: u64) -> Result<(), &'static str> {
    let target = crate::domain::DomainId::new(id);
    ensure_domain_control(target)?;
    crate::domain::resume_domain(target)
}

pub fn system_info() -> ShellSystemInfo {
    ShellSystemInfo {
        uptime_ticks: crate::task::current_tick(),
        cpu_temperature: cpu_temperature(),
    }
}

pub fn monitor_info() -> MonitorInfo {
    let snap = crate::monitor::snapshot();
    MonitorInfo {
        timestamp: snap.timestamp,
        cpu_usage: snap.cpu_usage,
        memory: MemoryMonitorInfo {
            heap_used: snap.memory.heap_used,
            heap_free: snap.memory.heap_free,
            heap_total: snap.memory.heap_total,
            usage_percent: snap.memory.usage_percent,
        },
        domains: DomainMonitorInfo {
            total: snap.domains.total,
            running: snap.domains.running,
            stopped: snap.domains.stopped,
        },
        tasks: TaskMonitorInfo {
            context_switches: snap.tasks.context_switches,
            voluntary_yields: snap.tasks.voluntary_yields,
            forced_preemptions: snap.tasks.forced_preemptions,
        },
        network: NetworkMonitorInfo {
            rx_packets: snap.network.rx_packets,
            tx_packets: snap.network.tx_packets,
            rx_bytes: snap.network.rx_bytes,
            tx_bytes: snap.network.tx_bytes,
        },
    }
}

pub fn thermal_info() -> ThermalInfo {
    let tm = crate::thermal::thermal_manager();
    let (polling_count, trip_events) = tm.stats();
    let throttle = tm.throttle_controller();
    let sensors = tm
        .sensors()
        .iter()
        .map(|s| ThermalSensorInfo {
            id: s.id as usize,
            name: s.name.clone(),
            current_c: if s.current.is_valid() {
                Some(s.current.celsius() as f32)
            } else {
                None
            },
            is_hot: s.is_hot(),
            is_critical: s.is_critical(),
        })
        .collect();

    ThermalInfo {
        cpu_celsius: cpu_temperature(),
        polling_count,
        trip_events,
        throttle_policy: alloc::format!("{:?}", throttle.current_policy()),
        throttle_count: throttle.throttle_count(),
        sensors,
    }
}

pub fn watchdog_info() -> WatchdogInfo {
    let wm = crate::watchdog::watchdog_manager();
    let (heartbeats, timeouts, checks) = wm.software().stats();
    WatchdogInfo {
        heartbeats,
        timeouts,
        checks,
        deadlocks_detected: wm.deadlock_detector().deadlocks_detected(),
    }
}

pub fn power_info() -> PowerInfo {
    let pm = crate::power::power_manager();
    let idle = crate::power::cpu_idle();
    let (c1, c2, c3) = idle.stats();
    let stats = pm.stats();

    PowerInfo {
        state: alloc::format!("{:?}", pm.current_state()),
        power_button_presses: stats
            .power_button_presses
            .load(core::sync::atomic::Ordering::Relaxed),
        sleep_button_presses: stats
            .sleep_button_presses
            .load(core::sync::atomic::Ordering::Relaxed),
        cpu_idle: CpuIdleInfo {
            c1_count: c1,
            c2_count: c2,
            c3_count: c3,
        },
    }
}

pub fn cpu_temperature() -> Option<f32> {
    crate::thermal::cpu_temperature().map(|t| t.celsius() as f32)
}

pub fn shutdown() -> ! {
    crate::power::shutdown()
}

pub fn reboot() -> ! {
    crate::power::reboot()
}

pub fn list_directory(path: &str) -> Result<Vec<DirEntry>, &'static str> {
    match crate::fs::list_directory(path, "/") {
        Ok(entries) => Ok(entries
            .into_iter()
            .map(|e| {
                let file_type = match e.file_type {
                    crate::fs::FileType::Directory => FileType::Directory,
                    crate::fs::FileType::Symlink => FileType::Symlink,
                    crate::fs::FileType::CharDevice => FileType::CharDevice,
                    crate::fs::FileType::BlockDevice => FileType::BlockDevice,
                    _ => FileType::File,
                };
                DirEntry {
                    name: e.name,
                    file_type,
                    size: 0,
                    ino: e.ino,
                }
            })
            .collect()),
        Err(_) => Err("Failed to list directory"),
    }
}

pub fn read_file(path: &str) -> Result<Vec<u8>, &'static str> {
    crate::fs::read_file_content(path, "/").map_err(|_| "Failed to read file")
}

pub fn read_file_zero_copy(path: &str) -> Result<Arc<Vec<u8>>, &'static str> {
    use crate::fs::async_memfs::Bytes;

    let content = crate::fs::read_file_content(path, "/").map_err(|_| "Failed to read file")?;
    let bytes = Bytes::from(content);
    Ok(bytes.into_inner())
}

pub fn write_file(path: &str, data: &[u8]) -> Result<(), &'static str> {
    crate::fs::write_file_content(path, "/", data).map_err(|_| "Failed to write file")
}

pub fn stat_file(path: &str) -> Result<FileAttributes, &'static str> {
    match crate::fs::stat_file(path, "/") {
        Ok(attr) => {
            let file_type = match attr.file_type {
                crate::fs::FileType::Directory => FileType::Directory,
                crate::fs::FileType::Symlink => FileType::Symlink,
                crate::fs::FileType::CharDevice => FileType::CharDevice,
                crate::fs::FileType::BlockDevice => FileType::BlockDevice,
                _ => FileType::File,
            };
            Ok(FileAttributes {
                size: attr.size,
                ino: attr.ino,
                nlink: attr.nlink as u64,
                file_type,
            })
        }
        Err(_) => Err("Failed to stat file"),
    }
}

pub fn make_directory(path: &str) -> Result<(), &'static str> {
    crate::fs::make_directory(path, "/").map_err(|_| "Failed to create directory")
}

pub fn remove_file(path: &str) -> Result<(), &'static str> {
    crate::fs::remove_file(path, "/").map_err(|_| "Failed to remove file")
}

pub fn remove_directory(path: &str) -> Result<(), &'static str> {
    crate::fs::remove_directory(path, "/").map_err(|_| "Failed to remove directory")
}
