// ============================================================================
// kernel/src/fs/sysfs.rs - Minimal sysfs support for /sys/cell and /sys/system
// ============================================================================

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::sync::atomic::Ordering;

use crate::domain_system::{get_domain_snapshot, list_domain_snapshots, DomainId, DomainState};
use crate::fs::{DirEntry, FileAttr, FileMode, FileType};

const CELL_FIELDS: [&str; 15] = [
    "name",
    "state",
    "tasks",
    "task_ids",
    "memory_kb",
    "memory_bytes",
    "rrefs",
    "runtime_ticks",
    "context_switches",
    "created_at",
    "numa_node",
    "dependencies",
    "dependents",
    "panic_message",
    "last_error",
];

const SYSTEM_ROOT_FILES: [&str; 9] = [
    "version",
    "uptime",
    "meminfo",
    "cpuinfo",
    "stat",
    "loadavg",
    "filesystems",
    "mounts",
    "cmdline",
];

const SYSTEM_DIRS: [&str; 2] = ["kernel", "net"];
const SYSTEM_KERNEL_FILES: [&str; 3] = ["hostname", "ostype", "version"];
const SYSTEM_NET_FILES: [&str; 4] = ["dev", "tcp", "udp", "arp"];

fn split_path(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

fn is_sys_path(comps: &[&str]) -> bool {
    matches!(comps.first(), Some(&"sys"))
}

fn is_cell_path(comps: &[&str]) -> bool {
    comps.len() >= 2 && comps[0] == "sys" && comps[1] == "cell"
}

fn is_system_path(comps: &[&str]) -> bool {
    comps.len() >= 2 && comps[0] == "sys" && comps[1] == "system"
}

fn parse_domain_id(comp: &str) -> Result<DomainId, &'static str> {
    let id = comp.parse::<u64>().map_err(|_| "Invalid domain id")?;
    Ok(DomainId::new(id))
}

fn state_to_str(state: DomainState) -> &'static str {
    match state {
        DomainState::Initializing => "initializing",
        DomainState::Running => "running",
        DomainState::Suspended => "suspended",
        DomainState::Stopped => "stopped",
        DomainState::Terminated => "terminated",
    }
}

fn format_u64_list(ids: &[u64]) -> String {
    if ids.is_empty() {
        return String::from("\n");
    }
    let mut out = String::new();
    for (idx, id) in ids.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        out.push_str(&id.to_string());
    }
    out.push('\n');
    out
}

fn format_domain_list(ids: &[DomainId]) -> String {
    if ids.is_empty() {
        return String::from("\n");
    }
    let mut out = String::new();
    for (idx, id) in ids.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        out.push_str(&id.as_u64().to_string());
    }
    out.push('\n');
    out
}

fn field_value(snapshot: &crate::domain_system::DomainSnapshot, field: &str) -> Option<String> {
    match field {
        "name" => Some(format!("{}\n", snapshot.name)),
        "state" => Some(format!("{}\n", state_to_str(snapshot.state))),
        "tasks" => Some(format!("{}\n", snapshot.tasks)),
        "task_ids" => Some(format_u64_list(&snapshot.task_ids)),
        "memory_kb" => Some(format!("{}\n", snapshot.memory_bytes / 1024)),
        "memory_bytes" => Some(format!("{}\n", snapshot.memory_bytes)),
        "rrefs" => Some(format!("{}\n", snapshot.rrefs)),
        "runtime_ticks" => Some(format!("{}\n", snapshot.runtime_ticks)),
        "context_switches" => Some(format!("{}\n", snapshot.context_switches)),
        "created_at" => Some(format!("{}\n", snapshot.created_at)),
        "numa_node" => Some(format!(
            "{}\n",
            snapshot.numa_node.map(|n| n as i64).unwrap_or(-1)
        )),
        "dependencies" => Some(format_domain_list(&snapshot.dependencies)),
        "dependents" => Some(format_domain_list(&snapshot.dependents)),
        "panic_message" => Some(format!(
            "{}\n",
            snapshot.panic_message.as_deref().unwrap_or("")
        )),
        "last_error" => Some(format!(
            "{}\n",
            snapshot.last_error.as_deref().unwrap_or("")
        )),
        _ => None,
    }
}

fn system_file_value(field: &str) -> Option<String> {
    match field {
        "version" => Some(format!(
            "ExoRust Kernel {} ({}) (gcc version 12.0.0)\n",
            env!("CARGO_PKG_VERSION"),
            "x86_64"
        )),
        "uptime" => {
            let uptime_ms = crate::time::current_tick();
            let uptime_secs = uptime_ms / 1000;
            let uptime_frac = (uptime_ms % 1000) / 10;
            let idle_secs = uptime_secs * 9 / 10;
            let idle_frac = uptime_frac * 9 / 10;
            Some(format!(
                "{}.{:02} {}.{:02}\n",
                uptime_secs, uptime_frac, idle_secs, idle_frac
            ))
        }
        "meminfo" => Some(generate_meminfo()),
        "cpuinfo" => Some(generate_cpuinfo()),
        "stat" => Some(generate_stat()),
        "loadavg" => Some(String::from("0.00 0.00 0.00 1/1 1\n")),
        "filesystems" => Some(String::from(
            "nodev\tproc\n\
             nodev\tdevfs\n\
             \text2\n\
             nodev\ttmpfs\n",
        )),
        "mounts" => Some(String::from(
            "proc /proc proc rw,nosuid,nodev,noexec 0 0\n\
             devfs /dev devfs rw,nosuid 0 0\n",
        )),
        "cmdline" => Some(String::from("console=ttyS0\n")),
        _ => None,
    }
}

fn system_kernel_value(field: &str) -> Option<String> {
    match field {
        "hostname" => Some(String::from("exorust\n")),
        "ostype" => Some(String::from("ExoRust\n")),
        "version" => Some(format!("#1 SMP {}\n", "ExoRust 0.1.0")),
        _ => None,
    }
}

fn system_net_value(field: &str) -> Option<String> {
    match field {
        "dev" => {
            let mut output = String::from(
                "Inter-|   Receive                                                |  Transmit\n\
                 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
            );
            output.push_str("    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n");
            output.push_str("  eth0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n");
            Some(output)
        }
        "tcp" => Some(String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )),
        "udp" => Some(String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )),
        "arp" => Some(String::from(
            "IP address       HW type     Flags       HW address            Mask     Device\n",
        )),
        _ => None,
    }
}

fn ino_for(path: &str) -> u64 {
    let mut hash = 14695981039346656037u64;
    for b in path.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash
}

fn file_attr(path: &str, file_type: FileType, size: u64) -> FileAttr {
    let mode = match file_type {
        FileType::Directory => FileMode::DEFAULT_DIR,
        FileType::Symlink => FileMode::DEFAULT_LINK,
        _ => FileMode::DEFAULT_FILE,
    };
    FileAttr {
        ino: ino_for(path),
        size,
        blocks: (size + 511) / 512,
        file_type,
        mode,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        atime: 0,
        mtime: 0,
        ctime: 0,
    }
}

pub fn is_sysfs_path(path: &str) -> bool {
    let comps = split_path(path);
    is_sys_path(&comps)
}

pub fn list_directory(path: &str) -> Option<Result<Vec<DirEntry>, &'static str>> {
    let comps = split_path(path);
    if !is_sys_path(&comps) {
        return None;
    }

    if comps.len() == 1 {
        let entries = ["cell", "system"]
            .iter()
            .map(|name| DirEntry {
                name: (*name).to_string(),
                ino: ino_for(&format!("/sys/{}", name)),
                file_type: FileType::Directory,
            })
            .collect();
        return Some(Ok(entries));
    }

    if is_cell_path(&comps) {
        match comps.len() {
            2 => {
                let mut snaps = list_domain_snapshots();
                snaps.sort_by_key(|s| s.id.as_u64());
                let entries = snaps
                    .into_iter()
                    .map(|snap| DirEntry {
                        name: snap.id.as_u64().to_string(),
                        ino: ino_for(&format!("/sys/cell/{}", snap.id.as_u64())),
                        file_type: FileType::Directory,
                    })
                    .collect();
                return Some(Ok(entries));
            }
            3 => {
                let id = match parse_domain_id(comps[2]) {
                    Ok(id) => id,
                    Err(e) => return Some(Err(e)),
                };
                if get_domain_snapshot(id).is_none() {
                    return Some(Err("Not found"));
                }
                let entries = CELL_FIELDS
                    .iter()
                    .map(|name| DirEntry {
                        name: (*name).to_string(),
                        ino: ino_for(&format!("/sys/cell/{}/{}", id.as_u64(), name)),
                        file_type: FileType::Regular,
                    })
                    .collect();
                return Some(Ok(entries));
            }
            _ => return Some(Err("Not a directory")),
        }
    }

    if is_system_path(&comps) {
        match comps.len() {
            2 => {
                let mut entries: Vec<DirEntry> = SYSTEM_DIRS
                    .iter()
                    .map(|name| DirEntry {
                        name: (*name).to_string(),
                        ino: ino_for(&format!("/sys/system/{}", name)),
                        file_type: FileType::Directory,
                    })
                    .collect();
                entries.extend(SYSTEM_ROOT_FILES.iter().map(|name| DirEntry {
                    name: (*name).to_string(),
                    ino: ino_for(&format!("/sys/system/{}", name)),
                    file_type: FileType::Regular,
                }));
                return Some(Ok(entries));
            }
            3 => {
                let leaf = comps[2];
                if leaf == "kernel" {
                    let entries = SYSTEM_KERNEL_FILES
                        .iter()
                        .map(|name| DirEntry {
                            name: (*name).to_string(),
                            ino: ino_for(&format!("/sys/system/kernel/{}", name)),
                            file_type: FileType::Regular,
                        })
                        .collect();
                    return Some(Ok(entries));
                }
                if leaf == "net" {
                    let entries = SYSTEM_NET_FILES
                        .iter()
                        .map(|name| DirEntry {
                            name: (*name).to_string(),
                            ino: ino_for(&format!("/sys/system/net/{}", name)),
                            file_type: FileType::Regular,
                        })
                        .collect();
                    return Some(Ok(entries));
                }
                if SYSTEM_ROOT_FILES.iter().any(|name| *name == leaf) {
                    return Some(Err("Not a directory"));
                }
                return Some(Err("Not found"));
            }
            _ => return Some(Err("Not a directory")),
        }
    }

    Some(Err("Not found"))
}

pub fn read_file(path: &str) -> Option<Result<Vec<u8>, &'static str>> {
    let comps = split_path(path);
    if !is_sys_path(&comps) {
        return None;
    }

    if comps.len() == 1 {
        return Some(Err("Is a directory"));
    }

    if is_cell_path(&comps) {
        if comps.len() != 4 {
            return Some(Err("Is a directory"));
        }

        let id = match parse_domain_id(comps[2]) {
            Ok(id) => id,
            Err(e) => return Some(Err(e)),
        };
        let snapshot = match get_domain_snapshot(id) {
            Some(s) => s,
            None => return Some(Err("Not found")),
        };
        let value = match field_value(&snapshot, comps[3]) {
            Some(v) => v,
            None => return Some(Err("Not found")),
        };
        return Some(Ok(value.into_bytes()));
    }

    if is_system_path(&comps) {
        if comps.len() == 2 {
            return Some(Err("Is a directory"));
        }

        if comps.len() == 3 {
            let leaf = comps[2];
            if leaf == "kernel" || leaf == "net" {
                return Some(Err("Is a directory"));
            }
            let value = match system_file_value(leaf) {
                Some(v) => v,
                None => return Some(Err("Not found")),
            };
            return Some(Ok(value.into_bytes()));
        }

        if comps.len() == 4 {
            let group = comps[2];
            let leaf = comps[3];
            let value = if group == "kernel" {
                system_kernel_value(leaf)
            } else if group == "net" {
                system_net_value(leaf)
            } else {
                None
            };
            let value = match value {
                Some(v) => v,
                None => return Some(Err("Not found")),
            };
            return Some(Ok(value.into_bytes()));
        }
        return Some(Err("Not found"));
    }

    Some(Err("Not found"))
}

pub fn stat_file(path: &str) -> Option<Result<FileAttr, &'static str>> {
    let comps = split_path(path);
    if !is_sys_path(&comps) {
        return None;
    }

    if comps.len() == 1 {
        return Some(Ok(file_attr(path, FileType::Directory, 0)));
    }

    if is_cell_path(&comps) {
        return match comps.len() {
            2 => Some(Ok(file_attr(path, FileType::Directory, 0))),
            3 => {
                let id = match parse_domain_id(comps[2]) {
                    Ok(id) => id,
                    Err(e) => return Some(Err(e)),
                };
                if get_domain_snapshot(id).is_none() {
                    return Some(Err("Not found"));
                }
                Some(Ok(file_attr(path, FileType::Directory, 0)))
            }
            4 => {
                let id = match parse_domain_id(comps[2]) {
                    Ok(id) => id,
                    Err(e) => return Some(Err(e)),
                };
                let snapshot = match get_domain_snapshot(id) {
                    Some(s) => s,
                    None => return Some(Err("Not found")),
                };
                let value = match field_value(&snapshot, comps[3]) {
                    Some(v) => v,
                    None => return Some(Err("Not found")),
                };
                Some(Ok(file_attr(path, FileType::Regular, value.len() as u64)))
            }
            _ => Some(Err("Not found")),
        };
    }

    if is_system_path(&comps) {
        return match comps.len() {
            2 => Some(Ok(file_attr(path, FileType::Directory, 0))),
            3 => {
                let leaf = comps[2];
                if leaf == "kernel" || leaf == "net" {
                    return Some(Ok(file_attr(path, FileType::Directory, 0)));
                }
                let value = match system_file_value(leaf) {
                    Some(v) => v,
                    None => return Some(Err("Not found")),
                };
                Some(Ok(file_attr(path, FileType::Regular, value.len() as u64)))
            }
            4 => {
                let group = comps[2];
                let leaf = comps[3];
                let value = if group == "kernel" {
                    system_kernel_value(leaf)
                } else if group == "net" {
                    system_net_value(leaf)
                } else {
                    None
                };
                let value = match value {
                    Some(v) => v,
                    None => return Some(Err("Not found")),
                };
                Some(Ok(file_attr(path, FileType::Regular, value.len() as u64)))
            }
            _ => Some(Err("Not found")),
        };
    }

    Some(Err("Not found"))
}

// --- /sys/system content helpers ---

fn generate_meminfo() -> String {
    let total_kb = crate::memory::total_memory_kb();
    let free_kb = crate::memory::free_memory_kb();
    let available_kb = free_kb + (free_kb / 4);
    let used_kb = total_kb.saturating_sub(free_kb);
    let cached_kb = used_kb / 4;
    let buffers_kb = used_kb / 8;
    let active_kb = used_kb / 2;
    let inactive_kb = used_kb / 4;

    format!(
        "MemTotal:       {:8} kB\n\
         MemFree:        {:8} kB\n\
         MemAvailable:   {:8} kB\n\
         Buffers:        {:8} kB\n\
         Cached:         {:8} kB\n\
         SwapCached:            0 kB\n\
         Active:         {:8} kB\n\
         Inactive:       {:8} kB\n\
         SwapTotal:             0 kB\n\
         SwapFree:              0 kB\n",
        total_kb,
        free_kb,
        available_kb,
        buffers_kb,
        cached_kb,
        active_kb,
        inactive_kb
    )
}

fn generate_cpuinfo() -> String {
    let cpu_count = crate::smp::cpu_count();
    let mut info = String::new();

    for cpu_id in 0..cpu_count {
        use core::fmt::Write;
        let _ = write!(
            info,
            "processor\t: {}\n\
             vendor_id\t: {}\n\
             cpu family\t: 6\n\
             model\t\t: 142\n\
             model name\t: {}\n\
             stepping\t: 10\n\
             cpu MHz\t\t: {:.3}\n\
             cache size\t: {} KB\n\
             physical id\t: 0\n\
             siblings\t: {}\n\
             core id\t\t: {}\n\
             cpu cores\t: {}\n\
             flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 sse sse2 ss ht syscall nx lm constant_tsc\n\
             bugs\t\t:\n\
             bogomips\t: {:.2}\n\n",
            cpu_id,
            get_cpu_vendor(),
            get_cpu_model_name(),
            3000.0,
            8192,
            cpu_count,
            cpu_id,
            cpu_count,
            6000.0
        );
    }

    info
}

fn generate_stat() -> String {
    let timer_ticks = crate::interrupts::get_timer_ticks();
    let ctx_switches = crate::task::context::CONTEXT_SWITCH_COUNT.load(Ordering::Relaxed);
    let boot_time = crate::time::now().saturating_sub(crate::time::current_tick() / 1000);
    let cpu_count = crate::smp::cpu_count();
    let domain_count = list_domain_snapshots().len() as u64;

    use core::fmt::Write;
    let mut output = String::new();

    let _ = write!(
        output,
        "cpu  {} 0 {} 0 0 0 {} 0 0 0\n",
        timer_ticks / 10,
        timer_ticks / 5,
        timer_ticks / 20
    );

    for i in 0..cpu_count {
        let _ = write!(
            output,
            "cpu{} {} 0 {} 0 0 0 {} 0 0 0\n",
            i,
            timer_ticks / (10 * cpu_count as u64),
            timer_ticks / (5 * cpu_count as u64),
            timer_ticks / (20 * cpu_count as u64)
        );
    }

    let _ = write!(output, "intr {}\n", timer_ticks);
    let _ = write!(output, "ctxt {}\n", ctx_switches);
    let _ = write!(output, "btime {}\n", boot_time);
    let _ = write!(output, "processes {}\n", domain_count);
    let _ = write!(output, "procs_running 1\n");
    let _ = write!(output, "procs_blocked 0\n");
    let _ = write!(output, "softirq 0 0 0 0 0 0 0 0 0 0 0\n");

    output
}

fn get_cpu_vendor() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;
        let result = __cpuid(0);
        let vendor_bytes = [
            (result.ebx as u8),
            ((result.ebx >> 8) as u8),
            ((result.ebx >> 16) as u8),
            ((result.ebx >> 24) as u8),
            (result.edx as u8),
            ((result.edx >> 8) as u8),
            ((result.edx >> 16) as u8),
            ((result.edx >> 24) as u8),
            (result.ecx as u8),
            ((result.ecx >> 8) as u8),
            ((result.ecx >> 16) as u8),
            ((result.ecx >> 24) as u8),
        ];
        if &vendor_bytes[..12] == b"GenuineIntel" {
            "GenuineIntel"
        } else if &vendor_bytes[..12] == b"AuthenticAMD" {
            "AuthenticAMD"
        } else {
            "Unknown"
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        "Unknown"
    }
}

fn get_cpu_model_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;
        let result = __cpuid(0x80000000);
        if result.eax >= 0x80000004 {
            let vendor = get_cpu_vendor();
            if vendor == "GenuineIntel" {
                "Intel(R) Core(TM) Processor"
            } else if vendor == "AuthenticAMD" {
                "AMD Processor"
            } else {
                "Unknown Processor"
            }
        } else {
            "Unknown Processor"
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        "Unknown Processor"
    }
}
