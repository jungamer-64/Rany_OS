// ============================================================================
// kernel/src/system_info.rs - System Information Provider
// ============================================================================
//!
//! # システム情報プロバイダー
//!
//! カーネル各サブシステムの情報を集約し、2つのAPIを提供する。
//!
//! ## 構造化データAPI（ExoShellネームスペース: `SysNamespace` が使用）
//! 生データアクセス関数群。`SysNamespace` がこれらを `ExoValue` に変換する。
//!
//! ## ファイルパス互換API（gui_services / procfs が使用）
//! `/sys/cell/*`、`/sys/system/*` パス経由のテキスト出力。
//!
//! ## 設計原則
//! - `ExoValue` への依存を持たない（shellモジュール非依存）
//! - 上位層（SysNamespace）がExoValueラッピングを担当

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::domain_system::{get_domain_snapshot, list_domain_snapshots, DomainId, DomainState};
use crate::fs::{DirEntry, FileAttr, FileMode, FileType};

mod cpuinfo_gen;
use cpuinfo_gen::*;

// ============================================================================
// Primary API: Raw data accessors (SysNamespace が ExoValue に変換する)
// ============================================================================

/// OS名
pub fn os_name() -> &'static str {
    "RanyOS"
}

/// アーキテクチャ名
pub fn arch_name() -> &'static str {
    "x86_64"
}

/// カーネルバージョン
pub fn kernel_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// カーネル名
pub fn kernel_name() -> &'static str {
    "ExoRust"
}

/// 合計メモリ (KB)
pub fn memory_total_kb() -> u64 {
    crate::memory::total_memory_kb()
}

/// 空きメモリ (KB)
pub fn memory_free_kb() -> u64 {
    crate::memory::free_memory_kb()
}

/// アップタイム (tick単位、1tick = 1ms)
pub fn uptime_ticks() -> u64 {
    crate::time::current_tick()
}

/// CPU数
pub fn cpu_count() -> usize {
    crate::smp::cpu_count() as usize
}

/// CPUベンダー文字列
pub fn cpu_vendor() -> &'static str {
    get_cpu_vendor()
}

/// CPUモデル名
pub fn cpu_model() -> &'static str {
    get_cpu_model_name()
}

/// タイマー割り込み回数
pub fn timer_ticks() -> u64 {
    crate::interrupts::get_timer_ticks()
}

/// コンテキストスイッチ回数
pub fn context_switch_count() -> u64 {
    crate::task::context::CONTEXT_SWITCH_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}

/// ブート時刻 (秒)
pub fn boot_time_secs() -> u64 {
    crate::time::now().saturating_sub(crate::time::current_tick() / 1000)
}

/// ドメインスナップショット一覧
pub fn domain_snapshots() -> Vec<crate::domain_system::DomainSnapshot> {
    let mut snaps = list_domain_snapshots();
    snaps.sort_by_key(|s| s.id.as_u64());
    snaps
}

/// 指定ドメインのスナップショット
pub fn domain_snapshot(id: u64) -> Option<crate::domain_system::DomainSnapshot> {
    get_domain_snapshot(DomainId::new(id))
}

/// ドメイン状態を文字列に変換
pub fn state_str(state: DomainState) -> &'static str {
    state_to_str(state)
}

// ============================================================================
// File-path compatibility layer: Constants & Utilities
// ============================================================================
// gui_services / procfs が使用する `/sys/` パスベースAPIの支援構造

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

/// `/sys/` パスかどうかを判定する（互換API）
pub fn is_sysfs_path(path: &str) -> bool {
    let comps = split_path(path);
    is_sys_path(&comps)
}

// ============================================================================
// Internal helpers
// ============================================================================

fn state_to_str(state: DomainState) -> &'static str {
    match state {
        DomainState::Initializing => "initializing",
        DomainState::Running => "running",
        DomainState::Suspended => "suspended",
        DomainState::Stopped => "stopped",
        DomainState::Terminated => "terminated",
    }
}

fn parse_domain_id(comp: &str) -> Result<DomainId, &'static str> {
    let id = comp.parse::<u64>().map_err(|_| "Invalid domain id")?;
    Ok(DomainId::new(id))
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

// ============================================================================
// File-path text formatters (compatibility layer - derives from ExoValue data)
// ============================================================================

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
        "filesystems" => Some(String::from("nodev\ttmpfs\n")),
        "mounts" => Some(String::from("")),
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

// ============================================================================
// Inode / FileAttr helpers
// ============================================================================

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

// ============================================================================
// Cell directory listing
// ============================================================================

fn list_cell_directory(comps: &[&str]) -> Option<Result<Vec<DirEntry>, &'static str>> {
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
            Some(Ok(entries))
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
            Some(Ok(entries))
        }
        _ => Some(Err("Not a directory")),
    }
}

// ============================================================================
// System directory listing
// ============================================================================

fn list_system_directory(comps: &[&str]) -> Option<Result<Vec<DirEntry>, &'static str>> {
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
            Some(Ok(entries))
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
            Some(Err("Not found"))
        }
        _ => Some(Err("Not a directory")),
    }
}

// ============================================================================
// Public API: list_directory
// ============================================================================

/// `/sys/` 配下のディレクトリ一覧を返す。
/// パスが `/sys/` でない場合は `None` を返す（他のハンドラへフォールスルー）。
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
        return list_cell_directory(&comps);
    }

    if is_system_path(&comps) {
        return list_system_directory(&comps);
    }

    Some(Err("Not found"))
}

// ============================================================================
// Internal read helpers
// ============================================================================

/// systemグループ(kernel/net)に属するファイル値を解決する
fn resolve_system_group_value(group: &str, leaf: &str) -> Option<String> {
    match group {
        "kernel" => system_kernel_value(leaf),
        "net" => system_net_value(leaf),
        _ => None,
    }
}

/// セルドメインのフィールド値を取得する
fn lookup_cell_field_value(comps: &[&str]) -> Result<String, &'static str> {
    let id = parse_domain_id(comps[2])?;
    let snapshot = get_domain_snapshot(id).ok_or("Not found")?;
    field_value(&snapshot, comps[3]).ok_or("Not found")
}

/// read_file: セルパスの読み取り処理
fn read_cell_file(comps: &[&str]) -> Result<Vec<u8>, &'static str> {
    if comps.len() != 4 {
        return Err("Is a directory");
    }
    let value = lookup_cell_field_value(comps)?;
    Ok(value.into_bytes())
}

/// read_file: システムパスの読み取り処理
fn read_system_file(comps: &[&str]) -> Result<Vec<u8>, &'static str> {
    if comps.len() == 2 {
        return Err("Is a directory");
    }
    if comps.len() == 3 {
        let leaf = comps[2];
        if leaf == "kernel" || leaf == "net" {
            return Err("Is a directory");
        }
        return system_file_value(leaf)
            .map(|v| v.into_bytes())
            .ok_or("Not found");
    }
    if comps.len() == 4 {
        return resolve_system_group_value(comps[2], comps[3])
            .map(|v| v.into_bytes())
            .ok_or("Not found");
    }
    Err("Not found")
}

// ============================================================================
// Public API: read_file
// ============================================================================

/// `/sys/` 配下のファイル内容を読み取る。
/// パスが `/sys/` でない場合は `None` を返す。
pub fn read_file(path: &str) -> Option<Result<Vec<u8>, &'static str>> {
    let comps = split_path(path);
    if !is_sys_path(&comps) {
        return None;
    }
    if comps.len() == 1 {
        return Some(Err("Is a directory"));
    }
    if is_cell_path(&comps) {
        return Some(read_cell_file(&comps));
    }
    if is_system_path(&comps) {
        return Some(read_system_file(&comps));
    }
    Some(Err("Not found"))
}

// ============================================================================
// Internal stat helpers
// ============================================================================

/// stat_file: セルパスのファイル属性取得
fn stat_cell_path(path: &str, comps: &[&str]) -> Result<FileAttr, &'static str> {
    match comps.len() {
        2 => Ok(file_attr(path, FileType::Directory, 0)),
        3 => {
            let id = parse_domain_id(comps[2])?;
            if get_domain_snapshot(id).is_none() {
                return Err("Not found");
            }
            Ok(file_attr(path, FileType::Directory, 0))
        }
        4 => {
            let value = lookup_cell_field_value(comps)?;
            Ok(file_attr(path, FileType::Regular, value.len() as u64))
        }
        _ => Err("Not found"),
    }
}

/// stat_file: システムパスのファイル属性取得
fn stat_system_path(path: &str, comps: &[&str]) -> Result<FileAttr, &'static str> {
    match comps.len() {
        2 => Ok(file_attr(path, FileType::Directory, 0)),
        3 => {
            let leaf = comps[2];
            if leaf == "kernel" || leaf == "net" {
                return Ok(file_attr(path, FileType::Directory, 0));
            }
            let value = system_file_value(leaf).ok_or("Not found")?;
            Ok(file_attr(path, FileType::Regular, value.len() as u64))
        }
        4 => {
            let value = resolve_system_group_value(comps[2], comps[3])
                .ok_or("Not found")?;
            Ok(file_attr(path, FileType::Regular, value.len() as u64))
        }
        _ => Err("Not found"),
    }
}

// ============================================================================
// Public API: stat_file
// ============================================================================

/// `/sys/` 配下のファイル属性を返す。
/// パスが `/sys/` でない場合は `None` を返す。
pub fn stat_file(path: &str) -> Option<Result<FileAttr, &'static str>> {
    let comps = split_path(path);
    if !is_sys_path(&comps) {
        return None;
    }
    if comps.len() == 1 {
        return Some(Ok(file_attr(path, FileType::Directory, 0)));
    }
    if is_cell_path(&comps) {
        return Some(stat_cell_path(path, &comps));
    }
    if is_system_path(&comps) {
        return Some(stat_system_path(path, &comps));
    }
    Some(Err("Not found"))
}

// ============================================================================
// Meminfo helper
// ============================================================================

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
