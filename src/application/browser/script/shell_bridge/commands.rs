// ============================================================================
// src/application/browser/script/shell_bridge/commands.rs - Built-in Commands
// ============================================================================
//!
//! ビルトイン同期コマンドの実装

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

use crate::application::browser::script::{ScriptError, ScriptResult};
use crate::application::browser::script::value::{
    ScriptValue, FileEntry, FileType, ProcessInfo, ProcessState,
};

// ============================================================================
// File System Commands
// ============================================================================

/// fs_ls: ディレクトリ一覧
pub fn cmd_fs_ls(args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    let path = args.get(0)
        .and_then(|v| v.as_string())
        .unwrap_or("/");
    
    // crate::fs::list_directory と連携
    match crate::fs::list_directory(path, "/") {
        Ok(dir_entries) => {
            let mut entries = Vec::new();
            for entry in dir_entries {
                let file_type = match entry.file_type {
                    crate::fs::FileType::Directory => FileType::Directory,
                    crate::fs::FileType::Regular => FileType::Regular,
                    crate::fs::FileType::Symlink => FileType::Symlink,
                    crate::fs::FileType::CharDevice | crate::fs::FileType::BlockDevice => FileType::Device,
                    crate::fs::FileType::Fifo => FileType::Pipe,
                    crate::fs::FileType::Socket => FileType::Socket,
                };
                entries.push(ScriptValue::FileEntry(FileEntry::new(
                    entry.name.clone(),
                    path.to_string(),
                    file_type,
                )));
            }
            Ok(ScriptValue::Array(entries))
        }
        Err(e) => Err(ScriptError::runtime(&format!("fs_ls error: {:?}", e))),
    }
}

/// fs_read: ファイル読み込み
pub fn cmd_fs_read(args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    let path = args.get(0)
        .and_then(|v| v.as_string())
        .ok_or_else(|| ScriptError::runtime("fs_read: path required"))?;
    
    // crate::fs::read_file_content と連携
    match crate::fs::read_file_content(path, "/") {
        Ok(content) => Ok(ScriptValue::Bytes(content)),
        Err(e) => Err(ScriptError::runtime(&format!("fs_read error: {:?}", e))),
    }
}

/// fs_write: ファイル書き込み
pub fn cmd_fs_write(args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    let path = args.get(0)
        .and_then(|v| v.as_string())
        .ok_or_else(|| ScriptError::runtime("fs_write: path required"))?;
    
    // 引数からデータを取得
    let data = match args.get(1) {
        Some(ScriptValue::Bytes(bytes)) => bytes.clone(),
        Some(ScriptValue::String(s)) => s.as_bytes().to_vec(),
        _ => return Err(ScriptError::runtime("fs_write: data required")),
    };
    
    // crate::fs::write_file_content と連携
    match crate::fs::write_file_content(path, "/", &data) {
        Ok(()) => Ok(ScriptValue::Bool(true)),
        Err(e) => Err(ScriptError::runtime(&format!("fs_write error: {:?}", e))),
    }
}

/// fs_stat: ファイル情報
pub fn cmd_fs_stat(args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    let path = args.get(0)
        .and_then(|v| v.as_string())
        .ok_or_else(|| ScriptError::runtime("fs_stat: path required"))?;
    
    Ok(ScriptValue::FileEntry(FileEntry::new(
        path.split('/').last().unwrap_or("").to_string(),
        path.to_string(),
        FileType::Regular,
    )))
}

/// fs_mkdir: ディレクトリ作成
pub fn cmd_fs_mkdir(args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    let path = args.get(0)
        .and_then(|v| v.as_string())
        .ok_or_else(|| ScriptError::runtime("fs_mkdir: path required"))?;
    
    // crate::fs::make_directory と連携
    match crate::fs::make_directory(path, "/") {
        Ok(()) => Ok(ScriptValue::Bool(true)),
        Err(e) => Err(ScriptError::runtime(&format!("fs_mkdir error: {:?}", e))),
    }
}

/// fs_rm: ファイル削除
pub fn cmd_fs_rm(args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    let path = args.get(0)
        .and_then(|v| v.as_string())
        .ok_or_else(|| ScriptError::runtime("fs_rm: path required"))?;
    
    // crate::fs::remove_file と連携
    match crate::fs::remove_file(path, "/") {
        Ok(()) => Ok(ScriptValue::Bool(true)),
        Err(e) => Err(ScriptError::runtime(&format!("fs_rm error: {:?}", e))),
    }
}

// ============================================================================
// Process Commands
// ============================================================================

/// ps: プロセス一覧
pub fn cmd_ps(_args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    // crate::task::process_manager から情報を取得
    let pm = crate::task::process_manager();
    let pids = pm.list();
    
    let mut processes = Vec::new();
    for pid in pids {
        if let Some(proc_arc) = pm.get(pid) {
            let proc = proc_arc.read();
            let state = match proc.state {
                crate::task::ProcessState::Creating => ProcessState::Sleeping,
                crate::task::ProcessState::Ready => ProcessState::Sleeping,
                crate::task::ProcessState::Running => ProcessState::Running,
                crate::task::ProcessState::Blocked => ProcessState::Blocked,
                crate::task::ProcessState::Stopped => ProcessState::Stopped,
                crate::task::ProcessState::Zombie => ProcessState::Zombie,
                crate::task::ProcessState::Dead => ProcessState::Zombie,
            };
            processes.push(ScriptValue::Process(ProcessInfo {
                pid: pid.as_u64() as u32,
                name: proc.name.clone(),
                state,
                cpu_usage: 0.0, // 詳細なCPU使用率は別途実装
                memory_kb: 0,   // 詳細なメモリ使用量は別途実装
                domain: String::from("user"),
            }));
        }
    }
    
    // カーネルプロセス（PID 0）を常に追加
    if processes.is_empty() {
        processes.push(ScriptValue::Process(ProcessInfo {
            pid: 0,
            name: String::from("kernel"),
            state: ProcessState::Running,
            cpu_usage: 0.0,
            memory_kb: 0,
            domain: String::from("system"),
        }));
    }
    
    Ok(ScriptValue::Array(processes))
}

// ============================================================================
// Network Commands
// ============================================================================

/// net_config: ネットワーク設定
pub fn cmd_net_config(_args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    // crate::net::global_stack から設定を取得
    let stack_guard = crate::net::global_stack().lock();
    let mut config = BTreeMap::new();
    
    if let Some(ref stack) = *stack_guard {
        let net_config = stack.config();
        
        // IPv4アドレス
        let ip = net_config.ipv4.address.as_bytes();
        config.insert(
            String::from("ip"),
            ScriptValue::String(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])),
        );
        
        // サブネットマスク
        let mask = net_config.ipv4.subnet_mask.as_bytes();
        config.insert(
            String::from("netmask"),
            ScriptValue::String(format!("{}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3])),
        );
        
        // ゲートウェイ
        let gw = net_config.ipv4.gateway.as_bytes();
        config.insert(
            String::from("gateway"),
            ScriptValue::String(format!("{}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3])),
        );
        
        // MACアドレス
        let mac = net_config.mac.as_bytes();
        config.insert(
            String::from("mac"),
            ScriptValue::String(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            )),
        );
        
        // ICMP Echo有効フラグ
        config.insert(
            String::from("icmp_echo_enabled"),
            ScriptValue::Bool(net_config.icmp_echo_enabled),
        );
    } else {
        // スタック未初期化時はデフォルト値
        config.insert(String::from("ip"), ScriptValue::String(String::from("0.0.0.0")));
        config.insert(String::from("netmask"), ScriptValue::String(String::from("0.0.0.0")));
        config.insert(String::from("gateway"), ScriptValue::String(String::from("0.0.0.0")));
        config.insert(String::from("mac"), ScriptValue::String(String::from("00:00:00:00:00:00")));
        config.insert(String::from("icmp_echo_enabled"), ScriptValue::Bool(false));
    }
    
    Ok(ScriptValue::Object(config))
}

/// net_connections: 接続一覧
pub fn cmd_net_connections(_args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    // crate::net から統計情報を取得（接続追跡は将来実装）
    let stack_guard = crate::net::global_stack().lock();
    let mut info = BTreeMap::new();
    
    if let Some(ref stack) = *stack_guard {
        let stats = stack.stats();
        info.insert(
            String::from("rx_packets"),
            ScriptValue::Int(stats.rx_packets.load(core::sync::atomic::Ordering::Relaxed) as i64),
        );
        info.insert(
            String::from("tx_packets"),
            ScriptValue::Int(stats.tx_packets.load(core::sync::atomic::Ordering::Relaxed) as i64),
        );
        info.insert(
            String::from("rx_bytes"),
            ScriptValue::Int(stats.rx_bytes.load(core::sync::atomic::Ordering::Relaxed) as i64),
        );
        info.insert(
            String::from("tx_bytes"),
            ScriptValue::Int(stats.tx_bytes.load(core::sync::atomic::Ordering::Relaxed) as i64),
        );
        info.insert(
            String::from("rx_errors"),
            ScriptValue::Int(stats.rx_errors.load(core::sync::atomic::Ordering::Relaxed) as i64),
        );
        info.insert(
            String::from("tx_errors"),
            ScriptValue::Int(stats.tx_errors.load(core::sync::atomic::Ordering::Relaxed) as i64),
        );
    } else {
        // スタック未初期化時は0を返す
        info.insert(String::from("rx_packets"), ScriptValue::Int(0));
        info.insert(String::from("tx_packets"), ScriptValue::Int(0));
        info.insert(String::from("rx_bytes"), ScriptValue::Int(0));
        info.insert(String::from("tx_bytes"), ScriptValue::Int(0));
        info.insert(String::from("rx_errors"), ScriptValue::Int(0));
        info.insert(String::from("tx_errors"), ScriptValue::Int(0));
    }
    
    Ok(ScriptValue::Object(info))
}

// ============================================================================
// System Commands
// ============================================================================

/// uptime: 稼働時間（秒）
pub fn cmd_uptime(_args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    // SystemClockから稼働時間を取得
    let uptime_secs = crate::time::system_clock().uptime_secs();
    Ok(ScriptValue::Int(uptime_secs as i64))
}

/// memory_info: メモリ情報
pub fn cmd_memory_info(_args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    // crate::memory からヒープ情報を取得
    let (used, free) = crate::memory::heap_stats();
    let total = crate::memory::HEAP_SIZE;
    
    let mut info = BTreeMap::new();
    info.insert(String::from("total"), ScriptValue::Int(total as i64));
    info.insert(String::from("used"), ScriptValue::Int(used as i64));
    info.insert(String::from("free"), ScriptValue::Int(free as i64));
    info.insert(String::from("heap_size_kb"), ScriptValue::Int((total / 1024) as i64));
    
    Ok(ScriptValue::Object(info))
}

// ============================================================================
// Utility Commands
// ============================================================================

/// type_of: 型名取得
pub fn cmd_type_of(args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    let value = args.get(0).cloned().unwrap_or(ScriptValue::Nil);
    Ok(ScriptValue::String(value.type_name().to_string()))
}

/// len: 長さ取得
pub fn cmd_len(args: &[ScriptValue]) -> ScriptResult<ScriptValue> {
    let value = args.get(0).cloned().unwrap_or(ScriptValue::Nil);
    let len = match &value {
        ScriptValue::String(s) => s.len() as i64,
        ScriptValue::Bytes(b) => b.len() as i64,
        ScriptValue::Array(a) => a.len() as i64,
        ScriptValue::Object(o) => o.len() as i64,
        _ => 0,
    };
    Ok(ScriptValue::Int(len))
}
