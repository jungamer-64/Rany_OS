// ============================================================================
// src/application/browser/script/shell_bridge/types.rs - Type Definitions
// ============================================================================
//!
//! Shell Bridgeの型定義と変換ユーティリティ

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;
use core::future::Future;
use core::pin::Pin;

use crate::application::browser::script::{ScriptError, ScriptResult};
use crate::application::browser::script::value::{
    ScriptValue, FileEntry, FileType, Permissions, NetConnection, ProcessInfo, ProcessState,
};

// ============================================================================
// Type Aliases
// ============================================================================

/// シェルコマンドの型定義（同期版）
pub type ShellCommandFn = fn(&[ScriptValue]) -> ScriptResult<ScriptValue>;

/// 非同期シェルコマンドのFuture型
pub type AsyncCommandFuture = Pin<Box<dyn Future<Output = ScriptResult<ScriptValue>> + Send>>;

/// 非同期シェルコマンドの型定義
pub type AsyncShellCommandFn = fn(&[ScriptValue]) -> AsyncCommandFuture;

/// 非同期タスクのID
pub type TaskId = u64;

// ============================================================================
// Async State
// ============================================================================

/// 非同期操作の状態
#[derive(Debug, Clone)]
pub enum AsyncState {
    /// 保留中
    Pending,
    /// 完了（結果付き）
    Ready(ScriptValue),
    /// エラー
    Error(String),
}

// ============================================================================
// Async Task
// ============================================================================

/// 非同期タスク情報
#[derive(Debug)]
pub struct AsyncTask {
    /// タスクID
    pub id: TaskId,
    /// タスク名
    pub name: String,
    /// 状態
    pub state: AsyncState,
    /// 作成時刻（tick）
    pub created_at: u64,
}

// ============================================================================
// Value Conversion
// ============================================================================

/// ExoValue と ScriptValue の相互変換トレイト
pub trait ValueConversion {
    /// ScriptValue へ変換
    fn to_script_value(self) -> ScriptValue;
    /// ScriptValue から変換
    fn from_script_value(value: ScriptValue) -> Self;
}

/// ExoValue から ScriptValue への変換ユーティリティ
pub mod conversion {
    use super::*;
    
    /// ExoValue相当の値をScriptValueに変換
    /// 
    /// これはexoshell.rsのExoValueとの直接的な変換ではなく、
    /// 同等の概念を持つ値の変換を提供する
    pub fn convert_to_script_value(
        exo_type: &str,
        data: &BTreeMap<String, String>,
    ) -> ScriptValue {
        match exo_type {
            "nil" => ScriptValue::Nil,
            "bool" => {
                let val = data.get("value").map(|s| s == "true").unwrap_or(false);
                ScriptValue::Bool(val)
            }
            "int" => {
                let val = data.get("value")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                ScriptValue::Int(val)
            }
            "float" => {
                let val = data.get("value")
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                ScriptValue::Float(val)
            }
            "string" => {
                let val = data.get("value").cloned().unwrap_or_default();
                ScriptValue::String(val)
            }
            "file_entry" => {
                let entry = FileEntry {
                    name: data.get("name").cloned().unwrap_or_default(),
                    path: data.get("path").cloned().unwrap_or_default(),
                    file_type: match data.get("file_type").map(|s| s.as_str()) {
                        Some("directory") => FileType::Directory,
                        Some("symlink") => FileType::Symlink,
                        Some("device") => FileType::Device,
                        Some("socket") => FileType::Socket,
                        Some("pipe") => FileType::Pipe,
                        _ => FileType::Regular,
                    },
                    size: data.get("size").and_then(|s| s.parse().ok()).unwrap_or(0),
                    owner: data.get("owner").cloned().unwrap_or_default(),
                    permissions: Permissions {
                        read: data.get("perm_read").map(|s| s == "true").unwrap_or(false),
                        write: data.get("perm_write").map(|s| s == "true").unwrap_or(false),
                        execute: data.get("perm_execute").map(|s| s == "true").unwrap_or(false),
                        delete: data.get("perm_delete").map(|s| s == "true").unwrap_or(false),
                        grant: data.get("perm_grant").map(|s| s == "true").unwrap_or(false),
                    },
                    created: data.get("created").and_then(|s| s.parse().ok()).unwrap_or(0),
                    modified: data.get("modified").and_then(|s| s.parse().ok()).unwrap_or(0),
                    inode: data.get("inode").and_then(|s| s.parse().ok()).unwrap_or(0),
                };
                ScriptValue::FileEntry(entry)
            }
            "net_connection" => {
                let conn = NetConnection {
                    protocol: data.get("protocol").cloned().unwrap_or_default(),
                    local_addr: parse_ipv4(data.get("local_addr").map(|s| s.as_str()).unwrap_or("0.0.0.0")),
                    local_port: data.get("local_port").and_then(|s| s.parse().ok()).unwrap_or(0),
                    remote_addr: parse_ipv4(data.get("remote_addr").map(|s| s.as_str()).unwrap_or("0.0.0.0")),
                    remote_port: data.get("remote_port").and_then(|s| s.parse().ok()).unwrap_or(0),
                    state: data.get("state").cloned().unwrap_or_default(),
                    rx_bytes: data.get("rx_bytes").and_then(|s| s.parse().ok()).unwrap_or(0),
                    tx_bytes: data.get("tx_bytes").and_then(|s| s.parse().ok()).unwrap_or(0),
                };
                ScriptValue::NetConnection(conn)
            }
            "process" => {
                let proc = ProcessInfo {
                    pid: data.get("pid").and_then(|s| s.parse().ok()).unwrap_or(0),
                    name: data.get("name").cloned().unwrap_or_default(),
                    state: match data.get("state").map(|s| s.as_str()) {
                        Some("running") => ProcessState::Running,
                        Some("sleeping") => ProcessState::Sleeping,
                        Some("blocked") => ProcessState::Blocked,
                        Some("stopped") => ProcessState::Stopped,
                        Some("zombie") => ProcessState::Zombie,
                        _ => ProcessState::Running,
                    },
                    cpu_usage: data.get("cpu_usage").and_then(|s| s.parse().ok()).unwrap_or(0.0),
                    memory_kb: data.get("memory_kb").and_then(|s| s.parse().ok()).unwrap_or(0),
                    domain: data.get("domain").cloned().unwrap_or_default(),
                };
                ScriptValue::Process(proc)
            }
            "error" => {
                let msg = data.get("message").cloned().unwrap_or_default();
                ScriptValue::Error(msg)
            }
            _ => ScriptValue::Nil,
        }
    }
    
    /// IPv4アドレス文字列をバイト配列にパース
    pub fn parse_ipv4(s: &str) -> [u8; 4] {
        let parts: Vec<u8> = s.split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        if parts.len() == 4 {
            [parts[0], parts[1], parts[2], parts[3]]
        } else {
            [0, 0, 0, 0]
        }
    }
    
    /// ScriptValueをシリアル化されたデータに変換
    pub fn script_value_to_map(value: &ScriptValue) -> (String, BTreeMap<String, String>) {
        let mut data = BTreeMap::new();
        
        let type_name = match value {
            ScriptValue::Nil => "nil",
            ScriptValue::Bool(b) => {
                data.insert(String::from("value"), b.to_string());
                "bool"
            }
            ScriptValue::Int(i) => {
                data.insert(String::from("value"), i.to_string());
                "int"
            }
            ScriptValue::Float(f) => {
                data.insert(String::from("value"), f.to_string());
                "float"
            }
            ScriptValue::String(s) => {
                data.insert(String::from("value"), s.clone());
                "string"
            }
            ScriptValue::Bytes(b) => {
                data.insert(String::from("length"), b.len().to_string());
                "bytes"
            }
            ScriptValue::Array(_) => "array",
            ScriptValue::Object(_) => "object",
            ScriptValue::Element(_) => "element",
            ScriptValue::Function(_) => "function",
            ScriptValue::NativeFunction(_) => "native_function",
            ScriptValue::Iterator(_) => "iterator",
            ScriptValue::Range(_) => "range",
            ScriptValue::FileEntry(e) => {
                data.insert(String::from("name"), e.name.clone());
                data.insert(String::from("path"), e.path.clone());
                data.insert(String::from("size"), e.size.to_string());
                "file_entry"
            }
            ScriptValue::NetConnection(c) => {
                data.insert(String::from("protocol"), c.protocol.clone());
                data.insert(String::from("local_port"), c.local_port.to_string());
                data.insert(String::from("remote_port"), c.remote_port.to_string());
                "net_connection"
            }
            ScriptValue::Process(p) => {
                data.insert(String::from("pid"), p.pid.to_string());
                data.insert(String::from("name"), p.name.clone());
                "process"
            }
            ScriptValue::Capability(cap) => {
                data.insert(String::from("id"), cap.id.to_string());
                data.insert(String::from("resource"), cap.resource.clone());
                "capability"
            }
            ScriptValue::Error(e) => {
                data.insert(String::from("message"), e.clone());
                "error"
            }
            ScriptValue::Promise(p) => {
                data.insert(String::from("state"), format!("{:?}", p.state));
                "promise"
            }
        };
        
        (type_name.to_string(), data)
    }
}
