// ============================================================================
// src/shell/exoshell.rs - ExoRust Native REPL Environment
// ============================================================================
//!
//! # ExoShell - Rust式REPL環境
//!
//! ExoRustの設計思想に基づいた新しいシェル環境。
//! Unix互換コマンドではなく、Rustの構文でOSリソースを直接操作する。
//!
//! ## 設計原則
//! 1. **型付きオブジェクト**: テキストストリームではなく構造体を直接操作
//! 2. **ゼロコピー**: SAS（単一アドレス空間）を活かしたポインタ渡し
//! 3. **Capability**: chmod/chown ではなく grant/revoke による権限管理
//! 4. **メソッドチェーン**: パイプラインではなくイテレータ操作
//! 5. **Async/Await**: I/O操作は非同期で他のタスクをブロックしない
//!
//! ## 使用例
//! ```text
//! # Unix式（非推奨）
//! ls -la /home | grep "admin"
//!
//! # ExoShell式（推奨）
//! fs.entries("/home").filter(|e| e.owner == "admin").display()
//! ```

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Display, Write};
use core::future::Future;
use core::pin::Pin;

// ============================================================================
// Core Types - 型付きオブジェクトシステム
// ============================================================================

/// ExoShellの値型
/// テキストではなく、構造化されたデータを表現
#[derive(Debug, Clone)]
pub enum ExoValue {
    /// 空値
    Nil,
    /// 真偽値
    Bool(bool),
    /// 整数
    Int(i64),
    /// 浮動小数点
    Float(f64),
    /// 文字列
    String(String),
    /// バイト列（ゼロコピー対応）
    Bytes(Vec<u8>),
    /// 配列（オブジェクトのリスト）
    Array(Vec<ExoValue>),
    /// マップ（キーバリュー）
    Map(BTreeMap<String, ExoValue>),
    /// ファイルエントリ
    FileEntry(FileEntry),
    /// ネットワーク接続
    NetConnection(NetConnection),
    /// プロセス情報
    Process(ProcessInfo),
    /// Capability（権限トークン）
    Capability(Capability),
    /// イテレータ（遅延評価）
    Iterator(ExoIterator),
    /// エラー
    Error(String),
}

/// ファイルシステムエントリ（構造化データ）
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub file_type: FileType,
    pub size: u64,
    pub owner: String,
    pub permissions: Permissions,
    pub created: u64,
    pub modified: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Device,
    Socket,
    Pipe,
}

/// Capabilityベースのパーミッション
/// Unix の rwx ではなく、具体的な操作権限を表現
#[derive(Debug, Clone)]
pub struct Permissions {
    /// 読み取り可能
    pub read: bool,
    /// 書き込み可能
    pub write: bool,
    /// 実行/トラバース可能
    pub execute: bool,
    /// 削除可能
    pub delete: bool,
    /// 権限変更可能（grant/revoke）
    pub grant: bool,
}

/// ネットワーク接続情報
#[derive(Debug, Clone)]
pub struct NetConnection {
    pub protocol: String,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub state: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// プロセス情報
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub state: ProcessState,
    pub cpu_usage: f32,
    pub memory_kb: u64,
    pub domain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Sleeping,
    Blocked,
    Stopped,
    Zombie,
}

/// Capability（権限トークン）
/// ExoRustのセキュリティモデルの中核
#[derive(Debug, Clone)]
pub struct Capability {
    /// Capability ID
    pub id: u64,
    /// 対象リソースのパス/識別子
    pub resource: String,
    /// 許可された操作
    pub operations: Vec<CapOperation>,
    /// 発行者（ドメイン）
    pub issuer: String,
    /// 有効期限（タイムスタンプ）
    pub expires: Option<u64>,
    /// 委譲可能か
    pub delegatable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOperation {
    Read,
    Write,
    Execute,
    Delete,
    Grant,
    Revoke,
    Create,
    List,
}

/// 遅延評価イテレータ
#[derive(Debug, Clone)]
pub struct ExoIterator {
    pub source: String,
    pub filters: Vec<String>,
    pub transforms: Vec<String>,
    pub limit: Option<usize>,
}

// ============================================================================
// Display implementations
// ============================================================================

impl Display for ExoValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExoValue::Nil => write!(f, "nil"),
            ExoValue::Bool(b) => write!(f, "{}", b),
            ExoValue::Int(i) => write!(f, "{}", i),
            ExoValue::Float(fl) => write!(f, "{:.2}", fl),
            ExoValue::String(s) => write!(f, "{}", s),
            ExoValue::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            ExoValue::Array(arr) => {
                writeln!(f, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    writeln!(f, "  [{}] {}", i, item)?;
                }
                write!(f, "]")
            }
            ExoValue::Map(map) => {
                writeln!(f, "{{")?;
                for (k, v) in map.iter() {
                    writeln!(f, "  {}: {}", k, v)?;
                }
                write!(f, "}}")
            }
            ExoValue::FileEntry(e) => e.fmt(f),
            ExoValue::NetConnection(c) => c.fmt(f),
            ExoValue::Process(p) => p.fmt(f),
            ExoValue::Capability(cap) => cap.fmt(f),
            ExoValue::Iterator(it) => write!(f, "<Iterator: {} -> {} filters>", it.source, it.filters.len()),
            ExoValue::Error(e) => write!(f, "Error: {}", e),
        }
    }
}

impl Display for FileEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_char = match self.file_type {
            FileType::Directory => 'd',
            FileType::Symlink => 'l',
            FileType::Device => 'c',
            FileType::Socket => 's',
            FileType::Pipe => 'p',
            FileType::Regular => '-',
        };
        let perm = format!(
            "{}{}{}",
            if self.permissions.read { "r" } else { "-" },
            if self.permissions.write { "w" } else { "-" },
            if self.permissions.execute { "x" } else { "-" }
        );
        write!(
            f,
            "{}{} {:>8} {} {}",
            type_char,
            perm,
            format_size(self.size),
            self.owner,
            self.name
        )
    }
}

impl Display for NetConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<5} {}.{}.{}.{}:{:<5} -> {}.{}.{}.{}:{:<5} [{}]",
            self.protocol,
            self.local_addr[0], self.local_addr[1], 
            self.local_addr[2], self.local_addr[3],
            self.local_port,
            self.remote_addr[0], self.remote_addr[1],
            self.remote_addr[2], self.remote_addr[3],
            self.remote_port,
            self.state
        )
    }
}

impl Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:>5} {:>8} {:>5.1}% {:>8} KB  {}",
            self.pid,
            format!("{:?}", self.state),
            self.cpu_usage,
            self.memory_kb,
            self.name
        )
    }
}

impl Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ops: Vec<&str> = self.operations.iter()
            .map(|op| match op {
                CapOperation::Read => "R",
                CapOperation::Write => "W",
                CapOperation::Execute => "X",
                CapOperation::Delete => "D",
                CapOperation::Grant => "G",
                CapOperation::Revoke => "V",
                CapOperation::Create => "C",
                CapOperation::List => "L",
            })
            .collect();
        write!(
            f,
            "Cap[{}] {} [{}] from:{} delegatable:{}",
            self.id,
            self.resource,
            ops.join(""),
            self.issuer,
            self.delegatable
        )
    }
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

// ============================================================================
// Namespace Objects - オブジェクト指向API (Async)
// ============================================================================

/// ファイルシステム名前空間
pub struct FsNamespace;

impl FsNamespace {
    /// ディレクトリのエントリを取得（イテレータとして）
    /// async版: I/O操作中に他のタスクに譲る
    pub async fn entries(path: &str) -> ExoValue {
        // Yield point: 他のタスクに実行機会を与える
        crate::task::yield_now().await;
        
        match crate::fs::list_directory(path, "/") {
            Ok(entries) => {
                let values: Vec<ExoValue> = entries
                    .into_iter()
                    .map(|e| {
                        ExoValue::FileEntry(FileEntry {
                            name: e.name.clone(),
                            path: if path == "/" {
                                format!("/{}", e.name)
                            } else {
                                format!("{}/{}", path, e.name)
                            },
                            file_type: match e.file_type {
                                crate::fs::FileType::Directory => FileType::Directory,
                                crate::fs::FileType::Symlink => FileType::Symlink,
                                crate::fs::FileType::CharDevice => FileType::Device,
                                crate::fs::FileType::BlockDevice => FileType::Device,
                                crate::fs::FileType::Socket => FileType::Socket,
                                crate::fs::FileType::Fifo => FileType::Pipe,
                                _ => FileType::Regular,
                            },
                            size: 0, // DirEntry doesn't have size, need stat for that
                            owner: String::from("root"),
                            permissions: Permissions {
                                read: true,
                                write: true,
                                execute: e.file_type == crate::fs::FileType::Directory,
                                delete: true,
                                grant: false,
                            },
                            created: 0,
                            modified: 0,
                            inode: e.ino,
                        })
                    })
                    .collect();
                ExoValue::Array(values)
            }
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ファイルを読み取り（ゼロコピー対応）
    pub async fn read(path: &str) -> ExoValue {
        crate::task::yield_now().await;
        
        match crate::fs::read_file_content(path, "/") {
            Ok(content) => ExoValue::Bytes(content),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ファイルに書き込み
    pub async fn write(path: &str, data: &[u8]) -> ExoValue {
        crate::task::yield_now().await;
        
        match crate::fs::write_file_content(path, "/", data) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ファイル/ディレクトリの詳細情報
    pub async fn stat(path: &str) -> ExoValue {
        crate::task::yield_now().await;
        
        match crate::fs::stat_file(path, "/") {
            Ok(attr) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("path"), ExoValue::String(path.to_string()));
                map.insert(String::from("size"), ExoValue::Int(attr.size as i64));
                map.insert(String::from("inode"), ExoValue::Int(attr.ino as i64));
                map.insert(String::from("links"), ExoValue::Int(attr.nlink as i64));
                map.insert(String::from("type"), ExoValue::String(format!("{:?}", attr.file_type)));
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ディレクトリ作成
    pub async fn mkdir(path: &str) -> ExoValue {
        crate::task::yield_now().await;
        
        match crate::fs::make_directory(path, "/") {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// 削除
    pub async fn remove(path: &str) -> ExoValue {
        crate::task::yield_now().await;
        
        // まずファイルとして削除を試行
        match crate::fs::remove_file(path, "/") {
            Ok(()) => ExoValue::Bool(true),
            Err(crate::fs::FsError::IsDirectory) => {
                // ディレクトリとして削除
                match crate::fs::remove_directory(path, "/") {
                    Ok(()) => ExoValue::Bool(true),
                    Err(e) => ExoValue::Error(format!("{:?}", e)),
                }
            }
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }
}

/// ネットワーク名前空間
pub struct NetNamespace;

impl NetNamespace {
    /// ネットワーク設定を取得
    pub fn config() -> ExoValue {
        if let Some(cfg) = crate::net::get_network_config() {
            let mut map = BTreeMap::new();
            map.insert(
                String::from("ip"),
                ExoValue::String(format!(
                    "{}.{}.{}.{}",
                    cfg.ip[0], cfg.ip[1], cfg.ip[2], cfg.ip[3]
                )),
            );
            map.insert(
                String::from("netmask"),
                ExoValue::String(format!(
                    "{}.{}.{}.{}",
                    cfg.netmask[0], cfg.netmask[1], cfg.netmask[2], cfg.netmask[3]
                )),
            );
            map.insert(
                String::from("mac"),
                ExoValue::String(format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    cfg.mac[0], cfg.mac[1], cfg.mac[2],
                    cfg.mac[3], cfg.mac[4], cfg.mac[5]
                )),
            );
            ExoValue::Map(map)
        } else {
            ExoValue::Error(String::from("Network not configured"))
        }
    }

    /// ネットワーク統計
    pub fn stats() -> ExoValue {
        if let Some(stats) = crate::net::get_network_stats() {
            let mut map = BTreeMap::new();
            map.insert(String::from("rx_packets"), ExoValue::Int(stats.rx_packets as i64));
            map.insert(String::from("tx_packets"), ExoValue::Int(stats.tx_packets as i64));
            map.insert(String::from("rx_bytes"), ExoValue::Int(stats.rx_bytes as i64));
            map.insert(String::from("tx_bytes"), ExoValue::Int(stats.tx_bytes as i64));
            map.insert(String::from("rx_errors"), ExoValue::Int(stats.rx_errors as i64));
            map.insert(String::from("rx_dropped"), ExoValue::Int(stats.rx_dropped as i64));
            ExoValue::Map(map)
        } else {
            ExoValue::Error(String::from("No network statistics"))
        }
    }

    /// ARP キャッシュ
    pub fn arp_cache() -> ExoValue {
        if let Some(entries) = crate::net::get_arp_cache() {
            let values: Vec<ExoValue> = entries
                .into_iter()
                .map(|e| {
                    let mut map = BTreeMap::new();
                    map.insert(
                        String::from("ip"),
                        ExoValue::String(format!(
                            "{}.{}.{}.{}",
                            e.ip[0], e.ip[1], e.ip[2], e.ip[3]
                        )),
                    );
                    map.insert(
                        String::from("mac"),
                        ExoValue::String(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            e.mac[0], e.mac[1], e.mac[2],
                            e.mac[3], e.mac[4], e.mac[5]
                        )),
                    );
                    map.insert(String::from("complete"), ExoValue::Bool(e.complete));
                    ExoValue::Map(map)
                })
                .collect();
            ExoValue::Array(values)
        } else {
            ExoValue::Array(Vec::new())
        }
    }

    /// ICMP エコー送信（async版 - パケット間でyield）
    pub async fn ping(ip: [u8; 4], count: u16) -> ExoValue {
        let mut results = Vec::new();
        for seq in 1..=count {
            // 各パケット送信前にyield（他タスクに機会を与える）
            crate::task::yield_now().await;
            
            match crate::net::send_icmp_echo(ip, seq) {
                Ok(rtt) => {
                    let mut map = BTreeMap::new();
                    map.insert(String::from("seq"), ExoValue::Int(seq as i64));
                    map.insert(String::from("rtt_ms"), ExoValue::Float(rtt as f64));
                    map.insert(String::from("success"), ExoValue::Bool(true));
                    results.push(ExoValue::Map(map));
                }
                Err(e) => {
                    let mut map = BTreeMap::new();
                    map.insert(String::from("seq"), ExoValue::Int(seq as i64));
                    map.insert(String::from("error"), ExoValue::String(e));
                    map.insert(String::from("success"), ExoValue::Bool(false));
                    results.push(ExoValue::Map(map));
                }
            }
            
            // パケット間に少し待機（async sleep）
            if seq < count {
                crate::task::sleep_ms(100).await;
            }
        }
        ExoValue::Array(results)
    }
}

/// プロセス/タスク名前空間
pub struct ProcNamespace;

impl ProcNamespace {
    /// 実行中のタスク一覧
    pub fn list() -> ExoValue {
        // TODO: 実際のタスクマネージャと連携
        let processes = vec![
            ProcessInfo {
                pid: 0,
                name: String::from("kernel"),
                state: ProcessState::Running,
                cpu_usage: 0.1,
                memory_kb: 4096,
                domain: String::from("kernel"),
            },
            ProcessInfo {
                pid: 1,
                name: String::from("shell"),
                state: ProcessState::Running,
                cpu_usage: 0.5,
                memory_kb: 1024,
                domain: String::from("user"),
            },
        ];
        
        ExoValue::Array(
            processes
                .into_iter()
                .map(ExoValue::Process)
                .collect()
        )
    }

    /// 特定プロセスの情報
    pub fn info(pid: u32) -> ExoValue {
        // TODO: 実際のプロセス情報を取得
        if pid == 0 {
            ExoValue::Process(ProcessInfo {
                pid: 0,
                name: String::from("kernel"),
                state: ProcessState::Running,
                cpu_usage: 0.1,
                memory_kb: 4096,
                domain: String::from("kernel"),
            })
        } else {
            ExoValue::Error(format!("Process {} not found", pid))
        }
    }
}

/// Capability 名前空間（権限管理）
pub struct CapNamespace;

impl CapNamespace {
    /// 現在のCapabilityを一覧
    pub fn list() -> ExoValue {
        // TODO: 実際のCapabilityレジストリと連携
        let caps = vec![
            Capability {
                id: 1,
                resource: String::from("/"),
                operations: vec![CapOperation::Read, CapOperation::List],
                issuer: String::from("kernel"),
                expires: None,
                delegatable: false,
            },
            Capability {
                id: 2,
                resource: String::from("/home"),
                operations: vec![
                    CapOperation::Read,
                    CapOperation::Write,
                    CapOperation::Create,
                    CapOperation::Delete,
                ],
                issuer: String::from("kernel"),
                expires: None,
                delegatable: true,
            },
        ];
        
        ExoValue::Array(caps.into_iter().map(ExoValue::Capability).collect())
    }

    /// 権限を付与
    pub fn grant(resource: &str, operations: &[CapOperation], target_domain: &str) -> ExoValue {
        // TODO: 実際の権限付与処理
        let cap = Capability {
            id: 100, // 新しいID
            resource: resource.to_string(),
            operations: operations.to_vec(),
            issuer: String::from("shell"),
            expires: None,
            delegatable: false,
        };
        
        crate::log!("[CAP] Granted {:?} on {} to {}\n", operations, resource, target_domain);
        ExoValue::Capability(cap)
    }

    /// 権限を剥奪
    pub fn revoke(cap_id: u64) -> ExoValue {
        // TODO: 実際の権限剥奪処理
        crate::log!("[CAP] Revoked capability {}\n", cap_id);
        ExoValue::Bool(true)
    }
}

/// システム名前空間
pub struct SysNamespace;

impl SysNamespace {
    /// システム情報
    pub fn info() -> ExoValue {
        let mut map = BTreeMap::new();
        map.insert(String::from("os"), ExoValue::String(String::from("RanyOS")));
        map.insert(String::from("arch"), ExoValue::String(String::from("x86_64")));
        map.insert(String::from("version"), ExoValue::String(String::from("0.3.0-alpha")));
        map.insert(String::from("kernel"), ExoValue::String(String::from("ExoRust")));
        
        let ticks = crate::task::timer::current_tick();
        map.insert(String::from("uptime_ms"), ExoValue::Int(ticks as i64));
        
        ExoValue::Map(map)
    }

    /// メモリ情報
    pub fn memory() -> ExoValue {
        let mut map = BTreeMap::new();
        // TODO: 実際のメモリ統計を取得
        map.insert(String::from("total_kb"), ExoValue::Int(131072));
        map.insert(String::from("used_kb"), ExoValue::Int(65536));
        map.insert(String::from("free_kb"), ExoValue::Int(65536));
        ExoValue::Map(map)
    }

    /// 時刻情報
    pub fn time() -> ExoValue {
        let ticks = crate::task::timer::current_tick();
        let seconds = ticks / 1000;
        let mut map = BTreeMap::new();
        map.insert(String::from("ticks"), ExoValue::Int(ticks as i64));
        map.insert(String::from("seconds"), ExoValue::Int(seconds as i64));
        map.insert(String::from("hours"), ExoValue::Int((seconds / 3600) as i64));
        map.insert(String::from("minutes"), ExoValue::Int(((seconds % 3600) / 60) as i64));
        ExoValue::Map(map)
    }

    /// システムモニター情報
    pub fn monitor() -> ExoValue {
        let snap = crate::monitor::snapshot();
        let mut map = BTreeMap::new();
        
        // 基本情報
        map.insert(String::from("timestamp"), ExoValue::Int(snap.timestamp as i64));
        map.insert(String::from("cpu_usage"), ExoValue::Int(snap.cpu_usage as i64));
        
        // メモリ情報
        let mut mem = BTreeMap::new();
        mem.insert(String::from("heap_used"), ExoValue::Int(snap.memory.heap_used as i64));
        mem.insert(String::from("heap_free"), ExoValue::Int(snap.memory.heap_free as i64));
        mem.insert(String::from("heap_total"), ExoValue::Int(snap.memory.heap_total as i64));
        mem.insert(String::from("usage_percent"), ExoValue::Int(snap.memory.usage_percent as i64));
        map.insert(String::from("memory"), ExoValue::Map(mem));
        
        // ドメイン情報
        let mut domains = BTreeMap::new();
        domains.insert(String::from("total"), ExoValue::Int(snap.domains.total as i64));
        domains.insert(String::from("running"), ExoValue::Int(snap.domains.running as i64));
        domains.insert(String::from("stopped"), ExoValue::Int(snap.domains.stopped as i64));
        map.insert(String::from("domains"), ExoValue::Map(domains));
        
        // タスク情報
        let mut tasks = BTreeMap::new();
        tasks.insert(String::from("context_switches"), ExoValue::Int(snap.tasks.context_switches as i64));
        tasks.insert(String::from("voluntary_yields"), ExoValue::Int(snap.tasks.voluntary_yields as i64));
        tasks.insert(String::from("forced_preemptions"), ExoValue::Int(snap.tasks.forced_preemptions as i64));
        map.insert(String::from("tasks"), ExoValue::Map(tasks));
        
        // ネットワーク情報
        let mut net = BTreeMap::new();
        net.insert(String::from("rx_packets"), ExoValue::Int(snap.network.rx_packets as i64));
        net.insert(String::from("tx_packets"), ExoValue::Int(snap.network.tx_packets as i64));
        net.insert(String::from("rx_bytes"), ExoValue::Int(snap.network.rx_bytes as i64));
        net.insert(String::from("tx_bytes"), ExoValue::Int(snap.network.tx_bytes as i64));
        map.insert(String::from("network"), ExoValue::Map(net));
        
        ExoValue::Map(map)
    }

    /// モニターダッシュボードを表示
    pub fn monitor_dashboard() -> ExoValue {
        let snap = crate::monitor::snapshot();
        crate::monitor::print_snapshot(&snap);
        ExoValue::String(String::from("Dashboard displayed"))
    }

    /// 温度情報
    pub fn thermal() -> ExoValue {
        let mut map = BTreeMap::new();
        
        // CPU温度を取得
        if let Some(temp) = crate::thermal::cpu_temperature() {
            map.insert(String::from("cpu_celsius"), ExoValue::Int(temp.celsius() as i64));
            map.insert(String::from("cpu_millicelsius"), ExoValue::Int(temp.millicelsius() as i64));
        } else {
            map.insert(String::from("cpu_celsius"), ExoValue::String(String::from("N/A")));
        }
        
        // サーマルマネージャから詳細情報
        let tm = crate::thermal::thermal_manager();
        let (polling_count, trip_events) = tm.stats();
        map.insert(String::from("polling_count"), ExoValue::Int(polling_count as i64));
        map.insert(String::from("trip_events"), ExoValue::Int(trip_events as i64));
        
        // スロットリング情報
        let throttle = tm.throttle_controller();
        let policy = throttle.current_policy();
        map.insert(String::from("throttle_policy"), ExoValue::String(format!("{:?}", policy)));
        map.insert(String::from("throttle_count"), ExoValue::Int(throttle.throttle_count() as i64));
        
        // センサー情報
        let sensors = tm.sensors();
        let mut sensor_list = Vec::new();
        for sensor in sensors.iter() {
            let mut s = BTreeMap::new();
            s.insert(String::from("id"), ExoValue::Int(sensor.id as i64));
            s.insert(String::from("name"), ExoValue::String(sensor.name.clone()));
            if sensor.current.is_valid() {
                s.insert(String::from("current_c"), ExoValue::Int(sensor.current.celsius() as i64));
            }
            s.insert(String::from("is_hot"), ExoValue::Bool(sensor.is_hot()));
            s.insert(String::from("is_critical"), ExoValue::Bool(sensor.is_critical()));
            sensor_list.push(ExoValue::Map(s));
        }
        map.insert(String::from("sensors"), ExoValue::Array(sensor_list));
        
        ExoValue::Map(map)
    }

    /// ウォッチドッグ情報
    pub fn watchdog() -> ExoValue {
        let mut map = BTreeMap::new();
        
        let wm = crate::watchdog::watchdog_manager();
        let sw = wm.software();
        let (heartbeats, timeouts, checks) = sw.stats();
        
        map.insert(String::from("heartbeats"), ExoValue::Int(heartbeats as i64));
        map.insert(String::from("timeouts"), ExoValue::Int(timeouts as i64));
        map.insert(String::from("checks"), ExoValue::Int(checks as i64));
        
        // デッドロック検出情報
        let dd = wm.deadlock_detector();
        map.insert(String::from("deadlocks_detected"), ExoValue::Int(dd.deadlocks_detected() as i64));
        
        ExoValue::Map(map)
    }

    /// 電源情報
    pub fn power() -> ExoValue {
        let mut map = BTreeMap::new();
        
        let pm = crate::power::power_manager();
        let state = pm.current_state();
        map.insert(String::from("state"), ExoValue::String(format!("{:?}", state)));
        
        let stats = pm.stats();
        map.insert(String::from("power_button_presses"), 
            ExoValue::Int(stats.power_button_presses.load(core::sync::atomic::Ordering::Relaxed) as i64));
        map.insert(String::from("sleep_button_presses"), 
            ExoValue::Int(stats.sleep_button_presses.load(core::sync::atomic::Ordering::Relaxed) as i64));
        
        // CPUアイドル統計
        let idle = crate::power::cpu_idle();
        let (c1, c2, c3) = idle.stats();
        let mut idle_stats = BTreeMap::new();
        idle_stats.insert(String::from("c1_count"), ExoValue::Int(c1 as i64));
        idle_stats.insert(String::from("c2_count"), ExoValue::Int(c2 as i64));
        idle_stats.insert(String::from("c3_count"), ExoValue::Int(c3 as i64));
        map.insert(String::from("cpu_idle"), ExoValue::Map(idle_stats));
        
        ExoValue::Map(map)
    }

    /// システムシャットダウン
    pub fn shutdown() -> ExoValue {
        crate::log!("[SYS] Shutdown requested via shell\n");
        // 実際のシャットダウンは危険なのでメッセージのみ
        ExoValue::String(String::from("Shutdown command received. Use Ctrl+Alt+Del or power button to actually shutdown."))
    }

    /// システムリブート
    pub fn reboot() -> ExoValue {
        crate::log!("[SYS] Reboot requested via shell\n");
        // 実際のリブートは危険なのでメッセージのみ
        ExoValue::String(String::from("Reboot command received. Use Ctrl+Alt+Del to actually reboot."))
    }
}

// ============================================================================
// Parse Error - 詳細なエラーハンドリング
// ============================================================================

/// パースエラーの種類
#[derive(Debug, Clone)]
pub enum ParseError {
    /// 文字列リテラルが閉じられていない
    UnterminatedString {
        position: usize,
        start_quote: char,
    },
    /// 予期しないトークン
    UnexpectedToken {
        expected: &'static str,
        found: String,
        position: usize,
    },
    /// 未知の名前空間
    UnknownNamespace {
        name: String,
    },
    /// 未知のメソッド
    UnknownMethod {
        namespace: String,
        method: String,
    },
    /// 引数の型が不正
    InvalidArgumentType {
        method: String,
        expected: &'static str,
        found: String,
    },
    /// 引数が不足
    MissingArgument {
        method: String,
        argument: &'static str,
    },
    /// 不正な数値
    InvalidNumber {
        value: String,
    },
    /// 不正なIPアドレス
    InvalidIpAddress {
        value: String,
    },
    /// 空の入力
    EmptyInput,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnterminatedString { position, start_quote } => {
                write!(f, "文字列が閉じられていません (位置 {}, 開始引用符: '{}')", position, start_quote)
            }
            ParseError::UnexpectedToken { expected, found, position } => {
                write!(f, "予期しないトークン: '{}' (期待: {}, 位置: {})", found, expected, position)
            }
            ParseError::UnknownNamespace { name } => {
                write!(f, "未知の名前空間: '{}'\n有効な名前空間: fs, net, proc, cap, sys", name)
            }
            ParseError::UnknownMethod { namespace, method } => {
                write!(f, "未知のメソッド: '{}.{}()'", namespace, method)
            }
            ParseError::InvalidArgumentType { method, expected, found } => {
                write!(f, "{}() の引数型が不正: 期待 {}, 実際 {}", method, expected, found)
            }
            ParseError::MissingArgument { method, argument } => {
                write!(f, "{}() に引数 '{}' がありません", method, argument)
            }
            ParseError::InvalidNumber { value } => {
                write!(f, "不正な数値: '{}'", value)
            }
            ParseError::InvalidIpAddress { value } => {
                write!(f, "不正なIPアドレス: '{}' (形式: x.x.x.x)", value)
            }
            ParseError::EmptyInput => {
                write!(f, "入力が空です")
            }
        }
    }
}

// ============================================================================
// Tokenizer - 引数内の'.'を正しく処理するパーサ
// ============================================================================

/// トークンの種類
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// 識別子（fs, entries, filter など）
    Ident(String),
    /// 文字列リテラル
    StringLit(String),
    /// 数値リテラル
    Number(i64),
    /// 浮動小数点リテラル
    Float(f64),
    /// ドット（メソッドチェーン）
    Dot,
    /// 開き括弧
    LParen,
    /// 閉じ括弧
    RParen,
    /// カンマ
    Comma,
    /// 比較演算子
    Operator(String),
}

/// 簡易トークナイザー
pub struct Tokenizer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Tokenizer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    pub fn tokenize(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        
        while self.pos < self.input.len() {
            self.skip_whitespace();
            
            if self.pos >= self.input.len() {
                break;
            }

            let c = self.peek().unwrap();

            match c {
                '.' => {
                    self.advance();
                    tokens.push(Token::Dot);
                }
                '(' => {
                    self.advance();
                    tokens.push(Token::LParen);
                }
                ')' => {
                    self.advance();
                    tokens.push(Token::RParen);
                }
                ',' => {
                    self.advance();
                    tokens.push(Token::Comma);
                }
                '"' | '\'' => {
                    tokens.push(self.read_string(c));
                }
                '>' | '<' | '=' | '!' => {
                    tokens.push(self.read_operator());
                }
                c if c.is_ascii_digit() || c == '-' => {
                    tokens.push(self.read_number());
                }
                c if c.is_alphabetic() || c == '_' || c == '$' => {
                    tokens.push(self.read_ident());
                }
                _ => {
                    // 未知の文字はスキップ
                    self.advance();
                }
            }
        }
        
        tokens
    }

    fn read_string(&mut self, quote: char) -> Token {
        self.advance(); // skip opening quote
        let start = self.pos;
        
        while let Some(c) = self.peek() {
            if c == quote {
                let s = self.input[start..self.pos].to_string();
                self.advance(); // skip closing quote
                return Token::StringLit(s);
            }
            self.advance();
        }
        
        // 閉じクォートがない場合
        Token::StringLit(self.input[start..].to_string())
    }

    fn read_number(&mut self) -> Token {
        let start = self.pos;
        let mut has_dot = false;
        
        // 負号
        if self.peek() == Some('-') {
            self.advance();
        }
        
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.advance();
            } else if c == '.' && !has_dot {
                has_dot = true;
                self.advance();
            } else {
                break;
            }
        }
        
        let s = &self.input[start..self.pos];
        if has_dot {
            Token::Float(s.parse().unwrap_or(0.0))
        } else {
            Token::Number(s.parse().unwrap_or(0))
        }
    }

    fn read_ident(&mut self) -> Token {
        let start = self.pos;
        
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '$' || c == '/' {
                self.advance();
            } else {
                break;
            }
        }
        
        Token::Ident(self.input[start..self.pos].to_string())
    }

    fn read_operator(&mut self) -> Token {
        let start = self.pos;
        
        while let Some(c) = self.peek() {
            if c == '>' || c == '<' || c == '=' || c == '!' {
                self.advance();
            } else {
                break;
            }
        }
        
        Token::Operator(self.input[start..self.pos].to_string())
    }
}

// ============================================================================
// Method Chain Parser
// ============================================================================

/// メソッド呼び出しの解析結果
#[derive(Debug, Clone)]
pub struct MethodCall {
    pub name: String,
    pub args: Vec<ExoValue>,
}

/// メソッドチェーンパーサ
pub struct ChainParser {
    tokens: Vec<Token>,
    pos: usize,
}

impl ChainParser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.pos);
        self.pos += 1;
        token
    }

    /// メソッドチェーンを解析
    /// 例: "fs.entries('/').filter('size > 1024').first()"
    /// 戻り値: Vec<MethodCall>
    pub fn parse(&mut self) -> Vec<MethodCall> {
        let mut calls = Vec::new();
        
        while self.pos < self.tokens.len() {
            // 識別子を期待
            if let Some(Token::Ident(name)) = self.peek().cloned() {
                self.advance();
                
                let args = if self.peek() == Some(&Token::LParen) {
                    self.parse_args()
                } else {
                    Vec::new()
                };
                
                calls.push(MethodCall {
                    name,
                    args,
                });
                
                // ドットがあれば次のメソッドへ
                if self.peek() == Some(&Token::Dot) {
                    self.advance();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        calls
    }

    /// 引数リストを解析
    fn parse_args(&mut self) -> Vec<ExoValue> {
        let mut args = Vec::new();
        
        // '(' をスキップ
        if self.peek() == Some(&Token::LParen) {
            self.advance();
        }
        
        loop {
            match self.peek().cloned() {
                Some(Token::RParen) => {
                    self.advance();
                    break;
                }
                Some(Token::Comma) => {
                    self.advance();
                }
                Some(Token::StringLit(s)) => {
                    self.advance();
                    args.push(ExoValue::String(s));
                }
                Some(Token::Number(n)) => {
                    self.advance();
                    args.push(ExoValue::Int(n));
                }
                Some(Token::Float(f)) => {
                    self.advance();
                    args.push(ExoValue::Float(f));
                }
                Some(Token::Ident(s)) => {
                    self.advance();
                    // 演算子が続く場合は条件式として解釈
                    if let Some(Token::Operator(op)) = self.peek().cloned() {
                        self.advance();
                        if let Some(val) = self.advance().cloned() {
                            let rhs = match val {
                                Token::Number(n) => n.to_string(),
                                Token::Float(f) => f.to_string(),
                                Token::StringLit(s) => s,
                                _ => String::new(),
                            };
                            // 条件式を文字列として格納
                            args.push(ExoValue::String(format!("{} {} {}", s, op, rhs)));
                        }
                    } else {
                        args.push(ExoValue::String(s));
                    }
                }
                None => break,
                _ => {
                    self.advance();
                }
            }
        }
        
        args
    }
}

// ============================================================================
// ExoShell REPL
// ============================================================================

/// ExoShell REPLインタプリタ
pub struct ExoShell {
    /// 変数バインディング
    bindings: BTreeMap<String, ExoValue>,
    /// カレントディレクトリ
    cwd: String,
    /// コマンド履歴
    history: Vec<String>,
    /// 最後の結果
    last_result: ExoValue,
}

impl ExoShell {
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
            cwd: String::from("/"),
            history: Vec::new(),
            last_result: ExoValue::Nil,
        }
    }

    /// 式を評価（メソッドチェーン対応）- async版
    pub async fn eval(&mut self, input: &str) -> ExoValue {
        let input = input.trim();
        
        if input.is_empty() || input.starts_with('#') {
            return ExoValue::Nil;
        }

        // 履歴に追加
        self.history.push(input.to_string());

        // 代入式: let x = ...
        if input.starts_with("let ") {
            let result = self.eval_let(&input[4..]).await;
            self.last_result = result.clone();
            return result;
        }

        // ヘルプ
        if input == "help" || input == "?" {
            return self.help();
        }

        // 変数参照
        if input.starts_with('$') {
            let var_name = &input[1..];
            return self.bindings.get(var_name).cloned().unwrap_or(ExoValue::Nil);
        }

        // メソッドチェーン対応の式評価
        let result = self.eval_chain(input).await;
        self.last_result = result.clone();
        result
    }

    /// メソッドチェーンを評価（async版）
    /// 例: fs.entries("/").filter("size > 1024").first()
    async fn eval_chain(&mut self, input: &str) -> ExoValue {
        // トークナイズ
        let mut tokenizer = Tokenizer::new(input);
        let tokens = tokenizer.tokenize();
        
        if tokens.is_empty() {
            return self.eval_alias(input).await;
        }

        // メソッドチェーンをパース
        let mut parser = ChainParser::new(tokens);
        let calls = parser.parse();
        
        if calls.is_empty() {
            return self.eval_alias(input).await;
        }

        // 最初の呼び出しで名前空間を判定
        let first = &calls[0];
        let mut current = self.eval_namespace_method(&first.name, &calls.get(1)).await;

        // 残りのメソッドチェーンを適用
        for call in calls.iter().skip(2) {
            current = self.apply_method(current, &call.name, &call.args);
            if let ExoValue::Error(_) = current {
                break;
            }
        }

        current
    }

    /// 名前空間の最初のメソッドを評価（async版）
    async fn eval_namespace_method(&mut self, namespace: &str, method: &Option<&MethodCall>) -> ExoValue {
        let method = match method {
            Some(m) => m,
            None => return ExoValue::Error(
                ParseError::UnexpectedToken {
                    expected: "メソッド呼び出し",
                    found: format!("{}の後に何もない", namespace),
                    position: 0,
                }.to_string()
            ),
        };

        match namespace {
            "fs" => self.eval_fs_method(&method.name, &method.args).await,
            "net" => self.eval_net_method(&method.name, &method.args).await,
            "proc" => self.eval_proc_method(&method.name, &method.args),
            "cap" => self.eval_cap_method(&method.name, &method.args),
            "sys" => self.eval_sys_method(&method.name, &method.args),
            "_" => self.last_result.clone(),
            name if name.starts_with('$') => {
                self.bindings.get(&name[1..]).cloned().unwrap_or(ExoValue::Nil)
            }
            _ => self.eval_alias(&format!("{}", namespace)).await,
        }
    }

    /// fs.* メソッド（構造化版）- async版
    async fn eval_fs_method(&mut self, name: &str, args: &[ExoValue]) -> ExoValue {
        match name {
            "entries" => {
                let path = args.first()
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap_or_else(|| self.cwd.clone());
                FsNamespace::entries(&path).await
            }
            "read" => {
                let path = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_default();
                FsNamespace::read(&path).await
            }
            "stat" => {
                let path = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_default();
                FsNamespace::stat(&path).await
            }
            "mkdir" => {
                let path = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_default();
                FsNamespace::mkdir(&path).await
            }
            "remove" | "rm" => {
                let path = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_default();
                FsNamespace::remove(&path).await
            }
            "cd" => {
                let path = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.clone()), _ => None })
                    .unwrap_or_else(|| String::from("/"));
                self.cwd = if path.starts_with('/') {
                    path
                } else {
                    format!("{}/{}", self.cwd, path)
                };
                ExoValue::String(self.cwd.clone())
            }
            "pwd" => ExoValue::String(self.cwd.clone()),
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("fs"),
                    method: name.to_string(),
                }.to_string() + "\n有効なメソッド: entries, read, stat, mkdir, remove, cd, pwd"
            ),
        }
    }

    /// net.* メソッド（構造化版）- async版
    async fn eval_net_method(&self, name: &str, args: &[ExoValue]) -> ExoValue {
        match name {
            "config" => NetNamespace::config(),
            "stats" => NetNamespace::stats(),
            "arp" => NetNamespace::arp_cache(),
            "ping" => {
                // ping("10.0.2.2", 4)
                let ip_str = match args.first() {
                    Some(ExoValue::String(s)) => s.clone(),
                    Some(other) => return ExoValue::Error(
                        ParseError::InvalidArgumentType {
                            method: String::from("ping"),
                            expected: "文字列 (IPアドレス)",
                            found: format!("{:?}", other),
                        }.to_string()
                    ),
                    None => return ExoValue::Error(
                        ParseError::MissingArgument {
                            method: String::from("ping"),
                            argument: "IPアドレス",
                        }.to_string() + "\n使用法: net.ping(\"10.0.2.2\", 4)"
                    ),
                };
                let count = args.get(1)
                    .and_then(|v| match v { ExoValue::Int(n) => Some(*n as u16), _ => None })
                    .unwrap_or(4);
                
                // IPアドレスをパース
                let parts: Vec<&str> = ip_str.split('.').collect();
                if parts.len() != 4 {
                    return ExoValue::Error(
                        ParseError::InvalidIpAddress { value: ip_str }.to_string()
                    );
                }
                let ip: Result<Vec<u8>, _> = parts.iter().map(|p| p.parse::<u8>()).collect();
                match ip {
                    Ok(o) if o.len() == 4 => NetNamespace::ping([o[0], o[1], o[2], o[3]], count).await,
                    _ => ExoValue::Error(
                        ParseError::InvalidIpAddress { value: ip_str }.to_string()
                    ),
                }
            }
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("net"),
                    method: name.to_string(),
                }.to_string() + "\n有効なメソッド: config, stats, arp, ping"
            ),
        }
    }

    /// proc.* メソッド（構造化版）
    fn eval_proc_method(&self, name: &str, args: &[ExoValue]) -> ExoValue {
        match name {
            "list" | "ps" => ProcNamespace::list(),
            "info" => {
                let pid = args.first()
                    .and_then(|v| match v { ExoValue::Int(n) => Some(*n as u32), _ => None })
                    .unwrap_or(0);
                ProcNamespace::info(pid)
            }
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("proc"),
                    method: name.to_string(),
                }.to_string() + "\n有効なメソッド: list, ps, info"
            ),
        }
    }

    /// cap.* メソッド（構造化版）
    fn eval_cap_method(&self, name: &str, args: &[ExoValue]) -> ExoValue {
        match name {
            "list" => CapNamespace::list(),
            "revoke" => {
                let id = args.first()
                    .and_then(|v| match v { ExoValue::Int(n) => Some(*n as u64), _ => None })
                    .unwrap_or(0);
                CapNamespace::revoke(id)
            }
            "grant" => {
                // grant("/path", ["read", "write"], "domain")
                // TODO: 完全な実装
                ExoValue::Error(String::from("grant() は未実装です"))
            }
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("cap"),
                    method: name.to_string(),
                }.to_string() + "\n有効なメソッド: list, grant, revoke"
            ),
        }
    }

    /// sys.* メソッド（構造化版）
    fn eval_sys_method(&self, name: &str, _args: &[ExoValue]) -> ExoValue {
        match name {
            "info" => SysNamespace::info(),
            "memory" | "mem" => SysNamespace::memory(),
            "time" => SysNamespace::time(),
            // システム監視
            "monitor" => SysNamespace::monitor(),
            "dashboard" => SysNamespace::monitor_dashboard(),
            // 温度監視
            "thermal" | "temp" => SysNamespace::thermal(),
            // ウォッチドッグ
            "watchdog" | "wd" => SysNamespace::watchdog(),
            // 電源管理
            "power" => SysNamespace::power(),
            "shutdown" => SysNamespace::shutdown(),
            "reboot" => SysNamespace::reboot(),
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("sys"),
                    method: name.to_string(),
                }.to_string() + "\n有効なメソッド: info, memory, time, monitor, dashboard, thermal, watchdog, power, shutdown, reboot"
            ),
        }
    }

    /// 値に対してメソッドを適用（メソッドチェーン）
    fn apply_method(&self, target: ExoValue, method: &str, args: &[ExoValue]) -> ExoValue {
        match target {
            ExoValue::Array(list) => self.apply_array_method(list, method, args),
            ExoValue::Map(map) => self.apply_map_method(map, method, args),
            ExoValue::Bytes(bytes) => self.apply_bytes_method(bytes, method, args),
            ExoValue::String(s) => self.apply_string_method(s, method, args),
            _ => ExoValue::Error(format!("Type does not support method '{}'", method)),
        }
    }

    /// 配列に対するメソッド
    fn apply_array_method(&self, list: Vec<ExoValue>, method: &str, args: &[ExoValue]) -> ExoValue {
        match method {
            // 基本メソッド
            "len" | "count" => ExoValue::Int(list.len() as i64),
            "first" => list.first().cloned().unwrap_or(ExoValue::Nil),
            "last" => list.last().cloned().unwrap_or(ExoValue::Nil),
            "reverse" => ExoValue::Array(list.into_iter().rev().collect()),
            
            // take(n) - 先頭n件を取得
            "take" | "head" => {
                let n = args.first()
                    .and_then(|v| match v { ExoValue::Int(n) => Some(*n as usize), _ => None })
                    .unwrap_or(10);
                ExoValue::Array(list.into_iter().take(n).collect())
            }
            
            // skip(n) - 先頭n件をスキップ
            "skip" | "tail" => {
                let n = args.first()
                    .and_then(|v| match v { ExoValue::Int(n) => Some(*n as usize), _ => None })
                    .unwrap_or(0);
                ExoValue::Array(list.into_iter().skip(n).collect())
            }
            
            // filter(条件) - フィルタリング
            "filter" | "where" => {
                let condition = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.as_str()), _ => None })
                    .unwrap_or("");
                self.filter_array(list, condition)
            }
            
            // sort() - ソート
            "sort" => {
                // 名前でソート（FileEntry対応）
                let mut sorted = list;
                sorted.sort_by(|a, b| {
                    let name_a = match a {
                        ExoValue::FileEntry(e) => &e.name,
                        ExoValue::String(s) => s,
                        _ => "",
                    };
                    let name_b = match b {
                        ExoValue::FileEntry(e) => &e.name,
                        ExoValue::String(s) => s,
                        _ => "",
                    };
                    name_a.cmp(name_b)
                });
                ExoValue::Array(sorted)
            }
            
            // map(field) - フィールド抽出
            "map" | "select" => {
                let field = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.as_str()), _ => None })
                    .unwrap_or("name");
                self.map_array(list, field)
            }
            
            _ => ExoValue::Error(format!("Array does not have method '{}'", method)),
        }
    }

    /// 配列をフィルタリング
    fn filter_array(&self, list: Vec<ExoValue>, condition: &str) -> ExoValue {
        // 条件式をパース: "size > 1024", "name contains test", "type == Directory"
        let parts: Vec<&str> = condition.split_whitespace().collect();
        
        if parts.len() < 3 {
            // 条件が不完全な場合は全て返す
            return ExoValue::Array(list);
        }
        
        let field = parts[0];
        let op = parts[1];
        let value = parts[2..].join(" ");
        
        let filtered: Vec<ExoValue> = list.into_iter().filter(|item| {
            match item {
                ExoValue::FileEntry(entry) => {
                    self.check_file_entry_condition(entry, field, op, &value)
                }
                ExoValue::Process(proc) => {
                    self.check_process_condition(proc, field, op, &value)
                }
                ExoValue::Map(map) => {
                    self.check_map_condition(map, field, op, &value)
                }
                _ => true,
            }
        }).collect();
        
        ExoValue::Array(filtered)
    }

    /// FileEntryの条件チェック
    fn check_file_entry_condition(&self, entry: &FileEntry, field: &str, op: &str, value: &str) -> bool {
        match field {
            "size" => {
                let entry_val = entry.size as i64;
                let cmp_val = value.parse::<i64>().unwrap_or(0);
                self.compare_numbers(entry_val, op, cmp_val)
            }
            "name" => {
                self.compare_strings(&entry.name, op, value)
            }
            "type" => {
                let type_str = format!("{:?}", entry.file_type);
                self.compare_strings(&type_str, op, value)
            }
            "owner" => {
                self.compare_strings(&entry.owner, op, value)
            }
            _ => true,
        }
    }

    /// ProcessInfoの条件チェック
    fn check_process_condition(&self, proc: &ProcessInfo, field: &str, op: &str, value: &str) -> bool {
        match field {
            "pid" => {
                let cmp_val = value.parse::<u32>().unwrap_or(0);
                self.compare_numbers(proc.pid as i64, op, cmp_val as i64)
            }
            "name" => {
                self.compare_strings(&proc.name, op, value)
            }
            "cpu" => {
                let cmp_val = value.parse::<f32>().unwrap_or(0.0);
                match op {
                    ">" => proc.cpu_usage > cmp_val,
                    ">=" => proc.cpu_usage >= cmp_val,
                    "<" => proc.cpu_usage < cmp_val,
                    "<=" => proc.cpu_usage <= cmp_val,
                    "==" | "=" => (proc.cpu_usage - cmp_val).abs() < 0.01,
                    _ => true,
                }
            }
            "memory" => {
                let cmp_val = value.parse::<u64>().unwrap_or(0);
                self.compare_numbers(proc.memory_kb as i64, op, cmp_val as i64)
            }
            _ => true,
        }
    }

    /// Mapの条件チェック
    fn check_map_condition(&self, map: &BTreeMap<String, ExoValue>, field: &str, op: &str, value: &str) -> bool {
        if let Some(field_val) = map.get(field) {
            match field_val {
                ExoValue::Int(n) => {
                    let cmp_val = value.parse::<i64>().unwrap_or(0);
                    self.compare_numbers(*n, op, cmp_val)
                }
                ExoValue::String(s) => {
                    self.compare_strings(s, op, value)
                }
                _ => true,
            }
        } else {
            true
        }
    }

    /// 数値比較
    fn compare_numbers(&self, a: i64, op: &str, b: i64) -> bool {
        match op {
            ">" => a > b,
            ">=" => a >= b,
            "<" => a < b,
            "<=" => a <= b,
            "==" | "=" => a == b,
            "!=" => a != b,
            _ => true,
        }
    }

    /// 文字列比較
    fn compare_strings(&self, a: &str, op: &str, b: &str) -> bool {
        match op {
            "==" | "=" => a == b,
            "!=" => a != b,
            "contains" => a.contains(b),
            "starts_with" | "startswith" => a.starts_with(b),
            "ends_with" | "endswith" => a.ends_with(b),
            _ => true,
        }
    }

    /// 配列のフィールドを抽出
    fn map_array(&self, list: Vec<ExoValue>, field: &str) -> ExoValue {
        let mapped: Vec<ExoValue> = list.into_iter().map(|item| {
            match item {
                ExoValue::FileEntry(entry) => {
                    match field {
                        "name" => ExoValue::String(entry.name),
                        "size" => ExoValue::Int(entry.size as i64),
                        "path" => ExoValue::String(entry.path),
                        "type" => ExoValue::String(format!("{:?}", entry.file_type)),
                        "owner" => ExoValue::String(entry.owner),
                        _ => ExoValue::Nil,
                    }
                }
                ExoValue::Process(proc) => {
                    match field {
                        "name" => ExoValue::String(proc.name),
                        "pid" => ExoValue::Int(proc.pid as i64),
                        "cpu" => ExoValue::Float(proc.cpu_usage as f64),
                        "memory" => ExoValue::Int(proc.memory_kb as i64),
                        _ => ExoValue::Nil,
                    }
                }
                ExoValue::Map(map) => {
                    map.get(field).cloned().unwrap_or(ExoValue::Nil)
                }
                _ => item,
            }
        }).collect();
        
        ExoValue::Array(mapped)
    }

    /// マップに対するメソッド
    fn apply_map_method(&self, map: BTreeMap<String, ExoValue>, method: &str, _args: &[ExoValue]) -> ExoValue {
        match method {
            "keys" => ExoValue::Array(map.keys().map(|k| ExoValue::String(k.clone())).collect()),
            "values" => ExoValue::Array(map.values().cloned().collect()),
            "len" => ExoValue::Int(map.len() as i64),
            _ => ExoValue::Error(format!("Map does not have method '{}'", method)),
        }
    }

    /// バイト列に対するメソッド
    fn apply_bytes_method(&self, bytes: Vec<u8>, method: &str, _args: &[ExoValue]) -> ExoValue {
        match method {
            "len" => ExoValue::Int(bytes.len() as i64),
            "to_string" | "text" => {
                match core::str::from_utf8(&bytes) {
                    Ok(s) => ExoValue::String(s.to_string()),
                    Err(_) => ExoValue::Error(String::from("Invalid UTF-8")),
                }
            }
            "hex" => {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                ExoValue::String(hex)
            }
            _ => ExoValue::Error(format!("Bytes does not have method '{}'", method)),
        }
    }

    /// 文字列に対するメソッド
    fn apply_string_method(&self, s: String, method: &str, args: &[ExoValue]) -> ExoValue {
        match method {
            "len" => ExoValue::Int(s.len() as i64),
            "upper" => ExoValue::String(s.to_uppercase()),
            "lower" => ExoValue::String(s.to_lowercase()),
            "trim" => ExoValue::String(s.trim().to_string()),
            "split" => {
                let sep = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.as_str()), _ => None })
                    .unwrap_or(" ");
                ExoValue::Array(s.split(sep).map(|p| ExoValue::String(p.to_string())).collect())
            }
            "contains" => {
                let needle = args.first()
                    .and_then(|v| match v { ExoValue::String(s) => Some(s.as_str()), _ => None })
                    .unwrap_or("");
                ExoValue::Bool(s.contains(needle))
            }
            _ => ExoValue::Error(format!("String does not have method '{}'", method)),
        }
    }

    /// let 式を評価（async版）
    async fn eval_let(&mut self, expr: &str) -> ExoValue {
        if let Some(eq_pos) = expr.find('=') {
            let name = expr[..eq_pos].trim().to_string();
            let value_expr = expr[eq_pos + 1..].trim();
            let value = self.eval_chain(value_expr).await;
            self.bindings.insert(name.clone(), value.clone());
            value
        } else {
            ExoValue::Error(String::from("Invalid let expression"))
        }
    }

    /// 互換性エイリアス（利便性のため）- async版
    async fn eval_alias(&mut self, cmd: &str) -> ExoValue {
        // 簡易エイリアス
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return ExoValue::Nil;
        }

        match parts[0] {
            "ls" => {
                let path = parts.get(1).unwrap_or(&".");
                let p = if *path == "." { self.cwd.clone() } else { path.to_string() };
                FsNamespace::entries(&p).await
            }
            "cd" => {
                if let Some(path) = parts.get(1) {
                    self.cwd = if path.starts_with('/') {
                        path.to_string()
                    } else if *path == ".." {
                        let mut segs: Vec<&str> = self.cwd.split('/').filter(|s| !s.is_empty()).collect();
                        segs.pop();
                        if segs.is_empty() {
                            String::from("/")
                        } else {
                            format!("/{}", segs.join("/"))
                        }
                    } else {
                        if self.cwd == "/" {
                            format!("/{}", path)
                        } else {
                            format!("{}/{}", self.cwd, path)
                        }
                    };
                }
                ExoValue::String(self.cwd.clone())
            }
            "pwd" => ExoValue::String(self.cwd.clone()),
            "cat" => {
                if let Some(path) = parts.get(1) {
                    FsNamespace::read(path).await
                } else {
                    ExoValue::Error(String::from("Usage: cat <file>"))
                }
            }
            "mkdir" => {
                if let Some(path) = parts.get(1) {
                    FsNamespace::mkdir(path).await
                } else {
                    ExoValue::Error(String::from("Usage: mkdir <dir>"))
                }
            }
            "rm" => {
                if let Some(path) = parts.get(1) {
                    FsNamespace::remove(path).await
                } else {
                    ExoValue::Error(String::from("Usage: rm <path>"))
                }
            }
            "ps" => ProcNamespace::list(),
            "ifconfig" => NetNamespace::config(),
            "arp" => NetNamespace::arp_cache(),
            "ping" => {
                if let Some(host) = parts.get(1) {
                    let ip_parts: Vec<&str> = host.split('.').collect();
                    if ip_parts.len() == 4 {
                        let ip: Result<Vec<u8>, _> = ip_parts.iter().map(|p| p.parse::<u8>()).collect();
                        if let Ok(octets) = ip {
                            if octets.len() == 4 {
                                return NetNamespace::ping(
                                    [octets[0], octets[1], octets[2], octets[3]],
                                    4,
                                ).await;
                            }
                        }
                    }
                    ExoValue::Error(format!("Invalid IP: {}", host))
                } else {
                    ExoValue::Error(String::from("Usage: ping <ip>"))
                }
            }
            "uname" => SysNamespace::info(),
            "free" => SysNamespace::memory(),
            "uptime" => SysNamespace::time(),
            _ => ExoValue::Error(format!(
                "Unknown: '{}'\nTry 'help' or use ExoShell syntax: fs.entries(), net.config(), etc.",
                cmd
            )),
        }
    }

    /// 文字列引数を抽出
    fn extract_string_arg(&self, arg: &str) -> String {
        let arg = arg.trim();
        if (arg.starts_with('"') && arg.ends_with('"'))
            || (arg.starts_with('\'') && arg.ends_with('\''))
        {
            arg[1..arg.len() - 1].to_string()
        } else {
            arg.to_string()
        }
    }

    /// ヘルプ表示
    fn help(&self) -> ExoValue {
        let help_text = r#"
╔══════════════════════════════════════════════════════════════════════════════╗
║                      ExoShell - Rust式REPL環境                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ ExoRustの設計思想に基づき、Unixコマンドではなく型付きオブジェクトを操作します ║
╚══════════════════════════════════════════════════════════════════════════════╝

【名前空間とメソッド】

  fs.*  - ファイルシステム
    fs.entries("/path")   - ディレクトリ内容を取得
    fs.read("/path")      - ファイル内容を読み取り
    fs.stat("/path")      - ファイル情報を取得
    fs.mkdir("/path")     - ディレクトリ作成
    fs.remove("/path")    - ファイル/ディレクトリ削除
    fs.cd("/path")        - カレントディレクトリ変更
    fs.pwd()              - カレントディレクトリ表示

  net.* - ネットワーク
    net.config()          - ネットワーク設定を表示
    net.stats()           - 送受信統計
    net.arp()             - ARPキャッシュ
    net.ping("ip", count) - ICMPエコー送信

  proc.* - プロセス/タスク
    proc.list()           - タスク一覧
    proc.info(pid)        - プロセス詳細

  cap.* - Capability（権限管理）
    cap.list()            - 現在のCapability一覧
    cap.grant(...)        - 権限を付与
    cap.revoke(id)        - 権限を剥奪

  sys.* - システム
    sys.info()            - システム情報
    sys.memory()          - メモリ使用量
    sys.time()            - 時刻情報
    sys.monitor()         - システム監視情報（CPU/メモリ/ネットワーク等）
    sys.dashboard()       - 監視ダッシュボード表示
    sys.thermal()         - 温度情報/スロットリング状態
    sys.watchdog()        - ウォッチドッグ状態
    sys.power()           - 電源状態/CPUアイドル統計
    sys.shutdown()        - シャットダウン要求
    sys.reboot()          - リブート要求

【変数】
  let x = fs.entries("/")   - 結果を変数に格納
  $x                        - 変数を参照
  _                         - 最後の結果

【エイリアス（互換性）】
  ls, cd, pwd, cat, mkdir, rm, ps, ifconfig, ping なども使用可能
  ただし推奨は上記の名前空間式構文です
"#;
        ExoValue::String(help_text.to_string())
    }

    /// カレントディレクトリを取得
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// プロンプト文字列を生成
    pub fn prompt(&self) -> String {
        format!("exo:{}> ", self.cwd)
    }

    /// Tab補完候補を取得
    pub fn complete(&self, input: &str) -> Vec<String> {
        let input = input.trim();
        
        // 空の入力は補完しない
        if input.is_empty() {
            return Vec::new();
        }

        // ファイルパス補完をチェック（クォート内）
        if let Some(completions) = self.complete_filepath(input) {
            return completions;
        }

        // 名前空間の補完
        let namespaces = ["fs", "net", "proc", "cap", "sys"];
        
        // "fs" や "ne" のような名前空間プレフィックスの補完
        if !input.contains('.') {
            return namespaces.iter()
                .filter(|ns| ns.starts_with(input))
                .map(|ns| format!("{}.", ns))
                .collect();
        }

        // "fs." のような名前空間後のメソッド補完
        let parts: Vec<&str> = input.splitn(2, '.').collect();
        if parts.len() < 2 {
            return Vec::new();
        }

        let namespace = parts[0];
        let method_prefix = parts[1];

        let methods: &[&str] = match namespace {
            "fs" => &["entries", "read", "stat", "mkdir", "remove", "cd", "pwd", "write"],
            "net" => &["config", "stats", "arp", "ping"],
            "proc" => &["list", "info"],
            "cap" => &["list", "grant", "revoke"],
            "sys" => &["info", "memory", "time", "monitor", "dashboard", "thermal", "watchdog", "power", "shutdown", "reboot"],
            _ => return Vec::new(),
        };

        // 既存のメソッドとマッチする場合
        // fs.ent -> fs.entries(
        methods.iter()
            .filter(|m| m.starts_with(method_prefix))
            .map(|m| format!("{}.{}(", namespace, m))
            .collect()
    }

    /// ファイルパス補完
    /// 入力が fs.read("/pa のような形式の場合、ファイルシステムを参照して補完
    fn complete_filepath(&self, input: &str) -> Option<Vec<String>> {
        // クォート開始位置を探す
        let quote_pos = input.rfind(|c| c == '"' || c == '\'')?;
        let quote_char = input.chars().nth(quote_pos)?;
        
        // クォートが閉じられていたら補完しない
        let after_quote = &input[quote_pos + 1..];
        if after_quote.contains(quote_char) {
            return None;
        }

        // パスのプレフィックス
        let path_prefix = after_quote;
        let prefix_before_quote = &input[..quote_pos + 1];

        // パスを分解
        let (dir_path, name_prefix) = if path_prefix.contains('/') {
            let last_slash = path_prefix.rfind('/').unwrap();
            if last_slash == 0 {
                ("/", &path_prefix[1..])
            } else {
                (&path_prefix[..last_slash], &path_prefix[last_slash + 1..])
            }
        } else {
            // 相対パス: カレントディレクトリから
            (self.cwd.as_str(), path_prefix)
        };

        // ディレクトリ内のエントリを取得
        let entries = match crate::fs::list_directory(dir_path, "/") {
            Ok(e) => e,
            Err(_) => return Some(Vec::new()),
        };

        // プレフィックスにマッチするエントリをフィルタ
        let completions: Vec<String> = entries
            .iter()
            .filter(|e| e.name.starts_with(name_prefix))
            .map(|e| {
                let full_path = if dir_path == "/" {
                    format!("/{}", e.name)
                } else {
                    format!("{}/{}", dir_path, e.name)
                };
                
                // ディレクトリなら末尾に / を付ける
                let suffix = if e.file_type == crate::fs::FileType::Directory {
                    "/"
                } else {
                    ""
                };
                
                format!("{}{}{}", prefix_before_quote, full_path, suffix)
            })
            .collect();

        Some(completions)
    }

    /// 履歴を取得（読み取り専用）
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// 履歴の長さを取得
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// 履歴のエントリを取得
    pub fn history_get(&self, index: usize) -> Option<&String> {
        self.history.get(index)
    }
}

// ============================================================================
// Global ExoShell instance
// ============================================================================

use spin::Mutex;

static EXOSHELL: Mutex<Option<ExoShell>> = Mutex::new(None);

/// ExoShellを初期化
pub fn init() {
    *EXOSHELL.lock() = Some(ExoShell::new());
    crate::log!("[EXOSHELL] ExoShell REPL initialized\n");
}

/// ExoShellにアクセス（同期操作のみ）
pub fn with_exoshell<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut ExoShell) -> R,
{
    let mut guard = EXOSHELL.lock();
    guard.as_mut().map(f)
}

// Note: グローバル eval 関数は削除されました。
// async fn eval() は Mutex と await が混在するため使用できません。
// 代わりに ExoShell インスタンスを直接使用してください：
//   let mut shell = ExoShell::new();
//   let result = shell.eval("fs.entries('/')").await;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exovalue_display() {
        let val = ExoValue::Int(42);
        assert_eq!(format!("{}", val), "42");
        
        let val = ExoValue::String(String::from("hello"));
        assert_eq!(format!("{}", val), "hello");
    }

    // Note: eval テストは async に対応していないため削除
    // async fn のテストは executor が必要
}
