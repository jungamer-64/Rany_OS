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
// Namespace Objects - オブジェクト指向API
// ============================================================================

/// ファイルシステム名前空間
pub struct FsNamespace;

impl FsNamespace {
    /// ディレクトリのエントリを取得（イテレータとして）
    pub fn entries(path: &str) -> ExoValue {
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
    pub fn read(path: &str) -> ExoValue {
        match crate::fs::read_file_content(path, "/") {
            Ok(content) => ExoValue::Bytes(content),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ファイルに書き込み
    pub fn write(path: &str, data: &[u8]) -> ExoValue {
        match crate::fs::write_file_content(path, "/", data) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ファイル/ディレクトリの詳細情報
    pub fn stat(path: &str) -> ExoValue {
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
    pub fn mkdir(path: &str) -> ExoValue {
        match crate::fs::make_directory(path, "/") {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// 削除
    pub fn remove(path: &str) -> ExoValue {
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

    /// ICMP エコー送信
    pub fn ping(ip: [u8; 4], count: u16) -> ExoValue {
        let mut results = Vec::new();
        for seq in 1..=count {
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

    /// 式を評価
    pub fn eval(&mut self, input: &str) -> ExoValue {
        let input = input.trim();
        
        if input.is_empty() || input.starts_with('#') {
            return ExoValue::Nil;
        }

        // 履歴に追加
        self.history.push(input.to_string());

        // 代入式: let x = ...
        if input.starts_with("let ") {
            return self.eval_let(&input[4..]);
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

        // 名前空間コマンドの解析
        self.eval_expression(input)
    }

    /// let 式を評価
    fn eval_let(&mut self, expr: &str) -> ExoValue {
        if let Some(eq_pos) = expr.find('=') {
            let name = expr[..eq_pos].trim().to_string();
            let value_expr = expr[eq_pos + 1..].trim();
            let value = self.eval_expression(value_expr);
            self.bindings.insert(name.clone(), value.clone());
            value
        } else {
            ExoValue::Error(String::from("Invalid let expression"))
        }
    }

    /// 式を評価（名前空間メソッド呼び出し）
    fn eval_expression(&mut self, expr: &str) -> ExoValue {
        // fs.entries("/path")
        // net.config()
        // proc.list()
        // cap.grant("/resource", ["read", "write"], "domain")
        // sys.info()

        let expr = expr.trim();

        // fs.* メソッド
        if expr.starts_with("fs.") {
            return self.eval_fs(&expr[3..]);
        }

        // net.* メソッド
        if expr.starts_with("net.") {
            return self.eval_net(&expr[4..]);
        }

        // proc.* メソッド
        if expr.starts_with("proc.") {
            return self.eval_proc(&expr[5..]);
        }

        // cap.* メソッド
        if expr.starts_with("cap.") {
            return self.eval_cap(&expr[4..]);
        }

        // sys.* メソッド
        if expr.starts_with("sys.") {
            return self.eval_sys(&expr[4..]);
        }

        // _ で最後の結果を参照
        if expr == "_" {
            return self.last_result.clone();
        }

        // 数値リテラル
        if let Ok(n) = expr.parse::<i64>() {
            return ExoValue::Int(n);
        }
        if let Ok(f) = expr.parse::<f64>() {
            return ExoValue::Float(f);
        }

        // 文字列リテラル
        if (expr.starts_with('"') && expr.ends_with('"'))
            || (expr.starts_with('\'') && expr.ends_with('\''))
        {
            return ExoValue::String(expr[1..expr.len() - 1].to_string());
        }

        // 互換性のためのエイリアス（非推奨だが利便性のため）
        self.eval_alias(expr)
    }

    /// fs.* メソッド
    fn eval_fs(&mut self, method: &str) -> ExoValue {
        // entries("path") または entries() でカレントディレクトリ
        if method.starts_with("entries(") && method.ends_with(')') {
            let arg = &method[8..method.len() - 1];
            let path = if arg.is_empty() {
                self.cwd.clone()
            } else {
                self.extract_string_arg(arg)
            };
            return FsNamespace::entries(&path);
        }

        // read("path")
        if method.starts_with("read(") && method.ends_with(')') {
            let path = self.extract_string_arg(&method[5..method.len() - 1]);
            return FsNamespace::read(&path);
        }

        // stat("path")
        if method.starts_with("stat(") && method.ends_with(')') {
            let path = self.extract_string_arg(&method[5..method.len() - 1]);
            return FsNamespace::stat(&path);
        }

        // mkdir("path")
        if method.starts_with("mkdir(") && method.ends_with(')') {
            let path = self.extract_string_arg(&method[6..method.len() - 1]);
            return FsNamespace::mkdir(&path);
        }

        // remove("path")
        if method.starts_with("remove(") && method.ends_with(')') {
            let path = self.extract_string_arg(&method[7..method.len() - 1]);
            return FsNamespace::remove(&path);
        }

        // cd("path") - カレントディレクトリ変更
        if method.starts_with("cd(") && method.ends_with(')') {
            let path = self.extract_string_arg(&method[3..method.len() - 1]);
            self.cwd = if path.starts_with('/') {
                path
            } else {
                format!("{}/{}", self.cwd, path)
            };
            return ExoValue::String(self.cwd.clone());
        }

        // pwd() - カレントディレクトリ表示
        if method == "pwd()" {
            return ExoValue::String(self.cwd.clone());
        }

        ExoValue::Error(format!("Unknown fs method: {}", method))
    }

    /// net.* メソッド
    fn eval_net(&self, method: &str) -> ExoValue {
        match method {
            "config()" => NetNamespace::config(),
            "stats()" => NetNamespace::stats(),
            "arp()" => NetNamespace::arp_cache(),
            _ if method.starts_with("ping(") && method.ends_with(')') => {
                // ping("10.0.2.2", 4) または ping("10.0.2.2")
                let args = &method[5..method.len() - 1];
                let parts: Vec<&str> = args.split(',').collect();
                
                if parts.is_empty() {
                    return ExoValue::Error(String::from("ping requires IP address"));
                }
                
                let ip_str = self.extract_string_arg(parts[0].trim());
                let count = if parts.len() > 1 {
                    parts[1].trim().parse::<u16>().unwrap_or(4)
                } else {
                    4
                };
                
                // IPアドレスをパース
                let ip_parts: Vec<&str> = ip_str.split('.').collect();
                if ip_parts.len() != 4 {
                    return ExoValue::Error(format!("Invalid IP: {}", ip_str));
                }
                let ip: Result<Vec<u8>, _> = ip_parts.iter().map(|p| p.parse::<u8>()).collect();
                match ip {
                    Ok(octets) if octets.len() == 4 => {
                        NetNamespace::ping([octets[0], octets[1], octets[2], octets[3]], count)
                    }
                    _ => ExoValue::Error(format!("Invalid IP: {}", ip_str)),
                }
            }
            _ => ExoValue::Error(format!("Unknown net method: {}", method)),
        }
    }

    /// proc.* メソッド
    fn eval_proc(&self, method: &str) -> ExoValue {
        if method == "list()" || method == "ps()" {
            return ProcNamespace::list();
        }
        
        if method.starts_with("info(") && method.ends_with(')') {
            let pid_str = &method[5..method.len() - 1];
            if let Ok(pid) = pid_str.parse::<u32>() {
                return ProcNamespace::info(pid);
            }
        }
        
        ExoValue::Error(format!("Unknown proc method: {}", method))
    }

    /// cap.* メソッド
    fn eval_cap(&self, method: &str) -> ExoValue {
        if method == "list()" {
            return CapNamespace::list();
        }
        
        // grant("resource", ["read", "write"], "domain")
        if method.starts_with("grant(") && method.ends_with(')') {
            // TODO: 引数のパースを実装
            return ExoValue::Error(String::from("grant() parsing not yet implemented"));
        }
        
        // revoke(cap_id)
        if method.starts_with("revoke(") && method.ends_with(')') {
            let id_str = &method[7..method.len() - 1];
            if let Ok(id) = id_str.parse::<u64>() {
                return CapNamespace::revoke(id);
            }
        }
        
        ExoValue::Error(format!("Unknown cap method: {}", method))
    }

    /// sys.* メソッド
    fn eval_sys(&self, method: &str) -> ExoValue {
        match method {
            "info()" => SysNamespace::info(),
            "memory()" | "mem()" => SysNamespace::memory(),
            "time()" => SysNamespace::time(),
            _ => ExoValue::Error(format!("Unknown sys method: {}", method)),
        }
    }

    /// 互換性エイリアス（利便性のため）
    fn eval_alias(&mut self, cmd: &str) -> ExoValue {
        // 簡易エイリアス
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return ExoValue::Nil;
        }

        match parts[0] {
            "ls" => {
                let path = parts.get(1).unwrap_or(&".");
                FsNamespace::entries(if *path == "." { &self.cwd } else { path })
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
                    FsNamespace::read(path)
                } else {
                    ExoValue::Error(String::from("Usage: cat <file>"))
                }
            }
            "mkdir" => {
                if let Some(path) = parts.get(1) {
                    FsNamespace::mkdir(path)
                } else {
                    ExoValue::Error(String::from("Usage: mkdir <dir>"))
                }
            }
            "rm" => {
                if let Some(path) = parts.get(1) {
                    FsNamespace::remove(path)
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
                                );
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

/// ExoShellにアクセス
pub fn with_exoshell<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut ExoShell) -> R,
{
    let mut guard = EXOSHELL.lock();
    guard.as_mut().map(f)
}

/// 式を評価（便利関数）
pub fn eval(input: &str) -> ExoValue {
    with_exoshell(|shell| shell.eval(input)).unwrap_or(ExoValue::Error(String::from("ExoShell not initialized")))
}

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

    #[test]
    fn test_exoshell_eval() {
        let mut shell = ExoShell::new();
        
        // 数値リテラル
        match shell.eval("42") {
            ExoValue::Int(n) => assert_eq!(n, 42),
            _ => panic!("Expected Int"),
        }
        
        // 文字列リテラル
        match shell.eval("\"hello\"") {
            ExoValue::String(s) => assert_eq!(s, "hello"),
            _ => panic!("Expected String"),
        }
    }
}
