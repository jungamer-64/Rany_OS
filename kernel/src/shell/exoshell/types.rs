// ============================================================================
// src/shell/exoshell/types.rs - ExoShell Core Types
// ============================================================================
//!
//! 型付きオブジェクトシステムの中核となる型定義
//!

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// ExoShellの値型
/// テキストではなく、構造化されたデータを表現（ゼロコピー対応）
#[derive(Debug, Clone, PartialEq)]
pub enum ExoValue<'a> {
    /// 空値
    Nil,
    /// 真偽値
    Bool(bool),
    /// 整数
    Int(i64),
    /// 浮動小数点
    Float(f64),
    /// 文字列（ゼロコピー）
    String(Cow<'a, str>),
    /// バイト列（ゼロコピー）
    Bytes(Cow<'a, [u8]>),
    /// 配列（オブジェクトのリスト）
    Array(Vec<ExoValue<'a>>),
    /// マップ（キーバリュー）
    Map(BTreeMap<String, ExoValue<'a>>),
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

impl<'a> ExoValue<'a> {
    /// 所有権を持つ静的な値に変換（ディープコピー）
    pub fn into_owned(self) -> ExoValue<'static> {
        match self {
            ExoValue::Nil => ExoValue::Nil,
            ExoValue::Bool(b) => ExoValue::Bool(b),
            ExoValue::Int(n) => ExoValue::Int(n),
            ExoValue::Float(f) => ExoValue::Float(f),
            ExoValue::String(s) => ExoValue::String(Cow::Owned(s.into_owned())),
            ExoValue::Bytes(b) => ExoValue::Bytes(Cow::Owned(b.into_owned())),
            ExoValue::Array(arr) => {
                ExoValue::Array(arr.into_iter().map(|v| v.into_owned()).collect())
            }
            ExoValue::Map(map) => {
                let mut new_map = BTreeMap::new();
                for (k, v) in map {
                    new_map.insert(k, v.into_owned());
                }
                ExoValue::Map(new_map)
            }
            ExoValue::FileEntry(e) => ExoValue::FileEntry(e),
            ExoValue::NetConnection(c) => ExoValue::NetConnection(c),
            ExoValue::Process(p) => ExoValue::Process(p),
            ExoValue::Capability(c) => ExoValue::Capability(c),
            ExoValue::Iterator(i) => ExoValue::Iterator(i),
            ExoValue::Error(e) => ExoValue::Error(e),
        }
    }
}

/// ファイルシステムエントリ（構造化データ）
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
pub struct ExoIterator {
    pub source: String,
    pub filters: Vec<String>,
    pub transforms: Vec<String>,
    pub limit: Option<usize>,
}
