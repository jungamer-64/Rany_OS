// ============================================================================
// kernel_api/src/error.rs - Common Error Types
// ============================================================================
//!
//! Error types shared across all kernel components.
//!
//! These are pure types with no kernel dependencies.

use core::fmt;

/// KAPI結果型
pub type KapiResult<T> = Result<T, KapiError>;

/// KAPIエラー - すべてのコンポーネントで使用される共通エラー型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KapiError {
    /// 権限不足
    PermissionDenied,
    /// リソース枯渇
    ResourceExhausted,
    /// 無効なハンドル
    InvalidHandle,
    /// タイムアウト
    Timeout,
    /// リソースが見つからない
    NotFound,
    /// 既に存在する
    AlreadyExists,
    /// I/Oエラー
    IoError,
    /// 接続エラー
    ConnectionError,
    /// メモリ不足
    OutOfMemory,
    /// サポートされていない操作
    NotSupported,
    /// 内部エラー
    Internal(i32),
}

impl fmt::Display for KapiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::ResourceExhausted => write!(f, "Resource exhausted"),
            Self::InvalidHandle => write!(f, "Invalid handle"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::NotFound => write!(f, "Resource not found"),
            Self::AlreadyExists => write!(f, "Resource already exists"),
            Self::IoError => write!(f, "I/O error"),
            Self::ConnectionError => write!(f, "Connection error"),
            Self::OutOfMemory => write!(f, "Out of memory"),
            Self::NotSupported => write!(f, "Operation not supported"),
            Self::Internal(code) => write!(f, "Internal error: {code}"),
        }
    }
}

/// メモリ関連エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    /// メモリ不足
    OutOfMemory,
    /// 無効なアドレス
    InvalidAddress,
    /// アライメント不正
    InvalidAlignment,
    /// サイズ不正
    InvalidSize,
    /// マッピング失敗
    MappingFailed,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::InvalidAddress => write!(f, "invalid address"),
            Self::InvalidAlignment => write!(f, "invalid alignment"),
            Self::InvalidSize => write!(f, "invalid size"),
            Self::MappingFailed => write!(f, "mapping failed"),
        }
    }
}

impl From<MemoryError> for KapiError {
    fn from(_: MemoryError) -> Self {
        KapiError::ResourceExhausted
    }
}

/// I/O関連エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoErrorKind {
    /// デバイスが見つからない
    DeviceNotFound,
    /// デバイスビジー
    DeviceBusy,
    /// タイムアウト
    Timeout,
    /// 読み取りエラー
    ReadError,
    /// 書き込みエラー
    WriteError,
    /// リソース不足
    NoResources,
    /// 無効なパラメータ
    InvalidParameter,
}

impl fmt::Display for IoErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceNotFound => write!(f, "device not found"),
            Self::DeviceBusy => write!(f, "device busy"),
            Self::Timeout => write!(f, "timeout"),
            Self::ReadError => write!(f, "read error"),
            Self::WriteError => write!(f, "write error"),
            Self::NoResources => write!(f, "no resources"),
            Self::InvalidParameter => write!(f, "invalid parameter"),
        }
    }
}

impl From<IoErrorKind> for KapiError {
    fn from(_: IoErrorKind) -> Self {
        KapiError::IoError
    }
}
