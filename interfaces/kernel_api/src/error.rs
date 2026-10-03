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
    /// The required service or allocator has not been initialized.
    NotInitialized,
    /// 既に存在する
    AlreadyExists,
    /// I/Oエラー
    IoError,
    /// 接続エラー
    ConnectionError,
    /// メモリ不足
    OutOfMemory,
    /// The requested memory range or address cannot be represented or accessed.
    InvalidAddress,
    /// The requested alignment is unsupported or invalid for the range.
    InvalidAlignment,
    /// The requested byte count is invalid or overflows its address space.
    InvalidSize,
    /// No usable translation was established for the requested range.
    MappingFailed,
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
            Self::NotInitialized => write!(f, "Service not initialized"),
            Self::AlreadyExists => write!(f, "Resource already exists"),
            Self::IoError => write!(f, "I/O error"),
            Self::ConnectionError => write!(f, "Connection error"),
            Self::OutOfMemory => write!(f, "Out of memory"),
            Self::InvalidAddress => write!(f, "Invalid memory address"),
            Self::InvalidAlignment => write!(f, "Invalid memory alignment"),
            Self::InvalidSize => write!(f, "Invalid memory size"),
            Self::MappingFailed => write!(f, "Memory mapping failed"),
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
    fn from(error: MemoryError) -> Self {
        match error {
            MemoryError::OutOfMemory => Self::OutOfMemory,
            MemoryError::InvalidAddress => Self::InvalidAddress,
            MemoryError::InvalidAlignment => Self::InvalidAlignment,
            MemoryError::InvalidSize => Self::InvalidSize,
            MemoryError::MappingFailed => Self::MappingFailed,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::driver::AbiError;

    #[test]
    fn memory_failure_classes_survive_native_and_wire_boundaries() {
        // Protocol values are independently specified here rather than
        // generated from the production encoder or decoder.
        for (memory, service, code) in [
            (MemoryError::OutOfMemory, KapiError::OutOfMemory, -5),
            (MemoryError::InvalidSize, KapiError::InvalidSize, -13),
            (
                MemoryError::InvalidAlignment,
                KapiError::InvalidAlignment,
                -14,
            ),
            (MemoryError::InvalidAddress, KapiError::InvalidAddress, -15),
            (MemoryError::MappingFailed, KapiError::MappingFailed, -16),
        ] {
            assert_eq!(KapiError::from(memory), service);
            assert_eq!(AbiError::from(service) as i32, code);
            assert_eq!(AbiError::from_raw(code).into_result(), Err(service));
        }
    }

    #[test]
    fn admission_exhaustion_and_service_absence_have_distinct_wire_results() {
        assert_eq!(AbiError::from_raw(0).into_result(), Ok(()));
        for (code, error) in [
            (-2, KapiError::NotFound),
            (-5, KapiError::OutOfMemory),
            (-11, KapiError::NotInitialized),
            (-12, KapiError::ResourceExhausted),
        ] {
            assert_eq!(AbiError::from(error) as i32, code);
            assert_eq!(AbiError::from_raw(code).into_result(), Err(error));
        }
    }
}
