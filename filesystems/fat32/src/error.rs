use crate::{BlockError, Box, Cluster, FsError, Sector};

use core::fmt;

// ============================================================================
// Enhanced Error Types
// ============================================================================

/// FAT32固有のエラー型
///
/// FsErrorよりも詳細な情報を保持し、デバッグとエラーリカバリを容易にする
#[derive(Debug, Clone)]
pub enum Fat32Error {
    /// 無効なブートセクタ
    InvalidBootSector {
        reason: &'static str,
        signature: u16,
    },
    /// 無効なクラスタ番号
    InvalidCluster { cluster: u32, max_valid: u32 },
    /// クラスタチェーンのループ検出
    ClusterChainLoop {
        cluster: Cluster,
        chain_length: usize,
    },
    /// パスが長すぎる
    PathTooLong { path_len: usize, max_length: usize },
    /// I/O操作エラー（詳細なコンテキスト付き）
    ///
    /// デバッグ時にどの操作でエラーが発生したかを特定しやすくする
    IoOperation {
        /// 操作名（"read_cluster", "write_fat", etc.）
        operation: &'static str,
        /// 関連するセクタ番号（存在する場合）
        sector: Option<Sector>,
        /// 関連するクラスタ番号（存在する場合）
        cluster: Option<Cluster>,
        /// 元のエラー（チェーン）
        source: Option<Box<Fat32Error>>,
    },
    /// ブロックデバイスエラー
    BlockDevice(BlockError),
    /// 一般的なファイルシステムエラー
    Fs(FsError),
}

impl fmt::Display for Fat32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fat32Error::InvalidBootSector { reason, signature } => {
                write!(
                    f,
                    "Invalid boot sector: {} (signature: 0x{:04X})",
                    reason, signature
                )
            }
            Fat32Error::InvalidCluster { cluster, max_valid } => {
                write!(f, "Invalid cluster {} (max: {})", cluster, max_valid)
            }
            Fat32Error::ClusterChainLoop {
                cluster,
                chain_length,
            } => {
                write!(
                    f,
                    "Cluster chain loop detected at cluster {} after {} iterations",
                    cluster.0, chain_length
                )
            }
            Fat32Error::PathTooLong {
                path_len,
                max_length,
            } => {
                write!(
                    f,
                    "Path too long: {} exceeds {} characters",
                    path_len, max_length
                )
            }
            Fat32Error::IoOperation {
                operation,
                sector,
                cluster,
                source,
            } => {
                write!(f, "I/O operation '{}' failed", operation)?;
                if let Some(s) = sector {
                    write!(f, " at sector {}", s.0)?;
                }
                if let Some(c) = cluster {
                    write!(f, " for cluster {}", c.0)?;
                }
                if let Some(src) = source {
                    write!(f, ": {}", src)?;
                }
                Ok(())
            }
            Fat32Error::BlockDevice(e) => {
                write!(f, "Block device error: {:?}", e)
            }
            Fat32Error::Fs(e) => {
                write!(f, "Filesystem error: {:?}", e)
            }
        }
    }
}

/// BlockErrorからFsErrorへの自動変換
///
/// これにより`?`演算子だけで自動変換でき、map_errが不要になる

/// Fat32ErrorからFsErrorへの変換
impl From<Fat32Error> for FsError {
    fn from(err: Fat32Error) -> Self {
        match err {
            Fat32Error::InvalidBootSector { .. } => FsError::InvalidInput,
            Fat32Error::InvalidCluster { .. } => FsError::FileSystemCorrupted,
            Fat32Error::ClusterChainLoop { .. } => FsError::FileSystemCorrupted,
            Fat32Error::PathTooLong { .. } => FsError::InvalidInput,
            Fat32Error::IoOperation { .. } => FsError::IoError,
            Fat32Error::BlockDevice(_) => FsError::IoError,
            Fat32Error::Fs(e) => e,
        }
    }
}

// ============================================================================
// Result Type Alias and Extensions
// ============================================================================

/// FAT32固有のResult型エイリアス
pub type Fat32Result<T> = Result<T, Fat32Error>;

/// Result型にコンテキスト追加機能を提供する拡張トレイト
///
/// # Example
/// ```ignore
/// device.read_sync(sector.as_u64(), &mut buffer)
///     .context("Failed to read cluster from device")?;
/// ```
pub trait ResultExt<T> {
    /// エラーに静的コンテキストメッセージを追加
    fn context(self, msg: &'static str) -> Fat32Result<T>;

    /// エラーに遅延評価でコンテキストを追加
    fn with_context<F>(self, f: F) -> Fat32Result<T>
    where
        F: FnOnce() -> &'static str;
}

impl<T, E: Into<Fat32Error>> ResultExt<T> for Result<T, E> {
    fn context(self, msg: &'static str) -> Fat32Result<T> {
        self.map_err(|e| {
            let fe: Fat32Error = e.into();
            let (sector, cluster) = match &fe {
                Fat32Error::IoOperation {
                    sector, cluster, ..
                } => (sector.clone(), cluster.clone()),
                _ => (None, None),
            };
            Fat32Error::IoOperation {
                operation: msg,
                sector,
                cluster,
                source: Some(Box::new(fe)),
            }
        })
    }

    fn with_context<F>(self, f: F) -> Fat32Result<T>
    where
        F: FnOnce() -> &'static str,
    {
        self.context(f())
    }
}

// ============================================================================
