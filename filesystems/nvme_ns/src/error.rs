// ============================================================================
// filesystems/nvme_ns/src/error.rs - Error Types
// ============================================================================

use alloc::string::String;
use core::fmt;

/// NVMe Namespace FS の結果型
pub type NsResult<T> = Result<T, NsError>;

/// NVMe Namespace FS エラー
#[derive(Debug, Clone)]
pub enum NsError {
    /// I/O エラー（NVMe コマンド失敗）
    IoError,
    /// スーパーブロックのマジックナンバーが無効
    InvalidSuperblock,
    /// inode 番号が範囲外
    InvalidInode(u64),
    /// ファイルが見つからない
    NotFound,
    /// すでに存在する
    AlreadyExists,
    /// ディレクトリではない
    NotADirectory,
    /// ディレクトリである
    IsADirectory,
    /// ディレクトリが空でない
    DirectoryNotEmpty,
    /// 空き領域なし
    NoSpace,
    /// 名前が長すぎる
    NameTooLong,
    /// 権限エラー
    PermissionDenied,
    /// 読み取り専用
    ReadOnly,
    /// 無効な引数
    InvalidArgument,
    /// 未サポート操作
    NotSupported,
    /// 内部エラー
    Internal(String),
}

impl fmt::Display for NsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NsError::IoError => write!(f, "I/O error"),
            NsError::InvalidSuperblock => write!(f, "invalid superblock"),
            NsError::InvalidInode(n) => write!(f, "invalid inode {}", n),
            NsError::NotFound => write!(f, "not found"),
            NsError::AlreadyExists => write!(f, "already exists"),
            NsError::NotADirectory => write!(f, "not a directory"),
            NsError::IsADirectory => write!(f, "is a directory"),
            NsError::DirectoryNotEmpty => write!(f, "directory not empty"),
            NsError::NoSpace => write!(f, "no space left"),
            NsError::NameTooLong => write!(f, "name too long"),
            NsError::PermissionDenied => write!(f, "permission denied"),
            NsError::ReadOnly => write!(f, "read-only filesystem"),
            NsError::InvalidArgument => write!(f, "invalid argument"),
            NsError::NotSupported => write!(f, "not supported"),
            NsError::Internal(msg) => write!(f, "internal: {}", msg),
        }
    }
}

impl From<NsError> for vfs::VfsError {
    fn from(e: NsError) -> Self {
        match e {
            NsError::IoError => vfs::VfsError::IoError,
            NsError::InvalidSuperblock => vfs::VfsError::IoError,
            NsError::InvalidInode(_) => vfs::VfsError::IoError,
            NsError::NotFound => vfs::VfsError::NotFound,
            NsError::AlreadyExists => vfs::VfsError::AlreadyExists,
            NsError::NotADirectory => vfs::VfsError::NotADirectory,
            NsError::IsADirectory => vfs::VfsError::IsADirectory,
            NsError::DirectoryNotEmpty => vfs::VfsError::DirectoryNotEmpty,
            NsError::NoSpace => vfs::VfsError::StorageFull,
            NsError::NameTooLong => vfs::VfsError::NameTooLong,
            NsError::PermissionDenied => vfs::VfsError::PermissionDenied,
            NsError::ReadOnly => vfs::VfsError::ReadOnly,
            NsError::InvalidArgument => vfs::VfsError::Other,
            NsError::NotSupported => vfs::VfsError::NotSupported,
            NsError::Internal(_) => vfs::VfsError::IoError,
        }
    }
}

impl From<vfs::VfsError> for NsError {
    fn from(e: vfs::VfsError) -> Self {
        match e {
            vfs::VfsError::NotFound => NsError::NotFound,
            vfs::VfsError::AlreadyExists => NsError::AlreadyExists,
            vfs::VfsError::NotADirectory => NsError::NotADirectory,
            vfs::VfsError::IsADirectory => NsError::IsADirectory,
            vfs::VfsError::DirectoryNotEmpty => NsError::DirectoryNotEmpty,
            vfs::VfsError::StorageFull => NsError::NoSpace,
            vfs::VfsError::PermissionDenied => NsError::PermissionDenied,
            vfs::VfsError::ReadOnly => NsError::ReadOnly,
            vfs::VfsError::IoError => NsError::IoError,
            vfs::VfsError::NotSupported => NsError::NotSupported,
            _ => NsError::IoError,
        }
    }
}
