// ============================================================================
// libs/vfs/src/error.rs - VFS Errors
// ============================================================================
//!
//! ファイルシステム操作のエラー型定義。
//!
//! カーネルとファイルシステム実装で共通して使用されるエラー型を提供します。

use core::fmt;

/// ファイルシステムエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    /// ファイルまたはディレクトリが見つからない
    NotFound,
    /// 権限がない
    PermissionDenied,
    /// ファイルまたはディレクトリが既に存在する
    AlreadyExists,
    /// ディレクトリが空でない
    DirectoryNotEmpty,
    /// ディレクトリではない
    NotADirectory,
    /// ディレクトリである
    IsADirectory,
    /// 無効な入力
    InvalidInput,
    /// 無効なパス
    InvalidPath,
    /// ストレージが満杯
    StorageFull,
    /// I/Oエラー
    IoError,
    /// サポートされていない操作
    NotSupported,
    /// 読み取り専用ファイルシステム
    ReadOnly,
    /// ファイルシステムが破損している
    FileSystemCorrupted,
    /// デバイス間リンク
    CrossDeviceLink,
    /// 開いているファイルが多すぎる
    TooManyOpenFiles,
    /// 不正なファイルディスクリプタ
    BadFileDescriptor,
    /// ファイル名が長すぎる
    NameTooLong,
    /// 処理が中断された
    Interrupted,
    /// その他のエラー
    Other,
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "File or directory not found"),
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::AlreadyExists => write!(f, "File or directory already exists"),
            Self::DirectoryNotEmpty => write!(f, "Directory not empty"),
            Self::NotADirectory => write!(f, "Not a directory"),
            Self::IsADirectory => write!(f, "Is a directory"),
            Self::InvalidInput => write!(f, "Invalid input"),
            Self::InvalidPath => write!(f, "Invalid path"),
            Self::StorageFull => write!(f, "Storage full"),
            Self::IoError => write!(f, "I/O error"),
            Self::NotSupported => write!(f, "Operation not supported"),
            Self::ReadOnly => write!(f, "Read-only file system"),
            Self::FileSystemCorrupted => write!(f, "File system corrupted"),
            Self::CrossDeviceLink => write!(f, "Cross-device link"),
            Self::TooManyOpenFiles => write!(f, "Too many open files"),
            Self::BadFileDescriptor => write!(f, "Bad file descriptor"),
            Self::NameTooLong => write!(f, "File name too long"),
            Self::Interrupted => write!(f, "Operation interrupted"),
            Self::Other => write!(f, "Other error"),
        }
    }
}

/// VFS操作の結果型
pub type VfsResult<T> = Result<T, VfsError>;

// ============================================================================
// Error Conversions
// ============================================================================

impl From<VfsError> for u32 {
    /// エラーコードへの変換（システムコール用）
    fn from(err: VfsError) -> u32 {
        match err {
            VfsError::NotFound => 2,             // ENOENT
            VfsError::PermissionDenied => 13,    // EACCES
            VfsError::AlreadyExists => 17,       // EEXIST
            VfsError::DirectoryNotEmpty => 39,   // ENOTEMPTY
            VfsError::NotADirectory => 20,       // ENOTDIR
            VfsError::IsADirectory => 21,        // EISDIR
            VfsError::InvalidInput => 22,        // EINVAL
            VfsError::InvalidPath => 22,         // EINVAL
            VfsError::StorageFull => 28,         // ENOSPC
            VfsError::IoError => 5,              // EIO
            VfsError::NotSupported => 95,        // EOPNOTSUPP
            VfsError::ReadOnly => 30,            // EROFS
            VfsError::FileSystemCorrupted => 5,  // EIO
            VfsError::CrossDeviceLink => 18,     // EXDEV
            VfsError::TooManyOpenFiles => 24,    // EMFILE
            VfsError::BadFileDescriptor => 9,    // EBADF
            VfsError::NameTooLong => 36,         // ENAMETOOLONG
            VfsError::Interrupted => 4,          // EINTR
            VfsError::Other => 255,
        }
    }
}
