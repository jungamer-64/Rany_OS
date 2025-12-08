// ============================================================================
// libs/vfs/src/error.rs - VFS Errors
// ============================================================================

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    DirectoryNotEmpty,
    NotADirectory,
    IsADirectory,
    InvalidInput,
    StorageFull,
    IoError,
    NotSupported,
    ReadOnly,
    FileSystemCorrupted,
    Other,
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VfsError::NotFound => write!(f, "File or directory not found"),
            VfsError::PermissionDenied => write!(f, "Permission denied"),
            VfsError::AlreadyExists => write!(f, "File or directory already exists"),
            VfsError::DirectoryNotEmpty => write!(f, "Directory not empty"),
            VfsError::NotADirectory => write!(f, "Not a directory"),
            VfsError::IsADirectory => write!(f, "Is a directory"),
            VfsError::InvalidInput => write!(f, "Invalid input"),
            VfsError::StorageFull => write!(f, "Storage full"),
            VfsError::IoError => write!(f, "I/O error"),
            VfsError::NotSupported => write!(f, "Operation not supported"),
            VfsError::ReadOnly => write!(f, "Read-only file system"),
            VfsError::FileSystemCorrupted => write!(f, "File system corrupted"),
            VfsError::Other => write!(f, "Other error"),
        }
    }
}

pub type VfsResult<T> = Result<T, VfsError>;
