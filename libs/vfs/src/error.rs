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
    CrossDeviceLink,
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
            Self::StorageFull => write!(f, "Storage full"),
            Self::IoError => write!(f, "I/O error"),
            Self::NotSupported => write!(f, "Operation not supported"),
            Self::ReadOnly => write!(f, "Read-only file system"),
            Self::FileSystemCorrupted => write!(f, "File system corrupted"),
            Self::CrossDeviceLink => write!(f, "Cross-device link"),
            Self::Other => write!(f, "Other error"),
        }
    }
}

pub type VfsResult<T> = Result<T, VfsError>;
