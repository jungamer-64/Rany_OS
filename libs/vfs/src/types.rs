// ============================================================================
// libs/vfs/src/types.rs - VFS Types
// ============================================================================

use bitflags::bitflags;

/// Inode number type
pub type InodeNum = u64;

/// ファイルタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Pipe,
    Socket,
}

/// ファイルメタデータ
#[derive(Debug, Clone, Copy, Default)]
pub struct Metadata {
    pub file_type: Option<FileType>,
    pub size: u64,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub readonly: bool,
}

/// シーク位置
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekFrom {
    Start(u64),
    End(i64),
    Current(i64),
}

bitflags! {
    /// ファイルオープンフラグ
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenFlags: u32 {
        const READ = 0x0001;
        const WRITE = 0x0002;
        const CREATE = 0x0004;
        const TRUNCATE = 0x0008;
        const APPEND = 0x0010;
        const EXCLUSIVE = 0x0020;
        const DIRECTORY = 0x0040;
    }
}

bitflags! {
    /// ファイルモード（パーミッション）
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FileMode: u32 {
        const READ = 0x04;
        const WRITE = 0x02;
        const EXECUTE = 0x01;
    }
}
