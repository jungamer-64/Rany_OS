// ============================================================================
// src/fs/vfs.rs - Virtual Filesystem Implementation
// ============================================================================
//!
//! VFS (Virtual Filesystem) 抽象化
//!
//! ## 設計
//! - UNIX-like なinode/dentry構造
//! - 非同期ファイル操作
//! - マウントポイント管理

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::RwLock;

// ============================================================================
// Error Types
// ============================================================================

/// Filesystem error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    /// File not found
    NotFound,
    /// Permission denied
    PermissionDenied,
    /// File already exists
    AlreadyExists,
    /// Not a directory
    NotDirectory,
    /// Is a directory
    IsDirectory,
    /// Invalid argument
    InvalidArgument,
    /// No space left on device
    NoSpace,
    /// Read-only filesystem
    ReadOnly,
    /// I/O error
    IoError,
    /// Not supported
    NotSupported,
    /// Invalid path
    InvalidPath,
    /// Directory not empty
    NotEmpty,
    /// Too many open files
    TooManyOpenFiles,
    /// Bad file descriptor
    BadFileDescriptor,
    /// Cross-device link
    CrossDeviceLink,
    /// Name too long
    NameTooLong,
    /// Interrupted
    Interrupted,
}

/// Result type for filesystem operations
pub type FsResult<T> = Result<T, FsError>;

// ============================================================================
// File Types and Modes
// ============================================================================

/// File type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    /// Regular file
    Regular,
    /// Directory
    Directory,
    /// Symbolic link
    Symlink,
    /// Block device
    BlockDevice,
    /// Character device
    CharDevice,
    /// Named pipe (FIFO)
    Fifo,
    /// Socket
    Socket,
}

/// File mode/permissions (UNIX-style)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMode(pub u16);

impl FileMode {
    /// Owner read permission
    pub const S_IRUSR: u16 = 0o400;
    /// Owner write permission
    pub const S_IWUSR: u16 = 0o200;
    /// Owner execute permission
    pub const S_IXUSR: u16 = 0o100;
    /// Group read permission
    pub const S_IRGRP: u16 = 0o040;
    /// Group write permission
    pub const S_IWGRP: u16 = 0o020;
    /// Group execute permission
    pub const S_IXGRP: u16 = 0o010;
    /// Other read permission
    pub const S_IROTH: u16 = 0o004;
    /// Other write permission
    pub const S_IWOTH: u16 = 0o002;
    /// Other execute permission
    pub const S_IXOTH: u16 = 0o001;
    
    /// Default file mode (rw-r--r--)
    pub const DEFAULT_FILE: FileMode = FileMode(0o644);
    /// Default directory mode (rwxr-xr-x)
    pub const DEFAULT_DIR: FileMode = FileMode(0o755);
    
    /// Check if owner can read
    pub fn owner_read(&self) -> bool {
        self.0 & Self::S_IRUSR != 0
    }
    
    /// Check if owner can write
    pub fn owner_write(&self) -> bool {
        self.0 & Self::S_IWUSR != 0
    }
    
    /// Check if owner can execute
    pub fn owner_execute(&self) -> bool {
        self.0 & Self::S_IXUSR != 0
    }
}

impl Default for FileMode {
    fn default() -> Self {
        Self::DEFAULT_FILE
    }
}

/// Open flags
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    /// Open for reading only
    pub const O_RDONLY: u32 = 0;
    /// Open for writing only
    pub const O_WRONLY: u32 = 1;
    /// Open for reading and writing
    pub const O_RDWR: u32 = 2;
    /// Create file if it does not exist
    pub const O_CREAT: u32 = 0o100;
    /// Fail if file exists (with O_CREAT)
    pub const O_EXCL: u32 = 0o200;
    /// Truncate file to zero length
    pub const O_TRUNC: u32 = 0o1000;
    /// Append to end of file
    pub const O_APPEND: u32 = 0o2000;
    /// Non-blocking mode
    pub const O_NONBLOCK: u32 = 0o4000;
    /// Synchronous I/O
    pub const O_SYNC: u32 = 0o4010000;
    /// Directory
    pub const O_DIRECTORY: u32 = 0o200000;
    
    /// Check if read access requested
    pub fn can_read(&self) -> bool {
        self.0 & 3 != Self::O_WRONLY
    }
    
    /// Check if write access requested
    pub fn can_write(&self) -> bool {
        self.0 & 3 != Self::O_RDONLY
    }
    
    /// Check if create flag set
    pub fn create(&self) -> bool {
        self.0 & Self::O_CREAT != 0
    }
    
    /// Check if truncate flag set
    pub fn truncate(&self) -> bool {
        self.0 & Self::O_TRUNC != 0
    }
    
    /// Check if append flag set
    pub fn append(&self) -> bool {
        self.0 & Self::O_APPEND != 0
    }
}

/// Seek position
#[derive(Clone, Copy, Debug)]
pub enum SeekFrom {
    /// Seek from start of file
    Start(u64),
    /// Seek from end of file
    End(i64),
    /// Seek from current position
    Current(i64),
}

// ============================================================================
// Inode and DirEntry
// ============================================================================

/// Inode number type
pub type InodeNum = u64;

/// File metadata/attributes
#[derive(Clone, Debug)]
pub struct FileAttr {
    /// Inode number
    pub ino: InodeNum,
    /// File size in bytes
    pub size: u64,
    /// Number of blocks
    pub blocks: u64,
    /// File type
    pub file_type: FileType,
    /// File mode/permissions
    pub mode: FileMode,
    /// Number of hard links
    pub nlink: u32,
    /// Owner user ID
    pub uid: u32,
    /// Owner group ID
    pub gid: u32,
    /// Device ID (for special files)
    pub rdev: u64,
    /// Block size for filesystem I/O
    pub blksize: u32,
    /// Last access time (nanoseconds since epoch)
    pub atime: u64,
    /// Last modification time
    pub mtime: u64,
    /// Last status change time
    pub ctime: u64,
}

impl Default for FileAttr {
    fn default() -> Self {
        Self {
            ino: 0,
            size: 0,
            blocks: 0,
            file_type: FileType::Regular,
            mode: FileMode::default(),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            atime: 0,
            mtime: 0,
            ctime: 0,
        }
    }
}

/// Directory entry
#[derive(Clone, Debug)]
pub struct DirEntry {
    /// Entry name
    pub name: String,
    /// Inode number
    pub ino: InodeNum,
    /// File type
    pub file_type: FileType,
}

// ============================================================================
// Inode Trait
// ============================================================================

/// Inode operations trait
pub trait Inode: Send + Sync {
    /// Get file attributes
    fn getattr(&self) -> FsResult<FileAttr>;
    
    /// Set file attributes
    fn setattr(&self, attr: &FileAttr) -> FsResult<()>;
    
    /// Look up a name in this directory
    fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>>;
    
    /// Read directory entries
    fn readdir(&self, offset: u64) -> FsResult<Vec<DirEntry>>;
    
    /// Create a file in this directory
    fn create(&self, name: &str, mode: FileMode, flags: OpenFlags) -> FsResult<Arc<dyn Inode>>;
    
    /// Create a directory
    fn mkdir(&self, name: &str, mode: FileMode) -> FsResult<Arc<dyn Inode>>;
    
    /// Remove a file
    fn unlink(&self, name: &str) -> FsResult<()>;
    
    /// Remove a directory
    fn rmdir(&self, name: &str) -> FsResult<()>;
    
    /// Rename a file
    fn rename(&self, old_name: &str, new_dir: &Arc<dyn Inode>, new_name: &str) -> FsResult<()>;
    
    /// Create a hard link
    fn link(&self, name: &str, inode: &Arc<dyn Inode>) -> FsResult<()>;
    
    /// Create a symbolic link
    fn symlink(&self, name: &str, target: &str) -> FsResult<Arc<dyn Inode>>;
    
    /// Read symbolic link target
    fn readlink(&self) -> FsResult<String>;
    
    /// Read data from file
    fn read(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize>;
    
    /// Write data to file
    fn write(&self, offset: u64, buf: &[u8]) -> FsResult<usize>;
    
    /// Truncate file to specified length
    fn truncate(&self, size: u64) -> FsResult<()>;
    
    /// Sync file data to storage
    fn fsync(&self, datasync: bool) -> FsResult<()>;
}

// ============================================================================
// Filesystem Trait
// ============================================================================

/// Filesystem operations trait
pub trait FileSystem: Send + Sync {
    /// Get filesystem name
    fn name(&self) -> &str;
    
    /// Get root inode
    fn root(&self) -> FsResult<Arc<dyn Inode>>;
    
    /// Get filesystem statistics
    fn statfs(&self) -> FsResult<FsStats>;
    
    /// Sync all pending writes to storage
    fn sync(&self) -> FsResult<()>;
    
    /// Unmount filesystem
    fn unmount(&self) -> FsResult<()>;
}

/// Filesystem statistics
#[derive(Clone, Debug, Default)]
pub struct FsStats {
    /// Total blocks
    pub blocks: u64,
    /// Free blocks
    pub bfree: u64,
    /// Available blocks (non-superuser)
    pub bavail: u64,
    /// Total inodes
    pub files: u64,
    /// Free inodes
    pub ffree: u64,
    /// Block size
    pub bsize: u32,
    /// Maximum filename length
    pub namelen: u32,
    /// Fragment size
    pub frsize: u32,
}

// ============================================================================
// Async File Handle
// ============================================================================

/// Open file handle
pub struct FileHandle {
    /// Associated inode
    inode: Arc<dyn Inode>,
    /// Open flags
    flags: OpenFlags,
    /// Current file position
    position: u64,
}

impl FileHandle {
    /// Create a new file handle
    pub fn new(inode: Arc<dyn Inode>, flags: OpenFlags) -> Self {
        Self {
            inode,
            flags,
            position: 0,
        }
    }
    
    /// Read data from file
    pub fn read(&mut self, buf: &mut [u8]) -> FsResult<usize> {
        if !self.flags.can_read() {
            return Err(FsError::PermissionDenied);
        }
        
        let n = self.inode.read(self.position, buf)?;
        self.position += n as u64;
        Ok(n)
    }
    
    /// Write data to file
    pub fn write(&mut self, buf: &[u8]) -> FsResult<usize> {
        if !self.flags.can_write() {
            return Err(FsError::PermissionDenied);
        }
        
        if self.flags.append() {
            let attr = self.inode.getattr()?;
            self.position = attr.size;
        }
        
        let n = self.inode.write(self.position, buf)?;
        self.position += n as u64;
        Ok(n)
    }
    
    /// Seek to position
    pub fn seek(&mut self, pos: SeekFrom) -> FsResult<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                let attr = self.inode.getattr()?;
                if offset < 0 {
                    attr.size.checked_sub((-offset) as u64)
                        .ok_or(FsError::InvalidArgument)?
                } else {
                    attr.size + offset as u64
                }
            }
            SeekFrom::Current(offset) => {
                if offset < 0 {
                    self.position.checked_sub((-offset) as u64)
                        .ok_or(FsError::InvalidArgument)?
                } else {
                    self.position + offset as u64
                }
            }
        };
        
        self.position = new_pos;
        Ok(new_pos)
    }
    
    /// Get file attributes
    pub fn getattr(&self) -> FsResult<FileAttr> {
        self.inode.getattr()
    }
    
    /// Sync file to storage
    pub fn fsync(&self, datasync: bool) -> FsResult<()> {
        self.inode.fsync(datasync)
    }
    
    /// Get current position
    pub fn position(&self) -> u64 {
        self.position
    }
}

// ============================================================================
// Async Operations
// ============================================================================

/// Future for async read operation
pub struct AsyncReadFuture<'a> {
    inode: Arc<dyn Inode>,
    position: u64,
    buf: &'a mut [u8],
    completed: bool,
}

impl<'a> AsyncReadFuture<'a> {
    /// Create a new async read future from a file handle
    pub fn new(handle: &FileHandle, buf: &'a mut [u8]) -> Self {
        Self {
            inode: handle.inode.clone(),
            position: handle.position,
            buf,
            completed: false,
        }
    }
}

impl<'a> Future for AsyncReadFuture<'a> {
    type Output = FsResult<usize>;
    
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        
        if this.completed {
            return Poll::Ready(Err(FsError::InvalidArgument));
        }
        
        // For now, synchronous implementation
        // Real implementation would use async block device
        this.completed = true;
        let position = this.position;
        let result = this.inode.read(position, this.buf);
        Poll::Ready(result)
    }
}

/// Future for async write operation
pub struct AsyncWriteFuture<'a> {
    inode: Arc<dyn Inode>,
    position: u64,
    buf: &'a [u8],
    completed: bool,
}

impl<'a> AsyncWriteFuture<'a> {
    /// Create a new async write future from a file handle
    pub fn new(handle: &FileHandle, buf: &'a [u8]) -> Self {
        Self {
            inode: handle.inode.clone(),
            position: handle.position,
            buf,
            completed: false,
        }
    }
}

impl<'a> Future for AsyncWriteFuture<'a> {
    type Output = FsResult<usize>;
    
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        
        if this.completed {
            return Poll::Ready(Err(FsError::InvalidArgument));
        }
        
        this.completed = true;
        let position = this.position;
        let result = this.inode.write(position, this.buf);
        Poll::Ready(result)
    }
}

// ============================================================================
// Path Resolution
// ============================================================================

/// Path resolver
pub struct PathResolver {
    root: Arc<dyn Inode>,
    cwd: Arc<dyn Inode>,
}

impl PathResolver {
    /// Create a new path resolver
    pub fn new(root: Arc<dyn Inode>) -> Self {
        Self {
            root: root.clone(),
            cwd: root,
        }
    }
    
    /// Resolve a path to an inode
    pub fn resolve(&self, path: &str) -> FsResult<Arc<dyn Inode>> {
        if path.is_empty() {
            return Err(FsError::InvalidPath);
        }
        
        let (start, components) = if path.starts_with('/') {
            (self.root.clone(), path[1..].split('/'))
        } else {
            (self.cwd.clone(), path.split('/'))
        };
        
        let mut current = start;
        
        for component in components {
            if component.is_empty() || component == "." {
                continue;
            }
            
            if component == ".." {
                // TODO: Handle parent directory
                // For now, stay at current
                continue;
            }
            
            current = current.lookup(component)?;
        }
        
        Ok(current)
    }
    
    /// Resolve parent directory and filename
    pub fn resolve_parent(&self, path: &str) -> FsResult<(Arc<dyn Inode>, String)> {
        if path.is_empty() {
            return Err(FsError::InvalidPath);
        }
        
        let path = path.trim_end_matches('/');
        
        if let Some(pos) = path.rfind('/') {
            let parent_path = if pos == 0 { "/" } else { &path[..pos] };
            let name = &path[pos + 1..];
            let parent = self.resolve(parent_path)?;
            Ok((parent, name.into()))
        } else {
            Ok((self.cwd.clone(), path.into()))
        }
    }
    
    /// Set current working directory
    pub fn set_cwd(&mut self, path: &str) -> FsResult<()> {
        let inode = self.resolve(path)?;
        let attr = inode.getattr()?;
        
        if attr.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }
        
        self.cwd = inode;
        Ok(())
    }
}

// ============================================================================
// Mount Table
// ============================================================================

/// Mount point entry
struct MountEntry {
    /// Mount path
    path: String,
    /// Mounted filesystem
    fs: Arc<dyn FileSystem>,
}

/// Global mount table
pub struct MountTable {
    mounts: RwLock<Vec<MountEntry>>,
}

impl MountTable {
    /// Create a new mount table
    pub const fn new() -> Self {
        Self {
            mounts: RwLock::new(Vec::new()),
        }
    }
    
    /// Mount a filesystem
    pub fn mount(&self, path: &str, fs: Arc<dyn FileSystem>) -> FsResult<()> {
        let mut mounts = self.mounts.write();
        
        // Check if already mounted
        if mounts.iter().any(|m| m.path == path) {
            return Err(FsError::AlreadyExists);
        }
        
        mounts.push(MountEntry {
            path: path.into(),
            fs,
        });
        
        Ok(())
    }
    
    /// Unmount a filesystem
    pub fn unmount(&self, path: &str) -> FsResult<()> {
        let mut mounts = self.mounts.write();
        
        if let Some(pos) = mounts.iter().position(|m| m.path == path) {
            let entry = mounts.remove(pos);
            entry.fs.unmount()?;
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }
    
    /// Find filesystem for a path
    pub fn find(&self, path: &str) -> Option<Arc<dyn FileSystem>> {
        let mounts = self.mounts.read();
        
        // Find longest matching mount point
        mounts
            .iter()
            .filter(|m| path.starts_with(&m.path))
            .max_by_key(|m| m.path.len())
            .map(|m| m.fs.clone())
    }
}

/// Global mount table instance
static MOUNT_TABLE: MountTable = MountTable::new();

/// Get the global mount table
pub fn mount_table() -> &'static MountTable {
    &MOUNT_TABLE
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_file_mode() {
        let mode = FileMode::DEFAULT_FILE;
        assert!(mode.owner_read());
        assert!(mode.owner_write());
        assert!(!mode.owner_execute());
    }
    
    #[test]
    fn test_open_flags() {
        let flags = OpenFlags(OpenFlags::O_RDWR | OpenFlags::O_CREAT);
        assert!(flags.can_read());
        assert!(flags.can_write());
        assert!(flags.create());
    }
}
