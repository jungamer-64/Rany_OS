// ============================================================================
// src/fs/fat32_adapter.rs - Adapter for FAT32 Crate
// ============================================================================
//!
//! # FAT32 Adapter
//!
//! `filesystems/fat32` クレート（`libs/vfs` ベース）を
//! カーネルの `fs_abstraction` トレイと適合させるためのアダプタ。
//!

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::fs_abstraction::{
    DirEntry, FileAttr, FileMode, FileSystem, FileType, FsError, FsResult, FsStats,
    Inode, OpenFlags,
};

// Import from the new crate
use fat32::Fat32FileSystem;
use vfs::{
    Directory as VfsDirectory, File as VfsFile, FileSystem as VfsFileSystem,
    FileType as VfsFileType, Metadata as VfsMetadata, VfsError, VfsNode,
};

// ============================================================================
// Type Conversion
// ============================================================================

impl From<VfsError> for FsError {
    fn from(err: VfsError) -> Self {
        match err {
            VfsError::NotFound => FsError::NotFound,
            VfsError::PermissionDenied => FsError::PermissionDenied,
            VfsError::AlreadyExists => FsError::AlreadyExists,
            VfsError::NotADirectory => FsError::NotDirectory,
            VfsError::IsADirectory => FsError::IsDirectory,
            VfsError::DirectoryNotEmpty => FsError::NotEmpty,
            VfsError::InvalidInput => FsError::InvalidArgument,
            VfsError::StorageFull => FsError::NoSpace,
            VfsError::ReadOnly => FsError::ReadOnly,
            VfsError::IoError => FsError::IoError,
            VfsError::NotSupported => FsError::NotSupported,
            VfsError::FileSystemCorrupted => FsError::CorruptedFs,
            VfsError::Other => FsError::IoError,
        }
    }
}

fn convert_file_type(ft: VfsFileType) -> FileType {
    match ft {
        VfsFileType::File => FileType::Regular,
        VfsFileType::Directory => FileType::Directory,
        VfsFileType::Symlink => FileType::Symlink,
        VfsFileType::BlockDevice => FileType::BlockDevice,
        VfsFileType::CharDevice => FileType::CharDevice,
        VfsFileType::Pipe => FileType::Fifo,
        VfsFileType::Socket => FileType::Socket,
    }
}

fn convert_to_vfs_file_type(ft: FileType) -> VfsFileType {
    match ft {
        FileType::Regular => VfsFileType::File,
        FileType::Directory => VfsFileType::Directory,
        FileType::Symlink => VfsFileType::Symlink,
        FileType::BlockDevice => VfsFileType::BlockDevice,
        FileType::CharDevice => VfsFileType::CharDevice,
        FileType::Fifo => VfsFileType::Pipe,
        FileType::Socket => VfsFileType::Socket,
    }
}

fn convert_metadata(meta: VfsMetadata, ino: u64) -> FileAttr {
    FileAttr {
        ino,
        size: meta.size,
        blocks: (meta.size + 511) / 512, // Approximate
        file_type: meta
            .file_type
            .map(convert_file_type)
            .unwrap_or(FileType::Regular),
        mode: FileMode::default(), // FAT32 doesn't support modes really
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096, // TODO: Get from FS
        atime: meta.accessed,
        mtime: meta.modified,
        ctime: meta.created,
    }
}

// ============================================================================
// FileSystem Adapter
// ============================================================================

pub struct Fat32FileSystemAdapter {
    inner: Arc<Fat32FileSystem>,
}

impl Fat32FileSystemAdapter {
    pub fn new(inner: Arc<Fat32FileSystem>) -> Self {
        Self { inner }
    }
}

impl FileSystem for Fat32FileSystemAdapter {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn root(&self) -> FsResult<Arc<dyn Inode>> {
        let root_node = self.inner.root_dir().map_err(FsError::from)?;
        // VfsNode is not Clone, but we need Arc<dyn Inode>
        // Fat32Inode implements VfsNode and is usually wrapped in Arc or is cloneable?
        // root_dir() returns Box<dyn VfsNode>.
        // We need to wrap it in our adapter.
        // Since Box<dyn VfsNode> owns the node, we can put it in Arc<Mutex>?
        // Or better, Fat32Inode is likely Arc internally or we can just wrap the Box.
        // But Inode needs Send+Sync.

        // Strategy: Wrap Box<dyn VfsNode> in Arc<Fat32InodeAdapter>
        // But Fat32InodeAdapter needs to hold the VfsNode.
        // Since VfsNode is a trait object, we can hold Box<dyn VfsNode>.
        // But we need Arc<Fat32InodeAdapter> to return.

        Ok(Arc::new(Fat32InodeAdapter {
            inner: spin::Mutex::new(root_node),
        }))
    }

    fn statfs(&self) -> FsResult<FsStats> {
        // FAT32 crate doesn't implement statfs yet in VFS trait,
        // but Fat32FileSystem might have methods.
        // For now return dummy or implement if possible.
        Ok(FsStats::default())
    }

    fn sync(&self) -> FsResult<()> {
        self.inner.sync().map_err(FsError::from)
    }

    fn unmount(&self) -> FsResult<()> {
        Ok(())
    }
}

// ============================================================================
// Inode Adapter
// ============================================================================

pub struct Fat32InodeAdapter {
    // We use Mutex because VfsNode methods take &self (immutable),
    // but some operations like open/as_dir might need internal mutability
    // or we just hold the Box.
    // Actually VfsNode methods take &self.
    // But we need to put it in a struct that can be Arc'd.
    inner: spin::Mutex<Box<dyn VfsNode>>,
}

impl Inode for Fat32InodeAdapter {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn getattr(&self) -> FsResult<FileAttr> {
        let node = self.inner.lock();
        let meta = node.metadata().map_err(FsError::from)?;
        // Inode number is not easily available from VfsNode unless we cast or it has a method.
        // VfsNode has name(), but not ino().
        // For now use 0 or hash of name.
        Ok(convert_metadata(meta, 0))
    }

    fn setattr(&self, _attr: &FileAttr) -> FsResult<()> {
        // Not fully supported in VFS trait yet
        Ok(())
    }

    fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>> {
        let node = self.inner.lock();
        let dir = node.as_dir().map_err(FsError::from)?;
        let child = dir.lookup(name).map_err(FsError::from)?;

        Ok(Arc::new(Fat32InodeAdapter {
            inner: spin::Mutex::new(child),
        }))
    }

    fn readdir(&self, _offset: u64) -> FsResult<Vec<DirEntry>> {
        let mut node = self.inner.lock();
        let mut dir = node.as_dir().map_err(FsError::from)?;
        let entries = dir.read_dir().map_err(FsError::from)?;

        Ok(entries
            .into_iter()
            .map(|e| DirEntry {
                name: e.name,
                ino: 0, // TODO
                file_type: convert_file_type(e.file_type),
            })
            .collect())
    }

    fn create(&self, name: &str, _mode: FileMode, _flags: OpenFlags) -> FsResult<Arc<dyn Inode>> {
        let mut node = self.inner.lock();
        let mut dir = node.as_dir().map_err(FsError::from)?;
        let child = dir.create(name, VfsFileType::File).map_err(FsError::from)?;

        Ok(Arc::new(Fat32InodeAdapter {
            inner: spin::Mutex::new(child),
        }))
    }

    fn mkdir(&self, name: &str, _mode: FileMode) -> FsResult<Arc<dyn Inode>> {
        let mut node = self.inner.lock();
        let mut dir = node.as_dir().map_err(FsError::from)?;
        let child = dir
            .create(name, VfsFileType::Directory)
            .map_err(FsError::from)?;

        Ok(Arc::new(Fat32InodeAdapter {
            inner: spin::Mutex::new(child),
        }))
    }

    fn unlink(&self, name: &str) -> FsResult<()> {
        let mut node = self.inner.lock();
        let mut dir = node.as_dir().map_err(FsError::from)?;
        dir.remove(name).map_err(FsError::from)
    }

    fn rmdir(&self, name: &str) -> FsResult<()> {
        let mut node = self.inner.lock();
        let mut dir = node.as_dir().map_err(FsError::from)?;
        dir.remove(name).map_err(FsError::from)
    }

    fn rename(&self, _old_name: &str, _new_dir: &Arc<dyn Inode>, _new_name: &str) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn link(&self, _name: &str, _inode: &Arc<dyn Inode>) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn symlink(&self, _name: &str, _target: &str) -> FsResult<Arc<dyn Inode>> {
        Err(FsError::NotSupported)
    }

    fn readlink(&self) -> FsResult<String> {
        Err(FsError::NotSupported)
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let node = self.inner.lock();
        let mut file = node.open(vfs::OpenFlags::empty()).map_err(FsError::from)?;
        file.seek(vfs::SeekFrom::Start(offset))
            .map_err(FsError::from)?;
        file.read(buf).map_err(FsError::from)
    }

    fn write(&self, offset: u64, buf: &[u8]) -> FsResult<usize> {
        let node = self.inner.lock();
        let mut file = node.open(vfs::OpenFlags::empty()).map_err(FsError::from)?;
        file.seek(vfs::SeekFrom::Start(offset))
            .map_err(FsError::from)?;
        file.write(buf).map_err(FsError::from)
    }

    fn truncate(&self, size: u64) -> FsResult<()> {
        let node = self.inner.lock();
        let mut file = node.open(vfs::OpenFlags::empty()).map_err(FsError::from)?;
        file.set_len(size).map_err(FsError::from)
    }

    fn fsync(&self, _datasync: bool) -> FsResult<()> {
        let node = self.inner.lock();
        let mut file = node.open(vfs::OpenFlags::empty()).map_err(FsError::from)?;
        file.flush().map_err(FsError::from)
    }
}
