// ============================================================================
// src/fs/nvme_ns_adapter.rs - Adapter for NVMe Namespace FS Crate
// ============================================================================
//!
//! # NVMe Namespace FS Adapter
//!
//! `filesystems/nvme_ns` クレートの `ExtendedFileSystem` + `NsInodeOps` を
//! カーネルの `fs_abstraction` トレイトに適合させるためのアダプタ。
//!
//! FAT32 アダプタ (`fat32_adapter.rs`) と同じパターンに従う。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::fs_abstraction::{
    DirEntry, FileAttr, FileMode, FileSystem, FileType, FsError, FsResult, FsStats, Inode,
    OpenFlags,
};
use crate::sync::PoisonLock;

use nvme_ns::NvmeNamespaceFs;
use vfs::{ExtendedFileSystem, FileType as VfsFileType, Inode as VfsInode};

// ============================================================================
// Type Conversion
// ============================================================================

fn convert_vfs_file_type(ft: VfsFileType) -> FileType {
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

fn convert_vfs_attr(attr: vfs::FileAttr) -> FileAttr {
    FileAttr {
        ino: attr.ino,
        size: attr.size,
        blocks: attr.blocks,
        file_type: convert_vfs_file_type(attr.file_type),
        mode: FileMode(attr.mode.bits()),
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev,
        blksize: attr.blksize,
        atime: attr.atime,
        mtime: attr.mtime,
        ctime: attr.ctime,
    }
}

fn convert_to_vfs_mode(mode: FileMode) -> vfs::UnixFileMode {
    vfs::UnixFileMode::new(mode.0)
}

fn convert_to_vfs_open_flags(_flags: OpenFlags) -> vfs::OpenFlags {
    vfs::OpenFlags::empty()
}

// ============================================================================
// FileSystem Adapter
// ============================================================================

/// NVMe Namespace FS → fs_abstraction::FileSystem アダプタ
pub struct NvmeNsFileSystemAdapter {
    inner: Arc<NvmeNamespaceFs>,
}

impl NvmeNsFileSystemAdapter {
    /// 新しいアダプタを作成
    pub fn new(inner: Arc<NvmeNamespaceFs>) -> Self {
        Self { inner }
    }
}

impl FileSystem for NvmeNsFileSystemAdapter {
    fn name(&self) -> &str {
        "nvme_ns"
    }

    fn root(&self) -> FsResult<Arc<dyn Inode>> {
        let root_inode = self.inner.root().map_err(FsError::from)?;
        Ok(Arc::new(NvmeNsInodeAdapter {
            inner: PoisonLock::new(root_inode),
        }))
    }

    fn statfs(&self) -> FsResult<FsStats> {
        let stats = self.inner.statfs().map_err(FsError::from)?;
        Ok(FsStats {
            blocks: stats.blocks,
            bfree: stats.bfree,
            bavail: stats.bavail,
            files: stats.files,
            ffree: stats.ffree,
            bsize: stats.bsize,
            namelen: stats.namelen,
            frsize: stats.frsize,
        })
    }

    fn sync(&self) -> FsResult<()> {
        self.inner.sync().map_err(FsError::from)
    }

    fn unmount(&self) -> FsResult<()> {
        self.inner.unmount().map_err(FsError::from)
    }
}

// ============================================================================
// Inode Adapter
// ============================================================================

/// VFS Inode → fs_abstraction::Inode アダプタ
pub struct NvmeNsInodeAdapter {
    inner: PoisonLock<Arc<dyn VfsInode>>,
}

impl Inode for NvmeNsInodeAdapter {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn getattr(&self) -> FsResult<FileAttr> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        let attr = inode.getattr().map_err(FsError::from)?;
        Ok(convert_vfs_attr(attr))
    }

    fn setattr(&self, attr: &FileAttr) -> FsResult<()> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        let vfs_attr = vfs::FileAttr {
            ino: attr.ino,
            size: attr.size,
            blocks: attr.blocks,
            file_type: VfsFileType::File, // 簡易変換
            mode: convert_to_vfs_mode(attr.mode),
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
            rdev: attr.rdev,
            blksize: attr.blksize,
            atime: attr.atime,
            mtime: attr.mtime,
            ctime: attr.ctime,
        };
        inode.setattr(&vfs_attr).map_err(FsError::from)
    }

    fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        let child = inode.lookup(name).map_err(FsError::from)?;
        Ok(Arc::new(NvmeNsInodeAdapter {
            inner: PoisonLock::new(child),
        }))
    }

    fn readdir(&self, offset: u64) -> FsResult<Vec<DirEntry>> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        let entries = inode.readdir(offset).map_err(FsError::from)?;
        Ok(entries
            .into_iter()
            .map(|e| DirEntry {
                name: e.name,
                ino: e.ino,
                file_type: convert_vfs_file_type(e.file_type),
            })
            .collect())
    }

    fn create(&self, name: &str, mode: FileMode, flags: OpenFlags) -> FsResult<Arc<dyn Inode>> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        let child = inode
            .create(
                name,
                convert_to_vfs_mode(mode),
                convert_to_vfs_open_flags(flags),
            )
            .map_err(FsError::from)?;
        Ok(Arc::new(NvmeNsInodeAdapter {
            inner: PoisonLock::new(child),
        }))
    }

    fn mkdir(&self, name: &str, mode: FileMode) -> FsResult<Arc<dyn Inode>> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        let child = inode
            .mkdir(name, convert_to_vfs_mode(mode))
            .map_err(FsError::from)?;
        Ok(Arc::new(NvmeNsInodeAdapter {
            inner: PoisonLock::new(child),
        }))
    }

    fn unlink(&self, name: &str) -> FsResult<()> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        inode.unlink(name).map_err(FsError::from)
    }

    fn rmdir(&self, name: &str) -> FsResult<()> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        inode.rmdir(name).map_err(FsError::from)
    }

    fn rename(&self, old_name: &str, new_dir: &Arc<dyn Inode>, new_name: &str) -> FsResult<()> {
        let _inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        // NvmeNsInodeAdapter → VFS Inode への変換が必要だが、
        // 現時点ではダウンキャスト不可のため NotSupported を返す
        let _ = (old_name, new_dir, new_name);
        Err(FsError::NotSupported)
    }

    fn link(&self, _name: &str, _inode: &Arc<dyn Inode>) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn symlink(&self, _name: &str, _target: &str) -> FsResult<Arc<dyn Inode>> {
        Err(FsError::NotSupported)
    }

    fn readlink(&self) -> FsResult<String> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        inode.readlink().map_err(FsError::from)
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        inode.read(offset, buf).map_err(FsError::from)
    }

    fn write(&self, offset: u64, buf: &[u8]) -> FsResult<usize> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        inode.write(offset, buf).map_err(FsError::from)
    }

    fn truncate(&self, size: u64) -> FsResult<()> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        inode.truncate(size).map_err(FsError::from)
    }

    fn fsync(&self, datasync: bool) -> FsResult<()> {
        let inode = self.inner.lock().map_err(|_| FsError::IoError)?;
        inode.fsync(datasync).map_err(FsError::from)
    }
}
