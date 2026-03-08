// ============================================================================
// filesystems/nvme_ns/src/inode.rs - Runtime Inode
// ============================================================================
//!
//! NVMe Namespace FS のランタイム inode 表現。
//!
//! `DiskInode` をメモリ上にキャッシュし、VFS の `Inode` トレイトを実装する。
//! ファイルシステム (`NvmeNamespaceFs`) への参照を保持し、ブロック I/O を委譲する。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use exorust_sync::PoisonLock;
use vfs::{FileAttr, FileType, FsStats, OpenFlags, UnixFileMode, VfsError, VfsResult};

use crate::error::NsError;
use crate::ondisk::{DIRECT_BLOCKS, DiskInode, InodeKind};

// ============================================================================
// NsInode
// ============================================================================

/// NVMe Namespace FS ランタイム inode
///
/// ファイルシステム全体への弱参照を保持し、ブロック読み書きを委譲する。
/// `DiskInode` のキャッシュを `PoisonLock` で保護して並行アクセスに対応。
pub struct NsInode {
    /// inode 番号
    ino: u64,
    /// ファイルシステムへの参照（ブロック I/O 委譲先）
    fs: Arc<dyn NsInodeOps>,
    /// オンディスク inode のキャッシュ（PoisonLock で保護）
    disk: PoisonLock<DiskInode>,
}

/// ファイルシステムが inode に提供すべき操作
///
/// `NvmeNamespaceFs` がこのトレイトを実装し、`NsInode` がブロック I/O を
/// ファイルシステム経由で実行できるようにする。
pub trait NsInodeOps: Send + Sync {
    /// inode 番号から DiskInode を読み取る
    fn read_inode(&self, ino: u64) -> Result<DiskInode, NsError>;

    /// DiskInode をディスクに書き戻す
    fn write_inode(&self, ino: u64, disk: &DiskInode) -> Result<(), NsError>;

    /// データブロックを読む（LBA 指定）
    fn read_block(&self, lba: u64, buf: &mut [u8]) -> Result<(), NsError>;

    /// データブロックに書く（LBA 指定）
    fn write_block(&self, lba: u64, buf: &[u8]) -> Result<(), NsError>;

    /// データブロックを確保して LBA を返す
    fn alloc_block(&self) -> Result<u64, NsError>;

    /// データブロックを解放する
    fn free_block(&self, lba: u64) -> Result<(), NsError>;

    /// inode を確保して番号を返す
    fn alloc_inode(&self) -> Result<u64, NsError>;

    /// inode を解放する
    fn free_inode(&self, ino: u64) -> Result<(), NsError>;

    /// ブロックサイズ（バイト）
    fn block_size(&self) -> u64;

    /// FS 統計情報
    fn fs_stats(&self) -> Result<FsStats, NsError>;
}

impl NsInode {
    /// 新しいランタイム inode を生成
    pub fn new(ino: u64, disk: DiskInode, fs: Arc<dyn NsInodeOps>) -> Self {
        Self {
            ino,
            fs,
            disk: PoisonLock::new(disk),
        }
    }

    /// inode 番号を取得
    #[inline]
    pub fn ino(&self) -> u64 {
        self.ino
    }

    /// ファイルシステム参照を取得
    pub fn fs(&self) -> &Arc<dyn NsInodeOps> {
        &self.fs
    }

    // ========================================================================
    // ブロックマッピング
    // ========================================================================

    /// ファイル内ブロック番号 → 物理 LBA へ変換
    ///
    /// 12 本のダイレクトポインタ → 単間接 → 二重間接 → 三重間接 の順に解決。
    /// 未割り当てブロック (LBA == 0) の場合は `Ok(None)` を返す。
    pub fn resolve_block(&self, file_block: u64) -> Result<Option<u64>, NsError> {
        let disk = self.disk.lock().map_err(|_| NsError::IoError)?;
        self.resolve_block_inner(&disk, file_block)
    }

    fn resolve_block_inner(
        &self,
        disk: &DiskInode,
        file_block: u64,
    ) -> Result<Option<u64>, NsError> {
        let ptrs_per_block = self.fs.block_size() / 8; // u64 ポインタ数

        // ダイレクト
        if file_block < DIRECT_BLOCKS as u64 {
            let lba = disk.direct[file_block as usize];
            return Ok(if lba == 0 { None } else { Some(lba) });
        }
        let remaining = file_block - DIRECT_BLOCKS as u64;

        // 単間接
        if remaining < ptrs_per_block {
            return self.resolve_indirect(disk.indirect, remaining);
        }
        let remaining = remaining - ptrs_per_block;

        // 二重間接
        let double_cap = ptrs_per_block * ptrs_per_block;
        if remaining < double_cap {
            return self.resolve_double_indirect(disk.double_indirect, remaining, ptrs_per_block);
        }
        let remaining = remaining - double_cap;

        // 三重間接
        let triple_cap = ptrs_per_block * ptrs_per_block * ptrs_per_block;
        if remaining < triple_cap {
            return self.resolve_triple_indirect(disk.triple_indirect, remaining, ptrs_per_block);
        }

        Err(NsError::InvalidArgument)
    }

    fn resolve_indirect(&self, indirect_lba: u64, index: u64) -> Result<Option<u64>, NsError> {
        if indirect_lba == 0 {
            return Ok(None);
        }
        let lba = self.read_ptr_from_block(indirect_lba, index)?;
        Ok(if lba == 0 { None } else { Some(lba) })
    }

    fn resolve_double_indirect(
        &self,
        dbl_lba: u64,
        index: u64,
        ptrs_per_block: u64,
    ) -> Result<Option<u64>, NsError> {
        if dbl_lba == 0 {
            return Ok(None);
        }
        let l1_idx = index / ptrs_per_block;
        let l2_idx = index % ptrs_per_block;
        let l1_lba = self.read_ptr_from_block(dbl_lba, l1_idx)?;
        if l1_lba == 0 {
            return Ok(None);
        }
        let lba = self.read_ptr_from_block(l1_lba, l2_idx)?;
        Ok(if lba == 0 { None } else { Some(lba) })
    }

    fn resolve_triple_indirect(
        &self,
        tri_lba: u64,
        index: u64,
        ptrs_per_block: u64,
    ) -> Result<Option<u64>, NsError> {
        if tri_lba == 0 {
            return Ok(None);
        }
        let l1_idx = index / (ptrs_per_block * ptrs_per_block);
        let rem = index % (ptrs_per_block * ptrs_per_block);
        let l1_lba = self.read_ptr_from_block(tri_lba, l1_idx)?;
        if l1_lba == 0 {
            return Ok(None);
        }
        self.resolve_double_indirect(l1_lba, rem, ptrs_per_block)
    }

    /// 間接ブロックからポインタを 1 つ読む
    fn read_ptr_from_block(&self, block_lba: u64, index: u64) -> Result<u64, NsError> {
        let bs = self.fs.block_size() as usize;
        let mut buf = alloc::vec![0u8; bs];
        self.fs.read_block(block_lba, &mut buf)?;
        let offset = (index as usize) * 8;
        if offset + 8 > bs {
            return Err(NsError::InvalidArgument);
        }
        Ok(u64::from_le_bytes(
            buf[offset..offset + 8].try_into().unwrap(),
        ))
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /// DiskInode のクローンを取得
    pub fn disk_inode(&self) -> Result<DiskInode, NsError> {
        let guard = self.disk.lock().map_err(|_| NsError::IoError)?;
        Ok(*guard)
    }

    fn kind_to_file_type(kind: InodeKind) -> FileType {
        match kind {
            InodeKind::Regular => FileType::File,
            InodeKind::Directory => FileType::Directory,
            InodeKind::Symlink => FileType::Symlink,
            InodeKind::Free => FileType::File,
        }
    }
}

// ============================================================================
// VFS Inode トレイト実装
// ============================================================================

impl vfs::Inode for NsInode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn getattr(&self) -> VfsResult<FileAttr> {
        let disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
        Ok(FileAttr {
            ino: self.ino,
            size: disk.size,
            blocks: disk.blocks,
            file_type: Self::kind_to_file_type(disk.inode_kind()),
            mode: UnixFileMode::new(disk.mode),
            nlink: disk.nlink,
            uid: disk.uid,
            gid: disk.gid,
            rdev: 0,
            blksize: self.fs.block_size() as u32,
            atime: disk.atime,
            mtime: disk.mtime,
            ctime: disk.ctime,
        })
    }

    fn setattr(&self, attr: &FileAttr) -> VfsResult<()> {
        let mut disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
        disk.mode = attr.mode.bits();
        disk.uid = attr.uid;
        disk.gid = attr.gid;
        disk.atime = attr.atime;
        disk.mtime = attr.mtime;
        disk.ctime = attr.ctime;
        self.fs.write_inode(self.ino, &disk).map_err(VfsError::from)
    }

    fn lookup(&self, name: &str) -> VfsResult<Arc<dyn vfs::Inode>> {
        let disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
        if disk.inode_kind() != InodeKind::Directory {
            return Err(VfsError::NotADirectory);
        }
        drop(disk);

        // ディレクトリデータを走査して名前に一致するエントリを探す
        let entries = self.read_dir_entries()?;
        for entry in &entries {
            if entry.name == name {
                let child_disk = self.fs.read_inode(entry.ino).map_err(VfsError::from)?;
                return Ok(Arc::new(NsInode::new(
                    entry.ino,
                    child_disk,
                    self.fs.clone(),
                )));
            }
        }
        Err(VfsError::NotFound)
    }

    fn readdir(&self, _offset: u64) -> VfsResult<Vec<vfs::InodeDirEntry>> {
        let disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
        if disk.inode_kind() != InodeKind::Directory {
            return Err(VfsError::NotADirectory);
        }
        drop(disk);

        let entries = self.read_dir_entries()?;
        Ok(entries
            .into_iter()
            .map(|e| vfs::InodeDirEntry {
                name: e.name,
                ino: e.ino,
                file_type: e.file_type,
            })
            .collect())
    }

    fn create(
        &self,
        name: &str,
        mode: UnixFileMode,
        _flags: OpenFlags,
    ) -> VfsResult<Arc<dyn vfs::Inode>> {
        self.create_child(name, InodeKind::Regular, mode)
    }

    fn mkdir(&self, name: &str, mode: UnixFileMode) -> VfsResult<Arc<dyn vfs::Inode>> {
        self.create_child(name, InodeKind::Directory, mode)
    }

    fn unlink(&self, name: &str) -> VfsResult<()> {
        self.remove_child(name, false)
    }

    fn rmdir(&self, name: &str) -> VfsResult<()> {
        self.remove_child(name, true)
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
        if disk.inode_kind() == InodeKind::Directory {
            return Err(VfsError::IsADirectory);
        }
        let file_size = disk.size;
        drop(disk);

        if offset >= file_size {
            return Ok(0);
        }

        let bs = self.fs.block_size();
        let end = core::cmp::min(offset + buf.len() as u64, file_size);
        let mut total = 0usize;
        let mut pos = offset;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while pos < end {
            let file_block = pos / bs;
            let block_offset = (pos % bs) as usize;
            let chunk_len = core::cmp::min((bs as usize) - block_offset, (end - pos) as usize);

            match self.resolve_block(file_block)? {
                Some(lba) => {
                    let mut block_buf = alloc::vec![0u8; bs as usize];
                    self.fs
                        .read_block(lba, &mut block_buf)
                        .map_err(VfsError::from)?;
                    buf[total..total + chunk_len]
                        .copy_from_slice(&block_buf[block_offset..block_offset + chunk_len]);
                }
                None => {
                    // スパースファイル: ゼロで埋める
                    for b in &mut buf[total..total + chunk_len] {
                        *b = 0;
                    }
                }
            }
            pos += chunk_len as u64;
            total += chunk_len;
        }

        Ok(total)
    }

    fn write(&self, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let bs = self.fs.block_size();
        let end = offset + buf.len() as u64;
        let mut total = 0usize;
        let mut pos = offset;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while pos < end {
            let file_block = pos / bs;
            let block_offset = (pos % bs) as usize;
            let chunk_len = core::cmp::min((bs as usize) - block_offset, (end - pos) as usize);

            // ブロック確保（未割り当ての場合）
            let lba = match self.resolve_block(file_block)? {
                Some(lba) => lba,
                None => {
                    let new_lba = self.fs.alloc_block().map_err(VfsError::from)?;
                    self.assign_block(file_block, new_lba)?;
                    new_lba
                }
            };

            if chunk_len == bs as usize {
                // フルブロック書き込み
                self.fs
                    .write_block(lba, &buf[total..total + chunk_len])
                    .map_err(VfsError::from)?;
            } else {
                // パーシャル書き込み: RMW
                let mut block_buf = alloc::vec![0u8; bs as usize];
                self.fs
                    .read_block(lba, &mut block_buf)
                    .map_err(VfsError::from)?;
                block_buf[block_offset..block_offset + chunk_len]
                    .copy_from_slice(&buf[total..total + chunk_len]);
                self.fs
                    .write_block(lba, &block_buf)
                    .map_err(VfsError::from)?;
            }

            pos += chunk_len as u64;
            total += chunk_len;
        }

        // サイズ更新
        {
            let mut disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
            if end > disk.size {
                disk.size = end;
            }
            disk.blocks = (disk.size + bs - 1) / bs;
            self.fs
                .write_inode(self.ino, &disk)
                .map_err(VfsError::from)?;
        }

        Ok(total)
    }

    fn truncate(&self, size: u64) -> VfsResult<()> {
        let mut disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
        disk.size = size;
        disk.blocks = (size + self.fs.block_size() - 1) / self.fs.block_size();
        self.fs
            .write_inode(self.ino, &disk)
            .map_err(VfsError::from)?;
        Ok(())
    }

    fn fsync(&self, _datasync: bool) -> VfsResult<()> {
        let disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
        self.fs
            .write_inode(self.ino, &disk)
            .map_err(VfsError::from)?;
        Ok(())
    }
}

// ============================================================================
// ディレクトリ操作ヘルパー
// ============================================================================

/// 内部ディレクトリエントリ（名前解決用）
struct InternalDirEntry {
    name: String,
    ino: u64,
    file_type: FileType,
}

impl NsInode {
    /// ディレクトリの全エントリを読み取る
    fn read_dir_entries(&self) -> Result<Vec<InternalDirEntry>, NsError> {
        let disk = self.disk.lock().map_err(|_| NsError::IoError)?;
        let bs = self.fs.block_size();
        let dir_size = disk.size;
        drop(disk);

        let mut entries = Vec::new();
        let mut offset = 0u64;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while offset < dir_size {
            let file_block = offset / bs;
            let lba = match self.resolve_block(file_block)? {
                Some(lba) => lba,
                None => break,
            };

            let mut block_buf = alloc::vec![0u8; bs as usize];
            self.fs.read_block(lba, &mut block_buf)?;

            let block_offset_start = (offset % bs) as usize;
            let mut pos = block_offset_start;

            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while pos + crate::dir::DIR_ENTRY_HEADER_SIZE <= bs as usize {
                match crate::dir::DirEntry::from_bytes(&block_buf[pos..]) {
                    Some(entry) => {
                        if entry.ino != 0 {
                            entries.push(InternalDirEntry {
                                name: entry.name_str().into(),
                                ino: entry.ino,
                                file_type: crate::dir::kind_to_file_type(entry.kind),
                            });
                        }
                        if entry.entry_len == 0 {
                            break;
                        }
                        pos += entry.entry_len as usize;
                    }
                    None => break,
                }
            }

            offset = (file_block + 1) * bs;
        }

        Ok(entries)
    }

    /// 子エントリを作成する共通ヘルパー
    fn create_child(
        &self,
        name: &str,
        kind: InodeKind,
        mode: UnixFileMode,
    ) -> VfsResult<Arc<dyn vfs::Inode>> {
        {
            let disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
            if disk.inode_kind() != InodeKind::Directory {
                return Err(VfsError::NotADirectory);
            }
        }

        // 名前の重複チェック
        let entries = self.read_dir_entries().map_err(VfsError::from)?;
        for e in &entries {
            if e.name == name {
                return Err(VfsError::AlreadyExists);
            }
        }

        // inode 確保
        let child_ino = self.fs.alloc_inode().map_err(VfsError::from)?;
        let child_disk = DiskInode::new(kind, mode.bits());
        self.fs
            .write_inode(child_ino, &child_disk)
            .map_err(VfsError::from)?;

        // ディレクトリエントリ追加
        self.append_dir_entry(child_ino, name, kind)?;

        Ok(Arc::new(NsInode::new(
            child_ino,
            child_disk,
            self.fs.clone(),
        )))
    }

    /// 子エントリを削除する共通ヘルパー
    fn remove_child(&self, name: &str, expect_dir: bool) -> VfsResult<()> {
        {
            let disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
            if disk.inode_kind() != InodeKind::Directory {
                return Err(VfsError::NotADirectory);
            }
        }

        let entries = self.read_dir_entries().map_err(VfsError::from)?;
        let target = entries.iter().find(|e| e.name == name);
        let entry = target.ok_or(VfsError::NotFound)?;

        if expect_dir && entry.file_type != FileType::Directory {
            return Err(VfsError::NotADirectory);
        }
        if !expect_dir && entry.file_type == FileType::Directory {
            return Err(VfsError::IsADirectory);
        }

        let target_ino = entry.ino;

        // ディレクトリの場合、空かチェック
        if expect_dir {
            let child_disk = self.fs.read_inode(target_ino).map_err(VfsError::from)?;
            let child_inode = NsInode::new(target_ino, child_disk, self.fs.clone());
            let child_entries = child_inode.read_dir_entries().map_err(VfsError::from)?;
            // "." と ".." 以外のエントリがあれば空でない
            let real_entries: Vec<_> = child_entries
                .iter()
                .filter(|e| e.name != "." && e.name != "..")
                .collect();
            if !real_entries.is_empty() {
                return Err(VfsError::DirectoryNotEmpty);
            }
        }

        // ディレクトリエントリを削除（ino を 0 にマーク）
        self.remove_dir_entry(name)?;

        // inode 解放
        self.fs.free_inode(target_ino).map_err(VfsError::from)?;

        Ok(())
    }

    /// ディレクトリにエントリを追加
    fn append_dir_entry(&self, ino: u64, name: &str, kind: InodeKind) -> VfsResult<()> {
        let entry_bytes = crate::dir::DirEntry::to_bytes(ino, name, kind);
        let bs = self.fs.block_size();

        let mut disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
        let dir_size = disk.size;

        // 現在の最終ブロックに空きがあるか確認
        let last_file_block = if dir_size == 0 {
            0
        } else {
            (dir_size - 1) / bs
        };
        let offset_in_block = if dir_size == 0 {
            0usize
        } else {
            (dir_size % bs) as usize
        };

        let need_new_block = dir_size == 0 || offset_in_block + entry_bytes.len() > bs as usize;

        if need_new_block {
            // 新しいブロックを確保
            let new_lba = self.fs.alloc_block().map_err(VfsError::from)?;
            let new_file_block = if dir_size == 0 {
                0
            } else {
                last_file_block + 1
            };
            drop(disk);
            self.assign_block(new_file_block, new_lba)?;

            // エントリを書き込み
            let mut block_buf = alloc::vec![0u8; bs as usize];
            block_buf[..entry_bytes.len()].copy_from_slice(&entry_bytes);
            self.fs
                .write_block(new_lba, &block_buf)
                .map_err(VfsError::from)?;

            // サイズ更新
            let mut disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
            disk.size = new_file_block * bs + entry_bytes.len() as u64;
            disk.blocks = new_file_block + 1;
            self.fs
                .write_inode(self.ino, &disk)
                .map_err(VfsError::from)?;
        } else {
            // 既存ブロックに追記
            let lba = match self.resolve_block_inner(&disk, last_file_block)? {
                Some(lba) => lba,
                None => return Err(VfsError::IoError),
            };
            let mut block_buf = alloc::vec![0u8; bs as usize];
            self.fs
                .read_block(lba, &mut block_buf)
                .map_err(VfsError::from)?;
            block_buf[offset_in_block..offset_in_block + entry_bytes.len()]
                .copy_from_slice(&entry_bytes);
            self.fs
                .write_block(lba, &block_buf)
                .map_err(VfsError::from)?;

            disk.size += entry_bytes.len() as u64;
            self.fs
                .write_inode(self.ino, &disk)
                .map_err(VfsError::from)?;
        }

        Ok(())
    }

    /// ディレクトリからエントリを削除（ino を 0 にマーク）
    fn remove_dir_entry(&self, name: &str) -> VfsResult<()> {
        let disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
        let bs = self.fs.block_size();
        let dir_size = disk.size;
        drop(disk);

        let mut offset = 0u64;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while offset < dir_size {
            let file_block = offset / bs;
            let lba = match self.resolve_block(file_block)? {
                Some(lba) => lba,
                None => break,
            };

            let mut block_buf = alloc::vec![0u8; bs as usize];
            self.fs
                .read_block(lba, &mut block_buf)
                .map_err(VfsError::from)?;

            let mut pos = (offset % bs) as usize;
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while pos + crate::dir::DIR_ENTRY_HEADER_SIZE <= bs as usize {
                match crate::dir::DirEntry::from_bytes(&block_buf[pos..]) {
                    Some(entry) => {
                        if entry.name_str() == name && entry.ino != 0 {
                            // ino をゼロにして削除マーク
                            block_buf[pos..pos + 8].copy_from_slice(&0u64.to_le_bytes());
                            self.fs
                                .write_block(lba, &block_buf)
                                .map_err(VfsError::from)?;
                            return Ok(());
                        }
                        if entry.entry_len == 0 {
                            break;
                        }
                        pos += entry.entry_len as usize;
                    }
                    None => break,
                }
            }
            offset = (file_block + 1) * bs;
        }

        Err(VfsError::NotFound)
    }

    /// ファイルブロック番号に LBA を割り当てる（ダイレクトポインタのみ実装）
    fn assign_block(&self, file_block: u64, lba: u64) -> VfsResult<()> {
        if file_block < DIRECT_BLOCKS as u64 {
            let mut disk = self.disk.lock().map_err(|_| VfsError::IoError)?;
            disk.direct[file_block as usize] = lba;
            self.fs
                .write_inode(self.ino, &disk)
                .map_err(VfsError::from)?;
            return Ok(());
        }
        // 間接ブロックの割り当ては将来拡張
        // TODO: 間接/二重間接/三重間接ブロックの割り当て実装
        Err(VfsError::NotSupported)
    }
}
