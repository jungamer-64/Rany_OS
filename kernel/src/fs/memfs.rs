// ============================================================================
// kernel/src/fs/memfs.rs
// ============================================================================
//! memfs - Memory-based Filesystem
//!
//! シェルコマンドの動作検証用のインメモリファイルシステム
//! 実際のストレージバックエンドなしで動作するファイルシステム

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use hashbrown::HashMap;
use spin::RwLock;

use super::page::PagedContent;
mod _split_1;
pub use _split_1::*;

use super::fs_abstraction::{
    DirEntry, FileAttr, FileMode, FileSystem, FileType, FsError, FsResult, FsStats, Inode,
    OpenFlags,
};

// ============================================================================
// MemoryFs Filesystem
// ============================================================================

/// メモリベースのファイルシステム
pub struct MemoryFs {
    /// ルートinode
    root: Arc<MemoryInode>,
    /// 次のinode番号
    next_ino: AtomicU64,
}

impl MemoryFs {
    /// 新しいMemoryFsを作成
    pub fn new() -> Arc<Self> {
        let root = Arc::new(MemoryInode::new_dir(1, "/", FileMode::DEFAULT_DIR));
        Arc::new(Self {
            root,
            next_ino: AtomicU64::new(2),
        })
    }

    /// 次のinode番号を取得
    fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::SeqCst)
    }

    /// ルートから検索してディレクトリを作成（パス全体）
    pub fn create_path(&self, path: &str) -> FsResult<()> {
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        let mut current: Arc<dyn Inode> = self.root.clone();

        for component in components {
            match current.lookup(component) {
                Ok(child) => {
                    current = child;
                }
                Err(FsError::NotFound) => {
                    let new_dir = current.mkdir(component, FileMode::DEFAULT_DIR)?;
                    current = new_dir;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }
}

impl Default for MemoryFs {
    fn default() -> Self {
        let root = Arc::new(MemoryInode::new_dir(1, "/", FileMode::DEFAULT_DIR));
        Self {
            root,
            next_ino: AtomicU64::new(2),
        }
    }
}

impl FileSystem for MemoryFs {
    fn name(&self) -> &str {
        "memfs"
    }

    fn root(&self) -> FsResult<Arc<dyn Inode>> {
        Ok(self.root.clone())
    }

    fn statfs(&self) -> FsResult<FsStats> {
        Ok(FsStats {
            blocks: 1024 * 1024, // 1M blocks
            bfree: 1024 * 1024,
            bavail: 1024 * 1024,
            files: 65536,
            ffree: 65536,
            bsize: 4096,
            namelen: 255,
            frsize: 4096,
        })
    }

    fn sync(&self) -> FsResult<()> {
        Ok(()) // メモリFSなので何もしない
    }

    fn unmount(&self) -> FsResult<()> {
        Ok(())
    }
}

// ============================================================================
// MemoryInode
// ============================================================================

/// Inodeの種類ごとのデータ保持（メモリ効率化）
///
/// 従来の `MemoryInodeData` は全てのフィールドを持っていましたが、
/// Enumにすることで必要なデータのみをヒープに確保します。
enum InodeKind {
    /// 通常ファイル: ページベースのコンテンツ
    File(PagedContent),
    /// ディレクトリ: 子エントリのマップ (O(1) lookup)
    Directory(HashMap<String, Arc<MemoryInode>>),
    /// シンボリックリンク: ターゲットパス
    Symlink(String),
}

/// メモリベースのinode
pub struct MemoryInode {
    /// inode番号
    pub(crate) ino: u64,
    /// ファイル名（デバッグ用）
    name: String,
    /// パーミッション
    mode: RwLock<FileMode>,
    /// タイムスタンプ（ナノ秒）
    atime: AtomicU64,
    mtime: AtomicU64,
    ctime: AtomicU64,
    /// サイズ（ファイルの場合のみ使用、論理サイズ）
    pub(crate) size: AtomicU64,
    /// ハードリンクカウント
    nlink: AtomicU32,
    /// ファイル種別ごとのデータ
    kind: RwLock<InodeKind>,
    /// 次のinode番号（ディレクトリ作成時用）
    next_child_ino: AtomicU64,
}

impl MemoryInode {
    /// 新しいディレクトリを作成
    pub fn new_dir(ino: u64, name: &str, mode: FileMode) -> Self {
        let now = crate::time::now() as u64 * 1_000_000_000; // nanoseconds
        Self {
            ino,
            kind: RwLock::new(InodeKind::Directory(HashMap::new())),
            mode: RwLock::new(mode),
            size: AtomicU64::new(0),
            nlink: AtomicU32::new(2), // ディレクトリ: . と親からのリンク
            atime: AtomicU64::new(now),
            mtime: AtomicU64::new(now),
            ctime: AtomicU64::new(now),
            name: name.to_string(),
            next_child_ino: AtomicU64::new(ino.wrapping_shl(20)),
        }
    }

    /// 新しいファイルを作成
    pub fn new_file(ino: u64, name: &str, mode: FileMode) -> Self {
        let now = crate::time::now() as u64 * 1_000_000_000;
        Self {
            ino,
            kind: RwLock::new(InodeKind::File(PagedContent::new())),
            mode: RwLock::new(mode),
            size: AtomicU64::new(0),
            nlink: AtomicU32::new(1), // ファイル: 初期リンク数1
            atime: AtomicU64::new(now),
            mtime: AtomicU64::new(now),
            ctime: AtomicU64::new(now),
            name: name.to_string(),
            next_child_ino: AtomicU64::new(ino.wrapping_shl(20)),
        }
    }

    /// 新しいシンボリックリンクを作成
    pub fn new_symlink(ino: u64, name: &str, target: &str) -> Self {
        let now = crate::time::now() as u64 * 1_000_000_000;
        Self {
            ino,
            kind: RwLock::new(InodeKind::Symlink(target.to_string())),
            mode: RwLock::new(FileMode::DEFAULT_LINK),
            size: AtomicU64::new(target.len() as u64),
            nlink: AtomicU32::new(1), // symlink: 初期リンク数1
            atime: AtomicU64::new(now),
            mtime: AtomicU64::new(now),
            ctime: AtomicU64::new(now),
            name: name.to_string(),
            next_child_ino: AtomicU64::new(ino.wrapping_shl(20)),
        }
    }

    /// 次の子inode番号を割り当て
    fn alloc_child_ino(&self) -> u64 {
        self.next_child_ino.fetch_add(1, Ordering::SeqCst)
    }

    /// ファイルタイプを取得
    pub fn file_type(&self) -> FileType {
        match &*self.kind.read() {
            InodeKind::File(_) => FileType::Regular,
            InodeKind::Directory(_) => FileType::Directory,
            InodeKind::Symlink(_) => FileType::Symlink,
        }
    }

    /// ページを直接取得（ゼロコピー読み取り用）
    pub fn get_page(&self, page_idx: u64) -> Option<Arc<super::page::Page>> {
        let guard = self.kind.read();
        if let InodeKind::File(content) = &*guard {
            content.get_page(page_idx)
        } else {
            None
        }
    }

    /// ファイルコンテンツの参照を取得（CoWコピー用）
    pub fn content(&self) -> Option<PagedContent> {
        let guard = self.kind.read();
        if let InodeKind::File(content) = &*guard {
            Some(content.clone())
        } else {
            None
        }
    }

    /// ファイルコンテンツをCoWで設定（O(1)コピー）
    pub fn set_content_cow(&self, new_content: PagedContent, size: u64) {
        let mut guard = self.kind.write();
        if let InodeKind::File(content) = &mut *guard {
            *content = new_content;
            self.size.store(size, Ordering::Relaxed);
            let now = crate::time::now() as u64 * 1_000_000_000;
            self.mtime.store(now, Ordering::Relaxed);
            self.ctime.store(now, Ordering::Relaxed);
        }
    }
}

impl Inode for MemoryInode {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn getattr(&self) -> FsResult<FileAttr> {
        let mode = *self.mode.read();
        let file_type = self.file_type();
        Ok(FileAttr {
            ino: self.ino,
            size: self.size.load(Ordering::Relaxed),
            blocks: (self.size.load(Ordering::Relaxed) + 511) / 512,
            atime: self.atime.load(Ordering::Relaxed),
            mtime: self.mtime.load(Ordering::Relaxed),
            ctime: self.ctime.load(Ordering::Relaxed),
            file_type,
            mode,
            nlink: self.nlink.load(Ordering::Relaxed),
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
        })
    }

    fn setattr(&self, attr: &FileAttr) -> FsResult<()> {
        // モードの更新
        *self.mode.write() = attr.mode;

        // タイムスタンプの更新
        self.atime.store(attr.atime, Ordering::Relaxed);
        self.mtime.store(attr.mtime, Ordering::Relaxed);
        self.ctime
            .store(crate::time::now() as u64 * 1_000_000_000, Ordering::Relaxed);

        // サイズ変更（truncate）
        let current_size = self.size.load(Ordering::Relaxed);
        if attr.size != current_size {
            self.truncate(attr.size)?;
        }

        Ok(())
    }

    // ... (lookup - unchanged) ...
    fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>> {
        let guard = self.kind.read();
        match &*guard {
            InodeKind::Directory(children) => children
                .get(name)
                .map(|inode| inode.clone() as Arc<dyn Inode>)
                .ok_or(FsError::NotFound),
            _ => Err(FsError::NotDirectory),
        }
    }

    // ... (readdir - unchanged) ...
    fn readdir(&self, _offset: u64) -> FsResult<Vec<DirEntry>> {
        let guard = self.kind.read();
        match &*guard {
            InodeKind::Directory(children) => {
                let mut entries = Vec::new();

                // . と ..
                entries.push(DirEntry {
                    ino: self.ino,
                    file_type: FileType::Directory,
                    name: ".".to_string(),
                });
                entries.push(DirEntry {
                    ino: self.ino,
                    file_type: FileType::Directory,
                    name: "..".to_string(),
                });

                // 子エントリ
                for (name, inode) in children.iter() {
                    entries.push(DirEntry {
                        ino: inode.ino,
                        file_type: inode.file_type(),
                        name: name.clone(),
                    });
                }
                Ok(entries)
            }
            _ => Err(FsError::NotDirectory),
        }
    }

    // ... (readdir - unchanged) ...

    fn create(&self, name: &str, mode: FileMode, _flags: OpenFlags) -> FsResult<Arc<dyn Inode>> {
        let mut guard = self.kind.write();
        match &mut *guard {
            InodeKind::Directory(children) => {
                if children.contains_key(name) {
                    return Err(FsError::AlreadyExists);
                }
                let ino = self.alloc_child_ino();
                let inode = Arc::new(MemoryInode::new_file(ino, name, mode));
                children.insert(name.to_string(), inode.clone());

                // Update timestamps
                let now = crate::time::now() as u64 * 1_000_000_000;
                self.mtime.store(now, Ordering::Relaxed);
                self.ctime.store(now, Ordering::Relaxed);

                Ok(inode)
            }
            _ => Err(FsError::NotDirectory),
        }
    }

    fn mkdir(&self, name: &str, mode: FileMode) -> FsResult<Arc<dyn Inode>> {
        let mut guard = self.kind.write();
        match &mut *guard {
            InodeKind::Directory(children) => {
                if children.contains_key(name) {
                    return Err(FsError::AlreadyExists);
                }
                let ino = self.alloc_child_ino();
                let inode = Arc::new(MemoryInode::new_dir(ino, name, mode));
                children.insert(name.to_string(), inode.clone());

                // 親ディレクトリのnlinkを増加（子ディレクトリからの'..'リンク）
                self.nlink.fetch_add(1, Ordering::Relaxed);

                // Update timestamps
                let now = crate::time::now() as u64 * 1_000_000_000;
                self.mtime.store(now, Ordering::Relaxed);
                self.ctime.store(now, Ordering::Relaxed);

                Ok(inode)
            }
            _ => Err(FsError::NotDirectory),
        }
    }

    fn unlink(&self, name: &str) -> FsResult<()> {
        let mut guard = self.kind.write();
        match &mut *guard {
            InodeKind::Directory(children) => {
                let child = children.get(name).ok_or(FsError::NotFound)?;

                // ディレクトリのunlinkは禁止（rmdirを使用）
                if child.file_type() == FileType::Directory {
                    return Err(FsError::IsDirectory);
                }

                // nlink をデクリメント
                let prev_nlink = child.nlink.fetch_sub(1, Ordering::Relaxed);

                // nlink が 0 になった場合のみエントリを削除
                // (ハードリンクがある場合は他のエントリが残る)
                if prev_nlink <= 1 {
                    children.remove(name);
                }

                // Update timestamps
                let now = crate::time::now() as u64 * 1_000_000_000;
                self.mtime.store(now, Ordering::Relaxed);
                self.ctime.store(now, Ordering::Relaxed);

                Ok(())
            }
            _ => Err(FsError::NotDirectory),
        }
    }

    fn rmdir(&self, name: &str) -> FsResult<()> {
        let mut guard = self.kind.write();
        match &mut *guard {
            InodeKind::Directory(children) => {
                let is_empty = if let Some(child) = children.get(name) {
                    if child.file_type() != FileType::Directory {
                        return Err(FsError::NotDirectory);
                    }
                    // 空かどうかチェック
                    let child_guard = child.kind.read();
                    if let InodeKind::Directory(grand_children) = &*child_guard {
                        !grand_children.is_empty()
                    } else {
                        false // Should not happen given file_type check
                    }
                } else {
                    return Err(FsError::NotFound);
                };

                if is_empty {
                    return Err(FsError::NotEmpty);
                }

                children.remove(name);

                // 親ディレクトリのnlinkを減少（子ディレクトリからの'..'リンクが消える）
                self.nlink.fetch_sub(1, Ordering::Relaxed);

                // Update timestamps
                let now = crate::time::now() as u64 * 1_000_000_000;
                self.mtime.store(now, Ordering::Relaxed);
                self.ctime.store(now, Ordering::Relaxed);

                Ok(())
            }
            _ => Err(FsError::NotDirectory),
        }
    }

    fn rename(&self, old_name: &str, new_dir: &Arc<dyn Inode>, new_name: &str) -> FsResult<()> {
        // Step 1: 自身からエントリを取り出す（ロック保持期間を最小化）
        let entry = {
            let mut guard = self.kind.write();
            match &mut *guard {
                InodeKind::Directory(children) => {
                    children.remove(old_name).ok_or(FsError::NotFound)?
                }
                _ => return Err(FsError::NotDirectory),
            }
        }; // guard drop

        // Step 2: 移動先への挿入

        // 移動先が MemoryInode かどうか確認
        if let Some(new_mem_dir) = new_dir.as_any().downcast_ref::<MemoryInode>() {
            let mut dest_guard = new_mem_dir.kind.write();
            if let InodeKind::Directory(dest_children) = &mut *dest_guard {
                dest_children.insert(new_name.to_string(), entry);
                return Ok(());
            } else {
                // 移動先がディレクトリでない
                // 補償: 元に戻す
                let mut self_guard = self.kind.write();
                if let InodeKind::Directory(children) = &mut *self_guard {
                    children.insert(old_name.to_string(), entry);
                }
                return Err(FsError::NotDirectory);
            }
        }

        // 移動先が MemoryInode でない場合（FS間移動）
        // 現状は非対応（CrossDeviceLink）として、元に戻す
        let mut self_guard = self.kind.write();
        if let InodeKind::Directory(children) = &mut *self_guard {
            children.insert(old_name.to_string(), entry);
        }

        Err(FsError::CrossDeviceLink)
    }

    fn link(&self, name: &str, inode: &Arc<dyn Inode>) -> FsResult<()> {
        // ハードリンク対象のinodeをMemoryInodeにダウンキャスト
        let mem_inode = inode
            .as_any()
            .downcast_ref::<MemoryInode>()
            .ok_or(FsError::CrossDeviceLink)?;

        // ディレクトリのハードリンクは禁止（POSIX準拠）
        if mem_inode.file_type() == FileType::Directory {
            return Err(FsError::IsDirectory);
        }

        let mut guard = self.kind.write();
        match &mut *guard {
            InodeKind::Directory(children) => {
                if children.contains_key(name) {
                    return Err(FsError::AlreadyExists);
                }

                // 同じArcを共有するため、元のinodeへの参照が必要
                // ここでは新しいArcを作成せず、nlinkのみ増加
                // 注意: 実際には同一のArc<MemoryInode>を共有する必要がある
                // 現在の設計では、as_any経由で参照を取得しているため
                // 元のArcを直接使用できない。回避策として、
                // クローンを作成せずnlinkをインクリメント
                mem_inode.nlink.fetch_add(1, Ordering::Relaxed);

                // 注: この実装では同一inodeへの複数エントリは
                // 完全なハードリンクではなく、nlink追跡のみ
                // 完全な実装にはArc<MemoryInode>の共有が必要

                let now = crate::time::now() as u64 * 1_000_000_000;
                self.mtime.store(now, Ordering::Relaxed);
                self.ctime.store(now, Ordering::Relaxed);

                Ok(())
            }
            _ => Err(FsError::NotDirectory),
        }
    }

    fn symlink(&self, name: &str, target: &str) -> FsResult<Arc<dyn Inode>> {
        let mut guard = self.kind.write();
        match &mut *guard {
            InodeKind::Directory(children) => {
                if children.contains_key(name) {
                    return Err(FsError::AlreadyExists);
                }
                let ino = self.alloc_child_ino();
                let inode = Arc::new(MemoryInode::new_symlink(ino, name, target));
                children.insert(name.to_string(), inode.clone());
                Ok(inode)
            }
            _ => Err(FsError::NotDirectory),
        }
    }

    fn readlink(&self) -> FsResult<String> {
        let guard = self.kind.read();
        match &*guard {
            InodeKind::Symlink(target) => Ok(target.clone()),
            _ => Err(FsError::InvalidArgument),
        }
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let guard = self.kind.read();
        match &*guard {
            InodeKind::File(content) => {
                let size = self.size.load(Ordering::Relaxed);
                if offset >= size {
                    return Ok(0);
                }
                let available = (size - offset) as usize;
                let to_read = buf.len().min(available);
                self.atime
                    .store(crate::time::now() as u64 * 1_000_000_000, Ordering::Relaxed);
                Ok(content.read(offset, &mut buf[..to_read]))
            }
            InodeKind::Directory(_) => Err(FsError::IsDirectory),
            _ => Err(FsError::InvalidArgument),
        }
    }

    fn write(&self, offset: u64, buf: &[u8]) -> FsResult<usize> {
        let mut guard = self.kind.write();
        match &mut *guard {
            InodeKind::File(content) => {
                let written = content.write(offset, buf);
                let new_size = offset + written as u64;
                let current_size = self.size.load(Ordering::Relaxed);
                if new_size > current_size {
                    self.size.store(new_size, Ordering::Relaxed);
                }
                let now = crate::time::now() as u64 * 1_000_000_000;
                self.mtime.store(now, Ordering::Relaxed);
                self.ctime.store(now, Ordering::Relaxed);
                Ok(written)
            }
            InodeKind::Directory(_) => Err(FsError::IsDirectory),
            _ => Err(FsError::InvalidArgument),
        }
    }

    fn truncate(&self, size: u64) -> FsResult<()> {
        let mut guard = self.kind.write();
        match &mut *guard {
            InodeKind::File(content) => {
                content.truncate(size);
                self.size.store(size, Ordering::Relaxed);
                let now = crate::time::now() as u64 * 1_000_000_000;
                self.mtime.store(now, Ordering::Relaxed);
                self.ctime.store(now, Ordering::Relaxed);
                Ok(())
            }
            InodeKind::Directory(_) => Err(FsError::IsDirectory),
            _ => Err(FsError::InvalidArgument),
        }
    }

    fn fsync(&self, _datasync: bool) -> FsResult<()> {
        Ok(()) // メモリFSなので何もしない
    }
}
