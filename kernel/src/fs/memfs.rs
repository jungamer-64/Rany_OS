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

// ============================================================================
// Shell Integration API
// ============================================================================

use spin::Once;

/// グローバルMemoryFsインスタンス
static SHELL_FS: Once<Arc<MemoryFs>> = Once::new();

/// シェル用ファイルシステムを初期化
pub fn init_shell_fs() {
    SHELL_FS.call_once(|| {
        let fs = MemoryFs::new();

        // 基本ディレクトリ構造を作成
        if let Ok(root) = fs.root() {
            let _ = root.mkdir("bin", FileMode::DEFAULT_DIR);
            let _ = root.mkdir("dev", FileMode::DEFAULT_DIR);
            let _ = root.mkdir("etc", FileMode::DEFAULT_DIR);
            let _ = root.mkdir("home", FileMode::DEFAULT_DIR);
            let _ = root.mkdir("proc", FileMode::DEFAULT_DIR);
            let _ = root.mkdir("tmp", FileMode::DEFAULT_DIR);
            let _ = root.mkdir("var", FileMode::DEFAULT_DIR);
            let _ = root.mkdir("drivers", FileMode::DEFAULT_DIR); // For dynamic driver loading

            // /etc/hostname を作成
            if let Ok(etc) = root.lookup("etc") {
                if let Ok(hostname_file) =
                    etc.create("hostname", FileMode::DEFAULT_FILE, OpenFlags::default())
                {
                    let _ = hostname_file.write(0, b"ranyos\n");
                }
                // /etc/version を作成
                if let Ok(version_file) =
                    etc.create("version", FileMode::DEFAULT_FILE, OpenFlags::default())
                {
                    let _ = version_file.write(0, b"ExoRust/RanyOS v0.3.0-alpha\n");
                }
            }

            // /home/user を作成
            if let Ok(home) = root.lookup("home") {
                let _ = home.mkdir("user", FileMode::DEFAULT_DIR);
            }
        }

        fs
    });
}

/// シェル用ファイルシステムを取得
pub fn shell_fs() -> Option<&'static Arc<MemoryFs>> {
    SHELL_FS.get()
}

/// パスを解決してinodeを取得
pub fn resolve_path(path: &str, cwd: &str) -> FsResult<Arc<dyn Inode>> {
    let fs = shell_fs().ok_or(FsError::IoError)?;
    let root = fs.root()?;

    // 絶対パスを構築
    let abs_path = if path.starts_with('/') {
        path.to_string()
    } else if path == "." {
        cwd.to_string()
    } else if path == ".." {
        let parts: Vec<&str> = cwd.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            "/".to_string()
        } else {
            let parent: Vec<&str> = parts[..parts.len().saturating_sub(1)].to_vec();
            if parent.is_empty() {
                "/".to_string()
            } else {
                alloc::format!("/{}", parent.join("/"))
            }
        }
    } else {
        if cwd == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}/{}", cwd, path)
        }
    };

    // パスをコンポーネントに分解して辿る
    let components: Vec<&str> = abs_path.split('/').filter(|s| !s.is_empty()).collect();

    if components.is_empty() {
        return Ok(root);
    }

    let mut current: Arc<dyn Inode> = root;

    for component in components {
        if component == "." {
            continue;
        }
        if component == ".." {
            // 親ディレクトリは今のところ無視（ルートに留まる）
            continue;
        }
        current = current.lookup(component)?;
    }

    Ok(current)
}

/// ディレクトリの内容を一覧表示
pub fn list_directory(path: &str, cwd: &str) -> FsResult<Vec<DirEntry>> {
    let inode = resolve_path(path, cwd)?;
    inode.readdir(0)
}

/// ファイルの内容を読み取り
pub fn read_file_content(path: &str, cwd: &str) -> FsResult<Vec<u8>> {
    let inode = resolve_path(path, cwd)?;
    let attr = inode.getattr()?;

    if attr.file_type == FileType::Directory {
        return Err(FsError::IsDirectory);
    }

    let mut buf = alloc::vec![0u8; attr.size as usize];
    let _ = inode.read(0, &mut buf)?;
    Ok(buf)
}

/// ディレクトリを作成
pub fn make_directory(path: &str, cwd: &str) -> FsResult<()> {
    let (parent_path, name) = split_path(path, cwd);
    let parent = resolve_path(&parent_path, cwd)?;
    parent.mkdir(&name, FileMode::DEFAULT_DIR)?;
    Ok(())
}

/// ファイルを作成/更新
pub fn touch_file(path: &str, cwd: &str) -> FsResult<()> {
    let (parent_path, name) = split_path(path, cwd);
    let parent = resolve_path(&parent_path, cwd)?;

    // 既存ファイルがあれば何もしない、なければ作成
    match parent.lookup(&name) {
        Ok(_) => Ok(()),
        Err(FsError::NotFound) => {
            parent.create(&name, FileMode::DEFAULT_FILE, OpenFlags::default())?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// ファイルを削除
pub fn remove_file(path: &str, cwd: &str) -> FsResult<()> {
    let (parent_path, name) = split_path(path, cwd);
    let parent = resolve_path(&parent_path, cwd)?;
    parent.unlink(&name)
}

/// ディレクトリを削除
pub fn remove_directory(path: &str, cwd: &str) -> FsResult<()> {
    let (parent_path, name) = split_path(path, cwd);
    let parent = resolve_path(&parent_path, cwd)?;
    parent.rmdir(&name)
}

/// ファイル/ディレクトリを移動
pub fn move_file(src: &str, dst: &str, cwd: &str) -> FsResult<()> {
    let (src_parent_path, src_name) = split_path(src, cwd);
    let (dst_parent_path, dst_name) = split_path(dst, cwd);

    let src_parent = resolve_path(&src_parent_path, cwd)?;
    let dst_parent = resolve_path(&dst_parent_path, cwd)?;

    src_parent.rename(&src_name, &dst_parent, &dst_name)
}

/// ファイルをコピー（従来方式 - PagedContentで高速化済み）
///
/// 注: memfs内でのCoW直接コピーには `copy_file_cow` を使用してください。
pub fn copy_file(src: &str, dst: &str, cwd: &str) -> FsResult<()> {
    // ソースを読み取り
    let content = read_file_content(src, cwd)?;

    // 宛先に書き込み
    let (dst_parent_path, dst_name) = split_path(dst, cwd);
    let dst_parent = resolve_path(&dst_parent_path, cwd)?;

    let dst_inode = match dst_parent.lookup(&dst_name) {
        Ok(inode) => inode,
        Err(FsError::NotFound) => {
            dst_parent.create(&dst_name, FileMode::DEFAULT_FILE, OpenFlags::default())?
        }
        Err(e) => return Err(e),
    };

    dst_inode.truncate(0)?;
    dst_inode.write(0, &content)?;

    Ok(())
}

/// ファイルをCoWコピー（O(1) - memfs専用）
///
/// PagedContentのclone()により実際のデータコピーは発生しません。
/// 書き込み時にのみArc::make_mut()でページが分離されます。
///
/// 大容量ファイルのコピーに最適。
pub fn copy_file_cow(src_inode: &MemoryInode, dst_inode: &MemoryInode) {
    if let Some(content) = src_inode.content() {
        let size = src_inode.size.load(core::sync::atomic::Ordering::Relaxed);
        dst_inode.set_content_cow(content, size);
    }
}

/// ファイルに内容を書き込み
pub fn write_file_content(path: &str, cwd: &str, content: &[u8]) -> FsResult<()> {
    let inode = match resolve_path(path, cwd) {
        Ok(inode) => inode,
        Err(FsError::NotFound) => {
            let (parent_path, name) = split_path(path, cwd);
            let parent = resolve_path(&parent_path, cwd)?;
            parent.create(&name, FileMode::DEFAULT_FILE, OpenFlags::default())?
        }
        Err(e) => return Err(e),
    };

    inode.truncate(0)?;
    inode.write(0, content)?;
    Ok(())
}

/// パスを親パスとファイル名に分割
fn split_path(path: &str, cwd: &str) -> (String, String) {
    // 絶対パスを構築
    let abs_path = if path.starts_with('/') {
        path.to_string()
    } else {
        if cwd == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}/{}", cwd, path)
        }
    };

    // 末尾のスラッシュを除去
    let abs_path = abs_path.trim_end_matches('/');

    // 最後の/を見つけて分割
    if let Some(pos) = abs_path.rfind('/') {
        let parent = if pos == 0 { "/" } else { &abs_path[..pos] };
        let name = &abs_path[pos + 1..];
        (parent.to_string(), name.to_string())
    } else {
        (cwd.to_string(), abs_path.to_string())
    }
}

/// ファイル/ディレクトリの情報を取得
pub fn stat_file(path: &str, cwd: &str) -> FsResult<FileAttr> {
    let inode = resolve_path(path, cwd)?;
    inode.getattr()
}

/// シンボリックリンクを作成
pub fn create_symlink(target: &str, link_name: &str, cwd: &str) -> FsResult<()> {
    let (parent_path, name) = split_path(link_name, cwd);
    let parent = resolve_path(&parent_path, cwd)?;

    parent.symlink(&name, target)?;
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test_case]
    fn test_paged_content_in_inode() {
        let inode = MemoryInode::new_file(1, "test.txt", FileMode::DEFAULT_FILE);

        // 書き込み
        inode.write(0, b"Hello, World!").unwrap();

        // 読み取り
        let mut buf = [0u8; 13];
        let n = inode.read(0, &mut buf).unwrap();
        assert_eq!(n, 13);
        assert_eq!(&buf, b"Hello, World!");
    }

    #[test_case]
    fn test_large_file_paging() {
        use super::super::page::PAGE_SIZE;

        let inode = MemoryInode::new_file(1, "large.bin", FileMode::DEFAULT_FILE);

        // 複数ページにまたがるデータ
        let data = vec![0xABu8; PAGE_SIZE * 3 + 100];
        inode.write(0, &data).unwrap();

        // サイズ確認
        let attr = inode.getattr().unwrap();
        assert_eq!(attr.size, data.len() as u64);

        // 読み取り確認
        let mut buf = vec![0u8; data.len()];
        inode.read(0, &mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test_case]
    fn test_cow_copy() {
        let src = MemoryInode::new_file(1, "src.txt", FileMode::DEFAULT_FILE);
        src.write(0, b"Original content").unwrap();

        let dst = MemoryInode::new_file(2, "dst.txt", FileMode::DEFAULT_FILE);

        // CoWコピー
        copy_file_cow(&src, &dst);

        // 内容が一致
        let mut buf = [0u8; 16];
        dst.read(0, &mut buf).unwrap();
        assert_eq!(&buf, b"Original content");

        // ソースを変更してもdstに影響なし（CoW）
        src.write(0, b"Modified content").unwrap();

        let mut buf2 = [0u8; 16];
        dst.read(0, &mut buf2).unwrap();
        assert_eq!(&buf2, b"Original content");
    }

    #[test_case]
    fn test_sparse_file() {
        let inode = MemoryInode::new_file(1, "sparse.bin", FileMode::DEFAULT_FILE);

        // オフセット1MBに書き込み（中間領域はスパース）
        let offset = 1024 * 1024;
        inode.write(offset, b"sparse data").unwrap();

        // 中間領域はゼロ
        let mut buf = [0xFFu8; 10];
        inode.read(1000, &mut buf).unwrap();
        assert_eq!(&buf, &[0u8; 10]);

        // 書き込み領域は正常
        let mut buf2 = [0u8; 11];
        inode.read(offset, &mut buf2).unwrap();
        assert_eq!(&buf2, b"sparse data");
    }

    #[test_case]
    fn test_truncate_releases_pages() {
        use super::super::page::PAGE_SIZE;

        let inode = MemoryInode::new_file(1, "truncate.bin", FileMode::DEFAULT_FILE);

        // 3ページ分書き込み
        let data = vec![0xCDu8; PAGE_SIZE * 3];
        inode.write(0, &data).unwrap();

        // 1ページに切り詰め
        inode.truncate(PAGE_SIZE as u64).unwrap();

        let attr = inode.getattr().unwrap();
        assert_eq!(attr.size, PAGE_SIZE as u64);
    }

    #[test_case]
    fn test_get_page_zero_copy() {
        let inode = MemoryInode::new_file(1, "zero_copy.bin", FileMode::DEFAULT_FILE);
        inode.write(0, b"Page data for test").unwrap();

        // ページ直接取得
        let page = inode.get_page(0);
        assert!(page.is_some());
        assert_eq!(&page.unwrap()[..18], b"Page data for test");

        // 存在しないページ
        let no_page = inode.get_page(100);
        assert!(no_page.is_none());
    }
}

