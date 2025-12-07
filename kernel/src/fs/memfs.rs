//! memfs - Memory-based Filesystem
//!
//! シェルコマンドの動作検証用のインメモリファイルシステム
//! 実際のストレージバックエンドなしで動作するファイルシステム

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

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
        let components: Vec<&str> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

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

/// メモリinode内部データ
struct MemoryInodeData {
    /// ファイル内容（ファイルの場合）
    content: Vec<u8>,
    /// 子エントリ（ディレクトリの場合）
    children: BTreeMap<String, Arc<MemoryInode>>,
    /// シンボリックリンクターゲット
    symlink_target: Option<String>,
}

/// メモリベースのinode
pub struct MemoryInode {
    /// inode番号
    ino: u64,
    /// ファイル名
    name: String,
    /// ファイルタイプ
    file_type: FileType,
    /// パーミッション
    mode: FileMode,
    /// サイズ
    size: AtomicU64,
    /// データ
    data: RwLock<MemoryInodeData>,
    /// 次のinode番号（ディレクトリ作成時用）
    next_child_ino: AtomicU64,
}

impl MemoryInode {
    /// 新しいディレクトリinodeを作成
    pub fn new_dir(ino: u64, name: &str, mode: FileMode) -> Self {
        Self {
            ino,
            name: name.to_string(),
            file_type: FileType::Directory,
            mode,
            size: AtomicU64::new(0),
            data: RwLock::new(MemoryInodeData {
                content: Vec::new(),
                children: BTreeMap::new(),
                symlink_target: None,
            }),
            next_child_ino: AtomicU64::new(ino + 1000), // 子inode用のベース
        }
    }

    /// 新しいファイルinodeを作成
    pub fn new_file(ino: u64, name: &str, mode: FileMode) -> Self {
        Self {
            ino,
            name: name.to_string(),
            file_type: FileType::Regular,
            mode,
            size: AtomicU64::new(0),
            data: RwLock::new(MemoryInodeData {
                content: Vec::new(),
                children: BTreeMap::new(),
                symlink_target: None,
            }),
            next_child_ino: AtomicU64::new(0),
        }
    }

    /// 新しいシンボリックリンクinodeを作成
    pub fn new_symlink(ino: u64, name: &str, target: &str) -> Self {
        Self {
            ino,
            name: name.to_string(),
            file_type: FileType::Symlink,
            mode: FileMode(0o777),
            size: AtomicU64::new(target.len() as u64),
            data: RwLock::new(MemoryInodeData {
                content: Vec::new(),
                children: BTreeMap::new(),
                symlink_target: Some(target.to_string()),
            }),
            next_child_ino: AtomicU64::new(0),
        }
    }

    /// 次の子inode番号を割り当て
    fn alloc_child_ino(&self) -> u64 {
        self.next_child_ino.fetch_add(1, Ordering::SeqCst)
    }
}

impl Inode for MemoryInode {
    fn getattr(&self) -> FsResult<FileAttr> {
        Ok(FileAttr {
            ino: self.ino,
            size: self.size.load(Ordering::Relaxed),
            blocks: (self.size.load(Ordering::Relaxed) + 511) / 512,
            atime: 0,
            mtime: 0,
            ctime: 0,
            file_type: self.file_type,
            mode: self.mode,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
        })
    }

    fn setattr(&self, _attr: &FileAttr) -> FsResult<()> {
        // メモリFSでは現状無視
        Ok(())
    }

    fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }

        let data = self.data.read();
        data.children
            .get(name)
            .map(|inode| inode.clone() as Arc<dyn Inode>)
            .ok_or(FsError::NotFound)
    }

    fn readdir(&self, _offset: u64) -> FsResult<Vec<DirEntry>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }

        let data = self.data.read();
        let mut entries = Vec::new();

        // . と ..
        entries.push(DirEntry {
            ino: self.ino,
            file_type: FileType::Directory,
            name: ".".to_string(),
        });
        entries.push(DirEntry {
            ino: self.ino, // 親の場合は親のino
            file_type: FileType::Directory,
            name: "..".to_string(),
        });

        // 子エントリ
        for (name, inode) in data.children.iter() {
            entries.push(DirEntry {
                ino: inode.ino,
                file_type: inode.file_type,
                name: name.clone(),
            });
        }

        Ok(entries)
    }

    fn create(&self, name: &str, mode: FileMode, _flags: OpenFlags) -> FsResult<Arc<dyn Inode>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }

        let mut data = self.data.write();

        if data.children.contains_key(name) {
            return Err(FsError::AlreadyExists);
        }

        let ino = self.alloc_child_ino();
        let inode = Arc::new(MemoryInode::new_file(ino, name, mode));
        data.children.insert(name.to_string(), inode.clone());

        Ok(inode)
    }

    fn mkdir(&self, name: &str, mode: FileMode) -> FsResult<Arc<dyn Inode>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }

        let mut data = self.data.write();

        if data.children.contains_key(name) {
            return Err(FsError::AlreadyExists);
        }

        let ino = self.alloc_child_ino();
        let inode = Arc::new(MemoryInode::new_dir(ino, name, mode));
        data.children.insert(name.to_string(), inode.clone());

        Ok(inode)
    }

    fn unlink(&self, name: &str) -> FsResult<()> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }

        let mut data = self.data.write();

        if let Some(inode) = data.children.get(name) {
            if inode.file_type == FileType::Directory {
                return Err(FsError::IsDirectory);
            }
            data.children.remove(name);
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    fn rmdir(&self, name: &str) -> FsResult<()> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }

        let mut data = self.data.write();

        if let Some(inode) = data.children.get(name) {
            if inode.file_type != FileType::Directory {
                return Err(FsError::NotDirectory);
            }

            // ディレクトリが空か確認
            let child_data = inode.data.read();
            if !child_data.children.is_empty() {
                return Err(FsError::NotEmpty);
            }
            drop(child_data);

            data.children.remove(name);
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    fn rename(&self, old_name: &str, new_dir: &Arc<dyn Inode>, new_name: &str) -> FsResult<()> {
        // 簡略化: 同一ディレクトリ内のリネームのみ対応
        // inode番号は getattr() から取得
        let new_dir_ino = new_dir.getattr().map(|a| a.ino).unwrap_or(0);
        if self.ino != new_dir_ino {
            return Err(FsError::CrossDeviceLink);
        }

        let mut data = self.data.write();

        if let Some(inode) = data.children.remove(old_name) {
            data.children.insert(new_name.to_string(), inode);
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    fn link(&self, _name: &str, _inode: &Arc<dyn Inode>) -> FsResult<()> {
        Err(FsError::NotSupported) // メモリFSではハードリンク非対応
    }

    fn symlink(&self, name: &str, target: &str) -> FsResult<Arc<dyn Inode>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }

        let mut data = self.data.write();

        if data.children.contains_key(name) {
            return Err(FsError::AlreadyExists);
        }

        let ino = self.alloc_child_ino();
        let inode = Arc::new(MemoryInode::new_symlink(ino, name, target));
        data.children.insert(name.to_string(), inode.clone());

        Ok(inode)
    }

    fn readlink(&self) -> FsResult<String> {
        if self.file_type != FileType::Symlink {
            return Err(FsError::InvalidArgument);
        }

        let data = self.data.read();
        data.symlink_target
            .clone()
            .ok_or(FsError::InvalidArgument)
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        if self.file_type != FileType::Regular {
            return Err(FsError::IsDirectory);
        }

        let data = self.data.read();
        let content = &data.content;

        if offset >= content.len() as u64 {
            return Ok(0);
        }

        let start = offset as usize;
        let end = core::cmp::min(start + buf.len(), content.len());
        let len = end - start;

        buf[..len].copy_from_slice(&content[start..end]);
        Ok(len)
    }

    fn write(&self, offset: u64, buf: &[u8]) -> FsResult<usize> {
        if self.file_type != FileType::Regular {
            return Err(FsError::IsDirectory);
        }

        let mut data = self.data.write();
        let content = &mut data.content;

        let offset = offset as usize;
        let end = offset + buf.len();

        // 必要に応じてコンテンツを拡張
        if end > content.len() {
            content.resize(end, 0);
        }

        content[offset..end].copy_from_slice(buf);
        self.size.store(content.len() as u64, Ordering::Relaxed);

        Ok(buf.len())
    }

    fn truncate(&self, size: u64) -> FsResult<()> {
        if self.file_type != FileType::Regular {
            return Err(FsError::IsDirectory);
        }

        let mut data = self.data.write();
        data.content.resize(size as usize, 0);
        self.size.store(size, Ordering::Relaxed);

        Ok(())
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

            // /etc/hostname を作成
            if let Ok(etc) = root.lookup("etc") {
                if let Ok(hostname_file) = etc.create("hostname", FileMode::DEFAULT_FILE, OpenFlags::default()) {
                    let _ = hostname_file.write(0, b"ranyos\n");
                }
                // /etc/version を作成
                if let Ok(version_file) = etc.create("version", FileMode::DEFAULT_FILE, OpenFlags::default()) {
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

/// ファイルをコピー
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
