use super::*;

// ============================================================================
// Shell Integration API
// ============================================================================

use crate::sync::InitOnce;

/// グローバルMemoryFsインスタンス
pub(crate) static SHELL_FS: InitOnce<Arc<MemoryFs>> = InitOnce::new();

#[derive(Clone, Copy)]
enum MutationKind {
    Mkdir = 1,
    Touch,
    Unlink,
    Rmdir,
    Rename,
    Copy,
    Write,
    Symlink,
}

use crate::durability::wal::{WalError, WalOperation};

enum MutationSlot {
    Available,
    Operating,
    Retained(WalOperation),
}
static MUTATION_SLOT: crate::sync::Mutex<MutationSlot> =
    crate::sync::Mutex::new(MutationSlot::Available);

enum MutationProgress {
    Prepared,
    MemoryCommitted(WalOperation),
    Confirmed,
}

/// Namespace admission is exclusive, but no spinlock crosses an await. The
/// owner keeps commit order equal to memory mutation order. Cancellation after
/// memory publication retains the intent and closes further mutation admission.
struct MutationOwner {
    progress: MutationProgress,
}
impl MutationOwner {
    fn acquire() -> FsResult<Self> {
        let mut slot = MUTATION_SLOT.lock();
        match &*slot {
            MutationSlot::Available => {
                *slot = MutationSlot::Operating;
                Ok(Self {
                    progress: MutationProgress::Prepared,
                })
            }
            MutationSlot::Operating => Err(FsError::JournalUnavailable(WalError::Busy)),
            MutationSlot::Retained(WalOperation::Write { data, .. }) => {
                Err(FsError::MutationRecoveryRequired {
                    intent_bytes: data.len(),
                })
            }
            MutationSlot::Retained(WalOperation::Trim { .. }) => {
                unreachable!("memfs encodes mutations as Write records")
            }
        }
    }
}
impl Drop for MutationOwner {
    fn drop(&mut self) {
        let progress = core::mem::replace(&mut self.progress, MutationProgress::Confirmed);
        *MUTATION_SLOT.lock() = match progress {
            MutationProgress::MemoryCommitted(intent) => MutationSlot::Retained(intent),
            MutationProgress::Prepared | MutationProgress::Confirmed => MutationSlot::Available,
        };
    }
}

fn encode_mutation(kind: MutationKind, path: &str, cwd: &str, payload: &[u8]) -> FsResult<Vec<u8>> {
    let path = build_absolute_path(path, cwd);
    let total = path
        .len()
        .checked_add(payload.len())
        .and_then(|bytes| bytes.checked_add(17))
        .ok_or(FsError::JournalUnavailable(WalError::Allocation))?;
    let path_len = u32::try_from(path.len())
        .map_err(|_| FsError::JournalUnavailable(WalError::InvalidConfig))?;
    let mut data = Vec::new();
    data.try_reserve_exact(total)
        .map_err(|_| FsError::JournalUnavailable(WalError::Allocation))?;
    data.extend_from_slice(b"MFSJ");
    data.push(kind as u8);
    data.extend_from_slice(&path_len.to_le_bytes());
    data.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    data.extend_from_slice(path.as_bytes());
    data.extend_from_slice(payload);
    Ok(data)
}

async fn mutate<T>(
    kind: MutationKind,
    path: &str,
    cwd: &str,
    payload: &[u8],
    apply: impl FnOnce() -> FsResult<T>,
) -> FsResult<T> {
    use crate::durability::wal::wal_manager;
    let mut owner = MutationOwner::acquire()?;
    let data = encode_mutation(kind, path, cwd, payload)?;
    let mut journal_bytes = Vec::new();
    journal_bytes
        .try_reserve_exact(data.len())
        .map_err(|_| FsError::JournalUnavailable(WalError::Allocation))?;
    journal_bytes.extend_from_slice(&data);
    let mut transaction = wal_manager().transaction();
    transaction
        .append(WalOperation::Write {
            offset: 0,
            data: journal_bytes,
        })
        .map_err(FsError::JournalUnavailable)?;
    let prepared = transaction.prepare().map_err(FsError::JournalUnavailable)?;
    // The synchronous application either fails without changing the namespace
    // or completes the mutation. No poll boundary occurs before intent retention.
    let result = apply()?;
    owner.progress = MutationProgress::MemoryCommitted(WalOperation::Write { offset: 0, data });
    prepared.commit().await.map_err(FsError::MemoryCommitted)?;
    owner.progress = MutationProgress::Confirmed;
    Ok(result)
}

/// Restore one committed memfs mutation without producing a new WAL entry.
/// Recovery owns transaction ordering; application is idempotent on a fresh or
/// partially restored memory filesystem. The journal remains the durable home
/// because memfs itself cannot acknowledge a persistent checkpoint.
pub(crate) fn apply_journal_operation(
    operation: &crate::durability::wal::WalOperation,
) -> FsResult<()> {
    let crate::durability::wal::WalOperation::Write { offset: 0, data } = operation else {
        return Err(FsError::NotSupported);
    };
    if data.len() < 17 || &data[..4] != b"MFSJ" {
        return Err(FsError::CorruptedFs);
    }
    let path_len =
        u32::from_le_bytes(data[5..9].try_into().map_err(|_| FsError::CorruptedFs)?) as usize;
    let payload_len = usize::try_from(u64::from_le_bytes(
        data[9..17].try_into().map_err(|_| FsError::CorruptedFs)?,
    ))
    .map_err(|_| FsError::CorruptedFs)?;
    let path_end = 17usize.checked_add(path_len).ok_or(FsError::CorruptedFs)?;
    if path_end.checked_add(payload_len) != Some(data.len()) {
        return Err(FsError::CorruptedFs);
    }
    let path = core::str::from_utf8(data.get(17..path_end).ok_or(FsError::CorruptedFs)?)
        .map_err(|_| FsError::CorruptedFs)?;
    if !path.starts_with('/') {
        return Err(FsError::CorruptedFs);
    }
    let payload = &data[path_end..];
    let (parent_path, name) = split_path(path, "/");
    let parent = resolve_path(&parent_path, "/")?;
    match data[4] {
        1 => match parent.lookup(&name) {
            Ok(inode) if inode.getattr()?.file_type == FileType::Directory => Ok(()),
            Ok(_) => Err(FsError::AlreadyExists),
            Err(FsError::NotFound) => parent.mkdir(&name, FileMode::DEFAULT_DIR).map(|_| ()),
            Err(cause) => Err(cause),
        },
        2 => match parent.lookup(&name) {
            Ok(_) => Ok(()),
            Err(FsError::NotFound) => parent
                .create(&name, FileMode::DEFAULT_FILE, OpenFlags::default())
                .map(|_| ()),
            Err(cause) => Err(cause),
        },
        3 | 4 => {
            let result = if data[4] == 3 {
                parent.unlink(&name)
            } else {
                parent.rmdir(&name)
            };
            match result {
                Err(FsError::NotFound) => Ok(()),
                other => other,
            }
        }
        5 => {
            let dst = core::str::from_utf8(payload).map_err(|_| FsError::CorruptedFs)?;
            if !dst.starts_with('/') {
                return Err(FsError::CorruptedFs);
            }
            let (dst_parent_path, dst_name) = split_path(dst, "/");
            let dst_parent = resolve_path(&dst_parent_path, "/")?;
            match parent.lookup(&name) {
                Err(FsError::NotFound) => dst_parent.lookup(&dst_name).map(|_| ()),
                Err(cause) => Err(cause),
                Ok(_) => parent.rename(&name, &dst_parent, &dst_name),
            }
        }
        6 | 7 => {
            let inode = match parent.lookup(&name) {
                Ok(inode) => inode,
                Err(FsError::NotFound) => {
                    parent.create(&name, FileMode::DEFAULT_FILE, OpenFlags::default())?
                }
                Err(cause) => return Err(cause),
            };
            inode.truncate(0)?;
            let written = inode.write(0, payload)?;
            if written != payload.len() {
                return Err(FsError::IoError);
            }
            Ok(())
        }
        8 => {
            let target = core::str::from_utf8(payload).map_err(|_| FsError::CorruptedFs)?;
            match parent.lookup(&name) {
                Ok(inode) if inode.readlink()? == target => Ok(()),
                Ok(_) => Err(FsError::AlreadyExists),
                Err(FsError::NotFound) => parent.symlink(&name, target).map(|_| ()),
                Err(cause) => Err(cause),
            }
        }
        _ => Err(FsError::CorruptedFs),
    }
}

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
            let _ = root.mkdir("sys", FileMode::DEFAULT_DIR);
            let _ = root.mkdir("tmp", FileMode::DEFAULT_DIR);
            let _ = root.mkdir("var", FileMode::DEFAULT_DIR);
            let _ = root.mkdir("drivers", FileMode::DEFAULT_DIR); // For dynamic driver loading

            if let Ok(sys) = root.lookup("sys") {
                let _ = sys.mkdir("cell", FileMode::DEFAULT_DIR);
                let _ = sys.mkdir("system", FileMode::DEFAULT_DIR);
                if let Ok(system) = sys.lookup("system") {
                    let _ = system.mkdir("kernel", FileMode::DEFAULT_DIR);
                    let _ = system.mkdir("net", FileMode::DEFAULT_DIR);
                }
            }

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

/// 相対パスを絶対パスに変換する
pub(crate) fn build_absolute_path(path: &str, cwd: &str) -> String {
    if path.starts_with('/') {
        return path.to_string();
    }
    if path == "." {
        return cwd.to_string();
    }
    if path == ".." {
        let parts: Vec<&str> = cwd.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() <= 1 {
            return "/".to_string();
        }
        return alloc::format!("/{}", parts[..parts.len() - 1].join("/"));
    }
    if cwd == "/" {
        alloc::format!("/{}", path)
    } else {
        alloc::format!("{}/{}", cwd, path)
    }
}

/// パスを解決してinodeを取得
pub fn resolve_path(path: &str, cwd: &str) -> FsResult<Arc<dyn Inode>> {
    let fs = shell_fs().ok_or(FsError::IoError)?;
    let root = fs.root()?;

    let abs_path = build_absolute_path(path, cwd);
    let components: Vec<&str> = abs_path.split('/').filter(|s| !s.is_empty()).collect();

    if components.is_empty() {
        return Ok(root);
    }

    let mut current: Arc<dyn Inode> = root;
    for component in components {
        if component == "." || component == ".." {
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
pub async fn make_directory(path: &str, cwd: &str) -> FsResult<()> {
    mutate(MutationKind::Mkdir, path, cwd, &[], || {
        let (parent_path, name) = split_path(path, cwd);
        let parent = resolve_path(&parent_path, cwd)?;
        parent.mkdir(&name, FileMode::DEFAULT_DIR)?;
        Ok(())
    })
    .await
}

/// ファイルを作成/更新
pub async fn touch_file(path: &str, cwd: &str) -> FsResult<()> {
    mutate(MutationKind::Touch, path, cwd, &[], || {
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
    })
    .await
}

/// ファイルを削除
pub async fn remove_file(path: &str, cwd: &str) -> FsResult<()> {
    mutate(MutationKind::Unlink, path, cwd, &[], || {
        let (parent_path, name) = split_path(path, cwd);
        let parent = resolve_path(&parent_path, cwd)?;
        parent.unlink(&name)?;
        Ok(())
    })
    .await
}

/// ディレクトリを削除
pub async fn remove_directory(path: &str, cwd: &str) -> FsResult<()> {
    mutate(MutationKind::Rmdir, path, cwd, &[], || {
        let (parent_path, name) = split_path(path, cwd);
        let parent = resolve_path(&parent_path, cwd)?;
        parent.rmdir(&name)?;
        Ok(())
    })
    .await
}

/// ファイル/ディレクトリを移動
pub async fn move_file(src: &str, dst: &str, cwd: &str) -> FsResult<()> {
    let destination = build_absolute_path(dst, cwd);
    mutate(
        MutationKind::Rename,
        src,
        cwd,
        destination.as_bytes(),
        || {
            let (src_parent_path, src_name) = split_path(src, cwd);
            let (dst_parent_path, dst_name) = split_path(dst, cwd);

            let src_parent = resolve_path(&src_parent_path, cwd)?;
            let dst_parent = resolve_path(&dst_parent_path, cwd)?;

            src_parent.rename(&src_name, &dst_parent, &dst_name)?;
            Ok(())
        },
    )
    .await
}

/// ファイルをコピー
///
/// 注: memfs内でのCoW直接コピーには `copy_file_cow` を使用してください。
pub async fn copy_file(src: &str, dst: &str, cwd: &str) -> FsResult<()> {
    // ソースを読み取り
    let content = read_file_content(src, cwd)?;

    mutate(MutationKind::Copy, dst, cwd, &content, || {
        replace_file(dst, cwd, &content)
    })
    .await
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
pub async fn write_file_content(path: &str, cwd: &str, content: &[u8]) -> FsResult<()> {
    mutate(MutationKind::Write, path, cwd, content, || {
        replace_file(path, cwd, content)
    })
    .await
}

fn replace_file(path: &str, cwd: &str, bytes: &[u8]) -> FsResult<()> {
    let (parent_path, name) = split_path(path, cwd);
    let parent = resolve_path(&parent_path, cwd)?;
    let parent = parent
        .as_any()
        .downcast_ref::<MemoryInode>()
        .ok_or(FsError::CrossDeviceLink)?;
    let mut content = PagedContent::new();
    content.write(0, bytes);
    parent.replace_child_file(&name, content, bytes.len() as u64)
}

/// パスを親パスとファイル名に分割
pub(crate) fn split_path(path: &str, cwd: &str) -> (String, String) {
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
pub async fn create_symlink(target: &str, link_name: &str, cwd: &str) -> FsResult<()> {
    mutate(
        MutationKind::Symlink,
        link_name,
        cwd,
        target.as_bytes(),
        || {
            let (parent_path, name) = split_path(link_name, cwd);
            let parent = resolve_path(&parent_path, cwd)?;

            parent.symlink(&name, target)?;
            Ok(())
        },
    )
    .await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, not(feature = "qemu-test-export")))]
#[path = "tests.rs"]
mod tests;
