use super::*;


// ============================================================================
// Shell Integration API
// ============================================================================

use spin::Once;

/// グローバルMemoryFsインスタンス
pub(crate) static SHELL_FS: Once<Arc<MemoryFs>> = Once::new();

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
            #[cfg(feature = "posix-compat")]
            let _ = root.mkdir("proc", FileMode::DEFAULT_DIR);
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
pub fn create_symlink(target: &str, link_name: &str, cwd: &str) -> FsResult<()> {
    let (parent_path, name) = split_path(link_name, cwd);
    let parent = resolve_path(&parent_path, cwd)?;

    parent.symlink(&name, target)?;
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, not(feature = "qemu-test-export")))]
#[path = "tests.rs"]
mod tests;
