use alloc::string::String;
use alloc::vec::Vec;

use super::{
    Arc,
    RwLock,
    FsResult,
    FsError,
    InodeNum,
    FileType,
    FileSystem,
    Inode,
};


// ============================================================================
// Mount Table
// ============================================================================

/// Mount point entry
pub(crate) struct MountEntry {
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
pub(crate) static MOUNT_TABLE: MountTable = MountTable::new();

/// Get the global mount table
pub fn mount_table() -> &'static MountTable {
    &MOUNT_TABLE
}

/// BFS: ディレクトリの子をキューに追加する
pub(crate) fn bfs_enqueue_child(
    parent: &Arc<dyn Inode>,
    name: &str,
    visited: &mut hashbrown::HashSet<u64>,
    queue: &mut alloc::collections::VecDeque<Arc<dyn Inode>>,
) {
    if let Ok(child) = parent.lookup(name) {
        if let Ok(attr) = child.getattr() {
            if !visited.contains(&attr.ino) {
                visited.insert(attr.ino);
                queue.push_back(child);
            }
        }
    }
}

/// BFS: ディレクトリエントリを検索し、対象inodeを見つけたら返す
pub(crate) fn bfs_search_directory(
    node: &Arc<dyn Inode>,
    ino: InodeNum,
    visited: &mut hashbrown::HashSet<u64>,
    queue: &mut alloc::collections::VecDeque<Arc<dyn Inode>>,
) -> Option<Arc<dyn Inode>> {
    let attr = node.getattr().ok()?;
    if attr.file_type != FileType::Directory {
        return None;
    }
    let entries = node.readdir(0).ok()?;
    for d in entries {
        if d.ino == ino {
            if let Ok(child) = node.lookup(&d.name) {
                return Some(child);
            }
        } else if d.file_type == FileType::Directory {
            bfs_enqueue_child(node, &d.name, visited, queue);
        }
    }
    None
}

/// マウントされた全ファイルシステムからinode番号でinodeを検索する
pub(crate) fn find_inode_by_number(ino: InodeNum) -> Option<Arc<dyn Inode>> {
    use alloc::collections::VecDeque;
    use hashbrown::HashSet;

    let mounts = MOUNT_TABLE.mounts.read();
    for entry in mounts.iter() {
        if let Ok(root) = entry.fs.root() {
            let mut queue: VecDeque<Arc<dyn Inode>> = VecDeque::new();
            let mut visited: HashSet<u64> = HashSet::new();
            if let Ok(attr) = root.getattr() {
                if attr.ino == ino {
                    return Some(root);
                }
                visited.insert(attr.ino);
                queue.push_back(root);
            }
            while let Some(node) = queue.pop_front() {
                if let Some(found) = bfs_search_directory(&node, ino, &mut visited, &mut queue) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Attempt to read data from the inode identified by `ino`.
/// This is a best-effort helper that traverses mounted filesystems and
/// attempts to locate the inode by number, then calls `Inode::read`.
/// Returns `Ok(bytes_read)` if read succeeds, `Err(())` otherwise.
pub fn read_inode_by_number(ino: InodeNum, offset: u64, buf: &mut [u8]) -> Result<usize, ()> {
    let inode = find_inode_by_number(ino).ok_or(())?;
    inode.read(offset, buf).map_err(|_| ())
}

/// Attempt to write data to the inode identified by `ino`.
/// This is a best-effort helper that traverses mounted filesystems and
/// attempts to locate the inode by number, then calls `Inode::write`.
/// Returns `Ok(())` if write succeeds, `Err(())` otherwise.
pub fn write_inode_by_number(ino: InodeNum, offset: u64, data: &[u8]) -> Result<(), ()> {
    let inode = find_inode_by_number(ino).ok_or(())?;
    inode.write(offset, data).map(|_| ()).map_err(|_| ())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, not(feature = "qemu-test-export")))]
#[path = "tests.rs"]
mod tests;
