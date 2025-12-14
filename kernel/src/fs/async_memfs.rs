// ============================================================================
// src/fs/async_memfs.rs - Async Memory Filesystem Wrapper
// ============================================================================
//!
//! # 非同期メモリファイルシステムラッパー
//!
//! ExoRustのAsync-First設計思想に準拠したMemoryFS用非同期ラッパー。
//! 既存の同期的な`MemoryInode`を非同期インターフェースでラップし、
//! Executorから呼び出し可能にする。
//!
//! ## 設計原則
//! - インターフェースは非同期（Future）だが、内部実装は同期
//! - メモリ操作は高速なため、poll時に即座にPoll::Readyを返す
//! - ゼロコピー対応の`Bytes`型を提供
//!
//! ## 使用例
//! ```ignore
//! let inode = AsyncMemoryInode::new(memory_inode);
//! let mut buf = [0u8; 1024];
//! let n = inode.read(0, &mut buf).await?;
//! ```

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::ops::Deref;
use core::pin::Pin;
use core::task::{Context, Poll};

use super::fs_abstraction::{DirEntry, FileAttr, FileMode, FsError, FsResult, OpenFlags};
use super::memfs::{MemoryFs, MemoryInode};

// ============================================================================
// Bytes - Zero-Copy Buffer Type
// ============================================================================

/// ゼロコピー対応の共有バッファ型
///
/// `Arc<Vec<u8>>` をラップし、複数のコンシューマ間でデータをコピーせずに共有可能。
/// 将来的にはスライス参照も保持できるように拡張予定。
#[derive(Clone)]
pub struct Bytes {
    inner: Arc<Vec<u8>>,
}

impl Bytes {
    /// 新しいBytesを作成
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            inner: Arc::new(data),
        }
    }

    /// 空のBytesを作成
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(Vec::new()),
        }
    }

    /// Arc<Vec<u8>>からBytesを作成
    pub fn from_arc(arc: Arc<Vec<u8>>) -> Self {
        Self { inner: arc }
    }

    /// バイト列の長さを取得
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// 内部データへの参照を取得
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// 内部のArc<Vec<u8>>を取得（所有権移動）
    pub fn into_inner(self) -> Arc<Vec<u8>> {
        self.inner
    }

    /// Vec<u8>にコピー（必要な場合のみ使用）
    pub fn to_vec(&self) -> Vec<u8> {
        self.inner.as_ref().clone()
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for Bytes {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

// ============================================================================
// AsyncInode Trait
// ============================================================================

/// 非同期Inodeトレイト
///
/// 標準の`Inode`トレイトの非同期版。
/// `async_trait`を使用せず、`Pin<Box<dyn Future>>`で明示的に実装。
pub trait AsyncInode: Send + Sync {
    /// ファイル属性を非同期に取得
    fn getattr_async(&self) -> Pin<Box<dyn Future<Output = FsResult<FileAttr>> + Send + '_>>;

    /// 名前でディレクトリエントリを検索
    fn lookup_async(
        &self,
        name: &str,
    ) -> Pin<Box<dyn Future<Output = FsResult<Arc<dyn AsyncInode>>> + Send + '_>>;

    /// ディレクトリエントリを非同期に読み取り
    fn readdir_async(
        &self,
        offset: u64,
    ) -> Pin<Box<dyn Future<Output = FsResult<Vec<DirEntry>>> + Send + '_>>;

    /// ファイルからデータを非同期に読み取り
    fn read_async<'a>(
        &'a self,
        offset: u64,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = FsResult<usize>> + Send + 'a>>;

    /// ファイルにデータを非同期に書き込み
    fn write_async<'a>(
        &'a self,
        offset: u64,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = FsResult<usize>> + Send + 'a>>;

    /// ゼロコピー読み取り（データの共有参照を返す）
    fn read_zero_copy(
        &self,
        offset: u64,
        len: usize,
    ) -> Pin<Box<dyn Future<Output = FsResult<Bytes>> + Send + '_>>;

    /// ファイル/ディレクトリを非同期に作成
    fn create_async(
        &self,
        name: &str,
        mode: FileMode,
        flags: OpenFlags,
    ) -> Pin<Box<dyn Future<Output = FsResult<Arc<dyn AsyncInode>>> + Send + '_>>;

    /// ディレクトリを非同期に作成
    fn mkdir_async(
        &self,
        name: &str,
        mode: FileMode,
    ) -> Pin<Box<dyn Future<Output = FsResult<Arc<dyn AsyncInode>>> + Send + '_>>;

    /// ファイルを非同期に削除
    fn unlink_async(&self, name: &str) -> Pin<Box<dyn Future<Output = FsResult<()>> + Send + '_>>;

    /// ディレクトリを非同期に削除
    fn rmdir_async(&self, name: &str) -> Pin<Box<dyn Future<Output = FsResult<()>> + Send + '_>>;

    /// ファイルを非同期に切り詰め
    fn truncate_async(
        &self,
        size: u64,
    ) -> Pin<Box<dyn Future<Output = FsResult<()>> + Send + '_>>;

    /// ファイル/ディレクトリを非同期に名前変更
    fn rename_async(
        &self,
        old_name: &str,
        new_name: &str,
    ) -> Pin<Box<dyn Future<Output = FsResult<()>> + Send + '_>>;

    /// シンボリックリンクを非同期に作成
    fn symlink_async(
        &self,
        name: &str,
        target: &str,
    ) -> Pin<Box<dyn Future<Output = FsResult<Arc<dyn AsyncInode>>> + Send + '_>>;

    /// シンボリックリンクのターゲットを非同期に読み取り
    fn readlink_async(&self) -> Pin<Box<dyn Future<Output = FsResult<String>> + Send + '_>>;
}

// ============================================================================
// AsyncMemoryInode - Wrapper Implementation
// ============================================================================

/// MemoryInode用の非同期ラッパー
pub struct AsyncMemoryInode {
    inner: Arc<MemoryInode>,
}

impl AsyncMemoryInode {
    /// 新しい非同期ラッパーを作成
    pub fn new(inode: Arc<MemoryInode>) -> Self {
        Self { inner: inode }
    }

    /// 内部のMemoryInodeへの参照を取得
    pub fn inner(&self) -> &Arc<MemoryInode> {
        &self.inner
    }
}

// Futureは即座に完了するため、シンプルな構造体で実装
struct ImmediateFuture<T> {
    result: Option<T>,
}

impl<T> ImmediateFuture<T> {
    fn new(result: T) -> Self {
        Self {
            result: Some(result),
        }
    }
}

impl<T: Unpin> Future for ImmediateFuture<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.result.take().expect("polled after completion"))
    }
}

// AsyncInode trait implementation for AsyncMemoryInode
impl AsyncInode for AsyncMemoryInode {
    fn getattr_async(&self) -> Pin<Box<dyn Future<Output = FsResult<FileAttr>> + Send + '_>> {
        use super::fs_abstraction::Inode;
        let result = self.inner.getattr();
        Box::pin(ImmediateFuture::new(result))
    }

    fn lookup_async(
        &self,
        name: &str,
    ) -> Pin<Box<dyn Future<Output = FsResult<Arc<dyn AsyncInode>>> + Send + '_>> {
        use super::fs_abstraction::Inode;
        let result = self.inner.lookup(name);
        let wrapped = result.map(|inode| {
            // downcast to MemoryInode if possible
            let mem_inode = unsafe {
                // Safety: We know this is a MemoryInode from our MemoryFs
                Arc::from_raw(Arc::into_raw(inode) as *const MemoryInode)
            };
            Arc::new(AsyncMemoryInode::new(mem_inode)) as Arc<dyn AsyncInode>
        });
        Box::pin(ImmediateFuture::new(wrapped))
    }

    fn readdir_async(
        &self,
        offset: u64,
    ) -> Pin<Box<dyn Future<Output = FsResult<Vec<DirEntry>>> + Send + '_>> {
        use super::fs_abstraction::Inode;
        let result = self.inner.readdir(offset);
        Box::pin(ImmediateFuture::new(result))
    }

    fn read_async<'a>(
        &'a self,
        offset: u64,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = FsResult<usize>> + Send + 'a>> {
        use super::fs_abstraction::Inode;
        // 同期的に読み取り、結果を即座に返す
        let result = self.inner.read(offset, buf);
        Box::pin(ImmediateFuture::new(result))
    }

    fn write_async<'a>(
        &'a self,
        offset: u64,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = FsResult<usize>> + Send + 'a>> {
        use super::fs_abstraction::Inode;
        let result = self.inner.write(offset, buf);
        Box::pin(ImmediateFuture::new(result))
    }

    fn read_zero_copy(
        &self,
        offset: u64,
        len: usize,
    ) -> Pin<Box<dyn Future<Output = FsResult<Bytes>> + Send + '_>> {
        use super::page::{PAGE_SIZE, PAGE_SHIFT, PAGE_MASK};
        
        let page_idx = offset >> PAGE_SHIFT;
        let offset_in_page = (offset as usize) & PAGE_MASK;
        
        // 単一ページ内の読み取りならゼロコピー可能
        if offset_in_page + len <= PAGE_SIZE {
            if let Some(page) = self.inner.get_page(page_idx) {
                // Arc<Page>からスライスを取得してBytesを作成
                let slice = &page[offset_in_page..offset_in_page + len];
                let bytes = Bytes::new(slice.to_vec());
                return Box::pin(ImmediateFuture::new(Ok(bytes)));
            } else {
                // スパース領域: ゼロで埋める
                let bytes = Bytes::new(vec![0u8; len]);
                return Box::pin(ImmediateFuture::new(Ok(bytes)));
            }
        }
        
        // ページ境界をまたぐ場合は従来のコピー
        use super::fs_abstraction::Inode;
        let mut buf = vec![0u8; len];
        let result = self.inner.read(offset, &mut buf).map(|n| {
            buf.truncate(n);
            Bytes::new(buf)
        });
        Box::pin(ImmediateFuture::new(result))
    }

    fn create_async(
        &self,
        name: &str,
        mode: FileMode,
        flags: OpenFlags,
    ) -> Pin<Box<dyn Future<Output = FsResult<Arc<dyn AsyncInode>>> + Send + '_>> {
        use super::fs_abstraction::Inode;
        let result = self.inner.create(name, mode, flags);
        let wrapped = result.map(|inode| {
            let mem_inode = unsafe {
                Arc::from_raw(Arc::into_raw(inode) as *const MemoryInode)
            };
            Arc::new(AsyncMemoryInode::new(mem_inode)) as Arc<dyn AsyncInode>
        });
        Box::pin(ImmediateFuture::new(wrapped))
    }

    fn mkdir_async(
        &self,
        name: &str,
        mode: FileMode,
    ) -> Pin<Box<dyn Future<Output = FsResult<Arc<dyn AsyncInode>>> + Send + '_>> {
        use super::fs_abstraction::Inode;
        let result = self.inner.mkdir(name, mode);
        let wrapped = result.map(|inode| {
            let mem_inode = unsafe {
                Arc::from_raw(Arc::into_raw(inode) as *const MemoryInode)
            };
            Arc::new(AsyncMemoryInode::new(mem_inode)) as Arc<dyn AsyncInode>
        });
        Box::pin(ImmediateFuture::new(wrapped))
    }

    fn unlink_async(&self, name: &str) -> Pin<Box<dyn Future<Output = FsResult<()>> + Send + '_>> {
        use super::fs_abstraction::Inode;
        let result = self.inner.unlink(name);
        Box::pin(ImmediateFuture::new(result))
    }

    fn rmdir_async(&self, name: &str) -> Pin<Box<dyn Future<Output = FsResult<()>> + Send + '_>> {
        use super::fs_abstraction::Inode;
        let result = self.inner.rmdir(name);
        Box::pin(ImmediateFuture::new(result))
    }

    fn truncate_async(
        &self,
        size: u64,
    ) -> Pin<Box<dyn Future<Output = FsResult<()>> + Send + '_>> {
        use super::fs_abstraction::Inode;
        let result = self.inner.truncate(size);
        Box::pin(ImmediateFuture::new(result))
    }

    fn rename_async(
        &self,
        _old_name: &str,
        _new_name: &str,
    ) -> Pin<Box<dyn Future<Output = FsResult<()>> + Send + '_>> {
        // TODO: Implement when Inode::rename is added
        Box::pin(ImmediateFuture::new(Err(FsError::NotSupported)))
    }

    fn symlink_async(
        &self,
        _name: &str,
        _target: &str,
    ) -> Pin<Box<dyn Future<Output = FsResult<Arc<dyn AsyncInode>>> + Send + '_>> {
        // TODO: Implement when Inode::symlink is added
        Box::pin(ImmediateFuture::new(Err(FsError::NotSupported)))
    }

    fn readlink_async(&self) -> Pin<Box<dyn Future<Output = FsResult<String>> + Send + '_>> {
        // TODO: Implement when Inode::readlink is added
        Box::pin(ImmediateFuture::new(Err(FsError::NotSupported)))
    }
}

// ============================================================================
// AsyncMemoryFs - Async Filesystem Wrapper
// ============================================================================

/// 非同期MemoryFsラッパー
pub struct AsyncMemoryFs {
    inner: Arc<MemoryFs>,
}

impl AsyncMemoryFs {
    /// 新しい非同期ラッパーを作成
    pub fn new(fs: Arc<MemoryFs>) -> Self {
        Self { inner: fs }
    }

    /// ルートinodeを非同期に取得
    pub fn root_async(
        &self,
    ) -> Pin<Box<dyn Future<Output = FsResult<Arc<dyn AsyncInode>>> + Send + '_>> {
        use super::fs_abstraction::FileSystem;
        let result = self.inner.root().map(|inode| {
            let mem_inode = unsafe {
                Arc::from_raw(Arc::into_raw(inode) as *const MemoryInode)
            };
            Arc::new(AsyncMemoryInode::new(mem_inode)) as Arc<dyn AsyncInode>
        });
        Box::pin(ImmediateFuture::new(result))
    }

    /// ファイルシステム名を取得
    pub fn name(&self) -> &str {
        use super::fs_abstraction::FileSystem;
        self.inner.name()
    }
}

// ============================================================================
// Async Shell Integration API
// ============================================================================

use super::memfs::resolve_path as sync_resolve_path;

/// パスを非同期に解決してAsyncInodeを取得
pub async fn resolve_path_async(path: &str, cwd: &str) -> FsResult<Arc<dyn AsyncInode>> {
    // 同期版を呼び出し、結果をラップ
    let inode = sync_resolve_path(path, cwd)?;
    let mem_inode = unsafe {
        Arc::from_raw(Arc::into_raw(inode) as *const MemoryInode)
    };
    Ok(Arc::new(AsyncMemoryInode::new(mem_inode)) as Arc<dyn AsyncInode>)
}

/// ディレクトリの内容を非同期に一覧表示
pub async fn list_directory_async(path: &str, cwd: &str) -> FsResult<Vec<DirEntry>> {
    let inode = resolve_path_async(path, cwd).await?;
    inode.readdir_async(0).await
}

/// ファイルの内容を非同期に読み取り
pub async fn read_file_content_async(path: &str, cwd: &str) -> FsResult<Vec<u8>> {
    use super::fs_abstraction::FileType;

    let inode = resolve_path_async(path, cwd).await?;
    let attr = inode.getattr_async().await?;

    if attr.file_type == FileType::Directory {
        return Err(FsError::IsDirectory);
    }

    let mut buf = vec![0u8; attr.size as usize];
    let _ = inode.read_async(0, &mut buf).await?;
    Ok(buf)
}

/// ファイルの内容をゼロコピーで非同期に読み取り
pub async fn read_file_zero_copy_async(path: &str, cwd: &str) -> FsResult<Bytes> {
    use super::fs_abstraction::FileType;

    let inode = resolve_path_async(path, cwd).await?;
    let attr = inode.getattr_async().await?;

    if attr.file_type == FileType::Directory {
        return Err(FsError::IsDirectory);
    }

    inode.read_zero_copy(0, attr.size as usize).await
}

/// ディレクトリを非同期に作成
pub async fn make_directory_async(path: &str, cwd: &str) -> FsResult<()> {
    let (parent_path, name) = split_path_async(path, cwd);
    let parent = resolve_path_async(&parent_path, cwd).await?;
    parent.mkdir_async(&name, FileMode::DEFAULT_DIR).await?;
    Ok(())
}

/// ファイルを非同期に作成/更新
pub async fn touch_file_async(path: &str, cwd: &str) -> FsResult<()> {
    let (parent_path, name) = split_path_async(path, cwd);
    let parent = resolve_path_async(&parent_path, cwd).await?;

    match parent.lookup_async(&name).await {
        Ok(_) => Ok(()),
        Err(FsError::NotFound) => {
            parent
                .create_async(&name, FileMode::DEFAULT_FILE, OpenFlags::default())
                .await?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// ファイルを非同期に削除
pub async fn remove_file_async(path: &str, cwd: &str) -> FsResult<()> {
    let (parent_path, name) = split_path_async(path, cwd);
    let parent = resolve_path_async(&parent_path, cwd).await?;
    parent.unlink_async(&name).await
}

/// ディレクトリを非同期に削除
pub async fn remove_directory_async(path: &str, cwd: &str) -> FsResult<()> {
    let (parent_path, name) = split_path_async(path, cwd);
    let parent = resolve_path_async(&parent_path, cwd).await?;
    parent.rmdir_async(&name).await
}

/// ファイルに内容を非同期に書き込み
pub async fn write_file_content_async(path: &str, cwd: &str, content: &[u8]) -> FsResult<()> {
    let inode = match resolve_path_async(path, cwd).await {
        Ok(inode) => inode,
        Err(FsError::NotFound) => {
            let (parent_path, name) = split_path_async(path, cwd);
            let parent = resolve_path_async(&parent_path, cwd).await?;
            parent
                .create_async(&name, FileMode::DEFAULT_FILE, OpenFlags::default())
                .await?
        }
        Err(e) => return Err(e),
    };

    inode.truncate_async(0).await?;
    inode.write_async(0, content).await?;
    Ok(())
}

/// ファイル/ディレクトリの情報を非同期に取得
pub async fn stat_file_async(path: &str, cwd: &str) -> FsResult<FileAttr> {
    let inode = resolve_path_async(path, cwd).await?;
    inode.getattr_async().await
}

/// ファイルをコピー（非同期版）
pub async fn copy_file_async(src: &str, dst: &str, cwd: &str) -> FsResult<()> {
    // ソースを読み取り
    let content = read_file_content_async(src, cwd).await?;
    // 宛先に書き込み
    write_file_content_async(dst, cwd, &content).await
}

// ヘルパー関数: パスを親パスとファイル名に分割
fn split_path_async(path: &str, cwd: &str) -> (String, String) {
    use alloc::format;

    // 絶対パスを構築
    let abs_path = if path.starts_with('/') {
        path.to_string()
    } else if cwd == "/" {
        format!("/{}", path)
    } else {
        format!("{}/{}", cwd, path)
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let bytes = Bytes::new(data.clone());

        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_bytes_clone_shares_data() {
        let data = vec![1, 2, 3, 4, 5];
        let bytes1 = Bytes::new(data);
        let bytes2 = bytes1.clone();

        // 両方とも同じデータを参照
        assert_eq!(bytes1.as_slice(), bytes2.as_slice());
        // 内部のArcがクローンされている（参照カウント増加）
        assert_eq!(Arc::strong_count(&bytes1.inner), 2);
    }

    #[test]
    fn test_bytes_empty() {
        let bytes = Bytes::empty();
        assert!(bytes.is_empty());
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn test_bytes_from_slice() {
        let slice: &[u8] = &[10, 20, 30];
        let bytes: Bytes = slice.into();
        assert_eq!(bytes.as_slice(), &[10, 20, 30]);
    }

    #[test]
    fn test_split_path_absolute() {
        let (parent, name) = split_path_async("/home/user/file.txt", "/");
        assert_eq!(parent, "/home/user");
        assert_eq!(name, "file.txt");
    }

    #[test]
    fn test_split_path_relative() {
        let (parent, name) = split_path_async("file.txt", "/home/user");
        assert_eq!(parent, "/home/user");
        assert_eq!(name, "file.txt");
    }

    #[test]
    fn test_split_path_root() {
        let (parent, name) = split_path_async("/file.txt", "/");
        assert_eq!(parent, "/");
        assert_eq!(name, "file.txt");
    }
}
