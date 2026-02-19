// ============================================================================
// libs/vfs/src/inode.rs - Inode Abstraction
// ============================================================================
//!
//! Inodeトレイトと関連型の定義。
//!
//! Inodeはファイルシステム内のファイルやディレクトリを表す抽象化です。
//! カーネルとファイルシステム実装の両方で共通して使用されます。

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::sync::Arc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use core::any::Any;

use crate::error::VfsResult;
use crate::types::{FileAttr, FileType, OpenFlags, UnixFileMode};

// ============================================================================
// Inode Trait
// ============================================================================

/// Inode操作トレイト
///
/// ファイルシステム内のファイルやディレクトリを表す抽象化。
/// 各ファイルシステム実装はこのトレイトを実装します。
///
/// # 実装ガイドライン
///
/// - 全てのメソッドはデフォルトで`NotSupported`エラーを返す
/// - ファイルシステムは必要なメソッドのみをオーバーライド
/// - ディレクトリ操作（lookup, readdir等）はディレクトリInodeでのみ有効
/// - ファイル操作（read, write等）はファイルInodeでのみ有効
#[cfg(feature = "alloc")]
pub trait Inode: Send + Sync + Any {
    // ========================================================================
    // Type Casting
    // ========================================================================

    /// 具象型へのダウンキャスト用
    fn as_any(&self) -> &dyn Any;

    // ========================================================================
    // Attribute Operations
    // ========================================================================

    /// ファイル属性を取得
    fn getattr(&self) -> VfsResult<FileAttr>;

    /// ファイル属性を設定
    fn setattr(&self, _attr: &FileAttr) -> VfsResult<()> {
        Err(crate::error::VfsError::NotSupported)
    }

    // ========================================================================
    // Directory Operations
    // ========================================================================

    /// ディレクトリ内の名前を検索
    fn lookup(&self, _name: &str) -> VfsResult<Arc<dyn Inode>> {
        Err(crate::error::VfsError::NotADirectory)
    }

    /// ディレクトリエントリを読み取り
    fn readdir(&self, _offset: u64) -> VfsResult<Vec<DirEntry>> {
        Err(crate::error::VfsError::NotADirectory)
    }

    /// ファイルを作成
    fn create(
        &self,
        _name: &str,
        _mode: UnixFileMode,
        _flags: OpenFlags,
    ) -> VfsResult<Arc<dyn Inode>> {
        Err(crate::error::VfsError::NotADirectory)
    }

    /// ディレクトリを作成
    fn mkdir(&self, _name: &str, _mode: UnixFileMode) -> VfsResult<Arc<dyn Inode>> {
        Err(crate::error::VfsError::NotADirectory)
    }

    /// ファイルを削除
    fn unlink(&self, _name: &str) -> VfsResult<()> {
        Err(crate::error::VfsError::NotADirectory)
    }

    /// ディレクトリを削除
    fn rmdir(&self, _name: &str) -> VfsResult<()> {
        Err(crate::error::VfsError::NotADirectory)
    }

    /// ファイルをリネーム
    fn rename(&self, _old_name: &str, _new_dir: &Arc<dyn Inode>, _new_name: &str) -> VfsResult<()> {
        Err(crate::error::VfsError::NotSupported)
    }

    /// ハードリンクを作成
    fn link(&self, _name: &str, _inode: &Arc<dyn Inode>) -> VfsResult<()> {
        Err(crate::error::VfsError::NotSupported)
    }

    /// シンボリックリンクを作成
    fn symlink(&self, _name: &str, _target: &str) -> VfsResult<Arc<dyn Inode>> {
        Err(crate::error::VfsError::NotSupported)
    }

    /// シンボリックリンクのターゲットを読み取り
    fn readlink(&self) -> VfsResult<String> {
        Err(crate::error::VfsError::InvalidInput)
    }

    // ========================================================================
    // File Operations
    // ========================================================================

    /// ファイルからデータを読み取り
    fn read(&self, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
        Err(crate::error::VfsError::IsADirectory)
    }

    /// ファイルにデータを書き込み
    fn write(&self, _offset: u64, _buf: &[u8]) -> VfsResult<usize> {
        Err(crate::error::VfsError::IsADirectory)
    }

    /// ファイルを指定サイズに切り詰め
    fn truncate(&self, _size: u64) -> VfsResult<()> {
        Err(crate::error::VfsError::IsADirectory)
    }

    /// ファイルデータをストレージに同期
    fn fsync(&self, _datasync: bool) -> VfsResult<()> {
        // デフォルトは何もしない（成功）
        Ok(())
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// ファイルタイプを取得
    fn file_type(&self) -> VfsResult<FileType> {
        self.getattr().map(|attr| attr.file_type)
    }

    /// ディレクトリかどうかを判定
    fn is_dir(&self) -> bool {
        self.file_type().is_ok_and(|ft| ft == FileType::Directory)
    }

    /// 通常ファイルかどうかを判定
    fn is_file(&self) -> bool {
        self.file_type().is_ok_and(|ft| ft == FileType::File)
    }

    /// シンボリックリンクかどうかを判定
    fn is_symlink(&self) -> bool {
        self.file_type().is_ok_and(|ft| ft == FileType::Symlink)
    }
}

// ============================================================================
// Directory Entry (re-export from types)
// ============================================================================

#[cfg(feature = "alloc")]
pub use crate::types::DirEntry;

// ============================================================================
// Utility Functions
// ============================================================================

/// Inode参照からArcにダウンキャスト
#[cfg(feature = "alloc")]
pub fn downcast_inode<T: Inode + 'static>(inode: &Arc<dyn Inode>) -> Option<Arc<T>> {
    // 安全のためデフォルトではNone
    // 実際のユースケースでは、具体的な型を直接保持することを推奨
    let _any = inode.as_any();
    None
}
