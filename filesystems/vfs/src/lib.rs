// ============================================================================
// libs/vfs/src/lib.rs - Virtual File System Abstraction
// ============================================================================
//!
//! # Virtual File System (VFS)
//!
//! ファイルシステムの抽象化レイヤー。
//! 異なるファイルシステム（FAT32, Ext2, MemFS等）を統一的に扱うためのトレイトと型を定義。
//!
//! ## 主なコンポーネント
//!
//! ### 高レベルAPI（シンプル）
//! - [`FileSystem`] - ファイルシステム全体の操作（ルート取得、マウント等）
//! - [`VfsNode`] - ファイルまたはディレクトリを表す抽象ノード
//! - [`File`] - 開かれたファイルの操作（読み書き、シーク）
//! - [`Directory`] - ディレクトリの操作（エントリ列挙、検索）
//!
//! ### 低レベルAPI（POSIX互換）
//! - [`Inode`] - POSIX互換のInode抽象化
//! - [`ExtendedFileSystem`] - 統計情報やsync等の拡張操作をサポート
//!
//! ## 使い分け
//!
//! - **シンプルなファイルシステム**: `FileSystem` + `VfsNode` を実装
//! - **フル機能のファイルシステム**: `ExtendedFileSystem` + `Inode` を実装
//!

#![no_std]
#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::use_self)] // Explicit type names in From impl for clarity
#![allow(clippy::match_same_arms)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::bool_assert_comparison)] // assert_eq!(x, true) clearer in tests

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::sync::Arc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub mod block;
pub mod cache;
pub mod error;
#[cfg(feature = "alloc")]
pub mod inode;
pub mod path;
pub mod types;

pub use error::{VfsError, VfsResult};
pub use path::Path;
pub use types::{
    FileAttr, FileMode, FileType, FsStats, InodeNum, Metadata, OpenFlags, SeekFrom, UnixFileMode,
};

// Block device types
pub use block::SECTOR_SIZE;

// Inode-related types (require alloc)
#[cfg(feature = "alloc")]
pub use inode::Inode;
#[cfg(feature = "alloc")]
pub use types::DirEntry as InodeDirEntry;

// ============================================================================
// Simple FileSystem Trait (High-level API)
// ============================================================================

/// シンプルなファイルシステムトレイト
///
/// 基本的なファイルシステム操作を提供します。
/// より高度な機能が必要な場合は [`ExtendedFileSystem`] を使用してください。
#[cfg(feature = "alloc")]
pub trait FileSystem: Send + Sync {
    /// ルートディレクトリを取得
    fn root_dir(&self) -> VfsResult<Box<dyn VfsNode>>;

    /// ファイルシステム名
    fn name(&self) -> &str;
}

// ============================================================================
// Extended FileSystem Trait (Low-level API)
// ============================================================================

/// 拡張ファイルシステムトレイト
///
/// POSIX互換のフル機能ファイルシステム操作を提供します。
/// Inode ベースのファイルシステム実装向け。
#[cfg(feature = "alloc")]
pub trait ExtendedFileSystem: Send + Sync {
    /// ファイルシステム名
    fn name(&self) -> &str;

    /// ルートInodeを取得
    fn root(&self) -> VfsResult<Arc<dyn Inode>>;

    /// ファイルシステム統計情報を取得
    fn statfs(&self) -> VfsResult<FsStats>;

    /// 保留中の書き込みをストレージに同期
    fn sync(&self) -> VfsResult<()>;

    /// ファイルシステムをアンマウント
    fn unmount(&self) -> VfsResult<()>;
}

// ============================================================================
// VfsNode Trait (High-level API)
// ============================================================================

/// VFSノード（ファイルまたはディレクトリ）
#[cfg(feature = "alloc")]
pub trait VfsNode: Send + Sync {
    /// メタデータを取得
    fn metadata(&self) -> VfsResult<Metadata>;

    /// ファイルとして開く
    fn open(&self, flags: OpenFlags) -> VfsResult<Box<dyn File>>;

    /// ディレクトリとして開く
    fn as_dir(&self) -> VfsResult<Box<dyn Directory>>;

    /// 名前を取得
    fn name(&self) -> String;

    /// Any型へのダウンキャスト用
    fn as_any(&self) -> &dyn core::any::Any;
}

// ============================================================================
// File Trait
// ============================================================================

/// ファイル操作トレイト
#[cfg(feature = "alloc")]
pub trait File: Send + Sync {
    /// 読み込み
    fn read(&mut self, buf: &mut [u8]) -> VfsResult<usize>;

    /// 書き込み
    fn write(&mut self, buf: &[u8]) -> VfsResult<usize>;

    /// シーク
    fn seek(&mut self, pos: SeekFrom) -> VfsResult<u64>;

    /// フラッシュ
    fn flush(&mut self) -> VfsResult<()>;

    /// サイズ変更
    fn set_len(&mut self, size: u64) -> VfsResult<()>;
}

// ============================================================================
// Directory Trait
// ============================================================================

/// ディレクトリオペレーション
#[cfg(feature = "alloc")]
pub trait Directory: Send + Sync {
    /// エントリを検索
    fn lookup(&self, name: &str) -> VfsResult<Box<dyn VfsNode>>;

    /// エントリを作成
    fn create(&mut self, name: &str, file_type: FileType) -> VfsResult<Box<dyn VfsNode>>;

    /// エントリを削除
    fn remove(&mut self, name: &str) -> VfsResult<()>;

    /// エントリを列挙
    fn read_dir(&mut self) -> VfsResult<Vec<DirEntry>>;
}

// ============================================================================
// Directory Entry (Simple)
// ============================================================================

/// ディレクトリエントリ（シンプル版）
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub file_type: FileType,
    pub metadata: Metadata,
}

// ============================================================================
// Error Conversions
// ============================================================================

impl From<block::BlockError> for VfsError {
    fn from(err: block::BlockError) -> Self {
        match err {
            block::BlockError::NotReady => VfsError::IoError,
            block::BlockError::InvalidBlock => VfsError::InvalidInput,
            block::BlockError::IoError => VfsError::IoError,
            block::BlockError::ReadOnly => VfsError::ReadOnly,
            block::BlockError::InvalidBufferSize => VfsError::InvalidInput,
            block::BlockError::QueueFull => VfsError::IoError,
            block::BlockError::Timeout => VfsError::IoError,
        }
    }
}

#[cfg(feature = "qemu-test-export")]
#[allow(clippy::must_use_candidate)]
pub mod qemu_tests {
    use super::path::Path;
    use super::{block, cache};

    pub fn path_join_smoke() -> bool {
        let p = Path::new("/sys");
        let joined = p.join("kernel");
        joined.as_str() == "/sys/kernel"
    }

    pub fn path_parent_smoke() -> bool {
        let p = Path::new("/var/log/kmsg");
        p.parent().is_some_and(|v| v.as_str() == "/var/log")
    }

    pub fn ramdisk_read_write_sync_smoke() -> bool {
        block::qemu_tests::ramdisk_read_write_sync_smoke()
    }

    pub fn ramdisk_read_write_multiple_blocks_smoke() -> bool {
        block::qemu_tests::ramdisk_read_write_multiple_blocks_smoke()
    }

    pub fn borrowed_read_into_invalid_size_smoke() -> bool {
        block::qemu_tests::read_into_buf_invalid_size_smoke()
    }

    pub fn borrowed_read_into_fallback_smoke() -> bool {
        block::qemu_tests::read_into_buf_default_fallback_smoke()
    }

    pub fn borrowed_write_from_fallback_smoke() -> bool {
        block::qemu_tests::write_from_buf_default_fallback_smoke()
    }

    pub fn page_cache_smoke() -> bool {
        cache::qemu_tests::cached_page_smoke()
            && cache::qemu_tests::page_pin_smoke()
            && cache::qemu_tests::page_cache_smoke()
    }

    pub fn block_cache_smoke() -> bool {
        cache::qemu_tests::block_cache_basic_smoke()
            && cache::qemu_tests::block_cache_lru_eviction_smoke()
            && cache::qemu_tests::block_cache_dirty_tracking_smoke()
            && cache::qemu_tests::block_cache_flush_smoke()
    }
}
