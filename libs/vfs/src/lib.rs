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
//! - `FileSystem`: ファイルシステム全体の操作（ルート取得、マウント等）
//! - `VfsNode`: ファイルまたはディレクトリを表す抽象ノード
//! - `File`: 開かれたファイルの操作（読み書き、シーク）
//! - `Directory`: ディレクトリの操作（エントリ列挙、検索）
//!

#![no_std]
#![allow(clippy::use_self)] // Explicit type names in From impl for clarity
#![allow(clippy::bool_assert_comparison)] // assert_eq!(x, true) clearer in tests

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub mod block;
pub mod cache;
pub mod error;
pub mod path;
pub mod types;

pub use error::{VfsError, VfsResult};
pub use path::Path;
pub use types::{FileMode, FileType, InodeNum, Metadata, OpenFlags, SeekFrom};

/// ファイルシステムトレイト
pub trait FileSystem: Send + Sync {
    /// ルートディレクトリを取得
    fn root_dir(&self) -> VfsResult<Box<dyn VfsNode>>;

    /// ファイルシステム名
    fn name(&self) -> &str;
}

/// VFSノード（ファイルまたはディレクトリ）
pub trait VfsNode: Send + Sync {
    /// メタデータを取得
    fn metadata(&self) -> VfsResult<Metadata>;

    /// ファイルとして開く
    fn open(&self, flags: OpenFlags) -> VfsResult<Box<dyn File>>;

    /// ディレクトリとして開く
    fn as_dir(&self) -> VfsResult<Box<dyn Directory>>;

    /// 名前を取得
    fn name(&self) -> String;
}

/// ファイル操作トレイト
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

/// ディレクトリオペレーション
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

/// ディレクトリエントリ
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub file_type: FileType,
    pub metadata: Metadata,
}

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
