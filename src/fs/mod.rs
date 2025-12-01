// ============================================================================
// src/fs/mod.rs - Filesystem Abstraction Layer
// ============================================================================
//!
//! ファイルシステム抽象化レイヤー
//!
//! ## 設計原則 (仕様書 6.3準拠)
//! - 非同期ファイルI/O API
//! - ページキャッシュ (Arc<Vec<u8>>)
//! - VFS (Virtual Filesystem) 抽象化
//! - ブロックデバイス抽象化

#![allow(dead_code)]

pub mod vfs;
pub mod cache;
pub mod block;

pub use vfs::{
    FileSystem, Inode, DirEntry, FileType, FileMode,
    OpenFlags, SeekFrom, FsError,
};
pub use cache::{PageCache, CachedPage, CacheStats};
pub use block::{BlockDevice, BlockRequest, RequestType};
