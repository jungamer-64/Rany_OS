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
pub mod async_ops;
pub mod fat32;
pub mod ext2;
pub mod procfs;
pub mod devfs;

#[allow(unused_imports)]
pub use vfs::{
    FileSystem, Inode, DirEntry, FileType, FileMode,
    OpenFlags, SeekFrom, FsError, FsResult, FileAttr, FsStats,
    FileHandle, PathResolver, MountTable, mount_table,
    AsyncReadFuture, AsyncWriteFuture,
};
#[allow(unused_imports)]
pub use cache::{PageCache, CachedPage, CacheStats};
#[allow(unused_imports)]
pub use block::{BlockDevice, BlockRequest, RequestType};
#[allow(unused_imports)]
pub use async_ops::{
    // 非同期ファイル操作
    AsyncFile, AsyncIoRequest, AsyncIoType,
    // ダイレクトブロックアクセス
    DirectBlockHandle,
    // Scatter-Gather I/O
    SgEntry, SgIoRequest,
    // I/Oスケジューラ
    AsyncIoScheduler, IoSchedulerStats, async_io_scheduler,
};
#[allow(unused_imports)]
pub use fat32::Fat32FileSystem;
#[allow(unused_imports)]
pub use ext2::Ext2FileSystem;
#[allow(unused_imports)]
pub use procfs::{
    ProcInode, ProcFileType, ProcEntry, ProcError, ProcFs, ProcFileHandle,
    procfs, Pid as ProcPid,
};
#[allow(unused_imports)]
pub use devfs::{
    DeviceNumber, DeviceType, DevInode, DevEntry, DevError, DevFs,
    DeviceOps, NullDevice, ZeroDevice, FullDevice, RandomDevice, ConsoleDevice,
    DevFileHandle, devfs,
};
