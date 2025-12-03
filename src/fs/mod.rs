// ============================================================================
// src/fs/mod.rs - Filesystem Abstraction Layer
// ============================================================================
//!
//! # ファイルシステム抽象化レイヤー
//!
//! ## 設計原則 (仕様書 6.3準拠)
//! - 非同期ファイルI/O API
//! - ページキャッシュ (Arc<Vec<u8>>)
//! - fs_abstraction: オプショナルなFS抽象化（旧称: VFS）
//! - ブロックデバイス抽象化
//!
//! ## 高速パス vs 互換パス
//! - **高速パス**: NVMeポーリングによる直接ブロックアクセス（推奨）
//! - **互換パス**: fs_abstractionを経由したファイルシステムアクセス

#![allow(dead_code)]

// FS抽象化レイヤー（旧称: vfs → オプショナルな層であることを明確化）
pub mod fs_abstraction;
// 後方互換性のためのエイリアス
pub use fs_abstraction as vfs;

pub mod async_ops;
pub mod block;
pub mod cache;
pub mod devfs;
pub mod ext2;
pub mod fat32;
pub mod procfs;

#[allow(unused_imports)]
pub use async_ops::{
    // 非同期ファイル操作
    AsyncFile,
    AsyncIoRequest,
    // I/Oスケジューラ
    AsyncIoScheduler,
    AsyncIoType,
    // ダイレクトブロックアクセス
    DirectBlockHandle,
    IoSchedulerStats,
    // Scatter-Gather I/O
    SgEntry,
    SgIoRequest,
    async_io_scheduler,
};
#[allow(unused_imports)]
pub use block::{BlockDevice, BlockRequest, RequestType};
#[allow(unused_imports)]
pub use cache::{CacheStats, CachedPage, PageCache};
#[allow(unused_imports)]
pub use devfs::{
    ConsoleDevice, DevEntry, DevError, DevFileHandle, DevFs, DevInode, DeviceNumber, DeviceOps,
    DeviceType, FullDevice, NullDevice, RandomDevice, ZeroDevice, devfs,
};
#[allow(unused_imports)]
pub use ext2::Ext2FileSystem;
#[allow(unused_imports)]
pub use fat32::Fat32FileSystem;
#[allow(unused_imports)]
pub use fs_abstraction::{
    AsyncReadFuture, AsyncWriteFuture, DirEntry, FileAttr, FileHandle, FileMode, FileSystem,
    FileType, FsError, FsResult, FsStats, Inode, MountTable, OpenFlags, PathResolver, SeekFrom,
    mount_table,
};
#[allow(unused_imports)]
pub use procfs::{
    Pid as ProcPid, ProcEntry, ProcError, ProcFileHandle, ProcFileType, ProcFs, ProcInode, procfs,
};
