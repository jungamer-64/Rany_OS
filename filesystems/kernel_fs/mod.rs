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
//!
//! ## ブロックデバイス
//! ブロックデバイス関連の型は `vfs::block` から再エクスポートしています。
//! これにより、カーネルとファイルシステム実装で同じ型を共有できます。

#![allow(dead_code)]

// FS抽象化レイヤー（旧称: vfs → オプショナルな層であることを明確化）
pub mod fs_abstraction;

pub mod async_ops;
pub mod cache;
pub mod devfs;
pub mod ext2;
pub mod fat32_adapter;
pub mod page_cluster_buffer;

// ============================================================================
// Block Device (re-exported from vfs)
// ============================================================================
// カーネル内で使用されるブロックデバイス型はvfsから再エクスポート。
// 独自実装は削除し、vfs::blockに統一。
pub mod block {
    //! ブロックデバイス抽象化（vfsから再エクスポート）
    pub use vfs::block::{
        // Core types
        BlockDevice, BlockRequest,
        RequestType,
    };
}

// Kernel-provided page-backed cluster allocator
#[allow(unused_imports)]
pub use page_cluster_buffer::PageClusterBufferAllocator;
pub mod memfs;
pub mod async_memfs;
pub mod page;
pub mod sysfs;
#[cfg(feature = "posix-compat")]
pub mod procfs;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

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
    SgIoFuture,
    SgIoRequest,
    async_io_scheduler,
};
#[allow(unused_imports)]
pub use block::{BlockDevice, BlockRequest, RequestType};
#[allow(unused_imports)]
pub use cache::{CacheStats, CachedPage, PageCache, page_cache, init_page_cache};
#[allow(unused_imports)]
pub use devfs::{
    ConsoleDevice, DevEntry, DevError, DevFileHandle, DevFs, DevInode, DeviceNumber, DeviceOps,
    DeviceType, FullDevice, NullDevice, RandomDevice, ZeroDevice, devfs,
};
#[allow(unused_imports)]
pub use ext2::Ext2FileSystem;
#[allow(unused_imports)]
#[allow(unused_imports)]
pub use fs_abstraction::{
    AsyncReadFuture, AsyncWriteFuture, DirEntry, FileAttr, FileHandle, FileMode, FileSystem,
    FileType, FsError, FsResult, FsStats, Inode, InodeNum, MountTable, OpenFlags, PathResolver, SeekFrom,
    write_inode_by_number, mount_table,
};
#[allow(unused_imports)]
pub use memfs::{
    MemoryFs, MemoryInode, copy_file, copy_file_cow, create_symlink, init_shell_fs, list_directory,
    make_directory, move_file, read_file_content, remove_directory, remove_file, resolve_path,
    shell_fs, stat_file, touch_file, write_file_content,
};
#[cfg(feature = "posix-compat")]
#[allow(unused_imports)]
pub use procfs::{
    Pid as ProcPid, ProcEntry, ProcError, ProcFileHandle, ProcFileType, ProcFs, ProcInode, procfs,
};
#[allow(unused_imports)]
pub use async_memfs::{
    // Async Inode trait and wrapper
    AsyncInode, AsyncMemoryInode, AsyncMemoryFs, Bytes,
    // Async shell integration APIs
    copy_file_async, list_directory_async, make_directory_async,
    read_file_content_async, read_file_zero_copy_async, remove_directory_async,
    remove_file_async, resolve_path_async, stat_file_async, touch_file_async,
    write_file_content_async,
};
#[allow(unused_imports)]
pub use page::{Page, PagedContent, PAGE_SIZE, PAGE_SHIFT, PAGE_MASK, new_zero_page};
