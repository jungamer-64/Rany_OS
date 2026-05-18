// ============================================================================
// src/fs/mod.rs - Filesystem Abstraction Layer
// ============================================================================
//!
//! # カーネル内ファイルシステム面
//!
//! ## 設計原則 (仕様書 6.3準拠)
//! - 非同期ファイルI/O API
//! - ページキャッシュ (Arc<Vec<u8>>)
//! - memfs と非同期ファイル操作の共有型
//! - ブロックデバイス I/O 境界
//!
//! ## 高速パス
//! - **高速パス**: NVMeポーリングによる直接ブロックアクセス
//! - **ローカルFS面**: memfs とカーネルサービスが共有する最小型
pub mod fs_model;

pub mod async_ops;
pub mod cache;
pub mod page_cluster_buffer;

pub mod block {
    //! ブロックデバイスI/O境界
    pub use kernel_api::block_io::*;
}

pub mod async_memfs;
pub mod memfs;
pub mod page;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;
pub use async_memfs::{
    // Async Inode trait and wrapper
    AsyncInode,
    AsyncMemoryFs,
    AsyncMemoryInode,
    Bytes,
    // Async shell integration APIs
    copy_file_async,
    list_directory_async,
    make_directory_async,
    read_file_content_async,
    read_file_zero_copy_async,
    remove_directory_async,
    remove_file_async,
    resolve_path_async,
    stat_file_async,
    touch_file_async,
    write_file_content_async,
};
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
pub use block::*;
pub use cache::{CacheStats, CachedPage, PageCache, init_page_cache, page_cache};
pub use fs_model::{
    AsyncReadFuture, AsyncWriteFuture, DirEntry, FileAttr, FileHandle, FileMode, FileSystem,
    FileType, FsError, FsResult, FsStats, Inode, InodeNum, MountTable, OpenFlags, PathResolver,
    SeekFrom, mount_table, write_inode_by_number,
};
pub use memfs::{
    MemoryFs, MemoryInode, copy_file, copy_file_cow, create_symlink, init_shell_fs, list_directory,
    make_directory, move_file, read_file_content, remove_directory, remove_file, resolve_path,
    shell_fs, stat_file, touch_file, write_file_content,
};
pub use page::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE, Page, PagedContent, new_zero_page};
