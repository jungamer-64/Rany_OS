// ============================================================================
// filesystems/nvme_ns/src/lib.rs - NVMe Namespace Filesystem
// ============================================================================
//!
//! # NVMe Namespace ファイルシステム
//!
//! 設計書 6.3 に基づく NVMe Namespace 直接アクセスファイルシステム。
//! FAT32 に代わるカーネルのメイン FS として、NVMe SSD の性能を最大限に引き出す。
//!
//! ## 設計原則
//! - **VFS バイパス**: 従来のブロックレイヤー / ページキャッシュ抽象化を最小化
//! - **Per-Core I/O**: 各 CPU コアごとの Submission/Completion Queue ペアで
//!   ロックフリーコマンド発行
//! - **ゼロコピー**: DMA バッファの所有権移動で不要なコピーを排除
//! - **非同期ファースト**: 全 I/O 操作を `Future` ベースで提供
//!
//! ## ディスクレイアウト
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │  LBA 0          : Superblock (1 block)              │
//! │  LBA 1..B       : Block Bitmap                      │
//! │  LBA B+1..I     : Inode Bitmap                      │
//! │  LBA I+1..T     : Inode Table                       │
//! │  LBA T+1..end   : Data Blocks                       │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! ## VFS トレイトとの統合
//! `vfs::FileSystem` / `vfs::Inode` を実装し、カーネルの `fs_abstraction` レイヤーと
//! 互換性を保つ一方、高速パスでは `DirectBlockHandle` を通じて NVMe コマンドを
//! 直接発行する。

#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod bitmap;
pub mod dir;
pub mod error;
pub mod fs;
pub mod inode;
pub mod layout;
pub mod ondisk;

// Re-exports
pub use bitmap::Bitmap;
pub use dir::{DirEntry, DirEntryIter};
pub use error::{NsError, NsResult};
pub use fs::NvmeNamespaceFs;
pub use inode::NsInode;
pub use layout::{NsLayout, SUPERBLOCK_MAGIC, SuperBlock};
pub use ondisk::{DiskInode, INODE_SIZE, InodeKind, ROOT_INODE_NUM};
