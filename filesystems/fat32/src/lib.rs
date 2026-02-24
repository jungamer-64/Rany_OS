// ============================================================================
// filesystems/fat32/src/lib.rs - FAT32 Filesystem Implementation (Type-Safe)
// ============================================================================
//!
//! # FAT32ファイルシステム (型安全版)
//!
//! FAT32形式のファイルシステム実装。
//! USBメモリ、SDカード等の読み書きに対応。
//!
//! ## 機能
//! - FAT32パーティション解析
//! - ディレクトリ読み取り/作成
//! - ファイル読み取り/書き込み
//! - ロングファイルネーム(LFN)サポート
//!   - LFNチェックサム検証による完全性確認
//!
//! ## 型安全性の改善
//! - Newtype パターン(`Cluster`, `Sector`)による取り違え防止
//! - `FileAttributes` による属性の型安全な管理
//! - `SafePackedRead` トレイトによる packed 構造体への安全なアクセス
//!
//! ## セキュリティ機能
//! - **競合状態対策**: アトミックなクラスタ割り当て(TOCTO脆弱性排除)
//! - **無限ループ対策**: クラスタチェーン探索に上限を設定
//! - **算術オーバーフロー対策**: クラスタ番号の検証
//! - **LFNチェックサム検証**: 悪意のあるファイルシステムイメージ対策
//! - **パス長制限**: DOS互換の最大260文字制限
//!
//! ## 既知の制限事項
//! - FATセクタキャッシュは固定サイズのため、アクセス偏りが強いとミスが増える
//! - クラスタ割り当て等の一部操作は整合性優先で即時ディスクI/Oを行う
//! - **Unicode Case Folding未対応**: ファイル名比較はASCII範囲のみ大小無視で比較。
//!   日本語等の非ASCII文字は完全一致が必要。`Ü` と `ü` は異なるファイルとして扱われる。
//!
//! ## 将来の改善予定
//! - ~~LRUキャッシュによるFATテーブルのオンデマンド読み込み~~ ✅ 実装済み（FatSectorCache）
//! - ~~ダーティフラグ管理によるバッチ書き込み~~ ✅ 実装済み（sync()で一括フラッシュ）
//! - ディレクトリエントリキャッシュによる繰り返し走査の高速化
//! - より高度なフラグメンテーション対策

#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)] // OpenFlags parameter for future use
#![allow(clippy::len_without_is_empty)] // ByteCount has explicit is_empty method

extern crate alloc;

// poison_lockは libs/sync から使用するため、ローカルモジュールを削除
mod async_mutex;
mod buffer_pool;
mod cache;
mod cluster_chain;
mod dir_builder;
mod dir_iter;
mod error;
mod irq_lock;
mod ondisk;
mod sfn;
mod time;
mod types;

mod format;
mod fs_cluster_io;
mod fs_core;
mod fs_mount;
mod fs_trait_impl;
mod fsck;
mod inode_constructors;
mod inode_dir_entries;
mod inode_dir_ops;
mod inode_file_io;
mod inode_metadata;
mod inode_vfs_impl;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

pub use buffer_pool::{
    ClusterBuffer, ClusterBufferAllocator, ClusterBufferPool, PooledClusterBuffer,
    VecClusterBufferAllocator,
};
pub use cache::{DirEntryCache, FatSectorCache};
pub use cluster_chain::ClusterChain;
pub use dir_builder::DirEntryBuilder;
pub use dir_iter::DirectoryIterator;
pub use error::{Fat32Error, Fat32Result, ResultExt};
pub use format::FormatOptions;
pub use fsck::{FsckIssue, FsckResult};
pub use ondisk::{
    BiosParameterBlock, BootSector, DirEntryRaw, Fat32ExtendedBpb, FsInfo, LfnEntry, SafePackedRead,
};
pub use sfn::{DirectoryEntryKind, collect_existing_sfns, generate_unique_sfn, long_name_to_sfn};
pub use time::{DummyTimeProvider, TimeProvider, dos_to_unix, unix_to_dos};
pub use types::{ByteCount, Cluster, ClusterExt, FileAttributes, FileOffset, NextCluster, Sector};

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use async_mutex::AsyncMutex;
use core::convert::TryFrom;
use core::fmt;
use core::ops::{Add, Sub};
use hashbrown::{HashMap, HashSet};
use irq_lock::IrqPoisonLock;
use ondisk::FSINFO_UNKNOWN;

use vfs::block::{
    BlockDevice, BlockDeviceZeroCopyAdapter, BlockError, OwnedBytes, ZeroCopyBlockDevice,
    ZeroCopyBuffer, ZeroCopyBufferMut,
};
use vfs::cache::LRUBlockCache;
use vfs::{
    DirEntry, FileMode, FileSystem, FileType, Metadata as FileAttr, OpenFlags, VfsError as FsError,
    VfsNode as Inode, VfsResult as FsResult,
};

// ============================================================================
// Debug Tracing Macros
// ============================================================================

/// FAT操作のトレースマクロ（debug-traceフィーチャー有効時のみ）
///
/// # Example
/// ```ignore
/// trace_fat_operation!("allocate", cluster);
/// trace_fat_operation!("read_chain", start_cluster, "length={}", chain_length);
/// ```
#[allow(unused_macros)]
#[cfg(feature = "debug-trace")]
macro_rules! trace_fat_operation {
    ($op:expr, $cluster:expr) => {
        log::trace!("[FAT32] {}: cluster {}", $op, $cluster.0);
    };
    ($op:expr, $cluster:expr, $($arg:tt)*) => {
        log::trace!("[FAT32] {}: cluster {} - {}", $op, $cluster.0, format_args!($($arg)*));
    };
}

#[allow(unused_macros)]
#[cfg(not(feature = "debug-trace"))]
macro_rules! trace_fat_operation {
    ($op:expr, $cluster:expr) => {};
    ($op:expr, $cluster:expr, $($arg:tt)*) => {};
}

// ============================================================================
// Constants
// ============================================================================

/// 最大クラスタチェーン長(無限ループ検出用)
const MAX_CLUSTER_CHAIN: usize = 0x10000000; // 268M clusters = 約1TB @ 4KB/cluster
/// 無限ループ検出のスキャン間隔
const CYCLE_CHECK_INTERVAL: usize = 1024;
/// 最大パス長(DOS互換)
const MAX_PATH_LEN: usize = 260;
/// 最大ファイル名長(単一コンポーネント)
const MAX_NAME_LEN: usize = 255;

/// LFN のパート数上限 (1パートにつき最大13 UCS-2文字、20パートで255文字)
const MAX_LFN_PARTS: usize = 26; // 許容範囲: 26で余裕を持たせる

/// Default zero-copy buffer type (Vec-backed compatibility).
pub type DefaultZeroCopyBuffer = OwnedBytes;

/// Zero-copy read segment (buffer + subrange).
pub struct ZeroCopySegment<B> {
    pub buffer: B,
    pub offset: usize,
    pub len: usize,
}

/// Zero-copy read result (single contiguous buffer or scatter list).
pub enum ZeroCopyRead<B> {
    Single(ZeroCopySegment<B>),
    Scatter(Vec<ZeroCopySegment<B>>),
}

impl<B: ZeroCopyBuffer> ZeroCopyRead<B> {
    /// Total length in bytes across all segments.
    pub fn len(&self) -> usize {
        match self {
            ZeroCopyRead::Single(seg) => seg.len,
            ZeroCopyRead::Scatter(segments) => segments.iter().map(|seg| seg.len).sum(),
        }
    }

    /// Check if the result is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Default FAT32 filesystem type (Vec-backed zero-copy compatibility).
pub type DefaultFat32FileSystem = Fat32FileSystem<DefaultZeroCopyBuffer>;

/// パス長が制限内かチェック
fn validate_path_length(path: &str) -> FsResult<()> {
    if path.len() > MAX_PATH_LEN {
        return Err(FsError::InvalidInput);
    }
    // 各パスコンポーネントもチェック
    for component in path.split('/').filter(|s| !s.is_empty()) {
        if component.len() > MAX_NAME_LEN {
            return Err(FsError::InvalidInput);
        }
    }
    Ok(())
}

// ============================================================================
// Cache Constants
// ============================================================================

// FAT Sector Cache (LRU-based On-Demand Loading)
// ============================================================================

/// FATセクタの数（1セクタ = 512バイト = 128エントリ）
const FAT_ENTRIES_PER_SECTOR: usize = BLOCK_SIZE / 4;

/// デフォルトのFATセクタキャッシュサイズ（セクタ数）
/// 256セクタ × 128エントリ × 4バイト = 128KB相当のFATをキャッシュ
const DEFAULT_FAT_SECTOR_CACHE_SIZE: usize = 256;

// ============================================================================
// Directory Entry Cache (Parsed Entry Caching)
// ============================================================================

/// ディレクトリごとのキャッシュサイズデフォルト
const DEFAULT_DIR_CACHE_SIZE: usize = 16;

// ============================================================================
// Block/On-disk Constants
// ============================================================================

/// ブロック/セクタサイズ
const BLOCK_SIZE: usize = 512;

// ============================================================================

// State Machine Pattern for FAT Entry Operations
// ============================================================================

/// FATエントリ操作のための型安全な状態機械モジュール
///
/// このモジュールは「状態機械パターン(Typestate Pattern)」を実装し、
/// FATエントリの状態遷移をコンパイル時に検証可能にします。
///
/// # Design Philosophy
/// - Free状態からのみallocate()が可能
/// - Allocated状態からlink_to()やmark_eof()が可能  
/// - 無効な状態遷移はコンパイル時にエラー
///
/// # Example
/// ```ignore
/// // 空きエントリを確保
/// let free_entry = FatEntry::new_free(cluster);
/// let allocated = free_entry.allocate()?;
///
/// // チェーンの終端としてマーク
/// let eof = allocated.mark_eof()?;
///
/// // または次のクラスタにリンク
/// let linked = allocated.link_to(next_cluster)?;
/// ```
pub mod fat_entry_state;

// ============================================================================
// On-disk Entry Constants
// ============================================================================

/// ブートセクタのサイズ
const BOOT_SECTOR_SIZE: usize = 512;

/// FAT32のマジックシグネチャ
const FAT32_SIGNATURE: u16 = 0xAA55;

/// ディレクトリエントリのサイズ
const DIR_ENTRY_SIZE: usize = 32;

/// 削除済みエントリのマーカー
const DELETED_ENTRY: u8 = 0xE5;

/// 最後のエントリのマーカー
const END_OF_DIR: u8 = 0x00;

// ============================================================================
// FAT32 Filesystem
// ============================================================================

/// FAT32ファイルシステム
///
/// # FATキャッシュ
/// FATはセクタ単位のLRUキャッシュ（`FatSectorCache`）のみを使用し、
/// 全体キャッシュは行わない。

pub struct Fat32FileSystem<B: ZeroCopyBufferMut + 'static> {
    /// Self weak reference for obtaining Arc<Self> without cloning
    self_weak: Weak<Fat32FileSystem<B>>,
    /// ブロックデバイス（互換パス用、ゼロコピー環境ではNone）
    legacy_device: Option<Arc<dyn BlockDevice>>,
    /// ゼロコピー対応ブロックデバイス
    zc_device: Arc<dyn ZeroCopyBlockDevice<Buffer = B>>,
    /// デバイスID（キャッシュキー用）
    device_id: u64,
    /// FATの開始セクタ（型安全）
    fat_start_sector: Sector,
    /// データ領域の開始セクタ（型安全）
    data_start_sector: Sector,
    /// クラスタあたりのセクタ数
    sectors_per_cluster: u32,
    /// 総クラスタ数
    total_clusters: u32,
    /// ルートディレクトリのクラスタ（型安全）
    root_cluster: Cluster,
    /// FATセクタキャッシュ（LRU）
    ///
    /// セクタ単位でFATをキャッシュし、メモリ使用量を制限する。
    fat_sector_cache: FatSectorCache,
    /// 空きクラスタ数
    free_clusters: AsyncMutex<u32>,
    /// FATサイズ（セクタ数）
    fat_size: u32,
    /// ブロックキャッシュ（LRU、O(1)操作）
    ///
    /// FATセクタとデータクラスタの両方をキャッシュ。
    /// デフォルトで32MBまでキャッシュ可能。
    block_cache: Arc<LRUBlockCache>,
    /// クラスタバッファプール
    cluster_buffer_pool: Arc<ClusterBufferPool>,
    /// 時刻プロバイダー（RTC連携用）
    time_provider: Arc<dyn TimeProvider>,
    /// FSInfoセクタ番号
    fs_info_sector: Sector,
    /// ディレクトリエントリキャッシュ
    dir_cache: DirEntryCache,
}

// ============================================================================
// FAT32 Inode
// ============================================================================

/// LFNパーツとSFNエントリから名前を解決する（検索用簡易版）
fn resolve_lfn_name_from_parts(lfn_parts: &[(u8, String, u8)], raw: &DirEntryRaw) -> String {
    if lfn_parts.is_empty() {
        return raw.short_name();
    }
    let expected_checksum = raw.calculate_checksum();
    if lfn_parts
        .first()
        .map_or(false, |&(_, _, cs)| cs == expected_checksum)
    {
        let mut sorted: Vec<_> = lfn_parts.to_vec();
        sorted.sort_by_key(|&(seq, _, _)| seq);
        sorted.iter().map(|(_, s, _)| s.as_str()).collect()
    } else {
        raw.short_name()
    }
}

/// 1クラスタ分のバッファ内でSFN名を検索する。
/// 見つかった場合は `Ok(Some(Some((cluster, offset))))` を返す。
/// End エントリで `Ok(Some(None))` を返す。
/// まだ見つかっていない場合は `Ok(None)` を返す。
fn search_cluster_for_sfn(
    buffer: &[u8],
    entries_per_cluster: usize,
    name_to_find: &str,
    lfn_parts: &mut Vec<(u8, String, u8)>,
    cluster: Cluster,
) -> FsResult<Option<Option<(Cluster, usize)>>> {
    for i in 0..entries_per_cluster {
        let offset = i * DIR_ENTRY_SIZE;
        let entry_bytes = &buffer[offset..offset + DIR_ENTRY_SIZE];

        match DirectoryEntryKind::from(entry_bytes) {
            DirectoryEntryKind::End => return Ok(Some(None)),
            DirectoryEntryKind::Deleted | DirectoryEntryKind::VolumeLabel => {
                lfn_parts.clear();
            }
            DirectoryEntryKind::LongName(lfn) => {
                if lfn_parts.len() >= MAX_LFN_PARTS {
                    return Err(FsError::FileSystemCorrupted);
                }
                lfn_parts.push((lfn.sequence(), lfn.get_name_part(), lfn.checksum()));
            }
            DirectoryEntryKind::Standard(raw) => {
                let name = resolve_lfn_name_from_parts(lfn_parts, &raw);
                lfn_parts.clear();
                if name.eq_ignore_ascii_case(name_to_find) {
                    return Ok(Some(Some((cluster, offset))));
                }
            }
        }
    }
    Ok(None)
}

/// FAT32 inode
pub struct Fat32Inode<B: ZeroCopyBufferMut + 'static> {
    /// ファイルシステム
    fs: Arc<Fat32FileSystem<B>>,
    /// ファイルタイプ
    file_type: FileType,
    /// 内部可変状態
    inner: AsyncMutex<Fat32InodeInner>,
}

#[derive(Debug, Clone)]
struct Fat32InodeInner {
    /// 開始クラスタ（型安全）
    first_cluster: Cluster,
    /// ファイルサイズ
    size: u64,
    /// 親ディレクトリのクラスタ（型安全）
    parent_cluster: Cluster,
    /// エントリ名
    name: String,
    /// 属性
    attributes: FileAttributes,
    /// 作成日時 (Unix epoch seconds)
    created: u64,
    /// 更新日時 (Unix epoch seconds)
    modified: u64,
    /// 最終アクセス日時 (Unix epoch seconds)
    accessed: u64,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn try_alloc_vec<T: Clone>(len: usize, value: T) -> FsResult<Vec<T>> {
    let mut buf = Vec::new();
    if buf.try_reserve_exact(len).is_err() {
        return Err(FsError::Other);
    }
    buf.resize(len, value);
    Ok(buf)
}

// ============================================================================
// VFS Implementations
// ============================================================================

pub struct Fat32File<B: ZeroCopyBufferMut + 'static> {
    inode: Arc<Fat32Inode<B>>,
    position: u64,
}

pub struct Fat32Directory<B: ZeroCopyBufferMut + 'static> {
    inode: Arc<Fat32Inode<B>>,
}
