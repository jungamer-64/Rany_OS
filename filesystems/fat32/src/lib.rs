// ============================================================================
// src/fs/fat32.rs - FAT32 Filesystem Implementation (Type-Safe)
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
//! - FATテーブル全体をメモリにキャッシュ(大容量ボリュームでOOMの可能性)
//! - FAT書き込みごとにディスクI/O発生(バッチ処理未実装)
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

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;
use core::ops::{Add, Sub};
use hashbrown::{HashMap, HashSet};
use spin::RwLock;

use vfs::block::BlockError;

use vfs::block::BlockDevice;
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
#[cfg(feature = "debug-trace")]
macro_rules! trace_fat_operation {
    ($op:expr, $cluster:expr) => {
        log::trace!("[FAT32] {}: cluster {}", $op, $cluster.0);
    };
    ($op:expr, $cluster:expr, $($arg:tt)*) => {
        log::trace!("[FAT32] {}: cluster {} - {}", $op, $cluster.0, format_args!($($arg)*));
    };
}

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
/// 最大パス長(DOS互換)
const MAX_PATH_LEN: usize = 260;
/// 最大ファイル名長(単一コンポーネント)
const MAX_NAME_LEN: usize = 255;

/// 最大FAT全体キャッシュサイズ(バイト) - これを超える場合はオンデマンド読み込みを使用
const MAX_FULL_FAT_CACHE_BYTES: usize = 16 * 1024 * 1024; // 16MB デフォルト閾値

/// LFN のパート数上限 (1パートにつき最大13 UCS-2文字、20パートで255文字)
const MAX_LFN_PARTS: usize = 26; // 許容範囲: 26で余裕を持たせる

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
// Time Provider (RTC Integration Hook)
// ============================================================================

/// FAT32ファイルシステムに現在時刻を提供するトレイト
///
/// カーネルのRTCドライバからの時刻取得を可能にするフック。
/// デフォルトでは固定値を返すダミー実装が使用される。
///
/// # Example
/// ```ignore
/// struct KernelTimeProvider;
///
/// impl TimeProvider for KernelTimeProvider {
///     fn current_dos_time(&self) -> u16 {
///         let now = rtc::get_time();
///         ((now.hour as u16) << 11) | ((now.minute as u16) << 5) | (now.second as u16 / 2)
///     }
///
///     fn current_dos_date(&self) -> u16 {
///         let now = rtc::get_date();
///         (((now.year - 1980) as u16) << 9) | ((now.month as u16) << 5) | (now.day as u16)
///     }
/// }
/// ```
pub trait TimeProvider: Send + Sync {
    /// 現在のDOS形式時刻を取得
    ///
    /// ビットレイアウト: hhhhhmmmmmmsssss
    /// - ビット15-11: 時 (0-23)
    /// - ビット10-5: 分 (0-59)
    /// - ビット4-0: 秒/2 (0-29)
    fn current_dos_time(&self) -> u16;

    /// 現在のDOS形式日付を取得
    ///
    /// ビットレイアウト: yyyyyyymmmmddddd
    /// - ビット15-9: 年 (1980年からのオフセット, 0-127)
    /// - ビット8-5: 月 (1-12)
    /// - ビット4-0: 日 (1-31)
    fn current_dos_date(&self) -> u16;
}

/// デフォルトの時刻プロバイダー（固定値を返す）
///
/// テストやRTCが利用できない環境で使用。
/// 2024年1月1日 12:00:00 を返す。
pub struct DummyTimeProvider;

impl TimeProvider for DummyTimeProvider {
    fn current_dos_time(&self) -> u16 {
        // 12:00:00 = (12 << 11) | (0 << 5) | 0
        (12 << 11) | (0 << 5) | 0
    }

    fn current_dos_date(&self) -> u16 {
        // 2024-01-01 = ((2024 - 1980) << 9) | (1 << 5) | 1
        ((2024 - 1980) << 9) | (1 << 5) | 1
    }
}

// ============================================================================
// FAT Sector Cache (LRU-based On-Demand Loading)
// ============================================================================

/// FATセクタの数（1セクタ = 512バイト = 128エントリ）
const FAT_ENTRIES_PER_SECTOR: usize = BLOCK_SIZE / 4;

/// デフォルトのFATセクタキャッシュサイズ（セクタ数）
/// 256セクタ × 128エントリ × 4バイト = 128KB相当のFATをキャッシュ
const DEFAULT_FAT_SECTOR_CACHE_SIZE: usize = 256;

/// FATセクタのLRUキャッシュ
///
/// 大容量ボリュームでFATテーブル全体をメモリに持たないために使用。
/// セクタ単位でキャッシュし、アクセス頻度の低いセクタを自動的に破棄する。
///
/// # スレッド安全性
/// 内部でRwLockを使用しているため、複数スレッドから安全にアクセス可能。
pub struct FatSectorCache {
    /// キャッシュデータ: セクタインデックス -> (エントリ配列, ダーティフラグ)
    cache: RwLock<FatSectorCacheInner>,
    /// 最大キャッシュセクタ数
    max_sectors: usize,
}

/// FatSectorCacheの内部データ
struct FatSectorCacheInner {
    /// セクタデータ: セクタインデックス -> Clusterエントリ配列
    sectors: HashMap<u32, Vec<Cluster>>,
    /// ダーティフラグ: セクタインデックス -> 書き込み必要フラグ
    dirty: HashSet<u32>,
    /// アクセス順序を追跡（最後にアクセスしたものが末尾）
    access_order: Vec<u32>,
}

impl FatSectorCache {
    /// 新しいFATセクタキャッシュを作成
    pub fn new(max_sectors: usize) -> Self {
        Self {
            cache: RwLock::new(FatSectorCacheInner {
                sectors: HashMap::with_capacity(max_sectors),
                dirty: HashSet::new(),
                access_order: Vec::with_capacity(max_sectors),
            }),
            max_sectors,
        }
    }

    /// キャッシュからセクタを取得（存在しない場合はNone）
    pub fn get(&self, sector_index: u32) -> Option<Vec<Cluster>> {
        let mut inner = self.cache.write();

        // まずセクタをクローンして借用を終了させる
        let data = inner.sectors.get(&sector_index).cloned();

        if data.is_some() {
            // クローン後なので安全にaccess_orderを更新可能
            inner.access_order.retain(|&s| s != sector_index);
            inner.access_order.push(sector_index);
        }

        data
    }

    /// セクタをキャッシュに追加
    ///
    /// キャッシュが満杯の場合、最も古いセクタを破棄（ダーティなら先にフラッシュが必要）
    pub fn insert(
        &self,
        sector_index: u32,
        data: Vec<Cluster>,
    ) -> Option<(u32, Vec<Cluster>, bool)> {
        let mut inner = self.cache.write();

        // 既に存在する場合は更新
        if inner.sectors.contains_key(&sector_index) {
            inner.sectors.insert(sector_index, data);
            inner.access_order.retain(|&s| s != sector_index);
            inner.access_order.push(sector_index);
            return None;
        }

        // キャッシュが満杯の場合、最も古いセクタを破棄
        let evicted = if inner.sectors.len() >= self.max_sectors && !inner.access_order.is_empty() {
            let oldest = inner.access_order.remove(0);
            let evicted_data = inner.sectors.remove(&oldest);
            let was_dirty = inner.dirty.remove(&oldest);
            evicted_data.map(|d| (oldest, d, was_dirty))
        } else {
            None
        };

        inner.sectors.insert(sector_index, data);
        inner.access_order.push(sector_index);

        evicted
    }

    /// セクタをダーティとしてマーク
    pub fn mark_dirty(&self, sector_index: u32) {
        let mut inner = self.cache.write();
        if inner.sectors.contains_key(&sector_index) {
            inner.dirty.insert(sector_index);
        }
    }

    /// セクタ内の特定エントリを更新
    pub fn update_entry(&self, sector_index: u32, offset: usize, value: Cluster) -> bool {
        let mut inner = self.cache.write();

        // contains_keyはボロウを返さないため安全
        if !inner.sectors.contains_key(&sector_index) {
            return false;
        }

        // セクタを可変借用してサイズチェックと値の更新
        let updated = if let Some(sector) = inner.sectors.get_mut(&sector_index) {
            if offset < sector.len() {
                sector[offset] = value;
                true
            } else {
                false
            }
        } else {
            false
        };

        if updated {
            inner.dirty.insert(sector_index);
            // アクセス順序を更新
            inner.access_order.retain(|&s| s != sector_index);
            inner.access_order.push(sector_index);
        }

        updated
    }

    /// すべてのダーティセクタを取得してダーティフラグをクリア
    pub fn take_dirty_sectors(&self) -> Vec<(u32, Vec<Cluster>)> {
        let mut inner = self.cache.write();
        let dirty_indices: Vec<u32> = inner.dirty.drain().collect();
        dirty_indices
            .into_iter()
            .filter_map(|idx| inner.sectors.get(&idx).map(|data| (idx, data.clone())))
            .collect()
    }

    /// キャッシュをクリア（アンマウント時など）
    pub fn clear(&self) {
        let mut inner = self.cache.write();
        inner.sectors.clear();
        inner.dirty.clear();
        inner.access_order.clear();
    }

    /// ダーティセクタがあるかチェック
    pub fn has_dirty(&self) -> bool {
        !self.cache.read().dirty.is_empty()
    }
}

// ============================================================================
// Directory Entry Cache (Parsed Entry Caching)
// ============================================================================

/// ディレクトリごとのキャッシュサイズデフォルト
const DEFAULT_DIR_CACHE_SIZE: usize = 16;

/// ディレクトリエントリキャッシュ
///
/// パース済みのディレクトリエントリを保持し、繰り返しアクセス時の
/// ディスクI/OとLFNパース処理を削減する。
pub struct DirEntryCache {
    /// ディレクトリクラスタ -> パース済みエントリリスト
    cache: RwLock<DirEntryCacheInner>,
    /// 最大キャッシュディレクトリ数
    max_dirs: usize,
}

/// DirEntryCacheの内部データ
struct DirEntryCacheInner {
    /// クラスタ -> エントリリスト
    entries: HashMap<Cluster, Vec<(String, DirEntryRaw)>>,
    /// アクセス順序（LRU用）- 末尾が最新
    access_order: Vec<Cluster>,
}

impl DirEntryCache {
    /// 新しいディレクトリキャッシュを作成
    pub fn new(max_dirs: usize) -> Self {
        Self {
            cache: RwLock::new(DirEntryCacheInner {
                entries: HashMap::new(),
                access_order: Vec::new(),
            }),
            max_dirs,
        }
    }

    /// キャッシュからディレクトリエントリを取得
    pub fn get(&self, cluster: Cluster) -> Option<Vec<(String, DirEntryRaw)>> {
        let mut inner = self.cache.write();

        // エントリをクローンして返す
        let data = inner.entries.get(&cluster).cloned();

        if data.is_some() {
            // アクセス順序を更新
            inner.access_order.retain(|&c| c != cluster);
            inner.access_order.push(cluster);
        }

        data
    }

    /// ディレクトリエントリをキャッシュに追加
    pub fn insert(&self, cluster: Cluster, entries: Vec<(String, DirEntryRaw)>) {
        let mut inner = self.cache.write();

        // 既存エントリを更新
        if inner.entries.contains_key(&cluster) {
            inner.entries.insert(cluster, entries);
            inner.access_order.retain(|&c| c != cluster);
            inner.access_order.push(cluster);
            return;
        }

        // キャッシュが満杯の場合、最も古いエントリを削除
        while inner.entries.len() >= self.max_dirs && !inner.access_order.is_empty() {
            if let Some(oldest) = inner.access_order.first().copied() {
                inner.access_order.remove(0);
                inner.entries.remove(&oldest);
            }
        }

        // 新しいエントリを追加
        inner.entries.insert(cluster, entries);
        inner.access_order.push(cluster);
    }

    /// 指定ディレクトリのキャッシュを無効化
    pub fn invalidate(&self, cluster: Cluster) {
        let mut inner = self.cache.write();
        inner.entries.remove(&cluster);
        inner.access_order.retain(|&c| c != cluster);
    }

    /// 全キャッシュをクリア
    pub fn clear(&self) {
        let mut inner = self.cache.write();
        inner.entries.clear();
        inner.access_order.clear();
    }
}

// ============================================================================
// Strong Types (Newtypes)
// ============================================================================

/// クラスタ番号を型安全に扱うためのラッパー
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cluster(pub u32);

impl Cluster {
    /// ルートディレクトリの最小クラスタ番号
    pub const ROOT: Cluster = Cluster(2);
    /// 空きクラスタマーカー
    pub const FREE: Cluster = Cluster(0x00000000);
    /// 不良クラスタマーカー
    pub const BAD: Cluster = Cluster(0x0FFFFFF7);
    /// EOFマーカー（0x0FFFFFF8以上の値はEOF）
    pub const EOF: Cluster = Cluster(0x0FFFFFF8);

    /// コンパイル時にクラスタが有効かチェック
    ///
    /// # Example
    /// ```ignore
    /// const FIRST_DATA_CLUSTER: Cluster = Cluster(2);
    /// const _: () = assert!(Cluster::is_valid_const(FIRST_DATA_CLUSTER.0));
    /// ```
    #[inline]
    pub const fn is_valid_const(value: u32) -> bool {
        value >= 2 && value < 0x0FFFFFF0
    }

    /// 有効なデータクラスタかどうか（2以上、かつ予約済みマーカー未満）
    #[inline]
    pub fn is_valid(&self) -> bool {
        Self::is_valid_const(self.0)
    }

    /// EOFクラスタかどうか
    #[inline]
    pub fn is_eof(&self) -> bool {
        self.0 >= Self::EOF.0
    }

    /// 空きクラスタかどうか
    #[inline]
    pub fn is_free(&self) -> bool {
        *self == Self::FREE
    }

    /// u32として値を取得
    #[inline]
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// コンパイル時にクラスタが指定範囲内か検証
    ///
    /// # Example
    /// ```ignore
    /// const MAX_CLUSTERS: u32 = 65525;
    /// assert!(Cluster::in_range(100, MAX_CLUSTERS));
    /// assert!(!Cluster::in_range(100000, MAX_CLUSTERS));
    /// ```
    #[inline]
    pub const fn in_range(value: u32, max: u32) -> bool {
        value >= 2 && value < max
    }

    /// コンパイル時に2つのクラスタが連続しているかチェック
    ///
    /// バッチ読み取り最適化で連続クラスタを検出するのに使用
    #[inline]
    pub const fn is_contiguous_with(self, other: Cluster) -> bool {
        other.0 == self.0 + 1
    }
}

/// FATエントリから読み取った次クラスタの状態を表す列挙型
///
/// マジックナンバー(0x0FFFFFF8等)を直接扱うのではなく、
/// 型安全な列挙型で状態を表現する
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextCluster {
    /// 有効な次のクラスタ番号
    Valid(Cluster),
    /// クラスタチェーンの終端（EOF）
    Eof,
    /// 不良クラスタ
    Bad,
    /// 空きクラスタ
    Free,
}

impl NextCluster {
    /// FATエントリ値からNextClusterを生成
    #[inline]
    pub fn from_fat_entry(cluster: Cluster) -> Self {
        if cluster.is_free() {
            NextCluster::Free
        } else if cluster == Cluster::BAD {
            NextCluster::Bad
        } else if cluster.is_eof() {
            NextCluster::Eof
        } else if cluster.is_valid() {
            NextCluster::Valid(cluster)
        } else {
            NextCluster::Eof // 予約済み領域はEOFとして扱う
        }
    }

    /// 有効なクラスタ番号を取得（Valid以外はNone）
    #[inline]
    pub fn as_valid(&self) -> Option<Cluster> {
        match self {
            NextCluster::Valid(c) => Some(*c),
            _ => None,
        }
    }
}

/// セクタ番号を型安全に扱うためのラッパー
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sector(pub u32);

impl Sector {
    /// u64として値を取得（BlockDevice APIとの互換性のため）
    #[inline]
    pub fn as_u64(&self) -> u64 {
        self.0 as u64
    }
}

impl Add<u32> for Sector {
    type Output = Sector;
    #[inline]
    fn add(self, rhs: u32) -> Self::Output {
        Sector(self.0 + rhs)
    }
}

impl Sub<Sector> for Sector {
    type Output = u32;
    #[inline]
    fn sub(self, rhs: Sector) -> Self::Output {
        self.0 - rhs.0
    }
}

/// u16からSectorへの安全な変換
impl TryFrom<u16> for Sector {
    type Error = FsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(Sector(value as u32))
    }
}

/// u32からSectorへの変換
impl From<u32> for Sector {
    fn from(value: u32) -> Self {
        Sector(value)
    }
}

// ============================================================================
// Constants & Attributes
// ============================================================================

/// ブロック/セクタサイズ
const BLOCK_SIZE: usize = 512;

// ============================================================================
// Enhanced Error Types
// ============================================================================

/// FAT32固有のエラー型
///
/// FsErrorよりも詳細な情報を保持し、デバッグとエラーリカバリを容易にする
#[derive(Debug, Clone)]
pub enum Fat32Error {
    /// 無効なブートセクタ
    InvalidBootSector {
        reason: &'static str,
        signature: u16,
    },
    /// 無効なクラスタ番号
    InvalidCluster { cluster: u32, max_valid: u32 },
    /// クラスタチェーンのループ検出
    ClusterChainLoop {
        cluster: Cluster,
        chain_length: usize,
    },
    /// パスが長すぎる
    PathTooLong { path_len: usize, max_length: usize },
    /// I/O操作エラー（詳細なコンテキスト付き）
    ///
    /// デバッグ時にどの操作でエラーが発生したかを特定しやすくする
    IoOperation {
        /// 操作名（"read_cluster", "write_fat", etc.）
        operation: &'static str,
        /// 関連するセクタ番号（存在する場合）
        sector: Option<Sector>,
        /// 関連するクラスタ番号（存在する場合）
        cluster: Option<Cluster>,
    },
    /// ブロックデバイスエラー
    BlockDevice(BlockError),
    /// 一般的なファイルシステムエラー
    Fs(FsError),
}

impl fmt::Display for Fat32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fat32Error::InvalidBootSector { reason, signature } => {
                write!(
                    f,
                    "Invalid boot sector: {} (signature: 0x{:04X})",
                    reason, signature
                )
            }
            Fat32Error::InvalidCluster { cluster, max_valid } => {
                write!(f, "Invalid cluster {} (max: {})", cluster, max_valid)
            }
            Fat32Error::ClusterChainLoop {
                cluster,
                chain_length,
            } => {
                write!(
                    f,
                    "Cluster chain loop detected at cluster {} after {} iterations",
                    cluster.0, chain_length
                )
            }
            Fat32Error::PathTooLong {
                path_len,
                max_length,
            } => {
                write!(
                    f,
                    "Path too long: {} exceeds {} characters",
                    path_len, max_length
                )
            }
            Fat32Error::IoOperation {
                operation,
                sector,
                cluster,
            } => {
                write!(f, "I/O operation '{}' failed", operation)?;
                if let Some(s) = sector {
                    write!(f, " at sector {}", s.0)?;
                }
                if let Some(c) = cluster {
                    write!(f, " for cluster {}", c.0)?;
                }
                Ok(())
            }
            Fat32Error::BlockDevice(e) => {
                write!(f, "Block device error: {:?}", e)
            }
            Fat32Error::Fs(e) => {
                write!(f, "Filesystem error: {:?}", e)
            }
        }
    }
}

/// BlockErrorからFsErrorへの自動変換
///
/// これにより`?`演算子だけで自動変換でき、map_errが不要になる

/// Fat32ErrorからFsErrorへの変換
impl From<Fat32Error> for FsError {
    fn from(err: Fat32Error) -> Self {
        match err {
            Fat32Error::InvalidBootSector { .. } => FsError::InvalidInput,
            Fat32Error::InvalidCluster { .. } => FsError::FileSystemCorrupted,
            Fat32Error::ClusterChainLoop { .. } => FsError::FileSystemCorrupted,
            Fat32Error::PathTooLong { .. } => FsError::InvalidInput,
            Fat32Error::IoOperation { .. } => FsError::IoError,
            Fat32Error::BlockDevice(_) => FsError::IoError,
            Fat32Error::Fs(e) => e,
        }
    }
}

// ============================================================================
// Result Type Alias and Extensions
// ============================================================================

/// FAT32固有のResult型エイリアス
pub type Fat32Result<T> = Result<T, Fat32Error>;

/// Result型にコンテキスト追加機能を提供する拡張トレイト
///
/// # Example
/// ```ignore
/// device.read_sync(sector.as_u64(), &mut buffer)
///     .context("Failed to read cluster from device")?;
/// ```
pub trait ResultExt<T> {
    /// エラーに静的コンテキストメッセージを追加
    fn context(self, msg: &'static str) -> Fat32Result<T>;

    /// エラーに遅延評価でコンテキストを追加
    fn with_context<F>(self, f: F) -> Fat32Result<T>
    where
        F: FnOnce() -> &'static str;
}

impl<T, E: Into<Fat32Error>> ResultExt<T> for Result<T, E> {
    fn context(self, _msg: &'static str) -> Fat32Result<T> {
        self.map_err(|e| e.into())
    }

    fn with_context<F>(self, _f: F) -> Fat32Result<T>
    where
        F: FnOnce() -> &'static str,
    {
        self.map_err(|e| e.into())
    }
}

// ============================================================================
// Additional Strong Types (Newtypes)
// ============================================================================

/// ファイルオフセットを型安全に扱うためのラッパー
///
/// ファイル内の位置をバイト単位で表現する
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileOffset(pub u64);

impl FileOffset {
    /// ゼロオフセット
    pub const ZERO: Self = FileOffset(0);

    /// オフセットが指すクラスタインデックスを計算
    #[inline]
    pub fn cluster_index(&self, cluster_size: u64) -> usize {
        (self.0 / cluster_size) as usize
    }

    /// クラスタ内のオフセットを計算
    #[inline]
    pub fn offset_in_cluster(&self, cluster_size: u64) -> usize {
        (self.0 % cluster_size) as usize
    }

    /// u64として値を取得
    #[inline]
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// コンパイル時にオフセットが指定範囲内か検証
    ///
    /// # Example
    /// ```ignore
    /// const FILE_SIZE: u64 = 1024 * 1024;
    /// assert!(FileOffset::in_range(500, FILE_SIZE));
    /// assert!(!FileOffset::in_range(FILE_SIZE + 1, FILE_SIZE));
    /// ```
    #[inline]
    pub const fn in_range(value: u64, max: u64) -> bool {
        value < max
    }
}

impl Add<usize> for FileOffset {
    type Output = FileOffset;
    fn add(self, rhs: usize) -> Self::Output {
        FileOffset(self.0 + rhs as u64)
    }
}

impl From<u64> for FileOffset {
    fn from(value: u64) -> Self {
        FileOffset(value)
    }
}

/// バイト数を型安全に扱うためのラッパー
///
/// サイズやカウントを明示的に型で表現する
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteCount(pub usize);

impl ByteCount {
    /// ゼロバイト
    pub const ZERO: Self = ByteCount(0);

    /// usizeとして値を取得
    #[inline]
    pub fn as_usize(&self) -> usize {
        self.0
    }

    /// 2つのByteCountの最小値を返す
    #[inline]
    pub fn min(self, other: ByteCount) -> ByteCount {
        ByteCount(self.0.min(other.0))
    }

    /// 空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl From<usize> for ByteCount {
    fn from(value: usize) -> Self {
        ByteCount(value)
    }
}

impl Add for ByteCount {
    type Output = ByteCount;
    fn add(self, rhs: ByteCount) -> Self::Output {
        ByteCount(self.0 + rhs.0)
    }
}

impl Sub for ByteCount {
    type Output = ByteCount;
    fn sub(self, rhs: ByteCount) -> Self::Output {
        ByteCount(self.0.saturating_sub(rhs.0))
    }
}

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
pub mod fat_entry_state {
    use super::{Cluster, FsError, FsResult};
    use core::marker::PhantomData;

    // ----------------------------------------------------------------
    // State Markers (Zero-Sized Types for Typestate)
    // ----------------------------------------------------------------

    /// 未使用状態を表すマーカー型
    pub struct Free;

    /// 割り当て済み状態を表すマーカー型
    pub struct Allocated;

    /// クラスタチェーンでリンクされた状態を表すマーカー型
    pub struct Linked;

    /// チェーン終端状態を表すマーカー型
    pub struct EndOfChain;

    // ----------------------------------------------------------------
    // FatEntry<State> - Type-Safe FAT Entry
    // ----------------------------------------------------------------

    /// 型安全なFATエントリ
    ///
    /// ジェネリクスの`State`パラメータにより、
    /// エントリの現在の状態をコンパイル時に追跡します。
    #[derive(Debug, Clone, Copy)]
    pub struct FatEntry<State> {
        cluster: Cluster,
        value: u32,
        _state: PhantomData<State>,
    }

    impl FatEntry<Free> {
        /// 空きクラスタから新しいFatEntryを作成
        ///
        /// # Arguments
        /// * `cluster` - 空きクラスタ番号
        #[inline]
        pub const fn new_free(cluster: Cluster) -> Self {
            FatEntry {
                cluster,
                value: 0,
                _state: PhantomData,
            }
        }

        /// 空きエントリを割り当て状態に遷移
        ///
        /// # Returns
        /// 割り当て済み状態のFatEntry
        #[inline]
        pub fn allocate(self) -> FatEntry<Allocated> {
            FatEntry {
                cluster: self.cluster,
                value: Cluster::EOF.0,
                _state: PhantomData,
            }
        }
    }

    impl FatEntry<Allocated> {
        /// 割り当て済みエントリを別のクラスタにリンク
        ///
        /// # Arguments
        /// * `next` - リンク先のクラスタ
        ///
        /// # Errors
        /// 無効なクラスタ番号の場合エラー
        #[inline]
        pub fn link_to(self, next: Cluster) -> FsResult<FatEntry<Linked>> {
            if next.0 < 2 {
                return Err(FsError::InvalidInput);
            }
            Ok(FatEntry {
                cluster: self.cluster,
                value: next.0,
                _state: PhantomData,
            })
        }

        /// 割り当て済みエントリをチェーン終端としてマーク
        #[inline]
        pub fn mark_eof(self) -> FatEntry<EndOfChain> {
            FatEntry {
                cluster: self.cluster,
                value: Cluster::EOF.0,
                _state: PhantomData,
            }
        }
    }

    impl<State> FatEntry<State> {
        /// クラスタ番号を取得
        #[inline]
        pub const fn cluster(&self) -> Cluster {
            self.cluster
        }

        /// FAT値を取得
        #[inline]
        pub const fn fat_value(&self) -> u32 {
            self.value
        }

        /// FATに書き込むべきClusterを取得
        #[inline]
        pub const fn as_cluster_value(&self) -> Cluster {
            Cluster(self.value)
        }
    }

    // ----------------------------------------------------------------
    // Builder for Entry Creation from Raw Values
    // ----------------------------------------------------------------

    /// 生のFAT値から適切な状態のFatEntryを構築するビルダー
    pub struct FatEntryBuilder {
        cluster: Cluster,
        raw_value: u32,
    }

    impl FatEntryBuilder {
        /// 新しいビルダーを作成
        #[inline]
        pub const fn new(cluster: Cluster, raw_value: u32) -> Self {
            FatEntryBuilder { cluster, raw_value }
        }

        /// 空きエントリとして構築(値が0の場合)
        pub fn build_if_free(self) -> Option<FatEntry<Free>> {
            if self.raw_value == 0 {
                Some(FatEntry {
                    cluster: self.cluster,
                    value: 0,
                    _state: PhantomData,
                })
            } else {
                None
            }
        }

        /// リンク済みエントリとして構築(次のクラスタへのリンクがある場合)
        pub fn build_if_linked(self) -> Option<FatEntry<Linked>> {
            let masked = self.raw_value & 0x0FFFFFFF;
            if masked >= 2 && masked < 0x0FFFFFF8 {
                Some(FatEntry {
                    cluster: self.cluster,
                    value: masked,
                    _state: PhantomData,
                })
            } else {
                None
            }
        }

        /// EOFエントリとして構築(チェーン終端の場合)
        pub fn build_if_eof(self) -> Option<FatEntry<EndOfChain>> {
            let masked = self.raw_value & 0x0FFFFFFF;
            if masked >= 0x0FFFFFF8 {
                Some(FatEntry {
                    cluster: self.cluster,
                    value: masked,
                    _state: PhantomData,
                })
            } else {
                None
            }
        }

        /// 状態を判定して適切な型を返す(動的ディスパッチ用)
        pub fn classify(self) -> FatEntryKind {
            let masked = self.raw_value & 0x0FFFFFFF;
            if masked == 0 {
                FatEntryKind::Free(self.cluster)
            } else if masked >= 0x0FFFFFF8 {
                FatEntryKind::EndOfChain(self.cluster)
            } else if masked >= 2 {
                FatEntryKind::Linked(self.cluster, Cluster(masked))
            } else {
                FatEntryKind::Reserved(self.cluster)
            }
        }
    }

    /// FATエントリの種類を表す列挙型(動的な判定用)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FatEntryKind {
        /// 未使用クラスタ
        Free(Cluster),
        /// 次のクラスタにリンク
        Linked(Cluster, Cluster),
        /// チェーン終端
        EndOfChain(Cluster),
        /// 予約済み(クラスタ0, 1)
        Reserved(Cluster),
    }
}

// ============================================================================
// Sealed Trait Pattern
// ============================================================================

mod sealed {
    /// 外部からの実装を防ぐためのシーリングトレイト
    pub trait Sealed {}
}

/// パックされた構造体への安全なアクセスを提供するトレイト
///
/// # Safety Note
/// このトレイトは`sealed::Sealed`を継承しており、
/// 外部クレートからの実装を防止している。
/// これにより、危険なunsafe操作が信頼されたコード内に限定される。
///
/// # Design Rationale
///
/// FAT32ディレクトリエントリは`#[repr(C, packed)]`構造体であり、
/// 直接参照を取るとアラインメント違反を引き起こす可能性がある。
/// このトレイトは以下の安全性を保証する：
///
/// 1. `read_unaligned`により非アラインアクセスを安全に処理
/// 2. Sealedトレイトにより外部実装を防止
/// 3. バッファサイズ検証は呼び出し側で保証（assert/debug_assert）
pub trait SafePackedRead: sealed::Sealed {
    /// バイト列から構造体を安全に読み取る
    ///
    /// # Arguments
    ///
    /// * `bytes` - 少なくとも構造体サイズ以上のバイトスライス
    ///
    /// # Panics
    ///
    /// デバッグビルドでは、バッファサイズが不十分な場合にパニックする
    fn from_bytes_safe(bytes: &[u8]) -> Self;
}

impl sealed::Sealed for DirEntryRaw {}
impl SafePackedRead for DirEntryRaw {
    /// バイト列からDirEntryRawを安全に読み取る
    ///
    /// # Safety (内部unsafe使用の根拠)
    ///
    /// この関数は内部で`read_unaligned`を使用していますが、以下の理由により安全です：
    ///
    /// 1. **メモリレイアウト**: `#[repr(C, packed)]`により、構造体のメモリレイアウトは
    ///    明確に定義されており、パディングなしで32バイト固定
    /// 2. **アラインメント**: すべてのフィールドが`[u8; N]`または`u8`型であり、
    ///    アラインメント要求は1バイト
    /// 3. **サイズ保証**: `DIR_ENTRY_SIZE == 32`は呼び出し側で保証されている
    /// 4. **Copyトレイト**: 構造体は`Copy`を実装しており、ビット単位のコピーが安全
    /// 5. **有効性**: 任意のビットパターンが有効なDirEntryRaw値を形成する
    ///    （無効なパターンは上位層で検証）
    fn from_bytes_safe(bytes: &[u8]) -> Self {
        debug_assert!(
            bytes.len() >= DIR_ENTRY_SIZE,
            "Buffer too small for DirEntryRaw: {} < {}",
            bytes.len(),
            DIR_ENTRY_SIZE
        );
        // Delegate to safe field-by-field parser
        DirEntryRaw::from_bytes(bytes)
    }
}

impl sealed::Sealed for LfnEntry {}
impl SafePackedRead for LfnEntry {
    /// バイト列からLfnEntryを安全に読み取る
    ///
    /// # Safety (内部unsafe使用の根拠)
    ///
    /// DirEntryRawと同様の理由により安全：
    /// - `#[repr(C, packed)]`で32バイト固定
    /// - 全フィールドがアラインメント要求1バイト
    /// - 任意のビットパターンが有効（無効パターンは上位層で検証）
    fn from_bytes_safe(bytes: &[u8]) -> Self {
        debug_assert!(
            bytes.len() >= DIR_ENTRY_SIZE,
            "Buffer too small for LfnEntry: {} < {}",
            bytes.len(),
            DIR_ENTRY_SIZE
        );
        // Delegate to safe field-by-field parser
        LfnEntry::from_bytes(bytes)
    }
}

// ============================================================================
// Extension Traits
// ============================================================================

/// Clusterに追加機能を提供する拡張トレイト
pub trait ClusterExt {
    /// クラスタが有効なデータ範囲内か検証
    fn validate(&self, max_clusters: u32) -> Result<(), Fat32Error>;

    /// 次のクラスタとの差分を計算（連続性チェック用）
    fn distance_to(&self, other: Cluster) -> Option<u32>;
}

impl ClusterExt for Cluster {
    fn validate(&self, max_clusters: u32) -> Result<(), Fat32Error> {
        if !self.is_valid() || self.0 >= max_clusters {
            Err(Fat32Error::InvalidCluster {
                cluster: self.0,
                max_valid: max_clusters.saturating_sub(1),
            })
        } else {
            Ok(())
        }
    }

    fn distance_to(&self, other: Cluster) -> Option<u32> {
        other.0.checked_sub(self.0)
    }
}

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

/// ファイル属性を管理する型安全な構造体
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileAttributes(u8);

impl FileAttributes {
    /// 読み取り専用属性
    pub const READ_ONLY: u8 = 0x01;
    /// 隠しファイル属性
    pub const HIDDEN: u8 = 0x02;
    /// システムファイル属性
    pub const SYSTEM: u8 = 0x04;
    /// ボリュームラベル属性
    pub const VOLUME_ID: u8 = 0x08;
    /// ディレクトリ属性
    pub const DIRECTORY: u8 = 0x10;
    /// アーカイブ属性
    pub const ARCHIVE: u8 = 0x20;
    /// デバイス属性
    pub const DEVICE: u8 = 0x40;
    /// ロングファイルネーム属性（VOLUME_ID | SYSTEM | HIDDEN | READ_ONLY）
    pub const LONG_NAME: u8 = 0x0F;

    /// ビットパターンから属性を生成
    #[inline]
    pub fn from_bits_truncate(bits: u8) -> Self {
        Self(bits)
    }

    /// 生のビット値を取得
    #[inline]
    pub fn bits(&self) -> u8 {
        self.0
    }

    /// ディレクトリかどうか
    #[inline]
    pub fn is_directory(&self) -> bool {
        (self.0 & Self::DIRECTORY) != 0
    }

    /// ロングファイルネームエントリかどうか
    #[inline]
    pub fn is_long_name(&self) -> bool {
        (self.0 & Self::LONG_NAME) == Self::LONG_NAME
    }

    /// 読み取り専用かどうか
    #[inline]
    pub fn is_read_only(&self) -> bool {
        (self.0 & Self::READ_ONLY) != 0
    }

    /// ボリュームIDかどうか
    #[inline]
    pub fn is_volume_id(&self) -> bool {
        (self.0 & Self::VOLUME_ID) != 0
    }

    /// 隠しファイルかどうか
    #[inline]
    pub fn is_hidden(&self) -> bool {
        (self.0 & Self::HIDDEN) != 0
    }

    /// システムファイルかどうか
    #[inline]
    pub fn is_system(&self) -> bool {
        (self.0 & Self::SYSTEM) != 0
    }
}

impl From<u8> for FileAttributes {
    #[inline]
    fn from(bits: u8) -> Self {
        Self(bits)
    }
}

impl From<FileAttributes> for u8 {
    #[inline]
    fn from(attr: FileAttributes) -> Self {
        attr.0
    }
}

impl fmt::Display for FileAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.is_read_only() {
            parts.push("RO");
        }
        if self.is_hidden() {
            parts.push("HIDDEN");
        }
        if self.is_system() {
            parts.push("SYSTEM");
        }
        if self.is_volume_id() {
            parts.push("VOLUME");
        }
        if self.is_directory() {
            parts.push("DIR");
        }
        // ARCHIVE はほぼすべてのファイルに設定されるので省略

        if parts.is_empty() {
            write!(f, "(none)")
        } else {
            write!(f, "{}", parts.join(" | "))
        }
    }
}

// ============================================================================
// Little-Endian Accessor Macro
// ============================================================================

/// リトルエンディアンバイト配列からプリミティブ型を取得するアクセサメソッドを自動生成するマクロ
///
/// # Example
/// ```ignore
/// le_accessor! {
///     impl BiosParameterBlock {
///         bytes_per_sector: [u8; 2] => u16,
///         hidden_sectors: [u8; 4] => u32,
///     }
/// }
/// ```
macro_rules! le_accessor {
    (impl $struct:ident { $($name:ident : $array:ty => $ty:ty),* $(,)? }) => {
        impl $struct {
            $(
                /// フィールドの値をリトルエンディアンから変換して取得
                #[inline]
                pub fn $name(&self) -> $ty {
                    <$ty>::from_le_bytes(self.$name)
                }
            )*
        }
    };
}

// ============================================================================
// BPB (BIOS Parameter Block)
// ============================================================================

/// BIOSパラメータブロック
///
/// # Safety Note
/// すべての整数型フィールドを `[u8; N]` で表現しています。
/// これによりアラインメントの問題を物理的に排除し、
/// `unsafe` ブロックなしで安全にアクセスできます。
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BiosParameterBlock {
    /// ジャンプ命令（3バイト）
    pub jmp_boot: [u8; 3],
    /// OEM名（8バイト）
    pub oem_name: [u8; 8],
    /// 1セクタあたりのバイト数
    bytes_per_sector: [u8; 2],
    /// 1クラスタあたりのセクタ数
    pub sectors_per_cluster: u8,
    /// 予約セクタ数
    reserved_sectors: [u8; 2],
    /// FAT数
    pub num_fats: u8,
    /// ルートディレクトリエントリ数（FAT32では0）
    root_entry_count: [u8; 2],
    /// 総セクタ数（16ビット、FAT32では0）
    total_sectors_16: [u8; 2],
    /// メディアタイプ
    pub media_type: u8,
    /// FATあたりのセクタ数（FAT12/16用、FAT32では0）
    fat_size_16: [u8; 2],
    /// トラックあたりのセクタ数
    sectors_per_track: [u8; 2],
    /// ヘッド数
    num_heads: [u8; 2],
    /// 隠しセクタ数
    hidden_sectors: [u8; 4],
    /// 総セクタ数（32ビット）
    total_sectors_32: [u8; 4],
}

// マクロでアクセサメソッドを自動生成
le_accessor! {
    impl BiosParameterBlock {
        bytes_per_sector: [u8; 2] => u16,
        reserved_sectors: [u8; 2] => u16,
        root_entry_count: [u8; 2] => u16,
        total_sectors_16: [u8; 2] => u16,
        fat_size_16: [u8; 2] => u16,
        hidden_sectors: [u8; 4] => u32,
        total_sectors_32: [u8; 4] => u32,
    }
}

/// FAT32拡張BPB
///
/// # Safety Note
/// すべての整数型フィールドを `[u8; N]` で表現しています。
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32ExtendedBpb {
    /// FATあたりのセクタ数
    fat_size_32: [u8; 4],
    /// 拡張フラグ
    ext_flags: [u8; 2],
    /// ファイルシステムバージョン
    fs_version: [u8; 2],
    /// ルートディレクトリの開始クラスタ
    root_cluster: [u8; 4],
    /// FSInfoセクタ番号
    fs_info_sector: [u8; 2],
    /// バックアップブートセクタ
    backup_boot_sector: [u8; 2],
    /// 予約
    pub reserved: [u8; 12],
    /// ドライブ番号
    pub drive_number: u8,
    /// 予約
    pub reserved1: u8,
    /// ブートシグネチャ
    pub boot_sig: u8,
    /// ボリュームシリアル番号
    volume_serial: [u8; 4],
    /// ボリュームラベル
    pub volume_label: [u8; 11],
    /// ファイルシステムタイプ
    pub fs_type: [u8; 8],
}

// マクロでアクセサメソッドを自動生成
le_accessor! {
    impl Fat32ExtendedBpb {
        fat_size_32: [u8; 4] => u32,
        ext_flags: [u8; 2] => u16,
        fs_version: [u8; 2] => u16,
        root_cluster: [u8; 4] => u32,
        fs_info_sector: [u8; 2] => u16,
        backup_boot_sector: [u8; 2] => u16,
        volume_serial: [u8; 4] => u32,
    }
}

/// ブートセクタ
///
/// # Safety Note
/// 内部の整数フィールドはすべて `[u8; N]` 形式で、
/// 安全なアクセサメソッド経由でアクセスします。
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BootSector {
    pub bpb: BiosParameterBlock,
    pub fat32: Fat32ExtendedBpb,
    pub boot_code: [u8; 420],
    signature: [u8; 2],
}

impl TryFrom<&[u8]> for BootSector {
    type Error = FsError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < BOOT_SECTOR_SIZE {
            return Err(FsError::InvalidInput);
        }

        // バイト配列としてコピー（アライメントの問題は発生しない）
        let boot_sector = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const BootSector) };

        // シグネチャチェック
        if boot_sector.signature() != FAT32_SIGNATURE {
            return Err(FsError::InvalidInput);
        }

        Ok(boot_sector)
    }
}

impl BootSector {
    /// バイト列から安全にBootSectorを読み取る
    ///
    /// # Deprecated
    /// `TryFrom` トレイトを使用してください: `BootSector::try_from(bytes)?`
    #[deprecated(since = "0.1.0", note = "Use TryFrom trait instead")]
    pub fn from_bytes(bytes: &[u8]) -> FsResult<Self> {
        Self::try_from(bytes)
    }

    /// シグネチャを取得
    #[inline]
    pub fn signature(&self) -> u16 {
        u16::from_le_bytes(self.signature)
    }

    /// クラスタあたりのセクタ数を安全に取得
    #[inline]
    pub fn sectors_per_cluster(&self) -> u32 {
        self.bpb.sectors_per_cluster as u32
    }

    /// 予約セクタ数を安全に取得
    #[inline]
    pub fn reserved_sectors(&self) -> u32 {
        self.bpb.reserved_sectors() as u32
    }

    /// FAT数を安全に取得
    #[inline]
    pub fn num_fats(&self) -> u32 {
        self.bpb.num_fats as u32
    }

    /// FAT32のFATサイズを安全に取得
    #[inline]
    pub fn fat_size_32(&self) -> u32 {
        self.fat32.fat_size_32()
    }

    /// ルートクラスタを安全に取得（型安全なCluster型を返す）
    #[inline]
    pub fn root_cluster(&self) -> Cluster {
        Cluster(self.fat32.root_cluster())
    }

    /// 総セクタ数を安全に取得
    #[inline]
    pub fn total_sectors(&self) -> u32 {
        let ts16 = self.bpb.total_sectors_16();
        if ts16 != 0 {
            ts16 as u32
        } else {
            self.bpb.total_sectors_32()
        }
    }

    /// ファイルシステムタイプを取得
    #[inline]
    pub fn fs_type(&self) -> [u8; 8] {
        self.fat32.fs_type
    }

    /// FSInfoセクタ番号を取得
    #[inline]
    pub fn fs_info_sector(&self) -> u16 {
        self.fat32.fs_info_sector()
    }
}

// ============================================================================
// FSInfo
// ============================================================================

/// FSInfo構造体
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FsInfo {
    /// リードシグネチャ（0x41615252）
    pub lead_sig: u32,
    /// 予約
    pub reserved1: [u8; 480],
    /// 構造体シグネチャ（0x61417272）
    pub struct_sig: u32,
    /// 空きクラスタ数
    pub free_count: u32,
    /// 次の空きクラスタ
    pub next_free: u32,
    /// 予約
    pub reserved2: [u8; 12],
    /// トレイルシグネチャ（0xAA550000）
    pub trail_sig: u32,
}

/// FSInfo構造体のシグネチャ定数
const FSINFO_LEAD_SIG: u32 = 0x41615252;
const FSINFO_STRUCT_SIG: u32 = 0x61417272;
const FSINFO_TRAIL_SIG: u32 = 0xAA550000;
/// 無効な値（不明な場合に使用）
const FSINFO_UNKNOWN: u32 = 0xFFFFFFFF;

impl FsInfo {
    /// バイト列からFsInfoを読み取る
    pub fn from_bytes(bytes: &[u8]) -> FsResult<Self> {
        if bytes.len() < 512 {
            return Err(FsError::InvalidInput);
        }

        let fsinfo = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const FsInfo) };

        // シグネチャを検証
        if fsinfo.lead_sig != FSINFO_LEAD_SIG
            || fsinfo.struct_sig != FSINFO_STRUCT_SIG
            || fsinfo.trail_sig != FSINFO_TRAIL_SIG
        {
            return Err(FsError::FileSystemCorrupted);
        }

        Ok(fsinfo)
    }

    /// FsInfoをバイト列に変換
    pub fn to_bytes(&self) -> [u8; 512] {
        let mut bytes = [0u8; 512];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const FsInfo as *const u8,
                bytes.as_mut_ptr(),
                core::mem::size_of::<FsInfo>(),
            );
        }
        bytes
    }

    /// 空きクラスタ数を取得（未知の場合はNone）
    pub fn free_count(&self) -> Option<u32> {
        if self.free_count == FSINFO_UNKNOWN {
            None
        } else {
            Some(self.free_count)
        }
    }

    /// 次の空きクラスタを取得（未知の場合はNone）
    pub fn next_free(&self) -> Option<u32> {
        if self.next_free == FSINFO_UNKNOWN {
            None
        } else {
            Some(self.next_free)
        }
    }

    /// 空きクラスタ数を設定
    pub fn set_free_count(&mut self, count: u32) {
        self.free_count = count;
    }

    /// 次の空きクラスタを設定
    pub fn set_next_free(&mut self, cluster: u32) {
        self.next_free = cluster;
    }

    /// 新しいFsInfoを作成
    pub fn new(free_count: u32, next_free: u32) -> Self {
        Self {
            lead_sig: FSINFO_LEAD_SIG,
            reserved1: [0u8; 480],
            struct_sig: FSINFO_STRUCT_SIG,
            free_count,
            next_free,
            reserved2: [0u8; 12],
            trail_sig: FSINFO_TRAIL_SIG,
        }
    }
}

// ============================================================================
// Directory Entry
// ============================================================================

/// 標準ディレクトリエントリ（8.3形式）
///
/// # Safety Note
/// すべての整数型フィールドを `[u8; N]` で表現しています。
/// これによりアラインメントの問題を物理的に排除します。
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DirEntryRaw {
    /// ファイル名（8バイト）
    pub name: [u8; 8],
    /// 拡張子（3バイト）
    pub ext: [u8; 3],
    /// 属性
    pub attr: u8,
    /// NT用予約
    pub nt_reserved: u8,
    /// 作成時刻（10ミリ秒単位）
    pub create_time_tenths: u8,
    /// 作成時刻
    create_time: [u8; 2],
    /// 作成日付
    create_date: [u8; 2],
    /// 最終アクセス日付
    access_date: [u8; 2],
    /// 開始クラスタ番号（上位16ビット）
    first_cluster_hi: [u8; 2],
    /// 更新時刻
    modify_time: [u8; 2],
    /// 更新日付
    modify_date: [u8; 2],
    /// 開始クラスタ番号（下位16ビット）
    first_cluster_lo: [u8; 2],
    /// ファイルサイズ
    file_size: [u8; 4],
}

/// packed構造体のためDebugを手動実装
impl fmt::Debug for DirEntryRaw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirEntryRaw")
            .field("name", &self.short_name())
            .field("attr", &self.attributes())
            .field("first_cluster", &self.first_cluster())
            .field("file_size", &self.file_size())
            .finish()
    }
}

impl DirEntryRaw {
    /// バイト列から安全にDirEntryRawを読み取る
    pub fn from_bytes(bytes: &[u8]) -> Self {
        // Safe field-by-field copy to avoid relying on #[repr(C, packed)] pointer casting.
        debug_assert!(
            bytes.len() >= DIR_ENTRY_SIZE,
            "Buffer too small for DirEntryRaw"
        );
        let mut entry = DirEntryRaw {
            name: [0u8; 8],
            ext: [0u8; 3],
            attr: 0,
            nt_reserved: 0,
            create_time_tenths: 0,
            create_time: [0u8; 2],
            create_date: [0u8; 2],
            access_date: [0u8; 2],
            first_cluster_hi: [0u8; 2],
            modify_time: [0u8; 2],
            modify_date: [0u8; 2],
            first_cluster_lo: [0u8; 2],
            file_size: [0u8; 4],
        };
        entry.name.copy_from_slice(&bytes[0..8]);
        entry.ext.copy_from_slice(&bytes[8..11]);
        entry.attr = bytes[11];
        entry.nt_reserved = bytes[12];
        entry.create_time_tenths = bytes[13];
        entry.create_time.copy_from_slice(&bytes[14..16]);
        entry.create_date.copy_from_slice(&bytes[16..18]);
        entry.access_date.copy_from_slice(&bytes[18..20]);
        entry.first_cluster_hi.copy_from_slice(&bytes[20..22]);
        entry.modify_time.copy_from_slice(&bytes[22..24]);
        entry.modify_date.copy_from_slice(&bytes[24..26]);
        entry.first_cluster_lo.copy_from_slice(&bytes[26..28]);
        entry.file_size.copy_from_slice(&bytes[28..32]);
        entry
    }

    /// 開始クラスタを取得（型安全なCluster型を返す）
    #[inline]
    pub fn first_cluster(&self) -> Cluster {
        let hi = u16::from_le_bytes(self.first_cluster_hi);
        let lo = u16::from_le_bytes(self.first_cluster_lo);
        Cluster(((hi as u32) << 16) | (lo as u32))
    }

    /// 開始クラスタを設定
    #[inline]
    pub fn set_first_cluster(&mut self, cluster: Cluster) {
        self.first_cluster_hi = ((cluster.0 >> 16) as u16).to_le_bytes();
        self.first_cluster_lo = ((cluster.0 & 0xFFFF) as u16).to_le_bytes();
    }

    /// 属性を取得（型安全なFileAttributes型を返す）
    #[inline]
    pub fn attributes(&self) -> FileAttributes {
        FileAttributes::from_bits_truncate(self.attr)
    }

    /// ファイルサイズを安全に取得
    #[inline]
    pub fn file_size(&self) -> u32 {
        u32::from_le_bytes(self.file_size)
    }

    /// ファイルサイズを設定
    #[inline]
    pub fn set_file_size(&mut self, size: u32) {
        self.file_size = size.to_le_bytes();
    }

    pub fn set_create_time(&mut self, time: u16) {
        self.create_time = time.to_le_bytes();
    }

    pub fn set_create_date(&mut self, date: u16) {
        self.create_date = date.to_le_bytes();
    }

    pub fn set_access_date(&mut self, date: u16) {
        self.access_date = date.to_le_bytes();
    }

    pub fn set_modify_time(&mut self, time: u16) {
        self.modify_time = time.to_le_bytes();
    }

    pub fn set_modify_date(&mut self, date: u16) {
        self.modify_date = date.to_le_bytes();
    }

    pub fn set_attributes(&mut self, attr: FileAttributes) {
        self.attr = attr.bits();
    }

    /// 作成時刻を取得
    #[inline]
    pub fn create_time(&self) -> u16 {
        u16::from_le_bytes(self.create_time)
    }

    /// 作成日付を取得
    #[inline]
    pub fn create_date(&self) -> u16 {
        u16::from_le_bytes(self.create_date)
    }

    /// 最終アクセス日付を取得
    #[inline]
    pub fn access_date(&self) -> u16 {
        u16::from_le_bytes(self.access_date)
    }

    /// 更新時刻を取得
    #[inline]
    pub fn modify_time(&self) -> u16 {
        u16::from_le_bytes(self.modify_time)
    }

    /// 更新日付を取得
    #[inline]
    pub fn modify_date(&self) -> u16 {
        u16::from_le_bytes(self.modify_date)
    }

    /// 新しいディレクトリエントリを作成
    ///
    /// # Arguments
    /// * `name` - 8バイトのベース名
    /// * `ext` - 3バイトの拡張子
    /// * `attr` - ファイル属性
    /// * `cluster` - 開始クラスタ
    /// * `size` - ファイルサイズ
    #[inline]
    pub fn new(
        name: [u8; 8],
        ext: [u8; 3],
        attr: FileAttributes,
        cluster: Cluster,
        size: u32,
    ) -> Self {
        Self {
            name,
            ext,
            attr: attr.bits(),
            nt_reserved: 0,
            create_time_tenths: 0,
            create_time: [0; 2],
            create_date: [0; 2],
            access_date: [0; 2],
            first_cluster_hi: ((cluster.0 >> 16) as u16).to_le_bytes(),
            modify_time: [0; 2],
            modify_date: [0; 2],
            first_cluster_lo: ((cluster.0 & 0xFFFF) as u16).to_le_bytes(),
            file_size: size.to_le_bytes(),
        }
    }

    /// 特殊ディレクトリエントリを作成するヘルパー（"." または ".."）
    ///
    /// # Arguments
    /// * `name` - エントリ名（最初の1〜2文字が'.'）
    /// * `cluster` - クラスタ番号
    #[inline]
    fn new_special_dir(name: [u8; 8], cluster: Cluster) -> Self {
        Self {
            name,
            ext: [b' '; 3],
            attr: FileAttributes::DIRECTORY,
            nt_reserved: 0,
            create_time_tenths: 0,
            create_time: [0; 2],
            create_date: [0; 2],
            access_date: [0; 2],
            first_cluster_hi: ((cluster.0 >> 16) as u16).to_le_bytes(),
            modify_time: [0; 2],
            modify_date: [0; 2],
            first_cluster_lo: ((cluster.0 & 0xFFFF) as u16).to_le_bytes(),
            file_size: [0; 4],
        }
    }

    /// "." エントリを作成
    #[inline]
    pub fn new_dot(cluster: Cluster) -> Self {
        Self::new_special_dir(*b".       ", cluster)
    }

    /// ".." エントリを作成
    #[inline]
    pub fn new_dotdot(parent_cluster: Cluster) -> Self {
        Self::new_special_dir(*b"..      ", parent_cluster)
    }

    /// 構造体をバイト列として参照
    ///
    /// # Safety (internal unsafe justification)
    ///
    /// この関数は内部で`from_raw_parts`を使用していますが、以下の**厳格な前提条件**により安全です：
    ///
    /// ## 前提条件（変更厳禁）
    ///
    /// 1. **メモリレイアウト保証**
    ///    - `#[repr(C, packed)]` により、パディングなしで連続配置される
    ///    - サイズは正確に `DIR_ENTRY_SIZE` (32バイト) である
    ///    - フィールド順序はFAT32仕様と一致している
    ///
    /// 2. **POD (Plain Old Data) であること**
    ///    - **全フィールドは `[u8; N]` または `u8` のプリミティブ型のみ**
    ///    - ヒープへのポインタ、参照、`Rc`、`Arc` などを含まない
    ///    - `Drop` トレイトを実装しない（ビット単位のコピーが安全）
    ///
    /// 3. **ライフタイム安全性**
    ///    - 返却されるスライスのライフタイムは `&self` に束縛されている
    ///    - 呼び出し側は構造体が生きている間のみスライスを参照できる
    ///
    /// ## ⚠️ 重要な制約（将来の開発者への警告）
    ///
    /// **以下の変更を行った場合、即座に未定義動作 (UB) になります：**
    ///
    /// - ❌ `Cluster` 型を `u32` 以外に変更する
    /// - ❌ `String` や `Vec<T>` などのヒープ型をフィールドに追加する
    /// - ❌ `#[repr(C)]` を削除する、または `packed` を削除する
    /// - ❌ フィールドの順序を変更する
    ///
    /// このような変更が必要な場合は、`as_bytes()` を手動シリアライズに書き換えること。
    /// 例:
    /// ```ignore
    /// let mut buf = [0u8; DIR_ENTRY_SIZE];
    /// buf[0..8].copy_from_slice(&self.name);
    /// buf[8..11].copy_from_slice(&self.ext);
    /// // ... 各フィールドを明示的にコピー
    /// ```
    ///
    /// # Example
    /// ```ignore
    /// let entry = DirEntryRaw::new(...);
    /// buffer[offset..offset + DIR_ENTRY_SIZE].copy_from_slice(entry.as_bytes());
    /// ```
    /// 構造体をバイト配列として出力 (安全なコピー版)
    #[inline]
    pub fn write_bytes_to(&self, dest: &mut [u8]) {
        debug_assert!(dest.len() >= DIR_ENTRY_SIZE);
        dest[0..8].copy_from_slice(&self.name);
        dest[8..11].copy_from_slice(&self.ext);
        dest[11] = self.attr;
        dest[12] = self.nt_reserved;
        dest[13] = self.create_time_tenths;
        dest[14..16].copy_from_slice(&self.create_time);
        dest[16..18].copy_from_slice(&self.create_date);
        dest[18..20].copy_from_slice(&self.access_date);
        dest[20..22].copy_from_slice(&self.first_cluster_hi);
        dest[22..24].copy_from_slice(&self.modify_time);
        dest[24..26].copy_from_slice(&self.modify_date);
        dest[26..28].copy_from_slice(&self.first_cluster_lo);
        dest[28..32].copy_from_slice(&self.file_size);
    }

    /// ディレクトリかどうか
    pub fn is_directory(&self) -> bool {
        self.attributes().is_directory()
    }

    /// ロングネームエントリかどうか
    pub fn is_long_name(&self) -> bool {
        self.attributes().is_long_name()
    }

    /// 削除済みかどうか
    pub fn is_deleted(&self) -> bool {
        self.name[0] == DELETED_ENTRY
    }

    /// ショートネームのチェックサムを計算(LFN検証用)
    ///
    /// # Algorithm
    /// MS-DOS標準のチェックサム計算アルゴリズム:
    /// sum = ((sum >> 1) | (sum << 7)) + name[i]
    ///
    /// # Implementation Note
    /// イテレータとfoldを使用した関数型スタイルで実装。
    /// ループ変数を管理する必要がなくなり、バグの入り込む余地が減少。
    pub fn calculate_checksum(&self) -> u8 {
        // 11バイト(8.3形式)のショートネーム全体を使用
        self.name
            .iter()
            .chain(self.ext.iter())
            .fold(0u8, |sum, &byte| sum.rotate_right(1).wrapping_add(byte))
    }

    /// 最後のエントリかどうか
    pub fn is_end(&self) -> bool {
        self.name[0] == END_OF_DIR
    }

    /// 8.3形式のファイル名を取得
    pub fn short_name(&self) -> String {
        self.short_name_cow().into_owned()
    }

    /// 8.3形式のファイル名を取得（Cow版）
    ///
    /// # Performance
    /// 必要な時だけStringを生成するため、アロケーションを削減できる
    pub fn short_name_cow(&self) -> Cow<'_, str> {
        let mut name = String::new();

        // ベース名（スペースを除去）
        for &c in &self.name {
            if c == b' ' {
                break;
            }
            name.push(c as char);
        }

        // 拡張子があれば追加
        let ext_start = self.ext.iter().position(|&c| c != b' ');
        if let Some(_) = ext_start {
            let ext: String = self
                .ext
                .iter()
                .take_while(|&&c| c != b' ')
                .map(|&c| c as char)
                .collect();
            if !ext.is_empty() {
                name.push('.');
                name.push_str(&ext);
            }
        }

        Cow::Owned(name)
    }
}

/// ロングファイルネームエントリ
///
/// # Safety Note
/// UCS-2文字フィールド（name1, name2, name3）を `[u8; N]` で表現しています。
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct LfnEntry {
    /// シーケンス番号
    pub seq: u8,
    /// 名前の1-5文字目（UCS-2、10バイト）
    name1: [u8; 10],
    /// 属性（常にATTR_LONG_NAME）
    pub attr: u8,
    /// タイプ（常に0）
    pub type_: u8,
    /// チェックサム
    pub checksum: u8,
    /// 名前の6-11文字目（UCS-2、12バイト）
    name2: [u8; 12],
    /// 常に0
    first_cluster: [u8; 2],
    /// 名前の12-13文字目（UCS-2、4バイト）
    name3: [u8; 4],
}

impl LfnEntry {
    pub fn sequence(&self) -> u8 {
        self.seq & 0x3F
    }

    pub fn is_last(&self) -> bool {
        (self.seq & 0x40) != 0
    }

    pub fn get_name_part_u16(&self) -> [u16; 13] {
        let mut part = [0u16; 13];
        for i in 0..5 {
            part[i] = u16::from_le_bytes([self.name1[i * 2], self.name1[i * 2 + 1]]);
        }
        for i in 0..6 {
            part[i + 5] = u16::from_le_bytes([self.name2[i * 2], self.name2[i * 2 + 1]]);
        }
        for i in 0..2 {
            part[i + 11] = u16::from_le_bytes([self.name3[i * 2], self.name3[i * 2 + 1]]);
        }
        part
    }

    /// バイト配列からUCS-2文字（u16）を読み取るヘルパー
    fn read_ucs2_chars(bytes: &[u8], chars: &mut Vec<u16>) {
        for chunk in bytes.chunks_exact(2) {
            let c = u16::from_le_bytes([chunk[0], chunk[1]]);
            if c == 0 || c == 0xFFFF {
                return;
            }
            chars.push(c);
        }
    }

    /// このエントリから名前の一部を取得
    pub fn get_name_part(&self) -> String {
        let mut chars = Vec::with_capacity(13);
        Self::read_ucs2_chars(&self.name1, &mut chars);
        Self::read_ucs2_chars(&self.name2, &mut chars);
        Self::read_ucs2_chars(&self.name3, &mut chars);
        String::from_utf16_lossy(&chars)
    }

    pub fn checksum(&self) -> u8 {
        self.checksum
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), DIR_ENTRY_SIZE);
        unsafe { *(bytes.as_ptr() as *const Self) }
    }

    pub fn new(seq: u8, name_part: &[u16; 13], checksum: u8, is_last: bool) -> Self {
        let mut seq_val = seq & 0x3F;
        if is_last {
            seq_val |= 0x40;
        }

        let mut entry = Self {
            seq: seq_val,
            name1: [0xFF; 10], // Init with 0xFFFF as per spec
            attr: FileAttributes::LONG_NAME,
            type_: 0,
            checksum,
            name2: [0xFF; 12],
            first_cluster: [0; 2],
            name3: [0xFF; 4],
        };

        for i in 0..5 {
            let bytes = name_part[i].to_le_bytes();
            entry.name1[i * 2] = bytes[0];
            entry.name1[i * 2 + 1] = bytes[1];
        }
        for i in 0..6 {
            let bytes = name_part[i + 5].to_le_bytes();
            entry.name2[i * 2] = bytes[0];
            entry.name2[i * 2 + 1] = bytes[1];
        }
        for i in 0..2 {
            let bytes = name_part[i + 11].to_le_bytes();
            entry.name3[i * 2] = bytes[0];
            entry.name3[i * 2 + 1] = bytes[1];
        }
        entry
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        unsafe { &*(self as *const Self as *const [u8; 32]) }
    }
}

/// packed構造体のためDebugを手動実装
impl fmt::Debug for LfnEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LfnEntry")
            .field("seq", &self.sequence())
            .field("is_last", &self.is_last())
            .field("checksum", &{ self.checksum })
            .field("name_part", &self.get_name_part())
            .finish()
    }
}

// ============================================================================
// DirEntryBuilder - Builder Pattern
// ============================================================================

/// ディレクトリエントリを構築するBuilderパターン
///
/// # Example
/// ```ignore
/// let entry = DirEntryBuilder::new(name, ext)
///     .attr(FileAttributes::from_bits_truncate(FileAttributes::ARCHIVE))
///     .cluster(cluster)
///     .size(100)
///     .create_time(0x5A20)
///     .modify_time(0x5A20)
///     .build();
/// ```
pub struct DirEntryBuilder {
    name: [u8; 8],
    ext: [u8; 3],
    attr: FileAttributes,
    cluster: Cluster,
    size: u32,
    create_time: Option<u16>,
    create_date: Option<u16>,
    modify_time: Option<u16>,
    modify_date: Option<u16>,
    access_date: Option<u16>,
}

impl DirEntryBuilder {
    /// 新しいBuilderを作成
    pub fn new(name: [u8; 8], ext: [u8; 3]) -> Self {
        Self {
            name,
            ext,
            attr: FileAttributes::from_bits_truncate(0),
            cluster: Cluster(0),
            size: 0,
            create_time: None,
            create_date: None,
            modify_time: None,
            modify_date: None,
            access_date: None,
        }
    }

    /// ファイル属性を設定
    pub fn attr(mut self, attr: FileAttributes) -> Self {
        self.attr = attr;
        self
    }

    /// 開始クラスタを設定
    pub fn cluster(mut self, cluster: Cluster) -> Self {
        self.cluster = cluster;
        self
    }

    /// ファイルサイズを設定
    pub fn size(mut self, size: u32) -> Self {
        self.size = size;
        self
    }

    /// 作成時刻を設定（DOS形式）
    pub fn create_time(mut self, time: u16) -> Self {
        self.create_time = Some(time);
        self
    }

    /// 作成日付を設定（DOS形式）
    pub fn create_date(mut self, date: u16) -> Self {
        self.create_date = Some(date);
        self
    }

    /// 更新時刻を設定（DOS形式）
    pub fn modify_time(mut self, time: u16) -> Self {
        self.modify_time = Some(time);
        self
    }

    /// 更新日付を設定（DOS形式）
    pub fn modify_date(mut self, date: u16) -> Self {
        self.modify_date = Some(date);
        self
    }

    /// アクセス日付を設定（DOS形式）
    pub fn access_date(mut self, date: u16) -> Self {
        self.access_date = Some(date);
        self
    }

    /// DirEntryRawを構築
    pub fn build(self) -> DirEntryRaw {
        DirEntryRaw {
            name: self.name,
            ext: self.ext,
            attr: self.attr.bits(),
            nt_reserved: 0,
            create_time_tenths: 0,
            create_time: self.create_time.unwrap_or(0).to_le_bytes(),
            create_date: self.create_date.unwrap_or(0).to_le_bytes(),
            access_date: self.access_date.unwrap_or(0).to_le_bytes(),
            first_cluster_hi: ((self.cluster.0 >> 16) as u16).to_le_bytes(),
            modify_time: self.modify_time.unwrap_or(0).to_le_bytes(),
            modify_date: self.modify_date.unwrap_or(0).to_le_bytes(),
            first_cluster_lo: ((self.cluster.0 & 0xFFFF) as u16).to_le_bytes(),
            file_size: self.size.to_le_bytes(),
        }
    }

    // =========================================================================
    // Advanced Builder Methods
    // =========================================================================

    /// 条件付きでビルダーを変更するメソッド
    ///
    /// # Example
    /// ```ignore
    /// let entry = DirEntryBuilder::new(name, ext)
    ///     .attr(FileAttributes::from_bits_truncate(FileAttributes::ARCHIVE))
    ///     .when(is_readonly, |b| b.attr(FileAttributes::from_bits_truncate(
    ///         FileAttributes::ARCHIVE | FileAttributes::READ_ONLY
    ///     )))
    ///     .build();
    /// ```
    pub fn when<F>(self, condition: bool, f: F) -> Self
    where
        F: FnOnce(Self) -> Self,
    {
        if condition { f(self) } else { self }
    }

    /// 現在時刻で作成日時と更新日時を設定（DOS形式）
    ///
    /// # Note
    /// RTCが利用可能な場合は実際の時刻を使用します。
    /// 利用不可能な場合はダミー値を使用します。
    pub fn with_current_time(self) -> Self {
        let dos_time = get_current_dos_time();
        let dos_date = get_current_dos_date();
        self.create_time(dos_time)
            .create_date(dos_date)
            .modify_time(dos_time)
            .modify_date(dos_date)
            .access_date(dos_date)
    }

    /// 検証付きビルド
    ///
    /// クラスタ番号が有効かどうかをチェックしてからビルドします。
    pub fn build_validated(self) -> FsResult<DirEntryRaw> {
        // クラスタ番号が0でない場合は有効性をチェック
        if self.cluster.0 != 0 && !self.cluster.is_valid() {
            return Err(FsError::InvalidInput);
        }
        Ok(self.build())
    }

    /// 属性にフラグを追加
    pub fn add_attr(mut self, flag: u8) -> Self {
        self.attr = FileAttributes::from_bits_truncate(self.attr.bits() | flag);
        self
    }

    /// 読み取り専用として設定
    pub fn read_only(self) -> Self {
        self.add_attr(FileAttributes::READ_ONLY)
    }

    /// 隠しファイルとして設定
    pub fn hidden(self) -> Self {
        self.add_attr(FileAttributes::HIDDEN)
    }

    /// システムファイルとして設定
    pub fn system(self) -> Self {
        self.add_attr(FileAttributes::SYSTEM)
    }
}

/// Unixエポック秒をDOS形式の日付・時刻に変換
///
/// 現在は簡易実装（ダミー値）を返します。
pub fn unix_to_dos(unix: u64) -> (u16, u16) {
    if unix == 0 {
        return (get_current_dos_date(), get_current_dos_time());
    }
    // TODO: 正確な変換の実装
    (get_current_dos_date(), get_current_dos_time())
}

/// DOS形式の日付・時刻をUnixエポック秒に変換
pub fn dos_to_unix(date: u16, time: u16) -> u64 {
    if date == 0 {
        return 0;
    }
    // DOS Date: (year-1980) << 9 | month << 5 | day
    // DOS Time: hour << 11 | minute << 5 | (sec/2)
    let day = (date & 0x1F) as u64;
    let month = ((date >> 5) & 0x0F) as u64;
    let year = ((date >> 9) & 0x7F) as u64 + 1980;

    let sec = (time & 0x1F) as u64 * 2;
    let min = ((time >> 5) & 0x3F) as u64;
    let hour = ((time >> 11) & 0x1F) as u64;

    // 簡易的な累計秒数計算（閏年を無視した近似、または0を返す）
    // NOTE: 正確な計算には chrono 等のライブラリや詳細な実装が必要
    let days_since_1980 = (year - 1980) * 365 + (month - 1) * 30 + (day - 1);
    days_since_1980 * 24 * 3600 + hour * 3600 + min * 60 + sec
}

/// 現在のDOS形式時刻を取得（ダミー実装）
fn get_current_dos_time() -> u16 {
    (12 << 11) | (0 << 5) | 0
}

/// 現在のDOS形式日付を取得（ダミー実装）
fn get_current_dos_date() -> u16 {
    ((2024 - 1980) << 9) | (1 << 5) | 1
}

/// ディレクトリエントリの種類を表す列挙型
///
/// 生のバイト列を解析した結果を型安全に表現する。
/// if/else の条件分岐をパターンマッチに置き換えることで、
/// コードの意図が明確になり、網羅性チェックも働く。
#[derive(Debug)]
pub enum DirectoryEntryKind {
    /// ディレクトリの終端マーカー
    End,
    /// 削除済みエントリ
    Deleted,
    /// ロングファイルネームエントリ
    LongName(LfnEntry),
    /// 通常のディレクトリエントリ
    Standard(DirEntryRaw),
    /// ボリュームラベル（スキップ対象）
    VolumeLabel,
}

impl From<&[u8]> for DirectoryEntryKind {
    fn from(bytes: &[u8]) -> Self {
        let first_byte = bytes[0];

        if first_byte == END_OF_DIR {
            return DirectoryEntryKind::End;
        }
        if first_byte == DELETED_ENTRY {
            return DirectoryEntryKind::Deleted;
        }

        let attr = FileAttributes::from(bytes[11]);
        if attr.is_long_name() {
            DirectoryEntryKind::LongName(LfnEntry::from_bytes(bytes))
        } else if attr.is_volume_id() {
            DirectoryEntryKind::VolumeLabel
        } else {
            DirectoryEntryKind::Standard(DirEntryRaw::from_bytes(bytes))
        }
    }
}

/// ディレクトリエントリを遅延評価で読み込むイテレータ
///
/// 従来の `read_dir_entries` は全エントリを `Vec` に読み込んでいたが、
/// このイテレータは必要な分だけを読み込む。
///
/// # メリット
/// - **メモリ効率**: エントリ数が多い場合でも巨大な Vec を確保しない
/// - **検索パフォーマンス**: `lookup` で特定ファイルを探す際、見つかった時点で読み込みを停止
/// - **Rustらしさ**: `find()`, `filter()`, `take()` 等のイテレータメソッドが使用可能
///
/// # カーネル統合上の注意
/// ⚠️ **ヒープアロケーション**: `buffer: Vec<u8>` がクラスタサイズ分（通常4~64KB）のメモリを確保します。
/// 大量のイテレータを同時に保持する場合、メモリ消費が増大する可能性があります。
///
/// 最適化オプション:
/// - **LRUキャッシュ**: よく参照されるディレクトリのバッファを再利用（Mempool推奨）
/// - **Per-CPUバッファ**: タスクごとではなく、CPUコアごとに共有バッファを使用
/// - **ページアロケータ**: 4KB単位でのアロケーションに切り替え（クラスタサイズ < 64KB時）
///
/// # Example
/// ```ignore
/// // 特定のファイルを検索（見つかったら即終了）
/// let entry = inode.entries()?
///     .find(|res| res.as_ref().ok()
///         .map(|e| e.name == "target.txt")
///         .unwrap_or(false))
///     .transpose()?;
/// ```
pub struct DirectoryIterator<'a> {
    fs: &'a Fat32FileSystem,
    chain: ClusterChain<'a>,
    buffer: Vec<u8>,
    offset: usize,
    lfn_parts: Vec<(u8, String, u8)>,
    finished: bool,
}

impl<'a> DirectoryIterator<'a> {
    /// 新しいディレクトリイテレータを作成
    fn new(fs: &'a Fat32FileSystem, start_cluster: Cluster) -> FsResult<Self> {
        let cluster_size = fs.cluster_size();
        let mut chain = fs.clusters(start_cluster);
        let mut buffer = vec![0u8; cluster_size];

        // 最初のクラスタを読み込む
        if let Some(cluster_res) = chain.next() {
            let cluster = cluster_res?;
            fs.read_cluster(cluster, &mut buffer)?;
        }

        Ok(Self {
            fs,
            chain,
            buffer,
            offset: 0,
            lfn_parts: Vec::new(),
            finished: false,
        })
    }

    /// 次のクラスタを読み込む
    fn load_next_cluster(&mut self) -> FsResult<bool> {
        if let Some(cluster_res) = self.chain.next() {
            let cluster = cluster_res?;
            self.fs.read_cluster(cluster, &mut self.buffer)?;
            self.offset = 0;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<'a> Iterator for DirectoryIterator<'a> {
    type Item = FsResult<(String, DirEntryRaw)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let cluster_size = self.fs.cluster_size();

        loop {
            // バッファの範囲を超えたら次のクラスタを読み込む
            if self.offset + DIR_ENTRY_SIZE > cluster_size {
                match self.load_next_cluster() {
                    Ok(true) => continue,
                    Ok(false) => {
                        self.finished = true;
                        return None;
                    }
                    Err(e) => {
                        self.finished = true;
                        return Some(Err(e));
                    }
                }
            }

            let entry_bytes = &self.buffer[self.offset..self.offset + DIR_ENTRY_SIZE];
            self.offset += DIR_ENTRY_SIZE;

            // パターンマッチでエントリの種類を判定
            match DirectoryEntryKind::from(entry_bytes) {
                DirectoryEntryKind::End => {
                    self.finished = true;
                    return None;
                }
                DirectoryEntryKind::Deleted => {
                    self.lfn_parts.clear();
                    continue; // 次のエントリへ
                }
                DirectoryEntryKind::LongName(lfn) => {
                    // LFNの過剰なパーツ数をチェックしてDoSを防止
                    if self.lfn_parts.len() >= MAX_LFN_PARTS {
                        self.finished = true;
                        return Some(Err(FsError::FileSystemCorrupted));
                    }
                    self.lfn_parts
                        .push((lfn.sequence(), lfn.get_name_part(), lfn.checksum()));
                    continue; // LFNをスタックに積むだけ、ループ継続
                }
                DirectoryEntryKind::VolumeLabel => {
                    self.lfn_parts.clear();
                    continue; // ボリュームラベルは無視
                }
                DirectoryEntryKind::Standard(raw) => {
                    // ロングネームを構築
                    let name = if !self.lfn_parts.is_empty() {
                        // LFNチェックサム検証
                        let expected_checksum = raw.calculate_checksum();
                        let lfn_checksum =
                            self.lfn_parts.first().map(|(_, _, cs)| *cs).unwrap_or(0);

                        if lfn_checksum != expected_checksum {
                            // チェックサム不一致：ショートネームにフォールバック
                            self.lfn_parts.clear();
                            raw.short_name()
                        } else {
                            self.lfn_parts.sort_by_key(|&(seq, _, _)| seq);
                            let long_name: String =
                                self.lfn_parts.iter().map(|(_, s, _)| s.as_str()).collect();
                            self.lfn_parts.clear();
                            long_name
                        }
                    } else {
                        raw.short_name()
                    };

                    // "." と ".." はスキップ
                    if name == "." || name == ".." {
                        continue;
                    }

                    return Some(Ok((name, raw)));
                }
            }
        }
    }
}

// ============================================================================
// DirectoryIterator Extension Methods
// ============================================================================

impl<'a> DirectoryIterator<'a> {
    /// イテレータが完全に消費されたかチェック
    ///
    /// # Example
    /// ```ignore
    /// let mut iter = inode.entries()?;
    /// while let Some(_) = iter.next() { /* ... */ }
    /// assert!(iter.is_exhausted());
    /// ```
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.finished
    }

    /// 残りのエントリ数を推定（Iterator traitのsize_hintと同等）
    ///
    /// FAT32ディレクトリの性質上、正確な残り数は事前に分からないため、
    /// 下限は0、上限は不明(None)となる。デバッグ・進捗表示用。
    pub fn size_hint(&self) -> (usize, Option<usize>) {
        if self.finished {
            (0, Some(0))
        } else {
            // FAT32ディレクトリは可変長のため、正確な数は不明
            (0, None)
        }
    }

    /// ファイルのみをフィルタするイテレータを返す
    ///
    /// # Example
    /// ```ignore
    /// let files: Vec<_> = inode.entries()?.files().collect::<Result<Vec<_>, _>>()?;
    /// ```
    pub fn files(self) -> impl Iterator<Item = FsResult<(String, DirEntryRaw)>> + 'a {
        self.filter(|res| {
            res.as_ref()
                .map(|(_, raw)| !raw.is_directory())
                .unwrap_or(true) // エラーの場合は通過させて後で処理
        })
    }

    /// ディレクトリのみをフィルタするイテレータを返す
    ///
    /// # Example
    /// ```ignore
    /// let dirs: Vec<_> = inode.entries()?.directories().collect::<Result<Vec<_>, _>>()?;
    /// ```
    pub fn directories(self) -> impl Iterator<Item = FsResult<(String, DirEntryRaw)>> + 'a {
        self.filter(|res| {
            res.as_ref()
                .map(|(_, raw)| raw.is_directory())
                .unwrap_or(true)
        })
    }

    /// 隠しファイルを除外するイテレータを返す
    ///
    /// # Example
    /// ```ignore
    /// let visible_files: Vec<_> = inode.entries()?.visible().collect::<Result<Vec<_>, _>>()?;
    /// ```
    pub fn visible(self) -> impl Iterator<Item = FsResult<(String, DirEntryRaw)>> + 'a {
        self.filter(|res| {
            res.as_ref()
                .map(|(_, raw)| !raw.attributes().is_hidden())
                .unwrap_or(true)
        })
    }

    /// 名前でエントリを検索（大文字小文字を無視）
    ///
    /// # Example
    /// ```ignore
    /// let entry = inode.entries()?.find_by_name("readme.txt")?;
    /// ```
    pub fn find_by_name(mut self, name: &str) -> FsResult<Option<(String, DirEntryRaw)>> {
        self.find(|res| {
            res.as_ref()
                .map(|(entry_name, _)| entry_name.eq_ignore_ascii_case(name))
                .unwrap_or(false)
        })
        .transpose()
    }
}

// ============================================================================
// FAT32 Filesystem
// ============================================================================

/// FAT32ファイルシステム
///
/// # ⚠️ CRITICAL: メモリ消費に関する重要な注意事項
///
/// **現在の実装はFATテーブル全体をメモリにキャッシュします。**
/// これは小〜中規模ボリューム（〜16GB）では問題ありませんが、
/// 大容量ボリュームや物理メモリが少ない環境では深刻な問題になります。
///
/// ## メモリ消費の計算例
///
/// - 32GB, 16KB/cluster: 約200万エントリ × 4バイト = **8MB**
/// - 128GB, 32KB/cluster: 約400万エントリ × 4バイト = **16MB**
/// - 1TB, 64KB/cluster: 約1600万エントリ × 4バイト = **64MB** ⚠️
///
/// ## カーネル統合時の推奨対応
///
/// カーネルヒープが安定稼働に達したら、以下のいずれかへの移行を**強く推奨**します：
///
/// 1. **LRUブロックキャッシュ方式** (推奨)
///    - FATセクタ（512バイト単位）をLRUキャッシュで管理
///    - 最大キャッシュサイズを制限可能（例: 256KB = 512セクタ）
///    - `lru` クレートを使用した実装例は `/docs/ARCHITECTURE.md` 参照
///
/// 2. **オンデマンド読み込み方式**
///    - FATエントリへのアクセス時に該当セクタのみ読み込み
///    - `BTreeMap<SectorIdx, [Cluster; 128]>` でセクタごとにキャッシュ
///    - 未使用セクタを定期的に破棄（エイジング）
///
/// 3. **ハイブリッド方式**
///    - ボリュームサイズに応じて動的に切り替え
///    - < 4GB: 全体キャッシュ（高速）
///    - >= 4GB: LRUキャッシュ（省メモリ）
///
/// ## 実装優先度
///
/// - **Phase 1** (現在): 全体キャッシュ（シンプル・高速・小容量向け）
/// - **Phase 2** (カーネル安定後): LRUキャッシュへ移行
/// - **Phase 3** (最適化): NVMe等の高速ストレージ向けプリフェッチ最適化

// ============================================================================
// Cluster Buffer Pooling (Performance Optimization)
// ============================================================================

/// クラスタバッチ処理やディレクトリ走査用のバッファプール
///
/// ヒープアロケーションを削減し、Per-CPU的なキャッシュ効果を狙う。
pub struct ClusterBufferPool {
    /// バッファのスロット群。
    /// 本来は Per-CPU にすべきだが、ドライバの独立性を保つため Mutex 配列で代用。
    buffers: alloc::vec::Vec<spin::Mutex<Option<alloc::vec::Vec<u8>>>>,
}

impl ClusterBufferPool {
    /// 指定されたスロット数でバッファプールを作成
    pub fn new(slots: usize) -> Self {
        let mut buffers = alloc::vec::Vec::with_capacity(slots);
        for _ in 0..slots {
            buffers.push(spin::Mutex::new(None));
        }
        Self { buffers }
    }

    /// バッファを取得
    pub fn get(&self, size: usize) -> alloc::vec::Vec<u8> {
        // 簡易的な Per-CPU 的アクセス（現在はCPU ID取得APIがないためスロット0を優先）
        // TODO: current_cpu_id() を取得できる場合はそれを使用
        for slot in &self.buffers {
            if let Some(mut guard) = slot.try_lock() {
                if let Some(buf) = guard.take() {
                    if buf.len() >= size {
                        return buf;
                    }
                }
            }
        }
        alloc::vec![0u8; size]
    }

    /// バッファを返却
    pub fn put(&self, buf: alloc::vec::Vec<u8>) {
        if buf.capacity() < BLOCK_SIZE {
            return; // 小さすぎるバッファはプールしない
        }
        for slot in &self.buffers {
            if let Some(mut guard) = slot.try_lock() {
                if guard.is_none() {
                    *guard = Some(buf);
                    return;
                }
            }
        }
    }
}

/// RAII形式のバッファ管理
pub struct PooledClusterBuffer<'a> {
    pool: &'a ClusterBufferPool,
    buffer: Option<alloc::vec::Vec<u8>>,
}

impl<'a> PooledClusterBuffer<'a> {
    pub fn new(pool: &'a ClusterBufferPool, size: usize) -> Self {
        Self {
            pool,
            buffer: Some(pool.get(size)),
        }
    }
}

impl<'a> core::ops::Deref for PooledClusterBuffer<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().unwrap()
    }
}

impl<'a> core::ops::DerefMut for PooledClusterBuffer<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().unwrap()
    }
}

impl<'a> Drop for PooledClusterBuffer<'a> {
    fn drop(&mut self) {
        if let Some(buf) = self.buffer.take() {
            self.pool.put(buf);
        }
    }
}
pub struct Fat32FileSystem {
    /// ブロックデバイス
    device: Arc<dyn BlockDevice>,
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
    /// FATキャッシュ（Cluster型でキャッシュ）- 小容量ボリューム用
    ///
    /// full_fat_cacheがtrueの場合のみ使用。大容量ボリュームではfat_sector_cacheを使用。
    fat_cache: RwLock<Vec<Cluster>>,
    /// FATセクタキャッシュ（LRU）- 大容量ボリューム用
    ///
    /// セクタ単位でFATをキャッシュし、メモリ使用量を制限する。
    fat_sector_cache: FatSectorCache,
    /// FAT全体をメモリに配置しているかフラグ
    full_fat_cache: bool,
    /// 空きクラスタ数
    free_clusters: RwLock<u32>,
    /// FATサイズ（セクタ数）
    fat_size: u32,
    /// ダーティセクタのビットマップ（バッチ書き込み用）
    /// 各ビットが1セクタ分のダーティ状態を表す
    dirty_sectors: RwLock<Vec<bool>>,
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

/// クラスタチェーンを走査するイテレータ
///
/// FAT32のクラスタチェーンをRustのイテレータとして抽象化。
/// `while cluster.is_valid() { ... get_next ... }` のループパターンを
/// 排除し、`for`ループや`skip()`、`take()`等のイテレータメソッドを活用可能にする。
///
/// # Example
/// ```ignore
/// // 3番目のクラスタから読み取り開始
/// for cluster_res in fs.clusters(start).skip(2) {
///     let cluster = cluster_res?;
///     // クラスタを処理
/// }
/// ```
pub struct ClusterChain<'a> {
    fs: &'a Fat32FileSystem,
    current: Cluster,
    count: usize,
}

impl<'a> ClusterChain<'a> {
    /// 新しいクラスタチェーンイテレータを作成
    fn new(fs: &'a Fat32FileSystem, start: Cluster) -> Self {
        Self {
            fs,
            current: start,
            count: 0,
        }
    }
}

impl<'a> Iterator for ClusterChain<'a> {
    type Item = FsResult<Cluster>;

    fn next(&mut self) -> Option<Self::Item> {
        // 無効なクラスタは終端
        if !self.current.is_valid() {
            return None;
        }

        // 無限ループ検出
        self.count += 1;
        if self.count > MAX_CLUSTER_CHAIN {
            self.current = Cluster::EOF;
            return Some(Err(FsError::FileSystemCorrupted));
        }

        let current = self.current;

        // 次のクラスタを取得して状態を更新
        match self.fs.read_fat_entry(current) {
            Ok(next) => {
                self.current = next;
                Some(Ok(current))
            }
            Err(e) => {
                self.current = Cluster::EOF; // エラー時は停止
                Some(Err(e))
            }
        }
    }
}

impl Fat32FileSystem {
    /// 指定されたクラスタから始まるクラスタチェーンのイテレータを返す
    ///
    /// # Arguments
    /// * `start` - チェーンの開始クラスタ
    ///
    /// # Returns
    /// クラスタ番号を順に返すイテレータ。各要素は`FsResult<Cluster>`。
    pub fn clusters(&self, start: Cluster) -> ClusterChain<'_> {
        ClusterChain::new(self, start)
    }

    /// ディレクトリエントリをキャッシュ付きで読み取る
    ///
    /// キャッシュヒット時はディスクI/Oとパース処理をスキップして高速に返す。
    /// キャッシュミス時は通常のイテレータで全エントリを読み取りキャッシュに保存。
    ///
    /// # Arguments
    /// * `start_cluster` - ディレクトリの開始クラスタ
    ///
    /// # Returns
    /// パース済みのディレクトリエントリリスト
    pub fn read_dir_cached(&self, start_cluster: Cluster) -> FsResult<Vec<(String, DirEntryRaw)>> {
        // キャッシュをチェック
        if let Some(entries) = self.dir_cache.get(start_cluster) {
            return Ok(entries);
        }

        // キャッシュミス: イテレータで全エントリを読み取り
        let iter = DirectoryIterator::new(self, start_cluster)?;
        let entries: Vec<(String, DirEntryRaw)> = iter.collect::<Result<Vec<_>, _>>()?;

        // キャッシュに保存
        self.dir_cache.insert(start_cluster, entries.clone());

        Ok(entries)
    }

    /// ディレクトリキャッシュを無効化
    ///
    /// ファイル/ディレクトリの追加・削除・リネーム時に呼び出す。
    ///
    /// # Arguments
    /// * `cluster` - 無効化するディレクトリの開始クラスタ
    pub fn invalidate_dir_cache(&self, cluster: Cluster) {
        self.dir_cache.invalidate(cluster);
    }

    /// 時刻プロバイダーを設定
    ///
    /// カーネルのRTCドライバと連携するためのフック。
    /// デフォルトでは`DummyTimeProvider`が使用される。
    ///
    /// # Example
    /// ```ignore
    /// struct KernelTimeProvider;
    /// impl TimeProvider for KernelTimeProvider {
    ///     fn current_dos_time(&self) -> u16 { /* RTC から取得 */ }
    ///     fn current_dos_date(&self) -> u16 { /* RTC から取得 */ }
    /// }
    ///
    /// let fs = Fat32FileSystem::mount(device)?;
    /// // Note: requires interior mutability pattern for Arc<Self>
    /// ```
    ///
    /// # Note
    /// この関数はマウント後にファイルシステムを変更するため、
    /// `Arc<Self>` での使用には別途パターンが必要です。
    /// 現在はマウント時のオプションとして使用することを推奨。
    pub fn time_provider(&self) -> &dyn TimeProvider {
        self.time_provider.as_ref()
    }

    /// FAT32ファイルシステムをマウント
    pub fn mount(device: Arc<dyn BlockDevice>) -> FsResult<Arc<Self>> {
        // ブートセクタを読み取り
        let mut boot_data = [0u8; BOOT_SECTOR_SIZE];
        device.read_sync(0, &mut boot_data)?;

        // TryFrom トレイトで安全にパース
        let boot_sector = BootSector::try_from(&boot_data[..])?;

        // FAT32であることを確認
        let fs_type = boot_sector.fs_type();
        if &fs_type[0..5] != b"FAT32" {
            return Err(FsError::InvalidInput);
        }

        // 各パラメータを計算（型安全）
        // 型変換と安全性チェック（オーバーフローやゼロ除算を回避）
        let fat_start_sector = Sector(boot_sector.reserved_sectors() as u32);
        let fat_size = boot_sector.fat_size_32();
        let num_fats = boot_sector.num_fats() as u32;

        // fat_area_size = fat_size * num_fats
        let fat_area_size = fat_size
            .checked_mul(num_fats)
            .ok_or(FsError::FileSystemCorrupted)?;

        let data_start_sector = fat_start_sector + fat_area_size;

        let total_sectors = boot_sector.total_sectors();
        let data_sectors = total_sectors
            .checked_sub(data_start_sector.0)
            .ok_or(FsError::FileSystemCorrupted)?;

        let sectors_per_cluster = boot_sector.sectors_per_cluster() as u32;
        if sectors_per_cluster == 0 {
            return Err(FsError::FileSystemCorrupted);
        }

        let total_clusters = data_sectors
            .checked_div(sectors_per_cluster)
            .ok_or(FsError::FileSystemCorrupted)?;

        // デバイスIDを生成（静的カウンタを使用）
        static DEVICE_ID_COUNTER: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(1);
        let device_id = DEVICE_ID_COUNTER.fetch_add(1, core::sync::atomic::Ordering::SeqCst);

        // ブロックキャッシュを作成（512バイトブロック、32MB上限）
        let block_cache = Arc::new(LRUBlockCache::new(
            BLOCK_SIZE,
            32 * 1024 * 1024, // 32MB キャッシュ上限
        ));

        // Decide whether to fully cache FAT table in RAM or use on-demand mode
        let fat_entry_count = (fat_size as usize) * (BLOCK_SIZE / 4);
        let full_fat_cache = fat_entry_count * 4 <= MAX_FULL_FAT_CACHE_BYTES;

        let fs = Arc::new(Self {
            device,
            device_id,
            fat_start_sector,
            data_start_sector,
            sectors_per_cluster,
            total_clusters,
            root_cluster: boot_sector.root_cluster(),
            fat_cache: RwLock::new(Vec::new()),
            fat_sector_cache: FatSectorCache::new(DEFAULT_FAT_SECTOR_CACHE_SIZE),
            full_fat_cache,
            free_clusters: RwLock::new(0),
            fat_size,
            dirty_sectors: RwLock::new(vec![false; fat_size as usize]),
            block_cache,
            cluster_buffer_pool: Arc::new(ClusterBufferPool::new(16)), // 16スロットあれば通常十分
            time_provider: Arc::new(DummyTimeProvider),
            fs_info_sector: Sector::from(boot_sector.fs_info_sector() as u32),
            dir_cache: DirEntryCache::new(DEFAULT_DIR_CACHE_SIZE),
        });

        // FATをキャッシュに読み込み（必要に応じてオンデマンドモード）
        if fs.full_fat_cache {
            fs.load_fat()?;
        } else {
            // FSInfoセクタから空きクラスタ数を取得（高速）
            let free = match fs.read_fsinfo() {
                Ok(fsinfo) => fsinfo.free_count().unwrap_or_else(|| {
                    // FSInfoに無効な値がある場合はディスクから集計
                    (&*fs).count_free_clusters_on_disk().unwrap_or(0)
                }),
                Err(_) => {
                    // FSInfo読み取り失敗時はディスクから集計
                    (&*fs).count_free_clusters_on_disk()?
                }
            };
            *fs.free_clusters.write() = free;
        }

        Ok(fs)
    }

    /// FATテーブルを読み込み
    ///
    /// # ⚠️ メモリ枯渇の懸念（カーネル統合時の重要事項）
    ///
    /// 現在の実装では、**FAT全体をヒープに連続確保**します。
    /// 大容量ボリューム(32GB以上)では、FATだけで数十MB〜数百MBのRAMを消費します。
    ///
    /// ## メモリ消費の実例
    ///
    /// - 32GB, 4KB/cluster => 約8M エントリ => **32MB RAM**
    /// - 64GB, 16KB/cluster => 約4M エントリ => **16MB RAM**
    /// - 1TB, 4KB/cluster => 約256M エントリ => **1GB RAM** ⚠️ カーネルヒープを圧迫！
    ///
    /// ## 推奨される改善策
    ///
    /// **Phase 2（カーネル安定後）への移行を強く推奨：**
    ///
    /// 1. **LRUブロックキャッシュ** (最優先)
    ///    - セクタ単位でキャッシュ（512バイト = 128エントリ）
    ///    - 最大キャッシュサイズを制限（例: 256KB = 512セクタ）
    ///    - `lru` クレートまたは独自実装
    ///
    /// 2. **Btree方式**
    ///    - `BTreeMap<SectorIdx, Box<[Cluster; 128]>>`
    ///    - アクセス頻度の低いセクタを自動破棄
    ///
    /// 3. **ハイブリッド方式**
    ///    - ボリュームサイズに応じて動的切り替え
    ///    - < 4GB: 全体キャッシュ（現行）
    ///    - >= 4GB: LRUキャッシュ
    ///
    /// ## スタック消費の最適化
    ///
    /// `buffer` はスタック上に512バイト確保していますが、これは許容範囲です。
    /// カーネルスタックが4KB未満の環境では、将来的に以下を検討：
    ///
    /// - ページアロケータから直接ページを取得（ヒープを経由しない）
    /// - Per-CPUの共有バッファを使用（スピンロック保護）
    ///
    /// # 現状の使用想定
    ///
    /// 小〜中規模ボリューム（〜16GB）での使用を想定しています。
    fn load_fat(&self) -> FsResult<()> {
        let sectors = self.fat_size as usize;
        let entries = sectors * BLOCK_SIZE / 4;

        // ヒープから連続した領域を確保（大容量ボリュームではリスク）
        let mut fat = vec![Cluster::FREE; entries];

        // スタック上のバッファ（512バイト、カーネルスタックが4KB以上なら安全）
        let mut buffer = [0u8; BLOCK_SIZE];

        for i in 0..sectors {
            let sector = self.fat_start_sector + i as u32;
            // Use cached reads to warm the LRU block cache when enabled
            self.read_sector_cached(sector.as_u64(), &mut buffer)?;

            for j in 0..BLOCK_SIZE / 4 {
                let idx = i * (BLOCK_SIZE / 4) + j;
                if idx < entries {
                    let val = u32::from_le_bytes([
                        buffer[j * 4],
                        buffer[j * 4 + 1],
                        buffer[j * 4 + 2],
                        buffer[j * 4 + 3],
                    ]) & 0x0FFFFFFF;
                    fat[idx] = Cluster(val);
                }
            }
        }

        // 空きクラスタを数える
        let free = fat.iter().filter(|c| c.is_free()).count() as u32;

        *self.fat_cache.write() = fat;
        *self.free_clusters.write() = free;

        Ok(())
    }

    /// FATをディスク上から走査して空きクラスタ数をカウントする（オンデマンドモードで使用）
    fn count_free_clusters_on_disk(&self) -> FsResult<u32> {
        let sectors = self.fat_size as usize;
        let entries = sectors * BLOCK_SIZE / 4;

        let mut free: u32 = 0;
        let mut buffer = [0u8; BLOCK_SIZE];

        for i in 0..sectors {
            let sector = self.fat_start_sector + i as u32;
            // キャッシュ経由で読み取り（既にキャッシュが有効な場合はヒットする）
            self.read_sector_cached(sector.as_u64(), &mut buffer)?;

            for j in 0..(BLOCK_SIZE / 4) {
                let idx = i * (BLOCK_SIZE / 4) + j;
                if idx >= entries {
                    break;
                }
                let val = u32::from_le_bytes([
                    buffer[j * 4],
                    buffer[j * 4 + 1],
                    buffer[j * 4 + 2],
                    buffer[j * 4 + 3],
                ]) & 0x0FFFFFFF;
                if val == 0 {
                    free = free.saturating_add(1);
                }
            }
        }

        Ok(free)
    }

    /// クラスタ番号からセクタ番号を計算(型安全)
    ///
    /// # Panics
    /// クラスタ番号が無効な場合(<2)はパニックする
    fn cluster_to_sector(&self, cluster: Cluster) -> Sector {
        assert!(cluster.0 >= 2, "Invalid cluster number: {}", cluster.0);
        // クラスタ2がデータ領域の先頭
        self.data_start_sector + (cluster.0 - 2) * self.sectors_per_cluster
    }

    /// FATエントリを読み取り（型安全）
    fn read_fat_entry(&self, cluster: Cluster) -> FsResult<Cluster> {
        trace_fat_operation!("read", cluster);
        let idx = cluster.0 as usize;
        if self.full_fat_cache {
            let fat = self.fat_cache.read();
            if idx >= fat.len() {
                return Err(FsError::InvalidInput);
            }
            Ok(fat[idx])
        } else {
            // オンデマンドモード: FatSectorCacheを使用
            let entries = (self.fat_size as usize) * (BLOCK_SIZE / 4);
            if idx >= entries {
                return Err(FsError::InvalidInput);
            }

            let fat_offset = idx * 4;
            let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
            let offset_in_sector = (fat_offset % BLOCK_SIZE) / 4;

            // FatSectorCacheをチェック
            if let Some(sector_data) = self.fat_sector_cache.get(sector_offset) {
                // キャッシュヒット
                return Ok(sector_data[offset_in_sector]);
            }

            // キャッシュミス: ディスクから読み込み
            let sector = self.fat_start_sector + sector_offset;
            let mut buffer = [0u8; BLOCK_SIZE];
            self.read_sector_cached(sector.as_u64(), &mut buffer)?;

            // バイト配列をClusterのVecに変換
            let mut sector_data = Vec::with_capacity(FAT_ENTRIES_PER_SECTOR);
            for i in 0..FAT_ENTRIES_PER_SECTOR {
                let off = i * 4;
                let val = u32::from_le_bytes([
                    buffer[off],
                    buffer[off + 1],
                    buffer[off + 2],
                    buffer[off + 3],
                ]) & 0x0FFFFFFF;
                sector_data.push(Cluster(val));
            }

            let result = sector_data[offset_in_sector];

            // キャッシュに追加（エビクションされたセクタがダーティなら書き戻し）
            if let Some((evicted_idx, evicted_data, was_dirty)) =
                self.fat_sector_cache.insert(sector_offset, sector_data)
            {
                if was_dirty {
                    self.flush_fat_sector(evicted_idx, &evicted_data)?;
                }
            }

            Ok(result)
        }
    }

    /// FATエントリを書き込み(型安全、遅延書き込み対応)
    ///
    /// キャッシュへの書き込みと、該当セクタへのダーティマーク付けを行う。
    /// 実際のディスク書き込みは`flush_dirty_fat_sectors()`または`sync()`で行われる。
    pub fn sync(&self) -> FsResult<()> {
        if self.full_fat_cache {
            self.flush_dirty_fat_sectors()?;
        } else {
            // FatSectorCacheのダーティセクタをフラッシュ
            let dirty_sectors = self.fat_sector_cache.take_dirty_sectors();
            for (sector_idx, sector_data) in dirty_sectors {
                self.flush_fat_sector(sector_idx, &sector_data)?;
            }
        }

        // FSInfoセクタを更新
        self.write_fsinfo()?;

        self.device.flush().map_err(Into::into)
    }

    /// FSInfoセクタを読み取る
    pub fn read_fsinfo(&self) -> FsResult<FsInfo> {
        // FSInfoセクタ番号が0の場合は無効
        if self.fs_info_sector.0 == 0 {
            return Err(FsError::NotSupported);
        }

        let mut buffer = [0u8; BLOCK_SIZE];
        self.read_sector_cached(self.fs_info_sector.as_u64(), &mut buffer)?;
        FsInfo::from_bytes(&buffer)
    }

    /// FSInfoセクタを書き込む
    pub fn write_fsinfo(&self) -> FsResult<()> {
        // FSInfoセクタ番号が0の場合は無効
        if self.fs_info_sector.0 == 0 {
            return Ok(()); // FSInfoが無効な場合は何もしない
        }

        // 現在のFSInfoを読み取り
        let mut fsinfo = match self.read_fsinfo() {
            Ok(info) => info,
            Err(_) => {
                // 読み取れない場合は新規作成
                FsInfo::new(FSINFO_UNKNOWN, FSINFO_UNKNOWN)
            }
        };

        // 空きクラスタ数を更新
        fsinfo.set_free_count(*self.free_clusters.read());

        // セクタに書き込み
        let buffer = fsinfo.to_bytes();
        self.write_sector_cached(self.fs_info_sector.as_u64(), &buffer)?;

        Ok(())
    }

    /// FATセクタをディスクに書き込む（プライマリFATとバックアップFAT）
    fn flush_fat_sector(&self, sector_idx: u32, sector_data: &[Cluster]) -> FsResult<()> {
        let sector = self.fat_start_sector + sector_idx;

        // ClusterのVecをバイト配列に変換
        let mut buffer = [0u8; BLOCK_SIZE];
        for (i, cluster) in sector_data.iter().enumerate().take(FAT_ENTRIES_PER_SECTOR) {
            let bytes = (cluster.0 & 0x0FFFFFFF).to_le_bytes();
            let off = i * 4;
            buffer[off..off + 4].copy_from_slice(&bytes);
        }

        // プライマリFAT
        self.write_sector_cached(sector.as_u64(), &buffer)?;
        // バックアップFAT
        let fat2_sector = sector + self.fat_size;
        self.write_sector_cached(fat2_sector.as_u64(), &buffer)?;

        Ok(())
    }

    fn write_fat_entry(&self, cluster: Cluster, value: Cluster) -> FsResult<()> {
        trace_fat_operation!("write", cluster, "value={}", value.0);
        let idx = cluster.0 as usize;
        if self.full_fat_cache {
            {
                let mut fat = self.fat_cache.write();
                if idx >= fat.len() {
                    return Err(FsError::InvalidInput);
                }
                fat[idx] = value;
            }

            // 該当セクタをダーティとしてマーク
            let sector_idx = (idx * 4) / BLOCK_SIZE;
            {
                let mut dirty = self.dirty_sectors.write();
                if sector_idx < dirty.len() {
                    dirty[sector_idx] = true;
                }
            }

            Ok(())
        } else {
            // オンデマンドモード: FatSectorCacheを使用（遅延書き込み）
            let sectors = self.fat_size as usize;
            let entries = sectors * BLOCK_SIZE / 4;
            if idx >= entries {
                return Err(FsError::InvalidInput);
            }

            let fat_offset = idx * 4;
            let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
            let offset_in_sector = (fat_offset % BLOCK_SIZE) / 4;

            // キャッシュにセクタがあれば直接更新
            if self
                .fat_sector_cache
                .update_entry(sector_offset, offset_in_sector, value)
            {
                // キャッシュ更新成功、ダーティマーク済み
                return Ok(());
            }

            // キャッシュにない場合、セクタをロードしてから更新
            let sector = self.fat_start_sector + sector_offset;
            let mut buffer = [0u8; BLOCK_SIZE];
            self.read_sector_cached(sector.as_u64(), &mut buffer)?;

            // 以前の値を取得（free cluster count更新用）
            let old_val = u32::from_le_bytes([
                buffer[offset_in_sector * 4],
                buffer[offset_in_sector * 4 + 1],
                buffer[offset_in_sector * 4 + 2],
                buffer[offset_in_sector * 4 + 3],
            ]) & 0x0FFFFFFF;

            // バイト配列をClusterのVecに変換
            let mut sector_data = Vec::with_capacity(FAT_ENTRIES_PER_SECTOR);
            for i in 0..FAT_ENTRIES_PER_SECTOR {
                let off = i * 4;
                let val = u32::from_le_bytes([
                    buffer[off],
                    buffer[off + 1],
                    buffer[off + 2],
                    buffer[off + 3],
                ]) & 0x0FFFFFFF;
                sector_data.push(Cluster(val));
            }

            // 値を更新
            sector_data[offset_in_sector] = value;

            // キャッシュに追加（エビクションされたセクタがダーティなら書き戻し）
            if let Some((evicted_idx, evicted_data, was_dirty)) =
                self.fat_sector_cache.insert(sector_offset, sector_data)
            {
                if was_dirty {
                    self.flush_fat_sector(evicted_idx, &evicted_data)?;
                }
            }

            // 新しく追加したセクタをダーティとしてマーク
            self.fat_sector_cache.mark_dirty(sector_offset);

            // free cluster count を更新
            if old_val == 0 && value.0 != 0 {
                let mut free = self.free_clusters.write();
                *free = free.saturating_sub(1);
            } else if old_val != 0 && value.0 == 0 {
                let mut free = self.free_clusters.write();
                *free = free.saturating_add(1);
            }

            Ok(())
        }
    }

    /// FATエントリを即座にディスクに書き込む(内部用)
    ///
    /// クリティカルな操作（クラスタ割り当て等）で使用。
    /// 通常の書き込みは`write_fat_entry`を使用し、
    /// バッチでフラッシュすることを推奨。
    fn write_fat_entry_to_disk(&self, cluster: Cluster, value: Cluster) -> FsResult<()> {
        trace_fat_operation!("write_disk", cluster, "value={}", value.0);
        let idx = cluster.0 as usize;
        // ディスクへの書き込みは2モード対応
        let fat_offset = idx * 4;
        let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
        let sector = self.fat_start_sector + sector_offset;
        let offset_in_sector = fat_offset % BLOCK_SIZE;

        let mut buffer = [0u8; BLOCK_SIZE];
        if self.full_fat_cache {
            // full cache の場合はメモリ上のfatを元にセクタを組み立てる
            let fat = self.fat_cache.read();
            let entry_start = sector_offset as usize * (BLOCK_SIZE / 4);
            let entry_end = (entry_start + BLOCK_SIZE / 4).min(fat.len());
            for (j, entry_idx) in (entry_start..entry_end).enumerate() {
                let bytes = (fat[entry_idx].0 & 0x0FFFFFFF).to_le_bytes();
                buffer[j * 4..j * 4 + 4].copy_from_slice(&bytes);
            }
            // 新しい値を書き込む（メモリ側がまだ更新されていないケースでも対応）
            let new_bytes = (value.0 & 0x0FFFFFFF).to_le_bytes();
            buffer[offset_in_sector..offset_in_sector + 4].copy_from_slice(&new_bytes);
        } else {
            // オンデマンド・モードならキャッシュ経由で読み取り（必要な部分だけ変更）
            self.read_sector_cached(sector.as_u64(), &mut buffer)?;
            let bytes = (value.0 & 0x0FFFFFFF).to_le_bytes();
            buffer[offset_in_sector..offset_in_sector + 4].copy_from_slice(&bytes);
        }

        self.write_sector_cached(sector.as_u64(), &buffer)?;

        // バックアップFAT(FAT2)への書き込み
        let fat2_sector = sector + self.fat_size;
        self.write_sector_cached(fat2_sector.as_u64(), &buffer)?;

        // このセクタはクリーンとしてマーク
        // 完了したのでダーティフラグをクリア
        {
            let mut dirty = self.dirty_sectors.write();
            if (sector_offset as usize) < dirty.len() {
                dirty[sector_offset as usize] = false;
            }
        }

        Ok(())
    }

    /// ダーティなFATセクタをまとめてディスクに書き込む
    ///
    /// # Performance
    /// 連続したダーティセクタを検出し、可能な限りまとめてI/Oを行う。
    /// バックアップFATへの書き込みも同時に行う。
    ///
    /// # Returns
    /// 書き込んだセクタ数
    fn flush_dirty_fat_sectors(&self) -> FsResult<usize> {
        let fat = self.fat_cache.read();
        let mut dirty = self.dirty_sectors.write();

        let mut flushed_count = 0usize;
        let mut buffer = [0u8; BLOCK_SIZE];

        for sector_idx in 0..dirty.len() {
            if !dirty[sector_idx] {
                continue;
            }

            // セクタの内容を構築
            let entry_start = sector_idx * (BLOCK_SIZE / 4);
            let entry_end = (entry_start + BLOCK_SIZE / 4).min(fat.len());

            for (j, entry_idx) in (entry_start..entry_end).enumerate() {
                let bytes = (fat[entry_idx].0 & 0x0FFFFFFF).to_le_bytes();
                buffer[j * 4..j * 4 + 4].copy_from_slice(&bytes);
            }

            // プライマリFATへ書き込み（キャッシュ経由で書き込みとキャッシュ更新）
            let sector = self.fat_start_sector + sector_idx as u32;
            self.write_sector_cached(sector.as_u64(), &buffer)?;

            // バックアップFAT(FAT2)への書き込み（キャッシュ経由）
            let fat2_sector = sector + self.fat_size;
            self.write_sector_cached(fat2_sector.as_u64(), &buffer)?;

            dirty[sector_idx] = false;
            flushed_count += 1;
        }

        Ok(flushed_count)
    }

    /// 空きクラスタを割り当て(型安全、アトミック)
    ///
    /// # Race Condition Fix
    /// 検索と確保を同一の書き込みロック区間内で実行することで、
    /// 複数スレッドが同じクラスタを確保するTOCTOU脆弱性を防止。
    fn allocate_cluster(&self) -> FsResult<Cluster> {
        // 最初から書き込みロックを取得してアトミック性を確保
        let mut fat_guard = self.fat_cache.write();

        // クラスタ2から検索開始
        let entries = if self.full_fat_cache {
            fat_guard.len()
        } else {
            (self.fat_size as usize) * (BLOCK_SIZE / 4)
        };

        for i in 2..entries {
            let is_free = if self.full_fat_cache {
                fat_guard[i].is_free()
            } else {
                // オンデマンドモード: セクタ読み取りで判定
                match self.read_fat_entry(Cluster(i as u32)) {
                    Ok(cluster) => cluster.is_free(),
                    Err(_) => false,
                }
            };

            if is_free {
                let cluster = Cluster(i as u32);

                // ディスクに即時書き込み
                // この処理はロックを保持したまま行う (整合性優先)
                trace_fat_operation!("allocate", cluster);
                self.write_fat_entry_to_disk(cluster, Cluster::EOF)?;

                // メモリキャッシュ側を更新(フルキャッシュ時のみ)
                if self.full_fat_cache {
                    fat_guard[i] = Cluster::EOF;
                }

                // 空きカウントを更新
                let mut free = self.free_clusters.write();
                *free = free.saturating_sub(1);
                drop(free);
                drop(fat_guard);

                return Ok(cluster);
            }
        }
        Err(FsError::StorageFull)
    }

    /// クラスタを解放(型安全)
    fn free_cluster(&self, cluster: Cluster) -> FsResult<()> {
        trace_fat_operation!("free", cluster);
        self.write_fat_entry(cluster, Cluster::FREE)?;
        let mut free = self.free_clusters.write();
        *free += 1;
        Ok(())
    }

    /// クラスタチェーンを解放(型安全、無限ループ対策)
    ///
    /// # Implementation Note
    /// `ClusterChain` イテレータを使用することで、
    /// ループカウンタの手動管理を排除し、コードを簡潔化。
    /// 無限ループ検出はイテレータ内部で行われる。
    fn free_cluster_chain(&self, start_cluster: Cluster) -> FsResult<()> {
        // collect で先にすべてのクラスタを取得（イテレート中にFATを変更するため）
        let clusters: Vec<Cluster> = self.clusters(start_cluster).collect::<FsResult<Vec<_>>>()?;

        for cluster in clusters {
            self.free_cluster(cluster)?;
        }

        Ok(())
    }

    /// クラスタを読み取り（型安全）
    ///
    /// 単一クラスタの読み取りは、連続クラスタ読み取りの特殊ケース(count=1)として実装
    fn read_cluster(&self, cluster: Cluster, buffer: &mut [u8]) -> FsResult<()> {
        self.read_contiguous_clusters(cluster, 1, buffer)
    }

    /// クラスタを書き込み（型安全）
    ///
    /// 単一クラスタの書き込みは、連続クラスタ書き込みの特殊ケース(count=1)として実装
    fn write_cluster(&self, cluster: Cluster, buffer: &[u8]) -> FsResult<()> {
        self.write_contiguous_clusters(cluster, 1, buffer)
    }

    // ========================================================================
    // Batch Operations (Performance Optimizations)
    // ========================================================================

    /// 連続したクラスタをバッチで読み取り（最適化版）
    ///
    /// FAT32ではファイルのクラスタが連続して配置されることが多いため、
    /// 連続したクラスタを一度のI/O操作でまとめて読み取ることで
    /// パフォーマンスを大幅に向上させます。
    ///
    /// # Algorithm
    /// 1. クラスタチェーンを走査し、連続した（物理的に隣接する）クラスタを検出
    /// 2. 連続したクラスタ群をまとめて一回のI/Oで読み取り
    /// 3. 非連続部分は通常の単一クラスタ読み取りにフォールバック
    ///
    /// # Arguments
    /// * `start_cluster` - 読み取り開始クラスタ
    /// * `buffer` - 読み取りデータを格納するバッファ
    ///
    /// # Returns
    /// 実際に読み取ったバイト数
    ///
    /// # Example
    /// ```ignore
    /// let mut buffer = vec![0u8; file_size];
    /// let bytes_read = fs.read_clusters_batch(start_cluster, &mut buffer)?;
    /// ```
    pub fn read_clusters_batch(
        &self,
        start_cluster: Cluster,
        buffer: &mut [u8],
    ) -> FsResult<usize> {
        let (bytes_read, error) = self.read_clusters_batch_internal(start_cluster, buffer, false);
        match error {
            Some(e) => Err(e),
            None => Ok(bytes_read),
        }
    }

    /// クラスタバッチ読み取りの内部実装
    ///
    /// # Arguments
    /// * `start_cluster` - 読み取り開始クラスタ
    /// * `buffer` - 読み取りデータを格納するバッファ
    /// * `allow_partial` - 部分的な読み取りを許容するか（エラー時の挙動を制御）
    ///
    /// # Returns
    /// `(bytes_read, first_error)` - 読み取れたバイト数と最初のエラー
    fn read_clusters_batch_internal(
        &self,
        start_cluster: Cluster,
        buffer: &mut [u8],
        allow_partial: bool,
    ) -> (usize, Option<FsError>) {
        let cluster_size = self.cluster_size();
        let max_clusters = self.buffer_cluster_capacity(buffer);

        if max_clusters == 0 {
            return (0, None);
        }

        let mut total_read = 0usize;
        let mut current_cluster = start_cluster;
        let mut clusters_read = 0usize;
        let mut first_error: Option<FsError> = None;

        while clusters_read < max_clusters && first_error.is_none() {
            // 連続したクラスタの開始点と長さを検出
            match self.find_contiguous_clusters(current_cluster, max_clusters - clusters_read) {
                Ok((contiguous_start, contiguous_count)) => {
                    if contiguous_count == 0 {
                        break;
                    }

                    // 連続したクラスタをバッチ読み取り
                    let batch_size = contiguous_count * cluster_size;
                    let buffer_offset = clusters_read * cluster_size;

                    if let Err(e) = self.read_contiguous_clusters(
                        contiguous_start,
                        contiguous_count,
                        &mut buffer[buffer_offset..buffer_offset + batch_size],
                    ) {
                        first_error = Some(e);
                        if !allow_partial {
                            break;
                        }
                    } else {
                        total_read += batch_size;
                        clusters_read += contiguous_count;
                    }

                    // 次のクラスタを取得
                    match self.get_next_cluster_after_batch(contiguous_start, contiguous_count) {
                        Ok(Some(next)) => current_cluster = next,
                        Ok(None) => break, // チェーン終端
                        Err(e) => {
                            first_error = Some(e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    first_error = Some(e);
                    break;
                }
            }
        }

        (total_read, first_error)
    }

    /// 連続したクラスタの数を検出
    ///
    /// # Arguments
    /// * `start` - 検索開始クラスタ
    /// * `max_count` - 最大検索数
    ///
    /// # Returns
    /// (開始クラスタ, 連続クラスタ数) のタプル
    fn find_contiguous_clusters(
        &self,
        start: Cluster,
        max_count: usize,
    ) -> FsResult<(Cluster, usize)> {
        if !start.is_valid() || start.is_eof() {
            return Ok((start, 0));
        }

        let mut count = 1usize;
        let mut current = start;

        while count < max_count {
            let next = if self.full_fat_cache {
                let fat = self.fat_cache.read();
                let idx = current.0 as usize;
                if idx >= fat.len() {
                    break;
                }
                fat[idx]
            } else {
                // オンデマンド: 個別のFATエントリを読み込む
                self.read_fat_entry(current)?
            };

            // EOFまたは無効なクラスタで終了
            if next.is_eof() || !next.is_valid() {
                break;
            }

            // 連続性をチェック（次のクラスタが物理的に隣接しているか）
            if next.0 != current.0 + 1 {
                break;
            }

            current = next;
            count += 1;
        }

        Ok((start, count))
    }

    /// 連続したクラスタを一括読み取り
    ///
    /// # Arguments
    /// * `start` - 開始クラスタ
    /// * `count` - クラスタ数
    /// * `buffer` - 出力バッファ
    fn read_contiguous_clusters(
        &self,
        start: Cluster,
        count: usize,
        buffer: &mut [u8],
    ) -> FsResult<()> {
        let cluster_size = self.cluster_size();
        let expected_size = count * cluster_size;

        if buffer.len() < expected_size {
            return Err(FsError::InvalidInput);
        }

        let start_sector = self.cluster_to_sector(start);
        let total_sectors = count * self.sectors_per_cluster as usize;

        // 1. デバイスから一括読み取り（パフォーマンス向上の核心）
        self.device
            .read_sync(start_sector.as_u64(), &mut buffer[..expected_size])?;

        // 2. キャッシュの同期
        // 読み取ったデータをキャッシュに反映させることで次回以降のヒット率を高める。
        // ただし、既にキャッシュにあるものは（ダーティな可能性があるため）上書きしない。
        for i in 0..total_sectors {
            let sector = start_sector + i as u32;
            let offset = i * BLOCK_SIZE;
            self.update_cache_if_missing(sector.as_u64(), &buffer[offset..offset + BLOCK_SIZE]);
        }

        Ok(())
    }

    /// キャッシュを使用してセクタを読み取る
    ///
    /// キャッシュにヒットした場合はキャッシュからコピー、
    /// ミスの場合はデバイスから読み取りキャッシュに追加。
    fn read_sector_cached(&self, sector: u64, buffer: &mut [u8]) -> FsResult<()> {
        // キャッシュヒットを試行
        if let Some(cached_block) = self.block_cache.get(self.device_id, sector) {
            // キャッシュヒット: データをコピー
            let data = cached_block.data();
            let data_guard = data.read();
            let copy_len = buffer.len().min(data_guard.len());
            buffer[..copy_len].copy_from_slice(&data_guard[..copy_len]);
            return Ok(());
        }

        // キャッシュミス: デバイスから読み取り
        let mut sector_buf = alloc::vec![0u8; BLOCK_SIZE];
        self.device.read_sync(sector, &mut sector_buf)?;

        // バッファにコピー
        let copy_len = buffer.len().min(sector_buf.len());
        buffer[..copy_len].copy_from_slice(&sector_buf[..copy_len]);

        // キャッシュに追加
        self.block_cache.insert(self.device_id, sector, sector_buf);

        Ok(())
    }

    /// バッチ読み取り後の次のクラスタを取得
    fn get_next_cluster_after_batch(
        &self,
        start: Cluster,
        count: usize,
    ) -> FsResult<Option<Cluster>> {
        if count == 0 {
            return Ok(None);
        }

        // バッチの最後のクラスタ
        let last_cluster = Cluster(start.0 + (count as u32) - 1);

        let idx = last_cluster.0 as usize;
        let next = if self.full_fat_cache {
            let fat = self.fat_cache.read();
            if idx >= fat.len() {
                return Err(FsError::InvalidInput);
            }
            fat[idx]
        } else {
            self.read_fat_entry(last_cluster)?
        };

        if next.is_eof() || !next.is_valid() {
            Ok(None)
        } else {
            Ok(Some(next))
        }
    }

    /// 連続したクラスタをバッチで書き込み（最適化版）
    ///
    /// `read_clusters_batch`の書き込み版。連続したクラスタへの
    /// 書き込みを最適化します。
    ///
    /// # Arguments
    /// * `clusters` - 書き込み先クラスタのリスト
    /// * `data` - 書き込むデータ
    ///
    /// # Returns
    /// 実際に書き込んだバイト数
    pub fn write_clusters_batch(&self, clusters: &[Cluster], data: &[u8]) -> FsResult<usize> {
        let cluster_size = self.cluster_size();
        let mut total_written = 0usize;
        let mut data_offset = 0usize;
        let mut i = 0usize;

        while i < clusters.len() && data_offset < data.len() {
            // 連続したクラスタを検出
            let mut contiguous_count = 1;
            while i + contiguous_count < clusters.len() {
                if clusters[i + contiguous_count].0 != clusters[i].0 + contiguous_count as u32 {
                    break;
                }
                contiguous_count += 1;
            }

            // バッチ書き込み
            let batch_size = (contiguous_count * cluster_size).min(data.len() - data_offset);
            self.write_contiguous_clusters(
                clusters[i],
                contiguous_count,
                &data[data_offset..data_offset + batch_size],
            )?;

            total_written += batch_size;
            data_offset += batch_size;
            i += contiguous_count;
        }

        Ok(total_written)
    }

    /// 連続したクラスタを一括書き込み
    fn write_contiguous_clusters(&self, start: Cluster, count: usize, data: &[u8]) -> FsResult<()> {
        let cluster_size = self.cluster_size();
        let expected_size = count * cluster_size;

        if data.len() < expected_size {
            return Err(FsError::InvalidInput);
        }

        let start_sector = self.cluster_to_sector(start);

        // 1. デバイスに一括書き込み（パフォーマンス向上の核心）
        self.device
            .write_sync(start_sector.as_u64(), &data[..expected_size])?;

        // 2. キャッシュの同期
        // 各セクタについて、キャッシュに存在するものだけを更新する。
        // デバイスへの書き込みは完了しているので、キャッシュを最新化する。
        let total_sectors = count * self.sectors_per_cluster as usize;
        for i in 0..total_sectors {
            let sector = start_sector + i as u32;
            let offset = i * BLOCK_SIZE;
            self.update_cache_only(sector.as_u64(), &data[offset..offset + BLOCK_SIZE]);
        }

        Ok(())
    }

    /// デバイスへの書き込みを伴わず、キャッシュのみを更新
    fn update_cache_only(&self, sector: u64, data: &[u8]) {
        if let Some(cached_block) = self.block_cache.get(self.device_id, sector) {
            let block_data = cached_block.data();
            let mut data_guard = block_data.write();
            let copy_len = data.len().min(data_guard.len());
            data_guard[..copy_len].copy_from_slice(&data[..copy_len]);
            cached_block.mark_clean();
        }
    }

    /// キャッシュに存在しない場合のみ追加
    fn update_cache_if_missing(&self, sector: u64, data: &[u8]) {
        if self.block_cache.get(self.device_id, sector).is_none() {
            self.block_cache
                .insert(self.device_id, sector, data.to_vec());
        }
    }

    /// キャッシュを使用してセクタを書き込む（write-through方式）
    ///
    /// デバイスに書き込み後、キャッシュも更新する。
    fn write_sector_cached(&self, sector: u64, data: &[u8]) -> FsResult<()> {
        // まずデバイスに書き込み（write-through）
        self.device.write_sync(sector, data)?;

        // キャッシュにも書き込み（存在する場合は更新、なければ追加）
        if let Some(cached_block) = self.block_cache.get(self.device_id, sector) {
            // キャッシュに存在する場合は更新
            let block_data = cached_block.data();
            let mut data_guard = block_data.write();
            let copy_len = data.len().min(data_guard.len());
            data_guard[..copy_len].copy_from_slice(&data[..copy_len]);
            // デバイスへ同期済みなのでクリーンとして扱う
            cached_block.mark_clean();
        } else {
            // キャッシュにない場合は追加
            let mut sector_buf = alloc::vec![0u8; BLOCK_SIZE];
            let copy_len = data.len().min(BLOCK_SIZE);
            sector_buf[..copy_len].copy_from_slice(&data[..copy_len]);
            self.block_cache.insert(self.device_id, sector, sector_buf);
        }

        Ok(())
    }

    /// バッチ読み取りで部分的な成功を許容するバージョン
    ///
    /// エラーが発生しても、それまでに読み取れたデータを返す。
    /// ストリーミング読み取りや、部分的なデータでも有用な場合に使用。
    ///
    /// # Returns
    ///
    /// `(bytes_read, first_error)` - 読み取れたバイト数と最初のエラー（存在する場合）
    ///
    /// # Example
    /// ```ignore
    /// let mut buffer = vec![0u8; file_size];
    /// let (bytes_read, maybe_error) = fs.read_clusters_batch_partial(start, &mut buffer);
    /// if bytes_read > 0 {
    ///     // 部分的に読み取れたデータを処理
    ///     process_data(&buffer[..bytes_read]);
    /// }
    /// if let Some(err) = maybe_error {
    ///     log::warn!("Partial read error: {:?}", err);
    /// }
    /// ```
    pub fn read_clusters_batch_partial(
        &self,
        start_cluster: Cluster,
        buffer: &mut [u8],
    ) -> (usize, Option<FsError>) {
        self.read_clusters_batch_internal(start_cluster, buffer, true)
    }

    /// クラスタサイズを取得
    fn cluster_size(&self) -> usize {
        self.sectors_per_cluster as usize * BLOCK_SIZE
    }

    /// バッファに格納可能なクラスタ数を計算
    ///
    /// # Example
    /// ```ignore
    /// let max_clusters = fs.buffer_cluster_capacity(&buffer);
    /// ```
    #[inline]
    fn buffer_cluster_capacity(&self, buffer: &[u8]) -> usize {
        buffer.len() / self.cluster_size()
    }

    /// ファイルシステムの不変条件を検証（デバッグビルドのみ）
    ///
    /// # Invariants
    ///
    /// 1. `fat_start_sector < data_start_sector`
    /// 2. `total_clusters > 0`
    /// 3. `sectors_per_cluster` は2の累乗
    /// 4. `root_cluster` は有効なクラスタ番号
    ///
    /// # Panics
    ///
    /// デバッグビルドで不変条件が破られた場合にパニックする
    #[cfg(debug_assertions)]
    pub fn verify_invariants(&self) {
        assert!(
            self.fat_start_sector.0 < self.data_start_sector.0,
            "FAT must be before data region: fat_start={}, data_start={}",
            self.fat_start_sector.0,
            self.data_start_sector.0
        );
        assert!(self.total_clusters > 0, "Total clusters must be positive");
        assert!(
            self.sectors_per_cluster.is_power_of_two(),
            "Sectors per cluster must be power of 2: got {}",
            self.sectors_per_cluster
        );
        assert!(
            self.root_cluster.is_valid(),
            "Root cluster must be valid: got {}",
            self.root_cluster.0
        );
    }

    /// リリースビルドでは何もしない
    #[cfg(not(debug_assertions))]
    #[inline]
    pub fn verify_invariants(&self) {}
}

impl FileSystem for Fat32FileSystem {
    fn name(&self) -> &str {
        "fat32"
    }

    fn root_dir(&self) -> FsResult<Box<dyn Inode>> {
        Ok(Box::new(Fat32Inode::new_directory(
            Arc::new(self.clone()),
            self.root_cluster,
            Cluster(0), // ルートの親は0とする
            String::from("/"),
        )))
    }
}

impl Clone for Fat32FileSystem {
    fn clone(&self) -> Self {
        Self {
            device: self.device.clone(),
            device_id: self.device_id,
            fat_start_sector: self.fat_start_sector,
            data_start_sector: self.data_start_sector,
            sectors_per_cluster: self.sectors_per_cluster,
            total_clusters: self.total_clusters,
            root_cluster: self.root_cluster,
            fat_cache: RwLock::new(self.fat_cache.read().clone()),
            fat_sector_cache: FatSectorCache::new(DEFAULT_FAT_SECTOR_CACHE_SIZE),
            free_clusters: RwLock::new(*self.free_clusters.read()),
            fat_size: self.fat_size,
            dirty_sectors: RwLock::new(self.dirty_sectors.read().clone()),
            block_cache: Arc::clone(&self.block_cache),
            full_fat_cache: self.full_fat_cache,
            cluster_buffer_pool: Arc::clone(&self.cluster_buffer_pool),
            time_provider: Arc::clone(&self.time_provider),
            fs_info_sector: self.fs_info_sector,
            dir_cache: DirEntryCache::new(DEFAULT_DIR_CACHE_SIZE),
        }
    }
}

/// 構造的なデバッグ出力（deviceフィールドは省略）
impl fmt::Debug for Fat32FileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dirty_count = self.dirty_sectors.read().iter().filter(|&&x| x).count();
        f.debug_struct("Fat32FileSystem")
            .field("fat_start_sector", &self.fat_start_sector)
            .field("data_start_sector", &self.data_start_sector)
            .field("sectors_per_cluster", &self.sectors_per_cluster)
            .field("total_clusters", &self.total_clusters)
            .field("root_cluster", &self.root_cluster)
            .field("free_clusters", &*self.free_clusters.read())
            .field("fat_size", &self.fat_size)
            .field("dirty_sector_count", &dirty_count)
            .finish_non_exhaustive() // "device" フィールドは省略
    }
}

// ============================================================================
// FAT32 Inode
// ============================================================================

/// FAT32 inode
pub struct Fat32Inode {
    /// ファイルシステム
    fs: Arc<Fat32FileSystem>,
    /// ファイルタイプ
    file_type: FileType,
    /// 内部可変状態
    inner: RwLock<Fat32InodeInner>,
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

impl Fat32Inode {
    /// 新しいディレクトリinodeを作成
    pub fn new_directory(
        fs: Arc<Fat32FileSystem>,
        cluster: Cluster,
        parent: Cluster,
        name: String,
    ) -> Self {
        Self {
            fs,
            file_type: FileType::Directory,
            inner: RwLock::new(Fat32InodeInner {
                first_cluster: cluster,
                size: 0,
                parent_cluster: parent,
                name,
                attributes: FileAttributes::from_bits_truncate(FileAttributes::DIRECTORY),
                created: 0,
                modified: 0,
                accessed: 0,
            }),
        }
    }

    /// 新しいファイルinodeを作成
    pub fn new_file(
        fs: Arc<Fat32FileSystem>,
        cluster: Cluster,
        size: u64,
        parent: Cluster,
        name: String,
    ) -> Self {
        Self {
            fs,
            file_type: FileType::File,
            inner: RwLock::new(Fat32InodeInner {
                first_cluster: cluster,
                size,
                parent_cluster: parent,
                name,
                attributes: FileAttributes::from_bits_truncate(FileAttributes::ARCHIVE),
                created: 0,
                modified: 0,
                accessed: 0,
            }),
        }
    }

    fn from_raw(
        fs: Arc<Fat32FileSystem>,
        parent: Cluster,
        name: String,
        raw: &DirEntryRaw,
    ) -> Self {
        let file_type = if raw.is_directory() {
            FileType::Directory
        } else {
            FileType::File
        };
        Self {
            fs,
            file_type,
            inner: RwLock::new(Fat32InodeInner {
                first_cluster: raw.first_cluster(),
                size: raw.file_size() as u64,
                parent_cluster: parent,
                name,
                attributes: raw.attributes(),
                created: dos_to_unix(raw.create_date(), raw.create_time()),
                modified: dos_to_unix(raw.modify_date(), raw.modify_time()),
                accessed: dos_to_unix(raw.access_date(), 0),
            }),
        }
    }

    /// 指定された名前を持つSFNエントリの場所（クラスタとオフセット）を検索します。
    /// このメソッドはロングファイルネームを正しく処理します。
    fn find_sfn_location(&self, name_to_find: &str) -> FsResult<Option<(Cluster, usize)>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }
        let inner = self.inner.read();

        let cluster_size = self.fs.cluster_size();
        let mut buffer = vec![0u8; cluster_size];
        let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;

        let mut lfn_parts: Vec<(u8, String, u8)> = Vec::new();

        for cluster_res in self.fs.clusters(inner.first_cluster) {
            let cluster = cluster_res?;
            self.fs.read_cluster(cluster, &mut buffer)?;

            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let entry_bytes = &buffer[offset..offset + DIR_ENTRY_SIZE];

                match DirectoryEntryKind::from(entry_bytes) {
                    DirectoryEntryKind::End => return Ok(None),
                    DirectoryEntryKind::Deleted => {
                        lfn_parts.clear();
                        continue;
                    }
                    DirectoryEntryKind::LongName(lfn) => {
                        if lfn_parts.len() >= MAX_LFN_PARTS {
                            return Err(FsError::FileSystemCorrupted);
                        }
                        lfn_parts.push((lfn.sequence(), lfn.get_name_part(), lfn.checksum()));
                        continue;
                    }
                    DirectoryEntryKind::VolumeLabel => {
                        lfn_parts.clear();
                        continue;
                    }
                    DirectoryEntryKind::Standard(raw) => {
                        let name = if !lfn_parts.is_empty() {
                            let expected_checksum = raw.calculate_checksum();
                            if lfn_parts
                                .first()
                                .map_or(false, |&(_, _, cs)| cs == expected_checksum)
                            {
                                lfn_parts.sort_by_key(|&(seq, _, _)| seq);
                                let long_name: String =
                                    lfn_parts.iter().map(|(_, s, _)| s.as_str()).collect();
                                long_name
                            } else {
                                lfn_parts.clear();
                                raw.short_name()
                            }
                        } else {
                            raw.short_name()
                        };

                        if name.eq_ignore_ascii_case(name_to_find) {
                            return Ok(Some((cluster, offset)));
                        }

                        lfn_parts.clear();
                    }
                }
            }
        }
        Ok(None)
    }

    /// ディレクトリエントリのイテレータを返す
    ///
    /// # 遅延評価のメリット
    ///
    /// - **メモリ効率**: 全エントリを Vec に読み込まない
    /// - **早期終了**: `lookup` で見つかったら即座に読み込みを停止
    /// - **標準メソッド**: `find()`, `filter()`, `collect()` 等が使用可能
    ///
    /// # Example
    ///
    /// ```ignore
    /// // 基本的な使用法
    /// for entry_result in inode.entries()? {
    ///     let (name, raw) = entry_result?;
    ///     println!("Found: {}", name);
    /// }
    ///
    /// // 特定ファイルの検索（大文字小文字を無視）
    /// let readme = inode.entries()?
    ///     .find_by_name("README.md")?
    ///     .ok_or(FsError::NotFound)?;
    ///
    /// // ファイルのみをフィルタ
    /// let files: Vec<_> = inode.entries()?
    ///     .files()
    ///     .collect::<FsResult<Vec<_>>>()?;
    ///
    /// // 複数条件の組み合わせ
    /// let visible_dirs: Vec<_> = inode.entries()?
    ///     .directories()
    ///     .visible()
    ///     .take(10)  // 最初の10個のみ
    ///     .collect::<FsResult<Vec<_>>>()?;
    ///
    /// // 完全性チェック
    /// let mut iter = inode.entries()?;
    /// while let Some(entry) = iter.next() {
    ///     // 処理...
    /// }
    /// assert!(iter.is_exhausted());
    /// ```
    ///
    /// # Errors
    ///
    /// - `FsError::NotADirectory` - このinodeがディレクトリでない場合
    /// - `FsError::IoError` - ディスク読み取りエラー
    /// - `FsError::FileSystemCorrupted` - クラスタチェーンが破損している場合
    ///
    /// # Performance
    ///
    /// イテレータは内部でクラスタを1つずつ読み込みます。
    /// 大量のエントリを処理する場合、`collect()`より
    /// ストリーミング処理（forループ）の方が効率的です。
    pub fn entries(&self) -> FsResult<DirectoryIterator<'_>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }
        let inner = self.inner.read();
        DirectoryIterator::new(&self.fs, inner.first_cluster)
    }

    /// 8.3形式のショートファイル名を生成
    ///
    /// 統合された実装: ベース名と拡張子のタプルを返す。
    /// 不正な文字はアンダースコアに置換される。
    #[inline]
    fn to_short_name_parts(name: &str) -> ([u8; 8], [u8; 3]) {
        let mut base = [b' '; 8];
        let mut ext = [b' '; 3];

        let name_upper = name.to_uppercase();
        let dot_pos = name_upper.rfind('.');

        let (base_part, ext_part) = if let Some(pos) = dot_pos {
            (&name_upper[..pos], Some(&name_upper[pos + 1..]))
        } else {
            (name_upper.as_str(), None)
        };

        // ベース名（最大8文字）
        for (i, c) in base_part.chars().take(8).enumerate() {
            base[i] = if c.is_ascii_alphanumeric() || c == '_' {
                c as u8
            } else {
                b'_'
            };
        }

        // 拡張子（最大3文字）
        if let Some(e) = ext_part {
            for (i, c) in e.chars().take(3).enumerate() {
                ext[i] = if c.is_ascii_alphanumeric() {
                    c as u8
                } else {
                    b'_'
                };
            }
        }

        (base, ext)
    }

    /// ディレクトリ内の既存SFN（11バイト形式）をすべて収集
    ///
    /// 衝突チェック用にディレクトリを走査し、すべてのショートファイル名を収集する。
    fn collect_existing_sfns(&self) -> FsResult<HashSet<[u8; 11]>> {
        let mut sfns = HashSet::new();

        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        let cluster_size = self.fs.cluster_size();
        let mut buffer = vec![0u8; cluster_size];
        let inner = self.inner.read();
        let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;

        for cluster_res in self.fs.clusters(inner.first_cluster) {
            let cluster = cluster_res?;
            self.fs.read_cluster(cluster, &mut buffer)?;

            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let entry_bytes = &buffer[offset..offset + DIR_ENTRY_SIZE];

                // 終端チェック
                if entry_bytes[0] == END_OF_DIR {
                    return Ok(sfns);
                }

                // 削除済みやLFNはスキップ
                if entry_bytes[0] == DELETED_ENTRY {
                    continue;
                }

                let attr = FileAttributes::from_bits_truncate(entry_bytes[11]);
                if attr.is_long_name() || attr.is_volume_id() {
                    continue;
                }

                // 11バイトのSFN（name[8] + ext[3]）を収集
                let mut sfn = [0u8; 11];
                sfn.copy_from_slice(&entry_bytes[0..11]);
                sfns.insert(sfn);
            }
        }

        Ok(sfns)
    }

    /// Windows互換の一意なSFNを生成（衝突回避付き）
    ///
    /// 1. 基本SFNを生成
    /// 2. 既存SFNと衝突する場合、NAME~1.EXT, NAME~2.EXT, ... NAME~9.EXT を試行
    /// 3. それでも衝突する場合はエラー（将来的にはハッシュベースに拡張可能）
    ///
    /// # Arguments
    /// * `name` - 元のファイル名
    /// * `existing_sfns` - 既存のSFN集合（11バイト形式）
    ///
    /// # Returns
    /// 一意なベース名（8バイト）と拡張子（3バイト）
    fn generate_unique_sfn(
        name: &str,
        existing_sfns: &HashSet<[u8; 11]>,
    ) -> FsResult<([u8; 8], [u8; 3])> {
        let (base, ext) = Self::to_short_name_parts(name);

        // 現在のSFNを11バイト形式に変換
        let mut sfn_11 = [0u8; 11];
        sfn_11[0..8].copy_from_slice(&base);
        sfn_11[8..11].copy_from_slice(&ext);

        // 衝突がなければそのまま返す
        if !existing_sfns.contains(&sfn_11) {
            return Ok((base, ext));
        }

        // 衝突がある場合、~1 から ~9 を試行
        for n in 1..=9 {
            let mut numbered_base = base;

            // 名前を短縮して ~N を追加
            // 例: "FILENAME" -> "FILENA~1"
            let suffix = [b'~', b'0' + n];
            let suffix_len = 2;

            // 基本名の有効な長さを計算（末尾のスペースを除く）
            let base_len = base.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);

            // ~N を挿入する位置を計算（最大6文字 + ~N = 8文字）
            let truncate_at = (base_len).min(8 - suffix_len);

            // 基本名を ~N で終わるように書き換え
            for i in 0..8 {
                if i < truncate_at {
                    // 元の文字をそのまま使用
                } else if i == truncate_at {
                    numbered_base[i] = suffix[0]; // '~'
                } else if i == truncate_at + 1 {
                    numbered_base[i] = suffix[1]; // '1'-'9'
                } else {
                    numbered_base[i] = b' ';
                }
            }

            // 新しいSFNをチェック
            let mut new_sfn_11 = [0u8; 11];
            new_sfn_11[0..8].copy_from_slice(&numbered_base);
            new_sfn_11[8..11].copy_from_slice(&ext);

            if !existing_sfns.contains(&new_sfn_11) {
                return Ok((numbered_base, ext));
            }
        }

        // すべての ~N が使用済みの場合はエラー
        // 将来的にはハッシュベースの方法（NAM~XXXX.EXT）に拡張可能
        Err(FsError::AlreadyExists)
    }

    /// ディレクトリ内のエントリを走査し、条件に一致するエントリを探す
    ///
    /// クラスタチェーンを走査する共通ロジックをカプセル化。
    /// コールバックがSome(T)を返した時点で走査を停止し、その値を返す。
    ///
    /// # Arguments
    /// * `predicate` - エントリとオフセットを受け取り、処理結果を返すコールバック
    ///
    /// # Returns
    /// コールバックが返した値、または走査完了時はNone
    fn scan_dir_entries<T, F>(&self, mut predicate: F) -> FsResult<Option<(T, Cluster, usize)>>
    where
        F: FnMut(&DirEntryRaw, usize) -> Option<T>,
    {
        let cluster_size = self.fs.cluster_size();
        let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size);
        let inner = self.inner.read();
        let mut current_cluster = inner.first_cluster;
        let mut chain_count = 0;
        let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;

        while current_cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidInput);
            }

            self.fs.read_cluster(current_cluster, &mut buffer)?;

            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let raw = DirEntryRaw::from_bytes(&buffer[offset..offset + DIR_ENTRY_SIZE]);

                if let Some(result) = predicate(&raw, offset) {
                    return Ok(Some((result, current_cluster, offset)));
                }

                if raw.is_end() {
                    return Ok(None);
                }
            }

            current_cluster = self.fs.read_fat_entry(current_cluster)?;
        }

        Ok(None)
    }
    /// 必要な数だけ空いている連続したディレクトリエントリの場所を検索します。
    ///
    /// # Returns
    /// 見つかった場所（開始クラスタ、オフセット）、または見つからない場合はNone
    fn find_free_entry_block(&self, count: usize) -> FsResult<Option<(Cluster, usize)>> {
        let cluster_size = self.fs.cluster_size();
        let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size);
        let inner = self.inner.read();
        let mut current_cluster = inner.first_cluster;
        let mut chain_count = 0;
        let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;

        let mut found_count = 0;
        let mut start_cluster = Cluster(0);
        let mut start_offset = 0;

        while current_cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidInput);
            }

            self.fs.read_cluster(current_cluster, &mut buffer)?;

            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let raw = DirEntryRaw::from_bytes(&buffer[offset..offset + DIR_ENTRY_SIZE]);

                if raw.is_end() {
                    // 終端が見つかった。ここから先はすべて空き。
                    if found_count == 0 {
                        return Ok(Some((current_cluster, offset)));
                    } else {
                        return Ok(Some((start_cluster, start_offset)));
                    }
                } else if raw.is_deleted() {
                    if found_count == 0 {
                        start_cluster = current_cluster;
                        start_offset = offset;
                    }
                    found_count += 1;
                    if found_count >= count {
                        return Ok(Some((start_cluster, start_offset)));
                    }
                } else {
                    found_count = 0;
                }
            }

            current_cluster = self.fs.read_fat_entry(current_cluster)?;
        }

        Ok(None)
    }

    /// ディレクトリに新しいエントリを追加
    fn add_dir_entry(
        &self,
        name: &str,
        cluster: Cluster,
        attr: FileAttributes,
        size: u32,
    ) -> FsResult<()> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        // LFNが必要か判定（8.3形式に収まらない、または非ASCII/小文字を含む）
        let needs_lfn = name.len() > 12
            || name.contains('.') && name.split('.').next().unwrap().len() > 8
            || name.split('.').nth(1).map_or(false, |ext| ext.len() > 3)
            || name.chars().any(|c| c.is_lowercase());

        let lfn_count = if needs_lfn { (name.len() + 12) / 13 } else { 0 };
        let total_needed = 1 + lfn_count;

        // 空きエントリを探す
        let (found_cluster, found_offset) = match self.find_free_entry_block(total_needed)? {
            Some(loc) => loc,
            None => {
                // 空きがない場合はクラスタを拡張
                let new_cluster = self.fs.allocate_cluster()?;
                let mut buffer =
                    PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, self.fs.cluster_size());
                // EOFマーカーを書き込む
                buffer[0] = END_OF_DIR;
                self.fs.write_cluster(new_cluster, &buffer)?;

                // チェーンの最後に追加
                let mut last_cluster = self.inner.read().first_cluster;
                loop {
                    let next = self.fs.read_fat_entry(last_cluster)?;
                    if next.is_eof() {
                        break;
                    }
                    last_cluster = next;
                }
                self.fs.write_fat_entry(last_cluster, new_cluster)?;
                (new_cluster, 0)
            }
        };

        // ディレクトリ内の既存SFNを収集して衝突チェック用に使用
        let existing_sfns = self.collect_existing_sfns()?;

        // ショートネームの生成（衝突回避付き）
        let (base, ext) = Self::generate_unique_sfn(name, &existing_sfns)?;
        let mut sfn = DirEntryRaw::new(base, ext, attr, cluster, size);

        // 現在時刻を設定（TimeProvider経由）
        let time = self.fs.time_provider.current_dos_time();
        let date = self.fs.time_provider.current_dos_date();
        sfn.set_create_date(date);
        sfn.set_create_time(time);
        sfn.set_modify_date(date);
        sfn.set_modify_time(time);
        sfn.set_access_date(date);

        let checksum = sfn.calculate_checksum();

        // データの書き込み
        let mut buffer =
            PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, self.fs.cluster_size());
        self.fs.read_cluster(found_cluster, &mut buffer)?;

        let mut current_offset = found_offset;
        let mut current_cluster = found_cluster;

        // LFNエントリを書き込む（最後のエントリから順に）
        if needs_lfn {
            let name_u16: Vec<u16> = name.encode_utf16().collect();
            for i in 0..lfn_count {
                let seq = (lfn_count - i) as u8;
                let is_last = i == 0;
                let char_offset = (lfn_count - 1 - i) * 13;

                let mut part = [0xFFFFu16; 13];
                for j in 0..13 {
                    if char_offset + j < name_u16.len() {
                        part[j] = name_u16[char_offset + j];
                    } else if char_offset + j == name_u16.len() {
                        part[j] = 0x0000; // Null terminator
                    }
                }

                let lfn = LfnEntry::new(seq, &part, checksum, is_last);
                buffer[current_offset..current_offset + DIR_ENTRY_SIZE]
                    .copy_from_slice(lfn.as_bytes());

                current_offset += DIR_ENTRY_SIZE;
                if current_offset >= self.fs.cluster_size() {
                    self.fs.write_cluster(current_cluster, &buffer)?;
                    current_cluster = self.fs.read_fat_entry(current_cluster)?;
                    self.fs.read_cluster(current_cluster, &mut buffer)?;
                    current_offset = 0;
                }
            }
        }

        // SFNエントリを書き込む
        sfn.write_bytes_to(&mut buffer[current_offset..current_offset + DIR_ENTRY_SIZE]);

        self.fs.write_cluster(current_cluster, &buffer)?;
        Ok(())
    }

    /// ディレクトリからエントリを削除
    fn remove_dir_entry(&self, name: &str) -> FsResult<DirEntryRaw> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        let cluster_size = self.fs.cluster_size();

        // 名前が一致するエントリを探す
        let found = self.scan_dir_entries(|raw, _offset| {
            if raw.is_deleted() {
                return None;
            }
            if raw.attributes().is_long_name() || raw.attributes().is_volume_id() {
                return None;
            }
            let entry_name = raw.short_name();
            if entry_name.eq_ignore_ascii_case(name) {
                Some(*raw)
            } else {
                None
            }
        })?;

        if let Some((raw, found_cluster, offset)) = found {
            // エントリを削除済みとしてマーク
            let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size);
            self.fs.read_cluster(found_cluster, &mut buffer)?;
            buffer[offset] = DELETED_ENTRY;
            self.fs.write_cluster(found_cluster, &buffer)?;
            return Ok(raw);
        }

        Err(FsError::NotFound)
    }
}

impl Fat32Inode {
    pub fn getattr(&self) -> FsResult<FileAttr> {
        let inner = self.inner.read();
        Ok(FileAttr {
            file_type: Some(self.file_type),
            size: inner.size,
            created: inner.created,
            modified: inner.modified,
            accessed: inner.accessed,
            readonly: inner.attributes.is_read_only(),
        })
    }

    pub fn setattr(&self, attr: &FileAttr) -> FsResult<()> {
        let mut size_changed = false;
        {
            let mut inner = self.inner.write();
            if attr.size != inner.size {
                size_changed = true;
            }
            if attr.created > 0 {
                inner.created = attr.created;
            }
            if attr.modified > 0 {
                inner.modified = attr.modified;
            }
            if attr.accessed > 0 {
                inner.accessed = attr.accessed;
            }
        }

        if size_changed {
            self.truncate(attr.size)?;
        }

        self.sync_metadata()?;
        Ok(())
    }

    pub fn lookup(&self, name: &str) -> FsResult<Arc<Fat32Inode>> {
        // パス長検証
        validate_path_length(name)?;

        // find_by_name()を活用した検索（DirectoryIterator拡張を再利用）
        let raw = self
            .entries()?
            .find_by_name(name)?
            .map(|(_, raw)| raw)
            .ok_or(FsError::NotFound)?;

        let inner = self.inner.read();
        let cluster = raw.first_cluster();
        if raw.attributes().is_directory() {
            Ok(Arc::new(Fat32Inode::new_directory(
                self.fs.clone(),
                cluster,
                inner.first_cluster,
                String::from(name),
            )))
        } else {
            Ok(Arc::new(Fat32Inode::new_file(
                self.fs.clone(),
                cluster,
                raw.file_size() as u64,
                inner.first_cluster,
                String::from(name),
            )))
        }
    }

    pub fn readdir(&self, _offset: u64) -> FsResult<Vec<DirEntry>> {
        self.entries()?
            .map(|res| {
                res.map(|(name, raw)| DirEntry {
                    name,
                    file_type: if raw.attributes().is_directory() {
                        FileType::Directory
                    } else {
                        FileType::File // TODO: check for other types
                    },
                    metadata: Metadata {
                        file_type: Some(if raw.attributes().is_directory() {
                            FileType::Directory
                        } else {
                            FileType::File
                        }),
                        size: raw.file_size() as u64,
                        created: 0,  // TODO
                        modified: 0, // TODO
                        accessed: 0, // TODO
                        readonly: raw.attributes().is_read_only(),
                    },
                })
            })
            .collect()
    }

    pub fn create(
        &self,
        name: &str,
        _mode: FileMode,
        _flags: OpenFlags,
    ) -> FsResult<Arc<Fat32Inode>> {
        // パス長検証
        validate_path_length(name)?;

        // 既存のエントリがないか確認
        if let Ok(_) = self.lookup(name) {
            return Err(FsError::AlreadyExists);
        }

        // 新しいファイル用のクラスタを割り当て（空ファイルの場合はクラスタ0）
        let new_cluster = Cluster(0); // 空ファイルはクラスタを持たない

        let inner = self.inner.read();
        // ディレクトリエントリを追加
        self.add_dir_entry(
            name,
            new_cluster,
            FileAttributes::from_bits_truncate(FileAttributes::ARCHIVE),
            0,
        )?;

        Ok(Arc::new(Fat32Inode::new_file(
            self.fs.clone(),
            new_cluster,
            0,
            inner.first_cluster,
            String::from(name),
        )))
    }

    pub fn mkdir(&self, name: &str, _mode: FileMode) -> FsResult<Arc<Fat32Inode>> {
        // パス長検証
        validate_path_length(name)?;

        // 既存のエントリがないか確認
        if let Ok(_) = self.lookup(name) {
            return Err(FsError::AlreadyExists);
        }

        // 新しいディレクトリ用のクラスタを割り当て
        let new_cluster = self.fs.allocate_cluster()?;

        // クラスタを初期化（. と .. エントリを作成）
        let cluster_size = self.fs.cluster_size();
        let mut buffer = vec![0u8; cluster_size];

        // "." エントリ - 新しいディレクトリ自身を指す
        let dot_entry = DirEntryRaw::new_dot(new_cluster);

        // ".." エントリ - 親ディレクトリを指す
        let inner = self.inner.read();
        let dotdot_entry = DirEntryRaw::new_dotdot(inner.first_cluster);

        // バッファに書き込み (as_bytes()で安全にシリアライズ)
        dot_entry.write_bytes_to(&mut buffer[0..DIR_ENTRY_SIZE]);
        dotdot_entry.write_bytes_to(&mut buffer[DIR_ENTRY_SIZE..DIR_ENTRY_SIZE * 2]);

        // 終端マーカー
        buffer[DIR_ENTRY_SIZE * 2] = END_OF_DIR;

        self.fs.write_cluster(new_cluster, &buffer)?;

        // 親ディレクトリにエントリを追加
        self.add_dir_entry(
            name,
            new_cluster,
            FileAttributes::from_bits_truncate(FileAttributes::DIRECTORY),
            0,
        )?;

        let inner = self.inner.read();
        Ok(Arc::new(Fat32Inode::new_directory(
            self.fs.clone(),
            new_cluster,
            inner.first_cluster,
            String::from(name),
        )))
    }

    pub fn unlink(&self, name: &str) -> FsResult<()> {
        // エントリを検索して削除
        let entry = self.remove_dir_entry(name)?;

        // ディレクトリは削除できない
        if entry.attributes().is_directory() {
            return Err(FsError::IsADirectory);
        }

        // クラスタチェーンを解放
        let cluster = entry.first_cluster();
        if cluster.is_valid() {
            self.fs.free_cluster_chain(cluster)?;
        }

        Ok(())
    }

    pub fn rmdir(&self, name: &str) -> FsResult<()> {
        // まず対象ディレクトリを検索
        let target = self.lookup(name)?;
        let attr = target.getattr()?;

        if attr.file_type != Some(FileType::Directory) {
            return Err(FsError::NotADirectory);
        }

        // ディレクトリが空かどうか確認
        let entries = target.readdir(0)?;
        if !entries.is_empty() {
            return Err(FsError::DirectoryNotEmpty);
        }

        // エントリを削除
        let entry = self.remove_dir_entry(name)?;

        // クラスタチェーンを解放
        let cluster = entry.first_cluster();
        if cluster.is_valid() {
            self.fs.free_cluster_chain(cluster)?;
        }

        Ok(())
    }

    fn rename(&self, old_name: &str, new_dir: &Arc<dyn Inode>, new_name: &str) -> FsResult<()> {
        validate_path_length(old_name)?;
        validate_path_length(new_name)?;

        // 宛先ディレクトリがFat32Inodeであることを確認
        let other_inode = (**new_dir)
            .as_any()
            .downcast_ref::<Fat32Inode>()
            .ok_or(FsError::CrossDeviceLink)?;

        // 同一ファイルシステムか確認
        if !Arc::ptr_eq(&self.fs, &other_inode.fs) {
            return Err(FsError::CrossDeviceLink);
        }

        // 宛先に同名ファイルが存在しないか確認
        if other_inode.lookup(new_name).is_ok() {
            return Err(FsError::AlreadyExists);
        }

        // 移動元エントリの情報を取得
        let (raw_entry, _, _) = self
            .scan_dir_entries(|raw, _| {
                if raw.is_deleted() {
                    return None;
                }
                if raw.attributes().is_long_name() || raw.attributes().is_volume_id() {
                    return None;
                }
                if raw.short_name().eq_ignore_ascii_case(old_name) {
                    Some(*raw)
                } else {
                    None
                }
            })?
            .ok_or(FsError::NotFound)?;

        let cluster = raw_entry.first_cluster();
        let attr = raw_entry.attributes();
        let size = raw_entry.file_size();

        // ディレクトリの場合、ループチェック
        if attr.is_directory() {
            let moved_cluster = cluster;
            let mut curr_cluster = other_inode.inner.read().first_cluster;

            // ルートに到達するか、移動対象クラスタに到達するまで親を辿る
            while curr_cluster.0 != 0 && curr_cluster != self.fs.root_cluster {
                if curr_cluster == moved_cluster {
                    return Err(FsError::InvalidInput); // ループ検出
                }

                // ".." エントリを読み取って親へ移動
                let cluster_size = self.fs.cluster_size();
                let mut buffer = vec![0u8; cluster_size];
                self.fs.read_cluster(curr_cluster, &mut buffer)?;

                let dotdot = DirEntryRaw::from_bytes(&buffer[DIR_ENTRY_SIZE..DIR_ENTRY_SIZE * 2]);
                let next = dotdot.first_cluster();
                if next == curr_cluster {
                    break;
                } // 安全策
                curr_cluster = next;
            }
        }

        // 新しいディレクトリにエントリを追加
        other_inode.add_dir_entry(new_name, cluster, attr, size)?;

        // 古いディレクトリからエントリを削除
        if let Err(e) = self.remove_dir_entry(old_name) {
            return Err(e);
        }

        // ディレクトリの場合、".." エントリを更新
        if attr.is_directory() && cluster.is_valid() {
            let cluster_size = self.fs.cluster_size();
            let mut buffer = vec![0u8; cluster_size];
            self.fs.read_cluster(cluster, &mut buffer)?;

            let dotdot_offset = DIR_ENTRY_SIZE;
            let mut dotdot =
                DirEntryRaw::from_bytes(&buffer[dotdot_offset..dotdot_offset + DIR_ENTRY_SIZE]);
            let new_parent = other_inode.inner.read().first_cluster;
            let new_parent_val = if new_parent == self.fs.root_cluster {
                Cluster(0)
            } else {
                new_parent
            };
            dotdot.set_first_cluster(new_parent_val);
            dotdot.write_bytes_to(&mut buffer[dotdot_offset..dotdot_offset + DIR_ENTRY_SIZE]);
            self.fs.write_cluster(cluster, &buffer)?;
        }

        Ok(())
    }

    fn link(&self, _name: &str, _inode: &Arc<dyn Inode>) -> FsResult<()> {
        // FAT32はハードリンクをサポートしない
        Err(FsError::NotSupported)
    }

    fn symlink(&self, _name: &str, _target: &str) -> FsResult<Arc<dyn Inode>> {
        // FAT32はシンボリックリンクをサポートしない
        Err(FsError::NotSupported)
    }

    fn readlink(&self) -> FsResult<String> {
        Err(FsError::NotSupported)
    }

    pub fn read(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }

        let inner = self.inner.read();
        if offset >= inner.size {
            return Ok(0);
        }

        let cluster_size = self.fs.cluster_size() as u64;
        let to_read = buf.len().min((inner.size - offset) as usize);

        // 開始クラスタまでスキップ（skip メソッド活用）
        let start_cluster_idx = (offset / cluster_size) as usize;
        let chain = self
            .fs
            .clusters(inner.first_cluster)
            .skip(start_cluster_idx);

        // 最初のクラスタ内でのオフセット
        let mut current_cluster_offset = (offset % cluster_size) as usize;

        // ⚠️ ヒープアロケーション（クラスタサイズが64KBの場合は64KB確保）
        // カーネル環境では、ページアロケータまたはPer-CPUバッファを推奨
        //
        // 最適化案:
        // 1. Per-CPUバッファ: CPU_LOCAL.with(|local| local.cluster_buffer.borrow_mut())
        // 2. ページアロケータ: alloc_pages(cluster_size / PAGE_SIZE)
        // 3. LRUキャッシュ: 頻繁に読まれるクラスタをメモリに保持（Exchange Heap経由）
        let mut cluster_buf = vec![0u8; cluster_size as usize];

        // 書き込み先バッファをミュータブルなスライスとして持ち、進めていく
        let mut remaining_buf = &mut buf[..to_read];
        let mut bytes_read = 0;

        // イテレータを使用してクラスタチェーンを走査
        for cluster_res in chain {
            if remaining_buf.is_empty() {
                break;
            }

            let cluster = cluster_res?;
            self.fs.read_cluster(cluster, &mut cluster_buf)?;

            // このクラスタから読み出せる有効なデータ範囲
            let available_data = &cluster_buf[current_cluster_offset..];

            // コピーする長さ（バッファの残りと、クラスタの残りの小さい方）
            let copy_len = remaining_buf.len().min(available_data.len());

            // split_at_mut でバッファを分割してコピー
            let (target, next) = remaining_buf.split_at_mut(copy_len);
            target.copy_from_slice(&available_data[..copy_len]);

            // 次のループの準備
            remaining_buf = next;
            bytes_read += copy_len;
            current_cluster_offset = 0; // 2つ目以降のクラスタは先頭から読む
        }

        Ok(bytes_read)
    }

    pub fn write(&self, offset: u64, buf: &[u8]) -> FsResult<usize> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }
        let mut inner = self.inner.write();

        if buf.is_empty() {
            return Ok(0);
        }

        let cluster_size = self.fs.cluster_size() as u64;
        let mut bytes_written = 0usize;

        // 必要なクラスタを確保
        let mut cluster = inner.first_cluster;

        // ファイルが空の場合、最初のクラスタを割り当て
        if !cluster.is_valid() {
            cluster = self.fs.allocate_cluster()?;
            inner.first_cluster = cluster;
            // 親ディレクトリのエントリを更新する必要がある（簡略化のため省略）
        }

        // 書き込み開始位置のクラスタまでスキップ
        let start_cluster_idx = offset / cluster_size;
        for _ in 0..start_cluster_idx {
            let next = self.fs.read_fat_entry(cluster)?;
            if !next.is_valid() {
                // 新しいクラスタを割り当て
                let new_cluster = self.fs.allocate_cluster()?;
                self.fs.write_fat_entry(cluster, new_cluster)?;
                cluster = new_cluster;
            } else {
                cluster = next;
            }
        }

        let mut cluster_offset = (offset % cluster_size) as usize;
        let mut cluster_buf = vec![0u8; cluster_size as usize];

        while bytes_written < buf.len() {
            // 既存のクラスタ内容を読み込み（部分書き込みの場合）
            if cluster_offset > 0
                || bytes_written + cluster_size as usize - cluster_offset > buf.len()
            {
                self.fs.read_cluster(cluster, &mut cluster_buf)?;
            }

            // バッファにデータをコピー
            let copy_len = (cluster_size as usize - cluster_offset).min(buf.len() - bytes_written);
            cluster_buf[cluster_offset..cluster_offset + copy_len]
                .copy_from_slice(&buf[bytes_written..bytes_written + copy_len]);

            // クラスタを書き込み
            self.fs.write_cluster(cluster, &cluster_buf)?;

            bytes_written += copy_len;
            cluster_offset = 0;

            // 次のクラスタが必要な場合
            if bytes_written < buf.len() {
                let next = self.fs.read_fat_entry(cluster)?;
                if !next.is_valid() {
                    let new_cluster = self.fs.allocate_cluster()?;
                    self.fs.write_fat_entry(cluster, new_cluster)?;
                    cluster = new_cluster;
                } else {
                    cluster = next;
                }
            }
        }

        inner.size = inner.size.max(offset + bytes_written as u64);
        drop(inner);
        self.sync_metadata()?;
        Ok(bytes_written)
    }

    fn truncate(&self, size: u64) -> FsResult<()> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }
        let mut inner = self.inner.write();

        let cluster_size = self.fs.cluster_size() as u64;

        if size == 0 {
            // 全クラスタを解放
            if inner.first_cluster.is_valid() {
                self.fs.free_cluster_chain(inner.first_cluster)?;
                inner.first_cluster = Cluster(0);
            }
            return Ok(());
        }

        // 必要なクラスタ数を計算
        let needed_clusters = (size + cluster_size - 1) / cluster_size;

        let mut cluster = inner.first_cluster;
        let mut count = 1u64;
        let mut chain_count = 0;

        // 必要なクラスタ数まで辿る
        while count < needed_clusters && cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidInput); // クラスタチェーンが循環している
            }

            let next = self.fs.read_fat_entry(cluster)?;
            if !next.is_valid() {
                // 拡張が必要：新しいクラスタを割り当て
                let new_cluster = self.fs.allocate_cluster()?;
                self.fs.write_fat_entry(cluster, new_cluster)?;
                cluster = new_cluster;
            } else {
                cluster = next;
            }
            count += 1;
        }

        // 余分なクラスタを解放
        if cluster.is_valid() {
            let next = self.fs.read_fat_entry(cluster)?;
            self.fs.write_fat_entry(cluster, Cluster::EOF)?;
            if next.is_valid() {
                self.fs.free_cluster_chain(next)?;
            }
        }

        inner.size = size;
        drop(inner);
        self.sync_metadata()?;
        Ok(())
    }

    /// メモリ上のメタデータ（サイズ、クラスタ、属性）をディスク上のディレクトリエントリに同期します。
    pub fn sync_metadata(&self) -> FsResult<()> {
        let inner = self.inner.read();
        // ルートディレクトリ自体は親エントリを持たないため、更新は不要。
        if inner.parent_cluster.0 == 0 {
            return Ok(());
        }

        // 親ディレクトリの一時的なinodeを作成して、そのメソッドを利用します。
        let parent_inode = Fat32Inode::new_directory(
            self.fs.clone(),
            inner.parent_cluster,
            Cluster(0),    // 親の親はここでは不要
            String::new(), // 親の名前はここでは不要
        );

        // 親ディレクトリ内でこのinodeのSFNエントリの場所を探します。
        let (cluster, offset) = parent_inode
            .find_sfn_location(&inner.name)?
            .ok_or(FsError::NotFound)?;

        // エントリを含むクラスタを読み込みます。
        let mut buffer = vec![0u8; self.fs.cluster_size()];
        self.fs.read_cluster(cluster, &mut buffer)?;

        // rawエントリを可変として取得し、現在のメタデータで更新します。
        let mut raw = DirEntryRaw::from_bytes(&buffer[offset..offset + DIR_ENTRY_SIZE]);
        raw.set_file_size(inner.size as u32);
        raw.set_first_cluster(inner.first_cluster);
        raw.set_attributes(inner.attributes);

        // タイムスタンプの同期
        let (mdate, mtime) = unix_to_dos(inner.modified);
        raw.set_modify_date(mdate);
        raw.set_modify_time(mtime);

        let (adate, _) = unix_to_dos(inner.accessed);
        raw.set_access_date(adate);

        let (cdate, ctime) = unix_to_dos(inner.created);
        raw.set_create_date(cdate);
        raw.set_create_time(ctime);

        // 更新されたエントリをバッファに書き戻し、ディスクに書き込みます。
        raw.write_bytes_to(&mut buffer[offset..offset + DIR_ENTRY_SIZE]);
        self.fs.write_cluster(cluster, &buffer)
    }

    fn fsync(&self, _datasync: bool) -> FsResult<()> {
        self.fs.sync()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_name() {
        // to_short_name_partsはプライベートなのでDirEntryRaw経由でテスト
        let entry = DirEntryRaw::new(
            *b"TEST    ",
            *b"TXT",
            FileAttributes::from_bits_truncate(0),
            Cluster(0),
            0,
        );
        assert_eq!(&entry.name, b"TEST    ");
        assert_eq!(&entry.ext, b"TXT");
    }

    #[test]
    fn test_checksum() {
        // DirEntryRaw::calculate_checksumを使用
        let entry = DirEntryRaw::new(
            *b"TEST    ",
            *b"TXT",
            FileAttributes::from_bits_truncate(0),
            Cluster(0),
            0,
        );
        let sum = entry.calculate_checksum();
        assert!(sum != 0); // 具体的な値はテストデータによる
    }

    // ========================================================================
    // Cluster Tests
    // ========================================================================

    #[test]
    fn test_cluster_validation() {
        // 有効なクラスタ
        assert!(Cluster(2).is_valid());
        assert!(Cluster(100).is_valid());
        assert!(Cluster(0x0FFFFFF0 - 1).is_valid());

        // 無効なクラスタ
        assert!(!Cluster(0).is_valid()); // FREE
        assert!(!Cluster(1).is_valid()); // Reserved
        assert!(!Cluster::EOF.is_valid());
        assert!(!Cluster::BAD.is_valid());
    }

    #[test]
    fn test_cluster_special_values() {
        assert!(Cluster::FREE.is_free());
        assert!(Cluster::EOF.is_eof());
        assert!(Cluster(0x0FFFFFFF).is_eof()); // 任意のEOF値
    }

    #[test]
    fn test_cluster_contiguity() {
        let c1 = Cluster(100);
        let c2 = Cluster(101);
        let c3 = Cluster(102);
        let c5 = Cluster(105);

        assert!(c1.is_contiguous_with(c2));
        assert!(c2.is_contiguous_with(c3));
        assert!(!c1.is_contiguous_with(c3)); // スキップ
        assert!(!c1.is_contiguous_with(c5)); // 離れている
    }

    #[test]
    fn test_cluster_in_range() {
        const MAX_CLUSTERS: u32 = 65525;

        assert!(Cluster::in_range(2, MAX_CLUSTERS));
        assert!(Cluster::in_range(100, MAX_CLUSTERS));
        assert!(Cluster::in_range(65524, MAX_CLUSTERS));

        assert!(!Cluster::in_range(0, MAX_CLUSTERS)); // FREE
        assert!(!Cluster::in_range(1, MAX_CLUSTERS)); // Reserved
        assert!(!Cluster::in_range(65525, MAX_CLUSTERS)); // Out of range
        assert!(!Cluster::in_range(100000, MAX_CLUSTERS)); // Way out
    }

    // ========================================================================
    // FileOffset Tests
    // ========================================================================

    #[test]
    fn test_file_offset_calculation() {
        let offset = FileOffset(8192);
        assert_eq!(offset.cluster_index(4096), 2);
        assert_eq!(offset.offset_in_cluster(4096), 0);

        let offset = FileOffset(5000);
        assert_eq!(offset.cluster_index(4096), 1);
        assert_eq!(offset.offset_in_cluster(4096), 904);

        let offset = FileOffset(0);
        assert_eq!(offset.cluster_index(4096), 0);
        assert_eq!(offset.offset_in_cluster(4096), 0);
    }

    #[test]
    fn test_file_offset_in_range() {
        const FILE_SIZE: u64 = 1024 * 1024; // 1MB

        assert!(FileOffset::in_range(0, FILE_SIZE));
        assert!(FileOffset::in_range(500, FILE_SIZE));
        assert!(FileOffset::in_range(FILE_SIZE - 1, FILE_SIZE));

        assert!(!FileOffset::in_range(FILE_SIZE, FILE_SIZE));
        assert!(!FileOffset::in_range(FILE_SIZE + 1, FILE_SIZE));
    }

    #[test]
    fn test_file_offset_arithmetic() {
        let offset = FileOffset(100);
        let new_offset = offset + 50usize;
        assert_eq!(new_offset.as_u64(), 150);
    }

    // ========================================================================
    // ByteCount Tests
    // ========================================================================

    #[test]
    fn test_byte_count_operations() {
        let a = ByteCount(100);
        let b = ByteCount(50);

        assert_eq!(a.min(b), b);
        assert_eq!(b.min(a), b);
        assert_eq!((a - b).as_usize(), 50);
        assert_eq!((a + b).as_usize(), 150);
    }

    #[test]
    fn test_byte_count_saturating_sub() {
        let a = ByteCount(50);
        let b = ByteCount(100);

        // saturating_sub により負にならない
        assert_eq!((a - b).as_usize(), 0);
    }

    #[test]
    fn test_byte_count_empty() {
        assert!(ByteCount::ZERO.is_empty());
        assert!(ByteCount(0).is_empty());
        assert!(!ByteCount(1).is_empty());
    }

    // ========================================================================
    // NextCluster Tests
    // ========================================================================

    #[test]
    fn test_next_cluster_from_fat_entry() {
        assert_eq!(
            NextCluster::from_fat_entry(Cluster::FREE),
            NextCluster::Free
        );
        assert_eq!(NextCluster::from_fat_entry(Cluster::EOF), NextCluster::Eof);
        assert_eq!(NextCluster::from_fat_entry(Cluster::BAD), NextCluster::Bad);
        assert_eq!(
            NextCluster::from_fat_entry(Cluster(100)),
            NextCluster::Valid(Cluster(100))
        );
    }

    #[test]
    fn test_next_cluster_as_valid() {
        assert_eq!(
            NextCluster::Valid(Cluster(100)).as_valid(),
            Some(Cluster(100))
        );
        assert_eq!(NextCluster::Eof.as_valid(), None);
        assert_eq!(NextCluster::Free.as_valid(), None);
        assert_eq!(NextCluster::Bad.as_valid(), None);
    }

    // ========================================================================
    // FileAttributes Tests
    // ========================================================================

    #[test]
    fn test_file_attributes() {
        let attrs = FileAttributes::from_bits_truncate(0x21); // READ_ONLY | ARCHIVE
        assert!(attrs.is_read_only());
        assert!((attrs.bits() & FileAttributes::ARCHIVE) != 0); // ARCHIVE check via bits
        assert!(!attrs.is_hidden());
        assert!(!attrs.is_system());
        assert!(!attrs.is_directory());
    }

    #[test]
    fn test_file_attributes_directory() {
        let attrs = FileAttributes::from_bits_truncate(0x10); // DIRECTORY
        assert!(attrs.is_directory());
        assert!(!attrs.is_read_only());
    }

    #[test]
    fn test_mount_minimal_boot_sector() {
        use alloc::sync::Arc;
        use vfs::block::RamDisk;

        let disk = Arc::new(RamDisk::new(2048, 512));

        let mut bs = [0u8; BOOT_SECTOR_SIZE];
        // Standard BPB offsets (little-endian fields)
        bs[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes per sector
        bs[13] = 1; // sectors per cluster
        bs[14..16].copy_from_slice(&32u16.to_le_bytes()); // reserved sectors
        bs[16] = 2; // number of FATs
        bs[32..36].copy_from_slice(&4096u32.to_le_bytes()); // total sectors (32-bit)
        bs[36..40].copy_from_slice(&1u32.to_le_bytes()); // FAT size 32
        bs[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        bs[82..90].copy_from_slice(b"FAT32   "); // fs type field
        bs[510] = 0x55; // signature (little-endian 0xAA55)
        bs[511] = 0xAA;

        disk.write_sync(0, &bs).expect("write boot sector");

        let fs = Fat32FileSystem::mount(disk).expect("mount should succeed");
        assert_eq!((&*fs).root_cluster, Cluster(2));
    }

    #[test]
    fn test_write_and_flush_fat_entry_writes_to_disk() {
        use alloc::sync::Arc;
        use vfs::block::RamDisk;

        let disk = Arc::new(RamDisk::new(2048, 512));

        let mut bs = [0u8; BOOT_SECTOR_SIZE];
        bs[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes per sector
        bs[13] = 1; // sectors per cluster
        bs[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved sectors = 1
        bs[16] = 2; // number of FATs
        bs[32..36].copy_from_slice(&4096u32.to_le_bytes()); // total sectors
        bs[36..40].copy_from_slice(&1u32.to_le_bytes()); // FAT size 32
        bs[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        bs[82..90].copy_from_slice(b"FAT32   "); // fs type field
        bs[510] = 0x55;
        bs[511] = 0xAA;

        disk.write_sync(0, &bs).expect("write boot sector");

        let fs = Fat32FileSystem::mount(disk.clone()).expect("mount should succeed");
        assert!(fs.full_fat_cache);

        // Write FAT entry index 2 -> EOF
        fs.write_fat_entry(Cluster(2), Cluster::EOF)
            .expect("write entry");

        // Check in-memory cache
        {
            let fat = fs.fat_cache.read();
            assert_eq!(fat[2], Cluster::EOF);
        }

        // Dirty sector should be set (sector_idx 0)
        {
            let dirty = fs.dirty_sectors.read();
            assert!(dirty[0]);
        }

        // Flush and verify disk contents
        fs.flush_dirty_fat_sectors().expect("flush");

        // After flush, dirty flag cleared
        {
            let dirty = fs.dirty_sectors.read();
            assert!(!dirty[0]);
        }

        // Read primary FAT sector from disk and verify entry value
        let mut buf = [0u8; BLOCK_SIZE];
        fs.device
            .read_sync(fs.fat_start_sector.as_u64(), &mut buf)
            .expect("read primary fat");

        let offset = 2 * 4;
        let val = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]) & 0x0FFFFFFF;
        assert_eq!(val, Cluster::EOF.0 & 0x0FFFFFFF);
    }

    #[test]
    fn test_file_attributes_lfn() {
        let attrs = FileAttributes::from_bits_truncate(0x0F); // LFN marker
        assert!(attrs.is_long_name());
    }

    #[test]
    fn test_lfn_checksum() {
        // "TEST    TXT" -> checksum: 0x51
        let mut base = [b' '; 8];
        base[0..4].copy_from_slice(b"TEST");
        let mut ext = [b' '; 3];
        ext[0..3].copy_from_slice(b"TXT");
        let entry = DirEntryRaw::new(
            base,
            ext,
            FileAttributes::from_bits_truncate(0),
            Cluster(2),
            0,
        );
        assert_eq!(entry.calculate_checksum(), 0x51);
    }
}

// ============================================================================
// VFS Implementations
// ============================================================================

use alloc::boxed::Box;
use vfs::{Directory, File, Metadata, SeekFrom};

impl Inode for Fat32Inode {
    fn metadata(&self) -> FsResult<Metadata> {
        let attr = self.getattr()?;
        let inner = self.inner.read();
        Ok(Metadata {
            file_type: Some(self.file_type),
            size: inner.size,
            created: inner.created,
            modified: inner.modified,
            accessed: inner.accessed,
            readonly: inner.attributes.is_read_only(),
        })
    }

    fn open(&self, _flags: OpenFlags) -> FsResult<Box<dyn File>> {
        Ok(Box::new(Fat32File {
            inode: Arc::new(self.clone()),
            position: 0,
        }))
    }

    fn as_dir(&self) -> FsResult<Box<dyn Directory>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }
        Ok(Box::new(Fat32Directory {
            inode: Arc::new(self.clone()),
        }))
    }

    fn name(&self) -> String {
        let inner = self.inner.read();
        inner.name.clone()
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl Clone for Fat32Inode {
    fn clone(&self) -> Self {
        Self {
            fs: self.fs.clone(),
            file_type: self.file_type,
            inner: RwLock::new(self.inner.read().clone()),
        }
    }
}

pub struct Fat32File {
    inode: Arc<Fat32Inode>,
    position: u64,
}

impl File for Fat32File {
    fn read(&mut self, buf: &mut [u8]) -> FsResult<usize> {
        let n = self.inode.read(self.position, buf)?;
        self.position += n as u64;
        Ok(n)
    }

    fn write(&mut self, buf: &[u8]) -> FsResult<usize> {
        let n = self.inode.write(self.position, buf)?;
        self.position += n as u64;
        Ok(n)
    }

    fn seek(&mut self, pos: SeekFrom) -> FsResult<u64> {
        let new_pos = match pos {
            SeekFrom::Start(off) => off,
            SeekFrom::End(off) => {
                let size = self.inode.getattr()?.size;
                if off < 0 {
                    size.checked_sub((-off) as u64)
                        .ok_or(FsError::InvalidInput)?
                } else {
                    size + off as u64
                }
            }
            SeekFrom::Current(off) => {
                if off < 0 {
                    self.position
                        .checked_sub((-off) as u64)
                        .ok_or(FsError::InvalidInput)?
                } else {
                    self.position + off as u64
                }
            }
        };
        self.position = new_pos;
        Ok(new_pos)
    }

    fn flush(&mut self) -> FsResult<()> {
        Ok(())
    }

    fn set_len(&mut self, size: u64) -> FsResult<()> {
        let mut attr = self.inode.getattr()?;
        attr.size = size;
        self.inode.setattr(&attr)
    }
}

pub struct Fat32Directory {
    inode: Arc<Fat32Inode>,
}

impl Directory for Fat32Directory {
    fn lookup(&self, name: &str) -> FsResult<Box<dyn Inode>> {
        let inode = self.inode.lookup(name)?;
        Ok(Box::new(
            Arc::try_unwrap(inode).unwrap_or_else(|arc| (*arc).clone()),
        ))
    }

    fn create(&mut self, name: &str, file_type: FileType) -> FsResult<Box<dyn Inode>> {
        let inode = if file_type == FileType::Directory {
            self.inode
                .mkdir(name, FileMode::from_bits_truncate(0o755))?
        } else {
            self.inode.create(
                name,
                FileMode::from_bits_truncate(0o644),
                OpenFlags::empty(),
            )?
        };
        Ok(Box::new(
            Arc::try_unwrap(inode).unwrap_or_else(|arc| (*arc).clone()),
        ))
    }

    fn remove(&mut self, name: &str) -> FsResult<()> {
        let target = self.inode.lookup(name)?;
        if target.getattr()?.file_type == Some(FileType::Directory) {
            self.inode.rmdir(name)
        } else {
            self.inode.unlink(name)
        }
    }

    fn read_dir(&mut self) -> FsResult<Vec<DirEntry>> {
        self.inode.readdir(0)
    }
}

// ============================================================================
// Format Utility (mkfs.fat32)
// ============================================================================

/// FAT32フォーマットオプション
#[derive(Debug, Clone)]
pub struct FormatOptions {
    /// ボリュームラベル（最大11文字、大文字）
    pub label: [u8; 11],
    /// セクタあたりのバイト数（通常512）
    pub bytes_per_sector: u16,
    /// クラスタあたりのセクタ数（自動計算する場合はNone）
    pub sectors_per_cluster: Option<u8>,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            label: *b"NO NAME    ",
            bytes_per_sector: 512,
            sectors_per_cluster: None,
        }
    }
}

impl FormatOptions {
    /// ボリュームラベルを設定
    pub fn with_label(mut self, label: &str) -> Self {
        let bytes = label.as_bytes();
        let len = bytes.len().min(11);
        self.label = [b' '; 11];
        for (i, &b) in bytes.iter().take(len).enumerate() {
            self.label[i] = b.to_ascii_uppercase();
        }
        self
    }

    /// クラスタサイズを設定
    pub fn with_cluster_size(mut self, sectors: u8) -> Self {
        self.sectors_per_cluster = Some(sectors);
        self
    }
}

impl Fat32FileSystem {
    /// ブロックデバイスをFAT32でフォーマット
    ///
    /// # Arguments
    /// * `device` - フォーマット対象のブロックデバイス
    /// * `options` - フォーマットオプション
    ///
    /// # Returns
    /// フォーマット済みのファイルシステム
    ///
    /// # Warning
    /// この操作はデバイス上の全データを消去します
    pub fn format(device: Arc<dyn BlockDevice>, options: FormatOptions) -> FsResult<Arc<Self>> {
        let info = device.info();
        let total_sectors = info.total_blocks as u32;
        let bytes_per_sector = options.bytes_per_sector as u32;

        // 最小サイズチェック（FAT32は32MB以上推奨）
        if total_sectors < 65536 {
            return Err(FsError::InvalidInput);
        }

        // クラスタサイズを決定
        let sectors_per_cluster = options.sectors_per_cluster.unwrap_or_else(|| {
            // Microsoft推奨アルゴリズム
            let size_mb = (total_sectors as u64 * bytes_per_sector as u64) / (1024 * 1024);
            match size_mb {
                0..=64 => 1,        // 512B cluster
                65..=128 => 2,      // 1KB cluster
                129..=256 => 4,     // 2KB cluster
                257..=8192 => 8,    // 4KB cluster
                8193..=16384 => 16, // 8KB cluster
                _ => 32,            // 16KB cluster
            }
        }) as u8;

        // FAT32パラメータ計算
        let reserved_sectors: u16 = 32;
        let num_fats: u8 = 2;
        let root_cluster: u32 = 2;

        // FAT サイズ計算
        let data_sectors = total_sectors - reserved_sectors as u32;
        let clusters = data_sectors / sectors_per_cluster as u32;
        let fat_size = (clusters * 4 + bytes_per_sector - 1) / bytes_per_sector;

        // ブートセクタ構築
        let mut boot_sector = [0u8; 512];

        // ジャンプ命令
        boot_sector[0] = 0xEB;
        boot_sector[1] = 0x58;
        boot_sector[2] = 0x90;

        // OEM名
        boot_sector[3..11].copy_from_slice(b"RANYOS  ");

        // BPB
        boot_sector[11..13].copy_from_slice(&options.bytes_per_sector.to_le_bytes());
        boot_sector[13] = sectors_per_cluster;
        boot_sector[14..16].copy_from_slice(&reserved_sectors.to_le_bytes());
        boot_sector[16] = num_fats;
        boot_sector[17..19].copy_from_slice(&0u16.to_le_bytes()); // FAT32では0
        boot_sector[19..21].copy_from_slice(&0u16.to_le_bytes()); // FAT32では0
        boot_sector[21] = 0xF8; // ハードディスク
        boot_sector[22..24].copy_from_slice(&0u16.to_le_bytes()); // FAT32では0
        boot_sector[24..26].copy_from_slice(&63u16.to_le_bytes()); // セクタ/トラック
        boot_sector[26..28].copy_from_slice(&255u16.to_le_bytes()); // ヘッド数
        boot_sector[28..32].copy_from_slice(&0u32.to_le_bytes()); // 隠しセクタ
        boot_sector[32..36].copy_from_slice(&total_sectors.to_le_bytes());

        // FAT32拡張BPB
        boot_sector[36..40].copy_from_slice(&fat_size.to_le_bytes());
        boot_sector[40..42].copy_from_slice(&0u16.to_le_bytes()); // 拡張フラグ
        boot_sector[42..44].copy_from_slice(&0u16.to_le_bytes()); // バージョン
        boot_sector[44..48].copy_from_slice(&root_cluster.to_le_bytes());
        boot_sector[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo sector
        boot_sector[50..52].copy_from_slice(&6u16.to_le_bytes()); // バックアップブートセクタ
        boot_sector[64] = 0x80; // ドライブ番号
        boot_sector[66] = 0x29; // 拡張ブートシグネチャ
        boot_sector[67..71].copy_from_slice(&0x12345678u32.to_le_bytes()); // ボリュームシリアル
        boot_sector[71..82].copy_from_slice(&options.label);
        boot_sector[82..90].copy_from_slice(b"FAT32   ");
        boot_sector[510] = 0x55;
        boot_sector[511] = 0xAA;

        // ブートセクタ書き込み
        device.write_sync(0, &boot_sector)?;

        // バックアップブートセクタ
        device.write_sync(6, &boot_sector)?;

        // FSInfo セクタ
        let free_clusters = clusters - 1; // ルートディレクトリ用に1クラスタ使用
        let fsinfo = FsInfo::new(free_clusters, 3); // 次の空きは3から
        device.write_sync(1, &fsinfo.to_bytes())?;
        device.write_sync(7, &fsinfo.to_bytes())?; // バックアップ

        // FAT 初期化
        let fat_start = reserved_sectors as u64;
        let mut fat_sector = [0u8; 512];

        // 最初のFATセクタ
        fat_sector[0..4].copy_from_slice(&0x0FFFFFF8u32.to_le_bytes()); // クラスタ0
        fat_sector[4..8].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // クラスタ1
        fat_sector[8..12].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // クラスタ2 (ルート、EOF)

        device.write_sync(fat_start, &fat_sector)?;
        device.write_sync(fat_start + fat_size as u64, &fat_sector)?; // バックアップFAT

        // 残りのFATセクタをゼロ初期化
        let zero_sector = [0u8; 512];
        for i in 1..fat_size {
            device.write_sync(fat_start + i as u64, &zero_sector)?;
            device.write_sync(fat_start + fat_size as u64 + i as u64, &zero_sector)?;
        }

        // ルートディレクトリ初期化
        let data_start = reserved_sectors as u32 + num_fats as u32 * fat_size;
        let root_dir_sector = data_start;

        let mut root_dir = [0u8; 512];
        // ボリュームラベルエントリ
        root_dir[0..11].copy_from_slice(&options.label);
        root_dir[11] = 0x08; // ボリュームラベル属性

        device.write_sync(root_dir_sector as u64, &root_dir)?;

        // フラッシュ
        device.flush()?;

        // マウント
        Self::mount(device)
    }
}
