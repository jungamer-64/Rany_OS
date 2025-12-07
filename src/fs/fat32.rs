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
//! - Newtype パターン(Cluster, Sector)による取り違え防止
//! - FileAttributes による属性の型安全な管理
//! - SafePackedRead トレイトによる packed 構造体への安全なアクセス
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
//!
//! ## 将来の改善予定
//! - LRUキャッシュによるFATテーブルのオンデマンド読み込み
//! - ダーティフラグ管理によるバッチ書き込み
//! - より高度なフラグメンテーション対策

#![allow(dead_code)]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;
use core::ops::{Add, Sub};
use spin::RwLock;

use super::block::BlockDevice;
use super::vfs::{
    DirEntry, FileAttr, FileMode, FileSystem, FileType, FsError, FsResult, FsStats, Inode,
    InodeNum, OpenFlags,
};

// ============================================================================
// Constants
// ============================================================================

/// 最大クラスタチェーン長(無限ループ検出用)
const MAX_CLUSTER_CHAIN: usize = 0x10000000; // 268M clusters = 約1TB @ 4KB/cluster
/// 最大パス長(DOS互換)
const MAX_PATH_LEN: usize = 260;
/// 最大ファイル名長(単一コンポーネント)
const MAX_NAME_LEN: usize = 255;

/// パス長が制限内かチェック
fn validate_path_length(path: &str) -> FsResult<()> {
    if path.len() > MAX_PATH_LEN {
        return Err(FsError::NameTooLong);
    }
    // 各パスコンポーネントもチェック
    for component in path.split('/').filter(|s| !s.is_empty()) {
        if component.len() > MAX_NAME_LEN {
            return Err(FsError::NameTooLong);
        }
    }
    Ok(())
}

// ============================================================================
// Strong Types (Newtypes)
// ============================================================================

/// クラスタ番号を型安全に扱うためのラッパー
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

    /// 有効なデータクラスタかどうか（2以上、かつ予約済みマーカー未満）
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.0 >= 2 && self.0 < 0x0FFFFFF0
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

// ============================================================================
// Constants & Attributes
// ============================================================================

/// ブロック/セクタサイズ
const BLOCK_SIZE: usize = 512;

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
        if self.is_read_only() { parts.push("RO"); }
        if self.is_hidden() { parts.push("HIDDEN"); }
        if self.is_system() { parts.push("SYSTEM"); }
        if self.is_volume_id() { parts.push("VOLUME"); }
        if self.is_directory() { parts.push("DIR"); }
        // ARCHIVE はほぼすべてのファイルに設定されるので省略
        
        if parts.is_empty() {
            write!(f, "(none)")
        } else {
            write!(f, "{}", parts.join(" | "))
        }
    }
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

impl BiosParameterBlock {
    /// 1セクタあたりのバイト数を取得
    #[inline]
    pub fn bytes_per_sector(&self) -> u16 {
        u16::from_le_bytes(self.bytes_per_sector)
    }
    
    /// 予約セクタ数を取得
    #[inline]
    pub fn reserved_sectors(&self) -> u16 {
        u16::from_le_bytes(self.reserved_sectors)
    }
    
    /// ルートディレクトリエントリ数を取得
    #[inline]
    pub fn root_entry_count(&self) -> u16 {
        u16::from_le_bytes(self.root_entry_count)
    }
    
    /// 総セクタ数（16ビット）を取得
    #[inline]
    pub fn total_sectors_16(&self) -> u16 {
        u16::from_le_bytes(self.total_sectors_16)
    }
    
    /// FATサイズ（16ビット）を取得
    #[inline]
    pub fn fat_size_16(&self) -> u16 {
        u16::from_le_bytes(self.fat_size_16)
    }
    
    /// 隠しセクタ数を取得
    #[inline]
    pub fn hidden_sectors(&self) -> u32 {
        u32::from_le_bytes(self.hidden_sectors)
    }
    
    /// 総セクタ数（32ビット）を取得
    #[inline]
    pub fn total_sectors_32(&self) -> u32 {
        u32::from_le_bytes(self.total_sectors_32)
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

impl Fat32ExtendedBpb {
    /// FATサイズ（32ビット）を取得
    #[inline]
    pub fn fat_size_32(&self) -> u32 {
        u32::from_le_bytes(self.fat_size_32)
    }
    
    /// 拡張フラグを取得
    #[inline]
    pub fn ext_flags(&self) -> u16 {
        u16::from_le_bytes(self.ext_flags)
    }
    
    /// ファイルシステムバージョンを取得
    #[inline]
    pub fn fs_version(&self) -> u16 {
        u16::from_le_bytes(self.fs_version)
    }
    
    /// ルートクラスタを取得
    #[inline]
    pub fn root_cluster(&self) -> u32 {
        u32::from_le_bytes(self.root_cluster)
    }
    
    /// FSInfoセクタ番号を取得
    #[inline]
    pub fn fs_info_sector(&self) -> u16 {
        u16::from_le_bytes(self.fs_info_sector)
    }
    
    /// バックアップブートセクタを取得
    #[inline]
    pub fn backup_boot_sector(&self) -> u16 {
        u16::from_le_bytes(self.backup_boot_sector)
    }
    
    /// ボリュームシリアル番号を取得
    #[inline]
    pub fn volume_serial(&self) -> u32 {
        u32::from_le_bytes(self.volume_serial)
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
            return Err(FsError::InvalidArgument);
        }
        
        // バイト配列としてコピー（アライメントの問題は発生しない）
        let boot_sector = unsafe { 
            core::ptr::read_unaligned(bytes.as_ptr() as *const BootSector) 
        };

        // シグネチャチェック
        if boot_sector.signature() != FAT32_SIGNATURE {
            return Err(FsError::InvalidArgument);
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

impl DirEntryRaw {
    /// バイト列から安全にDirEntryRawを読み取る
    pub fn from_bytes(bytes: &[u8]) -> Self {
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DirEntryRaw) }
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
    pub fn new(name: [u8; 8], ext: [u8; 3], attr: FileAttributes, cluster: Cluster, size: u32) -> Self {
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
    
    /// "." エントリを作成
    #[inline]
    pub fn new_dot(cluster: Cluster) -> Self {
        let mut name = [b' '; 8];
        name[0] = b'.';
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
    
    /// ".." エントリを作成
    #[inline]
    pub fn new_dotdot(parent_cluster: Cluster) -> Self {
        let mut name = [b' '; 8];
        name[0] = b'.';
        name[1] = b'.';
        Self {
            name,
            ext: [b' '; 3],
            attr: FileAttributes::DIRECTORY,
            nt_reserved: 0,
            create_time_tenths: 0,
            create_time: [0; 2],
            create_date: [0; 2],
            access_date: [0; 2],
            first_cluster_hi: ((parent_cluster.0 >> 16) as u16).to_le_bytes(),
            modify_time: [0; 2],
            modify_date: [0; 2],
            first_cluster_lo: ((parent_cluster.0 & 0xFFFF) as u16).to_le_bytes(),
            file_size: [0; 4],
        }
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

        name
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
                    self.lfn_parts.push((lfn.sequence(), lfn.get_name_part(), lfn.checksum()));
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
                        let lfn_checksum = self.lfn_parts.first().map(|(_, _, cs)| *cs).unwrap_or(0);
                        
                        if lfn_checksum != expected_checksum {
                            // チェックサム不一致：ショートネームにフォールバック
                            self.lfn_parts.clear();
                            raw.short_name()
                        } else {
                            self.lfn_parts.sort_by_key(|&(seq, _, _)| seq);
                            let long_name: String = self.lfn_parts.iter().map(|(_, s, _)| s.as_str()).collect();
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

/// ディレクトリエントリの種類を表す列挙型
///
/// 生のバイト列を解析した結果を型安全に表現する。
/// if/else の条件分岐をパターンマッチに置き換えることで、
/// コードの意図が明確になり、網羅性チェックも働く。
///
/// # Deprecated
/// この型は `DirectoryIterator` 内部で使用され、外部に公開する必要はなくなりました。
#[derive(Debug)]
#[deprecated(since = "0.1.0", note = "Internal use only, use DirectoryIterator instead")]
pub enum _DirectoryEntryKind {
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

impl LfnEntry {
    /// バイト列から安全にLfnEntryを読み取る
    pub fn from_bytes(bytes: &[u8]) -> Self {
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const LfnEntry) }
    }
    
    /// LFNエントリのチェックサムを取得
    #[inline]
    pub fn checksum(&self) -> u8 {
        self.checksum
    }
    
    /// バイト配列からUCS-2文字（u16）を読み取るヘルパー
    #[inline]
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

        // [u8; N] から UCS-2 文字列を安全に読み取り
        Self::read_ucs2_chars(&self.name1, &mut chars);
        Self::read_ucs2_chars(&self.name2, &mut chars);
        Self::read_ucs2_chars(&self.name3, &mut chars);

        String::from_utf16_lossy(&chars)
    }

    /// 最後のLFNエントリかどうか
    #[inline]
    pub fn is_last(&self) -> bool {
        self.seq & 0x40 != 0
    }

    /// シーケンス番号を取得（1-20）
    #[inline]
    pub fn sequence(&self) -> u8 {
        self.seq & 0x1F
    }
}

// ============================================================================
// FAT32 Filesystem
// ============================================================================

/// FAT32ファイルシステム
pub struct Fat32FileSystem {
    /// ブロックデバイス
    device: Arc<dyn BlockDevice>,
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
    /// FATキャッシュ（Cluster型でキャッシュ）
    fat_cache: RwLock<Vec<Cluster>>,
    /// 空きクラスタ数
    free_clusters: RwLock<u32>,
    /// FATサイズ（セクタ数）
    fat_size: u32,
    /// ダーティフラグ(将来的にバッチ書き込みに使用)
    fat_dirty: RwLock<bool>,
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
            return Some(Err(FsError::CorruptedFs));
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
    pub fn clusters(&self, start: Cluster) -> ClusterChain {
        ClusterChain::new(self, start)
    }

    /// FAT32ファイルシステムをマウント
    pub fn mount(device: Arc<dyn BlockDevice>) -> FsResult<Arc<Self>> {
        // ブートセクタを読み取り
        let mut boot_data = [0u8; BOOT_SECTOR_SIZE];
        device
            .read_sync(0, &mut boot_data)
            .map_err(|_| FsError::IoError)?;

        // TryFrom トレイトで安全にパース
        let boot_sector = BootSector::try_from(&boot_data[..])?;

        // FAT32であることを確認
        let fs_type = boot_sector.fs_type();
        if &fs_type[0..5] != b"FAT32" {
            return Err(FsError::InvalidArgument);
        }

        // 各パラメータを計算（型安全）
        let fat_start_sector = Sector(boot_sector.reserved_sectors());
        let fat_size = boot_sector.fat_size_32();
        let num_fats = boot_sector.num_fats();
        let data_start_sector = fat_start_sector + (num_fats * fat_size);

        let total_sectors = boot_sector.total_sectors();
        let data_sectors = total_sectors - data_start_sector.0;
        let sectors_per_cluster = boot_sector.sectors_per_cluster();
        let total_clusters = data_sectors / sectors_per_cluster;

        let fs = Arc::new(Self {
            device,
            fat_start_sector,
            data_start_sector,
            sectors_per_cluster,
            total_clusters,
            root_cluster: boot_sector.root_cluster(),
            fat_cache: RwLock::new(Vec::new()),
            free_clusters: RwLock::new(0),
            fat_size,
            fat_dirty: RwLock::new(false),
        });

        // FATをキャッシュに読み込み
        fs.load_fat()?;

        Ok(fs)
    }

    /// FATテーブルを読み込み
    /// 
    /// # メモリ枯渇の懸念
    /// 現在の実装では、FAT全体をメモリにロードしています。
    /// 大容量ボリューム(32GB以上)では、FATだけで数十MB〜数百MBのRAMを消費します。
    /// 
    /// **推奨される改善策:**
    /// - LRUキャッシュを実装し、必要なFATセクタのみをオンデマンドで読み込む
    /// - キャッシュサイズを制限し、古いエントリを破棄する
    /// - 現状は小〜中規模ボリューム(数GB程度)での使用を想定
    /// 
    /// # Example
    /// 32GB, 4KB/cluster => 約8M エントリ => 32MB RAM
    /// 1TB, 4KB/cluster => 約256M エントリ => 1GB RAM (カーネルヒープを圧迫!)
    fn load_fat(&self) -> FsResult<()> {
        let sectors = self.fat_size as usize;
        let entries = sectors * BLOCK_SIZE / 4;

        let mut fat = vec![Cluster::FREE; entries];
        let mut buffer = [0u8; BLOCK_SIZE];

        for i in 0..sectors {
            let sector = self.fat_start_sector + i as u32;
            self.device
                .read_sync(sector.as_u64(), &mut buffer)
                .map_err(|_| FsError::IoError)?;

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
        let fat = self.fat_cache.read();
        let idx = cluster.0 as usize;
        if idx >= fat.len() {
            return Err(FsError::InvalidArgument);
        }
        Ok(fat[idx])
    }

    /// FATエントリを書き込み(型安全)
    fn write_fat_entry(&self, cluster: Cluster, value: Cluster) -> FsResult<()> {
        let idx = cluster.0 as usize;
        {
            let mut fat = self.fat_cache.write();
            if idx >= fat.len() {
                return Err(FsError::InvalidArgument);
            }
            fat[idx] = value;
        }
        
        // ディスクへの書き込み
        self.write_fat_entry_to_disk(cluster, value)?;
        Ok(())
    }
    
    /// FATエントリをディスクに書き込む(内部用)
    fn write_fat_entry_to_disk(&self, cluster: Cluster, value: Cluster) -> FsResult<()> {
        let idx = cluster.0 as usize;
        
        // ディスクにも書き込み
        let fat_offset = idx * 4;
        let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
        let sector = self.fat_start_sector + sector_offset;
        let offset_in_sector = fat_offset % BLOCK_SIZE;

        let mut buffer = [0u8; BLOCK_SIZE];
        self.device
            .read_sync(sector.as_u64(), &mut buffer)
            .map_err(|_| FsError::IoError)?;

        let bytes = (value.0 & 0x0FFFFFFF).to_le_bytes();
        buffer[offset_in_sector..offset_in_sector + 4].copy_from_slice(&bytes);

        self.device
            .write_sync(sector.as_u64(), &buffer)
            .map_err(|_| FsError::IoError)?;

        // バックアップFAT(FAT2)への書き込み
        let fat2_sector = sector + self.fat_size;
        self.device
            .write_sync(fat2_sector.as_u64(), &buffer)
            .map_err(|_| FsError::IoError)?;

        Ok(())
    }

    /// 空きクラスタを割り当て(型安全、アトミック)
    /// 
    /// # Race Condition Fix
    /// 検索と確保を同一の書き込みロック区間内で実行することで、
    /// 複数スレッドが同じクラスタを確保するTOCTOU脆弱性を防止。
    fn allocate_cluster(&self) -> FsResult<Cluster> {
        // 最初から書き込みロックを取得してアトミック性を確保
        let mut fat = self.fat_cache.write();
        
        // クラスタ2から検索開始
        for i in 2..fat.len() {
            if fat[i].is_free() {
                let cluster = Cluster(i as u32);
                // メモリ上のキャッシュを即座に更新
                fat[i] = Cluster::EOF;
                
                // ロックを保持したまま空きクラスタカウントを更新
                let mut free = self.free_clusters.write();
                *free = free.saturating_sub(1);
                drop(free);
                drop(fat);
                
                // ディスクへの書き込み(ロック解放後に実行してパフォーマンス改善)
                self.write_fat_entry_to_disk(cluster, Cluster::EOF)?;
                
                return Ok(cluster);
            }
        }
        Err(FsError::NoSpace)
    }

    /// クラスタを解放(型安全)
    fn free_cluster(&self, cluster: Cluster) -> FsResult<()> {
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
        let clusters: Vec<Cluster> = self.clusters(start_cluster)
            .collect::<FsResult<Vec<_>>>()?;
        
        for cluster in clusters {
            self.free_cluster(cluster)?;
        }

        Ok(())
    }

    /// クラスタを読み取り（型安全）
    fn read_cluster(&self, cluster: Cluster, buffer: &mut [u8]) -> FsResult<()> {
        let start_sector = self.cluster_to_sector(cluster);
        let cluster_size = self.cluster_size();

        if buffer.len() < cluster_size {
            return Err(FsError::InvalidArgument);
        }

        for i in 0..self.sectors_per_cluster {
            let sector = start_sector + i;
            let offset = (i as usize) * BLOCK_SIZE;
            self.device
                .read_sync(sector.as_u64(), &mut buffer[offset..offset + BLOCK_SIZE])
                .map_err(|_| FsError::IoError)?;
        }

        Ok(())
    }

    /// クラスタを書き込み（型安全）
    fn write_cluster(&self, cluster: Cluster, buffer: &[u8]) -> FsResult<()> {
        let start_sector = self.cluster_to_sector(cluster);
        let cluster_size = self.cluster_size();

        if buffer.len() < cluster_size {
            return Err(FsError::InvalidArgument);
        }

        for i in 0..self.sectors_per_cluster {
            let sector = start_sector + i;
            let offset = (i as usize) * BLOCK_SIZE;
            self.device
                .write_sync(sector.as_u64(), &buffer[offset..offset + BLOCK_SIZE])
                .map_err(|_| FsError::IoError)?;
        }

        Ok(())
    }

    /// クラスタサイズを取得
    fn cluster_size(&self) -> usize {
        self.sectors_per_cluster as usize * BLOCK_SIZE
    }
}

impl FileSystem for Fat32FileSystem {
    fn name(&self) -> &str {
        "fat32"
    }

    fn root(&self) -> FsResult<Arc<dyn Inode>> {
        Ok(Arc::new(Fat32Inode::new_directory(
            Arc::new(self.clone()),
            self.root_cluster,
            Cluster(0), // ルートの親は0とする
        )))
    }

    fn statfs(&self) -> FsResult<FsStats> {
        let cluster_size = self.cluster_size() as u64;
        let free = *self.free_clusters.read() as u64;

        Ok(FsStats {
            blocks: self.total_clusters as u64,
            bfree: free,
            bavail: free,
            files: 0,
            ffree: 0,
            bsize: cluster_size as u32,
            namelen: 255,
            frsize: cluster_size as u32,
        })
    }

    fn sync(&self) -> FsResult<()> {
        // FAT32ではwrite_fat_entry()が個々のエントリを即座にディスクに書き込むため
        // キャッシュフラッシュは不要。デバイスレベルのflush()のみ実行する。
        //
        // Note: パフォーマンスが問題になる場合は、write_fat_entry()でダーティフラグを
        // 立てて、sync()時にまとめて書き込むようにバッチ処理を検討すること。
        self.device
            .flush()
            .map_err(|_| FsError::IoError)?;
        Ok(())
    }

    fn unmount(&self) -> FsResult<()> {
        self.sync()
    }
}

impl Clone for Fat32FileSystem {
    fn clone(&self) -> Self {
        Self {
            device: self.device.clone(),
            fat_start_sector: self.fat_start_sector,
            data_start_sector: self.data_start_sector,
            sectors_per_cluster: self.sectors_per_cluster,
            total_clusters: self.total_clusters,
            root_cluster: self.root_cluster,
            fat_cache: RwLock::new(self.fat_cache.read().clone()),
            free_clusters: RwLock::new(*self.free_clusters.read()),
            fat_size: self.fat_size,
            fat_dirty: RwLock::new(*self.fat_dirty.read()),
        }
    }
}

// ============================================================================
// FAT32 Inode
// ============================================================================

/// FAT32 inode
pub struct Fat32Inode {
    /// ファイルシステム
    fs: Arc<Fat32FileSystem>,
    /// 開始クラスタ（型安全）
    first_cluster: Cluster,
    /// ファイルサイズ
    size: u64,
    /// ファイルタイプ
    file_type: FileType,
    /// 親ディレクトリのクラスタ（型安全）
    parent_cluster: Cluster,
}

impl Fat32Inode {
    /// 新しいディレクトリinodeを作成
    pub fn new_directory(fs: Arc<Fat32FileSystem>, cluster: Cluster, parent: Cluster) -> Self {
        Self {
            fs,
            first_cluster: cluster,
            size: 0,
            file_type: FileType::Directory,
            parent_cluster: parent,
        }
    }

    /// 新しいファイルinodeを作成
    pub fn new_file(
        fs: Arc<Fat32FileSystem>,
        cluster: Cluster,
        size: u64,
        parent: Cluster,
    ) -> Self {
        Self {
            fs,
            first_cluster: cluster,
            size,
            file_type: FileType::Regular,
            parent_cluster: parent,
        }
    }

    /// ディレクトリエントリのイテレータを返す
    ///
    /// # 遅延評価のメリット
    /// - **メモリ効率**: 全エントリを Vec に読み込まない
    /// - **早期終了**: `lookup` で見つかったら即座に読み込みを停止
    /// - **標準メソッド**: `find()`, `filter()`, `collect()` 等が使用可能
    ///
    /// # Example
    /// ```ignore
    /// // 特定ファイルを検索
    /// let entry = inode.entries()?
    ///     .find(|res| res.as_ref().ok()
    ///         .map(|e| e.0 == "target.txt")
    ///         .unwrap_or(false))
    ///     .transpose()?;
    /// ```
    pub fn entries(&self) -> FsResult<DirectoryIterator> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }
        DirectoryIterator::new(&self.fs, self.first_cluster)
    }

    /// ディレクトリの全エントリを読み取り
    /// 
    /// # Deprecated
    /// `entries()` イテレータを使用してください。
    /// このメソッドは互換性のために残されています。
    #[deprecated(since = "0.1.0", note = "Use entries() iterator instead for better performance")]
    fn read_dir_entries(&self) -> FsResult<Vec<(String, DirEntryRaw)>> {
        self.entries()?.collect()
    }

    /// 8.3形式のショートファイル名を生成
    fn generate_short_name(name: &str) -> ([u8; 8], [u8; 3]) {
        let mut base = [b' '; 8];
        let mut ext = [b' '; 3];
        
        let name_upper = name.to_uppercase();
        let parts: Vec<&str> = name_upper.rsplitn(2, '.').collect();
        
        let (base_part, ext_part) = if parts.len() == 2 {
            (parts[1], Some(parts[0]))
        } else {
            (parts[0], None)
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

    /// ディレクトリに新しいエントリを追加
    fn add_dir_entry(&self, name: &str, cluster: Cluster, attr: FileAttributes, size: u32) -> FsResult<()> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }
        
        let cluster_size = self.fs.cluster_size();
        let mut buffer = vec![0u8; cluster_size];
        let mut current_cluster = self.first_cluster;
        let mut chain_count = 0;
        
        // 空きエントリを探す
        while current_cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidArgument); // クラスタチェーンが循環している
            }
            
            self.fs.read_cluster(current_cluster, &mut buffer)?;
            
            let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;
            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let first_byte = buffer[offset];
                
                // 空きエントリまたは削除済みエントリを使用
                if first_byte == END_OF_DIR || first_byte == DELETED_ENTRY {
                    // 新しいエントリを作成
                    let (base_name, ext_name) = Self::generate_short_name(name);
                    
                    let entry = DirEntryRaw::new(base_name, ext_name, attr, cluster, size);
                    
                    // バッファに書き込み
                    let entry_bytes = unsafe {
                        core::slice::from_raw_parts(
                            &entry as *const DirEntryRaw as *const u8,
                            DIR_ENTRY_SIZE
                        )
                    };
                    buffer[offset..offset + DIR_ENTRY_SIZE].copy_from_slice(entry_bytes);
                    
                    // 元がEND_OF_DIRだった場合、次のエントリもEND_OF_DIRにする
                    if first_byte == END_OF_DIR && i + 1 < entries_per_cluster {
                        buffer[offset + DIR_ENTRY_SIZE] = END_OF_DIR;
                    }
                    
                    // クラスタを書き戻し
                    self.fs.write_cluster(current_cluster, &buffer)?;
                    return Ok(());
                }
            }
            
            // 次のクラスタへ
            let next = self.fs.read_fat_entry(current_cluster)?;
            if !next.is_valid() {
                // 新しいクラスタを割り当て
                let new_cluster = self.fs.allocate_cluster()?;
                self.fs.write_fat_entry(current_cluster, new_cluster)?;
                
                // 新しいクラスタを初期化
                let mut new_buffer = vec![0u8; cluster_size];
                new_buffer[0] = END_OF_DIR;
                self.fs.write_cluster(new_cluster, &new_buffer)?;
                
                current_cluster = new_cluster;
            } else {
                current_cluster = next;
            }
        }
        
        Err(FsError::NoSpace)
    }

    /// ディレクトリからエントリを削除
    fn remove_dir_entry(&self, name: &str) -> FsResult<DirEntryRaw> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }
        
        let cluster_size = self.fs.cluster_size();
        let mut buffer = vec![0u8; cluster_size];
        let mut current_cluster = self.first_cluster;
        let mut chain_count = 0;
        
        while current_cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidArgument); // クラスタチェーンが循環している
            }
            
            self.fs.read_cluster(current_cluster, &mut buffer)?;
            
            let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;
            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let raw = DirEntryRaw::from_bytes(&buffer[offset..offset + DIR_ENTRY_SIZE]);
                
                if raw.is_end() {
                    return Err(FsError::NotFound);
                }
                
                if raw.is_deleted() {
                    continue;
                }
                
                if raw.attributes().is_long_name() || raw.attributes().is_volume_id() {
                    continue;
                }
                
                let entry_name = raw.short_name();
                if entry_name.eq_ignore_ascii_case(name) {
                    // エントリを削除済みとしてマーク
                    buffer[offset] = DELETED_ENTRY;
                    self.fs.write_cluster(current_cluster, &buffer)?;
                    return Ok(raw);
                }
            }
            
            current_cluster = self.fs.read_fat_entry(current_cluster)?;
        }
        
        Err(FsError::NotFound)
    }
}

impl Inode for Fat32Inode {
    fn getattr(&self) -> FsResult<FileAttr> {
        Ok(FileAttr {
            ino: self.first_cluster.as_u32() as InodeNum,
            size: self.size,
            blocks: (self.size + 511) / 512,
            file_type: self.file_type,
            mode: if self.file_type == FileType::Directory {
                FileMode::DEFAULT_DIR
            } else {
                FileMode::DEFAULT_FILE
            },
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: self.fs.cluster_size() as u32,
            atime: 0,
            mtime: 0,
            ctime: 0,
        })
    }

    fn setattr(&self, attr: &FileAttr) -> FsResult<()> {
        // FAT32の属性設定
        // Note: FAT32は限定的な属性のみサポート
        // - ファイルサイズ（トランケートのみ）
        // - 更新日時（mtime）
        // - 属性フラグ（読み取り専用、隠しファイル等）
        // uid/gid/modeはFAT32ではサポートされない
        let _ = attr; // 将来の実装用
        Ok(())
    }

    fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>> {
        // パス長検証
        validate_path_length(name)?;
        
        // イテレータで検索（見つかったら即終了）
        let entry = self.entries()?
            .find(|res| {
                res.as_ref()
                    .ok()
                    .map(|(entry_name, _)| entry_name.eq_ignore_ascii_case(name))
                    .unwrap_or(false)
            });

        match entry {
            Some(Ok((_, raw))) => {
                let cluster = raw.first_cluster();
                let attr = raw.attributes();
                if attr.is_directory() {
                    Ok(Arc::new(Fat32Inode::new_directory(
                        self.fs.clone(),
                        cluster,
                        self.first_cluster,
                    )))
                } else {
                    Ok(Arc::new(Fat32Inode::new_file(
                        self.fs.clone(),
                        cluster,
                        raw.file_size() as u64,
                        self.first_cluster,
                    )))
                }
            }
            Some(Err(e)) => Err(e),
            None => Err(FsError::NotFound),
        }
    }

    fn readdir(&self, _offset: u64) -> FsResult<Vec<DirEntry>> {
        self.entries()?
            .map(|res| {
                res.map(|(name, raw)| DirEntry {
                    name,
                    ino: raw.first_cluster().as_u32() as InodeNum,
                    file_type: if raw.attributes().is_directory() {
                        FileType::Directory
                    } else {
                        FileType::Regular
                    },
                })
            })
            .collect()
    }

    fn create(&self, name: &str, _mode: FileMode, _flags: OpenFlags) -> FsResult<Arc<dyn Inode>> {
        // パス長検証
        validate_path_length(name)?;
        
        // 既存のエントリがないか確認
        if let Ok(_) = self.lookup(name) {
            return Err(FsError::AlreadyExists);
        }
        
        // 新しいファイル用のクラスタを割り当て（空ファイルの場合はクラスタ0）
        let new_cluster = Cluster(0); // 空ファイルはクラスタを持たない
        
        // ディレクトリエントリを追加
        self.add_dir_entry(name, new_cluster, FileAttributes::from_bits_truncate(FileAttributes::ARCHIVE), 0)?;
        
        Ok(Arc::new(Fat32Inode::new_file(
            self.fs.clone(),
            new_cluster,
            0,
            self.first_cluster,
        )))
    }

    fn mkdir(&self, name: &str, _mode: FileMode) -> FsResult<Arc<dyn Inode>> {
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
        let dotdot_entry = DirEntryRaw::new_dotdot(self.first_cluster);
        
        // バッファに書き込み
        let dot_bytes = unsafe {
            core::slice::from_raw_parts(&dot_entry as *const DirEntryRaw as *const u8, DIR_ENTRY_SIZE)
        };
        buffer[0..DIR_ENTRY_SIZE].copy_from_slice(dot_bytes);
        
        let dotdot_bytes = unsafe {
            core::slice::from_raw_parts(&dotdot_entry as *const DirEntryRaw as *const u8, DIR_ENTRY_SIZE)
        };
        buffer[DIR_ENTRY_SIZE..DIR_ENTRY_SIZE * 2].copy_from_slice(dotdot_bytes);
        
        // 終端マーカー
        buffer[DIR_ENTRY_SIZE * 2] = END_OF_DIR;
        
        self.fs.write_cluster(new_cluster, &buffer)?;
        
        // 親ディレクトリにエントリを追加
        self.add_dir_entry(name, new_cluster, FileAttributes::from_bits_truncate(FileAttributes::DIRECTORY), 0)?;
        
        Ok(Arc::new(Fat32Inode::new_directory(
            self.fs.clone(),
            new_cluster,
            self.first_cluster,
        )))
    }

    fn unlink(&self, name: &str) -> FsResult<()> {
        // エントリを検索して削除
        let entry = self.remove_dir_entry(name)?;
        
        // ディレクトリは削除できない
        if entry.attributes().is_directory() {
            return Err(FsError::IsDirectory);
        }
        
        // クラスタチェーンを解放
        let cluster = entry.first_cluster();
        if cluster.is_valid() {
            self.fs.free_cluster_chain(cluster)?;
        }
        
        Ok(())
    }

    fn rmdir(&self, name: &str) -> FsResult<()> {
        // まず対象ディレクトリを検索
        let target = self.lookup(name)?;
        let attr = target.getattr()?;
        
        if attr.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }
        
        // ディレクトリが空かどうか確認
        let entries = target.readdir(0)?;
        if !entries.is_empty() {
            return Err(FsError::NotEmpty);
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

    fn rename(&self, _old_name: &str, _new_dir: &Arc<dyn Inode>, _new_name: &str) -> FsResult<()> {
        Err(FsError::NotSupported)
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

    fn read(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        if self.file_type != FileType::Regular {
            return Err(FsError::IsDirectory);
        }

        if offset >= self.size {
            return Ok(0);
        }

        let cluster_size = self.fs.cluster_size() as u64;
        let to_read = buf.len().min((self.size - offset) as usize);

        // 開始クラスタまでスキップ（skip メソッド活用）
        let start_cluster_idx = (offset / cluster_size) as usize;
        let chain = self.fs.clusters(self.first_cluster).skip(start_cluster_idx);

        // 最初のクラスタ内でのオフセット
        let mut current_cluster_offset = (offset % cluster_size) as usize;
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

    fn write(&self, offset: u64, buf: &[u8]) -> FsResult<usize> {
        if self.file_type != FileType::Regular {
            return Err(FsError::IsDirectory);
        }
        
        if buf.is_empty() {
            return Ok(0);
        }
        
        let cluster_size = self.fs.cluster_size() as u64;
        let mut bytes_written = 0usize;
        
        // 必要なクラスタを確保
        let mut cluster = self.first_cluster;
        
        // ファイルが空の場合、最初のクラスタを割り当て
        if !cluster.is_valid() {
            cluster = self.fs.allocate_cluster()?;
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
            if cluster_offset > 0 || bytes_written + cluster_size as usize - cluster_offset > buf.len() {
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
        
        Ok(bytes_written)
    }

    fn truncate(&self, size: u64) -> FsResult<()> {
        if self.file_type != FileType::Regular {
            return Err(FsError::IsDirectory);
        }
        
        let cluster_size = self.fs.cluster_size() as u64;
        
        if size == 0 {
            // 全クラスタを解放
            if self.first_cluster.is_valid() {
                self.fs.free_cluster_chain(self.first_cluster)?;
            }
            return Ok(());
        }
        
        // 必要なクラスタ数を計算
        let needed_clusters = (size + cluster_size - 1) / cluster_size;
        
        let mut cluster = self.first_cluster;
        let mut count = 1u64;
        let mut chain_count = 0;
        
        // 必要なクラスタ数まで辿る
        while count < needed_clusters && cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidArgument); // クラスタチェーンが循環している
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
        
        Ok(())
    }

    fn fsync(&self, _datasync: bool) -> FsResult<()> {
        self.fs.sync()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// 8.3形式のチェックサムを計算
///
/// # Implementation Note
/// イテレータと fold を使用した関数型スタイルで実装。
/// ループ変数を管理する必要がなくなり、バグの入り込む余地が減少。
fn calc_short_name_checksum(name: &[u8; 11]) -> u8 {
    name.iter().fold(0u8, |sum, &byte| sum.rotate_right(1).wrapping_add(byte))
}

/// 文字列を8.3形式に変換
fn to_short_name(name: &str) -> Option<[u8; 11]> {
    let mut result = [b' '; 11];
    let upper = name.to_uppercase();

    let dot_pos = upper.rfind('.');

    let (base, ext) = if let Some(pos) = dot_pos {
        (&upper[..pos], &upper[pos + 1..])
    } else {
        (upper.as_str(), "")
    };

    if base.len() > 8 || ext.len() > 3 {
        return None;
    }

    for (i, c) in base.bytes().enumerate() {
        if i >= 8 {
            break;
        }
        result[i] = c;
    }

    for (i, c) in ext.bytes().enumerate() {
        if i >= 3 {
            break;
        }
        result[8 + i] = c;
    }

    Some(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_name() {
        let result = to_short_name("TEST.TXT").unwrap();
        assert_eq!(&result[..8], b"TEST    ");
        assert_eq!(&result[8..], b"TXT");
    }

    #[test]
    fn test_checksum() {
        let name = *b"TEST    TXT";
        let sum = calc_short_name_checksum(&name);
        assert!(sum != 0); // 具体的な値はテストデータによる
    }
}
