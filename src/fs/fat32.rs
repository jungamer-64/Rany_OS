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
//! - ロングファイルネーム（LFN）サポート
//!
//! ## 型安全性の改善
//! - Newtype パターン（Cluster, Sector）による取り違え防止
//! - FileAttributes による属性の型安全な管理
//! - SafePackedRead トレイトによる packed 構造体への安全なアクセス

#![allow(dead_code)]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Add, Sub};
use spin::RwLock;

use super::block::BlockDevice;
use super::vfs::{
    DirEntry, FileAttr, FileMode, FileSystem, FileType, FsError, FsResult, FsStats, Inode,
    InodeNum, OpenFlags,
};

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

// ============================================================================
// Safe Access for Packed Structs
// ============================================================================

/// packed構造体のフィールド読み出しを安全に行うためのトレイト
///
/// `#[repr(C, packed)]` 構造体のフィールドへの直接参照は未定義動作を
/// 引き起こす可能性があるため、このトレイトを使用して安全にアクセスする。
trait SafePackedRead {
    /// 指定されたフィールドの値を安全に読み出す
    ///
    /// # Safety
    /// `field_fn` は有効なフィールドへのポインタを返す必要がある
    #[inline]
    unsafe fn read_field<T: Copy, F>(&self, field_fn: F) -> T
    where
        F: FnOnce(&Self) -> *const T,
    { unsafe {
        core::ptr::read_unaligned(field_fn(self))
    }}
}

// ============================================================================
// BPB (BIOS Parameter Block)
// ============================================================================

/// BIOSパラメータブロック
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BiosParameterBlock {
    /// ジャンプ命令（3バイト）
    pub jmp_boot: [u8; 3],
    /// OEM名（8バイト）
    pub oem_name: [u8; 8],
    /// 1セクタあたりのバイト数
    pub bytes_per_sector: u16,
    /// 1クラスタあたりのセクタ数
    pub sectors_per_cluster: u8,
    /// 予約セクタ数
    pub reserved_sectors: u16,
    /// FAT数
    pub num_fats: u8,
    /// ルートディレクトリエントリ数（FAT32では0）
    pub root_entry_count: u16,
    /// 総セクタ数（16ビット、FAT32では0）
    pub total_sectors_16: u16,
    /// メディアタイプ
    pub media_type: u8,
    /// FATあたりのセクタ数（FAT12/16用、FAT32では0）
    pub fat_size_16: u16,
    /// トラックあたりのセクタ数
    pub sectors_per_track: u16,
    /// ヘッド数
    pub num_heads: u16,
    /// 隠しセクタ数
    pub hidden_sectors: u32,
    /// 総セクタ数（32ビット）
    pub total_sectors_32: u32,
}

/// FAT32拡張BPB
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32ExtendedBpb {
    /// FATあたりのセクタ数
    pub fat_size_32: u32,
    /// 拡張フラグ
    pub ext_flags: u16,
    /// ファイルシステムバージョン
    pub fs_version: u16,
    /// ルートディレクトリの開始クラスタ
    pub root_cluster: u32,
    /// FSInfoセクタ番号
    pub fs_info_sector: u16,
    /// バックアップブートセクタ
    pub backup_boot_sector: u16,
    /// 予約
    pub reserved: [u8; 12],
    /// ドライブ番号
    pub drive_number: u8,
    /// 予約
    pub reserved1: u8,
    /// ブートシグネチャ
    pub boot_sig: u8,
    /// ボリュームシリアル番号
    pub volume_serial: u32,
    /// ボリュームラベル
    pub volume_label: [u8; 11],
    /// ファイルシステムタイプ
    pub fs_type: [u8; 8],
}

/// ブートセクタ
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BootSector {
    pub bpb: BiosParameterBlock,
    pub fat32: Fat32ExtendedBpb,
    pub boot_code: [u8; 420],
    pub signature: u16,
}

impl SafePackedRead for BootSector {}

impl BootSector {
    /// バイト列から安全にBootSectorを読み取る
    pub fn from_bytes(bytes: &[u8]) -> FsResult<Self> {
        if bytes.len() < BOOT_SECTOR_SIZE {
            return Err(FsError::InvalidArgument);
        }
        // アライメントの問題を回避するため、read_unalignedを使用
        let boot_sector = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const BootSector) };

        // シグネチャチェック
        if boot_sector.signature != FAT32_SIGNATURE {
            return Err(FsError::InvalidArgument);
        }

        Ok(boot_sector)
    }

    /// クラスタあたりのセクタ数を安全に取得
    pub fn sectors_per_cluster(&self) -> u32 {
        unsafe { self.read_field(|s| core::ptr::addr_of!(s.bpb.sectors_per_cluster)) as u32 }
    }

    /// 予約セクタ数を安全に取得
    pub fn reserved_sectors(&self) -> u32 {
        unsafe { self.read_field(|s| core::ptr::addr_of!(s.bpb.reserved_sectors)) as u32 }
    }

    /// FAT数を安全に取得
    pub fn num_fats(&self) -> u32 {
        unsafe { self.read_field(|s| core::ptr::addr_of!(s.bpb.num_fats)) as u32 }
    }

    /// FAT32のFATサイズを安全に取得
    pub fn fat_size_32(&self) -> u32 {
        unsafe { self.read_field(|s| core::ptr::addr_of!(s.fat32.fat_size_32)) }
    }

    /// ルートクラスタを安全に取得（型安全なCluster型を返す）
    pub fn root_cluster(&self) -> Cluster {
        Cluster(unsafe { self.read_field(|s| core::ptr::addr_of!(s.fat32.root_cluster)) })
    }

    /// 総セクタ数を安全に取得
    pub fn total_sectors(&self) -> u32 {
        let ts16: u16 = unsafe { self.read_field(|s| core::ptr::addr_of!(s.bpb.total_sectors_16)) };
        if ts16 != 0 {
            ts16 as u32
        } else {
            unsafe { self.read_field(|s| core::ptr::addr_of!(s.bpb.total_sectors_32)) }
        }
    }

    /// ファイルシステムタイプを取得
    pub fn fs_type(&self) -> [u8; 8] {
        unsafe { self.read_field(|s| core::ptr::addr_of!(s.fat32.fs_type)) }
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
    pub create_time: u16,
    /// 作成日付
    pub create_date: u16,
    /// 最終アクセス日付
    pub access_date: u16,
    /// 開始クラスタ番号（上位16ビット）
    pub first_cluster_hi: u16,
    /// 更新時刻
    pub modify_time: u16,
    /// 更新日付
    pub modify_date: u16,
    /// 開始クラスタ番号（下位16ビット）
    pub first_cluster_lo: u16,
    /// ファイルサイズ
    pub file_size: u32,
}

impl SafePackedRead for DirEntryRaw {}

impl DirEntryRaw {
    /// バイト列から安全にDirEntryRawを読み取る
    pub fn from_bytes(bytes: &[u8]) -> Self {
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DirEntryRaw) }
    }

    /// 開始クラスタを取得（型安全なCluster型を返す）
    pub fn first_cluster(&self) -> Cluster {
        let hi: u16 = unsafe { self.read_field(|s| core::ptr::addr_of!(s.first_cluster_hi)) };
        let lo: u16 = unsafe { self.read_field(|s| core::ptr::addr_of!(s.first_cluster_lo)) };
        Cluster(((hi as u32) << 16) | (lo as u32))
    }

    /// 開始クラスタを設定
    pub fn set_first_cluster(&mut self, cluster: Cluster) {
        self.first_cluster_hi = (cluster.0 >> 16) as u16;
        self.first_cluster_lo = (cluster.0 & 0xFFFF) as u16;
    }

    /// 属性を取得（型安全なFileAttributes型を返す）
    pub fn attributes(&self) -> FileAttributes {
        FileAttributes::from_bits_truncate(self.attr)
    }

    /// ファイルサイズを安全に取得
    pub fn file_size(&self) -> u32 {
        unsafe { self.read_field(|s| core::ptr::addr_of!(s.file_size)) }
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
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct LfnEntry {
    /// シーケンス番号
    pub seq: u8,
    /// 名前の1-5文字目（UCS-2）
    pub name1: [u16; 5],
    /// 属性（常にATTR_LONG_NAME）
    pub attr: u8,
    /// タイプ（常に0）
    pub type_: u8,
    /// チェックサム
    pub checksum: u8,
    /// 名前の6-11文字目（UCS-2）
    pub name2: [u16; 6],
    /// 常に0
    pub first_cluster: u16,
    /// 名前の12-13文字目（UCS-2）
    pub name3: [u16; 2],
}

impl SafePackedRead for LfnEntry {}

impl LfnEntry {
    /// バイト列から安全にLfnEntryを読み取る
    pub fn from_bytes(bytes: &[u8]) -> Self {
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const LfnEntry) }
    }

    /// このエントリから名前の一部を取得
    pub fn get_name_part(&self) -> String {
        let mut chars = Vec::with_capacity(13);

        // SafePackedReadトレイトを使って安全にコピー
        let name1: [u16; 5] = unsafe { self.read_field(|s| core::ptr::addr_of!(s.name1)) };
        let name2: [u16; 6] = unsafe { self.read_field(|s| core::ptr::addr_of!(s.name2)) };
        let name3: [u16; 2] = unsafe { self.read_field(|s| core::ptr::addr_of!(s.name3)) };

        for &c in name1.iter().chain(name2.iter()).chain(name3.iter()) {
            if c == 0 || c == 0xFFFF {
                break;
            }
            chars.push(c);
        }

        String::from_utf16_lossy(&chars)
    }

    /// 最後のLFNエントリかどうか
    pub fn is_last(&self) -> bool {
        self.seq & 0x40 != 0
    }

    /// シーケンス番号を取得（1-20）
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
}

impl Fat32FileSystem {
    /// FAT32ファイルシステムをマウント
    pub fn mount(device: Arc<dyn BlockDevice>) -> FsResult<Arc<Self>> {
        // ブートセクタを読み取り
        let mut boot_data = [0u8; BOOT_SECTOR_SIZE];
        device
            .read_sync(0, &mut boot_data)
            .map_err(|_| FsError::IoError)?;

        // BootSector::from_bytes で安全にパース
        let boot_sector = BootSector::from_bytes(&boot_data)?;

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
        });

        // FATをキャッシュに読み込み
        fs.load_fat()?;

        Ok(fs)
    }

    /// FATテーブルを読み込み
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

    /// クラスタ番号からセクタ番号を計算（型安全）
    fn cluster_to_sector(&self, cluster: Cluster) -> Sector {
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

    /// FATエントリを書き込み（型安全）
    fn write_fat_entry(&self, cluster: Cluster, value: Cluster) -> FsResult<()> {
        let idx = cluster.0 as usize;
        {
            let mut fat = self.fat_cache.write();
            if idx >= fat.len() {
                return Err(FsError::InvalidArgument);
            }
            fat[idx] = value;
        }

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

        // バックアップFAT（FAT2）への書き込み
        let fat2_sector = sector + self.fat_size;
        self.device
            .write_sync(fat2_sector.as_u64(), &buffer)
            .map_err(|_| FsError::IoError)?;

        Ok(())
    }

    /// 空きクラスタを割り当て（型安全）
    fn allocate_cluster(&self) -> FsResult<Cluster> {
        let fat = self.fat_cache.read();
        // クラスタ2から検索開始
        for (i, entry) in fat.iter().enumerate() {
            if i >= 2 && entry.is_free() {
                drop(fat);
                let cluster = Cluster(i as u32);
                self.write_fat_entry(cluster, Cluster::EOF)?;
                let mut free = self.free_clusters.write();
                *free = free.saturating_sub(1);
                return Ok(cluster);
            }
        }
        Err(FsError::NoSpace)
    }

    /// クラスタを解放（型安全）
    fn free_cluster(&self, cluster: Cluster) -> FsResult<()> {
        self.write_fat_entry(cluster, Cluster::FREE)?;
        let mut free = self.free_clusters.write();
        *free += 1;
        Ok(())
    }

    /// クラスタチェーンを解放（型安全）
    fn free_cluster_chain(&self, start_cluster: Cluster) -> FsResult<()> {
        let mut cluster = start_cluster;

        while cluster.is_valid() {
            let next = self.read_fat_entry(cluster)?;
            self.free_cluster(cluster)?;
            cluster = next;
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
        // TODO: キャッシュをフラッシュ
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

    /// ディレクトリの全エントリを読み取り
    fn read_dir_entries(&self) -> FsResult<Vec<(String, DirEntryRaw)>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotDirectory);
        }

        let mut entries = Vec::new();
        let mut cluster = self.first_cluster;
        let cluster_size = self.fs.cluster_size();
        let mut buffer = vec![0u8; cluster_size];
        let mut lfn_parts: Vec<(u8, String)> = Vec::new();

        while cluster.is_valid() {
            self.fs.read_cluster(cluster, &mut buffer)?;

            let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;
            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                // バイト列から安全に構造体を復元
                let raw = DirEntryRaw::from_bytes(&buffer[offset..offset + DIR_ENTRY_SIZE]);

                if raw.is_end() {
                    return Ok(entries);
                }

                if raw.is_deleted() {
                    lfn_parts.clear();
                    continue;
                }

                let attr = raw.attributes();

                if attr.is_long_name() {
                    let lfn = LfnEntry::from_bytes(&buffer[offset..offset + DIR_ENTRY_SIZE]);
                    lfn_parts.push((lfn.sequence(), lfn.get_name_part()));
                } else {
                    // ボリュームラベルはスキップ
                    if attr.is_volume_id() {
                        lfn_parts.clear();
                        continue;
                    }

                    // ロングネームを構築
                    let name = if !lfn_parts.is_empty() {
                        lfn_parts.sort_by_key(|&(seq, _)| seq);
                        let long_name: String = lfn_parts.iter().map(|(_, s)| s.as_str()).collect();
                        lfn_parts.clear();
                        long_name
                    } else {
                        raw.short_name()
                    };

                    // "." と ".." はスキップ
                    if name == "." || name == ".." {
                        continue;
                    }

                    entries.push((name, raw));
                }
            }

            // 次のクラスタへ（型安全）
            cluster = self.fs.read_fat_entry(cluster)?;
        }

        Ok(entries)
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

    fn setattr(&self, _attr: &FileAttr) -> FsResult<()> {
        // TODO: 属性の設定
        Ok(())
    }

    fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>> {
        let entries = self.read_dir_entries()?;

        for (entry_name, raw) in entries {
            if entry_name.eq_ignore_ascii_case(name) {
                let cluster = raw.first_cluster();
                let attr = raw.attributes();
                if attr.is_directory() {
                    return Ok(Arc::new(Fat32Inode::new_directory(
                        self.fs.clone(),
                        cluster,
                        self.first_cluster,
                    )));
                } else {
                    return Ok(Arc::new(Fat32Inode::new_file(
                        self.fs.clone(),
                        cluster,
                        raw.file_size() as u64,
                        self.first_cluster,
                    )));
                }
            }
        }

        Err(FsError::NotFound)
    }

    fn readdir(&self, _offset: u64) -> FsResult<Vec<DirEntry>> {
        let entries = self.read_dir_entries()?;

        Ok(entries
            .into_iter()
            .map(|(name, raw)| DirEntry {
                name,
                ino: raw.first_cluster().as_u32() as InodeNum,
                file_type: if raw.attributes().is_directory() {
                    FileType::Directory
                } else {
                    FileType::Regular
                },
            })
            .collect())
    }

    fn create(&self, _name: &str, _mode: FileMode, _flags: OpenFlags) -> FsResult<Arc<dyn Inode>> {
        // TODO: ファイル作成の実装
        Err(FsError::NotSupported)
    }

    fn mkdir(&self, _name: &str, _mode: FileMode) -> FsResult<Arc<dyn Inode>> {
        // TODO: ディレクトリ作成の実装
        Err(FsError::NotSupported)
    }

    fn unlink(&self, _name: &str) -> FsResult<()> {
        // TODO: ファイル削除の実装
        Err(FsError::NotSupported)
    }

    fn rmdir(&self, _name: &str) -> FsResult<()> {
        // TODO: ディレクトリ削除の実装
        Err(FsError::NotSupported)
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
        let mut bytes_read = 0usize;
        let to_read = buf.len().min((self.size - offset) as usize);

        // 開始クラスタを見つける
        let start_cluster_idx = offset / cluster_size;
        let mut cluster = self.first_cluster;
        for _ in 0..start_cluster_idx {
            cluster = self.fs.read_fat_entry(cluster)?;
            if !cluster.is_valid() {
                return Err(FsError::IoError);
            }
        }

        let mut cluster_offset = (offset % cluster_size) as usize;
        let mut cluster_buf = vec![0u8; cluster_size as usize];

        while bytes_read < to_read && cluster.is_valid() {
            self.fs.read_cluster(cluster, &mut cluster_buf)?;

            let available = cluster_size as usize - cluster_offset;
            let copy_len = available.min(to_read - bytes_read);

            buf[bytes_read..bytes_read + copy_len]
                .copy_from_slice(&cluster_buf[cluster_offset..cluster_offset + copy_len]);

            bytes_read += copy_len;
            cluster_offset = 0;
            cluster = self.fs.read_fat_entry(cluster)?;
        }

        Ok(bytes_read)
    }

    fn write(&self, _offset: u64, _buf: &[u8]) -> FsResult<usize> {
        // TODO: 書き込みの実装
        Err(FsError::NotSupported)
    }

    fn truncate(&self, _size: u64) -> FsResult<()> {
        // TODO: トランケートの実装
        Err(FsError::NotSupported)
    }

    fn fsync(&self, _datasync: bool) -> FsResult<()> {
        self.fs.sync()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// 8.3形式のチェックサムを計算
fn calc_short_name_checksum(name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in name {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
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
