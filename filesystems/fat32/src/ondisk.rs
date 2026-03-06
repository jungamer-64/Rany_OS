use crate::{
    BOOT_SECTOR_SIZE, Cluster, DELETED_ENTRY, DIR_ENTRY_SIZE, END_OF_DIR, FAT32_SIGNATURE,
    FileAttributes, FsError, FsResult,
};

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

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
        // Safe field-by-field copy
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
        // Safe field-by-field copy
        let mut entry = LfnEntry {
            seq: 0,
            name1: [0u8; 10],
            attr: 0,
            type_: 0,
            checksum: 0,
            name2: [0u8; 12],
            first_cluster: [0u8; 2],
            name3: [0u8; 4],
        };
        entry.seq = bytes[0];
        entry.name1.copy_from_slice(&bytes[1..11]);
        entry.attr = bytes[11];
        entry.type_ = bytes[12];
        entry.checksum = bytes[13];
        entry.name2.copy_from_slice(&bytes[14..26]);
        entry.first_cluster.copy_from_slice(&bytes[26..28]);
        entry.name3.copy_from_slice(&bytes[28..32]);
        entry
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
pub(crate) const FSINFO_UNKNOWN: u32 = 0xFFFFFFFF;

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
#[derive(Clone, Copy, PartialEq, Eq)]
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
    pub(crate) create_time: [u8; 2],
    /// 作成日付
    pub(crate) create_date: [u8; 2],
    /// 最終アクセス日付
    pub(crate) access_date: [u8; 2],
    /// 開始クラスタ番号（上位16ビット）
    pub(crate) first_cluster_hi: [u8; 2],
    /// 更新時刻
    pub(crate) modify_time: [u8; 2],
    /// 更新日付
    pub(crate) modify_date: [u8; 2],
    /// 開始クラスタ番号（下位16ビット）
    pub(crate) first_cluster_lo: [u8; 2],
    /// ファイルサイズ
    pub(crate) file_size: [u8; 4],
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
