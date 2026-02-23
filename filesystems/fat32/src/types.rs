use crate::*;

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
