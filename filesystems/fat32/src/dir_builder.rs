use crate::time::{get_current_dos_date, get_current_dos_time};
use crate::*;

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

    /// Set timestamps using a provided `TimeProvider` (e.g., RTC hook)
    pub fn with_time_provider(self, provider: &dyn TimeProvider) -> Self {
        let dos_time = provider.current_dos_time();
        let dos_date = provider.current_dos_date();
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
