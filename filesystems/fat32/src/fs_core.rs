use crate::{
    Arc, Cluster, ClusterChain, DirEntryRaw, DirectoryIterator, Fat32FileSystem, FsResult, String,
    TimeProvider, Vec, ZeroCopyBufferMut,
};

impl<B: ZeroCopyBufferMut + 'static> Fat32FileSystem<B> {
    /// 指定されたクラスタから始まるクラスタチェーンのイテレータを返す
    ///
    /// # Arguments
    /// * `start` - チェーンの開始クラスタ
    ///
    /// # Returns
    /// クラスタ番号を順に返すイテレータ。各要素は`FsResult<Cluster>`。
    pub fn clusters(&self, start: Cluster) -> ClusterChain<'_, B> {
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
    pub fn read_dir_cached(
        &self,
        start_cluster: Cluster,
    ) -> FsResult<Arc<[(String, DirEntryRaw)]>> {
        // キャッシュをチェック
        if let Some(entries) = self.dir_cache.get(start_cluster) {
            return Ok(entries);
        }

        // キャッシュミス: イテレータで全エントリを読み取り
        let iter = DirectoryIterator::new(self, start_cluster)?;
        let entries: Vec<(String, DirEntryRaw)> = iter.collect::<Result<Vec<_>, _>>()?;

        // キャッシュに保存（insertがArcを返す）
        let entries_arc = self.dir_cache.insert(start_cluster, entries);

        Ok(entries_arc)
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
    /// let fs = DefaultFat32FileSystem::mount(device)?;
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

    /// Total sectors in the filesystem (derived from total_clusters and sectors_per_cluster)
    pub fn total_sectors(&self) -> u32 {
        self.total_clusters * self.sectors_per_cluster
    }
}
