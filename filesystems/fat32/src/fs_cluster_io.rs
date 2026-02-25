use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{
    Cluster,
    Sector,
    FsResult,
    FsError,
    BLOCK_SIZE,
    FAT_ENTRIES_PER_SECTOR,
    try_alloc_vec,
    Fat32FileSystem,
    ZeroCopyBufferMut,
    FsInfo,
    FSINFO_UNKNOWN,
    IrqPoisonLock,
    MAX_CLUSTER_CHAIN,
};

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

impl<B: ZeroCopyBufferMut + 'static> Fat32FileSystem<B> {
    /// クラスタ番号からセクタ番号を計算(型安全)
    ///
    /// # Panics
    /// クラスタ番号が無効な場合(<2)はパニックする
    pub(crate) fn cluster_to_sector(&self, cluster: Cluster) -> FsResult<Sector> {
        if cluster.0 < 2 {
            return Err(FsError::InvalidInput);
        }
        // クラスタ2がデータ領域の先頭
        Ok(self.data_start_sector + (cluster.0 - 2) * self.sectors_per_cluster)
    }

    /// FATセクタバッファをClusterベクタにデコードする
    pub(crate) fn decode_fat_sector_to_clusters(buffer: &[u8]) -> FsResult<Vec<Cluster>> {
        let mut sector_data = try_alloc_vec(FAT_ENTRIES_PER_SECTOR, Cluster::FREE)?;
        for i in 0..FAT_ENTRIES_PER_SECTOR {
            let off = i * 4;
            let val = u32::from_le_bytes([
                buffer[off],
                buffer[off + 1],
                buffer[off + 2],
                buffer[off + 3],
            ]) & 0x0FFFFFFF;
            sector_data[i] = Cluster(val);
        }
        Ok(sector_data)
    }

    /// FATエントリを読み取り（型安全）
    pub(crate) fn read_fat_entry(&self, cluster: Cluster) -> FsResult<Cluster> {
        trace_fat_operation!("read", cluster);
        let idx = cluster.0 as usize;
        let entries = (self.fat_size as usize) * (BLOCK_SIZE / 4);
        if idx >= entries {
            return Err(FsError::InvalidInput);
        }

        let fat_offset = idx * 4;
        let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
        let offset_in_sector = (fat_offset % BLOCK_SIZE) / 4;

        if let Some(sector_arc) = self.fat_sector_cache.get(sector_offset) {
            let sector_guard = sector_arc.lock();
            return Ok(sector_guard[offset_in_sector]);
        }

        let sector = self.fat_start_sector + sector_offset;
        let mut buffer = [0u8; BLOCK_SIZE];
        self.read_sector_cached(sector.as_u64(), &mut buffer)?;

        let sector_data = Self::decode_fat_sector_to_clusters(&buffer)?;
        let result = sector_data[offset_in_sector];

        if let Some((evicted_idx, evicted_data, was_dirty)) =
            self.fat_sector_cache.insert(sector_offset, sector_data)
        {
            if was_dirty {
                self.flush_fat_sector(evicted_idx, &evicted_data)?;
            }
        }

        Ok(result)
    }

    /// 非同期でFATエントリを読み取り
    pub(crate) async fn read_fat_entry_async(&self, cluster: Cluster) -> FsResult<Cluster> {
        trace_fat_operation!("read_async", cluster);
        let idx = cluster.0 as usize;
        let entries = (self.fat_size as usize) * (BLOCK_SIZE / 4);
        if idx >= entries {
            return Err(FsError::InvalidInput);
        }

        let fat_offset = idx * 4;
        let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
        let offset_in_sector = (fat_offset % BLOCK_SIZE) / 4;

        if let Some(sector_arc) = self.fat_sector_cache.get(sector_offset) {
            let sector_guard = sector_arc.lock();
            return Ok(sector_guard[offset_in_sector]);
        }

        let sector = self.fat_start_sector + sector_offset;
        let mut buffer = [0u8; BLOCK_SIZE];
        self.read_sector_cached_async(sector.as_u64(), &mut buffer)
            .await?;

        let sector_data = Self::decode_fat_sector_to_clusters(&buffer)?;
        let result = sector_data[offset_in_sector];

        if let Some((evicted_idx, evicted_data, was_dirty)) =
            self.fat_sector_cache.insert(sector_offset, sector_data)
        {
            if was_dirty {
                self.flush_fat_sector_async(evicted_idx, &evicted_data)
                    .await?;
            }
        }

        Ok(result)
    }

    /// FATエントリを書き込み(型安全、遅延書き込み対応)
    ///
    /// キャッシュへの書き込みと、該当セクタへのダーティマーク付けを行う。
    /// 実際のディスク書き込みは`sync()`で行われる。
    pub fn sync(&self) -> FsResult<()> {
        let dirty_sectors = self.fat_sector_cache.take_dirty_sectors();
        for (sector_idx, sector_data_arc) in dirty_sectors {
            self.flush_fat_sector(sector_idx, &sector_data_arc)?;
        }

        // FSInfoセクタを更新
        self.write_fsinfo()?;

        let device = self.legacy_device.as_ref().ok_or(FsError::NotSupported)?;
        device.flush().map_err(Into::into)
    }

    /// 非同期でファイルシステムを同期
    pub async fn sync_async(&self) -> FsResult<()> {
        let dirty_sectors = self.fat_sector_cache.take_dirty_sectors();
        for (sector_idx, sector_data_arc) in dirty_sectors {
            if let Err(e) = self
                .flush_fat_sector_async(sector_idx, &sector_data_arc)
                .await
            {
                self.fat_sector_cache.mark_dirty(sector_idx);
                return Err(e);
            }
        }

        self.write_fsinfo_async().await?;

        self.zc_device.flush().map_err(Into::into)
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

    /// 非同期でFSInfoセクタを読み取る
    pub async fn read_fsinfo_async(&self) -> FsResult<FsInfo> {
        if self.fs_info_sector.0 == 0 {
            return Err(FsError::NotSupported);
        }

        let mut buffer = [0u8; BLOCK_SIZE];
        self.read_sector_cached_async(self.fs_info_sector.as_u64(), &mut buffer)
            .await?;
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
        fsinfo.set_free_count(*self.free_clusters.blocking_lock());

        // セクタに書き込み
        let buffer = fsinfo.to_bytes();
        self.write_sector_cached(self.fs_info_sector.as_u64(), &buffer)?;

        Ok(())
    }

    /// 非同期でFSInfoセクタを書き込む
    pub async fn write_fsinfo_async(&self) -> FsResult<()> {
        if self.fs_info_sector.0 == 0 {
            return Ok(());
        }

        let mut fsinfo = match self.read_fsinfo_async().await {
            Ok(info) => info,
            Err(_) => FsInfo::new(FSINFO_UNKNOWN, FSINFO_UNKNOWN),
        };

        let free_count = *self.free_clusters.lock_async().await;
        fsinfo.set_free_count(free_count);

        let buffer = fsinfo.to_bytes();
        self.write_sector_cached_async(self.fs_info_sector.as_u64(), &buffer)
            .await?;

        Ok(())
    }

    /// FATセクタをディスクに書き込む（プライマリFATとバックアップFAT）
    pub(crate) fn flush_fat_sector(
        &self,
        sector_idx: u32,
        sector_data_arc: &Arc<IrqPoisonLock<Box<[Cluster]>>>,
    ) -> FsResult<()> {
        let sector = self.fat_start_sector + sector_idx;

        // Clusterの配列をロックしてバイト配列に変換
        let buffer = {
            let sector_guard = sector_data_arc.lock();
            let mut buf = [0u8; BLOCK_SIZE];
            for (i, cluster) in sector_guard.iter().enumerate().take(FAT_ENTRIES_PER_SECTOR) {
                let bytes = (cluster.0 & 0x0FFFFFFF).to_le_bytes();
                let off = i * 4;
                buf[off..off + 4].copy_from_slice(&bytes);
            }
            buf
        };

        // プライマリFAT
        self.write_sector_cached(sector.as_u64(), &buffer)?;
        // バックアップFAT
        let fat2_sector = sector + self.fat_size;
        self.write_sector_cached(fat2_sector.as_u64(), &buffer)?;

        Ok(())
    }

    /// 非同期でFATセクタをディスクに書き込む（プライマリFATとバックアップFAT）
    pub(crate) async fn flush_fat_sector_async(
        &self,
        sector_idx: u32,
        sector_data_arc: &Arc<IrqPoisonLock<Box<[Cluster]>>>,
    ) -> FsResult<()> {
        let sector = self.fat_start_sector + sector_idx;

        let buffer = {
            let sector_guard = sector_data_arc.lock();
            let mut buf = [0u8; BLOCK_SIZE];
            for (i, cluster) in sector_guard.iter().enumerate().take(FAT_ENTRIES_PER_SECTOR) {
                let bytes = (cluster.0 & 0x0FFFFFFF).to_le_bytes();
                let off = i * 4;
                buf[off..off + 4].copy_from_slice(&bytes);
            }
            buf
        };

        self.write_sector_cached_async(sector.as_u64(), &buffer)
            .await?;
        let fat2_sector = sector + self.fat_size;
        self.write_sector_cached_async(fat2_sector.as_u64(), &buffer)
            .await?;

        Ok(())
    }

    /// FATセクタバッファをパースしてClusterベクタを生成する
    pub(crate) fn parse_fat_sector_buffer(buffer: &[u8]) -> FsResult<alloc::vec::Vec<Cluster>> {
        let mut sector_data = try_alloc_vec(FAT_ENTRIES_PER_SECTOR, Cluster::FREE)?;
        for i in 0..FAT_ENTRIES_PER_SECTOR {
            let off = i * 4;
            let val = u32::from_le_bytes([
                buffer[off],
                buffer[off + 1],
                buffer[off + 2],
                buffer[off + 3],
            ]) & 0x0FFFFFFF;
            sector_data[i] = Cluster(val);
        }
        Ok(sector_data)
    }

    /// FATセクタバッファから1エントリを読み取る
    pub(crate) fn read_fat_entry_from_buffer(buffer: &[u8], offset_in_sector: usize) -> u32 {
        u32::from_le_bytes([
            buffer[offset_in_sector * 4],
            buffer[offset_in_sector * 4 + 1],
            buffer[offset_in_sector * 4 + 2],
            buffer[offset_in_sector * 4 + 3],
        ]) & 0x0FFFFFFF
    }

    /// 空きクラスタ数を調整する（同期版）
    pub(crate) fn adjust_free_clusters_sync(&self, old_val: u32, new_val: u32) {
        if old_val == 0 && new_val != 0 {
            let mut free = self.free_clusters.blocking_lock();
            *free = free.saturating_sub(1);
        } else if old_val != 0 && new_val == 0 {
            let mut free = self.free_clusters.blocking_lock();
            *free = free.saturating_add(1);
        }
    }

    /// 空きクラスタ数を調整する（非同期版）
    pub(crate) async fn adjust_free_clusters_async(&self, old_val: u32, new_val: u32) {
        if old_val == 0 && new_val != 0 {
            let mut free = self.free_clusters.lock_async().await;
            *free = free.saturating_sub(1);
        } else if old_val != 0 && new_val == 0 {
            let mut free = self.free_clusters.lock_async().await;
            *free = free.saturating_add(1);
        }
    }

    pub(crate) fn write_fat_entry(&self, cluster: Cluster, value: Cluster) -> FsResult<()> {
        trace_fat_operation!("write", cluster, "value={}", value.0);
        let idx = cluster.0 as usize;
        let sectors = self.fat_size as usize;
        let entries = sectors * BLOCK_SIZE / 4;
        if idx >= entries {
            return Err(FsError::InvalidInput);
        }

        let fat_offset = idx * 4;
        let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
        let offset_in_sector = (fat_offset % BLOCK_SIZE) / 4;

        if self
            .fat_sector_cache
            .update_entry(sector_offset, offset_in_sector, value)
        {
            return Ok(());
        }

        let sector = self.fat_start_sector + sector_offset;
        let mut buffer = [0u8; BLOCK_SIZE];
        self.read_sector_cached(sector.as_u64(), &mut buffer)?;

        let old_val = Self::read_fat_entry_from_buffer(&buffer, offset_in_sector);
        let mut sector_data = Self::parse_fat_sector_buffer(&buffer)?;

        sector_data[offset_in_sector] = value;

        if let Some((evicted_idx, evicted_data, was_dirty)) =
            self.fat_sector_cache.insert(sector_offset, sector_data)
        {
            if was_dirty {
                self.flush_fat_sector(evicted_idx, &evicted_data)?;
            }
        }

        self.fat_sector_cache.mark_dirty(sector_offset);
        self.adjust_free_clusters_sync(old_val, value.0);

        Ok(())
    }

    /// 非同期でFATエントリを書き込み
    pub(crate) async fn write_fat_entry_async(
        &self,
        cluster: Cluster,
        value: Cluster,
    ) -> FsResult<()> {
        trace_fat_operation!("write_async", cluster, "value={}", value.0);
        let idx = cluster.0 as usize;
        let sectors = self.fat_size as usize;
        let entries = sectors * BLOCK_SIZE / 4;
        if idx >= entries {
            return Err(FsError::InvalidInput);
        }

        let fat_offset = idx * 4;
        let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
        let offset_in_sector = (fat_offset % BLOCK_SIZE) / 4;

        if self
            .fat_sector_cache
            .update_entry(sector_offset, offset_in_sector, value)
        {
            return Ok(());
        }

        let sector = self.fat_start_sector + sector_offset;
        let mut buffer = [0u8; BLOCK_SIZE];
        self.read_sector_cached_async(sector.as_u64(), &mut buffer)
            .await?;

        let old_val = Self::read_fat_entry_from_buffer(&buffer, offset_in_sector);
        let mut sector_data = Self::parse_fat_sector_buffer(&buffer)?;

        sector_data[offset_in_sector] = value;

        if let Some((evicted_idx, evicted_data, was_dirty)) =
            self.fat_sector_cache.insert(sector_offset, sector_data)
        {
            if was_dirty {
                self.flush_fat_sector_async(evicted_idx, &evicted_data)
                    .await?;
            }
        }

        self.fat_sector_cache.mark_dirty(sector_offset);
        self.adjust_free_clusters_async(old_val, value.0).await;

        Ok(())
    }

    /// FATエントリを即座にディスクに書き込む(内部用)
    ///
    /// クリティカルな操作（クラスタ割り当て等）で使用。
    /// 通常の書き込みは`write_fat_entry`を使用し、
    /// バッチでフラッシュすることを推奨。
    pub(crate) fn write_fat_entry_to_disk(&self, cluster: Cluster, value: Cluster) -> FsResult<()> {
        trace_fat_operation!("write_disk", cluster, "value={}", value.0);
        let idx = cluster.0 as usize;
        let fat_offset = idx * 4;
        let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
        let sector = self.fat_start_sector + sector_offset;
        let offset_in_sector = fat_offset % BLOCK_SIZE;

        let mut buffer = [0u8; BLOCK_SIZE];
        self.read_sector_cached(sector.as_u64(), &mut buffer)?;
        let bytes = (value.0 & 0x0FFFFFFF).to_le_bytes();
        buffer[offset_in_sector..offset_in_sector + 4].copy_from_slice(&bytes);

        self.write_sector_cached(sector.as_u64(), &buffer)?;

        // バックアップFAT(FAT2)への書き込み
        let fat2_sector = sector + self.fat_size;
        self.write_sector_cached(fat2_sector.as_u64(), &buffer)?;

        Ok(())
    }

    /// 非同期でFATエントリを即座にディスクに書き込む(内部用)
    pub(crate) async fn write_fat_entry_to_disk_async(
        &self,
        cluster: Cluster,
        value: Cluster,
    ) -> FsResult<()> {
        trace_fat_operation!("write_disk_async", cluster, "value={}", value.0);
        let idx = cluster.0 as usize;
        let fat_offset = idx * 4;
        let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
        let sector = self.fat_start_sector + sector_offset;
        let offset_in_sector = fat_offset % BLOCK_SIZE;

        let mut buffer = [0u8; BLOCK_SIZE];
        self.read_sector_cached_async(sector.as_u64(), &mut buffer)
            .await?;
        let bytes = (value.0 & 0x0FFFFFFF).to_le_bytes();
        buffer[offset_in_sector..offset_in_sector + 4].copy_from_slice(&bytes);

        self.write_sector_cached_async(sector.as_u64(), &buffer)
            .await?;

        let fat2_sector = sector + self.fat_size;
        self.write_sector_cached_async(fat2_sector.as_u64(), &buffer)
            .await?;

        Ok(())
    }

    /// 空きクラスタを割り当て(型安全、アトミック)
    ///
    /// # Race Condition Fix
    /// `update_entry_if` による比較更新で、同一クラスタの二重確保を防止。
    pub(crate) fn allocate_cluster(&self) -> FsResult<Cluster> {
        // クラスタ2から検索開始
        let entries = (self.fat_size as usize) * (BLOCK_SIZE / 4);

        for i in 2..entries {
            let cluster = Cluster(i as u32);
            let entry = match self.read_fat_entry(cluster) {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            if !entry.is_free() {
                continue;
            }

            let fat_offset = i * 4;
            let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
            let offset_in_sector = (fat_offset % BLOCK_SIZE) / 4;

            if !self.fat_sector_cache.update_entry_if(
                sector_offset,
                offset_in_sector,
                Cluster::FREE,
                Cluster::EOF,
            ) {
                continue;
            }

            trace_fat_operation!("allocate", cluster);
            if let Err(e) = self.write_fat_entry_to_disk(cluster, Cluster::EOF) {
                self.fat_sector_cache.update_entry_if(
                    sector_offset,
                    offset_in_sector,
                    Cluster::EOF,
                    Cluster::FREE,
                );
                return Err(e);
            }

            let mut free = self.free_clusters.blocking_lock();
            *free = free.saturating_sub(1);
            return Ok(cluster);
        }
        Err(FsError::StorageFull)
    }

    /// 非同期で空きクラスタを割り当て(型安全)
    pub(crate) async fn allocate_cluster_async(&self) -> FsResult<Cluster> {
        let entries = (self.fat_size as usize) * (BLOCK_SIZE / 4);

        for i in 2..entries {
            let cluster = Cluster(i as u32);

            let entry = match self.read_fat_entry_async(cluster).await {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            if !entry.is_free() {
                continue;
            }

            let fat_offset = i * 4;
            let sector_offset = (fat_offset / BLOCK_SIZE) as u32;
            let offset_in_sector = (fat_offset % BLOCK_SIZE) / 4;

            if !self.fat_sector_cache.update_entry_if(
                sector_offset,
                offset_in_sector,
                Cluster::FREE,
                Cluster::EOF,
            ) {
                continue;
            }

            trace_fat_operation!("allocate_async", cluster);
            if let Err(e) = self
                .write_fat_entry_to_disk_async(cluster, Cluster::EOF)
                .await
            {
                self.fat_sector_cache.update_entry_if(
                    sector_offset,
                    offset_in_sector,
                    Cluster::EOF,
                    Cluster::FREE,
                );
                return Err(e);
            }

            let mut free = self.free_clusters.lock_async().await;
            *free = free.saturating_sub(1);
            return Ok(cluster);
        }

        Err(FsError::StorageFull)
    }

    /// クラスタを解放(型安全)
    pub(crate) fn free_cluster(&self, cluster: Cluster) -> FsResult<()> {
        trace_fat_operation!("free", cluster);
        self.write_fat_entry(cluster, Cluster::FREE)?;
        let mut free = self.free_clusters.blocking_lock();
        *free += 1;
        Ok(())
    }

    /// 非同期でクラスタを解放(型安全)
    pub(crate) async fn free_cluster_async(&self, cluster: Cluster) -> FsResult<()> {
        trace_fat_operation!("free_async", cluster);
        self.write_fat_entry_async(cluster, Cluster::FREE).await?;
        let mut free = self.free_clusters.lock_async().await;
        *free += 1;
        Ok(())
    }

    /// クラスタチェーンを解放(型安全、無限ループ対策)
    ///
    /// # Implementation Note
    /// `ClusterChain` イテレータを使用することで、
    /// ループカウンタの手動管理を排除し、コードを簡潔化。
    /// 無限ループ検出はイテレータ内部で行われる。
    pub(crate) fn free_cluster_chain(&self, start_cluster: Cluster) -> FsResult<()> {
        // collect で先にすべてのクラスタを取得（イテレート中にFATを変更するため）
        let clusters: Vec<Cluster> = self.clusters(start_cluster).collect::<FsResult<Vec<_>>>()?;

        for cluster in clusters {
            self.free_cluster(cluster)?;
        }

        Ok(())
    }

    /// 非同期でクラスタチェーンを解放(型安全、無限ループ対策)
    pub(crate) async fn free_cluster_chain_async(&self, start_cluster: Cluster) -> FsResult<()> {
        let mut current = start_cluster;
        let mut count = 0usize;

        while current.is_valid() {
            count += 1;
            if count > MAX_CLUSTER_CHAIN {
                return Err(FsError::FileSystemCorrupted);
            }

            let next = self.read_fat_entry_async(current).await?;
            self.free_cluster_async(current).await?;

            if next.is_eof() || !next.is_valid() {
                break;
            }
            current = next;
        }

        Ok(())
    }

    /// クラスタを読み取り（型安全）
    ///
    /// 単一クラスタの読み取りは、連続クラスタ読み取りの特殊ケース(count=1)として実装
    pub(crate) fn read_cluster(&self, cluster: Cluster, buffer: &mut [u8]) -> FsResult<()> {
        self.read_contiguous_clusters(cluster, 1, buffer)
    }

    /// クラスタをゼロコピーで読み取り（所有権移動）
    pub(crate) async fn read_cluster_zero_copy(&self, cluster: Cluster) -> FsResult<B> {
        self.read_contiguous_clusters_zero_copy(cluster, 1).await
    }

    /// クラスタを書き込み（型安全）
    ///
    /// 単一クラスタの書き込みは、連続クラスタ書き込みの特殊ケース(count=1)として実装
    pub(crate) fn write_cluster(&self, cluster: Cluster, buffer: &[u8]) -> FsResult<()> {
        self.write_contiguous_clusters(cluster, 1, buffer)
    }

    /// クラスタをゼロコピーで書き込み（所有権移動）
    pub(crate) async fn write_cluster_zero_copy(&self, cluster: Cluster, buffer: B) -> FsResult<B> {
        self.write_contiguous_clusters_zero_copy_async(cluster, 1, buffer)
            .await
    }

    /// 非同期でクラスタを読み取り
    ///
    /// 単一クラスタの読み取りをブロックI/O Future経由で実行する。
    pub async fn read_cluster_async(&self, cluster: Cluster, buffer: &mut [u8]) -> FsResult<()> {
        self.read_contiguous_clusters_async(cluster, 1, buffer)
            .await
    }

    /// 非同期で連続クラスタを一括読み取り
    pub async fn read_contiguous_clusters_async(
        &self,
        start: Cluster,
        count: usize,
        buffer: &mut [u8],
    ) -> FsResult<()> {
        if count == 0 {
            return Ok(());
        }

        let cluster_size = self.cluster_size();
        let expected_size = count * cluster_size;

        if buffer.len() < expected_size {
            return Err(FsError::InvalidInput);
        }

        let data = self
            .read_contiguous_clusters_zero_copy(start, count)
            .await?;

        if data.len() < expected_size {
            return Err(FsError::IoError);
        }

        buffer[..expected_size].copy_from_slice(&data.as_slice()[..expected_size]);

        Ok(())
    }

    /// 非同期で連続クラスタをゼロコピー読み取り
    pub(crate) async fn read_contiguous_clusters_zero_copy(
        &self,
        start: Cluster,
        count: usize,
    ) -> FsResult<B> {
        if count == 0 {
            return Err(FsError::InvalidInput);
        }

        let cluster_size = self.cluster_size();
        let expected_size = count * cluster_size;
        let start_sector = self.cluster_to_sector(start)?;
        let total_sectors = count * self.sectors_per_cluster as usize;

        let data = self
            .zc_device
            .read_async(start_sector.as_u64(), total_sectors as u32)
            .await
            .map_err(FsError::from)?;

        if data.len() < expected_size {
            return Err(FsError::IoError);
        }

        // キャッシュを最新化（既存エントリのみ）
        for i in 0..total_sectors {
            let sector = start_sector + i as u32;
            let offset = i * BLOCK_SIZE;
            self.update_cache_if_missing(
                sector.as_u64(),
                &data.as_slice()[offset..offset + BLOCK_SIZE],
            );
        }

        Ok(data)
    }

    /// 非同期でクラスタを書き込み
    ///
    /// 単一クラスタの書き込みをFuture経由で実行する。
    pub async fn write_cluster_async(&self, cluster: Cluster, data: &[u8]) -> FsResult<()> {
        self.write_contiguous_clusters_async(cluster, 1, data).await
    }

    /// 非同期で連続クラスタを書き込み
    pub async fn write_contiguous_clusters_async(
        &self,
        start: Cluster,
        count: usize,
        data: &[u8],
    ) -> FsResult<()> {
        if count == 0 {
            return Ok(());
        }

        let cluster_size = self.cluster_size();
        let expected_size = count * cluster_size;

        if data.len() < expected_size {
            return Err(FsError::InvalidInput);
        }

        let mut buffer = self
            .zc_device
            .alloc_buffer(expected_size)
            .map_err(FsError::from)?;
        buffer.as_mut_slice()[..expected_size].copy_from_slice(&data[..expected_size]);
        let _ = self
            .write_contiguous_clusters_zero_copy_async(start, count, buffer)
            .await?;

        Ok(())
    }

    /// 非同期で連続クラスタをゼロコピー書き込み
    pub(crate) async fn write_contiguous_clusters_zero_copy_async(
        &self,
        start: Cluster,
        count: usize,
        buffer: B,
    ) -> FsResult<B> {
        if count == 0 {
            return Err(FsError::InvalidInput);
        }

        let cluster_size = self.cluster_size();
        let expected_size = count * cluster_size;

        if buffer.len() < expected_size {
            return Err(FsError::InvalidInput);
        }

        let start_sector = self.cluster_to_sector(start)?;
        let total_sectors = count * self.sectors_per_cluster as usize;

        let buffer = self
            .zc_device
            .write_async(start_sector.as_u64(), buffer)
            .await
            .map_err(FsError::from)?;

        for i in 0..total_sectors {
            let sector = start_sector + i as u32;
            let offset = i * BLOCK_SIZE;
            self.update_cache_only(
                sector.as_u64(),
                &buffer.as_slice()[offset..offset + BLOCK_SIZE],
            );
        }

        Ok(buffer)
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

    /// 連続クラスタの検出・読み取り・次クラスタ取得を一括で行うヘルパー
    ///
    /// # Returns
    /// `Ok((clusters_count, next_cluster))` - 読み取ったクラスタ数と次のクラスタ
    pub(crate) fn try_read_next_batch(
        &self,
        current_cluster: Cluster,
        buffer: &mut [u8],
        clusters_read: usize,
        cluster_size: usize,
        max_remaining: usize,
    ) -> FsResult<(usize, Option<Cluster>)> {
        let (start, count) = self.find_contiguous_clusters(current_cluster, max_remaining)?;
        if count == 0 {
            return Ok((0, None));
        }
        let batch_size = count * cluster_size;
        let offset = clusters_read * cluster_size;
        self.read_contiguous_clusters(start, count, &mut buffer[offset..offset + batch_size])?;
        let next = self.get_next_cluster_after_batch(start, count)?;
        Ok((count, next))
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
    pub(crate) fn read_clusters_batch_internal(
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
            match self.try_read_next_batch(
                current_cluster,
                buffer,
                clusters_read,
                cluster_size,
                max_clusters - clusters_read,
            ) {
                Ok((0, _)) => break,
                Ok((count, next)) => {
                    total_read += count * cluster_size;
                    clusters_read += count;
                    match next {
                        Some(n) => current_cluster = n,
                        None => break,
                    }
                }
                Err(e) => {
                    first_error = Some(e);
                    if !allow_partial {
                        break;
                    }
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
    pub(crate) fn find_contiguous_clusters(
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
            let next = self.read_fat_entry(current)?;

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
    pub(crate) fn read_contiguous_clusters(
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

        let start_sector = self.cluster_to_sector(start)?;
        let total_sectors = count * self.sectors_per_cluster as usize;

        // 1. デバイスから一括読み取り（パフォーマンス向上の核心）
        let device = self.legacy_device.as_ref().ok_or(FsError::NotSupported)?;
        device.read_sync(start_sector.as_u64(), &mut buffer[..expected_size])?;

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
    pub(crate) fn read_sector_cached(&self, sector: u64, buffer: &mut [u8]) -> FsResult<()> {
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
        let mut sector_buf = try_alloc_vec(BLOCK_SIZE, 0u8)?;
        let device = self.legacy_device.as_ref().ok_or(FsError::NotSupported)?;
        device.read_sync(sector, &mut sector_buf)?;

        // バッファにコピー
        let copy_len = buffer.len().min(sector_buf.len());
        buffer[..copy_len].copy_from_slice(&sector_buf[..copy_len]);

        // キャッシュに追加
        self.block_cache.insert(self.device_id, sector, sector_buf);

        Ok(())
    }

    /// 非同期でキャッシュを使用してセクタを読み取る
    pub(crate) async fn read_sector_cached_async(
        &self,
        sector: u64,
        buffer: &mut [u8],
    ) -> FsResult<()> {
        if let Some(cached_block) = self.block_cache.get(self.device_id, sector) {
            let data = cached_block.data();
            let data_guard = data.read();
            let copy_len = buffer.len().min(data_guard.len());
            buffer[..copy_len].copy_from_slice(&data_guard[..copy_len]);
            return Ok(());
        }

        let data = self
            .zc_device
            .read_async(sector, 1)
            .await
            .map_err(FsError::from)?;

        let copy_len = buffer.len().min(data.len());
        buffer[..copy_len].copy_from_slice(&data.as_slice()[..copy_len]);

        if let Ok(mut cache_buf) = try_alloc_vec(data.len(), 0u8) {
            cache_buf[..].copy_from_slice(data.as_slice());
            self.block_cache.insert(self.device_id, sector, cache_buf);
        }

        Ok(())
    }

    /// バッチ読み取り後の次のクラスタを取得
    pub(crate) fn get_next_cluster_after_batch(
        &self,
        start: Cluster,
        count: usize,
    ) -> FsResult<Option<Cluster>> {
        if count == 0 {
            return Ok(None);
        }

        // バッチの最後のクラスタ
        let last_cluster = Cluster(start.0 + (count as u32) - 1);

        let next = self.read_fat_entry(last_cluster)?;

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
    pub(crate) fn write_contiguous_clusters(
        &self,
        start: Cluster,
        count: usize,
        data: &[u8],
    ) -> FsResult<()> {
        let cluster_size = self.cluster_size();
        let expected_size = count * cluster_size;

        if data.len() < expected_size {
            return Err(FsError::InvalidInput);
        }

        let start_sector = self.cluster_to_sector(start)?;

        // 1. デバイスに一括書き込み（パフォーマンス向上の核心）
        let device = self.legacy_device.as_ref().ok_or(FsError::NotSupported)?;
        device.write_sync(start_sector.as_u64(), &data[..expected_size])?;

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
    pub(crate) fn update_cache_only(&self, sector: u64, data: &[u8]) {
        if let Some(cached_block) = self.block_cache.get(self.device_id, sector) {
            let block_data = cached_block.data();
            let mut data_guard = block_data.write();
            let copy_len = data.len().min(data_guard.len());
            data_guard[..copy_len].copy_from_slice(&data[..copy_len]);
            cached_block.mark_clean();
        }
    }

    /// キャッシュに存在しない場合のみ追加
    pub(crate) fn update_cache_if_missing(&self, sector: u64, data: &[u8]) {
        if self.block_cache.get(self.device_id, sector).is_none() {
            if let Ok(mut cache_buf) = try_alloc_vec(data.len(), 0u8) {
                cache_buf[..].copy_from_slice(data);
                self.block_cache.insert(self.device_id, sector, cache_buf);
            }
        }
    }

    /// キャッシュを使用してセクタを書き込む（write-through方式）
    ///
    /// デバイスに書き込み後、キャッシュも更新する。
    pub(crate) fn write_sector_cached(&self, sector: u64, data: &[u8]) -> FsResult<()> {
        // まずデバイスに書き込み（write-through）
        let device = self.legacy_device.as_ref().ok_or(FsError::NotSupported)?;
        device.write_sync(sector, data)?;

        // キャッシュにも書き込み（存在する場合は更新、なければ追加）
        if let Some(cached_block) = self.block_cache.get(self.device_id, sector) {
            // キャッシュに存在する場合は更新
            let block_data = cached_block.data();
            let mut data_guard = block_data.write();
            let copy_len = data.len().min(data_guard.len());
            data_guard[..copy_len].copy_from_slice(&data[..copy_len]);
            // デバイスへ同期済みなのでクリーンとして扱う
            cached_block.mark_clean();
        } else if let Ok(mut sector_buf) = try_alloc_vec(BLOCK_SIZE, 0u8) {
            // キャッシュにない場合は追加
            let copy_len = data.len().min(BLOCK_SIZE);
            sector_buf[..copy_len].copy_from_slice(&data[..copy_len]);
            self.block_cache.insert(self.device_id, sector, sector_buf);
        }

        Ok(())
    }

    /// 非同期でキャッシュを使用してセクタを書き込む（write-through方式）
    pub(crate) async fn write_sector_cached_async(&self, sector: u64, data: &[u8]) -> FsResult<()> {
        let mut buffer = self
            .zc_device
            .alloc_buffer(BLOCK_SIZE)
            .map_err(FsError::from)?;

        let copy_len = data.len().min(buffer.as_mut_slice().len());
        buffer.as_mut_slice()[..copy_len].copy_from_slice(&data[..copy_len]);

        let buffer = self
            .zc_device
            .write_async(sector, buffer)
            .await
            .map_err(FsError::from)?;

        if let Some(cached_block) = self.block_cache.get(self.device_id, sector) {
            let block_data = cached_block.data();
            let mut data_guard = block_data.write();
            let copy_len = buffer.len().min(data_guard.len());
            data_guard[..copy_len].copy_from_slice(&buffer.as_slice()[..copy_len]);
            cached_block.mark_clean();
        } else if let Ok(mut sector_buf) = try_alloc_vec(BLOCK_SIZE, 0u8) {
            let copy_len = buffer.len().min(BLOCK_SIZE);
            sector_buf[..copy_len].copy_from_slice(&buffer.as_slice()[..copy_len]);
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
    pub(crate) fn cluster_size(&self) -> usize {
        self.sectors_per_cluster as usize * BLOCK_SIZE
    }

    /// バッファに格納可能なクラスタ数を計算
    ///
    /// # Example
    /// ```ignore
    /// let max_clusters = fs.buffer_cluster_capacity(&buffer);
    /// ```
    #[inline]
    pub(crate) fn buffer_cluster_capacity(&self, buffer: &[u8]) -> usize {
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
