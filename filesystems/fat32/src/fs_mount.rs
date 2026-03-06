use crate::{
    Arc, AsyncMutex, BLOCK_SIZE, BOOT_SECTOR_SIZE, BlockDevice, BootSector, Cluster,
    ClusterBufferAllocator, ClusterBufferPool, DEFAULT_DIR_CACHE_SIZE,
    DEFAULT_FAT_SECTOR_CACHE_SIZE, DefaultZeroCopyBuffer, DirEntryCache, DummyTimeProvider,
    Fat32FileSystem, FatSectorCache, FsError, FsResult, LRUBlockCache, Sector, ZeroCopyBlockDevice,
    ZeroCopyBufferMut,
};

use vfs::block::BlockDeviceZeroCopyAdapter;

impl<B: ZeroCopyBufferMut + 'static> Fat32FileSystem<B> {
    /// FAT32ファイルシステムをマウント（ゼロコピー/Async）
    pub async fn mount_zero_copy(
        device: Arc<dyn ZeroCopyBlockDevice<Buffer = B>>,
    ) -> FsResult<Arc<Self>> {
        let boot_buf = device.read_async(0, 1).await.map_err(FsError::from)?;
        let boot_sector = BootSector::try_from(&boot_buf.as_slice()[..BOOT_SECTOR_SIZE])?;
        let fs = Self::mount_from_boot(boot_sector, device, None, None)?;
        fs.init_free_clusters_async().await?;
        Ok(fs)
    }

    /// FAT32 をゼロコピーデバイスかつカスタムバッファアロケータでマウント（Async）
    pub async fn mount_zero_copy_with_allocator(
        device: Arc<dyn ZeroCopyBlockDevice<Buffer = B>>,
        allocator: Arc<dyn ClusterBufferAllocator>,
    ) -> FsResult<Arc<Self>> {
        let boot_buf = device.read_async(0, 1).await.map_err(FsError::from)?;
        let boot_sector = BootSector::try_from(&boot_buf.as_slice()[..BOOT_SECTOR_SIZE])?;
        let fs = Self::mount_from_boot(boot_sector, device, None, Some(allocator))?;
        fs.init_free_clusters_async().await?;
        Ok(fs)
    }

    /// BootSectorからFAT32パラメータを検証・計算する
    pub(crate) fn validate_boot_sector_params(
        boot_sector: &BootSector,
    ) -> FsResult<(Sector, Sector, u32, u32, u32)> {
        let fs_type = boot_sector.fs_type();
        if &fs_type[0..5] != b"FAT32" {
            return Err(FsError::InvalidInput);
        }
        let fat_start_sector = Sector(boot_sector.reserved_sectors() as u32);
        let fat_size = boot_sector.fat_size_32();
        let num_fats = boot_sector.num_fats() as u32;
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
        Ok((
            fat_start_sector,
            data_start_sector,
            sectors_per_cluster,
            total_clusters,
            fat_size,
        ))
    }

    pub(crate) fn mount_from_boot(
        boot_sector: BootSector,
        zc_device: Arc<dyn ZeroCopyBlockDevice<Buffer = B>>,
        legacy_device: Option<Arc<dyn BlockDevice>>,
        allocator: Option<alloc::sync::Arc<dyn ClusterBufferAllocator>>,
    ) -> FsResult<Arc<Self>> {
        let (fat_start_sector, data_start_sector, sectors_per_cluster, total_clusters, fat_size) =
            Self::validate_boot_sector_params(&boot_sector)?;

        // デバイスIDを生成（静的カウンタを使用）
        static DEVICE_ID_COUNTER: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(1);
        let device_id = DEVICE_ID_COUNTER.fetch_add(1, core::sync::atomic::Ordering::SeqCst);

        // ブロックキャッシュを作成（512バイトブロック、32MB上限）
        let block_cache = Arc::new(LRUBlockCache::new(
            BLOCK_SIZE,
            32 * 1024 * 1024, // 32MB キャッシュ上限
        ));

        let cluster_buffer_pool = match allocator {
            Some(a) => Arc::new(ClusterBufferPool::with_allocator(16, a)?),
            None => Arc::new(ClusterBufferPool::new(16)?), // 16スロットあれば通常十分
        };
        let fs = Arc::new_cyclic(|weak| Self {
            self_weak: weak.clone(),
            legacy_device,
            zc_device: Arc::clone(&zc_device),
            device_id,
            fat_start_sector,
            data_start_sector,
            sectors_per_cluster,
            total_clusters,
            root_cluster: boot_sector.root_cluster(),
            fat_sector_cache: FatSectorCache::new(DEFAULT_FAT_SECTOR_CACHE_SIZE),
            free_clusters: AsyncMutex::new(0),
            fat_size,
            block_cache,
            cluster_buffer_pool: Arc::clone(&cluster_buffer_pool),
            time_provider: Arc::new(DummyTimeProvider),
            fs_info_sector: Sector::from(boot_sector.fs_info_sector() as u32),
            dir_cache: DirEntryCache::new(DEFAULT_DIR_CACHE_SIZE),
        });

        Ok(fs)
    }

    pub(crate) fn init_free_clusters_sync(&self) -> FsResult<()> {
        // FSInfoセクタから空きクラスタ数を取得（高速）
        let free = match self.read_fsinfo() {
            Ok(fsinfo) => fsinfo.free_count().unwrap_or_else(|| {
                // FSInfoに無効な値がある場合はディスクから集計
                self.count_free_clusters_on_disk().unwrap_or(0)
            }),
            Err(_) => {
                // FSInfo読み取り失敗時はディスクから集計
                self.count_free_clusters_on_disk()?
            }
        };
        *self.free_clusters.blocking_lock() = free;
        Ok(())
    }

    pub(crate) async fn init_free_clusters_async(&self) -> FsResult<()> {
        let free = match self.read_fsinfo_async().await {
            Ok(fsinfo) => fsinfo.free_count().unwrap_or_else(|| {
                // FSInfoに無効な値がある場合はディスクから集計
                0
            }),
            Err(_) => 0,
        };

        let free = if free == 0 {
            self.count_free_clusters_on_disk_async().await?
        } else {
            free
        };

        *self.free_clusters.blocking_lock() = free;
        Ok(())
    }

    /// FATをディスク上から走査して空きクラスタ数をカウントする（オンデマンドモードで使用）
    pub(crate) fn count_free_clusters_on_disk(&self) -> FsResult<u32> {
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

    /// 非同期でFATを走査して空きクラスタ数をカウント
    pub(crate) async fn count_free_clusters_on_disk_async(&self) -> FsResult<u32> {
        let sectors = self.fat_size as usize;
        let entries = sectors * BLOCK_SIZE / 4;

        let mut free: u32 = 0;
        let mut buffer = [0u8; BLOCK_SIZE];

        for i in 0..sectors {
            let sector = self.fat_start_sector + i as u32;
            self.read_sector_cached_async(sector.as_u64(), &mut buffer)
                .await?;

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
                if Cluster(val).is_free() {
                    free += 1;
                }
            }
        }

        Ok(free)
    }
}

impl Fat32FileSystem<DefaultZeroCopyBuffer> {
    /// FAT32ファイルシステムをマウント（互換パス、同期I/O）
    pub fn mount(device: Arc<dyn BlockDevice>) -> FsResult<Arc<Self>> {
        // ブートセクタを読み取り
        let mut boot_data = [0u8; BOOT_SECTOR_SIZE];
        device.read_sync(0, &mut boot_data)?;

        // TryFrom トレイトで安全にパース
        let boot_sector = BootSector::try_from(&boot_data[..])?;

        // レガシーデバイスをゼロコピー互換アダプタで包む
        let zc_device = Arc::new(BlockDeviceZeroCopyAdapter::new(Arc::clone(&device)));
        let fs = Self::mount_from_boot(boot_sector, zc_device, Some(device), None)?;
        fs.init_free_clusters_sync()?;
        Ok(fs)
    }

    /// FAT32ファイルシステムをマウント（同期 I/O + カスタムバッファアロケータ）
    pub fn mount_with_allocator(
        device: Arc<dyn BlockDevice>,
        allocator: Arc<dyn ClusterBufferAllocator>,
    ) -> FsResult<Arc<Self>> {
        // ブートセクタを読み取り
        let mut boot_data = [0u8; BOOT_SECTOR_SIZE];
        device.read_sync(0, &mut boot_data)?;

        let boot_sector = BootSector::try_from(&boot_data[..])?;

        let zc_device = Arc::new(BlockDeviceZeroCopyAdapter::new(Arc::clone(&device)));
        let fs = Self::mount_from_boot(boot_sector, zc_device, Some(device), Some(allocator))?;
        fs.init_free_clusters_sync()?;
        Ok(fs)
    }
}
