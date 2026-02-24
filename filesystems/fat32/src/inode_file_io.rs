use crate::*;

impl<B: ZeroCopyBufferMut + 'static> Fat32Inode<B> {
    /// ゼロコピー書き込みパラメータを検証
    pub(crate) fn validate_zero_copy_params(&self, offset: u64, buf_len: usize) -> FsResult<()> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }
        let cluster_size = self.fs.cluster_size() as u64;
        if offset % cluster_size != 0 || buf_len as u64 % cluster_size != 0 {
            return Err(FsError::NotSupported);
        }
        Ok(())
    }

    /// ゼロコピー書き込み用の開始クラスタを解決
    pub(crate) async fn resolve_zero_copy_start_cluster(
        &self,
        offset: u64,
        needed_clusters: usize,
    ) -> FsResult<Cluster> {
        let current_cluster = { self.inner.lock_async().await.first_cluster };
        if !current_cluster.is_valid() {
            return Err(FsError::NotSupported);
        }
        let cluster_size = self.fs.cluster_size() as u64;
        let start_cluster_idx = (offset / cluster_size) as usize;
        let target = self
            .seek_fat_chain_checked_async(current_cluster, start_cluster_idx)
            .await?
            .ok_or(FsError::NotSupported)?;
        self.verify_contiguous_chain_async(target, needed_clusters)
            .await?;
        Ok(target)
    }

    /// ゼロコピーでファイルを書き込み（所有権移動、Async）
    ///
    /// 現状は「クラスタ境界に整列した連続領域」のみ対応。
    pub async fn write_zero_copy_async(&self, offset: u64, buffer: B) -> FsResult<B> {
        self.validate_zero_copy_params(offset, buffer.len())?;

        if buffer.len() == 0 {
            return Ok(buffer);
        }

        let needed_clusters = buffer.len() / self.fs.cluster_size();
        let current_cluster = self
            .resolve_zero_copy_start_cluster(offset, needed_clusters)
            .await?;

        let buffer = self
            .fs
            .write_contiguous_clusters_zero_copy_async(current_cluster, needed_clusters, buffer)
            .await?;

        let mut inner = self.inner.lock_async().await;
        inner.size = inner.size.max(offset + buffer.len() as u64);
        drop(inner);
        self.sync_metadata_async().await?;

        Ok(buffer)
    }

    pub fn read(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }

        let inner = self.inner.blocking_lock();
        if offset >= inner.size {
            return Ok(0);
        }

        let cluster_size = self.fs.cluster_size();
        let cluster_size_u64 = cluster_size as u64;
        let to_read = buf.len().min((inner.size - offset) as usize);

        // 開始クラスタまでスキップ（skip メソッド活用）
        let start_cluster_idx = (offset / cluster_size_u64) as usize;
        let chain = self
            .fs
            .clusters(inner.first_cluster)
            .skip(start_cluster_idx);

        // 最初のクラスタ内でのオフセット
        let mut current_cluster_offset = (offset % cluster_size_u64) as usize;

        // バッファはクラスタプールから取得（枯渇時はヒープ確保）
        // カーネル環境では、ページアロケータまたはPer-CPUバッファを推奨
        //
        // 最適化案:
        // 1. Per-CPUバッファ: CPU_LOCAL.with(|local| local.cluster_buffer.borrow_mut())
        // 2. ページアロケータ: alloc_pages(cluster_size / PAGE_SIZE)
        // 3. LRUキャッシュ: 頻繁に読まれるクラスタをメモリに保持（Exchange Heap経由）
        let mut cluster_buf =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;

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

    /// 非同期版のファイル読み取り
    pub async fn read_async(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }

        let guard = self.inner.lock_async().await;
        let (size, first_cluster) = (guard.size, guard.first_cluster);

        if offset >= size || !first_cluster.is_valid() {
            return Ok(0);
        }

        let cluster_size_u64 = self.fs.cluster_size() as u64;
        let to_read = buf.len().min((size - offset) as usize);

        let start_cluster_idx = (offset / cluster_size_u64) as usize;
        let current_cluster = match self
            .seek_fat_chain_checked_async(first_cluster, start_cluster_idx)
            .await?
        {
            Some(c) => c,
            None => return Ok(0),
        };

        let cluster_offset = (offset % cluster_size_u64) as usize;
        self.read_clusters_into_buf_async(current_cluster, cluster_offset, &mut buf[..to_read])
            .await
    }

    /// FATチェーンをたどり、必要であれば新しいクラスタを割り当てる
    pub(crate) fn next_or_allocate_cluster(&self, current: Cluster) -> FsResult<Cluster> {
        let next = self.fs.read_fat_entry(current)?;
        if !next.is_valid() {
            let new_cluster = self.fs.allocate_cluster()?;
            self.fs.write_fat_entry(current, new_cluster)?;
            Ok(new_cluster)
        } else {
            Ok(next)
        }
    }

    /// FATチェーンをcountクラスタ分進める（必要に応じて割り当て）
    pub(crate) fn advance_fat_chain_allocating(
        &self,
        mut cluster: Cluster,
        count: u64,
    ) -> FsResult<Cluster> {
        for _ in 0..count {
            cluster = self.next_or_allocate_cluster(cluster)?;
        }
        Ok(cluster)
    }

    /// クラスタにデータを書き込む（部分書き込みの場合はread-modify-write）
    pub(crate) fn write_single_cluster(
        &self,
        cluster: Cluster,
        cluster_offset: usize,
        buf: &[u8],
        bytes_written: usize,
        cluster_size: usize,
        cluster_buf: &mut PooledClusterBuffer<'_>,
    ) -> FsResult<usize> {
        let is_partial =
            cluster_offset > 0 || bytes_written + cluster_size - cluster_offset > buf.len();
        if is_partial {
            self.fs.read_cluster(cluster, cluster_buf)?;
        }
        let copy_len = (cluster_size - cluster_offset).min(buf.len() - bytes_written);
        cluster_buf[cluster_offset..cluster_offset + copy_len]
            .copy_from_slice(&buf[bytes_written..bytes_written + copy_len]);
        self.fs.write_cluster(cluster, cluster_buf)?;
        Ok(copy_len)
    }

    /// Write data to clusters starting at the given cluster and offset.
    pub(crate) fn write_clusters(
        &self,
        start_cluster: Cluster,
        cluster_offset: usize,
        buf: &[u8],
    ) -> FsResult<usize> {
        let cluster_size = self.fs.cluster_size();
        let mut cluster_buf =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;
        let mut current = start_cluster;
        let mut offset = cluster_offset;
        let mut bytes_written = 0usize;

        while bytes_written < buf.len() {
            let copy_len = self.write_single_cluster(
                current,
                offset,
                buf,
                bytes_written,
                cluster_size,
                &mut cluster_buf,
            )?;
            bytes_written += copy_len;
            offset = 0;

            if bytes_written < buf.len() {
                current = self.next_or_allocate_cluster(current)?;
            }
        }
        Ok(bytes_written)
    }

    pub fn write(&self, offset: u64, buf: &[u8]) -> FsResult<usize> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }
        let mut inner = self.inner.blocking_lock();

        if buf.is_empty() {
            return Ok(0);
        }

        let cluster_size_u64 = self.fs.cluster_size() as u64;

        // 必要なクラスタを確保
        let mut cluster = inner.first_cluster;

        // ファイルが空の場合、最初のクラスタを割り当て
        if !cluster.is_valid() {
            cluster = self.fs.allocate_cluster()?;
            inner.first_cluster = cluster;
        }

        // 書き込み開始位置のクラスタまでスキップ
        cluster = self.advance_fat_chain_allocating(cluster, offset / cluster_size_u64)?;

        let cluster_offset = (offset % cluster_size_u64) as usize;
        let bytes_written = self.write_clusters(cluster, cluster_offset, buf)?;

        inner.size = inner.size.max(offset + bytes_written as u64);
        drop(inner);
        self.sync_metadata()?;
        Ok(bytes_written)
    }

    /// Async write loop: write data to clusters starting at the given cluster and offset.
    pub(crate) async fn write_clusters_async(
        &self,
        start_cluster: Cluster,
        cluster_offset: usize,
        buf: &[u8],
    ) -> FsResult<usize> {
        let cluster_size = self.fs.cluster_size();
        let mut cluster_buf =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;
        let mut current = start_cluster;
        let mut offset = cluster_offset;
        let mut bytes_written = 0usize;

        while bytes_written < buf.len() {
            let written = self
                .write_single_cluster_async(
                    current,
                    offset,
                    &buf[bytes_written..],
                    &mut cluster_buf,
                    cluster_size,
                )
                .await?;

            bytes_written += written;
            offset = 0;

            if bytes_written < buf.len() {
                current = self.advance_or_allocate_next_async(current).await?;
            }
        }
        Ok(bytes_written)
    }

    /// Update file size after writing, persisting metadata.
    pub(crate) async fn update_file_size_async(&self, new_end: u64) -> FsResult<()> {
        let mut inner = self.inner.lock_async().await;
        if inner.size < new_end {
            inner.size = new_end;
        }
        drop(inner);
        self.sync_metadata_async().await
    }

    /// 非同期版のファイル書き込み
    pub async fn write_async(&self, offset: u64, buf: &[u8]) -> FsResult<usize> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let cluster_size_u64 = self.fs.cluster_size() as u64;

        let mut cluster = self.ensure_first_cluster_async().await?;
        cluster = self
            .advance_fat_chain_async(cluster, offset / cluster_size_u64)
            .await?;

        let cluster_offset = (offset % cluster_size_u64) as usize;
        let bytes_written = self
            .write_clusters_async(cluster, cluster_offset, buf)
            .await?;

        self.update_file_size_async(offset + bytes_written as u64)
            .await?;
        Ok(bytes_written)
    }

    /// 最初のクラスタが未割り当ての場合に確保する
    pub(crate) async fn ensure_first_cluster_async(&self) -> FsResult<Cluster> {
        let cluster = { self.inner.lock_async().await.first_cluster };
        if cluster.is_valid() {
            return Ok(cluster);
        }
        let allocated = self.fs.allocate_cluster_async().await?;
        let mut inner = self.inner.lock_async().await;
        if !inner.first_cluster.is_valid() {
            inner.first_cluster = allocated;
            Ok(allocated)
        } else {
            let existing = inner.first_cluster;
            drop(inner);
            self.fs.free_cluster_async(allocated).await?;
            Ok(existing)
        }
    }

    /// FATチェーンをcountクラスタ分進める（必要に応じて新クラスタを割り当て）
    pub(crate) async fn advance_fat_chain_async(
        &self,
        start: Cluster,
        count: u64,
    ) -> FsResult<Cluster> {
        let mut cluster = start;
        for _ in 0..count {
            cluster = self.advance_or_allocate_next_async(cluster).await?;
        }
        Ok(cluster)
    }

    /// 次のクラスタを取得（未割当てなら新規割り当て）
    pub(crate) async fn advance_or_allocate_next_async(
        &self,
        cluster: Cluster,
    ) -> FsResult<Cluster> {
        let next = self.fs.read_fat_entry_async(cluster).await?;
        if next.is_valid() {
            Ok(next)
        } else {
            let new_cluster = self.fs.allocate_cluster_async().await?;
            self.fs.write_fat_entry_async(cluster, new_cluster).await?;
            Ok(new_cluster)
        }
    }

    /// クラスタチェーンを必要数まで辿り、不足なら拡張する（同期版）
    pub(crate) fn truncate_walk_chain(
        &self,
        first_cluster: Cluster,
        needed_clusters: u64,
    ) -> FsResult<Cluster> {
        let mut cluster = first_cluster;
        let mut count = 1u64;
        let mut chain_count = 0;

        while count < needed_clusters && cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidInput);
            }

            let next = self.fs.read_fat_entry(cluster)?;
            if !next.is_valid() {
                let new_cluster = self.fs.allocate_cluster()?;
                self.fs.write_fat_entry(cluster, new_cluster)?;
                cluster = new_cluster;
            } else {
                cluster = next;
            }
            count += 1;
        }
        Ok(cluster)
    }

    /// クラスタの後続チェーンを解放し、EOFマークを書き込む
    pub(crate) fn truncate_release_tail(&self, cluster: Cluster) -> FsResult<()> {
        if cluster.is_valid() {
            let next = self.fs.read_fat_entry(cluster)?;
            self.fs.write_fat_entry(cluster, Cluster::EOF)?;
            if next.is_valid() {
                self.fs.free_cluster_chain(next)?;
            }
        }
        Ok(())
    }

    /// FATチェーンから指定位置のクラスタを取得（非同期）。
    /// チェーン終端に達した場合は `Ok(None)` を返す。
    pub(crate) async fn seek_fat_chain_checked_async(
        &self,
        start: Cluster,
        count: usize,
    ) -> FsResult<Option<Cluster>> {
        let mut current = start;
        for _ in 0..count {
            let next = self.fs.read_fat_entry_async(current).await?;
            if next.is_eof() || !next.is_valid() {
                return Ok(None);
            }
            current = next;
        }
        Ok(Some(current))
    }

    /// 連続クラスタチェーンの検証（非同期）
    pub(crate) async fn verify_contiguous_chain_async(
        &self,
        start: Cluster,
        needed_clusters: usize,
    ) -> FsResult<()> {
        let mut last = start;
        for _ in 1..needed_clusters {
            let next = self.fs.read_fat_entry_async(last).await?;
            if next.is_eof() || !next.is_valid() || next.0 != last.0 + 1 {
                return Err(FsError::NotSupported);
            }
            last = next;
        }
        Ok(())
    }

    /// クラスタ列からバッファへのデータ読み取り（非同期）
    pub(crate) async fn read_clusters_into_buf_async(
        &self,
        mut current_cluster: Cluster,
        mut cluster_offset: usize,
        buf: &mut [u8],
    ) -> FsResult<usize> {
        let cluster_size = self.fs.cluster_size();
        let mut cluster_buf =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;
        let mut remaining_buf = buf;
        let mut bytes_read = 0;

        while !remaining_buf.is_empty() && current_cluster.is_valid() {
            self.fs
                .read_cluster_async(current_cluster, &mut cluster_buf)
                .await?;

            let available_data = &cluster_buf[cluster_offset..];
            let copy_len = remaining_buf.len().min(available_data.len());

            let (target, next) = remaining_buf.split_at_mut(copy_len);
            target.copy_from_slice(&available_data[..copy_len]);

            remaining_buf = next;
            bytes_read += copy_len;
            cluster_offset = 0;

            let next_cluster = self.fs.read_fat_entry_async(current_cluster).await?;
            if next_cluster.is_eof() || !next_cluster.is_valid() {
                break;
            }
            current_cluster = next_cluster;
        }

        Ok(bytes_read)
    }

    /// 単一クラスタへの書き込み（非同期）。書き込んだバイト数を返す。
    pub(crate) async fn write_single_cluster_async(
        &self,
        cluster: Cluster,
        cluster_offset: usize,
        data: &[u8],
        cluster_buf: &mut PooledClusterBuffer<'_>,
        cluster_size: usize,
    ) -> FsResult<usize> {
        if cluster_offset > 0 || data.len() < cluster_size - cluster_offset {
            self.fs.read_cluster_async(cluster, cluster_buf).await?;
        }

        let copy_len = (cluster_size - cluster_offset).min(data.len());
        cluster_buf[cluster_offset..cluster_offset + copy_len].copy_from_slice(&data[..copy_len]);

        self.fs.write_cluster_async(cluster, cluster_buf).await?;

        Ok(copy_len)
    }

    pub(crate) fn truncate(&self, size: u64) -> FsResult<()> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }
        let mut inner = self.inner.blocking_lock();

        let cluster_size = self.fs.cluster_size() as u64;

        if size == 0 {
            if inner.first_cluster.is_valid() {
                self.fs.free_cluster_chain(inner.first_cluster)?;
                inner.first_cluster = Cluster(0);
            }
            return Ok(());
        }

        let needed_clusters = (size + cluster_size - 1) / cluster_size;
        let cluster = self.truncate_walk_chain(inner.first_cluster, needed_clusters)?;
        self.truncate_release_tail(cluster)?;

        inner.size = size;
        drop(inner);
        self.sync_metadata()?;
        Ok(())
    }

    /// 非同期でファイルを切り詰め
    pub async fn truncate_async(&self, size: u64) -> FsResult<()> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }

        if size == 0 {
            return self.truncate_to_zero_async().await;
        }

        let cluster_size = self.fs.cluster_size() as u64;
        let needed_clusters = (size + cluster_size - 1) / cluster_size;

        let first_cluster = self.ensure_first_cluster_async().await?;
        let last = self
            .extend_chain_to_async(first_cluster, needed_clusters)
            .await?;
        self.trim_chain_after_async(last).await?;

        {
            let mut inner = self.inner.lock_async().await;
            inner.size = size;
            inner.first_cluster = first_cluster;
        }
        self.sync_metadata_async().await?;
        Ok(())
    }

    /// ゼロサイズへの非同期切り詰め
    pub(crate) async fn truncate_to_zero_async(&self) -> FsResult<()> {
        let first_cluster = { self.inner.lock_async().await.first_cluster };
        if first_cluster.is_valid() {
            self.fs.free_cluster_chain_async(first_cluster).await?;
        }
        let mut inner = self.inner.lock_async().await;
        inner.first_cluster = Cluster(0);
        inner.size = 0;
        drop(inner);
        self.sync_metadata_async().await?;
        Ok(())
    }

    /// クラスタチェインを必要な数まで拡張する（非同期）
    pub(crate) async fn extend_chain_to_async(
        &self,
        start: Cluster,
        needed_clusters: u64,
    ) -> FsResult<Cluster> {
        let mut cluster = start;
        let mut count = 1u64;
        let mut chain_count = 0usize;

        while count < needed_clusters && cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidInput);
            }

            let next = self.fs.read_fat_entry_async(cluster).await?;
            if !next.is_valid() {
                let new_cluster = self.fs.allocate_cluster_async().await?;
                self.fs.write_fat_entry_async(cluster, new_cluster).await?;
                cluster = new_cluster;
            } else {
                cluster = next;
            }
            count += 1;
        }
        Ok(cluster)
    }

    /// クラスタチェインの余分なクラスタを解放する（非同期）
    pub(crate) async fn trim_chain_after_async(&self, cluster: Cluster) -> FsResult<()> {
        if cluster.is_valid() {
            let next = self.fs.read_fat_entry_async(cluster).await?;
            self.fs.write_fat_entry_async(cluster, Cluster::EOF).await?;
            if next.is_valid() && !next.is_eof() {
                self.fs.free_cluster_chain_async(next).await?;
            }
        }
        Ok(())
    }

    /// メモリ上のメタデータ（サイズ、クラスタ、属性）をディスク上のディレクトリエントリに同期します。
    pub fn sync_metadata(&self) -> FsResult<()> {
        let inner = self.inner.blocking_lock();
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
        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), self.fs.cluster_size())?;
        self.fs.read_cluster(cluster, &mut buffer)?;

        // rawエントリを可変として取得し、現在のメタデータで更新します。
        let mut raw = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
            &buffer[offset..offset + DIR_ENTRY_SIZE],
        );
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

    /// 非同期でメタデータをディスク上のディレクトリエントリに同期します。
    pub async fn sync_metadata_async(&self) -> FsResult<()> {
        let (parent_cluster, name, size, first_cluster, attributes, created, modified, accessed) = {
            let guard = self.inner.lock_async().await;
            if guard.parent_cluster.0 == 0 {
                return Ok(());
            }
            let tuple = (
                guard.parent_cluster,
                guard.name.clone(),
                guard.size,
                guard.first_cluster,
                guard.attributes,
                guard.created,
                guard.modified,
                guard.accessed,
            );
            tuple
        };

        let parent_inode =
            Fat32Inode::new_directory(self.fs.clone(), parent_cluster, Cluster(0), String::new());

        let (cluster, offset) = parent_inode
            .find_sfn_location_async(&name)
            .await?
            .ok_or(FsError::NotFound)?;

        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), self.fs.cluster_size())?;
        self.fs.read_cluster_async(cluster, &mut buffer).await?;

        let mut raw = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
            &buffer[offset..offset + DIR_ENTRY_SIZE],
        );
        raw.set_file_size(size as u32);
        raw.set_first_cluster(first_cluster);
        raw.set_attributes(attributes);

        let (mdate, mtime) = unix_to_dos(modified);
        raw.set_modify_date(mdate);
        raw.set_modify_time(mtime);

        let (adate, _) = unix_to_dos(accessed);
        raw.set_access_date(adate);

        let (cdate, ctime) = unix_to_dos(created);
        raw.set_create_date(cdate);
        raw.set_create_time(ctime);

        raw.write_bytes_to(&mut buffer[offset..offset + DIR_ENTRY_SIZE]);
        self.fs.write_cluster_async(cluster, &buffer).await
    }

    pub(crate) fn fsync(&self, _datasync: bool) -> FsResult<()> {
        self.fs.sync()
    }

    /// 非同期でfsync
    pub async fn fsync_async(&self, _datasync: bool) -> FsResult<()> {
        self.fs.sync_async().await
    }
}
