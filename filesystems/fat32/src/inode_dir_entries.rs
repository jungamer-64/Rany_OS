use crate::{
    Cluster, DELETED_ENTRY, DIR_ENTRY_SIZE, DirEntryRaw, DirectoryIterator, END_OF_DIR, Fat32Inode,
    FileAttributes, FileType, FsError, FsResult, HashSet, LfnEntry, MAX_CLUSTER_CHAIN,
    PooledClusterBuffer, SafePackedRead, ZeroCopyBufferMut,
};

use alloc::vec::Vec;

impl<B: ZeroCopyBufferMut + 'static> Fat32Inode<B> {
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
    pub fn entries(&self) -> FsResult<DirectoryIterator<'_, B>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }
        let inner = self.inner.blocking_lock();
        DirectoryIterator::new(&self.fs, inner.first_cluster)
    }

    /// 8.3形式のショートファイル名を生成
    ///
    /// 統合された実装: ベース名と拡張子のタプルを返す。
    /// 不正な文字はアンダースコアに置換される。
    #[inline]
    pub(crate) fn to_short_name_parts(name: &str) -> ([u8; 8], [u8; 3]) {
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
    pub(crate) fn collect_existing_sfns(&self) -> FsResult<HashSet<[u8; 11]>> {
        let mut sfns = HashSet::new();

        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        let cluster_size = self.fs.cluster_size();
        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;
        let inner = self.inner.blocking_lock();
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

    /// 非同期でディレクトリ内の既存SFN（11バイト形式）をすべて収集
    pub(crate) async fn collect_existing_sfns_async(&self) -> FsResult<HashSet<[u8; 11]>> {
        let mut sfns = HashSet::new();

        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        let cluster_size = self.fs.cluster_size();
        let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size)?;
        let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;
        let mut current_cluster = self.inner.blocking_lock().first_cluster;
        let mut chain_count = 0usize;

        while current_cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidInput);
            }

            self.fs
                .read_cluster_async(current_cluster, &mut buffer)
                .await?;

            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let entry_bytes = &buffer[offset..offset + DIR_ENTRY_SIZE];

                if entry_bytes[0] == END_OF_DIR {
                    return Ok(sfns);
                }

                if entry_bytes[0] == DELETED_ENTRY {
                    continue;
                }

                let attr = FileAttributes::from_bits_truncate(entry_bytes[11]);
                if attr.is_long_name() || attr.is_volume_id() {
                    continue;
                }

                let mut sfn = [0u8; 11];
                sfn.copy_from_slice(&entry_bytes[0..11]);
                sfns.insert(sfn);
            }

            let next = self.fs.read_fat_entry_async(current_cluster).await?;
            if next.is_eof() || !next.is_valid() {
                break;
            }
            current_cluster = next;
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
    pub(crate) fn generate_unique_sfn(
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
    pub(crate) fn scan_dir_entries<T, F>(
        &self,
        mut predicate: F,
    ) -> FsResult<Option<(T, Cluster, usize)>>
    where
        F: FnMut(&DirEntryRaw, usize) -> Option<T>,
    {
        let cluster_size = self.fs.cluster_size();
        let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size)?;
        let inner = self.inner.blocking_lock();
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
                let raw = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
                    &buffer[offset..offset + DIR_ENTRY_SIZE],
                );

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

    /// 非同期でディレクトリ内のエントリを走査し、条件に一致するエントリを探す
    pub(crate) async fn scan_dir_entries_async<T, F>(
        &self,
        mut predicate: F,
    ) -> FsResult<Option<(T, Cluster, usize)>>
    where
        F: FnMut(&DirEntryRaw, usize) -> Option<T>,
    {
        let cluster_size = self.fs.cluster_size();
        let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size)?;
        let mut current_cluster = self.inner.blocking_lock().first_cluster;
        let mut chain_count = 0;
        let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;

        while current_cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidInput);
            }

            self.fs
                .read_cluster_async(current_cluster, &mut buffer)
                .await?;

            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let raw = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
                    &buffer[offset..offset + DIR_ENTRY_SIZE],
                );

                if let Some(result) = predicate(&raw, offset) {
                    return Ok(Some((result, current_cluster, offset)));
                }

                if raw.is_end() {
                    return Ok(None);
                }
            }

            let next = self.fs.read_fat_entry_async(current_cluster).await?;
            if next.is_eof() || !next.is_valid() {
                break;
            }
            current_cluster = next;
        }

        Ok(None)
    }
    /// 必要な数だけ空いている連続したディレクトリエントリの場所を検索します。
    ///
    /// # Returns
    /// 見つかった場所（開始クラスタ、オフセット）、または見つからない場合はNone
    pub(crate) fn find_free_entry_block(&self, count: usize) -> FsResult<Option<(Cluster, usize)>> {
        let cluster_size = self.fs.cluster_size();
        let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size)?;
        let inner = self.inner.blocking_lock();
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
                let raw = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
                    &buffer[offset..offset + DIR_ENTRY_SIZE],
                );

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

    /// 非同期で必要な数だけ空いている連続したディレクトリエントリの場所を検索します。
    pub(crate) async fn find_free_entry_block_async(
        &self,
        count: usize,
    ) -> FsResult<Option<(Cluster, usize)>> {
        let cluster_size = self.fs.cluster_size();
        let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size)?;
        let mut current_cluster = self.inner.blocking_lock().first_cluster;
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

            self.fs
                .read_cluster_async(current_cluster, &mut buffer)
                .await?;

            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let raw = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
                    &buffer[offset..offset + DIR_ENTRY_SIZE],
                );

                if raw.is_end() {
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

            let next = self.fs.read_fat_entry_async(current_cluster).await?;
            if next.is_eof() || !next.is_valid() {
                break;
            }
            current_cluster = next;
        }

        Ok(None)
    }

    /// ディレクトリに新しいエントリを追加
    pub(crate) fn add_dir_entry(
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
                    PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, self.fs.cluster_size())?;
                // EOFマーカーを書き込む
                buffer[0] = END_OF_DIR;
                self.fs.write_cluster(new_cluster, &buffer)?;

                // チェーンの最後に追加
                let mut last_cluster = self.inner.blocking_lock().first_cluster;
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
            PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, self.fs.cluster_size())?;
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

    /// 非同期でディレクトリに新しいエントリを追加
    pub(crate) async fn add_dir_entry_async(
        &self,
        name: &str,
        cluster: Cluster,
        attr: FileAttributes,
        size: u32,
    ) -> FsResult<()> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        let needs_lfn = name.len() > 12
            || name.contains('.') && name.split('.').next().unwrap().len() > 8
            || name.split('.').nth(1).map_or(false, |ext| ext.len() > 3)
            || name.chars().any(|c| c.is_lowercase());

        let lfn_count = if needs_lfn { (name.len() + 12) / 13 } else { 0 };
        let total_needed = 1 + lfn_count;

        let (found_cluster, found_offset) = match self
            .find_free_entry_block_async(total_needed)
            .await?
        {
            Some(loc) => loc,
            None => {
                let new_cluster = self.fs.allocate_cluster_async().await?;
                let mut buffer =
                    PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, self.fs.cluster_size())?;
                buffer[0] = END_OF_DIR;
                self.fs.write_cluster_async(new_cluster, &buffer).await?;

                let mut last_cluster = self.inner.lock_async().await.first_cluster;
                loop {
                    let next = self.fs.read_fat_entry_async(last_cluster).await?;
                    if next.is_eof() {
                        break;
                    }
                    last_cluster = next;
                }
                self.fs
                    .write_fat_entry_async(last_cluster, new_cluster)
                    .await?;
                (new_cluster, 0)
            }
        };

        let existing_sfns = self.collect_existing_sfns_async().await?;

        let (base, ext) = Self::generate_unique_sfn(name, &existing_sfns)?;
        let mut sfn = DirEntryRaw::new(base, ext, attr, cluster, size);

        let time = self.fs.time_provider.current_dos_time();
        let date = self.fs.time_provider.current_dos_date();
        sfn.set_create_date(date);
        sfn.set_create_time(time);
        sfn.set_modify_date(date);
        sfn.set_modify_time(time);
        sfn.set_access_date(date);

        let checksum = sfn.calculate_checksum();

        let mut buffer =
            PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, self.fs.cluster_size())?;
        self.fs
            .read_cluster_async(found_cluster, &mut buffer)
            .await?;

        let mut current_offset = found_offset;
        let mut current_cluster = found_cluster;

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
                        part[j] = 0x0000;
                    }
                }

                let lfn = LfnEntry::new(seq, &part, checksum, is_last);
                buffer[current_offset..current_offset + DIR_ENTRY_SIZE]
                    .copy_from_slice(lfn.as_bytes());

                current_offset += DIR_ENTRY_SIZE;
                if current_offset >= self.fs.cluster_size() {
                    self.fs
                        .write_cluster_async(current_cluster, &buffer)
                        .await?;
                    current_cluster = self.fs.read_fat_entry_async(current_cluster).await?;
                    self.fs
                        .read_cluster_async(current_cluster, &mut buffer)
                        .await?;
                    current_offset = 0;
                }
            }
        }

        sfn.write_bytes_to(&mut buffer[current_offset..current_offset + DIR_ENTRY_SIZE]);

        self.fs
            .write_cluster_async(current_cluster, &buffer)
            .await?;
        Ok(())
    }

    /// ディレクトリからエントリを削除
    pub(crate) fn remove_dir_entry(&self, name: &str) -> FsResult<DirEntryRaw> {
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
            let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size)?;
            self.fs.read_cluster(found_cluster, &mut buffer)?;
            buffer[offset] = DELETED_ENTRY;
            self.fs.write_cluster(found_cluster, &buffer)?;
            return Ok(raw);
        }

        Err(FsError::NotFound)
    }

    /// 非同期でディレクトリからエントリを削除
    pub(crate) async fn remove_dir_entry_async(&self, name: &str) -> FsResult<DirEntryRaw> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        let cluster_size = self.fs.cluster_size();

        let found = self
            .scan_dir_entries_async(|raw, _offset| {
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
            })
            .await?;

        if let Some((raw, found_cluster, offset)) = found {
            let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size)?;
            self.fs
                .read_cluster_async(found_cluster, &mut buffer)
                .await?;
            buffer[offset] = DELETED_ENTRY;
            self.fs.write_cluster_async(found_cluster, &buffer).await?;
            return Ok(raw);
        }

        Err(FsError::NotFound)
    }
}
