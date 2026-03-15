use crate::{
    Arc, Cluster, DIR_ENTRY_SIZE, DirEntry, DirEntryRaw, DirectoryEntryKind, END_OF_DIR,
    Fat32Inode, FileAttributes, FileMode, FileType, FsError, FsResult, HashSet, Inode,
    MAX_CLUSTER_CHAIN, MAX_LFN_PARTS, OpenFlags, PooledClusterBuffer, SafePackedRead, String, Vec,
    ZeroCopyBufferMut, ZeroCopyRead, ZeroCopySegment, dos_to_unix, validate_path_length,
};

use vfs::Metadata;

impl<B: ZeroCopyBufferMut + 'static> Fat32Inode<B> {
    pub fn lookup(&self, name: &str) -> FsResult<Arc<Fat32Inode<B>>> {
        // パス長検証
        validate_path_length(name)?;

        // find_by_name()を活用した検索（DirectoryIterator拡張を再利用）
        let raw = self
            .entries()?
            .find_by_name(name)?
            .map(|(_, raw)| raw)
            .ok_or(FsError::NotFound)?;

        let inner = self.inner.blocking_lock();
        let cluster = raw.first_cluster();
        if raw.attributes().is_directory() {
            Ok(Arc::new(Fat32Inode::new_directory(
                self.fs.clone(),
                cluster,
                inner.first_cluster,
                String::from(name),
            )))
        } else {
            Ok(Arc::new(Fat32Inode::new_file(
                self.fs.clone(),
                cluster,
                raw.file_size() as u64,
                inner.first_cluster,
                String::from(name),
            )))
        }
    }

    /// 非同期でディレクトリエントリを検索
    pub async fn lookup_async(&self, name: &str) -> FsResult<Arc<Fat32Inode<B>>> {
        validate_path_length(name)?;

        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        let (cluster, offset) = self
            .find_sfn_location_async(name)
            .await?
            .ok_or(FsError::NotFound)?;

        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), self.fs.cluster_size())?;
        self.fs.read_cluster_async(cluster, &mut buffer).await?;

        let raw = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
            &buffer[offset..offset + DIR_ENTRY_SIZE],
        );
        let parent_cluster = self.inner.lock_async().await.first_cluster;
        let first_cluster = raw.first_cluster();

        if raw.attributes().is_directory() {
            Ok(Arc::new(Fat32Inode::new_directory(
                self.fs.clone(),
                first_cluster,
                parent_cluster,
                String::from(name),
            )))
        } else {
            Ok(Arc::new(Fat32Inode::new_file(
                self.fs.clone(),
                first_cluster,
                raw.file_size() as u64,
                parent_cluster,
                String::from(name),
            )))
        }
    }

    pub fn readdir(&self, _offset: u64) -> FsResult<Vec<DirEntry>> {
        self.entries()?
            .map(|res| {
                res.map(|(name, raw)| {
                    let file_type = if raw.attributes().is_directory() {
                        FileType::Directory
                    } else {
                        FileType::File
                    };
                    DirEntry {
                        name,
                        file_type,
                        metadata: Metadata {
                            file_type: Some(file_type),
                            size: raw.file_size() as u64,
                            created: dos_to_unix(raw.create_date(), raw.create_time()),
                            modified: dos_to_unix(raw.modify_date(), raw.modify_time()),
                            accessed: dos_to_unix(raw.access_date(), 0),
                            readonly: raw.attributes().is_read_only(),
                        },
                    }
                })
            })
            .collect()
    }

    /// クラスタバッファ内のディレクトリエントリを処理
    pub(crate) fn process_cluster_dir_entries(
        buffer: &[u8],
        entries_per_cluster: usize,
        entries: &mut Vec<DirEntry>,
        lfn_parts: &mut Vec<(u8, bool, String, u8)>,
    ) -> FsResult<bool> {
        for i in 0..entries_per_cluster {
            let offset = i * DIR_ENTRY_SIZE;
            let entry_bytes = &buffer[offset..offset + DIR_ENTRY_SIZE];

            match DirectoryEntryKind::from(entry_bytes) {
                DirectoryEntryKind::End => return Ok(true),
                DirectoryEntryKind::Deleted => {
                    lfn_parts.clear();
                    continue;
                }
                DirectoryEntryKind::LongName(lfn) => {
                    if lfn_parts.len() >= MAX_LFN_PARTS {
                        return Err(FsError::FileSystemCorrupted);
                    }
                    lfn_parts.push((
                        lfn.sequence(),
                        lfn.is_last(),
                        lfn.get_name_part(),
                        lfn.checksum(),
                    ));
                    continue;
                }
                DirectoryEntryKind::VolumeLabel => {
                    lfn_parts.clear();
                    continue;
                }
                DirectoryEntryKind::Standard(raw) => {
                    let name = Self::resolve_lfn_name(lfn_parts, &raw);
                    if name == "." || name == ".." {
                        continue;
                    }
                    entries.push(Self::build_dir_entry(name, &raw));
                }
            }
        }
        Ok(false)
    }

    /// 1クラスタ分のディレクトリエントリを読み取り、次のクラスタを返す
    pub(crate) async fn read_one_dir_cluster_async(
        &self,
        cluster: Cluster,
        buffer: &mut [u8],
        entries_per_cluster: usize,
        entries: &mut Vec<DirEntry>,
        lfn_parts: &mut Vec<(u8, bool, String, u8)>,
    ) -> FsResult<Option<Cluster>> {
        self.fs.read_cluster_async(cluster, buffer).await?;
        let done =
            Self::process_cluster_dir_entries(buffer, entries_per_cluster, entries, lfn_parts)?;
        if done {
            return Ok(None);
        }
        let next = self.fs.read_fat_entry_async(cluster).await?;
        if next.is_eof() || !next.is_valid() {
            return Ok(None);
        }
        Ok(Some(next))
    }

    /// 非同期でディレクトリエントリを列挙
    pub async fn readdir_async(&self, _offset: u64) -> FsResult<Vec<DirEntry>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        let cluster_size = self.fs.cluster_size();
        let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;
        let mut buffer = PooledClusterBuffer::new(&self.fs.cluster_buffer_pool, cluster_size)?;

        let mut entries = Vec::new();
        let mut current_cluster = self.inner.lock_async().await.first_cluster;
        let mut chain_count = 0usize;
        let mut lfn_parts: Vec<(u8, bool, String, u8)> = Vec::new();

        while current_cluster.is_valid() {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::FileSystemCorrupted);
            }

            match self
                .read_one_dir_cluster_async(
                    current_cluster,
                    &mut buffer,
                    entries_per_cluster,
                    &mut entries,
                    &mut lfn_parts,
                )
                .await?
            {
                Some(next) => current_cluster = next,
                None => return Ok(entries),
            }
        }

        Ok(entries)
    }

    /// LFNパーツのシーケンスを検証する
    pub(crate) fn validate_lfn_sequence(lfn_parts: &[(u8, bool, String, u8)]) -> bool {
        let n = lfn_parts.len() as u8;
        let mut seen = HashSet::new();
        for &(seq, _, _, _) in lfn_parts.iter() {
            if seq == 0 || seq > n || !seen.insert(seq) {
                return false;
            }
        }
        lfn_parts
            .iter()
            .any(|&(seq, is_last, _, _)| seq == n && is_last)
    }

    /// LFNパーツからファイル名を解決する。LFNが無効ならショートネームにフォールバック。
    pub(crate) fn resolve_lfn_name(
        lfn_parts: &mut Vec<(u8, bool, String, u8)>,
        raw: &DirEntryRaw,
    ) -> String {
        if lfn_parts.is_empty() {
            return raw.short_name();
        }

        let expected_checksum = raw.calculate_checksum();
        let all_checksum_match = lfn_parts
            .iter()
            .all(|&(_, _, _, cs)| cs == expected_checksum);
        if !all_checksum_match {
            lfn_parts.clear();
            return raw.short_name();
        }

        lfn_parts.sort_by_key(|&(seq, _, _, _)| seq);

        if !Self::validate_lfn_sequence(lfn_parts) {
            lfn_parts.clear();
            return raw.short_name();
        }

        let long_name: String = lfn_parts
            .iter()
            .map(|&(_, _, ref s, _)| s.as_str())
            .collect();
        lfn_parts.clear();
        long_name
    }

    /// DirEntryRawからDirEntryを構築する
    pub(crate) fn build_dir_entry(name: String, raw: &DirEntryRaw) -> DirEntry {
        let file_type = if raw.attributes().is_directory() {
            FileType::Directory
        } else {
            FileType::File
        };
        DirEntry {
            name,
            file_type,
            metadata: Metadata {
                file_type: Some(file_type),
                size: raw.file_size() as u64,
                created: 0,
                modified: 0,
                accessed: 0,
                readonly: raw.attributes().is_read_only(),
            },
        }
    }

    pub fn create(
        &self,
        name: &str,
        _mode: FileMode,
        _flags: OpenFlags,
    ) -> FsResult<Arc<Fat32Inode<B>>> {
        // パス長検証
        validate_path_length(name)?;

        // 既存のエントリがないか確認
        if let Ok(_) = self.lookup(name) {
            return Err(FsError::AlreadyExists);
        }

        // 新しいファイル用のクラスタを割り当て（空ファイルの場合はクラスタ0）
        let new_cluster = Cluster(0); // 空ファイルはクラスタを持たない

        let inner = self.inner.blocking_lock();
        // ディレクトリエントリを追加
        self.add_dir_entry(
            name,
            new_cluster,
            FileAttributes::from_bits_truncate(FileAttributes::ARCHIVE),
            0,
        )?;

        Ok(Arc::new(Fat32Inode::new_file(
            self.fs.clone(),
            new_cluster,
            0,
            inner.first_cluster,
            String::from(name),
        )))
    }

    /// 非同期でファイルを作成
    pub async fn create_async(
        &self,
        name: &str,
        _mode: FileMode,
        _flags: OpenFlags,
    ) -> FsResult<Arc<Fat32Inode<B>>> {
        validate_path_length(name)?;

        if self.lookup_async(name).await.is_ok() {
            return Err(FsError::AlreadyExists);
        }

        let new_cluster = Cluster(0);
        self.add_dir_entry_async(
            name,
            new_cluster,
            FileAttributes::from_bits_truncate(FileAttributes::ARCHIVE),
            0,
        )
        .await?;

        let parent_cluster = self.inner.lock_async().await.first_cluster;
        Ok(Arc::new(Fat32Inode::new_file(
            self.fs.clone(),
            new_cluster,
            0,
            parent_cluster,
            String::from(name),
        )))
    }

    pub fn mkdir(&self, name: &str, _mode: FileMode) -> FsResult<Arc<Fat32Inode<B>>> {
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
        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;

        // "." エントリ - 新しいディレクトリ自身を指す
        let dot_entry = DirEntryRaw::new_dot(new_cluster);

        // ".." エントリ - 親ディレクトリを指す
        let inner = self.inner.blocking_lock();
        let dotdot_entry = DirEntryRaw::new_dotdot(inner.first_cluster);

        // バッファに書き込み (as_bytes()で安全にシリアライズ)
        dot_entry.write_bytes_to(&mut buffer[0..DIR_ENTRY_SIZE]);
        dotdot_entry.write_bytes_to(&mut buffer[DIR_ENTRY_SIZE..DIR_ENTRY_SIZE * 2]);

        // 終端マーカー
        buffer[DIR_ENTRY_SIZE * 2] = END_OF_DIR;

        self.fs.write_cluster(new_cluster, &buffer)?;

        // 親ディレクトリにエントリを追加
        self.add_dir_entry(
            name,
            new_cluster,
            FileAttributes::from_bits_truncate(FileAttributes::DIRECTORY),
            0,
        )?;

        let inner = self.inner.blocking_lock();
        Ok(Arc::new(Fat32Inode::new_directory(
            self.fs.clone(),
            new_cluster,
            inner.first_cluster,
            String::from(name),
        )))
    }

    /// 非同期でディレクトリを作成
    pub async fn mkdir_async(&self, name: &str, _mode: FileMode) -> FsResult<Arc<Fat32Inode<B>>> {
        validate_path_length(name)?;

        if self.lookup_async(name).await.is_ok() {
            return Err(FsError::AlreadyExists);
        }

        let new_cluster = self.fs.allocate_cluster_async().await?;
        let cluster_size = self.fs.cluster_size();
        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;

        let dot_entry = DirEntryRaw::new_dot(new_cluster);
        let parent_cluster = self.inner.lock_async().await.first_cluster;
        let dotdot_entry = DirEntryRaw::new_dotdot(parent_cluster);

        dot_entry.write_bytes_to(&mut buffer[0..DIR_ENTRY_SIZE]);
        dotdot_entry.write_bytes_to(&mut buffer[DIR_ENTRY_SIZE..DIR_ENTRY_SIZE * 2]);
        buffer[DIR_ENTRY_SIZE * 2] = END_OF_DIR;

        self.fs.write_cluster_async(new_cluster, &buffer).await?;

        self.add_dir_entry_async(
            name,
            new_cluster,
            FileAttributes::from_bits_truncate(FileAttributes::DIRECTORY),
            0,
        )
        .await?;

        Ok(Arc::new(Fat32Inode::new_directory(
            self.fs.clone(),
            new_cluster,
            parent_cluster,
            String::from(name),
        )))
    }

    pub fn unlink(&self, name: &str) -> FsResult<()> {
        // エントリを検索して削除
        let entry = self.remove_dir_entry(name)?;

        // ディレクトリは削除できない
        if entry.attributes().is_directory() {
            return Err(FsError::IsADirectory);
        }

        // クラスタチェーンを解放
        let cluster = entry.first_cluster();
        if cluster.is_valid() {
            self.fs.free_cluster_chain(cluster)?;
        }

        Ok(())
    }

    /// Verify that the named entry is a directory and that it is empty (sync).
    pub(crate) fn verify_empty_directory_sync(&self, name: &str) -> FsResult<()> {
        let target = self.lookup(name)?;
        let attr = target.getattr()?;
        if attr.file_type != Some(FileType::Directory) {
            return Err(FsError::NotADirectory);
        }
        let entries = target.readdir(0)?;
        if !entries.is_empty() {
            return Err(FsError::DirectoryNotEmpty);
        }
        Ok(())
    }

    pub fn rmdir(&self, name: &str) -> FsResult<()> {
        // まず対象ディレクトリを検索・検証
        self.verify_empty_directory_sync(name)?;

        // エントリを削除
        let entry = self.remove_dir_entry(name)?;

        // クラスタチェーンを解放
        let cluster = entry.first_cluster();
        if cluster.is_valid() {
            self.fs.free_cluster_chain(cluster)?;
        }

        Ok(())
    }

    /// 非同期でディレクトリが空か確認
    pub(crate) async fn is_directory_empty_async(&self) -> FsResult<bool> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        let found = self
            .scan_dir_entries_async(|raw, _| {
                if raw.is_deleted() {
                    return None;
                }
                if raw.attributes().is_long_name() || raw.attributes().is_volume_id() {
                    return None;
                }
                let name = raw.short_name();
                if name == "." || name == ".." {
                    return None;
                }
                Some(())
            })
            .await?;

        Ok(found.is_none())
    }

    /// 非同期でファイルを削除
    pub async fn unlink_async(&self, name: &str) -> FsResult<()> {
        let entry = self.remove_dir_entry_async(name).await?;

        if entry.attributes().is_directory() {
            return Err(FsError::IsADirectory);
        }

        let cluster = entry.first_cluster();
        if cluster.is_valid() {
            self.fs.free_cluster_chain_async(cluster).await?;
        }

        Ok(())
    }

    /// Verify that the named entry is an empty directory (async).
    pub(crate) async fn verify_empty_directory_async(&self, name: &str) -> FsResult<()> {
        let target = self.lookup_async(name).await?;
        let attr = target.getattr()?;
        if attr.file_type != Some(FileType::Directory) {
            return Err(FsError::NotADirectory);
        }
        if !target.is_directory_empty_async().await? {
            return Err(FsError::DirectoryNotEmpty);
        }
        Ok(())
    }

    /// 非同期でディレクトリを削除
    pub async fn rmdir_async(&self, name: &str) -> FsResult<()> {
        self.verify_empty_directory_async(name).await?;

        let entry = self.remove_dir_entry_async(name).await?;

        let cluster = entry.first_cluster();
        if cluster.is_valid() {
            self.fs.free_cluster_chain_async(cluster).await?;
        }

        Ok(())
    }

    // ========================================================================
    // rename ヘルパーメソッド群
    // ========================================================================

    /// リネーム先の Fat32Inode をダウンキャストし、同一FS上であることを検証する。
    pub(crate) fn validate_rename_target<'a>(
        &self,
        new_dir: &'a Arc<dyn Inode>,
    ) -> FsResult<&'a Fat32Inode<B>> {
        let other_inode = (**new_dir)
            .as_any()
            .downcast_ref::<Fat32Inode<B>>()
            .ok_or(FsError::CrossDeviceLink)?;
        if !Arc::ptr_eq(&self.fs, &other_inode.fs) {
            return Err(FsError::CrossDeviceLink);
        }
        Ok(other_inode)
    }

    /// ショート名でディレクトリエントリを同期的に検索する。
    pub(crate) fn find_raw_entry_by_short_name(&self, name: &str) -> FsResult<DirEntryRaw> {
        let (raw_entry, _, _) = self
            .scan_dir_entries(|raw, _| {
                if raw.is_deleted()
                    || raw.attributes().is_long_name()
                    || raw.attributes().is_volume_id()
                {
                    return None;
                }
                if raw.short_name().eq_ignore_ascii_case(name) {
                    Some(*raw)
                } else {
                    None
                }
            })?
            .ok_or(FsError::NotFound)?;
        Ok(raw_entry)
    }

    /// ショート名でディレクトリエントリを非同期的に検索する。
    pub(crate) async fn find_raw_entry_by_short_name_async(
        &self,
        name: &str,
    ) -> FsResult<DirEntryRaw> {
        let (raw_entry, _, _) = self
            .scan_dir_entries_async(|raw, _| {
                if raw.is_deleted()
                    || raw.attributes().is_long_name()
                    || raw.attributes().is_volume_id()
                {
                    return None;
                }
                if raw.short_name().eq_ignore_ascii_case(name) {
                    Some(*raw)
                } else {
                    None
                }
            })
            .await?
            .ok_or(FsError::NotFound)?;
        Ok(raw_entry)
    }

    /// ディレクトリ移動時のループ検出（同期版）。
    /// moved_cluster が dest_inode の祖先チェインに含まれていないことを確認する。
    pub(crate) fn check_rename_directory_loop(
        &self,
        moved_cluster: Cluster,
        dest_inode: &Fat32Inode<B>,
    ) -> FsResult<()> {
        let mut curr_cluster = dest_inode.inner.blocking_lock().first_cluster;
        let cluster_size = self.fs.cluster_size();
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while curr_cluster.0 != 0 && curr_cluster != self.fs.root_cluster {
            if curr_cluster == moved_cluster {
                return Err(FsError::InvalidInput);
            }
            let mut buffer =
                PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;
            self.fs.read_cluster(curr_cluster, &mut buffer)?;
            let dotdot = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
                &buffer[DIR_ENTRY_SIZE..DIR_ENTRY_SIZE * 2],
            );
            let next = dotdot.first_cluster();
            if next == curr_cluster {
                break;
            }
            curr_cluster = next;
        }
        Ok(())
    }

    /// ディレクトリ移動時のループ検出（非同期版）。
    pub(crate) async fn check_rename_directory_loop_async(
        &self,
        moved_cluster: Cluster,
        dest_inode: &Fat32Inode<B>,
    ) -> FsResult<()> {
        let mut curr_cluster = dest_inode.inner.blocking_lock().first_cluster;
        let mut chain_count = 0usize;
        let cluster_size = self.fs.cluster_size();
        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while curr_cluster.0 != 0 && curr_cluster != self.fs.root_cluster {
            chain_count += 1;
            if chain_count > MAX_CLUSTER_CHAIN {
                return Err(FsError::InvalidInput);
            }
            if curr_cluster == moved_cluster {
                return Err(FsError::InvalidInput);
            }
            self.fs
                .read_cluster_async(curr_cluster, &mut buffer)
                .await?;
            let dotdot = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
                &buffer[DIR_ENTRY_SIZE..DIR_ENTRY_SIZE * 2],
            );
            let next = dotdot.first_cluster();
            if next == curr_cluster {
                break;
            }
            curr_cluster = next;
        }
        Ok(())
    }

    /// 移動されたディレクトリの ".." エントリを新しい親に更新する（同期版）。
    pub(crate) fn update_dotdot_entry(
        &self,
        cluster: Cluster,
        new_parent_cluster: Cluster,
    ) -> FsResult<()> {
        let cluster_size = self.fs.cluster_size();
        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;
        self.fs.read_cluster(cluster, &mut buffer)?;
        let dotdot_offset = DIR_ENTRY_SIZE;
        let mut dotdot = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
            &buffer[dotdot_offset..dotdot_offset + DIR_ENTRY_SIZE],
        );
        let new_parent_val = if new_parent_cluster == self.fs.root_cluster {
            Cluster(0)
        } else {
            new_parent_cluster
        };
        dotdot.set_first_cluster(new_parent_val);
        dotdot.write_bytes_to(&mut buffer[dotdot_offset..dotdot_offset + DIR_ENTRY_SIZE]);
        self.fs.write_cluster(cluster, &buffer)?;
        Ok(())
    }

    /// 移動されたディレクトリの ".." エントリを新しい親に更新する（非同期版）。
    pub(crate) async fn update_dotdot_entry_async(
        &self,
        cluster: Cluster,
        new_parent_cluster: Cluster,
    ) -> FsResult<()> {
        let cluster_size = self.fs.cluster_size();
        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;
        self.fs.read_cluster_async(cluster, &mut buffer).await?;
        let dotdot_offset = DIR_ENTRY_SIZE;
        let mut dotdot = <DirEntryRaw as SafePackedRead>::from_bytes_safe(
            &buffer[dotdot_offset..dotdot_offset + DIR_ENTRY_SIZE],
        );
        let new_parent_val = if new_parent_cluster == self.fs.root_cluster {
            Cluster(0)
        } else {
            new_parent_cluster
        };
        dotdot.set_first_cluster(new_parent_val);
        dotdot.write_bytes_to(&mut buffer[dotdot_offset..dotdot_offset + DIR_ENTRY_SIZE]);
        self.fs.write_cluster_async(cluster, &buffer).await?;
        Ok(())
    }

    // ========================================================================
    // rename 本体
    // ========================================================================

    /// rename の共通ロジック: エントリを新ディレクトリに追加し、旧エントリを削除する。
    /// ディレクトリの場合はループ検出と ".." エントリ更新を行う。
    pub(crate) fn perform_rename_sync(
        &self,
        old_name: &str,
        other_inode: &Fat32Inode<B>,
        new_name: &str,
    ) -> FsResult<()> {
        let raw_entry = self.find_raw_entry_by_short_name(old_name)?;
        let cluster = raw_entry.first_cluster();
        let attr = raw_entry.attributes();
        let size = raw_entry.file_size();

        let is_dir = attr.is_directory();

        if is_dir {
            self.check_rename_directory_loop(cluster, other_inode)?;
        }

        other_inode.add_dir_entry(new_name, cluster, attr, size)?;
        self.remove_dir_entry(old_name)?;

        if is_dir && cluster.is_valid() {
            let new_parent = other_inode.inner.blocking_lock().first_cluster;
            self.update_dotdot_entry(cluster, new_parent)?;
        }

        Ok(())
    }

    /// 非同期でリネーム/移動
    pub async fn rename_async(
        &self,
        old_name: &str,
        new_dir: &Arc<dyn Inode>,
        new_name: &str,
    ) -> FsResult<()> {
        validate_path_length(old_name)?;
        validate_path_length(new_name)?;

        let other_inode = self.validate_rename_target(new_dir)?;

        if other_inode.lookup_async(new_name).await.is_ok() {
            return Err(FsError::AlreadyExists);
        }

        let raw_entry = self.find_raw_entry_by_short_name_async(old_name).await?;
        let cluster = raw_entry.first_cluster();
        let attr = raw_entry.attributes();
        let size = raw_entry.file_size();

        if attr.is_directory() {
            self.check_rename_directory_loop_async(cluster, other_inode)
                .await?;
        }

        other_inode
            .add_dir_entry_async(new_name, cluster, attr, size)
            .await?;

        self.remove_dir_entry_async(old_name).await?;

        if attr.is_directory() && cluster.is_valid() {
            let new_parent = other_inode.inner.blocking_lock().first_cluster;
            self.update_dotdot_entry_async(cluster, new_parent).await?;
        }

        Ok(())
    }

    pub(crate) fn rename(
        &self,
        old_name: &str,
        new_dir: &Arc<dyn Inode>,
        new_name: &str,
    ) -> FsResult<()> {
        validate_path_length(old_name)?;
        validate_path_length(new_name)?;

        let other_inode = self.validate_rename_target(new_dir)?;

        if other_inode.lookup(new_name).is_ok() {
            return Err(FsError::AlreadyExists);
        }

        self.perform_rename_sync(old_name, other_inode, new_name)
    }

    pub(crate) fn link(&self, _name: &str, _inode: &Arc<dyn Inode>) -> FsResult<()> {
        // FAT32はハードリンクをサポートしない
        Err(FsError::NotSupported)
    }

    pub(crate) fn symlink(&self, _name: &str, _target: &str) -> FsResult<Arc<dyn Inode>> {
        // FAT32はシンボリックリンクをサポートしない
        Err(FsError::NotSupported)
    }

    pub(crate) fn readlink(&self) -> FsResult<String> {
        Err(FsError::NotSupported)
    }

    /// ゼロコピーでファイルを読み取り（所有権移動、Async）
    ///
    /// 注意: オフセット/長さの端数はセグメントの範囲で表現し、コピーは行わない。
    pub async fn read_zero_copy_async(&self, offset: u64, len: usize) -> FsResult<ZeroCopyRead<B>> {
        if self.file_type != FileType::File {
            return Err(FsError::IsADirectory);
        }

        let guard = self.inner.lock_async().await;
        let (size, first_cluster) = (guard.size, guard.first_cluster);

        if offset >= size || len == 0 || !first_cluster.is_valid() {
            return Ok(ZeroCopyRead::Scatter(Vec::new()));
        }

        let cluster_size = self.fs.cluster_size() as u64;
        let to_read = len.min((size - offset) as usize);

        // 開始クラスタまで進める
        let start_cluster_idx = (offset / cluster_size) as usize;
        let current_cluster = self
            .seek_to_cluster_async(first_cluster, start_cluster_idx)
            .await?;

        let current_offset = (offset % cluster_size) as usize;
        let segments = self
            .collect_zero_copy_segments_async(current_cluster, current_offset, to_read)
            .await?;

        Ok(if segments.len() == 1 {
            ZeroCopyRead::Single(segments.into_iter().next().unwrap())
        } else {
            ZeroCopyRead::Scatter(segments)
        })
    }

    /// 指定インデックスまでクラスタチェインを辿る（非同期）
    pub(crate) async fn seek_to_cluster_async(
        &self,
        start: Cluster,
        count: usize,
    ) -> FsResult<Cluster> {
        let mut current = start;
        for _ in 0..count {
            let next = self.fs.read_fat_entry_async(current).await?;
            if next.is_eof() || !next.is_valid() {
                return Ok(Cluster(0)); // invalid sentinel
            }
            current = next;
        }
        Ok(current)
    }

    /// 単一のゼロコピーセグメントを構築する
    pub(crate) async fn build_zero_copy_segment(
        &self,
        current_cluster: Cluster,
        current_offset: usize,
        remaining: usize,
    ) -> FsResult<Option<(ZeroCopySegment<B>, usize)>> {
        let (_last, run_count) = self
            .find_contiguous_run_async(current_cluster, remaining + current_offset)
            .await?;

        let buffer = self
            .fs
            .read_contiguous_clusters_zero_copy(current_cluster, run_count)
            .await?;

        let available = buffer.len().saturating_sub(current_offset);
        let take = remaining.min(available);
        if take == 0 {
            return Ok(None);
        }

        Ok(Some((
            ZeroCopySegment {
                buffer,
                offset: current_offset,
                len: take,
            },
            take,
        )))
    }

    /// ゼロコピーセグメントを収集する（非同期）
    pub(crate) async fn collect_zero_copy_segments_async(
        &self,
        start_cluster: Cluster,
        start_offset: usize,
        total: usize,
    ) -> FsResult<Vec<ZeroCopySegment<B>>> {
        let mut remaining = total;
        let mut current_offset = start_offset;
        let mut current_cluster = start_cluster;
        let mut segments: Vec<ZeroCopySegment<B>> = Vec::new();

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while remaining > 0 && current_cluster.is_valid() {
            let seg = self
                .build_zero_copy_segment(current_cluster, current_offset, remaining)
                .await?;

            let take = match seg {
                Some((segment, taken)) => {
                    segments.push(segment);
                    taken
                }
                None => break,
            };

            remaining -= take;
            current_offset = 0;

            if remaining == 0 {
                break;
            }

            let (last, _) = self
                .find_contiguous_run_async(current_cluster, take + current_offset)
                .await?;
            let next = self.fs.read_fat_entry_async(last).await?;
            if next.is_eof() || !next.is_valid() {
                break;
            }
            current_cluster = next;
        }

        Ok(segments)
    }

    /// 連続したクラスタのランを検出する（非同期）
    pub(crate) async fn find_contiguous_run_async(
        &self,
        start: Cluster,
        max_bytes: usize,
    ) -> FsResult<(Cluster, usize)> {
        let max_clusters =
            ((max_bytes + self.fs.cluster_size() - 1) / self.fs.cluster_size()).max(1);
        let mut run_count = 1usize;
        let mut last = start;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while run_count < max_clusters {
            let next = self.fs.read_fat_entry_async(last).await?;
            if next.is_eof() || !next.is_valid() || next.0 != last.0 + 1 {
                break;
            }
            run_count += 1;
            last = next;
        }
        Ok((last, run_count))
    }
}
