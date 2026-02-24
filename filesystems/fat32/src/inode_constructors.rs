use crate::*;

impl<B: ZeroCopyBufferMut + 'static> Fat32Inode<B> {
    /// 新しいディレクトリinodeを作成
    pub fn new_directory(
        fs: Arc<Fat32FileSystem<B>>,
        cluster: Cluster,
        parent: Cluster,
        name: String,
    ) -> Self {
        Self {
            fs,
            file_type: FileType::Directory,
            inner: AsyncMutex::new(Fat32InodeInner {
                first_cluster: cluster,
                size: 0,
                parent_cluster: parent,
                name,
                attributes: FileAttributes::from_bits_truncate(FileAttributes::DIRECTORY),
                created: 0,
                modified: 0,
                accessed: 0,
            }),
        }
    }

    /// 新しいファイルinodeを作成
    pub fn new_file(
        fs: Arc<Fat32FileSystem<B>>,
        cluster: Cluster,
        size: u64,
        parent: Cluster,
        name: String,
    ) -> Self {
        Self {
            fs,
            file_type: FileType::File,
            inner: AsyncMutex::new(Fat32InodeInner {
                first_cluster: cluster,
                size,
                parent_cluster: parent,
                name,
                attributes: FileAttributes::from_bits_truncate(FileAttributes::ARCHIVE),
                created: 0,
                modified: 0,
                accessed: 0,
            }),
        }
    }

    pub(crate) fn from_raw(
        fs: Arc<Fat32FileSystem<B>>,
        parent: Cluster,
        name: String,
        raw: &DirEntryRaw,
    ) -> Self {
        let file_type = if raw.is_directory() {
            FileType::Directory
        } else {
            FileType::File
        };
        Self {
            fs,
            file_type,
            inner: AsyncMutex::new(Fat32InodeInner {
                first_cluster: raw.first_cluster(),
                size: raw.file_size() as u64,
                parent_cluster: parent,
                name,
                attributes: raw.attributes(),
                created: dos_to_unix(raw.create_date(), raw.create_time()),
                modified: dos_to_unix(raw.modify_date(), raw.modify_time()),
                accessed: dos_to_unix(raw.access_date(), 0),
            }),
        }
    }

    /// Resolve the effective name of a Standard directory entry, consuming any
    /// accumulated LFN parts. Returns the resolved name and clears `lfn_parts`.
    pub(crate) fn resolve_entry_name(
        raw: &DirEntryRaw,
        lfn_parts: &mut Vec<(u8, String, u8)>,
    ) -> String {
        if !lfn_parts.is_empty() {
            let expected_checksum = raw.calculate_checksum();
            if lfn_parts
                .first()
                .map_or(false, |&(_, _, cs)| cs == expected_checksum)
            {
                lfn_parts.sort_by_key(|&(seq, _, _)| seq);
                let long_name: String = lfn_parts.iter().map(|(_, s, _)| s.as_str()).collect();
                lfn_parts.clear();
                long_name
            } else {
                lfn_parts.clear();
                raw.short_name()
            }
        } else {
            raw.short_name()
        }
    }

    /// ディレクトリエントリを分類しSFN名を確認する
    pub(crate) fn match_sfn_entry(
        kind: DirectoryEntryKind,
        lfn_parts: &mut Vec<(u8, String, u8)>,
        name_to_find: &str,
        cluster: Cluster,
        offset: usize,
    ) -> FsResult<Option<Option<(Cluster, usize)>>> {
        match kind {
            DirectoryEntryKind::End => Ok(Some(None)),
            DirectoryEntryKind::Deleted => {
                lfn_parts.clear();
                Ok(None)
            }
            DirectoryEntryKind::LongName(lfn) => {
                if lfn_parts.len() >= MAX_LFN_PARTS {
                    return Err(FsError::FileSystemCorrupted);
                }
                lfn_parts.push((lfn.sequence(), lfn.get_name_part(), lfn.checksum()));
                Ok(None)
            }
            DirectoryEntryKind::VolumeLabel => {
                lfn_parts.clear();
                Ok(None)
            }
            DirectoryEntryKind::Standard(raw) => {
                let name = Self::resolve_entry_name(&raw, lfn_parts);
                if name.eq_ignore_ascii_case(name_to_find) {
                    Ok(Some(Some((cluster, offset))))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// 指定された名前を持つSFNエントリの場所（クラスタとオフセット）を検索します。
    /// このメソッドはロングファイルネームを正しく処理します。
    pub(crate) fn find_sfn_location(
        &self,
        name_to_find: &str,
    ) -> FsResult<Option<(Cluster, usize)>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }
        let inner = self.inner.blocking_lock();

        let cluster_size = self.fs.cluster_size();
        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;
        let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;

        let mut lfn_parts: Vec<(u8, String, u8)> = Vec::new();

        for cluster_res in self.fs.clusters(inner.first_cluster) {
            let cluster = cluster_res?;
            self.fs.read_cluster(cluster, &mut buffer)?;

            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let entry_bytes = &buffer[offset..offset + DIR_ENTRY_SIZE];

                let kind = DirectoryEntryKind::from(entry_bytes);
                match Self::match_sfn_entry(kind, &mut lfn_parts, name_to_find, cluster, offset)? {
                    Some(result) => return Ok(result),
                    None => continue,
                }
            }
        }
        Ok(None)
    }

    /// Validate that this inode is a directory and return its start cluster (if valid).
    pub(crate) fn validate_directory_cluster(&self) -> FsResult<Option<Cluster>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }
        let start_cluster = self.inner.blocking_lock().first_cluster;
        if !start_cluster.is_valid() {
            return Ok(None);
        }
        Ok(Some(start_cluster))
    }

    /// Read the next cluster in the FAT chain, returning `None` at EOF.
    pub(crate) async fn read_next_cluster_async(
        &self,
        current: Cluster,
    ) -> FsResult<Option<Cluster>> {
        let next = self.fs.read_fat_entry_async(current).await?;
        if next.is_eof() || !next.is_valid() {
            Ok(None)
        } else {
            Ok(Some(next))
        }
    }

    /// Walk the cluster chain searching for an SFN entry matching `name`.
    pub(crate) async fn walk_clusters_for_sfn_async(
        &self,
        start: Cluster,
        name: &str,
    ) -> FsResult<Option<(Cluster, usize)>> {
        let cluster_size = self.fs.cluster_size();
        let mut buffer =
            PooledClusterBuffer::new(self.fs.cluster_buffer_pool.as_ref(), cluster_size)?;
        let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;

        let mut lfn_parts: Vec<(u8, String, u8)> = Vec::new();
        let mut current = start;

        for _ in 0..MAX_CLUSTER_CHAIN {
            if !current.is_valid() {
                return Ok(None);
            }

            self.fs.read_cluster_async(current, &mut buffer).await?;

            if let Some(result) =
                search_cluster_for_sfn(&buffer, entries_per_cluster, name, &mut lfn_parts, current)?
            {
                return Ok(result);
            }

            current = self
                .read_next_cluster_async(current)
                .await?
                .unwrap_or(Cluster(0));
        }

        Err(FsError::FileSystemCorrupted)
    }

    /// 非同期で指定された名前を持つSFNエントリの場所を検索します。
    pub(crate) async fn find_sfn_location_async(
        &self,
        name_to_find: &str,
    ) -> FsResult<Option<(Cluster, usize)>> {
        let start_cluster = match self.validate_directory_cluster()? {
            Some(c) => c,
            None => return Ok(None),
        };
        self.walk_clusters_for_sfn_async(start_cluster, name_to_find)
            .await
    }
}
