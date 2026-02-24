use crate::sfn::{DirEntryAction, process_dir_entry};
use crate::*;

/// ディレクトリエントリを遅延評価で読み込むイテレータ
///
/// 従来の `read_dir_entries` は全エントリを `Vec` に読み込んでいたが、
/// このイテレータは必要な分だけを読み込む。
///
/// # メリット
/// - **メモリ効率**: エントリ数が多い場合でも巨大な Vec を確保しない
/// - **検索パフォーマンス**: `lookup` で特定ファイルを探す際、見つかった時点で読み込みを停止
/// - **Rustらしさ**: `find()`, `filter()`, `take()` 等のイテレータメソッドが使用可能
///
/// # カーネル統合上の注意
/// ⚠️ **バッファ確保**: `ClusterBufferPool` から取得しますが、枯渇時はヒープ確保が発生します。
/// 大量のイテレータを同時に保持する場合、メモリ消費が増大する可能性があります。
///
/// 最適化オプション:
/// - **LRUキャッシュ**: よく参照されるディレクトリのバッファを再利用（Mempool推奨）
/// - **Per-CPUバッファ**: タスクごとではなく、CPUコアごとに共有バッファを使用
/// - **ページアロケータ**: 4KB単位でのアロケーションに切り替え（クラスタサイズ < 64KB時）
///
/// # Example
/// ```ignore
/// // 特定のファイルを検索（見つかったら即終了）
/// let entry = inode.entries()?
///     .find(|res| res.as_ref().ok()
///         .map(|e| e.name == "target.txt")
///         .unwrap_or(false))
///     .transpose()?;
/// ```
pub struct DirectoryIterator<'a, B: ZeroCopyBufferMut + 'static> {
    fs: &'a Fat32FileSystem<B>,
    chain: ClusterChain<'a, B>,
    buffer: PooledClusterBuffer<'a>,
    offset: usize,
    lfn_parts: Vec<(u8, bool, String, u8)>, // (sequence, is_last, name_part, checksum)
    finished: bool,
}

impl<'a, B: ZeroCopyBufferMut + 'static> DirectoryIterator<'a, B> {
    /// 新しいディレクトリイテレータを作成
    pub(crate) fn new(fs: &'a Fat32FileSystem<B>, start_cluster: Cluster) -> FsResult<Self> {
        let cluster_size = fs.cluster_size();
        let mut chain = fs.clusters(start_cluster);
        let mut buffer = PooledClusterBuffer::new(fs.cluster_buffer_pool.as_ref(), cluster_size)?;

        // 最初のクラスタを読み込む
        if let Some(cluster_res) = chain.next() {
            let cluster = cluster_res?;
            fs.read_cluster(cluster, &mut buffer)?;
        }

        Ok(Self {
            fs,
            chain,
            buffer,
            offset: 0,
            lfn_parts: Vec::new(),
            finished: false,
        })
    }

    /// 次のクラスタを読み込む
    fn load_next_cluster(&mut self) -> FsResult<bool> {
        if let Some(cluster_res) = self.chain.next() {
            let cluster = cluster_res?;
            self.fs.read_cluster(cluster, &mut self.buffer)?;
            self.offset = 0;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<'a, B: ZeroCopyBufferMut + 'static> Iterator for DirectoryIterator<'a, B> {
    type Item = FsResult<(String, DirEntryRaw)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let cluster_size = self.fs.cluster_size();

        loop {
            // バッファの範囲を超えたら次のクラスタを読み込む
            if self.offset + DIR_ENTRY_SIZE > cluster_size {
                match self.load_next_cluster() {
                    Ok(true) => continue,
                    Ok(false) => {
                        self.finished = true;
                        return None;
                    }
                    Err(e) => {
                        self.finished = true;
                        return Some(Err(e));
                    }
                }
            }

            let entry_bytes = &self.buffer[self.offset..self.offset + DIR_ENTRY_SIZE];
            self.offset += DIR_ENTRY_SIZE;

            match process_dir_entry(entry_bytes, &mut self.lfn_parts) {
                DirEntryAction::EndOfDir => {
                    self.finished = true;
                    return None;
                }
                DirEntryAction::Skip => continue,
                DirEntryAction::Corrupted => {
                    self.finished = true;
                    return Some(Err(FsError::FileSystemCorrupted));
                }
                DirEntryAction::Found(name, raw) => {
                    return Some(Ok((name, raw)));
                }
            }
        }
    }
}

// ============================================================================
// DirectoryIterator Extension Methods
// ============================================================================

impl<'a, B: ZeroCopyBufferMut + 'static> DirectoryIterator<'a, B> {
    /// イテレータが完全に消費されたかチェック
    ///
    /// # Example
    /// ```ignore
    /// let mut iter = inode.entries()?;
    /// while let Some(_) = iter.next() { /* ... */ }
    /// assert!(iter.is_exhausted());
    /// ```
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.finished
    }

    /// 残りのエントリ数を推定（Iterator traitのsize_hintと同等）
    ///
    /// FAT32ディレクトリの性質上、正確な残り数は事前に分からないため、
    /// 下限は0、上限は不明(None)となる。デバッグ・進捗表示用。
    pub fn size_hint(&self) -> (usize, Option<usize>) {
        if self.finished {
            (0, Some(0))
        } else {
            // FAT32ディレクトリは可変長のため、正確な数は不明
            (0, None)
        }
    }

    /// ファイルのみをフィルタするイテレータを返す
    ///
    /// # Example
    /// ```ignore
    /// let files: Vec<_> = inode.entries()?.files().collect::<Result<Vec<_>, _>>()?;
    /// ```
    pub fn files(self) -> impl Iterator<Item = FsResult<(String, DirEntryRaw)>> + 'a {
        self.filter(|res| {
            res.as_ref()
                .map(|(_, raw)| !raw.is_directory())
                .unwrap_or(true) // エラーの場合は通過させて後で処理
        })
    }

    /// ディレクトリのみをフィルタするイテレータを返す
    ///
    /// # Example
    /// ```ignore
    /// let dirs: Vec<_> = inode.entries()?.directories().collect::<Result<Vec<_>, _>>()?;
    /// ```
    pub fn directories(self) -> impl Iterator<Item = FsResult<(String, DirEntryRaw)>> + 'a {
        self.filter(|res| {
            res.as_ref()
                .map(|(_, raw)| raw.is_directory())
                .unwrap_or(true)
        })
    }

    /// 隠しファイルを除外するイテレータを返す
    ///
    /// # Example
    /// ```ignore
    /// let visible_files: Vec<_> = inode.entries()?.visible().collect::<Result<Vec<_>, _>>()?;
    /// ```
    pub fn visible(self) -> impl Iterator<Item = FsResult<(String, DirEntryRaw)>> + 'a {
        self.filter(|res| {
            res.as_ref()
                .map(|(_, raw)| !raw.attributes().is_hidden())
                .unwrap_or(true)
        })
    }

    /// 名前でエントリを検索（大文字小文字を無視）
    ///
    /// # Example
    /// ```ignore
    /// let entry = inode.entries()?.find_by_name("readme.txt")?;
    /// ```
    pub fn find_by_name(mut self, name: &str) -> FsResult<Option<(String, DirEntryRaw)>> {
        self.find(|res| {
            res.as_ref()
                .map(|(entry_name, _)| entry_name.eq_ignore_ascii_case(name))
                .unwrap_or(false)
        })
        .transpose()
    }
}

// ============================================================================
