use crate::*;

// ============================================================================
// Filesystem Check (fsck)
// ============================================================================

/// ファイルシステムチェックで検出された問題の種類
#[derive(Debug, Clone)]
pub enum FsckIssue {
    /// 無効なFATエントリ
    InvalidFatEntry { cluster: u32, value: u32 },
    /// 循環参照
    CircularReference { cluster: u32 },
    /// ロストクラスタ（使用中だがどのファイルにも属さない）
    LostCluster { cluster: u32 },
    /// ファイルサイズ不一致
    SizeMismatch {
        cluster: u32,
        expected: u64,
        actual: u64,
    },
    /// FSInfo不整合
    InvalidFsInfo { message: &'static str },
}

/// ファイルシステムチェック結果
#[derive(Debug, Clone, Default)]
pub struct FsckResult {
    /// 検出された問題
    pub issues: Vec<FsckIssue>,
    /// スキャンしたクラスタ数
    pub scanned_clusters: u32,
    /// ロストクラスタ数
    pub lost_clusters: u32,
    /// 修復されたエラー数
    pub fixed_count: u32,
}

impl FsckResult {
    /// エラーがあるかどうか
    pub fn has_errors(&self) -> bool {
        !self.issues.is_empty()
    }

    /// エラー数を取得
    pub fn error_count(&self) -> usize {
        self.issues.len()
    }
}

impl Fat32FileSystem<DefaultZeroCopyBuffer> {
    /// 全FATエントリをスキャンし、使用済みクラスタビットマップと問題を記録する
    fn scan_fat_entries_for_fsck(
        &self,
        result: &mut FsckResult,
        used_clusters: &mut Vec<bool>,
    ) -> FsResult<()> {
        for cluster_idx in 2..self.total_clusters + 2 {
            result.scanned_clusters += 1;
            let cluster = Cluster(cluster_idx);

            let entry = match self.read_fat_entry(cluster) {
                Ok(e) => e,
                Err(_) => {
                    result.issues.push(FsckIssue::InvalidFatEntry {
                        cluster: cluster_idx,
                        value: 0xFFFFFFFF,
                    });
                    continue;
                }
            };

            if !entry.is_free() {
                if cluster_idx < used_clusters.len() as u32 {
                    used_clusters[cluster_idx as usize] = true;
                }

                if !entry.is_valid() && !entry.is_eof() && entry != Cluster::BAD {
                    result.issues.push(FsckIssue::InvalidFatEntry {
                        cluster: cluster_idx,
                        value: entry.0,
                    });
                }
            }
        }
        Ok(())
    }

    /// FSInfoセクタの整合性を検証し、必要に応じて修復する
    fn verify_and_repair_fsinfo(
        &self,
        result: &mut FsckResult,
        used_clusters: &[bool],
        repair: bool,
    ) {
        match self.read_fsinfo() {
            Ok(fsinfo) => {
                let actual_free =
                    used_clusters.iter().skip(2).filter(|&&used| !used).count() as u32;
                if let Some(reported) = fsinfo.free_count() {
                    if reported != actual_free && reported != 0 {
                        result.issues.push(FsckIssue::InvalidFsInfo {
                            message: "Free cluster count mismatch",
                        });

                        if repair {
                            *self.free_clusters.blocking_lock() = actual_free;
                            if self.write_fsinfo().is_ok() {
                                result.fixed_count += 1;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                result.issues.push(FsckIssue::InvalidFsInfo {
                    message: "Cannot read FSInfo sector",
                });
            }
        }
    }

    /// ファイルシステムの整合性チェック
    ///
    /// # Arguments
    /// * `repair` - true の場合、可能な問題を修復する
    ///
    /// # Returns
    /// チェック結果
    pub fn fsck(&self, repair: bool) -> FsResult<FsckResult> {
        let mut result = FsckResult::default();

        let mut used_clusters = try_alloc_vec(self.total_clusters as usize + 2, false)?;
        used_clusters[0] = true;
        used_clusters[1] = true;

        self.scan_fat_entries_for_fsck(&mut result, &mut used_clusters)?;
        self.verify_and_repair_fsinfo(&mut result, &used_clusters, repair);

        result.lost_clusters = 0;

        Ok(result)
    }
}
