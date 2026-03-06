use crate::{
    Box, Cluster, Fat32FileSystem, Fat32Inode, FileSystem, FsError, FsResult, Inode, String,
    ZeroCopyBufferMut,
};

use core::fmt;

impl<B: ZeroCopyBufferMut + 'static> FileSystem for Fat32FileSystem<B> {
    fn name(&self) -> &str {
        "fat32"
    }

    fn root_dir(&self) -> FsResult<Box<dyn Inode>> {
        let fs_arc = self.self_weak.upgrade().ok_or(FsError::IoError)?;
        Ok(Box::new(Fat32Inode::new_directory(
            fs_arc,
            self.root_cluster,
            Cluster(0), // ルートの親は0とする
            String::from("/"),
        )))
    }
}

/// 構造的なデバッグ出力（deviceフィールドは省略）
impl<B: ZeroCopyBufferMut + 'static> fmt::Debug for Fat32FileSystem<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fat32FileSystem")
            .field("fat_start_sector", &self.fat_start_sector)
            .field("data_start_sector", &self.data_start_sector)
            .field("sectors_per_cluster", &self.sectors_per_cluster)
            .field("total_clusters", &self.total_clusters)
            .field("root_cluster", &self.root_cluster)
            .field("free_clusters", &*self.free_clusters.blocking_lock())
            .field("fat_size", &self.fat_size)
            .finish_non_exhaustive() // "device" フィールドは省略
    }
}
