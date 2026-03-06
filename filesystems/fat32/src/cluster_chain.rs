use crate::{
    CYCLE_CHECK_INTERVAL, Cluster, Fat32FileSystem, FsError, FsResult, MAX_CLUSTER_CHAIN,
    ZeroCopyBufferMut,
};

/// クラスタチェーンを走査するイテレータ
///
/// FAT32のクラスタチェーンをRustのイテレータとして抽象化。
/// `while cluster.is_valid() { ... get_next ... }` のループパターンを
/// 排除し、`for`ループや`skip()`、`take()`等のイテレータメソッドを活用可能にする。
///
/// # Example
/// ```ignore
/// // 3番目のクラスタから読み取り開始
/// for cluster_res in fs.clusters(start).skip(2) {
///     let cluster = cluster_res?;
///     // クラスタを処理
/// }
/// ```
pub struct ClusterChain<'a, B: ZeroCopyBufferMut + 'static> {
    fs: &'a Fat32FileSystem<B>,
    current: Cluster,
    count: usize,
}

impl<'a, B: ZeroCopyBufferMut + 'static> ClusterChain<'a, B> {
    /// 新しいクラスタチェーンイテレータを作成
    pub(crate) fn new(fs: &'a Fat32FileSystem<B>, start: Cluster) -> Self {
        Self {
            fs,
            current: start,
            count: 0,
        }
    }

    /// Floyd の tortoise-hare アルゴリズムでクラスタチェーンの循環を検出する
    fn detect_cycle_floyd(&self) -> bool {
        let mut tortoise = self.current;
        let mut hare = self.current;
        loop {
            tortoise = match self.advance_fat_once(tortoise) {
                Some(t) => t,
                None => return false,
            };
            hare = match self
                .advance_fat_once(hare)
                .and_then(|h1| self.advance_fat_once(h1))
            {
                Some(h) => h,
                None => return false,
            };
            if tortoise == hare {
                return true;
            }
        }
    }

    /// FATエントリを1つ読み進め、有効かつEOFでなければ次のクラスタを返す
    fn advance_fat_once(&self, cluster: Cluster) -> Option<Cluster> {
        match self.fs.read_fat_entry(cluster) {
            Ok(n) if n.is_valid() && !n.is_eof() => Some(n),
            _ => None,
        }
    }
}

impl<'a, B: ZeroCopyBufferMut + 'static> Iterator for ClusterChain<'a, B> {
    type Item = FsResult<Cluster>;

    fn next(&mut self) -> Option<Self::Item> {
        // 無効なクラスタは終端
        if !self.current.is_valid() {
            return None;
        }

        // 無限ループ検出 (bounded by total_clusters + 1 and global MAX_CLUSTER_CHAIN)
        self.count += 1;
        let max = core::cmp::min(
            (self.fs.total_clusters as usize).saturating_add(1),
            MAX_CLUSTER_CHAIN,
        );
        if self.count > max {
            self.current = Cluster::EOF;
            return Some(Err(FsError::FileSystemCorrupted));
        }

        let current = self.current;

        // 定期的にFloyd法（tortoise-hare）で循環を検出
        if self.count > CYCLE_CHECK_INTERVAL && (self.count % CYCLE_CHECK_INTERVAL == 0) {
            if self.detect_cycle_floyd() {
                self.current = Cluster::EOF;
                return Some(Err(FsError::FileSystemCorrupted));
            }
        }

        // 次のクラスタを取得して状態を更新
        match self.fs.read_fat_entry(current) {
            Ok(next) => {
                self.current = next;
                Some(Ok(current))
            }
            Err(e) => {
                self.current = Cluster::EOF;
                Some(Err(e))
            }
        }
    }
}
