use crate::*;

/// FATセクタのLRUキャッシュ
///
/// 大容量ボリュームでFATテーブル全体をメモリに持たないために使用。
/// セクタ単位でキャッシュし、アクセス頻度の低いセクタを自動的に破棄する。
///
/// # スレッド安全性
/// 内部でIrqPoisonLockを使用しているため、割り込み安全かつ複数スレッドから安全にアクセス可能。
pub struct FatSectorCache {
    /// キャッシュデータ: セクタインデックス -> (エントリ配列, ダーティフラグ)
    cache: IrqPoisonLock<FatSectorCacheInner>,
    /// 最大キャッシュセクタ数
    max_sectors: usize,
}

/// FatSectorCacheの内部データ
struct FatSectorCacheInner {
    /// セクタデータ: セクタインデックス -> Clusterエントリバッファ（共有参照で保持、書き込みは局所的ロック）
    sectors: HashMap<u32, Arc<IrqPoisonLock<Box<[Cluster]>>>>,
    /// ダーティフラグ: セクタインデックス -> 書き込み必要フラグ
    dirty: HashSet<u32>,
    /// アクセス順序を追跡（最後にアクセスしたものが末尾）
    access_order: Vec<u32>,
}

impl FatSectorCache {
    /// 新しいFATセクタキャッシュを作成
    pub fn new(max_sectors: usize) -> Self {
        Self {
            cache: IrqPoisonLock::new(FatSectorCacheInner {
                sectors: HashMap::with_capacity(max_sectors),
                dirty: HashSet::new(),
                access_order: Vec::with_capacity(max_sectors),
            }),
            max_sectors,
        }
    }

    /// キャッシュからセクタを取得（存在しない場合はNone）
    /// 戻り値は各セクタをロックで保護した `Arc<IrqPoisonLock<Box<[Cluster]>>>` です。
    pub fn get(&self, sector_index: u32) -> Option<Arc<IrqPoisonLock<Box<[Cluster]>>>> {
        let mut inner = self.cache.lock();
        if let Some(entry_arc) = inner.sectors.get(&sector_index).cloned() {
            // アクセス順序を更新
            inner.access_order.retain(|&s| s != sector_index);
            inner.access_order.push(sector_index);
            return Some(entry_arc);
        }

        None
    }

    /// セクタをキャッシュに追加
    ///
    /// キャッシュが満杯の場合、最も古いセクタを破棄（ダーティなら先にフラッシュが必要）
    pub fn insert(
        &self,
        sector_index: u32,
        data: Vec<Cluster>,
    ) -> Option<(u32, Arc<IrqPoisonLock<Box<[Cluster]>>>, bool)> {
        let mut inner = self.cache.lock();

        let data_boxed = data.into_boxed_slice();
        let data_arc: Arc<IrqPoisonLock<Box<[Cluster]>>> = Arc::new(IrqPoisonLock::new(data_boxed));

        // 既に存在する場合は更新
        if inner.sectors.contains_key(&sector_index) {
            inner.sectors.insert(sector_index, Arc::clone(&data_arc));
            inner.access_order.retain(|&s| s != sector_index);
            inner.access_order.push(sector_index);
            return None;
        }

        // キャッシュが満杯の場合、最も古いセクタを破棄
        let evicted = if inner.sectors.len() >= self.max_sectors && !inner.access_order.is_empty() {
            let oldest = inner.access_order.remove(0);
            let evicted_data = inner.sectors.remove(&oldest);
            let was_dirty = inner.dirty.remove(&oldest);
            evicted_data.map(|d| (oldest, d, was_dirty))
        } else {
            None
        };

        inner.sectors.insert(sector_index, Arc::clone(&data_arc));
        inner.access_order.push(sector_index);

        evicted
    }

    /// セクタをダーティとしてマーク
    pub fn mark_dirty(&self, sector_index: u32) {
        let mut inner = self.cache.lock();
        if inner.sectors.contains_key(&sector_index) {
            inner.dirty.insert(sector_index);
        }
    }

    /// セクタ内の特定エントリを更新
    pub fn update_entry(&self, sector_index: u32, offset: usize, value: Cluster) -> bool {
        // まず Arc を取得して LRU を更新（キャッシュ存在確認）
        let sector_arc_opt = {
            let mut inner = self.cache.lock();
            if let Some(entry_arc) = inner.sectors.get(&sector_index).cloned() {
                inner.access_order.retain(|&s| s != sector_index);
                inner.access_order.push(sector_index);
                Some(entry_arc)
            } else {
                None
            }
        };

        if let Some(sector_arc) = sector_arc_opt {
            let mut sector = sector_arc.lock();
            if offset < sector.len() {
                sector[offset] = value;
                // 書き込みが成功したらダーティフラグを付ける
                let mut inner = self.cache.lock();
                inner.dirty.insert(sector_index);
                return true;
            }
        }

        false
    }

    /// セクタ内の特定エントリを条件付きで更新
    ///
    /// 現在値が `expected` の場合のみ `value` を書き込み、成功時はtrueを返す。
    pub fn update_entry_if(
        &self,
        sector_index: u32,
        offset: usize,
        expected: Cluster,
        value: Cluster,
    ) -> bool {
        let sector_arc_opt = {
            let mut inner = self.cache.lock();
            if let Some(entry_arc) = inner.sectors.get(&sector_index).cloned() {
                inner.access_order.retain(|&s| s != sector_index);
                inner.access_order.push(sector_index);
                Some(entry_arc)
            } else {
                None
            }
        };

        if let Some(sector_arc) = sector_arc_opt {
            let mut sector = sector_arc.lock();
            if offset >= sector.len() || sector[offset] != expected {
                return false;
            } else {
                sector[offset] = value;
                let mut inner = self.cache.lock();
                inner.dirty.insert(sector_index);
                return true;
            }
        }

        false
    }

    /// すべてのダーティセクタを取得してダーティフラグをクリア
    pub fn take_dirty_sectors(&self) -> Vec<(u32, Arc<IrqPoisonLock<Box<[Cluster]>>>)> {
        let mut inner = self.cache.lock();
        let dirty_indices: Vec<u32> = inner.dirty.drain().collect();
        let mut out = Vec::new();
        for idx in dirty_indices {
            if let Some(data) = inner.sectors.get(&idx) {
                out.push((idx, Arc::clone(data)));
            }
        }
        out
    }

    /// キャッシュをクリア（アンマウント時など）
    pub fn clear(&self) {
        let mut inner = self.cache.lock();
        inner.sectors.clear();
        inner.dirty.clear();
        inner.access_order.clear();
    }

    /// ダーティセクタがあるかチェック
    pub fn has_dirty(&self) -> bool {
        !self.cache.lock().dirty.is_empty()
    }
}


/// ディレクトリエントリキャッシュ
///
/// パース済みのディレクトリエントリを保持し、繰り返しアクセス時の
/// ディスクI/OとLFNパース処理を削減する。
pub struct DirEntryCache {
    /// ディレクトリクラスタ -> パース済みエントリリスト
    cache: IrqPoisonLock<DirEntryCacheInner>,
    /// 最大キャッシュディレクトリ数
    max_dirs: usize,
}

/// DirEntryCacheの内部データ
struct DirEntryCacheInner {
    /// クラスタ -> エントリリスト（共有参照で保持）
    entries: HashMap<Cluster, Arc<[(String, DirEntryRaw)]>>,
    /// アクセス順序（LRU用）- 末尾が最新
    access_order: Vec<Cluster>,
}

impl DirEntryCache {
    /// 新しいディレクトリキャッシュを作成
    pub fn new(max_dirs: usize) -> Self {
        Self {
            cache: IrqPoisonLock::new(DirEntryCacheInner {
                entries: HashMap::new(),
                access_order: Vec::new(),
            }),
            max_dirs,
        }
    }

    /// キャッシュからディレクトリエントリを取得
    pub fn get(&self, cluster: Cluster) -> Option<Arc<[(String, DirEntryRaw)]>> {
        let mut inner = self.cache.lock();
        let data = inner.entries.get(&cluster).cloned();

        if data.is_some() {
            inner.access_order.retain(|&c| c != cluster);
            inner.access_order.push(cluster);
        }

        data
    }

    /// ディレクトリエントリをキャッシュに追加
    /// Returns the Arc slice that was inserted/updated for convenience.
    pub fn insert(
        &self,
        cluster: Cluster,
        entries: Vec<(String, DirEntryRaw)>,
    ) -> Arc<[(String, DirEntryRaw)]> {
        let mut inner = self.cache.lock();
        let entries_arc: Arc<[(String, DirEntryRaw)]> = Arc::from(entries.into_boxed_slice());

        // 既存エントリを更新
        if inner.entries.contains_key(&cluster) {
            inner.entries.insert(cluster, Arc::clone(&entries_arc));
            inner.access_order.retain(|&c| c != cluster);
            inner.access_order.push(cluster);
            return entries_arc;
        }

        // キャッシュが満杯の場合、最も古いエントリを削除
        while inner.entries.len() >= self.max_dirs && !inner.access_order.is_empty() {
            if let Some(oldest) = inner.access_order.first().copied() {
                inner.access_order.remove(0);
                inner.entries.remove(&oldest);
            }
        }

        // 新しいエントリを追加
        inner.entries.insert(cluster, Arc::clone(&entries_arc));
        inner.access_order.push(cluster);
        entries_arc
    }

    /// 指定ディレクトリのキャッシュを無効化
    pub fn invalidate(&self, cluster: Cluster) {
        let mut inner = self.cache.lock();
        inner.entries.remove(&cluster);
        inner.access_order.retain(|&c| c != cluster);
    }

    /// 全キャッシュをクリア
    pub fn clear(&self) {
        let mut inner = self.cache.lock();
        inner.entries.clear();
        inner.access_order.clear();
    }
}

// ============================================================================
