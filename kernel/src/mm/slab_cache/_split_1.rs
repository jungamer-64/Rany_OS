use super::*;


/// Slab統計情報
mod _split_1;
#[derive(Debug, Clone)]
pub struct SlabStats {
    pub object_size: usize,
    pub free_count: usize,
    pub page_count: usize,
    pub alloc_count: usize,
    pub dealloc_count: usize,
    /// 現在のリフィルページ数（適応的バルクリフィル）
    pub refill_pages: usize,
    /// Partial状態のページ数
    pub partial_page_count: usize,
    /// Empty状態のページ数
    pub empty_page_count: usize,
    /// Full状態のページ数
    pub full_page_count: usize,
    /// Partialページからの割り当て回数
    pub partial_alloc_count: usize,
    /// Emptyページからの割り当て回数
    pub empty_alloc_count: usize,
}

// ============================================================================
// Magazine Layer (Solaris/Bonwick Style)
// ============================================================================
//
// Magazine Layerは、Per-CPUキャッシュの上に更に高速なオブジェクトキャッシュを提供する。
// 各CPUは2つのマガジン（loaded/previous）を保持し、マガジン内のオブジェクトは
// ロックフリーでアクセス可能。
//
// アーキテクチャ:
// ```
//   [CPU 0]          [CPU 1]          [CPU N]
//   loaded/prev      loaded/prev      loaded/prev
//       |                |                |
//       v                v                v
//   +------------------------------------------+
//   |           Magazine Depot (global)        |
//   |   full_magazines[]  empty_magazines[]    |
//   +------------------------------------------+
//       |
//       v
//   [SlabCache (per-core)]
// ```
//
// 性能特性:
// - Hot Path (Magazine内): ロックフリー、キャッシュライン競合なし
// - Warm Path (Depot交換): 短いクリティカルセクション、マガジン単位の交換
// - Cold Path (Slab): 従来のSlabアロケータにフォールバック
//
// ============================================================================

/// マガジンのデフォルトサイズ（オブジェクト数）
pub const MAGAZINE_SIZE: usize = 32;

/// Depot内の最大マガジン数
pub const MAX_DEPOT_MAGAZINES: usize = 64;

/// マガジン構造体
///
/// オブジェクトポインタの配列を保持する。スタックライクに操作。
#[repr(align(64))] // キャッシュラインアライン
#[derive(Debug)]
pub struct Magazine<const SIZE: usize = MAGAZINE_SIZE> {
    /// オブジェクトポインタの配列
    objects: [Option<NonNull<u8>>; SIZE],
    /// 現在のオブジェクト数（スタックトップ）
    count: usize,
    /// オブジェクトサイズ（検証用）
    object_size: usize,
}

impl<const SIZE: usize> Magazine<SIZE> {
    /// 空のマガジンを作成
    pub const fn new(object_size: usize) -> Self {
        Self {
            objects: [None; SIZE],
            count: 0,
            object_size,
        }
    }

    /// マガジンが空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// マガジンが満杯かどうか
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= SIZE
    }

    /// オブジェクト数を取得
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// オブジェクトをpop（割り当て用）
    #[inline]
    pub fn pop(&mut self) -> Option<NonNull<u8>> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        self.objects[self.count].take()
    }

    /// オブジェクトをpush（解放用）
    #[inline]
    pub fn push(&mut self, ptr: NonNull<u8>) -> bool {
        if self.count >= SIZE {
            return false;
        }
        self.objects[self.count] = Some(ptr);
        self.count += 1;
        true
    }

    /// マガジンをクリア（全オブジェクトを返却）
    pub fn clear(&mut self) -> impl Iterator<Item = NonNull<u8>> + '_ {
        let count = self.count;
        self.count = 0;
        (0..count).filter_map(move |i| self.objects[i].take())
    }
}

/// マガジンデポ
///
/// 全CPUで共有されるマガジンプール。満杯/空マガジンを交換する。
#[derive(Debug)]
pub struct MagazineDepot<const SIZE: usize = MAGAZINE_SIZE> {
    /// 満杯マガジンのリスト
    full_magazines: [Option<Magazine<SIZE>>; MAX_DEPOT_MAGAZINES],
    /// 満杯マガジン数
    full_count: usize,
    /// 空マガジンのリスト
    empty_magazines: [Option<Magazine<SIZE>>; MAX_DEPOT_MAGAZINES],
    /// 空マガジン数
    empty_count: usize,
    /// オブジェクトサイズ
    object_size: usize,
    /// 統計: Depot交換回数
    exchange_count: usize,
}

impl<const SIZE: usize> MagazineDepot<SIZE> {
    /// 新しいデポを作成
    ///
    /// # Note
    /// ジェネリクス制約により、const fnでの配列初期化が難しいため、
    /// デフォルトサイズ（MAGAZINE_SIZE）のみサポート
    pub fn new(object_size: usize) -> Self {
        Self {
            full_magazines: core::array::from_fn(|_| None),
            full_count: 0,
            empty_magazines: core::array::from_fn(|_| None),
            empty_count: 0,
            object_size,
            exchange_count: 0,
        }
    }

    /// 満杯マガジンを取得し、空マガジンを返却
    pub fn exchange_for_full(&mut self, empty_mag: Magazine<SIZE>) -> Option<Magazine<SIZE>> {
        // 空マガジンを格納
        if self.empty_count < MAX_DEPOT_MAGAZINES {
            self.empty_magazines[self.empty_count] = Some(empty_mag);
            self.empty_count += 1;
        }
        // 満杯マガジンを取得
        if self.full_count > 0 {
            self.full_count -= 1;
            self.exchange_count += 1;
            self.full_magazines[self.full_count].take()
        } else {
            None
        }
    }

    /// 空マガジンを取得し、満杯マガジンを返却
    pub fn exchange_for_empty(&mut self, full_mag: Magazine<SIZE>) -> Option<Magazine<SIZE>> {
        // 満杯マガジンを格納
        if self.full_count < MAX_DEPOT_MAGAZINES {
            self.full_magazines[self.full_count] = Some(full_mag);
            self.full_count += 1;
        }
        // 空マガジンを取得
        if self.empty_count > 0 {
            self.empty_count -= 1;
            self.exchange_count += 1;
            self.empty_magazines[self.empty_count].take()
        } else {
            None
        }
    }

    /// 新しい空マガジンを作成
    pub fn create_empty_magazine(&self) -> Magazine<SIZE> {
        Magazine::new(self.object_size)
    }

    /// デポの統計情報
    pub fn stats(&self) -> MagazineDepotStats {
        MagazineDepotStats {
            full_magazines: self.full_count,
            empty_magazines: self.empty_count,
            exchange_count: self.exchange_count,
        }
    }
}

/// Per-CPUマガジンキャッシュ
///
/// 各CPUが保持する2つのマガジン。allocate/deallocateは
/// まずこのレイヤーで処理される。
#[repr(align(64))]
#[derive(Debug)]
pub struct PerCpuMagazineCache<const SIZE: usize = MAGAZINE_SIZE> {
    /// ロード済みマガジン（プライマリ）
    loaded: Magazine<SIZE>,
    /// 前のマガジン（セカンダリ）
    previous: Magazine<SIZE>,
    /// CPU ID
    cpu_id: usize,
    /// オブジェクトサイズ
    object_size: usize,
    /// 統計: マガジンからの割り当て回数
    magazine_allocs: usize,
    /// 統計: マガジンへの解放回数
    magazine_deallocs: usize,
    /// 統計: マガジン交換回数
    swaps: usize,
    /// 統計: Depotへのフォールバック回数
    depot_fallbacks: usize,
}

impl<const SIZE: usize> PerCpuMagazineCache<SIZE> {
    /// 新しいPer-CPUマガジンキャッシュを作成
    pub const fn new(cpu_id: usize, object_size: usize) -> Self {
        Self {
            loaded: Magazine::new(object_size),
            previous: Magazine::new(object_size),
            cpu_id,
            object_size,
            magazine_allocs: 0,
            magazine_deallocs: 0,
            swaps: 0,
            depot_fallbacks: 0,
        }
    }

    /// マガジンからオブジェクトを割り当て（Hot Path）
    #[inline]
    pub fn allocate(&mut self) -> Option<NonNull<u8>> {
        // 1. loadedマガジンから取得を試みる
        if let Some(ptr) = self.loaded.pop() {
            self.magazine_allocs += 1;
            return Some(ptr);
        }

        // 2. previousと交換してリトライ
        core::mem::swap(&mut self.loaded, &mut self.previous);
        self.swaps += 1;

        if let Some(ptr) = self.loaded.pop() {
            self.magazine_allocs += 1;
            return Some(ptr);
        }

        // 3. 両方空 → Depotへフォールバックが必要
        self.depot_fallbacks += 1;
        None
    }

    /// マガジンにオブジェクトを解放（Hot Path）
    #[inline]
    pub fn deallocate(&mut self, ptr: NonNull<u8>) -> bool {
        // 1. loadedマガジンにpushを試みる
        if self.loaded.push(ptr) {
            self.magazine_deallocs += 1;
            return true;
        }

        // 2. previousと交換してリトライ
        core::mem::swap(&mut self.loaded, &mut self.previous);
        self.swaps += 1;

        if self.loaded.push(ptr) {
            self.magazine_deallocs += 1;
            return true;
        }

        // 3. 両方満杯 → Depotへフォールバックが必要
        self.depot_fallbacks += 1;
        false
    }

    /// Depotから満杯マガジンを取得
    pub fn refill_from_depot(&mut self, depot: &mut MagazineDepot<SIZE>) -> bool {
        // loadedが空の場合、Depotから満杯マガジンを取得
        if self.loaded.is_empty() {
            let empty_mag = core::mem::replace(
                &mut self.loaded,
                Magazine::new(self.object_size)
            );
            if let Some(full_mag) = depot.exchange_for_full(empty_mag) {
                self.loaded = full_mag;
                return true;
            }
        }
        false
    }

    /// Depotへ満杯マガジンを返却
    pub fn flush_to_depot(&mut self, depot: &mut MagazineDepot<SIZE>) -> bool {
        // loadedが満杯の場合、Depotに返却して空マガジンを取得
        if self.loaded.is_full() {
            let full_mag = core::mem::replace(
                &mut self.loaded,
                Magazine::new(self.object_size)
            );
            if let Some(empty_mag) = depot.exchange_for_empty(full_mag) {
                self.loaded = empty_mag;
                return true;
            } else {
                // 空マガジンがない場合は新規作成
                self.loaded = depot.create_empty_magazine();
                return true;
            }
        }
        false
    }

    /// 統計情報を取得
    pub fn stats(&self) -> PerCpuMagazineStats {
        PerCpuMagazineStats {
            cpu_id: self.cpu_id,
            loaded_count: self.loaded.len(),
            previous_count: self.previous.len(),
            magazine_allocs: self.magazine_allocs,
            magazine_deallocs: self.magazine_deallocs,
            swaps: self.swaps,
            depot_fallbacks: self.depot_fallbacks,
        }
    }
}

/// マガジンデポの統計
#[derive(Debug, Clone, Copy)]
pub struct MagazineDepotStats {
    /// 満杯マガジン数
    pub full_magazines: usize,
    /// 空マガジン数
    pub empty_magazines: usize,
    /// 交換回数
    pub exchange_count: usize,
}

/// Per-CPUマガジンの統計
#[derive(Debug, Clone, Copy)]
pub struct PerCpuMagazineStats {
    /// CPU ID
    pub cpu_id: usize,
    /// loadedマガジンのオブジェクト数
    pub loaded_count: usize,
    /// previousマガジンのオブジェクト数
    pub previous_count: usize,
    /// マガジンからの割り当て回数
    pub magazine_allocs: usize,
    /// マガジンへの解放回数
    pub magazine_deallocs: usize,
    /// loaded/previous交換回数
    pub swaps: usize,
    /// Depotフォールバック回数
    pub depot_fallbacks: usize,
}

/// Magazine Layer付きSlabキャッシュ
///
/// Magazine Layerを統合したSlabキャッシュ。
/// 割り当て/解放は以下の順序で試行:
///
/// 1. Per-CPUマガジン（Hot Path）
/// 2. グローバルDepot（Warm Path）
/// 3. 下位Slab（Cold Path）
#[derive(Debug)]
pub struct MagazineSlabCache<const MAG_SIZE: usize = MAGAZINE_SIZE> {
    /// 下位のSlabキャッシュ
    slab: SlabCache,
    /// Per-CPUマガジンキャッシュ配列
    per_cpu_mags: [Option<PerCpuMagazineCache<MAG_SIZE>>; MAX_CPUS],
    /// グローバルマガジンデポ（要Mutex保護）
    depot: MagazineDepot<MAG_SIZE>,
    /// オブジェクトサイズ
    object_size: usize,
    /// 統計: Slabフォールバック割り当て回数
    slab_alloc_fallbacks: usize,
    /// 統計: Slabフォールバック解放回数
    slab_dealloc_fallbacks: usize,
}

impl<const MAG_SIZE: usize> MagazineSlabCache<MAG_SIZE> {
    /// 新しいMagazineSlabCacheを作成
    pub fn new(object_size: usize) -> Self {
        Self {
            slab: SlabCache::new(object_size),
            per_cpu_mags: core::array::from_fn(|_| None),
            depot: MagazineDepot::new(object_size),
            object_size,
            slab_alloc_fallbacks: 0,
            slab_dealloc_fallbacks: 0,
        }
    }

    /// 指定CPUのマガジンキャッシュを初期化
    pub fn init_cpu(&mut self, cpu_id: usize) {
        if cpu_id < MAX_CPUS && self.per_cpu_mags[cpu_id].is_none() {
            self.per_cpu_mags[cpu_id] = Some(PerCpuMagazineCache::new(cpu_id, self.object_size));
        }
    }

    /// オブジェクトを割り当て
    ///
    /// # Path Priority
    /// 1. Per-CPUマガジン（ロックフリー）
    /// 2. Depot交換（短いクリティカルセクション）
    /// 3. Slabからの新規割り当て
    pub fn allocate(&mut self, cpu_id: usize) -> Option<NonNull<u8>> {
        // 1. Per-CPUマガジンから割り当て（Hot Path）
        if let Some(mag_cache) = self.per_cpu_mags.get_mut(cpu_id).and_then(|m| m.as_mut()) {
            if let Some(ptr) = mag_cache.allocate() {
                return Some(ptr);
            }

            // 2. Depotから満杯マガジンを取得（Warm Path）
            if mag_cache.refill_from_depot(&mut self.depot) {
                if let Some(ptr) = mag_cache.allocate() {
                    return Some(ptr);
                }
            }
        }

        // 3. Slabから割り当て（Cold Path）
        self.slab_alloc_fallbacks += 1;
        self.slab.allocate()
    }

    /// オブジェクトを解放
    ///
    /// # Path Priority
    /// 1. Per-CPUマガジンへ（ロックフリー）
    /// 2. Depot交換（満杯マガジン返却）
    /// 3. Slabへの直接解放
    pub unsafe fn deallocate(&mut self, cpu_id: usize, ptr: NonNull<u8>) {
        // 1. Per-CPUマガジンへ解放（Hot Path）
        if let Some(mag_cache) = self.per_cpu_mags.get_mut(cpu_id).and_then(|m| m.as_mut()) {
            if mag_cache.deallocate(ptr) {
                return;
            }

            // 2. Depotへ満杯マガジンを返却（Warm Path）
            if mag_cache.flush_to_depot(&mut self.depot) {
                if mag_cache.deallocate(ptr) {
                    return;
                }
            }
        }

        // 3. Slabへ直接解放（Cold Path）
        self.slab_dealloc_fallbacks += 1;
        self.slab.deallocate(ptr);
    }

    /// 統計情報を取得
    pub fn stats(&self) -> MagazineSlabStats {
        MagazineSlabStats {
            slab_stats: self.slab.stats(),
            depot_stats: self.depot.stats(),
            slab_alloc_fallbacks: self.slab_alloc_fallbacks,
            slab_dealloc_fallbacks: self.slab_dealloc_fallbacks,
        }
    }

    /// Per-CPUマガジンの統計を取得
    pub fn per_cpu_stats(&self, cpu_id: usize) -> Option<PerCpuMagazineStats> {
        self.per_cpu_mags.get(cpu_id)
            .and_then(|m| m.as_ref())
            .map(|m| m.stats())
    }

    /// 下位Slabへのアクセス
    pub fn inner_slab(&self) -> &SlabCache {
        &self.slab
    }
}

/// MagazineSlabCacheの統計
#[derive(Debug, Clone)]
pub struct MagazineSlabStats {
    /// 下位Slabの統計
    pub slab_stats: SlabStats,
    /// Depotの統計
    pub depot_stats: MagazineDepotStats,
    /// Slabフォールバック割り当て回数
    pub slab_alloc_fallbacks: usize,
    /// Slabフォールバック解放回数
    pub slab_dealloc_fallbacks: usize,
}

// SAFETY: FreeList と SlabCache はSAS環境で使用され、
// Per-Core構造のため他コアから同時アクセスされない
// SAFETY: Per-Core構造のため他コアから同時アクセスされない
unsafe impl Send for SlabCache {}
unsafe impl Send for PerCoreCache {}
unsafe impl<const SIZE: usize> Send for Magazine<SIZE> {}
unsafe impl<const SIZE: usize> Send for MagazineDepot<SIZE> {}
unsafe impl<const SIZE: usize> Send for PerCpuMagazineCache<SIZE> {}
unsafe impl<const SIZE: usize> Send for MagazineSlabCache<SIZE> {}

/// Per-Core キャッシュ
/// 設計書: 各コア専用のSlabキャッシュ
#[repr(align(64))] // キャッシュラインにアライン
#[derive(Debug)]
pub struct PerCoreCache {
    /// 各サイズクラスのSlabキャッシュ
    caches: [SlabCache; SLAB_SIZES.len()],
    /// CPU ID
    cpu_id: usize,
    /// NUMA node ID for this CPU (for strict NUMA placement)
    numa_node: Option<u8>,
}

impl PerCoreCache {
    /// 新しいPer-Coreキャッシュを作成
    pub fn new(cpu_id: usize) -> Self {
        Self {
            caches: [
                SlabCache::new(SLAB_SIZES[0]),
                SlabCache::new(SLAB_SIZES[1]),
                SlabCache::new(SLAB_SIZES[2]),
                SlabCache::new(SLAB_SIZES[3]),
                SlabCache::new(SLAB_SIZES[4]),
                SlabCache::new(SLAB_SIZES[5]),
                SlabCache::new(SLAB_SIZES[6]),
                SlabCache::new(SLAB_SIZES[7]),
            ],
            cpu_id,
            numa_node: None,
        }
    }

    /// 新しいPer-Coreキャッシュを作成（NUMA node指定）
    ///
    /// 指定されたNUMAノードから優先的にメモリを確保する。
    /// これによりCPUとメモリのアフィニティを保証し、
    /// リモートメモリアクセスのレイテンシを削減する。
    pub fn new_on_node(cpu_id: usize, numa_node: u8) -> Self {
        Self {
            caches: [
                SlabCache::new_on_node(SLAB_SIZES[0], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[1], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[2], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[3], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[4], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[5], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[6], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[7], numa_node),
            ],
            cpu_id,
            numa_node: Some(numa_node),
        }
    }

    /// Set NUMA node for this Per-Core cache
    ///
    /// Updates all underlying Slab caches to use the specified NUMA node.
    /// Should be called during CPU initialization after NUMA topology is known.
    pub fn set_numa_node(&mut self, node: u8) {
        self.numa_node = Some(node);
        for cache in &mut self.caches {
            cache.set_numa_node(node);
        }
    }

    /// Get the NUMA node for this Per-Core cache
    pub fn numa_node(&self) -> Option<u8> {
        self.numa_node
    }

    /// サイズに適したキャッシュインデックスを取得
    pub(super) fn size_class(size: usize) -> Option<usize> {
        SLAB_SIZES.iter().position(|&s| size <= s)
    }

    /// メモリを割り当て
    pub fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let size = layout.size().max(layout.align());

        if let Some(class) = Self::size_class(size) {
            self.caches[class].allocate()
        } else {
            // Slabサイズを超える場合はグローバルヒープにフォールバック
            unsafe {
                let ptr = alloc::alloc::alloc(layout);
                NonNull::new(ptr)
            }
        }
    }

    /// メモリを解放
    pub unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let size = layout.size().max(layout.align());

        if let Some(class) = Self::size_class(size) {
            // SAFETY: 呼び出し元がポインタの有効性を保証
            unsafe {
                self.caches[class].deallocate(ptr);
            }
        } else {
            // グローバルヒープに返却
            // SAFETY: ptrはallocで割り当てられたものと仮定
            unsafe {
                alloc::alloc::dealloc(ptr.as_ptr(), layout);
            }
        }
    }

    /// 統計情報を取得
    pub fn stats(&self) -> Vec<SlabStats> {
        self.caches.iter().map(|c| c.stats()).collect()
    }

    pub fn cpu_id(&self) -> usize {
        self.cpu_id
    }
}

/// 最大CPU数
pub const MAX_CPUS: usize = 64;

/// グローバルなPer-Coreキャッシュ配列
/// 重要: 各コアのキャッシュは **個別のMutex** で保護される
/// これにより、Core 0 がロックを取っている間も Core 1 は自分のキャッシュを使用可能
pub(crate) static PER_CORE_CACHES: [PoisonLock<Option<PerCoreCache>>; MAX_CPUS] = {
    // const配列の初期化（Rust 1.63+）
    const INIT: PoisonLock<Option<PerCoreCache>> = PoisonLock::new(None);
    [INIT; MAX_CPUS]
};

// ============================================================================
// Lock-free Remote Free Rings (Mimalloc/Snmalloc style)
// ============================================================================
//
// リモート解放の問題:
//   CPU A が割り当てたオブジェクトを CPU B が解放する場合、
//   従来は CPU A のロックを取得する必要があり、Cache Line Bouncing を引き起こす。
//
// 解決策:
//   各 CPU が自分専用の「リモートフリーリング」を持つ。
//   他 CPU は解放時にロック不要でリングにプッシュするだけ。
//   オーナー CPU は allocate 時にリングをドレインして回収。
//
// ============================================================================

/// Per-CPU リモートフリーリング
///
/// 各 CPU が他 CPU からの解放要求を受け取るための MPSC キュー。
/// - Push: ロックフリー（他 CPU から呼ばれる）
/// - Drain: オーナー CPU のみ（allocate 時に一括回収）
pub(crate) static SLAB_REMOTE_FREE_RINGS: [RemoteFreeRing<SLAB_REMOTE_FREE_CAPACITY>; MAX_CPUS] = {
    const INIT: RemoteFreeRing<SLAB_REMOTE_FREE_CAPACITY> = RemoteFreeRing::new();
    [INIT; MAX_CPUS]
};

/// リモートフリー統計
pub(crate) static REMOTE_FREE_STATS: RemoteFreeStats = RemoteFreeStats::new();

/// リモートフリー統計構造体
pub struct RemoteFreeStats {
    /// リモートプッシュ成功数
    pub remote_pushes: AtomicU64,
    /// リモートプッシュ失敗数（リング満杯）
    pub remote_push_failures: AtomicU64,
    /// ドレイン回数
    pub drain_count: AtomicU64,
    /// ドレインで回収したエントリ数
    pub drained_entries: AtomicU64,
}

impl RemoteFreeStats {
    pub const fn new() -> Self {
        Self {
            remote_pushes: AtomicU64::new(0),
            remote_push_failures: AtomicU64::new(0),
            drain_count: AtomicU64::new(0),
            drained_entries: AtomicU64::new(0),
        }
    }
}

/// リモートフリーリングを初期化
///
/// 各 CPU のリングのシーケンス番号を初期化する。
/// init_per_core_caches の後に呼び出す。
pub fn init_slab_remote_free_rings(num_cpus: usize) {
    let num_cpus = num_cpus.min(MAX_CPUS);
    for cpu_id in 0..num_cpus {
        SLAB_REMOTE_FREE_RINGS[cpu_id].init();
    }
}

/// リモートフリーリングにプッシュ（ロックフリー）
///
/// 他 CPU から呼ばれる。オーナー CPU のロックを取らない。
///
/// # Arguments
/// * `owner_cpu` - オブジェクトを所有する CPU ID
/// * `ptr` - 解放するポインタ
/// * `size_class` - サイズクラスインデックス
///
/// # Returns
/// * `true` - プッシュ成功
/// * `false` - リング満杯（フォールバック解放が必要）
#[inline]
pub fn slab_remote_free_push(owner_cpu: usize, ptr: u64, size_class: u8) -> bool {
    if owner_cpu >= MAX_CPUS {
        return false;
    }
    
    // Always succeeds (internally falls back to overflow list)
    SLAB_REMOTE_FREE_RINGS[owner_cpu].push(ptr, size_class);
    REMOTE_FREE_STATS.remote_pushes.fetch_add(1, Ordering::Relaxed);
    true
}

/// 自分のリモートフリーリングをドレイン（オーナー CPU のみ）
///
/// allocate 時の最初に呼び出し、他 CPU から送られた解放要求を一括処理。
/// これによりバッチ効率が向上し、ロック競合が完全に排除される。
///
/// # Arguments
/// * `cpu_id` - 現在の CPU ID
/// * `cache` - このCPUの PerCoreCache
pub(crate) fn drain_remote_frees(cpu_id: usize, cache: &mut PerCoreCache) {
    if cpu_id >= MAX_CPUS {
        return;
    }
    
    let ring = &SLAB_REMOTE_FREE_RINGS[cpu_id];
    let mut drained = 0u64;
    
    // リングから全エントリをドレイン（最大256エントリ）
    ring.drain_with(SLAB_REMOTE_FREE_CAPACITY, |entry| {
        let ptr_addr = entry.addr;
        let size_class = entry.size_class as usize;
        
        if size_class < SLAB_SIZES.len() {
            if let Some(ptr) = NonNull::new(ptr_addr as *mut u8) {
                // SAFETY: ポインタはこのCPUのSlabから割り当てられたもの
                unsafe {
                    cache.caches[size_class].deallocate(ptr);
                }
                drained += 1;
            }
        }
    });
    
    if drained > 0 {
        REMOTE_FREE_STATS.drain_count.fetch_add(1, Ordering::Relaxed);
        REMOTE_FREE_STATS.drained_entries.fetch_add(drained, Ordering::Relaxed);
    }
}

/// Per-Coreキャッシュシステムを初期化
pub fn init_per_core_caches(num_cpus: usize) {
    let num_cpus = num_cpus.min(MAX_CPUS);

    for cpu_id in 0..num_cpus {
        init_per_core_cache_for_cpu(cpu_id);
    }
}

/// Initialize per-core cache for a single CPU (idempotent)
pub fn init_per_core_cache_for_cpu(cpu_id: usize) {
    if cpu_id >= MAX_CPUS {
        return;
    }
    // 各コアのMutexに個別にアクセス（他コアをブロックしない）
    // Initialization-time best-effort recovery for per-core caches: continue init even if a lock
    // shows as poisoned.
    let mut guard = PER_CORE_CACHES[cpu_id].lock_for_init("[MEM] Per-core slab init");
    if guard.is_none() {
        *guard = Some(PerCoreCache::new(cpu_id));
    }
}
