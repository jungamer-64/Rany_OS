use super::*;

/// 現在のCPUのPer-Coreキャッシュから割り当て
///
/// # Note
/// - init_per_core_caches が呼ばれた後に使用する必要がある
/// - cpu_id は有効な範囲内である必要がある
/// - 各コアのキャッシュは独立してロックされるため、他コアをブロックしない
///
/// # リモートフリー統合
/// 割り当て前に自分のリモートフリーリングをドレインし、
/// 他CPUから送られた解放要求を一括処理する。
/// これによりバッチ効率が向上し、Cache Line Bouncing が完全に排除される。
///
/// # TODO: API改善
/// 現在は `cpu_id` を引数で受け取っているが、これはAPI設計として問題がある。
/// 将来的には `GsBase` レジスタを使ってPer-CPUデータを参照し、
/// `per_core_alloc(layout)` だけで動作するようにすべき。
pub fn per_core_alloc(cpu_id: usize, layout: Layout) -> Option<NonNull<u8>> {
    if cpu_id >= MAX_CPUS {
        return None;
    }
    // このコアのMutexだけをロック（他コアに影響しない）
    match PER_CORE_CACHES[cpu_id].lock() {
        Ok(mut guard) => {
            if let Some(cache) = guard.as_mut() {
                // リモートフリーのドレイン（他CPUからの解放要求を回収）
                drain_remote_frees(cpu_id, cache);
                // 割り当て
                cache.allocate(layout)
            } else {
                None
            }
        }
        Err(_) => {
            // Poisoned: fallback to global heap allocation instead of accessing potentially
            // corrupted per-core cache data.
            log::error!(
                "[MEM] Slab Poisoned cpu={}; falling back to global allocator",
                cpu_id
            );
            unsafe {
                let ptr = alloc::alloc::alloc(layout);
                NonNull::new(ptr)
            }
        }
    }
}

/// 現在のCPUのPer-Coreキャッシュに解放
///
/// # Safety
/// - ptr は per_core_alloc で割り当てられたものである必要がある
pub unsafe fn per_core_dealloc(cpu_id: usize, ptr: NonNull<u8>, layout: Layout) {
    if cpu_id >= MAX_CPUS {
        return;
    }
    // このコアのMutexだけをロック（他コアに影響しない）
    match PER_CORE_CACHES[cpu_id].lock() {
        Ok(mut guard) => {
            if let Some(cache) = guard.as_mut() {
                // SAFETY: 呼び出し元が保証
                unsafe {
                    cache.deallocate(ptr, layout);
                }
                return;
            }
            // fallthrough to global dealloc if no per-core cache
        }
        Err(_) => {
            log::error!(
                "[MEM] Slab Poisoned cpu={}; falling back to global dealloc",
                cpu_id
            );
            // fallthrough to global dealloc
        }
    }

    // Global deallocation fallback
    unsafe {
        alloc::alloc::dealloc(ptr.as_ptr(), layout);
    }
}

// ============================================================================
// GsBase を使用した自動 CPU ID 取得 API
// cpu_id 引数が不要になり、APIが簡素化される
// ============================================================================

/// 現在のCPUのPer-Coreキャッシュから割り当て（GsBase版）
///
/// CPU IDを自動的に取得するため、引数が不要
///
/// # Note
/// - `init_per_core_caches` と `per_cpu::setup_current_cpu` が
///   呼ばれた後に使用する必要がある
/// - GsBaseが設定されていない場合は None を返す（panicしない）
pub fn per_core_alloc_auto(layout: Layout) -> Option<NonNull<u8>> {
    // try_current_cpu_id を使用し、初期化前でも安全に動作
    let cpu_id = crate::per_cpu::try_current_cpu_id()?;
    per_core_alloc(cpu_id, layout)
}

/// 現在のCPUのPer-Coreキャッシュに解放（GsBase版）
///
/// CPU IDを自動的に取得するため、引数が不要
///
/// # Safety
/// - ptr は per_core_alloc または per_core_alloc_auto で
///   割り当てられたものである必要がある
pub unsafe fn per_core_dealloc_auto(ptr: NonNull<u8>, layout: Layout) {
    // try_current_cpu_id を使用し、初期化前でも安全に動作
    if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
        // SAFETY: 呼び出し元が保証
        unsafe {
            per_core_dealloc(cpu_id, ptr, layout);
        }
    }
    // 初期化前の場合は何もしない（リークするが安全）
}

// ============================================================================
// Cross-CPU Remote Free API (Lock-free)
// ============================================================================
//
// Producer-Consumer パターンなど、オブジェクトを割り当てた CPU と
// 解放する CPU が異なる場合に使用する。
//
// 従来: 解放時にオーナー CPU のロックを取得 → Cache Line Bouncing
// 改善: リモートフリーリングにプッシュ（ロックフリー）→ オーナーが回収
//
// ============================================================================

/// クロスCPU解放（ロックフリー）
///
/// 現在のCPUとは異なるCPUが割り当てたオブジェクトを解放する。
/// オーナーCPUのロックを取らず、リモートフリーリングにプッシュする。
///
/// # Arguments
/// * `owner_cpu` - オブジェクトを割り当てた CPU ID
/// * `ptr` - 解放するポインタ
/// * `layout` - メモリレイアウト
///
/// # Returns
/// * `true` - リモートフリー成功（またはローカル解放）
/// * `false` - リモートフリー失敗（フォールバック解放が必要）
///
/// # Safety
/// - ptr は owner_cpu の per_core_alloc で割り当てられたものである必要がある
pub unsafe fn per_core_dealloc_remote(owner_cpu: usize, ptr: NonNull<u8>, layout: Layout) -> bool {
    let size = layout.size().max(layout.align());

    // サイズクラスを特定
    let size_class = match SLAB_SIZES.iter().position(|&s| size <= s) {
        Some(class) => class as u8,
        None => {
            // Slabサイズを超える場合はグローバルヒープに返却
            unsafe {
                alloc::alloc::dealloc(ptr.as_ptr(), layout);
            }
            return true;
        }
    };

    // リモートフリーリングにプッシュ
    // リング満杯時も内部でフォールバックキューに保存されるため、常に成功する
    slab_remote_free_push(owner_cpu, ptr.as_ptr() as u64, size_class);
    true
}

/// リモートフリー統計を取得
pub fn slab_remote_free_stats() -> (u64, u64, u64, u64) {
    (
        REMOTE_FREE_STATS.remote_pushes.load(Ordering::Relaxed),
        REMOTE_FREE_STATS
            .remote_push_failures
            .load(Ordering::Relaxed),
        REMOTE_FREE_STATS.drain_count.load(Ordering::Relaxed),
        REMOTE_FREE_STATS.drained_entries.load(Ordering::Relaxed),
    )
}

// ============================================================================
// Typed Slab Cache with Constructor/Destructor support
// ============================================================================

/// コンストラクタ関数型: オブジェクトの初期化を行う
pub type SlabCtor = fn(NonNull<u8>);

/// デストラクタ関数型: オブジェクトのクリーンアップを行う（解放ではない）
pub type SlabDtor = fn(NonNull<u8>);

/// コンストラクタ/デストラクタ付きSlabキャッシュ
///
/// オブジェクトの初期化コストを削減するため、一度初期化されたオブジェクトは
/// 解放後も初期化済み状態を維持する（デストラクタでリセットのみ行う）
///
/// # 設計思想
/// - コンストラクタは最初の割り当て時のみ呼ばれる（オブジェクト新規作成時）
/// - デストラクタは解放時に毎回呼ばれる（状態リセット用）
/// - 再割り当て時は初期化済みなのでコンストラクタをスキップ
///
/// # 例
/// ```ignore
/// fn init_task_struct(ptr: NonNull<u8>) {
///     let task = unsafe { &mut *(ptr.as_ptr() as *mut TaskStruct) };
///     task.state = TaskState::Init;
///     task.priority = 0;
///     // ... 重い初期化処理
/// }
///
/// fn reset_task_struct(ptr: NonNull<u8>) {
///     let task = unsafe { &mut *(ptr.as_ptr() as *mut TaskStruct) };
///     task.state = TaskState::Init; // 状態リセットのみ
/// }
///
/// let cache = TypedSlabCache::new_with_ctor_dtor(
///     size_of::<TaskStruct>(),
///     init_task_struct,
///     Some(reset_task_struct)
/// );
/// ```
pub struct TypedSlabCache {
    /// 内部のSlabキャッシュ (Shared via Registry)
    inner: Arc<PoisonLock<SlabCache>>,
    /// コンストラクタ関数（初回割り当て時に呼ばれる）
    ctor: Option<SlabCtor>,
    /// デストラクタ関数（解放時に呼ばれる）
    dtor: Option<SlabDtor>,
    /// 初期化済みオブジェクトの追跡用ビットマップ
    /// (簡易実装: 最初のページあたりの最初64オブジェクトのみ追跡)
    /// 本格実装ではページごとにビットマップを持つ
    initialized_bitmap: u64,
    /// 初回コンストラクタ呼び出し回数（統計用）
    ctor_calls: usize,
    /// デストラクタ呼び出し回数（統計用）
    dtor_calls: usize,
    /// コンストラクタスキップ回数（再利用時）
    ctor_skipped: usize,
}

impl TypedSlabCache {
    /// コンストラクタ付きTypedSlabCacheを作成
    pub fn new_with_ctor(object_size: usize, ctor: SlabCtor) -> Self {
        // TypedSlabCache maintains internal state (initialized_bitmap) so it cannot be merged
        let flags = SlabFlags {
            mergeable: false,
            read_only: false,
        };
        let inner = SlabCacheRegistry::global().get_or_create(object_size, flags);
        Self {
            inner,
            ctor: Some(ctor),
            dtor: None,
            initialized_bitmap: 0,
            ctor_calls: 0,
            dtor_calls: 0,
            ctor_skipped: 0,
        }
    }

    /// コンストラクタ/デストラクタ付きTypedSlabCacheを作成
    pub fn new_with_ctor_dtor(object_size: usize, ctor: SlabCtor, dtor: Option<SlabDtor>) -> Self {
        // TypedSlabCache maintains internal state, no merging
        let flags = SlabFlags {
            mergeable: false,
            read_only: false,
        };
        let inner = SlabCacheRegistry::global().get_or_create(object_size, flags);
        Self {
            inner,
            ctor: Some(ctor),
            dtor,
            initialized_bitmap: 0,
            ctor_calls: 0,
            dtor_calls: 0,
            ctor_skipped: 0,
        }
    }

    /// NUMA node指定でTypedSlabCacheを作成
    pub fn new_with_ctor_on_node(object_size: usize, ctor: SlabCtor, numa_node: u8) -> Self {
        // NUMA aware, not mergeable currently (registry doesn't track node yet, or assume non-mergeable)
        // For now, create direct since Registry doesn't support NUMA constraints yet
        // OR wrapper allowing new_on_node.
        // Let's stick to simple Arc<PoisonLock> wrap for now, bypassing registry for NUMA explicit calls
        // until Registry is upgraded.
        let inner = Arc::new(PoisonLock::new(SlabCache::new_on_node(object_size, numa_node)));
        Self {
            inner,
            ctor: Some(ctor),
            dtor: None,
            initialized_bitmap: 0,
            ctor_calls: 0,
            dtor_calls: 0,
            ctor_skipped: 0,
        }
    }

    /// オブジェクトを割り当て
    ///
    /// 初回割り当てではコンストラクタが呼ばれ、再利用時はスキップ
    pub fn allocate(&mut self) -> Option<NonNull<u8>> {
        let ptr = self.inner.lock().unwrap_or_else(|e| e.into_inner()).allocate()?;

        // オブジェクトのインデックスを計算（簡易実装: アドレス下位ビットから）
        let obj_index = self.ptr_to_index(ptr);

        if obj_index < 64 {
            let mask = 1u64 << obj_index;
            if self.initialized_bitmap & mask == 0 {
                // 初回割り当て: コンストラクタを呼ぶ
                if let Some(ctor) = self.ctor {
                    ctor(ptr);
                    self.ctor_calls += 1;
                }
                self.initialized_bitmap |= mask;
            } else {
                // 再利用: コンストラクタをスキップ
                self.ctor_skipped += 1;
            }
        } else {
            // インデックスが64以上の場合は毎回コンストラクタを呼ぶ（安全側に倒す）
            if let Some(ctor) = self.ctor {
                ctor(ptr);
                self.ctor_calls += 1;
            }
        }

        Some(ptr)
    }

    /// オブジェクトを解放
    ///
    /// デストラクタが設定されていれば呼び出す
    ///
    /// # Safety
    /// - ptr は allocate() で取得したものである必要がある
    pub unsafe fn deallocate(&mut self, ptr: NonNull<u8>) {
        // デストラクタを呼ぶ（状態リセット用）
        if let Some(dtor) = self.dtor {
            dtor(ptr);
            self.dtor_calls += 1;
        }

        // 内部キャッシュに返却（初期化フラグは維持）
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).deallocate(ptr);
    }

    /// ポインタからオブジェクトインデックスを計算（簡易実装）
    pub(super) fn ptr_to_index(&self, ptr: NonNull<u8>) -> usize {
        // アドレス下位12ビット（ページ内オフセット）をオブジェクトサイズで割る
        let offset = (ptr.as_ptr() as usize) & 0xFFF;
        offset / self.inner.lock().unwrap_or_else(|e| e.into_inner()).object_size
    }

    /// 統計情報を取得
    pub fn stats(&self) -> TypedSlabStats {
        let inner_stats = self.inner.lock().unwrap_or_else(|e| e.into_inner()).stats();
        TypedSlabStats {
            alloc_count: inner_stats.alloc_count,
            dealloc_count: inner_stats.dealloc_count,
            page_count: inner_stats.page_count,
            ctor_calls: self.ctor_calls,
            dtor_calls: self.dtor_calls,
            ctor_skipped: self.ctor_skipped,
        }
    }

    /// コンストラクタ効率を計算（スキップ率）
    pub fn ctor_skip_ratio(&self) -> f32 {
        let total = self.ctor_calls + self.ctor_skipped;
        if total == 0 {
            0.0
        } else {
            self.ctor_skipped as f32 / total as f32
        }
    }

    /// 内部SlabCacheへのアクセス（統計等） - ロックが必要
    pub fn inner(&self) -> Arc<PoisonLock<SlabCache>> {
        self.inner.clone()
    }
}

/// TypedSlabCacheの統計情報
#[derive(Debug, Clone, Copy)]
pub struct TypedSlabStats {
    /// 総割り当て回数
    pub alloc_count: usize,
    /// 総解放回数
    pub dealloc_count: usize,
    /// 確保したページ数
    pub page_count: usize,
    /// コンストラクタ呼び出し回数
    pub ctor_calls: usize,
    /// デストラクタ呼び出し回数
    pub dtor_calls: usize,
    /// コンストラクタスキップ回数
    pub ctor_skipped: usize,
}

// ============================================================================
// Pre-defined Typed Caches for common kernel objects
// ============================================================================

/// カーネルオブジェクト用の事前定義キャッシュ群
pub mod kernel_caches {
    use super::*;

    /// タスク構造体のサイズ（仮: 実際のTaskStructサイズに合わせる）
    pub const TASK_STRUCT_SIZE: usize = 512;

    /// VMエリア構造体のサイズ
    pub const VMA_SIZE: usize = 128;

    /// ファイルディスクリプタ構造体のサイズ
    pub const FILE_DESC_SIZE: usize = 64;

    /// 汎用のnoop コンストラクタ（ゼロクリアのみ）
    pub fn zero_ctor(ptr: NonNull<u8>) {
        unsafe {
            core::ptr::write_bytes(ptr.as_ptr(), 0, 64);
        }
    }

    /// ゼロクリアなしのnoop コンストラクタ
    pub fn noop_ctor(_ptr: NonNull<u8>) {
        // 何もしない（既にゼロクリアされている場合用）
    }
}

// ============================================================================
// Phase 5: 2.3 Object Caching Layer
// ============================================================================
//
// ## 概要
//
// 特定の型のオブジェクトをキャッシュして再利用するレイヤー。
// Slabアロケータの上に構築され、以下の利点を提供：
//
// 1. **型安全な割り当て**: ジェネリクスで型を指定
// 2. **初期化の最適化**: コンストラクタをキャッシュしてスキップ可能
// 3. **オブジェクトプーリング**: 解放後も初期化済み状態を保持
// 4. **バッチ操作**: 複数オブジェクトの一括割り当て/解放
//
// ## 使用例
//
// ```rust
// let cache = ObjectCache::<MyStruct>::new("my_struct");
// let obj = cache.alloc().unwrap();
// // obj は初期化済み MyStruct
// unsafe { cache.free(obj); }
// ```
//
// ============================================================================

/// オブジェクトキャッシュの設定
#[derive(Debug, Clone, Copy)]
pub struct ObjectCacheConfig {
    /// プール内の最大オブジェクト数
    pub max_pooled: usize,
    /// バッチ割り当てサイズ
    pub batch_size: usize,
    /// アイドル時の縮小閾値
    pub shrink_threshold: usize,
    /// 初期化をスキップするか
    pub skip_init_on_reuse: bool,
}

impl Default for ObjectCacheConfig {
    fn default() -> Self {
        Self {
            max_pooled: 64,
            batch_size: 8,
            shrink_threshold: 128,
            skip_init_on_reuse: true,
        }
    }
}

/// オブジェクトキャッシュ統計
#[derive(Debug, Clone, Copy, Default)]
pub struct ObjectCacheStats {
    /// 総割り当て回数
    pub allocations: u64,
    /// 総解放回数
    pub deallocations: u64,
    /// プールからの割り当て回数（キャッシュヒット）
    pub pool_hits: u64,
    /// 新規割り当て回数（キャッシュミス）
    pub pool_misses: u64,
    /// プールに返却された回数
    pub pool_returns: u64,
    /// プールから溢れた回数
    pub pool_overflows: u64,
    /// 初期化スキップ回数
    pub init_skipped: u64,
    /// バッチ割り当て回数
    pub batch_allocs: u64,
}

/// 型付きオブジェクトキャッシュ
///
/// ## 特徴
///
/// - `T: Default`の型に対して自動的にデフォルト初期化
/// - プーリングによる高速な再割り当て
/// - バッチ操作のサポート
pub struct ObjectCache<T> {
    /// 名前（デバッグ用）
    name: &'static str,
    /// 内部Slabキャッシュ
    inner: Arc<PoisonLock<SlabCache>>,
    /// プールされたオブジェクト
    pool: PoisonLock<Vec<NonNull<T>>>,
    /// 設定
    config: ObjectCacheConfig,
    /// 統計
    stats: PoisonLock<ObjectCacheStats>,
}

// SAFETY: ObjectCacheはスレッドセーフなロックで保護されている
unsafe impl<T: Send> Send for ObjectCache<T> {}
unsafe impl<T: Send> Sync for ObjectCache<T> {}

impl<T> ObjectCache<T> {
    /// 新しいオブジェクトキャッシュを作成
    pub fn new(name: &'static str) -> Self {
        Self::with_config(name, ObjectCacheConfig::default())
    }

    /// 設定付きで新しいオブジェクトキャッシュを作成
    pub fn with_config(name: &'static str, config: ObjectCacheConfig) -> Self {
        // ObjectCache is stateless regarding initialization (pools it manually),
        // so it IS mergeable.
        let flags = SlabFlags {
            mergeable: true,
            read_only: false,
        };
        let inner = SlabCacheRegistry::global().get_or_create(core::mem::size_of::<T>(), flags);
        Self {
            name,
            inner,
            pool: PoisonLock::new(Vec::with_capacity(config.max_pooled)),
            config,
            stats: PoisonLock::new(ObjectCacheStats::default()),
        }
    }

    /// 名前を取得
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// オブジェクトを割り当て（未初期化）
    ///
    /// # Safety
    ///
    /// 返されたポインタは未初期化状態。使用前に初期化が必要。
    pub unsafe fn alloc_uninit(&self) -> Option<NonNull<T>> {
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        stats.allocations += 1;

        // プールから取得を試みる
        {
            let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ptr) = pool.pop() {
                stats.pool_hits += 1;
                return Some(ptr);
            }
        }

        // キャッシュミス: Slabから新規割り当て
        stats.pool_misses += 1;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.allocate().map(|ptr| ptr.cast())
    }

    /// オブジェクトを解放
    ///
    /// # Safety
    ///
    /// - `ptr`はこのキャッシュから割り当てられたもの
    /// - 解放後は使用禁止
    pub unsafe fn free(&self, ptr: NonNull<T>) {
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        stats.deallocations += 1;

        // プールに返却を試みる
        {
            let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            if pool.len() < self.config.max_pooled {
                pool.push(ptr);
                stats.pool_returns += 1;
                return;
            }
        }

        // プール満杯: Slabに返却
        stats.pool_overflows += 1;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.deallocate(ptr.cast());
    }

    /// バッチ割り当て（未初期化）
    ///
    /// # Safety
    ///
    /// 返されたポインタは全て未初期化状態。
    pub unsafe fn alloc_batch_uninit(&self, count: usize) -> Vec<NonNull<T>> {
        let mut result = Vec::with_capacity(count);
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        stats.batch_allocs += 1;
        drop(stats);

        for _ in 0..count {
            if let Some(ptr) = self.alloc_uninit() {
                result.push(ptr);
            } else {
                break;
            }
        }

        result
    }

    /// バッチ解放
    ///
    /// # Safety
    ///
    /// 全てのポインタはこのキャッシュから割り当てられたもの。
    pub unsafe fn free_batch(&self, ptrs: &[NonNull<T>]) {
        for &ptr in ptrs {
            self.free(ptr);
        }
    }

    /// プールを縮小
    ///
    /// `shrink_threshold`を超えるオブジェクトをSlabに返却。
    pub fn shrink(&self) {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        while pool.len() > self.config.shrink_threshold {
            if let Some(ptr) = pool.pop() {
                unsafe {
                    inner.deallocate(ptr.cast());
                }
            }
        }
    }

    /// プールをクリア
    pub fn clear_pool(&self) {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        while let Some(ptr) = pool.pop() {
            unsafe {
                inner.deallocate(ptr.cast());
            }
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> ObjectCacheStats {
        *self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// キャッシュヒット率を計算
    pub fn hit_rate(&self) -> f32 {
        let stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        let total = stats.pool_hits + stats.pool_misses;
        if total == 0 {
            0.0
        } else {
            stats.pool_hits as f32 / total as f32 * 100.0
        }
    }

    /// プールのサイズを取得
    pub fn pool_size(&self) -> usize {
        self.pool.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl<T: Default> ObjectCache<T> {
    /// オブジェクトを割り当て（デフォルト初期化済み）
    ///
    /// プールから取得した場合、`skip_init_on_reuse`が`true`なら
    /// 初期化をスキップする。
    pub fn alloc(&self) -> Option<NonNull<T>> {
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        stats.allocations += 1;

        // プールから取得を試みる
        {
            let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ptr) = pool.pop() {
                stats.pool_hits += 1;
                if self.config.skip_init_on_reuse {
                    stats.init_skipped += 1;
                } else {
                    // 再初期化
                    unsafe {
                        core::ptr::write(ptr.as_ptr(), T::default());
                    }
                }
                return Some(ptr);
            }
        }

        // キャッシュミス: Slabから新規割り当て + 初期化
        stats.pool_misses += 1;
        drop(stats);

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.allocate().map(|ptr| {
            let typed_ptr: NonNull<T> = ptr.cast();
            unsafe {
                core::ptr::write(typed_ptr.as_ptr(), T::default());
            }
            typed_ptr
        })
    }

    /// バッチ割り当て（デフォルト初期化済み）
    pub fn alloc_batch(&self, count: usize) -> Vec<NonNull<T>> {
        let mut result = Vec::with_capacity(count);
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        stats.batch_allocs += 1;
        drop(stats);

        for _ in 0..count {
            if let Some(ptr) = self.alloc() {
                result.push(ptr);
            } else {
                break;
            }
        }

        result
    }
}

impl<T> Drop for ObjectCache<T> {
    fn drop(&mut self) {
        // プール内のオブジェクトをSlabに返却
        self.clear_pool();
    }
}

#[cfg(test)]
#[path = "../tests.rs"]
mod tests;
