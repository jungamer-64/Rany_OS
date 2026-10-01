use super::*;

pub use crate::heap::ExtendedHeapStats;

/// CPU magazines retain backing independently of this facade's lifetime.
/// Each CPU binds at most one backing and can only drain its own magazine.
pub struct ExchangeHeap {
    backing: spin::Once<Arc<PoisonLock<ExchangeBlocks>>>,
    admission: PoisonLock<()>,
}
impl ExchangeHeap {
    pub const fn new() -> Self {
        Self {
            backing: spin::Once::new(),
            admission: PoisonLock::new(()),
        }
    }

    /// Duplicate admission, poisoning or metadata allocation failure returns
    /// incoming RAM untouched. Backing publication cannot replace a live owner.
    pub(crate) fn initialize(
        &self,
        memory: crate::heap::HeapMemory,
    ) -> Result<(), crate::heap::HeapMemory> {
        let Ok(_admission) = self.admission.lock() else {
            return Err(memory);
        };
        if self.backing.get().is_some() {
            return Err(memory);
        }
        let Ok(backing) = Arc::try_new(PoisonLock::new(ExchangeBlocks::empty())) else {
            return Err(memory);
        };
        match backing.lock() {
            Ok(mut blocks) => blocks.initialize(memory)?,
            Err(_) => return Err(memory),
        }
        self.backing.call_once(|| backing);
        Ok(())
    }

    fn bind_current(backing: &Arc<PoisonLock<ExchangeBlocks>>) {
        let Some(cpu) = crate::cpu::CurrentCpu::acquire() else {
            return;
        };
        if cpu.with_exchange_cache(|cache| cache.matches(backing)) == Some(true) {
            return;
        }
        if let Some(old) =
            cpu.with_exchange_cache(|cache| core::mem::replace(cache, ExchangeMagazine::new()))
        {
            old.release();
        }
        // Establish the cold binding lease outside the short CPU borrow.
        // Hot allocation/free only compares the retained identity.
        let mut lease = Some(Arc::clone(backing));
        if let Some(cpu) = crate::cpu::CurrentCpu::acquire() {
            cpu.with_exchange_cache(|cache| {
                if cache.backing.is_none() {
                    cache.backing = lease.take();
                }
            });
        }
    }

    pub fn allocate(&self, layout: Layout) -> Option<NonNull<u8>> {
        let backing = self.backing.get()?;
        let class = CacheClass::for_layout(layout);
        let mut bound = false;
        if let Some(class) = class {
            if let Some(cpu) = crate::cpu::CurrentCpu::acquire() {
                if let Some((matches, block)) = cpu.with_exchange_cache(|cache| {
                    let matches = cache.matches(backing);
                    (matches, matches.then(|| cache.cache.take(class)).flatten())
                }) {
                    if let Some(block) = block {
                        return Some(block.into_pointer());
                    }
                    bound = matches;
                }
            }
            if !bound {
                Self::bind_current(backing);
                bound = crate::cpu::CurrentCpu::acquire()
                    .and_then(|cpu| cpu.with_exchange_cache(|cache| cache.matches(backing)))
                    == Some(true);
            }
        }
        let layout = class.map_or(layout, CacheClass::layout);
        let mut batch = [const { None }; 8];
        let result = {
            let mut blocks = backing.lock().ok()?;
            let result = blocks.allocate(layout)?;
            if let Some(class) = class.filter(|_| bound) {
                for slot in &mut batch {
                    let Some(pointer) = blocks.allocate(layout) else {
                        break;
                    };
                    // SAFETY: a fresh exclusive canonical allocation, retained
                    // by this exact backing before magazine publication.
                    *slot = Some(unsafe { CachedAllocation::retain(pointer, class) });
                }
            }
            result
        };
        if let Some(cpu) = crate::cpu::CurrentCpu::acquire() {
            cpu.with_exchange_cache(|cache| {
                if cache.matches(backing) {
                    for slot in &mut batch {
                        if let Some(block) = slot.take() {
                            *slot = cache.cache.insert(block).err();
                        }
                    }
                }
            });
        }
        if batch.iter().any(Option::is_some) {
            if let Ok(mut blocks) = backing.lock() {
                for block in batch.into_iter().flatten() {
                    // SAFETY: rejected publication preserves the unique entry.
                    unsafe { blocks.deallocate(block.into_pointer(), layout) };
                }
            }
        }
        Some(result)
    }

    /// # Safety
    /// `ptr` is this heap's live exclusive allocation with the original Layout.
    /// No payload borrow, prior return or outstanding DMA use remains.
    pub unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        let backing = self.backing.get().expect("live allocation retains backing");
        let class = CacheClass::for_layout(layout);
        let mut pointer = ptr;
        if let Some(class) = class {
            // SAFETY: caller consumes this backing's exclusive canonical block.
            let mut pending = Some(unsafe { CachedAllocation::retain(pointer, class) });
            let matches = crate::cpu::CurrentCpu::acquire().and_then(|cpu| {
                cpu.with_exchange_cache(|cache| {
                    if !cache.matches(backing) {
                        return false;
                    }
                    pending = cache
                        .cache
                        .insert(pending.take().expect("pending owner"))
                        .err();
                    true
                })
            }) == Some(true);
            if !matches {
                Self::bind_current(backing);
                if let Some(cpu) = crate::cpu::CurrentCpu::acquire() {
                    cpu.with_exchange_cache(|cache| {
                        if cache.matches(backing) {
                            pending = cache
                                .cache
                                .insert(pending.take().expect("pending owner"))
                                .err();
                        }
                    });
                }
            }
            let Some(block) = pending else {
                return;
            };
            pointer = block.into_pointer();
        }
        if let Ok(mut blocks) = backing.lock() {
            // SAFETY: cache rejection leaves this block owned by the caller.
            unsafe { blocks.deallocate(pointer, class.map_or(layout, CacheClass::layout)) };
        }
    }

    pub fn stats(&self) -> HeapStats {
        self.extended_stats().map_or(
            HeapStats {
                allocated: 0,
                free: 0,
            },
            |stats| HeapStats {
                allocated: stats.allocated,
                free: stats.free,
            },
        )
    }
    pub fn extended_stats(&self) -> Option<ExtendedHeapStats> {
        Some(self.backing.get()?.lock().ok()?.stats())
    }
}

unsafe impl GlobalAlloc for ExchangeHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocate(layout)
            .map(|p| p.as_ptr())
            .unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(non_null) = NonNull::new(ptr) {
            // SAFETY: GlobalAllocの契約でptrは以前にallocで取得したもの
            unsafe {
                self.deallocate(non_null, layout);
            }
        }
    }
}

/// ヒープ統計情報
#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    pub allocated: usize,
    pub free: usize,
}

/// Exchange Heap インスタンス（グローバルアロケータではない）
/// RRefで使用する専用のヒープ
pub(crate) static EXCHANGE_HEAP: ExchangeHeap = ExchangeHeap::new();

/// Exchange Heap経由でメモリを割り当て（RRefで使用）
pub fn allocate_on_exchange<T>(value: T) -> Option<NonNull<T>> {
    let layout = Layout::new::<T>();
    EXCHANGE_HEAP.allocate(layout).map(|ptr| {
        let typed_ptr = ptr.as_ptr() as *mut T;
        unsafe {
            typed_ptr.write(value);
        }
        NonNull::new(typed_ptr).expect("typed_ptr null")
    })
}

/// Exchange Heap上のメモリを解放
///
/// # Safety
/// - `ptr` はExchange Heap上に割り当てられたメモリである必要がある
pub unsafe fn deallocate_on_exchange<T>(ptr: NonNull<T>) {
    let layout = Layout::new::<T>();
    // SAFETY: 呼び出し元がポインタの有効性を保証
    unsafe {
        ptr.as_ptr().drop_in_place();
        EXCHANGE_HEAP.deallocate(ptr.cast(), layout);
    }
}

/// 生のポインタとレイアウトを指定してExchange Heapから解放
///
/// # Safety
/// - `ptr` はExchange Heap上に割り当てられたメモリである必要がある
/// - `layout` は割り当て時と同じである必要がある
pub unsafe fn deallocate_raw(ptr: NonNull<u8>, layout: Layout) {
    // SAFETY: 呼び出し元がポインタとレイアウトの有効性を保証
    unsafe {
        EXCHANGE_HEAP.deallocate(ptr, layout);
    }
}

/// 生のレイアウトを指定してExchange Heapからメモリを割り当て
pub fn allocate_raw(layout: Layout) -> Option<NonNull<u8>> {
    EXCHANGE_HEAP.allocate(layout)
}

/// Exchange Heapの統計を取得
pub fn exchange_heap_stats() -> HeapStats {
    EXCHANGE_HEAP.stats()
}

// ============================================================================
// 安全なスライス割り当て API
// 未初期化メモリの問題を型レベルで防ぐ
// ============================================================================

use core::marker::PhantomData;
use core::mem::MaybeUninit;

/// Exchange Heap上にゼロ初期化されたスライスを割り当て
///
/// # Arguments
/// * `len` - スライスの要素数
///
/// # Returns
/// 初期化済みスライスへのポインタとレイアウト
///
/// # Safety Guarantee
/// 返されるメモリは必ずゼロ初期化されている
pub fn allocate_zeroed_slice<T: Sized>(len: usize) -> Option<(NonNull<T>, Layout)> {
    if len == 0 {
        return None;
    }

    let layout = Layout::array::<T>(len).ok()?;
    let ptr = EXCHANGE_HEAP.allocate(layout)?;

    // ゼロ初期化
    unsafe {
        core::ptr::write_bytes(ptr.as_ptr(), 0, layout.size());
    }

    Some((ptr.cast(), layout))
}

/// Exchange Heap上に未初期化スライスを割り当て
///
/// MaybeUninit<T> の配列として返すことで、
/// 未初期化メモリへのアクセスを型レベルで防ぐ
///
/// # Arguments
/// * `len` - スライスの要素数
///
/// # Returns
/// 未初期化スライスへのポインタとレイアウト
pub fn allocate_uninit_slice<T: Sized>(len: usize) -> Option<(NonNull<MaybeUninit<T>>, Layout)> {
    if len == 0 {
        return None;
    }

    let layout = Layout::array::<MaybeUninit<T>>(len).ok()?;
    let ptr = EXCHANGE_HEAP.allocate(layout)?;

    Some((ptr.cast(), layout))
}

/// 初期化関数を使ってスライスを割り当て・初期化
///
/// # Arguments
/// * `len` - スライスの要素数
/// * `init` - 各要素を初期化する関数 (インデックスを受け取る)
///
/// # Returns
/// 初期化済みスライスへのポインタとレイアウト
pub fn allocate_slice_with<T: Sized, F>(len: usize, mut init: F) -> Option<(NonNull<T>, Layout)>
where
    F: FnMut(usize) -> T,
{
    if len == 0 {
        return None;
    }

    let layout = Layout::array::<T>(len).ok()?;
    let ptr = EXCHANGE_HEAP.allocate(layout)?;
    let typed_ptr = ptr.as_ptr() as *mut T;

    // 各要素を初期化
    unsafe {
        for i in 0..len {
            typed_ptr.add(i).write(init(i));
        }
    }

    Some((NonNull::new(typed_ptr)?, layout))
}

/// デフォルト値でスライスを割り当て・初期化
///
/// # Arguments
/// * `len` - スライスの要素数
///
/// # Returns
/// 初期化済みスライスへのポインタとレイアウト
pub fn allocate_slice_default<T: Sized + Default>(len: usize) -> Option<(NonNull<T>, Layout)> {
    allocate_slice_with(len, |_| T::default())
}

/// スライスを解放
///
/// # Safety
/// - `ptr` は `allocate_*_slice` で取得したポインタである必要がある
/// - `layout` は割り当て時と同じである必要がある
/// - 解放後にポインタを使用してはならない
pub unsafe fn deallocate_slice<T>(ptr: NonNull<T>, len: usize) {
    if len == 0 {
        return;
    }

    // 各要素のデストラクタを呼ぶ
    unsafe {
        for i in 0..len {
            ptr.as_ptr().add(i).drop_in_place();
        }
    }

    // メモリを解放
    if let Ok(layout) = Layout::array::<T>(len) {
        // SAFETY: ptrは有効なExchange Heap上のメモリ
        unsafe {
            EXCHANGE_HEAP.deallocate(ptr.cast(), layout);
        }
    }
}

// ============================================================================
// 型安全なスライスラッパー（改善案5: Exchange Heap型安全性強化）
// ============================================================================

/// 初期化済みスライス
///
/// 型レベルで初期化状態を追跡し、未初期化メモリへの
/// 不正アクセスを防止する。
pub struct InitializedSlice<T: Sized> {
    ptr: NonNull<T>,
    len: usize,
    layout: Layout,
    _marker: PhantomData<T>,
}

impl<T: Sized> InitializedSlice<T> {
    /// スライスを作成（内部使用のみ）
    pub(super) fn new(ptr: NonNull<T>, len: usize, layout: Layout) -> Self {
        Self {
            ptr,
            len,
            layout,
            _marker: PhantomData,
        }
    }

    /// ゼロ初期化されたスライスを作成
    pub fn zeroed(len: usize) -> Option<Self> {
        let (ptr, layout) = allocate_zeroed_slice::<T>(len)?;
        Some(Self::new(ptr, len, layout))
    }

    /// 初期化関数でスライスを作成
    pub fn with_init<F>(len: usize, init: F) -> Option<Self>
    where
        F: FnMut(usize) -> T,
    {
        let (ptr, layout) = allocate_slice_with(len, init)?;
        Some(Self::new(ptr, len, layout))
    }

    /// デフォルト値でスライスを作成
    pub fn with_default(len: usize) -> Option<Self>
    where
        T: Default,
    {
        let (ptr, layout) = allocate_slice_default(len)?;
        Some(Self::new(ptr, len, layout))
    }

    /// スライスへの参照を取得
    pub fn as_slice(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// 可変スライスへの参照を取得
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// 長さを取得
    pub fn len(&self) -> usize {
        self.len
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// ポインタを取得（危険）
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }

    /// 可変ポインタを取得（危険）
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr.as_ptr()
    }
}

impl<T: Sized> Drop for InitializedSlice<T> {
    fn drop(&mut self) {
        if self.len > 0 {
            unsafe {
                // 各要素のデストラクタを呼ぶ
                for i in 0..self.len {
                    self.ptr.as_ptr().add(i).drop_in_place();
                }
                // メモリを解放
                EXCHANGE_HEAP.deallocate(self.ptr.cast(), self.layout);
            }
        }
    }
}

impl<T: Sized> core::ops::Deref for InitializedSlice<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T: Sized> core::ops::DerefMut for InitializedSlice<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

// Send/Sync は T に依存
unsafe impl<T: Sized + Send> Send for InitializedSlice<T> {}
unsafe impl<T: Sized + Sync> Sync for InitializedSlice<T> {}

/// 未初期化スライス
///
/// MaybeUninitのラッパーとして、安全な初期化パターンを強制する。
/// 一度初期化したら InitializedSlice に変換する必要がある。
pub struct UninitializedSlice<T: Sized> {
    ptr: NonNull<MaybeUninit<T>>,
    len: usize,
    layout: Layout,
    /// 初期化済み要素数
    initialized_count: usize,
    _marker: PhantomData<T>,
}

impl<T: Sized> UninitializedSlice<T> {
    /// 未初期化スライスを作成
    pub fn new(len: usize) -> Option<Self> {
        let (ptr, layout) = allocate_uninit_slice::<T>(len)?;
        Some(Self {
            ptr,
            len,
            layout,
            initialized_count: 0,
            _marker: PhantomData,
        })
    }

    /// 長さを取得
    pub fn len(&self) -> usize {
        self.len
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 初期化済み要素数を取得
    pub fn initialized_count(&self) -> usize {
        self.initialized_count
    }

    /// 完全に初期化されているか
    pub fn is_fully_initialized(&self) -> bool {
        self.initialized_count == self.len
    }

    /// 連続して要素を初期化
    pub fn init_next(&mut self, value: T) -> Result<(), ExchangeHeapError> {
        if self.initialized_count >= self.len {
            return Err(ExchangeHeapError::SliceFull);
        }

        unsafe {
            self.init_at(self.initialized_count, value);
        }
        self.initialized_count += 1;
        Ok(())
    }

    /// 初期化済みスライスに変換
    ///
    /// # Safety
    /// 全要素が初期化されている必要がある
    pub unsafe fn assume_init(self) -> InitializedSlice<T> {
        let slice = InitializedSlice::new(self.ptr.cast(), self.len, self.layout);

        // selfのDropを防ぐ
        core::mem::forget(self);

        slice
    }

    /// 安全に初期化済みスライスに変換（全要素初期化済みの場合のみ）
    pub fn try_into_initialized(self) -> Result<InitializedSlice<T>, Self> {
        if self.is_fully_initialized() {
            Ok(unsafe { self.assume_init() })
        } else {
            Err(self)
        }
    }

    /// イテレータを使って初期化
    pub fn init_from_iter<I>(mut self, iter: I) -> Result<InitializedSlice<T>, Self>
    where
        I: IntoIterator<Item = T>,
    {
        for (i, value) in iter.into_iter().enumerate() {
            if i >= self.len {
                break;
            }
            unsafe {
                self.init_at(i, value);
            }
        }

        self.try_into_initialized()
    }
}

impl<T: Sized> Drop for UninitializedSlice<T> {
    fn drop(&mut self) {
        // 初期化済み要素のデストラクタを呼ぶ
        unsafe {
            for i in 0..self.initialized_count {
                let ptr = self.ptr.as_ptr().add(i);
                core::ptr::drop_in_place((*ptr).as_mut_ptr());
            }
            // メモリを解放
            EXCHANGE_HEAP.deallocate(self.ptr.cast(), self.layout);
        }
    }
}

/// Exchange Heapエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeHeapError {
    /// メモリ不足
    OutOfMemory,
    /// スライスが満杯
    SliceFull,
    /// 不完全な初期化
    PartiallyInitialized,
}
