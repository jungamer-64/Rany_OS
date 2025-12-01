// ============================================================================
// src/mm/exchange_heap.rs - Exchange Heap for Zero-Copy IPC
// 設計書 5.3: 線形型と交換ヒープ（RedLeaf OS参照）
// ============================================================================
#![allow(dead_code)]

use alloc::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use spin::Mutex;
use linked_list_allocator::Heap;

/// Exchange Heap: ドメイン間でゼロコピー通信するためのヒープ
/// プライベートヒープとは別に管理される
pub struct ExchangeHeap {
    heap: Mutex<Heap>,
}

impl ExchangeHeap {
    /// 新しいExchange Heapを作成（未初期化）
    pub const fn new() -> Self {
        Self {
            heap: Mutex::new(Heap::empty()),
        }
    }
    
    /// Exchange Heapを指定アドレスとサイズで初期化
    /// 
    /// # Safety
    /// - `heap_start` は有効なメモリ領域を指している必要がある
    /// - `size` はそのメモリ領域のサイズと一致する必要がある
    /// - このメモリ領域は他のアロケータと重複してはならない
    pub unsafe fn init(&self, heap_start: usize, size: usize) {
        // SAFETY: 呼び出し元がメモリ領域の有効性を保証
        unsafe { self.heap.lock().init(heap_start as *mut u8, size); }
    }
    
    /// Exchange Heap上にメモリを割り当て
    pub fn allocate(&self, layout: Layout) -> Option<NonNull<u8>> {
        self.heap
            .lock()
            .allocate_first_fit(layout)
            .ok()
    }
    
    /// Exchange Heap上のメモリを解放
    /// 
    /// # Safety
    /// - `ptr` は以前に `allocate` で取得したポインタである必要がある
    /// - `layout` は `allocate` 時と同じである必要がある
    pub unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // SAFETY: 呼び出し元がポインタとレイアウトの有効性を保証
        unsafe { self.heap.lock().deallocate(ptr, layout); }
    }
    
    /// ヒープ使用統計を取得（デバッグ用）
    pub fn stats(&self) -> HeapStats {
        let heap = self.heap.lock();
        HeapStats {
            allocated: heap.used(),
            free: heap.free(),
        }
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
            unsafe { self.deallocate(non_null, layout); }
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
static EXCHANGE_HEAP: ExchangeHeap = ExchangeHeap::new();

/// Exchange Heapが初期化済みかどうか
static INITIALIZED: spin::Once<()> = spin::Once::new();

/// Exchange Heapの初期化関数
/// 
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_exchange_heap(heap_start: usize, size: usize) {
    INITIALIZED.call_once(|| {
        // SAFETY: 呼び出し元がメモリ領域の有効性を保証
        unsafe { EXCHANGE_HEAP.init(heap_start, size); }
    });
}

/// Exchange Heap経由でメモリを割り当て（RRefで使用）
pub fn allocate_on_exchange<T>(value: T) -> Option<NonNull<T>> {
    let layout = Layout::new::<T>();
    EXCHANGE_HEAP.allocate(layout).map(|ptr| {
        unsafe {
            let typed_ptr = ptr.as_ptr() as *mut T;
            typed_ptr.write(value);
            NonNull::new_unchecked(typed_ptr)
        }
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
    unsafe { EXCHANGE_HEAP.deallocate(ptr, layout); }
}

/// Exchange Heapの統計を取得
pub fn exchange_heap_stats() -> HeapStats {
    EXCHANGE_HEAP.stats()
}

// ============================================================================
// 安全なスライス割り当て API
// 未初期化メモリの問題を型レベルで防ぐ
// ============================================================================

use core::mem::MaybeUninit;
use core::marker::PhantomData;

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
        unsafe { EXCHANGE_HEAP.deallocate(ptr.cast(), layout); }
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
    fn new(ptr: NonNull<T>, len: usize, layout: Layout) -> Self {
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
    
    /// 要素を初期化（インデックス指定）
    /// 
    /// # Safety
    /// 同じインデックスを2回初期化しないこと
    pub unsafe fn init_at(&mut self, index: usize, value: T) {
        debug_assert!(index < self.len);
        unsafe {
            self.ptr.as_ptr().add(index).write(MaybeUninit::new(value));
        }
        // 注: この実装では厳密な追跡は行わない
        // より正確な追跡が必要な場合はビットマップを使用
        self.initialized_count = self.initialized_count.max(index + 1);
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
        let slice = InitializedSlice::new(
            self.ptr.cast(),
            self.len,
            self.layout,
        );
        
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_exchange_heap() {
        // メモリ領域を確保（テスト用）
        const HEAP_SIZE: usize = 4096;
        static mut HEAP_MEM: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
        
        unsafe {
            EXCHANGE_HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE);
        }
        
        // アロケーション
        let layout = Layout::from_size_align(64, 8).unwrap();
        let ptr = EXCHANGE_HEAP.allocate(layout).expect("Allocation failed");
        
        // 統計確認
        let stats = EXCHANGE_HEAP.stats();
        assert!(stats.allocated > 0);
        
        // デアロケーション
        unsafe {
            EXCHANGE_HEAP.deallocate(ptr, layout);
        }
    }
}
