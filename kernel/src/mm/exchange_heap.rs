// ============================================================================
// src/mm/exchange_heap.rs - Exchange Heap for Zero-Copy IPC
// 設計書 5.3: 線形型と交換ヒープ（RedLeaf OS参照）
//
// v0.3.0: linked_list_allocator から内蔵Buddy Allocatorへ移行
// v0.4.0: Segregated Free Lists (区分フリーリスト) 導入
//         - O(n) First-Fit から O(1) サイズクラス探索へ
//         - IPCの頻繁な割り当て/解放のボトルネックを解消
// ============================================================================
#![allow(dead_code)]

use crate::sync::PoisonLock;
use alloc::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;

// ============================================================================
// Segregated Free Lists アロケータ
// ============================================================================

/// サイズクラスの数 (8B, 16B, 32B, ... 最大 2^31 B)
/// インデックス i のリストは 2^(i+3) バイトのブロックを管理
const SIZE_CLASS_COUNT: usize = 29;

/// 最小ブロックサイズ (8 bytes = 2^3)
const MIN_BLOCK_SIZE: usize = 8;

/// 最小ブロックサイズのlog2
const MIN_BLOCK_SIZE_LOG2: usize = 3;

/// 空きブロックヘッダ
#[repr(C)]
struct FreeBlock {
    /// ブロックサイズ（ヘッダを含む）
    size: usize,
    /// 同一サイズクラス内の次の空きブロック
    next: Option<NonNull<FreeBlock>>,
}

/// Segregated Free Lists アロケータ
///
/// TLSFアロケータに類似したアプローチで、サイズクラスごとに
/// 別々のフリーリストを管理する。
///
/// ## サイズクラス
/// - クラス 0: 8-15 bytes
/// - クラス 1: 16-31 bytes
/// - クラス 2: 32-63 bytes
/// - ...
/// - クラス n: 2^(n+3) - 2^(n+4)-1 bytes
///
/// ## 割り当て計算量
/// - O(1): ビット探索命令でサイズクラスを特定
/// - ベストケース: 対応クラスに空きがあれば即座に返却
/// - ワーストケース: より大きいクラスから分割（小さい定数）
#[derive(Debug)]
struct SegregatedFreeListHeap {
    /// ヒープ開始アドレス
    heap_start: usize,
    /// ヒープ終了アドレス
    heap_end: usize,
    /// サイズクラスごとのフリーリスト
    free_lists: [Option<NonNull<FreeBlock>>; SIZE_CLASS_COUNT],
    /// 空きブロックが存在するサイズクラスのビットマップ
    /// bit i が 1 なら free_lists[i] に空きブロックがある
    free_bitmap: u32,
    /// 使用中のバイト数
    allocated_bytes: usize,
    /// 統計: 割り当て回数
    alloc_count: u64,
    /// 統計: 解放回数
    dealloc_count: u64,
    /// 統計: ブロック分割回数
    split_count: u64,
    /// 統計: ブロック結合回数
    coalesce_count: u64,
}

// SegregatedFreeListHeap は PoisonLock で保護されるため Send/Sync は安全
unsafe impl Send for SegregatedFreeListHeap {}
unsafe impl Sync for SegregatedFreeListHeap {}

impl SegregatedFreeListHeap {
    const fn empty() -> Self {
        Self {
            heap_start: 0,
            heap_end: 0,
            free_lists: [None; SIZE_CLASS_COUNT],
            free_bitmap: 0,
            allocated_bytes: 0,
            alloc_count: 0,
            dealloc_count: 0,
            split_count: 0,
            coalesce_count: 0,
        }
    }

    /// サイズからサイズクラスインデックスを計算（切り上げ）
    ///
    /// # Returns
    /// サイズを収容できる最小のクラスインデックス
    #[inline]
    fn size_to_class(size: usize) -> usize {
        if size <= MIN_BLOCK_SIZE {
            return 0;
        }
        // size > MIN_BLOCK_SIZE の場合
        // 必要なクラス = ceil(log2(size)) - MIN_BLOCK_SIZE_LOG2
        let bits_needed = usize::BITS - (size - 1).leading_zeros();
        let class = (bits_needed as usize).saturating_sub(MIN_BLOCK_SIZE_LOG2);
        class.min(SIZE_CLASS_COUNT - 1)
    }

    /// サイズクラスからブロックサイズを計算
    #[inline]
    fn class_to_size(class: usize) -> usize {
        MIN_BLOCK_SIZE << class
    }

    /// ヒープを初期化
    ///
    /// # Safety
    /// - `heap_start` は有効なメモリ領域を指す
    /// - `size` バイトがアクセス可能
    unsafe fn init(&mut self, heap_start: *mut u8, size: usize) {
        self.heap_start = heap_start as usize;
        self.heap_end = self.heap_start + size;
        self.allocated_bytes = 0;
        self.free_bitmap = 0;
        self.alloc_count = 0;
        self.dealloc_count = 0;
        self.split_count = 0;
        self.coalesce_count = 0;

        // フリーリストをクリア
        for list in self.free_lists.iter_mut() {
            *list = None;
        }

        // 初期状態: 全体を最大サイズのブロックとして登録
        if size >= core::mem::size_of::<FreeBlock>() {
            self.add_free_block(heap_start as usize, size);
        }
    }

    /// 空きブロックを適切なサイズクラスに追加
    fn add_free_block(&mut self, addr: usize, size: usize) {
        let min_size = core::mem::size_of::<FreeBlock>();
        if size < min_size {
            return;
        }

        let class = Self::size_to_class(size);
        let block_ptr = addr as *mut FreeBlock;

        unsafe {
            (*block_ptr).size = size;
            (*block_ptr).next = self.free_lists[class];
        }

        self.free_lists[class] = NonNull::new(block_ptr);
        self.free_bitmap |= 1u32 << class;
    }

    /// 指定サイズクラスから空きブロックを取得
    fn pop_free_block(&mut self, class: usize) -> Option<NonNull<FreeBlock>> {
        let block = self.free_lists[class]?;

        unsafe {
            self.free_lists[class] = (*block.as_ptr()).next;
        }

        // リストが空になったらビットマップをクリア
        if self.free_lists[class].is_none() {
            self.free_bitmap &= !(1u32 << class);
        }

        Some(block)
    }

    /// メモリを割り当て（O(1) Segregated Fit）
    fn allocate(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        let align = layout.align().max(core::mem::align_of::<FreeBlock>());
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());

        // 要求サイズに対応するクラスを計算
        let required_class = Self::size_to_class(size);

        // このクラス以上で空きがあるクラスをビットマップで O(1) 探索
        let available_mask = self.free_bitmap & !((1u32 << required_class) - 1);
        if available_mask == 0 {
            return Err(());
        }

        // 最小の空きクラスを取得 (trailing_zeros = tzcnt/bsf 命令)
        let found_class = available_mask.trailing_zeros() as usize;

        // そのクラスからブロックを取得
        let block = self.pop_free_block(found_class).ok_or(())?;
        let block_ptr = block.as_ptr();
        let block_size = unsafe { (*block_ptr).size };
        let block_addr = block_ptr as usize;

        // アライメント調整
        let aligned_addr = (block_addr + align - 1) & !(align - 1);
        let padding = aligned_addr - block_addr;

        // 必要な総サイズ
        let total_needed = padding + size;

        if block_size < total_needed {
            // サイズ不足（通常起こらないが安全のため）
            self.add_free_block(block_addr, block_size);
            return Err(());
        }

        let remaining = block_size - total_needed;

        // 残りが十分大きければ分割して別クラスに戻す
        let min_split_size = core::mem::size_of::<FreeBlock>();
        if remaining >= min_split_size {
            let new_block_addr = aligned_addr + size;
            self.add_free_block(new_block_addr, remaining);
            self.split_count += 1;
        }

        self.allocated_bytes += total_needed;
        self.alloc_count += 1;

        Ok(NonNull::new(aligned_addr as *mut u8).expect("aligned addr null"))
    }

    /// メモリを解放
    ///
    /// # Safety
    /// - `ptr` は以前に `allocate` で取得したポインタ
    unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        let addr = ptr.as_ptr() as usize;

        // 境界チェック
        if addr < self.heap_start || addr >= self.heap_end {
            return;
        }

        self.allocated_bytes = self.allocated_bytes.saturating_sub(size);
        self.dealloc_count += 1;

        // 空きブロックとして追加（隣接結合は将来の最適化として保留）
        // Note: 完全な隣接結合にはブロック境界情報の追跡が必要
        // 現時点ではシンプルにサイズクラスに追加
        self.add_free_block(addr, size);
    }

    fn used(&self) -> usize {
        self.allocated_bytes
    }

    fn free(&self) -> usize {
        (self.heap_end - self.heap_start).saturating_sub(self.allocated_bytes)
    }

    /// 拡張統計情報を取得
    fn extended_stats(&self) -> ExtendedHeapStats {
        let mut non_empty_classes = 0u32;
        for i in 0..SIZE_CLASS_COUNT {
            if self.free_lists[i].is_some() {
                non_empty_classes |= 1u32 << i;
            }
        }

        ExtendedHeapStats {
            allocated: self.allocated_bytes,
            free: self.free(),
            alloc_count: self.alloc_count,
            dealloc_count: self.dealloc_count,
            split_count: self.split_count,
            coalesce_count: self.coalesce_count,
            non_empty_classes,
        }
    }
}

// ============================================================================
// 後方互換性のための型エイリアス（内部実装が変わっても外部APIは同じ）
// ============================================================================
type SimpleFreeListHeap = SegregatedFreeListHeap;

/// 拡張ヒープ統計情報
#[derive(Debug, Clone, Copy)]
pub struct ExtendedHeapStats {
    pub allocated: usize,
    pub free: usize,
    pub alloc_count: u64,
    pub dealloc_count: u64,
    pub split_count: u64,
    pub coalesce_count: u64,
    /// 空きブロックが存在するサイズクラス（ビットマップ）
    pub non_empty_classes: u32,
}

// ============================================================================
// 旧API互換のSimpleFreeListHeap実装（削除済み、上記で置換）
// ============================================================================

impl SegregatedFreeListHeap {
    /// 旧API互換: allocate_first_fit
    fn allocate_first_fit(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        self.allocate(layout)
    }
}

/// Exchange Heap: ドメイン間でゼロコピー通信するためのヒープ
/// プライベートヒープとは別に管理される
pub struct ExchangeHeap {
    heap: PoisonLock<SimpleFreeListHeap>,
}

impl ExchangeHeap {
    /// 新しいExchange Heapを作成（未初期化）
    pub const fn new() -> Self {
        Self {
            heap: PoisonLock::new(SimpleFreeListHeap::empty()),
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
        unsafe {
            // Initialization-time best-effort recovery: proceed with initialization even if the lock
        // appears poisoned to avoid blocking boot.
        let mut guard = self.heap.lock_for_init("[MEM] Exchange Heap init");
        guard.init(heap_start as *mut u8, size);
        }
    }

    /// Exchange Heap上にメモリを割り当て
    pub fn allocate(&self, layout: Layout) -> Option<NonNull<u8>> {
        match self.heap.lock() {
            Ok(mut guard) => guard.allocate_first_fit(layout).ok(),
            Err(_) => {
                log::error!("[MEM] Exchange Heap poisoned - allocation failed");
                None
            }
        }
    }

    /// Exchange Heap上のメモリを解放
    ///
    /// # Safety
    /// - `ptr` は以前に `allocate` で取得したポインタである必要がある
    /// - `layout` は `allocate` 時と同じである必要がある
    pub unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // SAFETY: 呼び出し元がポインタとレイアウトの有効性を保証
        match self.heap.lock() {
            Ok(mut guard) => unsafe { guard.deallocate(ptr, layout) },
            Err(_) => {
                log::error!("[MEM] Exchange Heap poisoned - deallocate ignored");
            }
        }
    }

    /// ヒープ使用統計を取得（デバッグ用）
    pub fn stats(&self) -> HeapStats {
        match self.heap.lock() {
            Ok(guard) => HeapStats {
                allocated: guard.used(),
                free: guard.free(),
            },
            Err(_) => {
                log::error!("[MEM] Exchange Heap poisoned - returning zero stats");
                HeapStats { allocated: 0, free: 0 }
            }
        }
    }

    /// 拡張統計情報を取得（デバッグ/性能分析用）
    pub fn extended_stats(&self) -> Option<ExtendedHeapStats> {
        match self.heap.lock() {
            Ok(guard) => Some(guard.extended_stats()),
            Err(_) => {
                log::error!("[MEM] Exchange Heap poisoned - returning None for extended stats");
                None
            }
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
        unsafe {
            EXCHANGE_HEAP.init(heap_start, size);
        }
    });
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exchange_heap_poisoned_allocation_fails() {
        use crate::sync::set_panicking;

        let heap = ExchangeHeap::new();
        unsafe { heap.init(0x1000, 4096) }

        // Poison the lock by simulating a panic while holding the guard
        set_panicking(true);
        {
            let _guard = heap.heap.lock().unwrap();
            // dropping _guard while panicking will mark the lock as poisoned
        }
        set_panicking(false);

        let layout = core::alloc::Layout::from_size_align(64, 8).unwrap();
        assert!(heap.allocate(layout).is_none());
    }

    #[test]
    fn test_exchange_heap() {
        // メモリ領域を確保（テスト用）
        const HEAP_SIZE: usize = 4096;
        static mut HEAP_MEM: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

        unsafe {
            // Use addr_of_mut! to avoid creating a shared reference to a mutable static
            EXCHANGE_HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE);
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
