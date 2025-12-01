// ============================================================================
// src/mm/exchange_heap.rs - Exchange Heap for Zero-Copy IPC
// 設計書 5.3: 線形型と交換ヒープ（RedLeaf OS参照）
// ============================================================================
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
        self.heap.lock().init(heap_start as *mut u8, size);
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
        self.heap.lock().deallocate(ptr, layout);
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
            self.deallocate(non_null, layout);
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
        EXCHANGE_HEAP.init(heap_start, size);
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
    ptr.as_ptr().drop_in_place();
    EXCHANGE_HEAP.deallocate(ptr.cast(), layout);
}

/// 生のポインタとレイアウトを指定してExchange Heapから解放
/// 
/// # Safety
/// - `ptr` はExchange Heap上に割り当てられたメモリである必要がある
/// - `layout` は割り当て時と同じである必要がある
pub unsafe fn deallocate_raw(ptr: NonNull<u8>, layout: Layout) {
    EXCHANGE_HEAP.deallocate(ptr, layout);
}

/// Exchange Heapの統計を取得
pub fn exchange_heap_stats() -> HeapStats {
    EXCHANGE_HEAP.stats()
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
