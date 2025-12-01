// ============================================================================
// src/mm/slab_cache.rs - Per-Core Slab Cache
// 設計書 5.2 Tier3: コアローカルな高速割り当て
// LinuxのSLUBアロケータに類似。各コアごとに独立したロックで動作し、False Sharingを防ぐ
// ============================================================================
use core::alloc::Layout;
use core::ptr::NonNull;
use alloc::vec::Vec;
use spin::Mutex;

/// Slab内のオブジェクトサイズクラス（2のべき乗）
pub const SLAB_SIZES: [usize; 8] = [8, 16, 32, 64, 128, 256, 512, 1024];

/// 1つのSlabページのサイズ
const SLAB_PAGE_SIZE: usize = 4096;

/// キャッシュラインサイズ（False Sharing防止）
const CACHE_LINE_SIZE: usize = 64;

/// Slab内の空きオブジェクトリスト
struct FreeList {
    head: Option<NonNull<FreeNode>>,
    count: usize,
}

/// 空きリストのノード
struct FreeNode {
    next: Option<NonNull<FreeNode>>,
}

impl FreeList {
    const fn new() -> Self {
        Self {
            head: None,
            count: 0,
        }
    }
    
    /// 空きリストにノードを追加
    unsafe fn push(&mut self, ptr: NonNull<u8>) {
        let node = ptr.as_ptr() as *mut FreeNode;
        // SAFETY: ptrはFreeNodeとして使用可能なメモリを指している
        unsafe {
            (*node).next = self.head;
            self.head = Some(NonNull::new_unchecked(node));
        }
        self.count += 1;
    }
    
    /// 空きリストからノードを取得
    fn pop(&mut self) -> Option<NonNull<u8>> {
        self.head.map(|node| {
            unsafe {
                self.head = (*node.as_ptr()).next;
                self.count -= 1;
                node.cast()
            }
        })
    }
    
    fn is_empty(&self) -> bool {
        self.head.is_none()
    }
}

/// 1つのサイズクラス用のSlabキャッシュ
pub struct SlabCache {
    /// オブジェクトサイズ
    object_size: usize,
    /// 空きリスト
    free_list: FreeList,
    /// Slabページのリスト（メモリ管理用）
    pages: Vec<NonNull<u8>>,
    /// 統計: 割り当て回数
    /// 注: PerCoreCacheはコアごとにロックされるため、Atomicは不要
    alloc_count: usize,
    /// 統計: 解放回数
    dealloc_count: usize,
}

impl SlabCache {
    /// 新しいSlabキャッシュを作成
    pub fn new(object_size: usize) -> Self {
        // オブジェクトサイズはキャッシュラインの倍数に揃える（False Sharing防止）
        let aligned_size = ((object_size + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE) * CACHE_LINE_SIZE;
        let aligned_size = aligned_size.max(core::mem::size_of::<FreeNode>());
        
        Self {
            object_size: aligned_size,
            free_list: FreeList::new(),
            pages: Vec::new(),
            alloc_count: 0,
            dealloc_count: 0,
        }
    }
    
    /// オブジェクトを割り当て
    pub fn allocate(&mut self) -> Option<NonNull<u8>> {
        // 空きリストから取得を試みる
        if let Some(ptr) = self.free_list.pop() {
            self.alloc_count += 1;
            return Some(ptr);
        }
        
        // 空きリストが空なら新しいSlabページを追加
        self.grow()?;
        
        // 再度空きリストから取得
        let ptr = self.free_list.pop()?;
        self.alloc_count += 1;
        Some(ptr)
    }
    
    /// オブジェクトを解放
    pub unsafe fn deallocate(&mut self, ptr: NonNull<u8>) {
        // SAFETY: 呼び出し元がポインタの有効性を保証
        unsafe { self.free_list.push(ptr); }
        self.dealloc_count += 1;
    }
    
    /// 新しいSlabページを追加
    /// 
    /// Buddy Allocator から直接物理フレームを取得し、
    /// リニアマッピングで仮想アドレスに変換する。
    /// 
    /// これにより GlobalAlloc (LinkedListAllocator) を経由せず、
    /// Slab の高速性を維持したままページを補充できる。
    fn grow(&mut self) -> Option<()> {
        // Buddy Allocator から直接 4KiB フレームを取得
        let frame = crate::mm::buddy_allocator::buddy_alloc_frame()?;
        
        // 物理アドレス → 仮想アドレス (SAS リニアマッピング)
        let phys_addr = frame.start_address();
        let virt_addr = crate::mm::mapping::phys_to_virt(phys_addr);
        
        let page_ptr = unsafe {
            NonNull::new_unchecked(virt_addr.as_u64() as *mut u8)
        };
        
        // ページ内をオブジェクトに分割して空きリストに追加
        let objects_per_page = SLAB_PAGE_SIZE / self.object_size;
        for i in 0..objects_per_page {
            let obj_ptr = unsafe {
                NonNull::new_unchecked(page_ptr.as_ptr().add(i * self.object_size))
            };
            unsafe {
                self.free_list.push(obj_ptr);
            }
        }
        
        self.pages.push(page_ptr);
        Some(())
    }
    
    /// 統計情報を取得
    pub fn stats(&self) -> SlabStats {
        SlabStats {
            object_size: self.object_size,
            free_count: self.free_list.count,
            page_count: self.pages.len(),
            alloc_count: self.alloc_count,
            dealloc_count: self.dealloc_count,
        }
    }
}

/// Slab統計情報
#[derive(Debug, Clone)]
pub struct SlabStats {
    pub object_size: usize,
    pub free_count: usize,
    pub page_count: usize,
    pub alloc_count: usize,
    pub dealloc_count: usize,
}

// SAFETY: FreeList と SlabCache はSAS環境で使用され、
// Per-Core構造のため他コアから同時アクセスされない
unsafe impl Send for FreeList {}
unsafe impl Send for SlabCache {}
unsafe impl Send for PerCoreCache {}

/// Per-Core キャッシュ
/// 設計書: 各コア専用のSlabキャッシュ
#[repr(align(64))] // キャッシュラインにアライン
pub struct PerCoreCache {
    /// 各サイズクラスのSlabキャッシュ
    caches: [SlabCache; SLAB_SIZES.len()],
    /// CPU ID
    cpu_id: usize,
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
        }
    }
    
    /// サイズに適したキャッシュインデックスを取得
    fn size_class(size: usize) -> Option<usize> {
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
            unsafe { self.caches[class].deallocate(ptr); }
        } else {
            // グローバルヒープに返却
            // SAFETY: ptrはallocで割り当てられたものと仮定
            unsafe { alloc::alloc::dealloc(ptr.as_ptr(), layout); }
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
static PER_CORE_CACHES: [Mutex<Option<PerCoreCache>>; MAX_CPUS] = {
    // const配列の初期化（Rust 1.63+）
    const INIT: Mutex<Option<PerCoreCache>> = Mutex::new(None);
    [INIT; MAX_CPUS]
};

/// Per-Coreキャッシュシステムを初期化
pub fn init_per_core_caches(num_cpus: usize) {
    let num_cpus = num_cpus.min(MAX_CPUS);
    
    for cpu_id in 0..num_cpus {
        // 各コアのMutexに個別にアクセス（他コアをブロックしない）
        *PER_CORE_CACHES[cpu_id].lock() = Some(PerCoreCache::new(cpu_id));
    }
}

/// 現在のCPUのPer-Coreキャッシュから割り当て
/// 
/// # Note
/// - init_per_core_caches が呼ばれた後に使用する必要がある
/// - cpu_id は有効な範囲内である必要がある
/// - 各コアのキャッシュは独立してロックされるため、他コアをブロックしない
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
    let mut guard = PER_CORE_CACHES[cpu_id].lock();
    guard.as_mut().and_then(|cache| cache.allocate(layout))
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
    let mut guard = PER_CORE_CACHES[cpu_id].lock();
    if let Some(cache) = guard.as_mut() {
        // SAFETY: 呼び出し元が保証
        unsafe { cache.deallocate(ptr, layout); }
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
    let cpu_id = crate::mm::per_cpu::try_current_cpu_id()?;
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
    if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
        // SAFETY: 呼び出し元が保証
        unsafe { per_core_dealloc(cpu_id, ptr, layout); }
    }
    // 初期化前の場合は何もしない（リークするが安全）
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_slab_cache() {
        let mut cache = SlabCache::new(64);
        
        // 複数回割り当て
        let ptr1 = cache.allocate();
        assert!(ptr1.is_some());
        
        let ptr2 = cache.allocate();
        assert!(ptr2.is_some());
        
        // 異なるアドレス
        assert_ne!(ptr1.unwrap().as_ptr(), ptr2.unwrap().as_ptr());
        
        // 解放
        unsafe {
            cache.deallocate(ptr1.unwrap());
            cache.deallocate(ptr2.unwrap());
        }
        
        // 統計確認
        let stats = cache.stats();
        assert_eq!(stats.alloc_count, 2);
        assert_eq!(stats.dealloc_count, 2);
    }
}
