// ============================================================================
// src/memory.rs - 完全なメモリサブシステム初期化
// 設計書 5: メモリ管理戦略 - 階層型アロケータ設計
// ============================================================================
#![allow(dead_code)]

use x86_64::{PhysAddr, VirtAddr};
use linked_list_allocator::LockedHeap;
use alloc::vec::Vec;

/// 設計書 1.3: Higher Half Kernel Base (SAS)
pub const PHYSICAL_MEMORY_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// グローバルヒープアロケータ
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// ヒープの開始アドレスとサイズ
pub const HEAP_START: u64 = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

/// Exchange Heap の設定
pub const EXCHANGE_HEAP_START: u64 = 0x_5555_5555_0000;
pub const EXCHANGE_HEAP_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// メモリサブシステム初期化フラグ
static MEMORY_INITIALIZED: core::sync::atomic::AtomicBool = 
    core::sync::atomic::AtomicBool::new(false);

/// メモリサブシステムの完全初期化
/// 
/// 初期化順序:
/// 1. グローバルヒープ（allocが使えるようになる）
/// 2. Buddy Allocator（物理フレーム管理）
/// 3. Exchange Heap（ゼロコピーIPC用）
/// 4. Per-CPU データ構造
/// 5. Per-Core Slab Cache
pub fn init() {
    use core::sync::atomic::Ordering;
    
    if MEMORY_INITIALIZED.swap(true, Ordering::SeqCst) {
        crate::log!("[MEM] Warning: Memory already initialized\n");
        return;
    }
    
    crate::log!("[MEM] Initializing memory subsystem\n");
    
    // 1. グローバルヒープの初期化（最初に行う - allocが必要）
    init_global_heap();
    crate::log!("[MEM] Global heap initialized ({}KB)\n", HEAP_SIZE / 1024);
    
    // 2. Buddy Allocator の初期化（デフォルトのメモリ領域を使用）
    // 注: 本番環境ではブートローダーからメモリマップを取得
    let usable_regions = get_default_memory_regions();
    crate::log!("[MEM] Using {} memory regions\n", usable_regions.len());
    
    unsafe {
        crate::mm::init_buddy_allocator(&usable_regions);
    }
    crate::log!("[MEM] Buddy allocator initialized\n");
    
    // 3. Exchange Heap の初期化（ゼロコピーIPC用）
    unsafe {
        crate::mm::init_exchange_heap(
            EXCHANGE_HEAP_START as usize,
            EXCHANGE_HEAP_SIZE,
        );
    }
    crate::log!("[MEM] Exchange heap initialized ({}MB)\n", EXCHANGE_HEAP_SIZE / 1024 / 1024);
    
    // 4. Per-CPU データ構造の初期化（BSPのみ）
    unsafe {
        crate::mm::init_per_cpu(1);
        crate::mm::setup_current_cpu(0);
    }
    crate::log!("[MEM] Per-CPU data initialized\n");
    
    // 5. Per-Core Slab Cache の初期化
    crate::mm::init_per_core_caches(1);
    crate::log!("[MEM] Per-core slab caches initialized\n");
    
    // メモリ統計を表示
    print_memory_stats();
}

/// グローバルヒープの初期化
fn init_global_heap() {
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }
}

/// デフォルトのメモリ領域を取得
/// 本番環境ではブートローダーから取得するが、開発用にハードコード
fn get_default_memory_regions() -> Vec<(PhysAddr, u64)> {
    // 16MiB - 256MiB の範囲を使用可能として設定
    // 最初の16MiBはBIOSやカーネルのために予約
    alloc::vec![
        (PhysAddr::new(0x100_0000), 240 * 1024 * 1024), // 16MiB - 256MiB
    ]
}

/// メモリ統計を表示
fn print_memory_stats() {
    let buddy_stats = crate::mm::buddy_allocator_stats();
    
    crate::log!("[MEM] === Memory Statistics ===\n");
    crate::log!("[MEM] Total Frames: {}\n", buddy_stats.total_frames);
    crate::log!("[MEM] Free Frames: {} ({} KB)\n", 
        buddy_stats.free_frames, 
        buddy_stats.free_frames * 4
    );
    crate::log!("[MEM] Split Operations: {}\n", buddy_stats.split_count);
    crate::log!("[MEM] Coalesce Operations: {}\n", buddy_stats.coalesce_count);
    
    // Order別の統計を表示
    for (order, (blocks, _frames)) in buddy_stats.order_stats.iter().enumerate() {
        if *blocks > 0 {
            let block_size_kb = (1usize << order) * 4;
            crate::log!("[MEM]   Order {}: {} blocks ({}KB each)\n", 
                order, blocks, block_size_kb
            );
        }
    }
}

/// 物理アドレス -> 仮想アドレスへの変換 (O(1))
#[inline(always)]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64() + PHYSICAL_MEMORY_OFFSET)
}

/// 仮想アドレス -> 物理アドレスへの変換 (O(1))
#[inline(always)]
pub fn virt_to_phys(virt: VirtAddr) -> PhysAddr {
    PhysAddr::new(virt.as_u64() - PHYSICAL_MEMORY_OFFSET)
}

/// メモリサブシステムが初期化済みかどうか
pub fn is_initialized() -> bool {
    MEMORY_INITIALIZED.load(core::sync::atomic::Ordering::SeqCst)
}

/// ヒープ統計を取得
pub fn heap_stats() -> (usize, usize) {
    let allocator = ALLOCATOR.lock();
    (allocator.used(), allocator.free())
}
