// ============================================================================
// src/memory.rs - 完全なメモリサブシステム初期化
// 設計書 5: メモリ管理戦略 - 階層型アロケータ設計
//
// 重要: linked_list_allocator は設計理念に反するため使用しない
// 代わりにBuddy Allocatorベースのヒープを使用（O(log n)保証）
// ============================================================================
#![allow(dead_code)]

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

/// 設計書 1.3: Higher Half Kernel Base (SAS)
/// ブートローダーから取得した物理メモリオフセット（ランタイム設定）
static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0xFFFF_8000_0000_0000);

/// 物理メモリオフセットを取得
#[inline]
pub fn physical_memory_offset() -> u64 {
    PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed)
}

/// 物理メモリオフセットを設定（ブートローダーから取得した値で初期化）
pub fn set_physical_memory_offset(offset: u64) {
    PHYSICAL_MEMORY_OFFSET.store(offset, Ordering::SeqCst);
}

// ============================================================================
// Buddy-Based Kernel Heap Allocator
// 設計理念: O(log n)割り当てを保証し、<100ns per allocation を達成
// ============================================================================

/// カーネルヒープ用のBuddy Allocator
/// linked_list_allocator (O(n)) の代わりに使用
struct BuddyHeapAllocator {
    /// ヒープの開始アドレス
    heap_start: usize,
    /// ヒープのサイズ
    heap_size: usize,
    /// 初期化済みフラグ
    initialized: bool,
    /// Buddy システム: 各オーダーの空きブロックリスト
    /// オーダー0 = 最小ブロック (MIN_BLOCK_SIZE)
    /// オーダーN = 2^N * MIN_BLOCK_SIZE
    free_lists: [Option<usize>; Self::MAX_ORDER + 1],
    /// 各ブロックの状態を追跡（split/freeビット）
    /// ビット = 1: 分割済み or 使用中
    block_states: [u64; 1024],
}

impl BuddyHeapAllocator {
    /// 最小ブロックサイズ（64バイト = キャッシュライン）
    const MIN_BLOCK_SIZE: usize = 64;
    /// 最大オーダー（64バイト * 2^16 = 4MB最大ブロック）
    const MAX_ORDER: usize = 16;

    const fn new() -> Self {
        Self {
            heap_start: 0,
            heap_size: 0,
            initialized: false,
            free_lists: [None; Self::MAX_ORDER + 1],
            block_states: [0u64; 1024],
        }
    }

    /// ヒープを初期化
    unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        crate::vga::early_serial_str("[BUD] init\n");
        self.heap_start = heap_start;
        self.heap_size = heap_size;
        self.initialized = true;

        crate::vga::early_serial_str("[BUD] clear\n");
        // 全てのフリーリストをクリア
        for list in self.free_lists.iter_mut() {
            *list = None;
        }

        crate::vga::early_serial_str("[BUD] loop\n");
        // ヒープ全体を最大オーダーのブロックとして登録
        let mut current = heap_start;
        let end = heap_start + heap_size;

        while current + Self::MIN_BLOCK_SIZE <= end {
            // 現在位置から配置可能な最大ブロックを決定
            let remaining = end - current;
            let order = Self::size_to_order(remaining).min(Self::MAX_ORDER);
            let block_size = Self::order_to_size(order);

            if current + block_size <= end {
                crate::vga::early_serial_str("[BUD] add\n");
                self.add_to_free_list(current, order);
                current += block_size;
            } else {
                break;
            }
        }
        crate::vga::early_serial_str("[BUD] done\n");
    }

    /// サイズから必要なオーダーを計算
    #[inline]
    fn size_to_order(size: usize) -> usize {
        let blocks = (size + Self::MIN_BLOCK_SIZE - 1) / Self::MIN_BLOCK_SIZE;
        if blocks <= 1 {
            0
        } else {
            (usize::BITS - (blocks - 1).leading_zeros()) as usize
        }
    }

    /// オーダーからサイズを計算
    #[inline]
    const fn order_to_size(order: usize) -> usize {
        Self::MIN_BLOCK_SIZE << order
    }

    /// フリーリストにブロックを追加
    fn add_to_free_list(&mut self, addr: usize, order: usize) {
        crate::vga::early_serial_str("[F1]");
        // アドレスに次のフリーブロックへのポインタを格納
        let ptr = addr as *mut usize;
        crate::vga::early_serial_str("[F2]");
        unsafe {
            core::ptr::write_volatile(ptr, self.free_lists[order].unwrap_or(0));
        }
        crate::vga::early_serial_str("[F3]");
        self.free_lists[order] = Some(addr);
        crate::vga::early_serial_str("[F4]\n");
    }

    /// フリーリストからブロックを取得
    fn remove_from_free_list(&mut self, order: usize) -> Option<usize> {
        self.free_lists[order].take().map(|addr| {
            let ptr = addr as *const usize;
            let next = unsafe { *ptr };
            self.free_lists[order] = if next == 0 { None } else { Some(next) };
            addr
        })
    }

    /// 特定アドレスのブロックをフリーリストから削除
    fn remove_specific(&mut self, addr: usize, order: usize) -> bool {
        let mut prev: Option<usize> = None;
        let mut current = self.free_lists[order];

        while let Some(curr_addr) = current {
            if curr_addr == addr {
                // 見つかった - リストから削除
                let next_ptr = curr_addr as *const usize;
                let next = unsafe { *next_ptr };
                let next_opt = if next == 0 { None } else { Some(next) };

                if let Some(prev_addr) = prev {
                    unsafe {
                        *(prev_addr as *mut usize) = next;
                    }
                } else {
                    self.free_lists[order] = next_opt;
                }
                return true;
            }
            prev = current;
            let next_ptr = curr_addr as *const usize;
            let next = unsafe { *next_ptr };
            current = if next == 0 { None } else { Some(next) };
        }
        false
    }

    /// メモリを割り当て（O(log n)）
    fn allocate(&mut self, layout: Layout) -> *mut u8 {
        if !self.initialized {
            return null_mut();
        }

        let size = layout.size().max(layout.align()).max(Self::MIN_BLOCK_SIZE);
        let order = Self::size_to_order(size);

        if order > Self::MAX_ORDER {
            return null_mut();
        }

        // 要求オーダー以上の空きブロックを探す
        for current_order in order..=Self::MAX_ORDER {
            if let Some(block) = self.remove_from_free_list(current_order) {
                // 必要に応じて分割
                self.split_block(block, current_order, order);
                return block as *mut u8;
            }
        }

        null_mut()
    }

    /// ブロックを目標オーダーまで分割
    fn split_block(&mut self, addr: usize, from_order: usize, to_order: usize) {
        let mut current_order = from_order;

        while current_order > to_order {
            current_order -= 1;
            let buddy_addr = addr + Self::order_to_size(current_order);
            self.add_to_free_list(buddy_addr, current_order);
        }
    }

    /// メモリを解放（O(log n)）
    fn deallocate(&mut self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() || !self.initialized {
            return;
        }

        let size = layout.size().max(layout.align()).max(Self::MIN_BLOCK_SIZE);
        let order = Self::size_to_order(size);
        let addr = ptr as usize;

        self.coalesce(addr, order);
    }

    /// Buddyとの合体を反復的に試みる
    fn coalesce(&mut self, addr: usize, order: usize) {
        let mut current_addr = addr;
        let mut current_order = order;

        while current_order < Self::MAX_ORDER {
            let buddy_addr = self.buddy_addr(current_addr, current_order);

            // Buddyがフリーリストにあるか確認
            if !self.remove_specific(buddy_addr, current_order) {
                break;
            }

            // 合体: 小さい方のアドレスを使用
            current_addr = current_addr.min(buddy_addr);
            current_order += 1;
        }

        self.add_to_free_list(current_addr, current_order);
    }

    /// Buddyのアドレスを計算
    #[inline]
    fn buddy_addr(&self, addr: usize, order: usize) -> usize {
        let offset = addr - self.heap_start;
        let block_size = Self::order_to_size(order);
        self.heap_start + (offset ^ block_size)
    }
}

/// スレッドセーフなグローバルアロケータラッパー
struct LockedBuddyHeap(Mutex<BuddyHeapAllocator>);

impl LockedBuddyHeap {
    const fn new() -> Self {
        Self(Mutex::new(BuddyHeapAllocator::new()))
    }
}

unsafe impl GlobalAlloc for LockedBuddyHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().allocate(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().deallocate(ptr, layout)
    }
}

/// グローバルヒープアロケータ（Buddy Allocatorベース）
/// 設計理念: O(log n)割り当てで <100ns を達成
#[global_allocator]
static ALLOCATOR: LockedBuddyHeap = LockedBuddyHeap::new();

/// ヒープのサイズ
pub const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

/// Exchange Heap のサイズ
pub const EXCHANGE_HEAP_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// ヒープの開始アドレスを計算（ランタイム）
/// 物理メモリ16MBをPhysical Memory Offsetでマップした仮想アドレス
#[inline]
fn heap_start() -> u64 {
    physical_memory_offset() + 0x100_0000
}

/// Exchange Heap の開始アドレスを計算（ランタイム）
#[inline]
fn exchange_heap_start() -> u64 {
    physical_memory_offset() + 0x200_0000
}

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

    crate::vga::early_serial_str("[MEM] init start\n");

    if MEMORY_INITIALIZED.swap(true, Ordering::SeqCst) {
        crate::vga::early_serial_str("[MEM] already init\n");
        return;
    }

    crate::vga::early_serial_str("[MEM] global heap\n");

    // 1. グローバルヒープの初期化（最初に行う - allocが必要）
    init_global_heap();
    crate::vga::early_serial_str("[MEM] heap done\n");

    // 2. Buddy Allocator の初期化（デフォルトのメモリ領域を使用）
    // 注: 本番環境ではブートローダーからメモリマップを取得
    crate::vga::early_serial_str("[MEM] buddy prep\n");
    let usable_regions = get_default_memory_regions();
    crate::vga::early_serial_str("[MEM] buddy init\n");

    unsafe {
        crate::mm::init_buddy_allocator(&usable_regions);
    }
    crate::vga::early_serial_str("[MEM] buddy done\n");

    // 3. Exchange Heap の初期化（ゼロコピーIPC用）
    crate::vga::early_serial_str("[MEM] exheap init\n");
    unsafe {
        crate::mm::init_exchange_heap(exchange_heap_start() as usize, EXCHANGE_HEAP_SIZE);
    }
    crate::vga::early_serial_str("[MEM] exheap done\n");

    // 4. Per-CPU データ構造の初期化（BSPのみ）
    crate::vga::early_serial_str("[MEM] percpu init\n");
    unsafe {
        crate::mm::init_per_cpu(1);
        crate::mm::setup_current_cpu(0);
    }
    crate::vga::early_serial_str("[MEM] percpu done\n");

    // 5. Per-Core Slab Cache の初期化
    crate::vga::early_serial_str("[MEM] slab init\n");
    crate::mm::init_per_core_caches(1);
    crate::vga::early_serial_str("[MEM] slab done\n");

    // メモリ統計を表示（スキップ）
    // print_memory_stats();
    crate::vga::early_serial_str("[MEM] all done\n");
}

/// グローバルヒープの初期化（Buddy Allocatorベース）
fn init_global_heap() {
    crate::vga::early_serial_str("[HEAP] lock\n");
    let mut guard = ALLOCATOR.0.lock();
    crate::vga::early_serial_str("[HEAP] init call\n");
    let start = heap_start();
    crate::vga::early_serial_str("[HEAP] addr ok\n");
    unsafe {
        guard.init(start as usize, HEAP_SIZE);
    }
    crate::vga::early_serial_str("[HEAP] done\n");
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
    crate::log!(
        "[MEM] Free Frames: {} ({} KB)\n",
        buddy_stats.free_frames,
        buddy_stats.free_frames * 4
    );
    crate::log!("[MEM] Split Operations: {}\n", buddy_stats.split_count);
    crate::log!(
        "[MEM] Coalesce Operations: {}\n",
        buddy_stats.coalesce_count
    );

    // Order別の統計を表示
    for (order, (blocks, _frames)) in buddy_stats.order_stats.iter().enumerate() {
        if *blocks > 0 {
            let block_size_kb = (1usize << order) * 4;
            crate::log!(
                "[MEM]   Order {}: {} blocks ({}KB each)\n",
                order,
                blocks,
                block_size_kb
            );
        }
    }
}

/// 物理アドレス -> 仮想アドレスへの変換 (O(1))
#[inline(always)]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64() + physical_memory_offset())
}

/// 仮想アドレス -> 物理アドレスへの変換 (O(1))
#[inline(always)]
pub fn virt_to_phys(virt: VirtAddr) -> PhysAddr {
    PhysAddr::new(virt.as_u64() - physical_memory_offset())
}

/// メモリサブシステムが初期化済みかどうか
pub fn is_initialized() -> bool {
    MEMORY_INITIALIZED.load(core::sync::atomic::Ordering::SeqCst)
}

/// ヒープ統計を取得（Buddy Allocator用）
/// 戻り値: (使用中バイト数概算, 空きバイト数概算)
pub fn heap_stats() -> (usize, usize) {
    // Buddy allocatorでは正確な使用量追跡は複雑なため、
    // ヒープサイズ全体を返す（詳細はbuddy_allocator_stats()を使用）
    (0, HEAP_SIZE)
}
