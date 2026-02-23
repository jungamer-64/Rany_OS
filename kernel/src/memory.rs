// ============================================================================
// src/memory.rs - 完全なメモリサブシステム初期化
// 設計書 5: メモリ管理戦略 - 階層型アロケータ設計
//
// 重要: linked_list_allocator は設計理念に反するため使用しない
// 代わりにBuddy Allocatorベースのヒープを使用（O(log n)保証）
// ============================================================================
#![allow(dead_code)]

// OOM Killer サブモジュール (設計書 9.3.4)
pub mod oom_killer;

use crate::sync::PoisonLock;
use boot_proto::{ExoBootInfo, MemoryDescriptor, MemoryMap, NumaInfo};
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{PhysAddr, VirtAddr};

/// 設計書 1.3: Higher Half Kernel Base (SAS)
/// ブートローダーから取得した物理メモリオフセット（ランタイム設定）
#[cfg(any(not(test), feature = "full_mm_tests"))]
mod ap_boot_reserve;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub use ap_boot_reserve::*;

/// Test-mode volatile write stub (the real implementation is in ap_boot_reserve.rs).
#[cfg(all(test, not(feature = "full_mm_tests")))]
fn checked_volatile_write_usize(addr: usize, val: usize, _context: &str) {
    unsafe { core::ptr::write_volatile(addr as *mut usize, val); }
}

/// Test-mode phys_to_virt stub.
#[cfg(all(test, not(feature = "full_mm_tests")))]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64())
}

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
#[derive(Debug)]
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
    /// 最大オーダー（64バイト * 2^20 = 64MB最大ブロック）
    const MAX_ORDER: usize = 20;

    const fn new() -> Self {
        Self {
            heap_start: 0,
            heap_size: 0,
            initialized: false,
            free_lists: [None; Self::MAX_ORDER + 1],
            block_states: [0u64; 1024],
        }
    }

    /// 現在のアドレスに対するアラインメント対応ブロックオーダーを計算
    fn find_aligned_order(current: usize, end: usize) -> Option<(usize, usize)> {
        let remaining = end - current;
        if remaining < Self::MIN_BLOCK_SIZE {
            return None;
        }
        let mut order = Self::size_to_order(remaining).min(Self::MAX_ORDER);
        while order > 0 {
            let block_size = Self::order_to_size(order);
            if current % block_size == 0 && current + block_size <= end {
                break;
            }
            order -= 1;
        }
        Some((order, Self::order_to_size(order)))
    }

    /// ヒープを初期化
    unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        crate::io::log::early_print("[BUD] init\n");
        self.heap_start = heap_start;
        self.heap_size = heap_size;
        self.initialized = true;

        crate::io::log::early_print("[BUD] clear\n");
        // 全てのフリーリストをクリア
        for list in self.free_lists.iter_mut() {
            *list = None;
        }

        crate::io::log::early_print("[BUD] loop\n");
        // ヒープ全体を適切なオーダーのブロックとして登録
        // 各オーダーのブロックは自身のサイズでアラインされている必要がある
        let mut current = heap_start;
        let end = heap_start + heap_size;

        while current < end {
            let (order, block_size) = match Self::find_aligned_order(current, end) {
                Some(v) => v,
                None => break,
            };

            // Order 0のアラインメントチェック（MIN_BLOCK_SIZE=64バイト）
            if current % block_size != 0 {
                // アラインメントを満たすまで進める
                let aligned = (current + block_size - 1) & !(block_size - 1);
                if aligned >= end {
                    break;
                }
                current = aligned;
                continue;
            }

            if current + block_size <= end {
                crate::io::log::early_print("[BUD] add\n");
                self.add_to_free_list(current, order);
                current += block_size;
            } else {
                break;
            }
        }
        crate::io::log::early_print("[BUD] done\n");
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
        let old_head = self.free_lists[order].unwrap_or(0);

        // アドレスに次のフリーブロックへのポインタを格納
        let ptr_addr = addr as usize;

        // DEBUG: Validate addresses
        #[cfg(debug_assertions)]
        if addr < self.heap_start || addr >= self.heap_start + HEAP_SIZE {
            crate::io::log::early_print("[HEAP] ERROR: add_to_free_list got invalid addr!\n");
            crate::io::log::early_print("[HEAP] heap_start=");
            crate::io::log::early_print_hex(self.heap_start as u64);
            crate::io::log::early_print(" heap_end=");
            crate::io::log::early_print_hex((self.heap_start + HEAP_SIZE) as u64);
            crate::io::log::early_print("\n");
        }

        checked_volatile_write_usize(ptr_addr, old_head, "BUD add_to_free_list");
        self.free_lists[order] = Some(addr);
    }

    /// フリーリストからブロックを取得
    fn remove_from_free_list(&mut self, order: usize) -> Option<usize> {


        self.free_lists[order].take().map(|addr| {
            // DEBUG: Validate the address being returned
            #[cfg(debug_assertions)]
            if addr < self.heap_start || addr >= self.heap_start + HEAP_SIZE {
                crate::io::log::early_print(
                    "[HEAP] ERROR: remove_from_free_list returning invalid addr!\n",
                );
            }

            let ptr_addr = addr as usize;
            let next = crate::io::mmio::volatile_read::<usize>(ptr_addr);

            // DEBUG: Validate next pointer
            #[cfg(debug_assertions)]
            if next != 0 && (next < self.heap_start || next >= self.heap_start + HEAP_SIZE) {
                crate::io::log::early_print("[HEAP] ERROR: next pointer is invalid! Addr=");
                crate::io::log::early_print_hex(ptr_addr as u64);
                crate::io::log::early_print(" Next=");
                crate::io::log::early_print_hex(next as u64);
                crate::io::log::early_print(" Order=");
                crate::io::log::early_print_dec(order as u64);
                crate::io::log::early_print("\n");

                // Capture a lightweight stack backtrace at the point of detection
                crate::io::log::early_print("[HEAP] Capturing backtrace (invalid next detected)\n");
                let bt = crate::unwind::Backtrace::capture();
                for entry in bt.iter() {
                    crate::io::log::early_print("[HEAP][BT] IP=");
                    crate::io::log::early_print_hex(entry.frame.instruction_pointer as u64);
                    crate::io::log::early_print("\n");
                }

                // Dump current free list heads for all orders to find corrupted entry
                for i in 0..=Self::MAX_ORDER {
                    crate::io::log::early_print("[HEAP] free_lists[");
                    crate::io::log::early_print_dec(i as u64);
                    crate::io::log::early_print("] = ");
                    let head = self.free_lists[i].unwrap_or(0);
                    crate::io::log::early_print_hex(head as u64);
                    crate::io::log::early_print("\n");
                }
            }

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
                let next_ptr = curr_addr as usize;
                let next = crate::io::mmio::volatile_read::<usize>(next_ptr);
                let next_opt = if next == 0 { None } else { Some(next) };

                if let Some(prev_addr) = prev {
                    checked_volatile_write_usize(prev_addr, next, "BUD remove_specific prev->next");
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
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] allocate: not initialized\n");
            return null_mut();
        }

        // アラインメント要求を満たすために、
        // size と align の両方を満たす最小のブロックを使用
        let align = layout.align();
        let size = layout.size();

        // 必要なサイズ: sizeとalignの大きい方（最低 MIN_BLOCK_SIZE）
        // Buddyアロケータでは、ブロックは常に2のべき乗サイズで、
        // 自身のサイズでアラインされているため、
        // align <= block_size を満たせばアラインメントも満たす
        let alloc_size = size.max(align).max(Self::MIN_BLOCK_SIZE);
        let order = Self::size_to_order(alloc_size);

        if order > Self::MAX_ORDER {
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] allocate: order too large\n");
            return null_mut();
        }

        // 要求オーダー以上の空きブロックを探す
        for current_order in order..=Self::MAX_ORDER {
            if let Some(block) = self.remove_from_free_list(current_order) {
                // 必要に応じて分割
                self.split_block(block, current_order, order);


        

                // Buddyブロックは自身のサイズでアラインされているため、
                // block_size >= align なら自動的にアラインメントを満たす
                return block as *mut u8;
            }
        }

        #[cfg(debug_assertions)]
        crate::io::log::early_print("[HEAP] allocate: out of memory\n");
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
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] deallocate: null or not init\n");
            return;
        }

        let size = layout.size().max(layout.align()).max(Self::MIN_BLOCK_SIZE);
        let order = Self::size_to_order(size);
        let addr = ptr as usize;


        if addr < self.heap_start || addr >= self.heap_start + HEAP_SIZE {
            crate::io::log::early_print("[HEAP] ERROR: deallocate got invalid ptr!\n");
        }

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
pub struct LockedBuddyHeap(PoisonLock<BuddyHeapAllocator>);

impl LockedBuddyHeap {
    pub const fn new() -> Self {
        Self(PoisonLock::new(BuddyHeapAllocator::new()))
    }

    /// Check if the heap allocator is initialized
    pub fn is_initialized(&self) -> Option<bool> {
        self.0.lock().ok().map(|g| g.initialized)
    }
}

unsafe impl GlobalAlloc for LockedBuddyHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let _align = layout.align();
        
        // Log suspicious allocations
        if size == 0 {
             crate::io::log::early_print("[ALLOC] WARNING: alloc called with size 0\n");
        }

        match self.0.lock() {
            Ok(mut guard) => {
                let ptr = guard.allocate(layout);
                if ptr.is_null() {
                    Self::dump_alloc_failure(&*guard, layout, size);
                }
                ptr
            }
            Err(poisoned) => {
                crate::io::log::early_print("[ALLOC] Poisoned lock\n");
                Self::dump_poisoned_state(poisoned.get_ref());
                null_mut()
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Ok(mut guard) = self.0.lock() {
            guard.deallocate(ptr, layout);
        }
    }
}

impl LockedBuddyHeap {
    fn dump_alloc_failure(guard: &BuddyHeapAllocator, layout: Layout, size: usize) {
        crate::io::log::early_print("[ALLOC] FAILED size=");
        let mut s = size;
        let mut buf = [0u8; 20];
        let mut i = 19;
        if s == 0 {
            buf[i] = b'0';
            i -= 1;
        } else {
            while s > 0 {
                buf[i] = b'0' + (s % 10) as u8;
                s /= 10;
                i -= 1;
            }
        }
        for k in (i+1)..20 {
            crate::io::log::early_print_char(buf[k]);
        }

        crate::io::log::early_print(" align=");
        crate::io::log::early_print_dec(layout.align() as u64);
        crate::io::log::early_print("\n");

        crate::io::log::early_print("[ALLOC] guard.initialized=");
        crate::io::log::early_print_dec(if guard.initialized { 1 } else { 0 });
        crate::io::log::early_print("\n");

        crate::io::log::early_print("[ALLOC] Dumping free_lists:\n");
        for i in 0..=BuddyHeapAllocator::MAX_ORDER {
            crate::io::log::early_print("[ALLOC] free_lists[");
            crate::io::log::early_print_dec(i as u64);
            crate::io::log::early_print("] = ");
            let head = guard.free_lists[i].unwrap_or(0);
            crate::io::log::early_print_hex(head as u64);
            crate::io::log::early_print("\n");
        }

        crate::io::log::early_print("[ALLOC] Backtrace:\n");
        let bt = crate::unwind::Backtrace::capture();
        for entry in bt.iter() {
            crate::io::log::early_print("[ALLOC][BT] IP=");
            crate::io::log::early_print_hex(entry.frame.instruction_pointer as u64);
            crate::io::log::early_print("\n");
        }
    }

    fn dump_poisoned_state(guard_ref: &crate::sync::PoisonLockGuard<BuddyHeapAllocator>) {
        crate::io::log::early_print("[ALLOC] Dumping buddy free_lists (poisoned)\n");
        let alloc_ref: &BuddyHeapAllocator = &*guard_ref;
        for i in 0..=BuddyHeapAllocator::MAX_ORDER {
            crate::io::log::early_print("[ALLOC] free_lists[");
            crate::io::log::early_print_dec(i as u64);
            crate::io::log::early_print("] = ");
            let head = alloc_ref.free_lists[i].unwrap_or(0);
            crate::io::log::early_print_hex(head as u64);
            crate::io::log::early_print("\n");
        }
    }
}

/// グローバルヒープアロケータ（Buddy Allocatorベース）
/// 設計理念: O(log n)割り当てで <100ns を達成
#[cfg(not(feature = "full_mm_tests"))]
pub static ALLOCATOR: LockedBuddyHeap = LockedBuddyHeap::new();

#[cfg(feature = "full_mm_tests")]
pub use crate::ALLOCATOR;

/// ヒープのサイズ
pub const HEAP_SIZE: usize = 128 * 1024 * 1024; // 128 MiB

/// Exchange Heap のサイズ
pub const EXCHANGE_HEAP_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
const EFI_PAGE_SIZE: u64 = 4096;
const EFI_MEMORY_TYPE_BOOT_SERVICES_CODE: u32 = 3;
const EFI_MEMORY_TYPE_BOOT_SERVICES_DATA: u32 = 4;
const EFI_MEMORY_TYPE_ACPI_RECLAIM: u32 = 9;
const EFI_MEMORY_TYPE_CONVENTIONAL: u32 = 7;
const MIN_USABLE_PHYS_ADDR: u64 = 0x100_0000; // 16 MiB

/// ヒープの開始アドレスを計算（ランタイム）
/// 物理メモリ16MBをPhysical Memory Offsetでマップした仮想アドレス
#[inline]
fn heap_start() -> u64 {
    physical_memory_offset() + 0x100_0000
}

/// Exchange Heap の開始アドレスを計算（ランタイム）
///
/// NOTE: place the Exchange Heap after the global heap to avoid overlap
/// with the main kernel heap (see bugfix for overlapping regions).
#[inline]
fn exchange_heap_start() -> u64 {
    // heap_start() + HEAP_SIZE (no overlap)
    heap_start().saturating_add(HEAP_SIZE as u64)
}

/// メモリサブシステム初期化フラグ
static MEMORY_INITIALIZED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

fn is_usable_efi_memory_type(ty: u32) -> bool {
    ty == EFI_MEMORY_TYPE_CONVENTIONAL
        || ty == EFI_MEMORY_TYPE_BOOT_SERVICES_CODE
        || ty == EFI_MEMORY_TYPE_BOOT_SERVICES_DATA
}

/// Validate a memory descriptor and return (clamped_start, end) if usable.
fn validate_usable_descriptor(desc: &MemoryDescriptor, min_addr: u64) -> Option<(u64, u64)> {
    if desc.page_count == 0 {
        return None;
    }
    let size = desc.page_count.checked_mul(EFI_PAGE_SIZE)?;
    let start = desc.phys_start;
    let end = start.checked_add(size)?;
    let start = start.max(min_addr);
    if end <= start {
        return None;
    }
    Some((start, end))
}

fn get_boot_memory_regions(memory_map: &MemoryMap) -> Vec<(PhysAddr, u64)> {
    let mut regions = Vec::new();
    if memory_map.entries.is_null() || memory_map.count == 0 {
        return regions;
    }

    let count = memory_map.count.min(usize::MAX as u64) as usize;
    let descriptors = unsafe { core::slice::from_raw_parts(memory_map.entries, count) };

    for desc in descriptors {
        if !is_usable_efi_memory_type(desc.r#type) {
            continue;
        }
        if let Some((start, end)) = validate_usable_descriptor(desc, MIN_USABLE_PHYS_ADDR) {
            regions.push((PhysAddr::new(start), end - start));
        }
    }

    regions
}

fn subtract_from_region(
    start: u64,
    end: u64,
    reserved_start: u64,
    reserved_end: u64,
    filtered: &mut Vec<(PhysAddr, u64)>,
) {
    if reserved_end <= start || reserved_start >= end {
        filtered.push((PhysAddr::new(start), end - start));
        return;
    }
    if start < reserved_start {
        filtered.push((PhysAddr::new(start), reserved_start - start));
    }
    if end > reserved_end {
        filtered.push((PhysAddr::new(reserved_end), end - reserved_end));
    }
}

fn subtract_reserved_range(
    regions: Vec<(PhysAddr, u64)>,
    reserved_start: u64,
    reserved_size: u64,
) -> Vec<(PhysAddr, u64)> {
    if reserved_size == 0 {
        return regions;
    }
    let reserved_end = reserved_start.saturating_add(reserved_size);
    let mut filtered = Vec::with_capacity(regions.len());

    for (addr, size) in regions {
        let start = addr.as_u64();
        let end = start.saturating_add(size);
        subtract_from_region(start, end, reserved_start, reserved_end, &mut filtered);
    }

    filtered
}

fn reserve_bootstrap_heaps(regions: Vec<(PhysAddr, u64)>) -> Vec<(PhysAddr, u64)> {
    let hhdm = physical_memory_offset();
    let heap_phys = heap_start().saturating_sub(hhdm);
    let exchange_phys = exchange_heap_start().saturating_sub(hhdm);

    // Reserve and remove bootstrap heap regions (global heap and exchange heap)
    let regions = subtract_reserved_range(regions, heap_phys, HEAP_SIZE as u64);
    let regions = subtract_reserved_range(regions, exchange_phys, EXCHANGE_HEAP_SIZE as u64);

    regions
}

fn hhdm_ptr_to_phys(ptr: u64) -> Option<u64> {
    if ptr == 0 {
        return None;
    }
    let hhdm = physical_memory_offset();
    if ptr < hhdm {
        return None;
    }
    Some(ptr - hhdm)
}

fn addr_to_phys(addr: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    let hhdm = physical_memory_offset();
    if addr >= hhdm {
        Some(addr - hhdm)
    } else {
        Some(addr)
    }
}

/// Subtract a reserved range if address is valid and size is non-zero.
fn subtract_if_valid(
    regions: Vec<(PhysAddr, u64)>,
    phys: Option<u64>,
    size: u64,
) -> Vec<(PhysAddr, u64)> {
    match phys {
        Some(p) if size > 0 => subtract_reserved_range(regions, p, size),
        _ => regions,
    }
}
