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
use boot_proto::{ExoBootInfo, MemoryMap, NumaInfo};
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};
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
            // 現在アドレスから、アラインメント条件を満たす最大のオーダーを見つける
            let remaining = end - current;
            if remaining < Self::MIN_BLOCK_SIZE {
                break;
            }

            // このアドレスで使用可能な最大オーダーを計算
            // アドレスは block_size でアラインされている必要がある
            let mut order = Self::size_to_order(remaining).min(Self::MAX_ORDER);

            // アラインメント条件を満たすまでオーダーを下げる
            while order > 0 {
                let block_size = Self::order_to_size(order);
                if current % block_size == 0 && current + block_size <= end {
                    break;
                }
                order -= 1;
            }

            // Order 0のアラインメントチェック（MIN_BLOCK_SIZE=64バイト）
            let block_size = Self::order_to_size(order);
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
        // DEBUG: Log the operation
        #[cfg(debug_assertions)]
        crate::io::log::early_print("[HEAP] add_to_free_list\n");

        // アドレスに次のフリーブロックへのポインタを格納
        let ptr_addr = addr as usize;
        let old_head = self.free_lists[order].unwrap_or(0);

        // DEBUG: Validate addresses
        #[cfg(debug_assertions)]
        if addr < self.heap_start || addr >= self.heap_start + HEAP_SIZE {
            crate::io::log::early_print("[HEAP] ERROR: add_to_free_list got invalid addr!\n");
        }

        crate::io::mmio::volatile_write::<usize>(ptr_addr, old_head);
        self.free_lists[order] = Some(addr);
    }

    /// フリーリストからブロックを取得
    fn remove_from_free_list(&mut self, order: usize) -> Option<usize> {
        #[cfg(debug_assertions)]
        crate::io::log::early_print("[HEAP] remove_from_free_list\n");

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
                crate::io::log::early_print("[HEAP] ERROR: next pointer is invalid!\n");
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
                    crate::io::mmio::volatile_write::<usize>(prev_addr, next);
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
        #[cfg(debug_assertions)]
        crate::io::log::early_print("[HEAP] allocate enter\n");

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

                #[cfg(debug_assertions)]
                crate::io::log::early_print("[HEAP] allocate success\n");

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
        #[cfg(debug_assertions)]
        crate::io::log::early_print("[HEAP] deallocate enter\n");

        if ptr.is_null() || !self.initialized {
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] deallocate: null or not init\n");
            return;
        }

        let size = layout.size().max(layout.align()).max(Self::MIN_BLOCK_SIZE);
        let order = Self::size_to_order(size);
        let addr = ptr as usize;

        #[cfg(debug_assertions)]
        if addr < self.heap_start || addr >= self.heap_start + HEAP_SIZE {
            crate::io::log::early_print("[HEAP] ERROR: deallocate got invalid ptr!\n");
        }

        self.coalesce(addr, order);

        #[cfg(debug_assertions)]
        crate::io::log::early_print("[HEAP] deallocate done\n");
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
struct LockedBuddyHeap(PoisonLock<BuddyHeapAllocator>);

impl LockedBuddyHeap {
    const fn new() -> Self {
        Self(PoisonLock::new(BuddyHeapAllocator::new()))
    }
}

unsafe impl GlobalAlloc for LockedBuddyHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match self.0.lock() {
            Ok(mut guard) => guard.allocate(layout),
            Err(_) => {
                // Poisoned: Heap is corrupt. Return null (OOM).
                // Cannot log here due to recursion risk.
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

/// グローバルヒープアロケータ（Buddy Allocatorベース）
/// 設計理念: O(log n)割り当てで <100ns を達成
#[global_allocator]
static ALLOCATOR: LockedBuddyHeap = LockedBuddyHeap::new();

/// ヒープのサイズ
pub const HEAP_SIZE: usize = 32 * 1024 * 1024; // 32 MiB

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
#[inline]
fn exchange_heap_start() -> u64 {
    physical_memory_offset() + 0x200_0000
}

/// メモリサブシステム初期化フラグ
static MEMORY_INITIALIZED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

fn is_usable_efi_memory_type(ty: u32) -> bool {
    ty == EFI_MEMORY_TYPE_CONVENTIONAL
        || ty == EFI_MEMORY_TYPE_BOOT_SERVICES_CODE
        || ty == EFI_MEMORY_TYPE_BOOT_SERVICES_DATA
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
        if desc.page_count == 0 {
            continue;
        }
        let size = match desc.page_count.checked_mul(EFI_PAGE_SIZE) {
            Some(size) => size,
            None => continue,
        };
        let start = desc.phys_start;
        let end = match start.checked_add(size) {
            Some(end) => end,
            None => continue,
        };
        let start = start.max(MIN_USABLE_PHYS_ADDR);
        if end <= start {
            continue;
        }
        regions.push((PhysAddr::new(start), end - start));
    }

    regions
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
        if reserved_end <= start || reserved_start >= end {
            filtered.push((addr, size));
            continue;
        }
        if start < reserved_start {
            let left_size = reserved_start - start;
            if left_size > 0 {
                filtered.push((PhysAddr::new(start), left_size));
            }
        }
        if end > reserved_end {
            let right_size = end - reserved_end;
            if right_size > 0 {
                filtered.push((PhysAddr::new(reserved_end), right_size));
            }
        }
    }

    filtered
}

fn reserve_bootstrap_heaps(regions: Vec<(PhysAddr, u64)>) -> Vec<(PhysAddr, u64)> {
    let hhdm = physical_memory_offset();
    let heap_phys = heap_start().saturating_sub(hhdm);
    let exchange_phys = exchange_heap_start().saturating_sub(hhdm);

    let regions = subtract_reserved_range(regions, heap_phys, HEAP_SIZE as u64);
    subtract_reserved_range(regions, exchange_phys, EXCHANGE_HEAP_SIZE as u64)
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

fn reserve_boot_info_ranges(
    mut regions: Vec<(PhysAddr, u64)>,
    boot_info: &ExoBootInfo,
) -> Vec<(PhysAddr, u64)> {
    let boot_info_ptr = boot_info as *const _ as u64;
    if let Some(phys) = hhdm_ptr_to_phys(boot_info_ptr) {
        regions = subtract_reserved_range(
            regions,
            phys,
            core::mem::size_of::<ExoBootInfo>() as u64,
        );
    }

    let mmap_ptr = boot_info.memory_map.entries as u64;
    if let Some(phys) = hhdm_ptr_to_phys(mmap_ptr) {
        let entry_size = core::mem::size_of::<boot_proto::MemoryDescriptor>() as u64;
        if let Some(bytes) = boot_info.memory_map.count.checked_mul(entry_size) {
            regions = subtract_reserved_range(regions, phys, bytes);
        }
    }

    if let Some(phys) = hhdm_ptr_to_phys(boot_info.cmdline_ptr) {
        let size = boot_info.cmdline_len.saturating_add(1);
        if size > 0 {
            regions = subtract_reserved_range(regions, phys, size);
        }
    }

    if let Some(phys) = hhdm_ptr_to_phys(boot_info.initramfs.ptr) {
        let size = boot_info.initramfs.size;
        if size > 0 {
            regions = subtract_reserved_range(regions, phys, size);
        }
    }

    if let Some(phys) = addr_to_phys(boot_info.framebuffer.address) {
        let size = boot_info.framebuffer.size() as u64;
        if size > 0 {
            regions = subtract_reserved_range(regions, phys, size);
        }
    }

    let ap_boot = &boot_info.ap_boot;
    if ap_boot.trampoline_size > 0 {
        regions = subtract_reserved_range(
            regions,
            ap_boot.trampoline_addr,
            ap_boot.trampoline_size,
        );
    }
    if ap_boot.stack_size > 0 && ap_boot.stack_count > 0 {
        let size = (ap_boot.stack_size as u64)
            .checked_mul(ap_boot.stack_count as u64)
            .unwrap_or(0);
        if size > 0 {
            regions = subtract_reserved_range(regions, ap_boot.stack_base, size);
        }
    }

    let runtime = &boot_info.uefi_runtime;
    let runtime_count = (runtime.runtime_mmap_count as usize)
        .min(runtime.runtime_mmap.len());
    for i in 0..runtime_count {
        let region = &runtime.runtime_mmap[i];
        if region.phys_addr == 0 || region.page_count == 0 {
            continue;
        }
        if let Some(size) = region.page_count.checked_mul(EFI_PAGE_SIZE) {
            if size > 0 {
                regions = subtract_reserved_range(regions, region.phys_addr, size);
            }
        }
    }

    regions
}

/// メモリサブシステムの完全初期化
///
/// 初期化順序:
/// 1. グローバルヒープ（allocが使えるようになる）
/// 2. Buddy Allocator（物理フレーム管理）
/// 3. Exchange Heap（ゼロコピーIPC用）
/// 4. Per-CPU データ構造
/// 5. Per-Core Slab Cache
pub fn init(rsdp_addr: Option<u64>, numa_info: Option<&NumaInfo>, boot_info: Option<&ExoBootInfo>) {
    use core::sync::atomic::Ordering;

    crate::io::log::early_print("[MEM] init start\n");

    if MEMORY_INITIALIZED.swap(true, Ordering::SeqCst) {
        crate::io::log::early_print("[MEM] already init\n");
        return;
    }

    crate::io::log::early_print("[MEM] global heap\n");

    // 0. Higher Half Manager の初期化 (IOMMUなどが依存)
    crate::mm::init(physical_memory_offset());
    crate::io::log::early_print("[MEM] higher half init\n");

    // 1. グローバルヒープの初期化（最初に行う - allocが必要）
    init_global_heap();
    crate::io::log::early_print("[MEM] heap done\n");

    // 2. Buddy Allocator の初期化（ブートローダーのメモリマップを使用）
    crate::io::log::early_print("[MEM] buddy prep\n");
    let memory_map = boot_info.map(|info| &info.memory_map);
    let mut usable_regions = if let Some(map) = memory_map {
        crate::io::log::early_print("[MEM] boot memory map\n");
        let regions = get_boot_memory_regions(map);
        if regions.is_empty() {
            crate::io::log::early_print("[MEM] boot map empty\n");
            get_default_memory_regions()
        } else {
            regions
        }
    } else {
        get_default_memory_regions()
    };
    usable_regions = reserve_bootstrap_heaps(usable_regions);
    if let Some(info) = boot_info {
        usable_regions = reserve_boot_info_ranges(usable_regions, info);
    }
    crate::io::log::early_print("[MEM] buddy init\n");

    unsafe {
        crate::mm::init_buddy_allocator(&usable_regions);
    }
    crate::io::log::early_print("[MEM] buddy done\n");

    // 2.5. NUMA情報（ブートローダー/ACPI）からPMMを初期化
    let mut pmm_initialized = false;
    if let Some(info) = numa_info {
        if info.node_count > 0 {
            crate::io::log::early_print("[MEM] NUMA info from bootloader\n");
            unsafe {
                if crate::mm::init_numa_frame_allocator_from_info(info) {
                    pmm_initialized = true;
                }
            }
        }
    }

    if !pmm_initialized {
        crate::io::log::early_print("[MEM] SRAT check\n");
        if let Some(_rsdp_addr_val) = rsdp_addr {
            crate::io::log::early_print("[MEM] parsing SRAT\n");
            // Acquire SRAT entries from ACPI parser if available
            let regions = crate::io::acpi::numa_memory_regions();
            let mut numa_regions = alloc::vec::Vec::new();
            for (base, length, proximity) in regions {
                // Log using a heap-backed format (heap already initialized at this point)
                let s = alloc::format!(
                    "[MEM] registering region {:#x} len {:#x} prox {}\n",
                    base,
                    length,
                    proximity
                );
                crate::io::log::early_print(&s);

                // Convert to PhysAddr and NumaNodeId
                let base_phys = x86_64::PhysAddr::new(base);
                let node = crate::mm::NumaNodeId::new(proximity as u8);
                numa_regions.push((base_phys, length, node));
            }
            if !numa_regions.is_empty() {
                unsafe {
                    crate::mm::init_numa_frame_allocator(&numa_regions);
                    pmm_initialized = true;
                }
            } else {
                crate::io::log::early_print("[MEM] SRAT empty\n");
            }
        } else {
            crate::io::log::early_print("[MEM] no SRAT (RSDP not provided)\n");
        }
    }

    if !pmm_initialized {
        crate::io::log::early_print("[MEM] using global PMM\n");
        unsafe {
            crate::mm::init_frame_allocator(&usable_regions);
        }
    }

    // 3. Exchange Heap の初期化（ゼロコピーIPC用）
    crate::io::log::early_print("[MEM] exheap init\n");
    unsafe {
        crate::mm::init_exchange_heap(exchange_heap_start() as usize, EXCHANGE_HEAP_SIZE);
    }
    crate::io::log::early_print("[MEM] exheap done\n");

    // 4. Per-CPU データ構造の初期化（BSPのみ）
    // 注: init_per_cpu() 内部でBSPのGsBaseが設定されるため、
    //     setup_current_cpu(0) は省略可能（冪等性のため呼んでも問題なし）
    crate::io::log::early_print("[MEM] percpu init\n");
    unsafe {
        crate::mm::init_per_cpu(1);
        // BSPのGsBaseはinit_per_cpu内で設定済み
        // AP（追加プロセッサ）起動時は各APでsetup_current_cpu(cpu_id)を呼ぶ
    }
    crate::io::log::early_print("[MEM] percpu done\n");

    // 5. Per-Core Slab Cache の初期化
    crate::io::log::early_print("[MEM] slab init\n");
    crate::mm::init_per_core_caches(1);
    crate::io::log::early_print("[MEM] slab done\n");

    // メモリ統計を表示（スキップ）
    // print_memory_stats();
    crate::io::log::early_print("[MEM] all done\n");
}

/// ACPI Reclaimable メモリをPMMへ返却
pub fn reclaim_acpi_reclaimable(boot_info: &ExoBootInfo) {
    let mmap = &boot_info.memory_map;
    if mmap.entries.is_null() || mmap.count == 0 {
        return;
    }

    let count = mmap.count.min(usize::MAX as u64) as usize;
    let descriptors = unsafe { core::slice::from_raw_parts(mmap.entries, count) };

    let mut total_pages = 0u64;
    for desc in descriptors {
        if desc.r#type != EFI_MEMORY_TYPE_ACPI_RECLAIM {
            continue;
        }
        if desc.page_count == 0 {
            continue;
        }
        let size = match desc.page_count.checked_mul(EFI_PAGE_SIZE) {
            Some(size) => size,
            None => continue,
        };
        let start = desc.phys_start.max(MIN_USABLE_PHYS_ADDR);
        let end = match desc.phys_start.checked_add(size) {
            Some(end) => end,
            None => continue,
        };
        if end <= start {
            continue;
        }
        let released = crate::mm::pmm_release_range(PhysAddr::new(start), end - start);
        total_pages += released;
    }

    if total_pages > 0 {
        log::info!("[MEM] Reclaimed ACPI memory: {} pages", total_pages);
    }
}

/// グローバルヒープの初期化（Buddy Allocatorベース）
fn init_global_heap() {
    crate::io::log::early_print("[HEAP] lock\n");
    let mut guard = ALLOCATOR.0.lock_for_init("[HEAP] global allocator init");
    crate::io::log::early_print("[HEAP] init call\n");
    let start = heap_start();
    crate::io::log::early_print("[HEAP] addr ok\n");
    unsafe {
        guard.init(start as usize, HEAP_SIZE);
    }
    crate::io::log::early_print("[HEAP] done\n");
}

/// デフォルトのメモリ領域を取得
/// 本番環境ではブートローダーから取得するが、開発用にハードコード
fn get_default_memory_regions() -> Vec<(PhysAddr, u64)> {
    // 16MiB - 496MiB の範囲を使用可能として設定 (QEMU 512MBに収まる)
    // 最初の16MiBはBIOSやカーネルのために予約
    alloc::vec![
        (PhysAddr::new(0x100_0000), 480 * 1024 * 1024), // 16MiB - 496MiB
    ]
}

/// メモリ統計を表示
fn print_memory_stats() {
    let buddy_stats = crate::mm::buddy_allocator_stats();

    log::info!("[MEM] === Memory Statistics ===\n");
    log::info!("[MEM] Total Frames: {}\n", buddy_stats.total_frames);
    log::info!(
        "[MEM] Free Frames: {} ({} KB)\n",
        buddy_stats.free_frames,
        buddy_stats.free_frames * 4
    );
    log::info!("[MEM] Split Operations: {}\n", buddy_stats.split_count);
    log::info!(
        "[MEM] Coalesce Operations: {}\n",
        buddy_stats.coalesce_count
    );

    // Order別の統計を表示
    for (order, (blocks, _frames)) in buddy_stats.order_stats.iter().enumerate() {
        if *blocks > 0 {
            let block_size_kb = (1usize << order) * 4;
            log::info!(
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

/// システム総メモリをKB単位で取得
pub fn total_memory_kb() -> u64 {
    let stats = crate::mm::buddy_allocator_stats();
    (stats.total_frames as u64) * 4 // 1フレーム = 4KB
}

/// 空きメモリをKB単位で取得
pub fn free_memory_kb() -> u64 {
    let stats = crate::mm::buddy_allocator_stats();
    (stats.free_frames as u64) * 4 // 1フレーム = 4KB
}

/// 使用中メモリをKB単位で取得
pub fn used_memory_kb() -> u64 {
    total_memory_kb().saturating_sub(free_memory_kb())
}
