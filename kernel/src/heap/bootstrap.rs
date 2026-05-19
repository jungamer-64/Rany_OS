use super::*;
use boot_proto::{ExoBootInfo, ExoBootInfoView, NumaInfo, UsableMemoryRegion};
use core::sync::atomic::{AtomicU64, Ordering};

static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0xFFFF_8000_0000_0000);

#[inline]
pub(crate) fn physical_memory_offset() -> u64 {
    PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed)
}

pub(crate) fn set_physical_memory_offset(offset: u64) {
    PHYSICAL_MEMORY_OFFSET.store(offset, Ordering::SeqCst);
}

/// Reserve AP boot trampoline and stack ranges.
pub(crate) fn reserve_ap_boot_ranges(
    mut regions: Vec<(PhysAddr, u64)>,
    ap_boot: &boot_proto::ApBootInfo,
) -> Vec<(PhysAddr, u64)> {
    if let Some((trampoline_start, trampoline_size)) = ap_boot.trampoline_range() {
        regions = subtract_reserved_range(regions, trampoline_start, trampoline_size);
    }
    if let Some((stack_start, stack_size)) = ap_boot.stack_region_range() {
        regions = subtract_reserved_range(regions, stack_start, stack_size);
    }
    regions
}

/// Reserve UEFI runtime memory map ranges.
pub(crate) fn reserve_uefi_runtime_ranges(
    mut regions: Vec<(PhysAddr, u64)>,
    runtime: &boot_proto::UefiRuntimeInfo,
) -> Vec<(PhysAddr, u64)> {
    let runtime_count = (runtime.runtime_mmap_count as usize).min(runtime.runtime_mmap.len());
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

fn span_with_trailing_nul(span: boot_proto::BootHhdmSpan) -> Option<boot_proto::BootHhdmSpan> {
    boot_proto::BootHhdmSpan::new(span.start(), span.len().checked_add(1)?).ok()
}

fn subtract_hhdm_span(
    regions: Vec<(PhysAddr, u64)>,
    span: Option<boot_proto::BootHhdmSpan>,
    hhdm_start: u64,
) -> Vec<(PhysAddr, u64)> {
    let Some((start, size)) = span.and_then(|span| span.phys_range(hhdm_start)) else {
        return regions;
    };
    subtract_reserved_range(regions, start, size)
}

pub(crate) fn reserve_boot_info_ranges(
    mut regions: Vec<(PhysAddr, u64)>,
    boot_info: &ExoBootInfoView<'_>,
) -> Vec<(PhysAddr, u64)> {
    let raw = boot_info.boot_info();
    let boot_info_ptr = raw as *const _ as u64;
    regions = subtract_if_valid(
        regions,
        hhdm_ptr_to_phys(boot_info_ptr),
        core::mem::size_of::<ExoBootInfo>() as u64,
    );

    regions = subtract_hhdm_span(regions, raw.memory_map.span(), raw.phys_mem_offset);
    regions = subtract_hhdm_span(
        regions,
        raw.usable_memory.regions_span(),
        raw.phys_mem_offset,
    );
    regions = subtract_hhdm_span(
        regions,
        raw.cmdline_span().and_then(span_with_trailing_nul),
        raw.phys_mem_offset,
    );
    regions = subtract_hhdm_span(
        regions,
        raw.boot_artifacts.entries_span(),
        raw.phys_mem_offset,
    );
    for entry in boot_info.boot_artifacts().iter() {
        regions = subtract_hhdm_span(regions, Some(entry.path_span()), raw.phys_mem_offset);
        regions = subtract_hhdm_span(regions, entry.data_span(), raw.phys_mem_offset);
    }

    regions = subtract_if_valid(
        regions,
        addr_to_phys(raw.framebuffer.address),
        raw.framebuffer.size() as u64,
    );

    regions = reserve_ap_boot_ranges(regions, &raw.ap_boot);
    regions = reserve_uefi_runtime_ranges(regions, &raw.uefi_runtime);

    regions
}

fn get_boot_usable_regions(usable_memory: &[UsableMemoryRegion]) -> Vec<(PhysAddr, u64)> {
    let mut regions = Vec::new();
    for region in usable_memory {
        if region.length == 0 {
            continue;
        }
        regions.push((PhysAddr::new(region.base), region.length));
    }
    regions
}

/// ブートメモリマップから使用可能領域を準備してBuddy Allocatorを初期化する
pub(crate) fn init_buddy_from_boot_info(
    boot_info: Option<&ExoBootInfoView<'_>>,
) -> alloc::vec::Vec<(x86_64::PhysAddr, u64)> {
    let usable_regions = if let Some(info) = boot_info {
        let authoritative = get_boot_usable_regions(info.usable_memory());
        if !authoritative.is_empty() {
            authoritative
        } else {
            let mut fallback = if info.memory_map().is_empty() {
                get_default_memory_regions()
            } else {
                let regions = get_boot_memory_regions(info.memory_map());
                if regions.is_empty() {
                    get_default_memory_regions()
                } else {
                    regions
                }
            };
            fallback = reserve_bootstrap_heaps(fallback);
            reserve_boot_info_ranges(fallback, info)
        }
    } else {
        get_default_memory_regions()
    };

    unsafe {
        crate::mm::phys::buddy_allocator::init_buddy_allocator(&usable_regions);
    }

    #[cfg(feature = "buddy_freelist")]
    {
        unsafe {
            crate::mm::phys::buddy_freelist::init_freelist_buddy(&usable_regions);
        }
    }

    verify_buddy_integrity();

    usable_regions
}

/// NUMA情報を使ってPMM (Physical Memory Manager) を初期化する
pub(crate) fn init_numa_pmm(
    numa_info: Option<&NumaInfo>,
    usable_regions: &[(x86_64::PhysAddr, u64)],
) {
    let mut pmm_initialized = false;
    if let Some(info) = numa_info {
        if info.node_count > 0 {
            unsafe {
                if crate::mm::phys::frame_allocator::init_numa_frame_allocator_from_info(info) {
                    pmm_initialized = true;
                }
            }
        }
    }

    if !pmm_initialized {
        unsafe {
            crate::mm::phys::frame_allocator::init_frame_allocator(usable_regions);
        }
    }
}

/// Exchange Heap, BSP Per-CPU/TLS, Per-Core Slab Cache の初期化
pub(crate) fn init_post_buddy(boot_info: Option<&ExoBootInfoView<'_>>) {
    unsafe {
        crate::mm::cache::exchange_heap::init_exchange_heap(
            exchange_heap_start() as usize,
            EXCHANGE_HEAP_SIZE,
        );
    }
    verify_buddy_integrity();

    unsafe {
        crate::per_cpu::complete_bsp_per_cpu_tls(
            boot_info.map(|info| &info.boot_info().tls_template),
        );
    }

    crate::mm::cache::slab_cache::init_per_core_cache_for_cpu(0);
}

/// メモリサブシステムの完全初期化
///
/// 初期化順序:
/// 1. グローバルヒープ（allocが使えるようになる）
/// 2. Buddy Allocator（物理フレーム管理）
/// 3. Exchange Heap（ゼロコピーIPC用）
/// 4. Per-CPU データ構造
/// 5. Per-Core Slab Cache
pub fn init(numa_info: Option<&NumaInfo>, boot_info: Option<&ExoBootInfoView<'_>>) {
    use core::sync::atomic::Ordering;

    crate::io::log::early_print("[MEM] init start\n");

    if MEMORY_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // 0. Higher Half Manager の初期化 (IOMMUなどが依存)
    crate::mm::virt::higher_half::init(physical_memory_offset());

    // 1. グローバルヒープの初期化（最初に行う - allocが必要）
    init_global_heap();
    verify_buddy_integrity();

    // 2. Buddy Allocator の初期化（ブートローダーのメモリマップを使用）
    let usable_regions = init_buddy_from_boot_info(boot_info);

    // 2.5. NUMA情報（ブートローダー/ACPI）からPMMを初期化
    init_numa_pmm(numa_info, &usable_regions);

    // 3-5. Exchange Heap, Per-CPU, Per-Core Slab Cache
    init_post_buddy(boot_info);

    // Early-boot helper vector is no longer needed.  Avoid allocator churn on
    // function epilogue in qemu-test-export/full-mm paths where allocator
    // metadata can still be in a fragile state.
    core::mem::forget(usable_regions);

    crate::io::log::early_print("[MEM] init done\n");
}

/// ヒープ整合性チェック（デバッグ用）
/// - 全ての free_list の head と、その head に格納された next ポインタを検査
/// - 不正が見つかった場合、バックトレースを出力する
pub fn verify_buddy_integrity() {
    #[cfg(not(feature = "full_mm_tests"))]
    {
        match ALLOCATOR.0.lock() {
            Ok(guard) => {
                for i in 0..=BuddyHeapAllocator::MAX_ORDER {
                    let head = guard.free_lists[i].unwrap_or(0);

                    if head != 0 {
                        let next = crate::io::mmio::volatile_read::<usize>(head as usize);
                        if next != 0
                            && (next < guard.heap_start || next >= guard.heap_start + HEAP_SIZE)
                        {
                            crate::io::log::early_print("[HEAP_CHECK] INVALID NEXT at head=");
                            crate::io::log::early_print_hex(head as u64);
                            crate::io::log::early_print(" next=");
                            crate::io::log::early_print_hex(next as u64);
                            crate::io::log::early_print("\n");

                            crate::io::log::early_print("[HEAP_CHECK] Capturing backtrace...\n");
                            let bt = crate::unwind::Backtrace::capture();
                            for entry in bt.iter() {
                                crate::io::log::early_print("[HEAP_CHECK][BT] IP=");
                                crate::io::log::early_print_hex(
                                    entry.frame.instruction_pointer as u64,
                                );
                                crate::io::log::early_print("\n");
                            }
                        }
                    }
                }
            }
            Err(_) => {
                crate::io::log::early_print("[HEAP_CHECK] Failed to lock buddy allocator\n");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Debug write-detection helpers (debug-only)
// - Detect suspicious writes of values like EXCHANGE_HEAP_SIZE (0x400000)
// - Print a backtrace when detected and continue (non-fatal)
// ---------------------------------------------------------------------------

#[cfg(debug_assertions)]
pub(crate) fn debug_log_suspicious_write(addr: usize, val: usize, context: &str) {
    const SUSPICIOUS_VAL: usize = EXCHANGE_HEAP_SIZE; // 0x400000
    if val == SUSPICIOUS_VAL || val == 0x0000_0000_0400_000usize {
        // Many of the ExHeap initialization writes will write the exchange heap size
        // into headers/footers — suppress those to reduce noise unless the write is
        // outside the exchange-heap region.
        let ex_start = exchange_heap_start() as usize;
        let ex_end = ex_start.saturating_add(EXCHANGE_HEAP_SIZE);
        if addr >= ex_start && addr < ex_end {
            return; // expected during ExHeap init
        }

        crate::io::log::early_print("[SUSPICIOUS-WRITE] ");
        crate::io::log::early_print(context);
        crate::io::log::early_print(" addr=");
        crate::io::log::early_print_hex(addr as u64);
        crate::io::log::early_print(" val=");
        crate::io::log::early_print_hex(val as u64);
        crate::io::log::early_print("\n");

        crate::io::log::early_print("[SUSPICIOUS-WRITE] Capturing backtrace...\n");
        let bt = crate::unwind::Backtrace::capture();
        for entry in bt.iter() {
            crate::io::log::early_print("[SUSPICIOUS-WRITE][BT] IP=");
            crate::io::log::early_print_hex(entry.frame.instruction_pointer as u64);
            crate::io::log::early_print("\n");
        }
    }
}

/// Volatile write wrapper that performs debug checks for suspicious values
pub(crate) fn checked_volatile_write_usize(addr: usize, val: usize, context: &str) {
    #[cfg(debug_assertions)]
    debug_log_suspicious_write(addr, val, context);
    crate::io::mmio::volatile_write::<usize>(addr, val);
}

/// Direct volatile store wrapper (for plain memory stores)
pub(crate) fn checked_store_usize(addr: usize, val: usize, context: &str) {
    #[cfg(debug_assertions)]
    debug_log_suspicious_write(addr, val, context);
    unsafe {
        core::ptr::write_volatile(addr as *mut usize, val);
    }
}

/// グローバルヒープの初期化（Buddy Allocatorベース）
pub(crate) fn init_global_heap() {
    #[cfg(any(
        not(feature = "full_mm_tests"),
        all(feature = "full_mm_tests", not(test))
    ))]
    {
        crate::io::log::early_print("[HEAP] lock\n");
        let mut guard = ALLOCATOR.0.lock_for_init("[HEAP] global allocator init");
        crate::io::log::early_print("[HEAP] init call\n");
        let start = heap_start();
        crate::io::log::early_print("[HEAP] addr ok\n");
        unsafe {
            guard.init(start as usize, HEAP_SIZE);
        }
        drop(guard);
        crate::io::log::early_print("[HEAP] done\n");
    }

    #[cfg(all(feature = "full_mm_tests", test))]
    {
        crate::io::log::early_print("[HEAP] Skipping global heap init (using dummy)\n");
    }
}

/// Ensure global heap allocator state is usable before runtime subsystems
/// (ACPI/IOMMU/etc.) begin allocating.
///
/// If metadata was clobbered and the allocator appears uninitialized, rebuild
/// the buddy free lists from the canonical heap geometry.
pub fn ensure_global_heap_ready() {
    #[cfg(any(
        not(feature = "full_mm_tests"),
        all(feature = "full_mm_tests", not(test))
    ))]
    {
        let mut guard = ALLOCATOR
            .0
            .lock_for_init("[HEAP] ensure global allocator ready");
        if guard.ensure_initialized() {
            set_heap_deallocation_enabled(true);
            return;
        }

        let has_free_list_entries = guard.free_lists.iter().any(|entry| entry.is_some());
        if !has_free_list_entries {
            crate::io::log::early_print("[HEAP] allocator free-lists empty - rebuilding\n");
            unsafe {
                guard.init(heap_start() as usize, HEAP_SIZE);
            }
            set_heap_deallocation_enabled(true);
            return;
        }

        if guard.heap_start == 0 {
            guard.heap_start = heap_start() as usize;
        }
        if guard.heap_size == 0 {
            guard.heap_size = HEAP_SIZE;
        }
        if guard.ensure_initialized() {
            crate::io::log::early_print("[HEAP] allocator metadata repaired\n");
        } else {
            crate::io::log::early_print("[HEAP] allocator metadata unrecoverable\n");
        }
        set_heap_deallocation_enabled(true);
    }

    #[cfg(all(feature = "full_mm_tests", test))]
    {
        // dummy allocator path
    }
}

/// デフォルトのメモリ領域を取得
/// 本番環境ではブートローダーから取得するが、開発用にハードコード
pub(crate) fn get_default_memory_regions() -> Vec<(PhysAddr, u64)> {
    // 16MiB - 496MiB の範囲を使用可能として設定 (QEMU 512MBに収まる)
    // 最初の16MiBはBIOSやカーネルのために予約
    alloc::vec![
        (PhysAddr::new(0x100_0000), 480 * 1024 * 1024), // 16MiB - 496MiB
    ]
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
    let stats = crate::mm::phys::buddy_allocator::buddy_allocator_stats();
    (stats.total_frames as u64) * 4 // 1フレーム = 4KB
}

/// 空きメモリをKB単位で取得
pub fn free_memory_kb() -> u64 {
    let stats = crate::mm::phys::buddy_allocator::buddy_allocator_stats();
    (stats.free_frames as u64) * 4 // 1フレーム = 4KB
}

/// 使用中メモリをKB単位で取得
pub fn used_memory_kb() -> u64 {
    total_memory_kb().saturating_sub(free_memory_kb())
}
