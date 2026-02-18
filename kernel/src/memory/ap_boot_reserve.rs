use super::*;


/// Reserve AP boot trampoline and stack ranges.
pub(crate) fn reserve_ap_boot_ranges(
    mut regions: Vec<(PhysAddr, u64)>,
    ap_boot: &boot_proto::ApBootInfo,
) -> Vec<(PhysAddr, u64)> {
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
    regions
}

/// Reserve UEFI runtime memory map ranges.
pub(crate) fn reserve_uefi_runtime_ranges(
    mut regions: Vec<(PhysAddr, u64)>,
    runtime: &boot_proto::UefiRuntimeInfo,
) -> Vec<(PhysAddr, u64)> {
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

pub(crate) fn reserve_boot_info_ranges(
    mut regions: Vec<(PhysAddr, u64)>,
    boot_info: &ExoBootInfo,
) -> Vec<(PhysAddr, u64)> {
    let boot_info_ptr = boot_info as *const _ as u64;
    regions = subtract_if_valid(
        regions,
        hhdm_ptr_to_phys(boot_info_ptr),
        core::mem::size_of::<ExoBootInfo>() as u64,
    );

    let mmap_ptr = boot_info.memory_map.entries as u64;
    let entry_size = core::mem::size_of::<boot_proto::MemoryDescriptor>() as u64;
    let mmap_bytes = boot_info.memory_map.count.checked_mul(entry_size).unwrap_or(0);
    regions = subtract_if_valid(regions, hhdm_ptr_to_phys(mmap_ptr), mmap_bytes);

    regions = subtract_if_valid(
        regions,
        hhdm_ptr_to_phys(boot_info.cmdline_ptr),
        boot_info.cmdline_len.saturating_add(1),
    );

    regions = subtract_if_valid(
        regions,
        hhdm_ptr_to_phys(boot_info.initramfs.ptr),
        boot_info.initramfs.size,
    );

    regions = subtract_if_valid(
        regions,
        addr_to_phys(boot_info.framebuffer.address),
        boot_info.framebuffer.size() as u64,
    );

    regions = reserve_ap_boot_ranges(regions, &boot_info.ap_boot);
    regions = reserve_uefi_runtime_ranges(regions, &boot_info.uefi_runtime);

    regions
}

/// ブートメモリマップから使用可能領域を準備してBuddy Allocatorを初期化する
pub(crate) fn init_buddy_from_boot_info(
    boot_info: Option<&ExoBootInfo>,
) -> alloc::vec::Vec<(x86_64::PhysAddr, u64)> {
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

    crate::io::log::early_print("[MEM] After reserve_bootstrap_heaps:\n");
    for (addr, size) in usable_regions.iter() {
        crate::io::log::early_print("  region phys=");
        crate::io::log::early_print_hex(addr.as_u64());
        crate::io::log::early_print(" size=");
        crate::io::log::early_print_hex(*size);
        crate::io::log::early_print("\n");
    }

    crate::io::log::early_print("[MEM] heap_start=");
    crate::io::log::early_print_hex(heap_start());
    crate::io::log::early_print(" exchange_heap_start=");
    crate::io::log::early_print_hex(exchange_heap_start());
    crate::io::log::early_print("\n");

    let hhdm = physical_memory_offset();
    crate::io::log::early_print("[MEM] HHDM=");
    crate::io::log::early_print_hex(hhdm);
    crate::io::log::early_print(" heap_phys=");
    crate::io::log::early_print_hex(heap_start().saturating_sub(hhdm));
    crate::io::log::early_print(" exchange_phys=");
    crate::io::log::early_print_hex(exchange_heap_start().saturating_sub(hhdm));
    crate::io::log::early_print("\n");

    if let Some(info) = boot_info {
        usable_regions = reserve_boot_info_ranges(usable_regions, info);
    }
    crate::io::log::early_print("[MEM] buddy bootstrap\n");

    unsafe {
        crate::mm::init_buddy_allocator(&usable_regions);
    }
    crate::io::log::early_print("[MEM] buddy ready\n");

    #[cfg(feature = "buddy_freelist")]
    {
        crate::io::log::early_print("[MEM] freelist buddy init\n");
        unsafe {
            crate::mm::buddy_freelist::init_freelist_buddy(&usable_regions);
        }
        crate::io::log::early_print("[MEM] freelist buddy ready\n");
    }

    crate::io::log::early_print("[HEAP_CHECK] after init_buddy_allocator\n");
    verify_buddy_integrity();

    usable_regions
}

/// NUMA情報を使ってPMM (Physical Memory Manager) を初期化する
pub(crate) fn init_numa_pmm(
    rsdp_addr: Option<u64>,
    numa_info: Option<&NumaInfo>,
    usable_regions: &[(x86_64::PhysAddr, u64)],
) {
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
        pmm_initialized = init_pmm_from_srat(rsdp_addr);
    }

    if !pmm_initialized {
        crate::io::log::early_print("[MEM] using global PMM\n");
        unsafe {
            crate::mm::init_frame_allocator(usable_regions);
        }
    }
}

/// SRAT (ACPI) からNUMA領域を解析してPMMを初期化する
pub(crate) fn init_pmm_from_srat(rsdp_addr: Option<u64>) -> bool {
    crate::io::log::early_print("[MEM] SRAT check\n");
    let Some(_rsdp_addr_val) = rsdp_addr else {
        crate::io::log::early_print("[MEM] no SRAT (RSDP not provided)\n");
        return false;
    };
    crate::io::log::early_print("[MEM] parsing SRAT\n");
    let regions = crate::io::acpi::numa_memory_regions();
    let mut numa_regions = alloc::vec::Vec::new();
    for (base, length, proximity) in regions {
        let s = alloc::format!(
            "[MEM] registering region {:#x} len {:#x} prox {}\n",
            base, length, proximity
        );
        crate::io::log::early_print(&s);
        let base_phys = x86_64::PhysAddr::new(base);
        let node = crate::mm::NumaNodeId::new(proximity as u8);
        numa_regions.push((base_phys, length, node));
    }
    if !numa_regions.is_empty() {
        unsafe {
            crate::mm::init_numa_frame_allocator(&numa_regions);
        }
        true
    } else {
        crate::io::log::early_print("[MEM] SRAT empty\n");
        false
    }
}

/// Exchange Heap, Per-CPU, Per-Core Slab Cache の初期化
pub(crate) fn init_post_buddy() {
    crate::io::log::early_print("[MEM] exheap init\n");
    unsafe {
        crate::mm::init_exchange_heap(exchange_heap_start() as usize, EXCHANGE_HEAP_SIZE);
    }
    crate::io::log::early_print("[MEM] exheap done\n");
    crate::io::log::early_print("[HEAP_CHECK] after exchange_heap_init\n");
    verify_buddy_integrity();

    crate::io::log::early_print("[MEM] percpu init\n");
    unsafe {
        crate::mm::init_per_cpu(1);
    }
    crate::io::log::early_print("[MEM] percpu done\n");

    crate::io::log::early_print("[MEM] slab init\n");
    crate::mm::init_per_core_caches(1);
    crate::io::log::early_print("[MEM] slab done\n");
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
    crate::io::log::early_print("[HEAP_CHECK] after global heap init\n");
    verify_buddy_integrity();

    // 2. Buddy Allocator の初期化（ブートローダーのメモリマップを使用）
    let usable_regions = init_buddy_from_boot_info(boot_info);

    // 2.5. NUMA情報（ブートローダー/ACPI）からPMMを初期化
    init_numa_pmm(rsdp_addr, numa_info, &usable_regions);

    // 3-5. Exchange Heap, Per-CPU, Per-Core Slab Cache
    init_post_buddy();

    crate::io::log::early_print("[MEM] all done\n");
}

/// ヒープ整合性チェック（デバッグ用）
/// - 全ての free_list の head と、その head に格納された next ポインタを検査
/// - 不正が見つかった場合、バックトレースを出力する
pub fn verify_buddy_integrity() {
    #[cfg(not(feature = "full_mm_tests"))]
    {
        crate::io::log::early_print("[HEAP_CHECK] Verifying buddy free lists...\n");
        match ALLOCATOR.0.lock() {
            Ok(guard) => {
                for i in 0..=BuddyHeapAllocator::MAX_ORDER {
                    crate::io::log::early_print("[HEAP_CHECK] free_lists[");
                    crate::io::log::early_print_dec(i as u64);
                    crate::io::log::early_print("] = ");
                    let head = guard.free_lists[i].unwrap_or(0);
                    crate::io::log::early_print_hex(head as u64);
                    crate::io::log::early_print("\n");

                    if head != 0 {
                        let next = crate::io::mmio::volatile_read::<usize>(head as usize);
                        if next != 0 && (next < guard.heap_start || next >= guard.heap_start + HEAP_SIZE) {
                            crate::io::log::early_print("[HEAP_CHECK] INVALID NEXT at head=");
                            crate::io::log::early_print_hex(head as u64);
                            crate::io::log::early_print(" next=");
                            crate::io::log::early_print_hex(next as u64);
                            crate::io::log::early_print("\n");

                            crate::io::log::early_print("[HEAP_CHECK] Capturing backtrace...\n");
                            let bt = crate::unwind::Backtrace::capture();
                            for entry in bt.iter() {
                                crate::io::log::early_print("[HEAP_CHECK][BT] IP=");
                                crate::io::log::early_print_hex(entry.frame.instruction_pointer as u64);
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

    #[cfg(feature = "full_mm_tests")]
    {
        crate::io::log::early_print("[HEAP_CHECK] Skipping buddy integrity check in full_mm_tests\n");
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
pub fn checked_volatile_write_usize(addr: usize, val: usize, context: &str) {
    #[cfg(debug_assertions)]
    debug_log_suspicious_write(addr, val, context);
    crate::io::mmio::volatile_write::<usize>(addr, val);
}

/// Direct volatile store wrapper (for plain memory stores)
pub fn checked_store_usize(addr: usize, val: usize, context: &str) {
    #[cfg(debug_assertions)]
    debug_log_suspicious_write(addr, val, context);
    unsafe { core::ptr::write_volatile(addr as *mut usize, val); }
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
        if let Some((start, end)) = validate_usable_descriptor(desc, MIN_USABLE_PHYS_ADDR) {
            let released = crate::mm::pmm_release_range(PhysAddr::new(start), end - start);
            total_pages += released;
        }
    }

    if total_pages > 0 {
        log::info!("[MEM] Reclaimed ACPI memory: {} pages", total_pages);
    }
}

/// グローバルヒープの初期化（Buddy Allocatorベース）
pub(crate) fn init_global_heap() {
    #[cfg(not(feature = "full_mm_tests"))]
    {
        crate::io::log::early_print("[HEAP] lock\n");
        let mut guard = ALLOCATOR.0.lock_for_init("[HEAP] global allocator init");
    crate::io::log::early_print("[HEAP] init call\n");
    let start = heap_start();
    crate::io::log::early_print("[HEAP] addr ok\n");
    unsafe {
        guard.init(start as usize, HEAP_SIZE);
    }
    // Debug: print guard pointer for diagnosing early-allocation issues
    {
        let guard_ptr = (&*ALLOCATOR.0.lock().unwrap()) as *const _ as usize;
        crate::io::log::early_print("[HEAP DEBUG] init guard ptr=");
        crate::io::log::early_print_hex(guard_ptr as u64);
        crate::io::log::early_print("\n");
    }
    crate::io::log::early_print("[HEAP] done\n");
    }

    #[cfg(feature = "full_mm_tests")]
    {
        crate::io::log::early_print("[HEAP] Skipping global heap init (using dummy)\n");
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

/// メモリ統計を表示
pub(crate) fn print_memory_stats() {
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

#[cfg(not(test))]
// #[alloc_error_handler] removed. Defined in kernel_content.rs

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

