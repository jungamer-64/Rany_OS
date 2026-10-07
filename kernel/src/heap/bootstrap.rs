use super::*;
use boot_proto::{ExoBootInfo, ExoBootInfoView, UsableMemoryRegion};
use core::sync::atomic::{AtomicU64, Ordering};

static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0xFFFF_8000_0000_0000);

#[inline]
pub(crate) fn physical_memory_offset() -> u64 {
    PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed)
}

pub(crate) fn set_physical_memory_offset(offset: u64) {
    PHYSICAL_MEMORY_OFFSET.store(offset, Ordering::SeqCst);
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

    if let Ok(trampoline_start) = raw.ap_trampoline.address() {
        regions = subtract_reserved_range(
            regions,
            trampoline_start.as_u64(),
            u64::from(raw.ap_trampoline.byte_len),
        );
    }
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

/// Exclude retained boot owners before transferring RAM into the sole PMM.
pub(crate) fn prepare_pmm_regions(
    info: &ExoBootInfoView<'_>,
    heap_geometry: boot_proto::BootstrapHeapGeometry,
) -> Option<alloc::vec::Vec<(x86_64::PhysAddr, u64)>> {
    let authoritative = get_boot_usable_regions(info.usable_memory());
    let mut usable_regions = if authoritative.is_empty() {
        reserve_boot_info_ranges(
            reserve_kernel_image(get_boot_memory_regions(info.memory_map())),
            info,
        )
    } else {
        authoritative
    };
    // Reservation follows the unique admitted owner's immutable geometry in
    // both normalized and raw-map paths; no guessed RAM source is available.
    let (physical, bytes) = heap_geometry.allocation_range();
    usable_regions = subtract_reserved_range(usable_regions, physical, bytes);
    if usable_regions.is_empty() {
        return None;
    }

    Some(usable_regions)
}

/// NUMA情報を使ってPMM (Physical Memory Manager) を初期化する
pub(crate) fn init_numa_pmm(usable_regions: &[(x86_64::PhysAddr, u64)]) {
    let placement = crate::platform::firmware::numa_placement()
        .unwrap_or_else(|error| panic!("PMM firmware topology admission failed: {error:?}"));
    // SAFETY: the boot ownership boundary excluded retained heaps and live
    // boot allocations before transferring these exclusive RAM ranges.
    unsafe {
        crate::mm::phys::frame_allocator::init_numa_frame_allocator_with_placement(
            placement,
            usable_regions,
        )
        .unwrap_or_else(|error| panic!("exclusive PMM admission failed: {error:?}"));
    }
}

fn initialize_firmware_catalog(boot_info: Option<&ExoBootInfoView<'_>>) {
    let Some(info) = boot_info else {
        return;
    };
    let rsdp_address = info.boot_info().rsdp_addr;
    if rsdp_address == 0 {
        return;
    }
    match unsafe {
        crate::platform::firmware::initialize_tables(rsdp_address, physical_memory_offset())
    } {
        Ok(catalog) => log::info!(
            target: "init",
            "ACPI static catalog owns {} table(s)",
            catalog.tables().len()
        ),
        Err(error) => log::warn!(
            target: "init",
            "ACPI static catalog unavailable: {:?}",
            error
        ),
    }
}

/// Observation of the bootstrap slab after both heaps and the PMM have
/// accepted their disjoint RAM owners. It grants no allocation or release right;
/// firmware protection consumes it before devices may publish DMA mappings.
pub(crate) struct BootRamAdmission {
    bootstrap: core::ops::Range<u64>,
}

impl BootRamAdmission {
    pub(crate) fn bootstrap_range(&self) -> core::ops::Range<u64> {
        self.bootstrap.clone()
    }
}

#[derive(Debug)]
pub(crate) enum HeapInitError {
    AlreadyStarted {
        retained: super::super::BootstrapHeaps,
    },
    GlobalAllocatorUnavailable {
        kernel: HeapMemory,
        exchange: HeapMemory,
    },
    NoUsableRam {
        exchange: HeapMemory,
    },
    ExchangeAllocatorUnavailable {
        retained: HeapMemory,
    },
}

impl core::fmt::Display for HeapInitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyStarted { retained } => {
                write!(f, "memory startup already consumed; retained {retained:?}")
            }
            Self::GlobalAllocatorUnavailable { kernel, exchange } => write!(
                f,
                "global allocator rejected RAM; retained {kernel:?}, {exchange:?}"
            ),
            Self::NoUsableRam { exchange } => write!(
                f,
                "no usable RAM after reservations; global heap committed, retained {exchange:?}"
            ),
            Self::ExchangeAllocatorUnavailable { retained } => write!(
                f,
                "exchange allocator rejected RAM after PMM startup; retained {retained:?}"
            ),
        }
    }
}

/// メモリサブシステムの完全初期化
///
/// 初期化順序:
/// 1. グローバルヒープ（allocが使えるようになる）
/// 2. Buddy Allocator（物理フレーム管理）
/// 3. Exchange Heap（ゼロコピーIPC用）
/// 4. Per-CPU データ構造
/// 5. Per-Core Slab Cache
///
/// # Errors
/// Duplicate startup returns both incoming owners. A failed global admission
/// also returns both owners. Later failure retains unused exchange RAM while
/// global/physical allocators remain committed; none of these errors permits
/// reinitialization or restarting runtime workers. The boot root must terminate.
pub(crate) fn init(
    boot_info: &ExoBootInfoView<'_>,
    heaps: super::super::BootstrapHeaps,
) -> Result<BootRamAdmission, HeapInitError> {
    use core::sync::atomic::Ordering;

    crate::io::log::early_print("[MEM] init start\n");

    // Only Ready is published to observers. A partial startup failure is
    // terminal; the retained global heap is never reinitialized or reissued.
    if MEMORY_STATE
        .compare_exchange(
            MemoryState::Uninitialized as u8,
            MemoryState::Initializing as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(HeapInitError::AlreadyStarted { retained: heaps });
    }
    let (kernel, exchange, geometry) = heaps.into_parts();

    // 0. Higher Half Manager の初期化 (IOMMUなどが依存)
    crate::mm::virt::higher_half::init(physical_memory_offset());

    // 1. グローバルヒープの初期化（最初に行う - allocが必要）
    #[cfg(not(all(feature = "full_mm_tests", test, not(feature = "std"))))]
    {
        let admitted = match ALLOCATOR.0.lock() {
            Ok(mut allocator) => allocator.init(kernel),
            Err(_) => Err(kernel),
        };
        if let Err(kernel) = admitted {
            MEMORY_STATE.store(MemoryState::Failed as u8, Ordering::Release);
            return Err(HeapInitError::GlobalAllocatorUnavailable { kernel, exchange });
        }
    }
    #[cfg(all(feature = "full_mm_tests", test, not(feature = "std")))]
    core::mem::forget(kernel);
    verify_buddy_integrity();

    // The catalog owns copies of firmware tables and therefore needs the
    // kernel heap. It must precede NUMA PMM construction, whose topology is
    // derived from this catalog rather than from a bootloader snapshot.
    initialize_firmware_catalog(Some(boot_info));

    // 2. Prepare exclusive PMM RAM from boot ownership.
    let Some(usable_regions) = prepare_pmm_regions(boot_info, geometry) else {
        MEMORY_STATE.store(MemoryState::Failed as u8, Ordering::Release);
        return Err(HeapInitError::NoUsableRam { exchange });
    };

    // 2.5. NUMA情報（ブートローダー/ACPI）からPMMを初期化
    init_numa_pmm(&usable_regions);

    // 3-5. Exchange Heap, Per-CPU, Per-Core Slab Cache
    if let Err(retained) = crate::mm::cache::exchange_heap::EXCHANGE_HEAP.initialize(exchange) {
        MEMORY_STATE.store(MemoryState::Failed as u8, Ordering::Release);
        return Err(HeapInitError::ExchangeAllocatorUnavailable { retained });
    }
    verify_buddy_integrity();

    drop(usable_regions);

    MEMORY_STATE.store(MemoryState::Ready as u8, Ordering::Release);
    crate::io::log::early_print("[MEM] init done\n");
    let (start, size) = geometry.allocation_range();
    Ok(BootRamAdmission {
        bootstrap: start..start + size,
    })
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
                        // SAFETY: the retained heap owner and exclusive lock
                        // keep each initialized free-list header alive.
                        let next = unsafe { core::ptr::read(head as *const usize) };
                        if next != 0
                            && (next < guard.heap_start
                                || next >= guard.heap_start + guard.heap_size)
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

/// メモリサブシステムが初期化済みかどうか
pub fn is_initialized() -> bool {
    MEMORY_STATE.load(core::sync::atomic::Ordering::Acquire) == MemoryState::Ready as u8
}

/// ヒープ統計を取得（Buddy Allocator用）
/// 戻り値: (使用中バイト数概算, 空きバイト数概算)
pub fn heap_stats() -> (usize, usize) {
    // Bootstrap accounting is a cold observation of the owned free lists.
    #[cfg(not(all(feature = "full_mm_tests", test, not(feature = "std"))))]
    {
        let (pool_used, pool_free) = super::super::raw::stats();
        let (boot_used, boot_free) = ALLOCATOR
            .0
            .lock()
            .map(|guard| {
                let free = guard.free_bytes();
                (guard.heap_size - free, free)
            })
            .unwrap_or((0, 0));
        (boot_used + pool_used, boot_free + pool_free)
    }
    #[cfg(all(feature = "full_mm_tests", test, not(feature = "std")))]
    {
        (0, 0)
    }
}

/// システム総メモリをKB単位で取得
pub fn total_memory_kb() -> u64 {
    let (_, total) = crate::mm::phys::frame_allocator::frame_allocator_stats();
    total as u64 * 4
}

/// 空きメモリをKB単位で取得
pub fn free_memory_kb() -> u64 {
    let (free, _) = crate::mm::phys::frame_allocator::frame_allocator_stats();
    free * 4
}

/// 使用中メモリをKB単位で取得
pub fn used_memory_kb() -> u64 {
    total_memory_kb().saturating_sub(free_memory_kb())
}
