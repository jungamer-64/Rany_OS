//! Heap allocator implementation and bootstrap helpers.
#[path = "oom.rs"]
pub mod oom;

#[cfg(any(not(test), feature = "full_mm_tests"))]
#[path = "bootstrap.rs"]
mod bootstrap;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub(crate) use bootstrap::init;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub use bootstrap::{
    free_memory_kb, heap_stats, is_initialized, total_memory_kb, used_memory_kb,
    verify_buddy_integrity,
};
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub(crate) use bootstrap::{physical_memory_offset, set_physical_memory_offset};

use super::HeapMemory;
use crate::sync::PoisonLock;
use alloc::vec::Vec;
use boot_proto::MemoryDescriptor;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use x86_64::PhysAddr;

const ALLOC_HEADER_MAGIC: u64 = 0x514f_5441_4d45_4d31;
const QUOTA_ALLOCATION_RACE_RETRY: usize = 3;
const ALLOC_OOM_RETRY: usize = 1;

/// The current execution supplies a stable account; this boundary never looks
/// up a domain in a registry. Contention remains bounded inside GlobalAlloc.
fn reserve_quota(
    bytes: u64,
) -> Result<Option<crate::domain::quota::MemoryCredit>, crate::domain::quota::QuotaError> {
    let Some(current) = crate::cpu::CurrentCpu::acquire() else {
        return Ok(None);
    };
    for attempt in 0..=QUOTA_ALLOCATION_RACE_RETRY {
        match current.reserve_memory(bytes) {
            Err(crate::domain::quota::QuotaError::AllocationRace)
                if attempt < QUOTA_ALLOCATION_RACE_RETRY =>
            {
                continue;
            }
            result => return result,
        }
    }
    unreachable!("bounded quota attempts return on their last iteration")
}

use super::buddy::BuddyHeapAllocator;

/// Kernel allocations use bounded CPU magazines and node-owned slab/Buddy pools.
/// The mutex retains only the separately transferred loader bootstrap heap.
pub struct KernelHeap(PoisonLock<BuddyHeapAllocator>);

impl KernelHeap {
    pub const fn new() -> Self {
        Self(PoisonLock::new(BuddyHeapAllocator::new()))
    }

    /// Check if the heap allocator is initialized
    pub fn is_initialized(&self) -> Option<bool> {
        self.0.lock().ok().map(|g| g.backing.is_some())
    }
}

/// The unique source is transferred into/out of this header exactly once.
/// Class selection uses the full extended Layout, including quota metadata.
#[repr(C)]
struct AllocHeader {
    magic: u64,
    quota: Option<crate::domain::quota::MemoryCredit>,
    raw_size: usize,
    raw_align: usize,
    source: super::raw::AllocationSource,
}

// Quota and source metadata must leave room for a nonzero payload in the
// smallest slab class. CPU-affinity changes cannot silently double the small
// allocation footprint by making that class unreachable.
const _: () = assert!(core::mem::size_of::<AllocHeader>() < super::raw::SMALLEST_CLASS_BYTES);

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let requested = layout.size() as u64;
        let Ok((extended, offset)) = Layout::new::<AllocHeader>().extend(layout) else {
            return null_mut();
        };
        let raw_layout = extended.pad_to_align();
        for attempt in 0..=ALLOC_OOM_RETRY {
            let Ok(quota) = reserve_quota(requested) else {
                return null_mut();
            };
            let block = super::raw::allocate(raw_layout).or_else(|| {
                // The loader transferred this disjoint pool separately from
                // PMM RAM. It serves early boot and bounded slow-path fallback.
                let mut heap = self.0.lock().ok()?;
                core::ptr::NonNull::new(heap.allocate(raw_layout)).map(|pointer| {
                    super::raw::RawBlock {
                        pointer,
                        source: super::raw::AllocationSource::Bootstrap,
                    }
                })
            });
            if let Some(block) = block {
                // SAFETY: the raw owner reserves enough aligned writable RAM
                // for this header and the requested payload; source is consumed.
                unsafe {
                    block
                        .pointer
                        .as_ptr()
                        .cast::<AllocHeader>()
                        .write(AllocHeader {
                            magic: ALLOC_HEADER_MAGIC,
                            quota,
                            raw_size: raw_layout.size(),
                            raw_align: raw_layout.align(),
                            source: block.source,
                        });
                    crate::profiler::record_kernel_heap_allocation();
                    return block.pointer.as_ptr().add(offset);
                }
            }
            drop(quota);
            if attempt == ALLOC_OOM_RETRY || !crate::heap::oom::try_free_memory() {
                break;
            }
        }
        null_mut()
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Ok((_, offset)) = Layout::new::<AllocHeader>().extend(layout) else {
            return;
        };
        // SAFETY: GlobalAlloc callers provide this exact live pointer/Layout.
        // Header consumption transfers the unique source and quota return right.
        let raw = unsafe { pointer.sub(offset) };
        // SAFETY: every successful allocation initialized this disjoint header.
        let header = unsafe { raw.cast::<AllocHeader>().read() };
        assert_eq!(
            header.magic, ALLOC_HEADER_MAGIC,
            "allocation header must belong to this heap"
        );
        let raw_layout = Layout::from_size_align(header.raw_size, header.raw_align)
            .expect("retained allocation layout");
        drop(header.quota);
        match header.source {
            super::raw::AllocationSource::Bootstrap => {
                if let Ok(mut heap) = self.0.lock() {
                    heap.deallocate(raw, raw_layout);
                }
            }
            source => {
                // SAFETY: the consumed header retains this exact raw pointer.
                let pointer = unsafe { core::ptr::NonNull::new_unchecked(raw) };
                super::raw::cache_or_release(super::raw::RawBlock { pointer, source }, raw_layout);
            }
        }
    }
}

/// GlobalAlloc source ownership and quota accounting are retained across CPU moves.
#[cfg(any(
    not(feature = "full_mm_tests"),
    all(feature = "full_mm_tests", not(test)),
    all(test, feature = "std")
))]
pub static ALLOCATOR: KernelHeap = KernelHeap::new();

#[cfg(all(feature = "full_mm_tests", test, not(feature = "std")))]
pub use crate::ALLOCATOR;

const EFI_PAGE_SIZE: u64 = 4096;
const EFI_MEMORY_TYPE_BOOT_SERVICES_CODE: u32 = 3;
const EFI_MEMORY_TYPE_BOOT_SERVICES_DATA: u32 = 4;
const EFI_MEMORY_TYPE_CONVENTIONAL: u32 = 7;
const MIN_USABLE_PHYS_ADDR: u64 = 0x100_0000; // 16 MiB

/// メモリサブシステム初期化フラグ
#[repr(u8)]
enum MemoryState {
    Uninitialized,
    Initializing,
    Ready,
    Failed,
}
static MEMORY_STATE: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(MemoryState::Uninitialized as u8);

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

fn get_boot_memory_regions(memory_map: &[MemoryDescriptor]) -> Vec<(PhysAddr, u64)> {
    let mut regions = Vec::new();
    if memory_map.is_empty() {
        return regions;
    }

    for desc in memory_map {
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

fn reserve_kernel_image(mut regions: Vec<(PhysAddr, u64)>) -> Vec<(PhysAddr, u64)> {
    // Reserve kernel image (.text/.rodata/.data/.bss) so PMM never hands out
    // frames that back static kernel state (e.g. global allocator metadata).
    if let Some((kernel_start, kernel_end)) = kernel_phys_range() {
        let kernel_size = kernel_end.saturating_sub(kernel_start);
        regions = subtract_reserved_range(regions, kernel_start, kernel_size);
    }

    regions
}

#[cfg(not(test))]
fn kernel_phys_range() -> Option<(u64, u64)> {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }

    let (kernel_start_virt, kernel_end_virt) = unsafe {
        (
            crate::mm::virt::higher_half::VirtAddr::new(&__kernel_start as *const u8 as u64),
            crate::mm::virt::higher_half::VirtAddr::new(&__kernel_end as *const u8 as u64),
        )
    };
    if kernel_end_virt.as_u64() <= kernel_start_virt.as_u64() {
        return None;
    }

    let kernel_start_phys = crate::mm::virt::higher_half::global_translate(kernel_start_virt)
        .map(|p| p.as_u64())
        .or_else(|| addr_to_phys(kernel_start_virt.as_u64()))?;

    let kernel_last_virt =
        crate::mm::virt::higher_half::VirtAddr::new(kernel_end_virt.as_u64().saturating_sub(1));
    let kernel_last_phys = crate::mm::virt::higher_half::global_translate(kernel_last_virt)
        .map(|p| p.as_u64())
        .or_else(|| addr_to_phys(kernel_last_virt.as_u64()))?;
    let kernel_end_phys = kernel_last_phys.saturating_add(1);

    if kernel_end_phys <= kernel_start_phys {
        return None;
    }

    Some((kernel_start_phys, kernel_end_phys))
}

#[cfg(test)]
fn kernel_phys_range() -> Option<(u64, u64)> {
    None
}

fn hhdm_ptr_to_phys(ptr: u64) -> Option<u64> {
    if ptr == 0 {
        return None;
    }
    let hhdm = crate::heap::physical_memory_offset();
    if ptr < hhdm {
        return None;
    }
    Some(ptr - hhdm)
}

fn addr_to_phys(addr: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    let hhdm = crate::heap::physical_memory_offset();
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
