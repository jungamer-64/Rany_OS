//! Kernel DMA cache and IOMMU support.
//!
//! Allocation and transfer ownership are intentionally absent here while the
//! resource registry becomes the single DMA authority.

mod cache_ops;
pub use cache_ops::*;

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::structures::paging::PageTableFlags;

const DMA_ALIGNMENT: usize = 4096;

fn align_up(value: usize, align: usize) -> Option<usize> {
    if !align.is_power_of_two() {
        return None;
    }
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

pub(crate) fn iommu_align_len(len: usize) -> Option<usize> {
    align_up(len, DMA_ALIGNMENT)
}

pub(crate) fn iommu_needs_bounce(phys_addr: u64, len: usize) -> bool {
    (phys_addr & (DMA_ALIGNMENT as u64 - 1) != 0) || (len & (DMA_ALIGNMENT - 1) != 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IommuBounceAllocError {
    InvalidLen,
    AllocFailed,
}

pub(crate) fn allocate_iommu_bounce_bytes(
    len: usize,
) -> Result<crate::ipc::RRef<[u8]>, IommuBounceAllocError> {
    let aligned_len = iommu_align_len(len).ok_or(IommuBounceAllocError::InvalidLen)?;
    if aligned_len == 0 {
        return Err(IommuBounceAllocError::InvalidLen);
    }
    crate::ipc::RRef::new_slice_default_aligned(
        crate::ipc::DomainId::KERNEL,
        aligned_len,
        DMA_ALIGNMENT,
    )
    .ok_or(IommuBounceAllocError::AllocFailed)
}

/// Page-cache mode selected through the x86 page-table attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheMode {
    WriteBack = 0,
    WriteThrough = 1,
    Uncacheable = 2,
    WriteCombining = 3,
    WriteProtected = 4,
}

impl CacheMode {
    pub fn to_page_flags(self) -> PageTableFlags {
        match self {
            CacheMode::WriteBack => PageTableFlags::empty(),
            CacheMode::WriteThrough => PageTableFlags::WRITE_THROUGH,
            CacheMode::Uncacheable => PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH,
            CacheMode::WriteCombining => PageTableFlags::NO_CACHE,
            CacheMode::WriteProtected => PageTableFlags::WRITE_THROUGH,
        }
    }
}

pub const CACHE_LINE_SIZE: usize = 64;

static SUPPORTS_CLFLUSHOPT: AtomicBool = AtomicBool::new(false);
static SUPPORTS_CLWB: AtomicBool = AtomicBool::new(false);

pub fn init_cache_features() {
    let result = core::arch::x86_64::__cpuid_count(0x07, 0);
    SUPPORTS_CLFLUSHOPT.store((result.ebx & (1 << 23)) != 0, Ordering::Relaxed);
    SUPPORTS_CLWB.store((result.ebx & (1 << 24)) != 0, Ordering::Relaxed);
}

#[inline]
pub fn supports_clflushopt() -> bool {
    SUPPORTS_CLFLUSHOPT.load(Ordering::Relaxed)
}

#[inline]
pub fn supports_clwb() -> bool {
    SUPPORTS_CLWB.load(Ordering::Relaxed)
}

#[inline(always)]
pub fn clflush(addr: *const u8) {
    unsafe {
        asm!("clflush [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn clflushopt(addr: *const u8) {
    unsafe {
        asm!("clflushopt [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn clwb(addr: *const u8) {
    unsafe {
        asm!("clwb [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}

#[inline(always)]
fn flush_line(addr: *const u8) {
    if SUPPORTS_CLFLUSHOPT.load(Ordering::Relaxed) {
        clflushopt(addr);
    } else {
        clflush(addr);
    }
}

#[inline(always)]
pub fn mfence() {
    unsafe {
        asm!("mfence", options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn sfence() {
    unsafe {
        asm!("sfence", options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn lfence() {
    unsafe {
        asm!("lfence", options(nostack, preserves_flags));
    }
}
