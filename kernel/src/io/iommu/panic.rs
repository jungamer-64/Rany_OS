// ============================================================================
// kernel/src/io/iommu/panic.rs
// ============================================================================
//! Panic-safe DMA pool for emergency mappings.
//!
//! The pool is initialized during boot, mapping a contiguous physical region
//! into the global IOMMU domain. Allocations are lock-free and require no heap
//! access, making them safe to use during panic handling.

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Once;
use x86_64::PhysAddr;

use super::types::IommuError;

/// Default panic DMA pool size (bytes).
pub const PANIC_DMA_POOL_BYTES: usize = 256 * 1024;

const PANIC_DMA_ALIGN: u64 = crate::mm::types::PAGE_SIZE_4K as u64;
const PANIC_DMA_MAGIC: u32 = 0x5041_4E49;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PanicDmaRecordHeader {
    pub magic: u32,
    pub len: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct PanicDmaRecordInfo {
    pub iova: u64,
    pub phys: PhysAddr,
    pub len: usize,
    pub total: usize,
    pub virt: *mut u8,
}

struct PanicDmaPool {
    base_phys: u64,
    base_iova: u64,
    size: u64,
    virt_base: usize,
    cursor: AtomicU64,
}

/// An allocation carved from the panic DMA pool.
#[derive(Debug, Clone, Copy)]
pub struct PanicDmaRegion {
    pub iova: u64,
    pub phys: PhysAddr,
    pub size: usize,
    pub virt: *mut u8,
}

// SAFETY: PanicDmaRegion points to static panic DMA pool memory that is
// valid for the entire lifetime of the kernel. The pool is allocated once
// during boot and never deallocated. All fields are trivially copyable.
unsafe impl Send for PanicDmaRegion {}
unsafe impl Sync for PanicDmaRegion {}

static PANIC_DMA_POOL: Once<PanicDmaPool> = Once::new();
static LAST_PANIC_DMA_PHYS: AtomicU64 = AtomicU64::new(0);
static LAST_PANIC_DMA_IOVA: AtomicU64 = AtomicU64::new(0);
static LAST_PANIC_DMA_LEN: AtomicU64 = AtomicU64::new(0);
static LAST_PANIC_DMA_SIZE: AtomicU64 = AtomicU64::new(0);
static LAST_PANIC_DMA_VIRT: AtomicU64 = AtomicU64::new(0);

use crate::util::align_up_u64 as align_up;

/// Initialize the panic DMA pool.
///
/// Must be called after the IOMMU backend is initialized and enabled.
pub fn init_panic_dma_pool(bytes: usize) -> Result<(), IommuError> {
    if PANIC_DMA_POOL.get().is_some() {
        return Err(IommuError::AlreadyInitialized);
    }

    if bytes == 0 {
        return Err(IommuError::InvalidAlignment);
    }

    let size = align_up(bytes as u64, PANIC_DMA_ALIGN);
    let frames = (size / PANIC_DMA_ALIGN) as usize;

    let phys = crate::mm::phys::frame_allocator::alloc_contiguous_frames(frames).ok_or(IommuError::OutOfMemory)?;
    let phys_addr = PhysAddr::new(phys.as_u64());
    let iova = match unsafe { super::api::map_for_dma(phys_addr, size) } {
        Ok(iova) => iova,
        Err(err) => {
            crate::mm::phys::frame_allocator::dealloc_contiguous_frames(phys, frames);
            return Err(err);
        }
    };

    let virt_base = crate::mm::virt::mapping::phys_to_virt(phys_addr).as_u64() as usize;
    unsafe {
        core::ptr::write_bytes(virt_base as *mut u8, 0, size as usize);
    }

    let pool = PanicDmaPool {
        base_phys: phys_addr.as_u64(),
        base_iova: iova,
        size,
        virt_base,
        cursor: AtomicU64::new(0),
    };

    PANIC_DMA_POOL.call_once(|| pool);
    Ok(())
}

/// Initialize the panic DMA pool with the default size.
///
/// The initial allocation may fail if no sufficiently large contiguous region is
/// available. In that case we retry with progressively smaller sizes (divide by
/// four) down to one page.  This makes boot more robust on fragmented memory
/// layouts.
pub fn init_panic_dma_pool_default() -> Result<(), IommuError> {
    let mut size = PANIC_DMA_POOL_BYTES;
    while size >= crate::mm::types::PAGE_SIZE_4K {
        match init_panic_dma_pool(size) {
            Ok(()) => return Ok(()),
            Err(IommuError::OutOfMemory) => {
                size /= 4;
            }
            Err(e) => return Err(e),
        }
    }
    Err(IommuError::OutOfMemory)
}

/// Allocate from the panic DMA pool without locks or heap allocation.
pub fn panic_alloc_dma(bytes: usize) -> Option<PanicDmaRegion> {
    let pool = PANIC_DMA_POOL.get()?;
    if bytes == 0 {
        return None;
    }

    let size = align_up(bytes as u64, PANIC_DMA_ALIGN);
    if size > pool.size {
        return None;
    }
    let offset = loop {
        let cursor = pool.cursor.load(Ordering::Acquire);
        let offset = cursor % pool.size;
        let next = if offset + size > pool.size {
            cursor
                .wrapping_add(pool.size - offset)
                .wrapping_add(size)
        } else {
            cursor.wrapping_add(size)
        };
        if pool
            .cursor
            .compare_exchange(cursor, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break if offset + size > pool.size { 0 } else { offset };
        }
    };

    let phys = pool.base_phys + offset;
    let iova = pool.base_iova + offset;
    let virt = (pool.virt_base as u64 + offset) as *mut u8;

    Some(PanicDmaRegion {
        iova,
        phys: PhysAddr::new(phys),
        size: size as usize,
        virt,
    })
}

/// Write a panic record into the DMA pool and return the record info.
pub fn write_panic_record(message: &str) -> Option<PanicDmaRecordInfo> {
    let region = panic_alloc_dma(4096)?;
    let header_size = core::mem::size_of::<PanicDmaRecordHeader>();
    let payload = message.as_bytes();
    let max_len = region.size.saturating_sub(header_size);
    let copy_len = payload.len().min(max_len);

    unsafe {
        let header_ptr = region.virt as *mut PanicDmaRecordHeader;
        core::ptr::write(
            header_ptr,
            PanicDmaRecordHeader {
                magic: PANIC_DMA_MAGIC,
                len: copy_len as u32,
            },
        );
        core::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            (region.virt as *mut u8).add(header_size),
            copy_len,
        );
    }

    LAST_PANIC_DMA_PHYS.store(region.phys.as_u64(), Ordering::Release);
    LAST_PANIC_DMA_IOVA.store(region.iova, Ordering::Release);
    LAST_PANIC_DMA_LEN.store(copy_len as u64, Ordering::Release);
    LAST_PANIC_DMA_SIZE.store(region.size as u64, Ordering::Release);
    LAST_PANIC_DMA_VIRT.store(region.virt as u64, Ordering::Release);

    Some(PanicDmaRecordInfo {
        iova: region.iova,
        phys: region.phys,
        len: copy_len,
        total: region.size,
        virt: region.virt,
    })
}

/// Get the last panic DMA record, if available.
pub fn last_panic_record() -> Option<PanicDmaRecordInfo> {
    let phys = LAST_PANIC_DMA_PHYS.load(Ordering::Acquire);
    if phys == 0 {
        return None;
    }

    Some(PanicDmaRecordInfo {
        iova: LAST_PANIC_DMA_IOVA.load(Ordering::Acquire),
        phys: PhysAddr::new(phys),
        len: LAST_PANIC_DMA_LEN.load(Ordering::Acquire) as usize,
        total: LAST_PANIC_DMA_SIZE.load(Ordering::Acquire) as usize,
        virt: LAST_PANIC_DMA_VIRT.load(Ordering::Acquire) as *mut u8,
    })
}

/// Return the last panic record message, if present.
pub fn last_panic_record_message() -> Option<&'static str> {
    let info = last_panic_record()?;
    // SAFETY: The panic DMA pool is static and the record header is immutable.
    unsafe { read_panic_record_message(&info) }
}

/// Read the panic record payload as a UTF-8 string.
///
/// # Safety
///
/// The caller must ensure the record memory remains valid and immutable.
pub unsafe fn read_panic_record_message(info: &PanicDmaRecordInfo) -> Option<&'static str> { unsafe {
    if info.total < core::mem::size_of::<PanicDmaRecordHeader>() {
        return None;
    }

    let header_ptr = info.virt as *const PanicDmaRecordHeader;
    let header = core::ptr::read(header_ptr);
    if header.magic != PANIC_DMA_MAGIC {
        return None;
    }

    let len = (header.len as usize).min(info.total - core::mem::size_of::<PanicDmaRecordHeader>());
    let payload_ptr = (info.virt as *const u8).add(core::mem::size_of::<PanicDmaRecordHeader>());
    let payload = core::slice::from_raw_parts(payload_ptr, len);
    core::str::from_utf8(payload).ok()
}}

/// Check whether the panic DMA pool is initialized.
pub fn panic_dma_pool_ready() -> bool {
    PANIC_DMA_POOL.get().is_some()
}
