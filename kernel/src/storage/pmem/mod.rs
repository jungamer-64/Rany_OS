//! Persistent memory helpers (`clwb` + `sfence`) and simple region allocator.

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

pub const CACHELINE_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmemError {
    NoRegion,
    InvalidRange,
    OutOfRange,
    OutOfSpace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmemRegion {
    pub base: usize,
    pub len: usize,
}

impl PmemRegion {
    #[inline]
    pub fn end(self) -> usize {
        self.base.saturating_add(self.len)
    }

    #[inline]
    pub fn contains_range(self, addr: usize, len: usize) -> bool {
        let end = match addr.checked_add(len) {
            Some(v) => v,
            None => return false,
        };
        addr >= self.base && end <= self.end()
    }
}

/// Monotonic allocator for a PMEM region.
pub struct PmemAllocator {
    region: PmemRegion,
    cursor: AtomicUsize,
}

impl PmemAllocator {
    pub fn new(region: PmemRegion) -> Self {
        Self {
            region,
            cursor: AtomicUsize::new(region.base),
        }
    }

    pub fn allocate(&self, size: usize, align: usize) -> Result<usize, PmemError> {
        if size == 0 {
            return Err(PmemError::InvalidRange);
        }
        let align = align.max(1);
        if !align.is_power_of_two() {
            return Err(PmemError::InvalidRange);
        }

        loop {
            let current = self.cursor.load(Ordering::Acquire);
            let aligned = (current + align - 1) & !(align - 1);
            let next = match aligned.checked_add(size) {
                Some(v) => v,
                None => return Err(PmemError::OutOfSpace),
            };
            if next > self.region.end() {
                return Err(PmemError::OutOfSpace);
            }
            if self
                .cursor
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(aligned);
            }
            core::hint::spin_loop();
        }
    }
}

static PMEM_REGION: RwLock<Option<PmemRegion>> = RwLock::new(None);
static PMEM_ALLOCATOR: Mutex<Option<PmemAllocator>> = Mutex::new(None);

/// Register PMEM region discovered by platform code.
pub fn register_region(base: *mut u8, len: usize) -> Result<(), PmemError> {
    if base.is_null() || len == 0 {
        return Err(PmemError::InvalidRange);
    }
    let region = PmemRegion {
        base: base as usize,
        len,
    };
    *PMEM_REGION.write() = Some(region);
    *PMEM_ALLOCATOR.lock() = Some(PmemAllocator::new(region));
    Ok(())
}

pub fn current_region() -> Option<PmemRegion> {
    *PMEM_REGION.read()
}

/// Allocate bytes from registered PMEM region.
pub fn allocate(size: usize, align: usize) -> Result<*mut u8, PmemError> {
    let guard = PMEM_ALLOCATOR.lock();
    let alloc = guard.as_ref().ok_or(PmemError::NoRegion)?;
    let addr = alloc.allocate(size, align)?;
    Ok(addr as *mut u8)
}

/// Persist a memory range in PMEM order:
/// `clwb` each cacheline, then `sfence`.
pub fn persist_range(ptr: *const u8, len: usize) -> Result<(), PmemError> {
    let region = current_region().ok_or(PmemError::NoRegion)?;
    if ptr.is_null() || len == 0 {
        return Err(PmemError::InvalidRange);
    }
    let addr = ptr as usize;
    if !region.contains_range(addr, len) {
        return Err(PmemError::OutOfRange);
    }
    flush_cachelines(addr, len);
    crate::io::dma::sfence();
    Ok(())
}

#[inline]
fn flush_cachelines(addr: usize, len: usize) {
    if !crate::io::dma::supports_clwb() {
        return;
    }
    let start = addr & !(CACHELINE_BYTES - 1);
    let end = addr.saturating_add(len);
    let mut p = start;
    while p < end {
        crate::io::dma::clwb(p as *const u8);
        p = p.saturating_add(CACHELINE_BYTES);
    }
}

/// Placeholder platform discovery hook.
///
/// The actual PMEM map should be wired from ACPI NFIT / firmware table parsing.
pub fn init_default_region() {}

