#![allow(dead_code)]
//! Persistent memory helpers (`clwb` + `sfence`) and simple region allocator.

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, RwLock};
use x86_64::PhysAddr;

pub const CACHELINE_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmemError {
    NoRegion,
    InvalidRange,
    OutOfRange,
    OutOfSpace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmemDiscoveryError {
    TableNotFound,
    InvalidTable,
    RegisterFailed(PmemError),
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

trait PersistOps {
    fn flush_range(&mut self, addr: usize, len: usize);
    fn fence(&mut self);
}

struct HardwarePersistOps;

impl PersistOps for HardwarePersistOps {
    fn flush_range(&mut self, addr: usize, len: usize) {
        flush_cachelines(addr, len);
    }

    fn fence(&mut self) {
        crate::io::dma::sfence();
    }
}

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
    let mut ops = HardwarePersistOps;
    persist_range_with_ops(ptr, len, &mut ops)
}

fn persist_range_with_ops<O: PersistOps + ?Sized>(
    ptr: *const u8,
    len: usize,
    ops: &mut O,
) -> Result<(), PmemError> {
    let region = current_region().ok_or(PmemError::NoRegion)?;
    if ptr.is_null() || len == 0 {
        return Err(PmemError::InvalidRange);
    }
    let addr = ptr as usize;
    if !region.contains_range(addr, len) {
        return Err(PmemError::OutOfRange);
    }
    ops.flush_range(addr, len);
    ops.fence();
    Ok(())
}

/// Persist log first, then data payload with ordering fences.
pub fn persist_ordered(
    log_ptr: *const u8,
    log_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> Result<(), PmemError> {
    let mut ops = HardwarePersistOps;
    persist_ordered_with_ops(log_ptr, log_len, data_ptr, data_len, &mut ops)
}

fn persist_ordered_with_ops<O: PersistOps + ?Sized>(
    log_ptr: *const u8,
    log_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    ops: &mut O,
) -> Result<(), PmemError> {
    persist_range_with_ops(log_ptr, log_len, ops)?;
    persist_range_with_ops(data_ptr, data_len, ops)?;
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

#[inline]
fn read_u16(ptr: usize) -> u16 {
    u16::from_le_bytes([
        unsafe { core::ptr::read_unaligned(ptr as *const u8) },
        unsafe { core::ptr::read_unaligned((ptr + 1) as *const u8) },
    ])
}

#[inline]
fn read_u64(ptr: usize) -> u64 {
    let mut b = [0u8; 8];
    let mut i = 0usize;
    while i < 8 {
        b[i] = unsafe { core::ptr::read_unaligned((ptr + i) as *const u8) };
        i += 1;
    }
    u64::from_le_bytes(b)
}

/// Discover PMEM region from ACPI NFIT SPA range entries.
///
/// Returns `Ok(None)` when NFIT is absent or no suitable SPA range is found.
pub fn init_from_nfit() -> Result<Option<PmemRegion>, PmemDiscoveryError> {
    let nfit_addr = match crate::io::acpi::find_table_global(&crate::io::acpi::signature::NFIT) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let header = unsafe { &*(nfit_addr as *const crate::io::acpi::AcpiSdtHeader) };
    if !header.validate() {
        return Err(PmemDiscoveryError::InvalidTable);
    }

    let table_len = header.length as usize;
    let mut offset = nfit_addr + core::mem::size_of::<crate::io::acpi::AcpiSdtHeader>();
    let end = nfit_addr + table_len;

    while offset + 4 <= end {
        let ty = read_u16(offset);
        let len = read_u16(offset + 2) as usize;
        if len < 4 || offset + len > end {
            break;
        }

        // NFIT SPA Range Structure (Type 0), minimum 56 bytes.
        if ty == 0 && len >= 56 {
            let spa_base = read_u64(offset + 32);
            let spa_len = read_u64(offset + 40);
            if spa_base != 0 && spa_len != 0 {
                let virt = crate::memory::phys_to_virt(PhysAddr::new(spa_base));
                register_region(virt.as_u64() as *mut u8, spa_len as usize)
                    .map_err(PmemDiscoveryError::RegisterFailed)?;
                return Ok(current_region());
            }
        }

        offset += len;
    }

    Ok(None)
}

/// Default platform discovery hook: attempt NFIT discovery and fail-open.
pub fn init_default_region() {
    let _ = init_from_nfit();
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const TEST_REGION_LEN: usize = 4096;
    static mut TEST_REGION: [u8; TEST_REGION_LEN] = [0; TEST_REGION_LEN];

    fn setup_region() -> PmemRegion {
        let base_ptr = core::ptr::addr_of_mut!(TEST_REGION).cast::<u8>();
        register_region(base_ptr, TEST_REGION_LEN).expect("register test region");
        current_region().expect("region should be available")
    }

    #[derive(Default)]
    struct TraceOps {
        events: Vec<&'static str>,
    }

    impl PersistOps for TraceOps {
        fn flush_range(&mut self, _addr: usize, _len: usize) {
            self.events.push("flush");
        }

        fn fence(&mut self) {
            self.events.push("fence");
        }
    }

    #[test_case]
    fn register_region_and_lookup() {
        let region = setup_region();
        assert_eq!(region.len, TEST_REGION_LEN);
        assert!(region.base != 0);
    }

    #[test_case]
    fn persist_range_rejects_out_of_range() {
        let region = setup_region();
        let ptr = (region.end() - 8) as *const u8;
        let err = persist_range(ptr, 16).expect_err("range should exceed region");
        assert_eq!(err, PmemError::OutOfRange);
    }

    #[test_case]
    fn persist_ordered_preserves_flush_fence_sequence() {
        let region = setup_region();
        let log_ptr = region.base as *const u8;
        let data_ptr = (region.base + 128) as *const u8;
        let mut trace = TraceOps::default();

        persist_ordered_with_ops(log_ptr, 64, data_ptr, 64, &mut trace)
            .expect("ordered persist should succeed");
        assert_eq!(
            trace.events,
            alloc::vec!["flush", "fence", "flush", "fence"]
        );
    }
}
