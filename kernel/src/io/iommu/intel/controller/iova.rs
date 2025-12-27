// ============================================================================
// kernel/src/io/iommu/intel/controller/iova.rs
// ============================================================================

//! IOVA (I/O Virtual Address) Management Methods
//!
//! This module contains IOVA allocation and management methods for `IommuController` via `IovaManager` trait.

use super::IommuController;
use crate::io::iommu::iova_allocator::{IovaAllocator, IovaGranularity};
use crate::io::iommu::types::IommuError;

pub trait IovaManager {
    fn init_iova(&self, base: u64, size: u64) -> Result<(), IommuError>;
    fn allocate_iova_fast(&self, size: u64) -> Result<u64, IommuError>;
    fn free_iova_fast(&self, iova: u64, size: u64) -> Result<(), IommuError>;
    fn allocate_iova(&self, size: u64) -> Result<u64, IommuError>;
    fn allocate_iova_aligned(
        &self,
        size: u64,
        granularity: IovaGranularity,
    ) -> Result<u64, IommuError>;
    fn free_iova(&self, addr: u64, size: u64) -> Result<(), IommuError>;
}

impl IovaManager for IommuController {
    /// Initialize controller IOVA allocator
    fn init_iova(&self, base: u64, size: u64) -> Result<(), IommuError> {
        let mut guard = self
            .iova_allocator
            .lock_for_init("[IOMMU] iova_allocator init");
        *guard = Some(IovaAllocator::new(base, size));
        Ok(())
    }

    /// Allocate I/O virtual address (Optimized with Per-Core Cache and Batch Refill)
    fn allocate_iova_fast(&self, size: u64) -> Result<u64, IommuError> {
        // 4KB以外はグローバルアロケータへ
        if size != 4096 {
            return self.allocate_iova(size);
        }

        let mut pc_ref = unsafe { crate::mm::per_cpu::current_per_cpu_mut() };

        // 1. Try Cache
        if let Some(ref mut pc) = pc_ref {
            if let Some(iova) = pc.iova_magazine.pop() {
                return Ok(iova);
            }
        }

        // Drop mutable borrow of per-cpu to allow method call
        // (Not strictly needed if NLL works, but safest)
        // pc_ref lifetime ends here effectively as we re-acquire later or don't use it.
        // Actually we need to re-acquire to push.

        // 2. Cache Miss - Batch Allocation
        // Allocate 32 pages (128KB) at once to amortize lock cost
        const BATCH_COUNT: u64 = 32;
        const BATCH_SIZE: u64 = BATCH_COUNT * 4096;

        // Try to allocate a contiguous batch from global allocator
        // If this fails (e.g. fragmentation), fallback to single page allocation
        let batch_start = match self.allocate_iova(BATCH_SIZE) {
            Ok(addr) => addr,
            Err(_) => return self.allocate_iova(size),
        };

        // We use the first page for the current request
        let result = batch_start;

        // 3. Fill Magazine with remaining pages
        // If we lost per-cpu access (unlikely), we free them back immediately.
        if let Some(pc) = unsafe { crate::mm::per_cpu::current_per_cpu_mut() } {
            for i in 1..BATCH_COUNT {
                let page = batch_start + i * 4096;
                if !pc.iova_magazine.push(page) {
                    // Magazine full (unlikely if we just popped empty, but possible if capacity is tiny)
                    // Free back to global
                    let _ = self.free_iova(page, 4096);
                }
            }
        } else {
            // Fallback: free the rest
            let _ = self.free_iova(batch_start + 4096, BATCH_SIZE - 4096);
        }

        Ok(result)
    }

    /// Free IOVA (Optimized with Per-Core Cache)
    fn free_iova_fast(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        if size != 4096 {
            return self.free_iova(iova, size);
        }

        if let Some(pc) = unsafe { crate::mm::per_cpu::current_per_cpu_mut() } {
            if pc.iova_magazine.push(iova) {
                return Ok(());
            }
        }

        // Cache overflow or no per-cpu - free globally
        self.free_iova(iova, size)
    }

    /// Allocate I/O virtual address range
    fn allocate_iova(&self, size: u64) -> Result<u64, IommuError> {
        // A poisoned allocator lock indicates an internal corruption of the
        // allocator state; fail with a HardwareError instead of attempting to
        // use possibly inconsistent internal structures.
        let mut guard = match self.iova_allocator.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!(
                    "[IOMMU] iova_allocator lock poisoned while allocating IOVA - hardware error"
                );
                return Err(IommuError::HardwareError);
            }
        };

        if let Some(alloc) = guard.as_mut() {
            alloc
                .allocate(size, IovaGranularity::Page4K)
                .ok_or(IommuError::OutOfMemory)
        } else {
            Err(IommuError::NotInitialized)
        }
    }

    /// Allocate an IOVA range with specific granularity (for super-pages)
    fn allocate_iova_aligned(
        &self,
        size: u64,
        granularity: IovaGranularity,
    ) -> Result<u64, IommuError> {
        let mut guard = self
            .iova_allocator
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let alloc = guard.as_mut().ok_or(IommuError::NotPresent)?;
        alloc
            .allocate(size, granularity)
            .ok_or(IommuError::HardwareError)
    }

    /// Free an IOVA range
    fn free_iova(&self, addr: u64, size: u64) -> Result<(), IommuError> {
        let mut guard = self
            .iova_allocator
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let alloc = guard.as_mut().ok_or(IommuError::NotPresent)?;
        alloc.free(addr, size)
    }
}
