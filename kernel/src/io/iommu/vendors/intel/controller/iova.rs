// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/iova.rs
// ============================================================================

//! IOVA (I/O Virtual Address) Management Methods
//!
//! This module contains IOVA allocation and management methods for `IommuController` via `IovaManager` trait.
//!
//! The underlying `IovaAllocator` is a lock-free bitmap-based allocator with
//! per-CPU magazine caching, providing O(1) allocation/free for 4KB/2MB/1GB pages.

use super::IommuController;
use crate::io::iommu::common::dma::iova_allocator::{IovaAllocator, PageGranularity};
use crate::io::iommu::types::IommuError;

pub trait IovaManager {
    fn init_iova(&self, base: u64, size: u64) -> Result<(), IommuError>;
    fn allocate_iova_fast(&self, size: u64) -> Result<u64, IommuError>;
    fn free_iova_fast(&self, iova: u64, size: u64) -> Result<(), IommuError>;
    fn allocate_iova(&self, size: u64) -> Result<u64, IommuError>;
    fn allocate_iova_masked(&self, size: u64, mask: u64) -> Result<u64, IommuError>;
    fn allocate_iova_aligned(
        &self,
        size: u64,
        granularity: PageGranularity,
    ) -> Result<u64, IommuError>;
    fn free_iova(&self, addr: u64, size: u64) -> Result<(), IommuError>;
    fn reserve_iova(&self, addr: u64, size: u64) -> Result<(), IommuError>;
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

    /// Allocate I/O virtual address (Fast path with per-CPU magazine)
    ///
    /// IovaAllocator already provides O(1) allocation with per-CPU magazine,
    /// so this delegates directly.
    fn allocate_iova_fast(&self, size: u64) -> Result<u64, IommuError> {
        self.allocate_iova(size)
    }

    /// Free IOVA (Fast path with per-CPU magazine)
    ///
    /// IovaAllocator already provides O(1) free with per-CPU magazine,
    /// so this delegates directly.
    fn free_iova_fast(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.free_iova(iova, size)
    }

    /// Allocate I/O virtual address range
    fn allocate_iova(&self, size: u64) -> Result<u64, IommuError> {
        let guard = match self.iova_allocator.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!(
                    "[IOMMU] iova_allocator lock poisoned while allocating IOVA - hardware error"
                );
                return Err(IommuError::HardwareError);
            }
        };

        if let Some(alloc) = guard.as_ref() {
            if size <= 4096 {
                alloc
                    .allocate(size, PageGranularity::Page4K)
                    .ok_or(IommuError::OutOfMemory)
            } else {
                // allocate() requires size == granularity.size_bytes(), so for
                // multi-page allocations use contiguous allocator with 4KB alignment
                let aligned = (size + 4095) & !4095;
                alloc
                    .allocate_contiguous(aligned, 4096)
                    .ok_or(IommuError::OutOfMemory)
            }
        } else {
            Err(IommuError::NotInitialized)
        }
    }

    /// Allocate an IOVA range with specific granularity (for super-pages)
    fn allocate_iova_aligned(
        &self,
        size: u64,
        granularity: PageGranularity,
    ) -> Result<u64, IommuError> {
        let guard = self
            .iova_allocator
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let alloc = guard.as_ref().ok_or(IommuError::NotPresent)?;
        alloc
            .allocate(size, granularity)
            .ok_or(IommuError::HardwareError)
    }

    /// Allocate an IOVA range within a DMA mask limit (inclusive).
    fn allocate_iova_masked(&self, size: u64, mask: u64) -> Result<u64, IommuError> {
        let guard = self
            .iova_allocator
            .lock()
            .map_err(|_| IommuError::HardwareError)?;

        let alloc = guard.as_ref().ok_or(IommuError::NotPresent)?;

        let res = alloc.allocate_with_limit(size, PageGranularity::Page4K, mask);

        res.ok_or(IommuError::OutOfMemory)
    }

    /// Free an IOVA range
    fn free_iova(&self, addr: u64, size: u64) -> Result<(), IommuError> {
        let guard = self
            .iova_allocator
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let alloc = guard.as_ref().ok_or(IommuError::NotPresent)?;
        alloc.free(addr, size)
    }

    /// Reserve an IOVA range (identity or fixed mapping).
    fn reserve_iova(&self, addr: u64, size: u64) -> Result<(), IommuError> {
        let guard = self
            .iova_allocator
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let alloc = guard.as_ref().ok_or(IommuError::NotPresent)?;
        alloc.reserve(addr, size)
    }
}
