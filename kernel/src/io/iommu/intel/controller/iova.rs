// ============================================================================
// kernel/src/io/iommu/intel/controller/iova.rs
// ============================================================================

//! IOVA (I/O Virtual Address) Management Methods
//!
//! This module contains IOVA allocation and management methods for `IommuController` via `IovaManager` trait.
//!
//! The underlying `IovaAllocatorFast` is a lock-free bitmap-based allocator with
//! per-CPU magazine caching, providing O(1) allocation/free for 4KB/2MB/1GB pages.

use super::IommuController;
use crate::io::iommu::{IovaAllocatorFast, IovaGranularity};
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
        granularity: IovaGranularity,
    ) -> Result<u64, IommuError>;
    fn free_iova(&self, addr: u64, size: u64) -> Result<(), IommuError>;
    fn reserve_iova(&self, addr: u64, size: u64) -> Result<(), IommuError>;
}

impl IovaManager for IommuController {
    /// Initialize controller IOVA allocator
    fn init_iova(&self, base: u64, size: u64) -> Result<(), IommuError> {
        let cpu_id = crate::mm::per_cpu::try_current_cpu_id().unwrap_or(usize::MAX);
        crate::io::log::early_print("[IOMMU] init_iova: enter cpu=");
        crate::io::log::early_print_dec(cpu_id as u64);
        crate::io::log::early_print(" base=");
        crate::io::log::early_print_hex(base);
        crate::io::log::early_print(" size=");
        crate::io::log::early_print_hex(size);
        crate::io::log::early_print("\n");

        // Print heap state for diagnostics
        if let Some(initialized) = crate::memory::ALLOCATOR.is_initialized() {
            crate::io::log::early_print("[IOMMU] heap_initialized=");
            crate::io::log::early_print_dec(if initialized { 1 } else { 0 });
            crate::io::log::early_print("\n");
        } else {
            crate::io::log::early_print("[IOMMU] ALLOCATOR lock poisoned\n");
        }

        let mut guard = self
            .iova_allocator
            .lock_for_init("[IOMMU] iova_allocator init");
        *guard = Some(IovaAllocatorFast::new(base, size));
        crate::io::log::early_print("[IOMMU] init_iova: IovaAllocator initialized\n");
        Ok(())
    }

    /// Allocate I/O virtual address (Fast path with per-CPU magazine)
    ///
    /// IovaAllocatorFast already provides O(1) allocation with per-CPU magazine,
    /// so this delegates directly.
    fn allocate_iova_fast(&self, size: u64) -> Result<u64, IommuError> {
        self.allocate_iova(size)
    }

    /// Free IOVA (Fast path with per-CPU magazine)
    ///
    /// IovaAllocatorFast already provides O(1) free with per-CPU magazine,
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
        let cpu_id = crate::mm::per_cpu::try_current_cpu_id().unwrap_or(usize::MAX);
        crate::io::log::early_print("[IOMMU] allocate_iova_masked: enter cpu=");
        crate::io::log::early_print_dec(cpu_id as u64);
        crate::io::log::early_print(" size=");
        crate::io::log::early_print_dec(size as u64);
        crate::io::log::early_print(" mask=");
        crate::io::log::early_print_hex(mask as u64);
        crate::io::log::early_print("\n");

        let guard = self
            .iova_allocator
            .lock()
            .map_err(|_| IommuError::HardwareError)?;

        if guard.is_none() {
            crate::io::log::early_print("[IOMMU] allocate_iova_masked: iova_allocator not initialized\n");
            return Err(IommuError::NotPresent);
        }

        let alloc = guard.as_ref().ok_or(IommuError::NotPresent)?;

        crate::io::log::early_print("[IOMMU] allocate_iova_masked: calling allocate_with_limit\n");
        let res = alloc.allocate_with_limit(size, IovaGranularity::Page4K, mask);
        if res.is_none() {
            crate::io::log::early_print("[IOMMU] allocate_iova_masked: allocation returned None (OOM)\n");
            // Print heap diagnostic snapshot
            if let Some(initialized) = crate::memory::ALLOCATOR.is_initialized() {
                crate::io::log::early_print("[IOMMU] heap_initialized=");
                crate::io::log::early_print_dec(if initialized { 1 } else { 0 });
                crate::io::log::early_print("\n");
            } else {
                crate::io::log::early_print("[IOMMU] ALLOCATOR lock poisoned\n");
            }
        }

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
