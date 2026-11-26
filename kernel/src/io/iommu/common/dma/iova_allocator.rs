// ============================================================================
// kernel/src/io/iommu/common/dma/iova_allocator.rs - Device IOVA allocator
// ============================================================================

//! Device IOVA reservations. Published ranges retain their reservations in
//! the mapping owner until their translation invalidation completes.

#![deny(unsafe_code)]

use crate::io::iommu::types::IommuError;
pub use crate::mm::phys::fast_allocator::PageGranularity;
use crate::mm::phys::fast_allocator::{AddressPoolError, FastBitmapAllocator};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct IovaAllocator {
    inner: FastBitmapAllocator,
}

impl IovaAllocator {
    /// Create a new IOVA Allocator
    ///
    /// # Arguments
    /// * `base` - Base IOVA address (must be 4KB aligned)
    /// * `size` - Size of the IOVA space (bytes)
    pub fn new(base: u64, size: u64) -> Result<Self, IommuError> {
        // Initialize Inner Allocator
        let inner = FastBitmapAllocator::try_new(base, size).map_err(|error| match error {
            AddressPoolError::Alignment => IommuError::InvalidAlignment,
            AddressPoolError::InvalidRange => IommuError::InvalidAddress,
            AddressPoolError::MetadataAllocation => IommuError::OutOfMemory,
            AddressPoolError::Exhausted => IommuError::OutOfIova,
        })?;

        Ok(Self { inner })
    }

    /// Allocate a contiguous range
    #[inline]
    pub fn allocate_contiguous(&self, size: u64, align: u64) -> Option<u64> {
        self.inner.allocate_contiguous(size, align)
    }

    /// Get base address
    #[inline]
    pub fn base(&self) -> u64 {
        self.inner.base()
    }

    /// Get total size
    #[inline]
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    /// Reserve a range of addresses
    pub fn reserve(&self, start: u64, size: u64) -> Result<(), IommuError> {
        self.inner
            .reserve(start, size)
            .map_err(|_| IommuError::InvalidAddress)
    }

    /// Allocate with every byte at or below the inclusive DMA address limit.
    pub fn allocate_with_limit(
        &self,
        size: u64,
        granularity: PageGranularity,
        inclusive_limit: u64,
    ) -> Option<u64> {
        // The bitmap accepts an exclusive endpoint. Its validated pool endpoint
        // also bounds the result when the inclusive limit is u64::MAX.
        let exclusive_limit = inclusive_limit.saturating_add(1);
        self.inner
            .allocate_contiguous_below(
                size.max(granularity.size_bytes()),
                granularity.size_bytes(),
                exclusive_limit,
            )
            .ok()
    }

    /// Return an unpublished reservation or one whose translation has retired.
    pub fn free_immediate(&self, addr: u64, size: u64) -> Result<(), IommuError> {
        // Validate the entire extent before publishing any page for reuse. A
        // size-step loop could free a prefix and then fail on its invalid tail.
        self.inner
            .free_range_immediate(addr, size)
            .map_err(|error| match error {
                AddressPoolError::Alignment => IommuError::InvalidAlignment,
                _ => IommuError::InvalidAddress,
            })
    }
}
