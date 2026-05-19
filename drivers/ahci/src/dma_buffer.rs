//! AHCI DMA safe buffer implementation
//!
//! Provides type-safe buffers for DMA transfers using kernel_api.

// use x86_64::PhysAddr; // Not used from x86_64 but we use u64 from api
// use core::slice;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::service::kernel::instance as kernel;
use x86_64::PhysAddr; // For type conversions if needed

use super::types::SECTOR_SIZE;

type DmaBuffer = DmaSlice<CpuOwned>;

/// DMA-safe buffer for sector reading
pub struct AhciDmaReadBuffer {
    buffer: DmaBuffer,
    sector_count: usize,
}

impl AhciDmaReadBuffer {
    /// Create buffer for specified number of sectors
    pub fn new(sector_count: usize, device_id: PackedPciLocation) -> Option<Self> {
        let size = sector_count * SECTOR_SIZE;
        let buffer = kernel().alloc_dma_for_device(size, device_id).ok()?;

        Some(Self {
            buffer,
            sector_count,
        })
    }

    /// Get device-visible address (IOVA)
    pub fn device_addr(&self) -> Option<PhysAddr> {
        Some(PhysAddr::new_truncate(self.buffer.device_address()))
    }

    /// Prepare for DMA transfer (invalidate cache if needed)
    pub fn prepare_transfer(&self) {
        // x86 is coherent
    }

    /// Finish transfer (flush cache if needed)
    pub fn finish_transfer(&self) {
        // x86 is coherent
    }

    /// Access data slice
    pub fn data(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    /// Buffer size
    pub fn size(&self) -> usize {
        self.sector_count * SECTOR_SIZE
    }
}

/// DMA-safe buffer for sector writing
pub struct AhciDmaWriteBuffer {
    buffer: DmaBuffer,
}

impl AhciDmaWriteBuffer {
    /// Create buffer with initial data
    pub fn with_data(data: &[u8], device_id: PackedPciLocation) -> Option<Self> {
        let sector_count = (data.len() + SECTOR_SIZE - 1) / SECTOR_SIZE;
        let size = sector_count * SECTOR_SIZE;

        let mut buffer = kernel().alloc_dma_for_device(size, device_id).ok()?;

        buffer.as_slice_mut()[..data.len()].copy_from_slice(data);

        Some(Self { buffer })
    }

    /// Get device-visible address (IOVA)
    pub fn device_addr(&self) -> Option<PhysAddr> {
        Some(PhysAddr::new_truncate(self.buffer.device_address()))
    }

    /// Prepare transfer
    pub fn prepare_transfer(&self) {}

    /// Finish transfer
    pub fn finish_transfer(&self) {}
}

/// Helper for IDENTIFY command buffer
pub struct AhciIdentifyBuffer {
    buffer: DmaBuffer,
}

impl AhciIdentifyBuffer {
    /// Create 512-byte buffer
    pub fn new(device_id: PackedPciLocation) -> Option<Self> {
        let buffer = kernel().alloc_dma_for_device(512, device_id).ok()?;
        Some(Self { buffer })
    }

    pub fn device_addr(&self) -> PhysAddr {
        PhysAddr::new_truncate(self.buffer.device_address())
    }

    pub fn finish_and_get_words(&self) -> [u16; 256] {
        let mut words = [0u16; 256];
        let slice = self.buffer.as_slice();
        for (i, word) in words.iter_mut().enumerate() {
            let idx = i * 2;
            if idx + 1 < slice.len() {
                *word = u16::from_le_bytes([slice[idx], slice[idx + 1]]);
            }
        }
        words
    }
}
