//! AHCI DMA safe buffer implementation
//!
//! Provides type-safe buffers for DMA transfers using kernel_api.

// use x86_64::PhysAddr; // Not used from x86_64 but we use u64 from api
// use core::slice;
use kernel_api::services::kernel;
use kernel_api::DmaBuffer;
// use kernel_api::types::DmaBuffer as KapiDmaBuffer;
use x86_64::PhysAddr; // For type conversions if needed

use super::types::SECTOR_SIZE;

/// DMA-safe buffer for sector reading
pub struct AhciDmaReadBuffer {
    buffer: DmaBuffer,
    sector_count: usize,
}

impl AhciDmaReadBuffer {
    /// Create buffer for specified number of sectors
    pub fn new(sector_count: usize) -> Option<Self> {
        let size = sector_count * SECTOR_SIZE;
        let buffer = kernel().alloc_dma(size).ok()?;

        Some(Self {
            buffer,
            sector_count,
        })
    }

    /// Get physical address
    pub fn phys_addr(&self) -> Option<PhysAddr> {
        Some(PhysAddr::new(self.buffer.physical_address()))
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
        unsafe { self.buffer.as_slice() }
    }

    /// Buffer size
    pub fn size(&self) -> usize {
        self.sector_count * SECTOR_SIZE
    }
}

/// DMA-safe buffer for sector writing
pub struct AhciDmaWriteBuffer {
    buffer: DmaBuffer,
    sector_count: usize,
}

impl AhciDmaWriteBuffer {
    /// Create buffer with initial data
    pub fn with_data(data: &[u8]) -> Option<Self> {
        let sector_count = (data.len() + SECTOR_SIZE - 1) / SECTOR_SIZE;
        let size = sector_count * SECTOR_SIZE;

        let mut buffer = kernel().alloc_dma(size).ok()?;
        
        unsafe { buffer.as_slice_mut()[..data.len()].copy_from_slice(data) };

        Some(Self {
            buffer,
            sector_count,
        })
    }

    /// Get physical address
    pub fn phys_addr(&self) -> Option<PhysAddr> {
        Some(PhysAddr::new(self.buffer.physical_address()))
    }

    /// Prepare transfer
    pub fn prepare_transfer(&self) {
    }

    /// Finish transfer
    pub fn finish_transfer(&self) {
    }
}

/// Helper for IDENTIFY command buffer
pub struct AhciIdentifyBuffer {
    buffer: DmaBuffer,
}

impl AhciIdentifyBuffer {
    /// Create 512-byte buffer
    pub fn new() -> Option<Self> {
        let buffer = kernel().alloc_dma(512).ok()?;
        Some(Self { buffer })
    }

    pub fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.buffer.physical_address())
    }

    pub fn finish_and_get_words(&self) -> [u16; 256] {
        let mut words = [0u16; 256];
        let slice = unsafe { self.buffer.as_slice() };
        for (i, word) in words.iter_mut().enumerate() {
            let idx = i * 2;
            if idx + 1 < slice.len() {
                *word = u16::from_le_bytes([slice[idx], slice[idx + 1]]);
            }
        }
        words
    }
}

impl Default for AhciIdentifyBuffer {
    fn default() -> Self {
        Self::new().expect("Failed to allocate AHCI identify buffer")
    }
}
