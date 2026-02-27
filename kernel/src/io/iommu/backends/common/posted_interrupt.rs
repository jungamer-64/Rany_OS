// ============================================================================
// kernel/src/io/iommu/backends/common/posted_interrupt.rs
// ============================================================================

//! Posted Interrupt structures and operations

use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use crate::mm::phys::frame_allocator::{alloc_contiguous_frames, dealloc_contiguous_frames};
use crate::io::iommu::core::tables::{phys_to_virt_usize, virt_ptr_to_phys};

// ============================================================================
// Posted Interrupt Descriptor (PID)
// ============================================================================

/// Posted Interrupt Descriptor (PID)
///
/// 64-byte aligned structure used for Posted Interrupt processing.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct PostedInterruptDescriptor {
    /// Posted Interrupt Request (PIR) - bitmap of 256 vectors
    pub pir: [u64; 4],
    /// Notification Info
    /// - Bit 0: ON (Outstanding Notification)
    /// - Bit 1: SN (Suppress Notification)
    /// - Bits 16-23: NV (Notification Vector)
    /// - Bits 32-63: NDST (Notification Destination APIC ID)
    pub notification_info: AtomicU64,
    /// Reserved
    pub reserved: [u64; 3],
}

impl PostedInterruptDescriptor {
    pub const ON: u64 = 1 << 0;
    pub const SN: u64 = 1 << 1;

    /// Create a new zeroed PID
    pub fn new() -> Self {
        Self {
            pir: [0; 4],
            notification_info: AtomicU64::new(0),
            reserved: [0; 3],
        }
    }
}

impl Default for PostedInterruptDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

/// Posted Interrupt Descriptor Pool
///
/// Manages allocation of Posted Interrupt Descriptors (PIDs).
/// Each PID is 64-byte aligned for hardware requirements.
pub struct PostedInterruptPool {
    /// Base physical address of the pool (64-byte aligned)
    base: usize,
    /// Number of PIDs in the pool
    size: usize,
    /// Allocation bitmap (1 = allocated, 0 = free)
    allocated: Vec<u64>,
}

impl PostedInterruptPool {
    /// Maximum number of PIDs supported
    pub const MAX_PIDS: usize = 256;

    /// Create a new PID pool
    pub fn new(num_pids: usize) -> Option<Self> {
        let size = num_pids.min(Self::MAX_PIDS);
        // Each PID is 64 bytes
        let total_bytes = size * core::mem::size_of::<PostedInterruptDescriptor>();
        let num_pages = (total_bytes + 4095) / 4096;

        // Allocate contiguous physical frames for hardware requirements
        let phys = alloc_contiguous_frames(num_pages)?
            .as_u64();
        let base = phys_to_virt_usize(phys);

        // Security: Mark the range as protected from DMA
        crate::security::dma::register_protected_range(phys, total_bytes as u64);

        // Bitmap: 64 PIDs per u64
        let bitmap_size = (size + 63) / 64;
        let allocated = alloc::vec![0u64; bitmap_size];

        Some(Self {
            base,
            size,
            allocated,
        })
    }

    /// Allocate a PID, returning its index and physical address
    pub fn allocate(&mut self) -> Option<(u16, u64)> {
        for (word_idx, word) in self.allocated.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros() as usize;
                let index = word_idx * 64 + bit;
                if index >= self.size {
                    return None;
                }
                *word |= 1 << bit;
                let addr = self.base + index * core::mem::size_of::<PostedInterruptDescriptor>();
                return Some((index as u16, addr as u64));
            }
        }
        None
    }

    /// Free a PID by index
    pub fn free(&mut self, index: u16) {
        let word_idx = index as usize / 64;
        let bit = index as usize % 64;
        if word_idx < self.allocated.len() {
            self.allocated[word_idx] &= !(1 << bit);
        }
    }

    /// Get a mutable reference to a PID by index
    pub fn get_mut(&mut self, index: u16) -> Option<&mut PostedInterruptDescriptor> {
        if (index as usize) < self.size {
            let ptr = self.base as *mut PostedInterruptDescriptor;
            Some(unsafe { &mut *ptr.add(index as usize) })
        } else {
            None
        }
    }

    /// Get the physical address of a PID
    pub fn get_address(&self, index: u16) -> Option<u64> {
        if (index as usize) < self.size {
            Some(
                (self.base + (index as usize) * core::mem::size_of::<PostedInterruptDescriptor>())
                    as u64,
            )
        } else {
            None
        }
    }
}

impl Drop for PostedInterruptPool {
    fn drop(&mut self) {
        let total_bytes = self.size * core::mem::size_of::<PostedInterruptDescriptor>();
        let num_pages = (total_bytes + 4095) / 4096;
        if let Ok(phys) = virt_ptr_to_phys(self.base as *const u8) {
            crate::security::dma::unregister_protected_range(phys, total_bytes as u64);
            
            // Free the contiguous region
            dealloc_contiguous_frames(x86_64::PhysAddr::new(phys), num_pages);
        }
    }
}
