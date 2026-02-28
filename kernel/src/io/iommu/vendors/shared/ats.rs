// ============================================================================
// kernel/src/io/iommu/vendors/common/ats.rs
// ============================================================================

//! IOMMU ATS (Address Translation Services) and PRI (Page Request Interface)
//!
//! This module contains structures for
//! Page Request handling, which are part of the ATS/PRI extensions.

use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

// Convenience wrappers for contiguous frame allocation
use crate::mm::phys::frame_allocator::{alloc_contiguous_frames, dealloc_contiguous_frames};



// ============================================================================
// Page Request Interface (PRI) Structures
// ============================================================================

/// Page Request Queue Entry
///
/// 16-byte entry in the Page Request Queue.
/// Devices use this to request page translations during ATS faults.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct PageRequestEntry {
    /// Low 64 bits
    /// - Bits 0-15: Source ID (Requester ID)
    /// - Bits 16-31: Reserved
    /// - Bits 52-55: Request Type
    /// - Bit 56: PASID Present
    /// - Bit 57: Execute Requested
    /// - Bit 58: Privileged Mode Requested
    /// - Bit 59: Last Request in Group
    /// - Bits 60-63: Reserved
    pub lo: u64,
    /// High 64 bits
    /// - Bits 0-51: Page Address (4KB aligned)
    /// - Bits 52-71: PASID (if present)
    /// - Bits 72-80: PRG Index (Page Request Group Index)
    pub hi: u64,
}

impl PageRequestEntry {
    /// Last Request in Group
    pub const LAST_REQ: u64 = 1 << 59;
    /// Execute Requested
    pub const EXEC_REQ: u64 = 1 << 57;
    /// Privileged Mode Requested
    pub const PRIV_REQ: u64 = 1 << 58;
    /// PASID Present
    pub const PASID_PRESENT: u64 = 1 << 56;

    /// Get the source ID (Requester ID)
    pub fn source_id(&self) -> u16 {
        (self.lo & 0xFFFF) as u16
    }

    /// Get the page address (4KB aligned)
    pub fn page_address(&self) -> u64 {
        self.hi & 0x000F_FFFF_FFFF_F000
    }

    /// Get the PASID (if present)
    pub fn pasid(&self) -> Option<u32> {
        if (self.lo & Self::PASID_PRESENT) != 0 {
            Some(((self.hi >> 52) & 0xFFFFF) as u32)
        } else {
            None
        }
    }

    /// Check if this is the last request in a group
    pub fn is_last(&self) -> bool {
        (self.lo & Self::LAST_REQ) != 0
    }
}

/// Page Request Queue
///
/// Ring buffer queue for page request entries.
/// Hardware writes requests at the tail, software reads from head.
pub struct PageRequestQueue {
    /// Base virtual address of the queue
    base: usize,
    /// Number of entries (power of 2)
    size: usize,
    /// Current head index (software reads from here)
    head: usize,
    /// Cached tail from hardware
    tail: usize,
}

impl PageRequestQueue {
    /// Default PRQ size (256 entries)
    pub const DEFAULT_SIZE: usize = 256;

    /// Create a new Page Request Queue
    pub fn new(size: usize) -> Option<Self> {
        // Size must be power of 2
        let size = size.next_power_of_two().min(4096);
        let total_bytes = size * core::mem::size_of::<PageRequestEntry>();
        let num_pages = (total_bytes + 4095) / 4096;

        // Allocate contiguous physical frames for hardware requirements
        let phys = alloc_contiguous_frames(num_pages)?
            .as_u64();
        let base = crate::io::iommu::common::tables::phys_to_virt_usize(phys);

        // Security: Mark the range as protected from DMA
        crate::security::dma::register_protected_range(phys, total_bytes as u64);

        Some(Self {
            base,
            size,
            head: 0,
            tail: 0,
        })
    }

    /// Get the physical base address
    pub fn base_address(&self) -> u64 {
        crate::io::iommu::common::tables::virt_ptr_to_phys(self.base as *const u8).unwrap_or(0)
    }

    /// Get the size (number of entries)
    pub fn size(&self) -> usize {
        self.size
    }

    /// Update the tail from hardware register
    pub fn update_tail(&mut self, tail: usize) {
        self.tail = tail & (self.size - 1);
    }

    /// Check if queue has pending entries
    pub fn has_pending(&self) -> bool {
        self.head != self.tail
    }

    /// Pop the next request entry
    pub fn pop(&mut self) -> Option<PageRequestEntry> {
        if self.head == self.tail {
            return None;
        }

        let ptr = self.base as *const PageRequestEntry;
        let entry = unsafe { *ptr.add(self.head) };
        self.head = (self.head + 1) & (self.size - 1);

        Some(entry)
    }

    /// Get current head index (for writing to hardware)
    pub fn head(&self) -> usize {
        self.head
    }
}

impl Drop for PageRequestQueue {
    fn drop(&mut self) {
        let total_bytes = self.size * core::mem::size_of::<PageRequestEntry>();
        let num_pages = (total_bytes + 4095) / 4096;
        if let Ok(phys) = crate::io::iommu::common::tables::virt_ptr_to_phys(self.base as *const u8) {
            crate::security::dma::unregister_protected_range(phys, total_bytes as u64);

            // free contiguous region
            dealloc_contiguous_frames(x86_64::PhysAddr::new(phys), num_pages);
        }
    }
}
