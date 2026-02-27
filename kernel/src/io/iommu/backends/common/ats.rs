// ============================================================================
// kernel/src/io/iommu/common/ats.rs
// ============================================================================
//! IOMMU ATS (Address Translation Services) and PRI (Page Request Interface)
//!
//! This module contains structures for Posted Interrupt processing and
//! Page Request handling, which are part of the ATS/PRI extensions.

use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

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

        // Allocate 64-byte aligned memory
        let layout = alloc::alloc::Layout::from_size_align(total_bytes, 64).ok()?;
        let base_ptr = crate::util::allocate_zeroed(layout)?;
        let base = base_ptr.as_ptr() as usize;

        // Security: Mark the range as protected from DMA
        if let Ok(phys) = crate::io::iommu::core::tables::virt_ptr_to_phys(base as *const u8) {
            crate::security::dma::register_protected_range(phys, total_bytes as u64);
        }

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
        if let Ok(phys) = crate::io::iommu::core::tables::virt_ptr_to_phys(self.base as *const u8) {
            crate::security::dma::unregister_protected_range(phys, total_bytes as u64);
        }

        let layout = alloc::alloc::Layout::from_size_align(total_bytes, 64).unwrap();
        unsafe {
            alloc::alloc::dealloc(self.base as *mut u8, layout);
        }
    }
}

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

        // Allocate 4KB aligned memory
        let layout = alloc::alloc::Layout::from_size_align(total_bytes, 4096).ok()?;
        let base_ptr = crate::util::allocate_zeroed(layout)?;
        let base = base_ptr.as_ptr() as usize;

        // Security: Mark the range as protected from DMA
        if let Ok(phys) = crate::io::iommu::core::tables::virt_ptr_to_phys(base as *const u8) {
            crate::security::dma::register_protected_range(phys, total_bytes as u64);
        }

        Some(Self {
            base,
            size,
            head: 0,
            tail: 0,
        })
    }

    /// Get the physical base address
    pub fn base_address(&self) -> u64 {
        self.base as u64
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
        if let Ok(phys) = crate::io::iommu::core::tables::virt_ptr_to_phys(self.base as *const u8) {
            crate::security::dma::unregister_protected_range(phys, total_bytes as u64);
        }

        let layout = alloc::alloc::Layout::from_size_align(total_bytes, 4096).unwrap();
        unsafe {
            alloc::alloc::dealloc(self.base as *mut u8, layout);
        }
    }
}
