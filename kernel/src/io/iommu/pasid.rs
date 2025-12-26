//! PASID (Process Address Space ID) Support for Scalable Mode
//!
//! Intel VT-d Scalable Mode enables per-process DMA isolation using PASID.

// ============================================================================
// PASID Directory Entry
// ============================================================================

/// PASID Directory Entry (Scalable Mode)
///
/// 8-byte entry in the PASID Directory. Points to a PASID Table.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PasidDirectoryEntry(u64);

impl PasidDirectoryEntry {
    /// Present bit
    pub const PRESENT: u64 = 1 << 0;

    /// Create a new entry
    pub fn new() -> Self {
        Self(0)
    }

    /// Set the PASID Table pointer
    pub fn set_table_ptr(&mut self, addr: u64) {
        // Bits 12-63 contain physical address of PASID Table (4KB aligned)
        self.0 = (addr & !0xFFF) | Self::PRESENT;
    }

    /// Get PASID Table address
    pub fn table_addr(&self) -> u64 {
        self.0 & !0xFFF
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.0 & Self::PRESENT) != 0
    }
}
