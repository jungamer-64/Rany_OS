// ============================================================================
// kernel/src/io/iommu/vendors/amd/tables.rs
// ============================================================================

use crate::io::iommu::common::tables::Zeroable;

/// AMD-Vi Page Table Entry
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AmdPte(pub u64);

impl AmdPte {
    /// Present (PR) - Bit 0
    pub const PRESENT: u64 = 1 << 0;
    /// Read (R) - Bit 61 (Only for PTEs)
    pub const READ: u64 = 1 << 61;
    /// Write (W) - Bit 62 (Only for PTEs)
    pub const WRITE: u64 = 1 << 62;
    /// Force Coherency (FC) - Bit 63
    #[cfg(test)]
    pub const FC: u64 = 1 << 63;
    /// Accessed (A) - Bit 5
    #[cfg(test)]
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty (D) - Bit 6
    #[cfg(test)]
    pub const DIRTY: u64 = 1 << 6;

    /// Create a new empty entry
    #[cfg(test)]
    pub fn new() -> Self {
        Self(0)
    }

    /// Create a mapping entry (Leaf)
    pub fn mapping(phys_addr: u64, read: bool, write: bool, _level: u8) -> Self {
        let mut flags = Self::PRESENT;
        // Next Level: Bits 9-11 must be 0 for leaf page mapping
        // (For 4KB page at Level 1, or 2MB page at Level 2, etc.)

        if read {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }

        // Address mask: Bits 51:12
        Self((phys_addr & 0x000F_FFFF_FFFF_F000) | flags)
    }

    /// Create a Pointer to Next Level Table (Directory Entry)
    /// next_level: level of the table being pointed to (1, 2, 3...)
    ///
    /// Note: Directory entries in AMD-Vi generally don't set R/W bits.
    /// Permissions are checked at the leaf level or by intersection,
    /// but the spec says IR/IW bits in intermediate entries are ignored.
    pub fn table_pointer(phys_addr: u64, next_level: u8) -> Self {
        let next_lvl_bits = ((next_level as u64) & 0x7) << 9;

        // Present bit set. Next Level field set.
        Self((phys_addr & 0x000F_FFFF_FFFF_F000) | next_lvl_bits | Self::PRESENT)
    }

    /// Check if present
    #[cfg(test)]
    pub fn is_present(&self) -> bool {
        (self.0 & Self::PRESENT) != 0
    }

    /// Get Next Level field (9-11)
    #[cfg(test)]
    pub fn next_level(&self) -> u8 {
        ((self.0 >> 9) & 0x7) as u8
    }

    /// Get physical address
    #[cfg(test)]
    pub fn phys_addr(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }
}

// SAFETY: All zeros is not present - valid state
unsafe impl Zeroable for AmdPte {}
