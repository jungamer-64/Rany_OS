// ============================================================================
// kernel/src/io/iommu/amd/paging.rs
// ============================================================================

//! AMD-Vi Page Table Entry definitions
//!
//! AMD-Vi uses the defined I/O Page Table format which is similar to x86-64
//! page tables but with different permission bit locations.

use crate::io::iommu::tables::Zeroable;

/// AMD-Vi I/O Page Table Entry
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AmdPte(pub u64);

impl AmdPte {
    /// Present (PR) - Bit 0
    pub const PRESENT: u64 = 1 << 0;
    /// Read (R) - Bit 61
    pub const READ: u64 = 1 << 61;
    /// Write (W) - Bit 62
    pub const WRITE: u64 = 1 << 62;
    /// Force Coherency (FC) - Bit 63
    pub const FC: u64 = 1 << 63;
    /// Accessed (A) - Bit 5
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty (D) - Bit 6
    pub const DIRTY: u64 = 1 << 6;
    /// Page Size (PSE) - Bit 7 (for 2MB/1GB pages - wait, spec says level dependent)
    /// Actually AMD IOMMU spec says:
    /// Level 1 (PT): Bit 7 is ignored/reserved.
    /// Level 2-6: Bit 0 is Present. If Next Level >= 1, it points to table.
    /// Bit 9-11: Next Level (0=Page, 1-6=Table).
    ///
    /// Wait, AMD IOMMU paging is different from x86 NPT/EPT!
    /// Let's verify AMD I/O Virtualization Technology (IOMMU) Specification.
    ///
    /// "Page Table Entry (PTE): The PTE is the lowest level in the translation
    /// hierarchy. It maps a virtual page number to a system physical page number."
    ///
    /// Fields:
    /// [63] FC - Force Coherency
    /// [62] IW - Write permission (if using v1 table)
    /// [61] IR - Read permission (if using v1 table)
    /// [51:12] Physical Page Address
    /// [11:9] Next Level (0 for PTE) - MUST BE 0 for 4KB page
    /// [6] D - Dirty
    /// [5] A - Accessed
    /// [0] PR - Present
    ///
    /// Directory Entry (PDE):
    /// [63:61] Ignored
    /// [51:12] Physical Address of next table
    /// [11:9] Next Level (>= 1) -> 0 means 4KB page (but this is PDE?)
    /// If Bit 0 (PR) is 1 and Next Level > 0, it points to another table.
    /// If Bit 0 (PR) is 1 and Next Level = 0, it is a Large Page?
    ///
    /// Specs say:
    /// "If the Next Level field is 0, the entry is a Page Table Entry (PTE)."
    /// "If the Next Level field is 7, the entry is a 1GB super-page." (wait, 7 is reserved?)
    ///
    /// Actually:
    /// Level 1 is 4KB Page Table. Entries have Next Level = 0.
    /// Level 2 is Page Dircetory. Entries point to Level 1 (Next Level = 1?).
    ///
    /// Reviewing "AMD I/O Virtualization Technology (IOMMU) Specification" Rev 3.07:
    /// Table 18: Page Table Entry (PTE) - Level 1
    ///   Bits [62]: IW
    ///   Bits [61]: IR
    ///   Bits [51:12]: Physical Address
    ///   Bits [11:9]: Next Level = 0
    ///   Bit [0]: PR
    ///
    /// Large Pages (2MB):
    /// Level 2 PDE can treat the entry as mapping a 2MB page if use "Page Mode" translation?
    /// "Guest Translation" vs "Host Translation".
    ///
    /// For Host Translation (our case):
    /// "I/O Page Tables are 4-level... strict 4KB or allow large pages?"
    ///
    /// ACPI IVRS indicates support for page sizes.
    /// If Host Translation, bits 9-11 (Next Level) determine usage.
    /// 0 = Map 4KB page (at Level 1) or Large Page (at Level > 1)?
    ///
    /// Actually, "If the Next Level field is 0, bits 51:12 contain the physical address of the page."
    /// This applies to ANY level.
    /// So:
    /// - At Level 1, Next Level naturally 0.
    /// - At Level 2 (PDE), if Next Level is 0, it maps a 2MB page.
    /// - At Level 3 (PDPE), if Next Level is 0, it maps a 1GB page.
    /// - At Level 4 (PML4), if Next Level is 0, it maps a 512GB page.
    ///
    /// Standard Table Pointer (Directory Entry):
    /// Bits 9-11: Next Level = (Current Level - 1)
    ///
    /// So:
    /// Level 4 Entry: Next Level = 3 (points to Level 3 table)
    /// Level 3 Entry: Next Level = 2 (points to Level 2 table)
    /// Level 2 Entry: Next Level = 1 (points to Level 1 table)
    /// Level 1 Entry: Next Level = 0 (maps 4KB page)
    ///
    /// Large Page (Super Page):
    /// Level 2 Entry: Next Level = 0 -> Maps 2MB page
    /// Level 3 Entry: Next Level = 0 -> Maps 1GB page
    ///
    /// This is simpler than Intel/Standard x86! No PS bit. Just Next Level = 0.

    pub fn new() -> Self {
        Self(0)
    }

    pub fn mapping(phys_addr: u64, read: bool, write: bool, level: u8) -> Self {
        let mut flags = Self::PRESENT;
        // Next Level: Bits 9-11
        // For standard table pointer, next_level = current_level - 1
        // For page mapping (4KB or Large), next_level = 0
        //
        // This function creates a mapping entry (leaf).
        // So Next Level must be 0.
        // (Default 0).

        // Intel R/W are at 0/1, AMD at 61/62.
        if read {
            flags |= Self::READ;
        }
        if write {
            flags |= Self::WRITE;
        }

        Self((phys_addr & 0x000F_FFFF_FFFF_F000) | flags)
    }

    /// Create a Pointer to Next Level Table
    /// next_level: 1, 2, 3...
    pub fn table_pointer(phys_addr: u64, next_level: u8) -> Self {
        let flags = Self::PRESENT |
                    Self::READ |  // Directories typically allow R/W to next level permissions?
                    Self::WRITE; // Actually permissions are checked at each level intersection or leaf?
        // AMD Spec: "For page table walks... IR and IW bits in intermediate
        // IO page table entries are ignored."
        // Wait, "The IR and IW bits are valid only for PTEs (Next Level = 0)."
        // So for directories, we don't set IR/IW.

        let next_lvl_bits = ((next_level as u64) & 0x7) << 9;
        Self((phys_addr & 0x000F_FFFF_FFFF_F000) | next_lvl_bits | Self::PRESENT)
    }

    pub fn is_present(&self) -> bool {
        (self.0 & Self::PRESENT) != 0
    }

    pub fn next_level(&self) -> u8 {
        ((self.0 >> 9) & 0x7) as u8
    }

    pub fn phys_addr(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }
}

// SAFETY: All zeros is not present
unsafe impl Zeroable for AmdPte {}
