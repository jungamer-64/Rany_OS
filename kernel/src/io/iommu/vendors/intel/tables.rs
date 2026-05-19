// ============================================================================
// kernel/src/io/iommu/vendors/intel/tables.rs
// ============================================================================

use crate::io::iommu::common::tables::{HardwareTable, Zeroable};
use crate::io::iommu::types::IommuError;

// ============================================================================
// Root Table
// ============================================================================

/// Root table entry
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct RootEntry {
    /// Lower 64 bits (context table pointer)
    pub lo: u64,
    /// Upper 64 bits (reserved)
    pub hi: u64,
}

impl RootEntry {
    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        (self.lo & 1) != 0
    }

    /// Check if lower context table pointer is present
    #[cfg(test)]
    pub fn is_present_low(&self) -> bool {
        (self.lo & 1) != 0
    }

    /// Check if upper context table pointer is present
    #[cfg(test)]
    pub fn is_present_high(&self) -> bool {
        (self.hi & 1) != 0
    }

    /// Set context table pointer
    pub fn set_context_table(&mut self, addr: u64) {
        self.lo = (addr & !0xFFF) | 1; // Present bit
    }

    /// Set context table pointers for scalable mode (lower and upper halves)
    pub fn set_context_table_pair(&mut self, low_addr: u64, high_addr: u64) {
        // SECURITY: Write the high QWORD first, then the low QWORD with a memory fence.
        // This ensures the IOMMU sees the upper context table pointer before or at
        // the same time as the lower one.
        self.hi = (high_addr & !0xFFF) | 1; // Present bit
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.lo = (low_addr & !0xFFF) | 1; // Present bit
    }
}

// SAFETY: RootEntry with all zeros represents "not present" - a valid state
unsafe impl Zeroable for RootEntry {}

// ============================================================================
// Context Table
// ============================================================================

/// Context table entry
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct ContextEntry {
    /// Lower 64 bits
    pub lo: u64,
    /// Upper 64 bits
    pub hi: u64,
}

impl ContextEntry {
    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        (self.lo & 1) != 0
    }

    /// Set second level page table pointer (Translation Type = 00b)
    pub fn set_sl_pt(&mut self, addr: u64, domain_id: u16, agaw: u8) {
        // SECURITY: Set fields in an order that avoids race conditions.
        // We set the high QWORD (domain ID) first, then the low QWORD (address + Present).
        self.hi = ((domain_id as u64) << 8) | ((agaw as u64) << 0);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.lo = (addr & !0xFFF) | 1; // Present
    }

    /// Set passthrough (Translation Type = 10b / 2)
    pub fn set_passthrough(&mut self, domain_id: u16, agaw: u8) {
        // SECURITY: Set domain ID first, then Translation Type and Present bit.
        // PT (bit 3:2) = 10b (2). Present (bit 0) = 1.
        self.hi = ((domain_id as u64) << 8) | ((agaw as u64) & 0x7);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.lo = (2 << 2) | 1;
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u16 {
        ((self.hi >> 8) & 0xFFFF) as u16
    }
}

// SAFETY: ContextEntry with all zeros represents "not present" - a valid state
unsafe impl Zeroable for ContextEntry {}

// ============================================================================
// Scalable Mode Context Table
// ============================================================================

/// Scalable Mode Context Entry (32 bytes)
///
/// Used in Scalable Mode Translation (SMTS) for PASID-based translation.
/// Each entry is 32 bytes; the first 16 bytes hold PASID directory pointer
/// and RID->PASID mapping, remaining 16 bytes are reserved.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug)]
pub struct ScalableContextEntry {
    /// 4 QWORDs (32 bytes)
    pub qwords: [u64; 4],
}

impl Default for ScalableContextEntry {
    fn default() -> Self {
        Self { qwords: [0; 4] }
    }
}

impl ScalableContextEntry {
    /// Present bit (QWORD 0, bit 0)
    pub const PRESENT: u64 = 1 << 0;
    /// Fault Processing Disable (QWORD 0, bit 1)
    pub const FAULT_DISABLE: u64 = 1 << 1;
    /// Device-TLB Enable (QWORD 0, bit 2)
    pub const DTE: u64 = 1 << 2;
    /// PASID Enable (QWORD 0, bit 3)
    pub const PASID_ENABLE: u64 = 1 << 3;
    /// PASID Directory Pointer (QWORD 0, bits 12-63)
    pub const PASID_DIR_MASK: u64 = !0xFFF;
    /// PASID Directory Size (QWORD 0, bits 9-11)
    pub const PDS_SHIFT: u64 = 9;
    /// RID->PASID mapping (QWORD 1, bits 0-19)
    pub const RID_PASID_MASK: u64 = (1 << 20) - 1;

    /// Create a new empty entry
    pub const fn new() -> Self {
        Self { qwords: [0; 4] }
    }

    /// Check if the entry is present
    pub fn is_present(&self) -> bool {
        (self.qwords[0] & Self::PRESENT) != 0
    }

    /// Set the PASID directory pointer and size
    pub fn set_pasid_dir(&mut self, pasid_dir_addr: u64, pds: u8) {
        // Preserve control bits in bits [8:0] (Present, FPD, DTE, PASID_EN)
        // to avoid fragile dependency on call ordering.
        let control_mask: u64 = 0x1FF; // bits [8:0]
        let preserved = self.qwords[0] & control_mask;
        self.qwords[0] = (pasid_dir_addr & Self::PASID_DIR_MASK)
            | (((pds as u64) & 0x7) << Self::PDS_SHIFT)
            | preserved;
    }

    /// Set RID->PASID mapping (for requests without PASID)
    pub fn set_rid2pasid(&mut self, pasid: u32) {
        let pasid_bits = (pasid as u64) & Self::RID_PASID_MASK;
        self.qwords[1] = (self.qwords[1] & !Self::RID_PASID_MASK) | pasid_bits;
    }

    /// Mark entry present
    pub fn set_present(&mut self) {
        self.qwords[0] |= Self::PRESENT;
    }

    /// Enable fault processing (clear FPD)
    pub fn set_fault_enable(&mut self) {
        self.qwords[0] &= !Self::FAULT_DISABLE;
    }

    /// Enable PASID translation
    pub fn set_pasid_enable(&mut self) {
        self.qwords[0] |= Self::PASID_ENABLE;
    }

    /// Enable Device-TLB (ATS)
    pub fn set_dte(&mut self) {
        self.qwords[0] |= Self::DTE;
    }
}

// SAFETY: ScalableContextEntry with all zeros is not present - valid state
unsafe impl Zeroable for ScalableContextEntry {}

// ============================================================================
// PASID Table
// ============================================================================

/// PASID Directory Entry (8 bytes)
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PasidDirEntry(pub u64);

impl PasidDirEntry {
    /// Present bit
    pub const PRESENT: u64 = 1 << 0;
    /// PASID Table Pointer (bits 12-63)
    pub const TABLE_MASK: u64 = !0xFFF;

    /// Create a new empty entry
    pub const fn new() -> Self {
        Self(0)
    }

    /// Set PASID table pointer
    pub fn set_table(&mut self, addr: u64) {
        self.0 = (addr & Self::TABLE_MASK) | Self::PRESENT;
    }
}

// SAFETY: PasidDirEntry with all zeros is not present - valid state
unsafe impl Zeroable for PasidDirEntry {}

/// PASID Table Entry (64 bytes)
///
/// Each entry in the PASID table defines the address translation
/// for a specific PASID.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct PasidTableEntry {
    /// 8 QWORDs
    pub qwords: [u64; 8],
}

impl Default for PasidTableEntry {
    fn default() -> Self {
        Self { qwords: [0; 8] }
    }
}

impl PasidTableEntry {
    /// Present bit (QWORD 0, bit 0)
    pub const PRESENT: u64 = 1 << 0;
    /// Address Width (QWORD 0, bits 2-4)
    pub const AW_SHIFT: u64 = 2;
    /// Translation Type (QWORD 0, bits 6-8)
    pub const PGTT_SHIFT: u64 = 6;
    /// Second Level Page Table Pointer (QWORD 0, bits 12-63)
    pub const SLPT_MASK: u64 = !0xFFF;
    /// Domain ID (QWORD 1, bits 0-15)
    pub const DID_MASK: u64 = 0xFFFF;

    /// PGTT encodings
    pub const PGTT_SL_ONLY: u64 = 2;
    pub const PGTT_PT: u64 = 4;

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.qwords[0] & Self::PRESENT) != 0
    }

    /// Clear entry
    pub fn clear(&mut self) {
        self.qwords = [0; 8];
    }

    /// Set second level page table pointer (SL-only translation)
    pub fn set_sl_pt(&mut self, addr: u64, address_width: u8, domain_id: u16) {
        self.clear();
        // SECURITY: Set fields in an order that avoids race conditions.
        // We set other qwords before qwords[0] (which contains the Present bit).
        self.qwords[1] = (domain_id as u64) & Self::DID_MASK;
        let qw0 = (addr & Self::SLPT_MASK)
            | Self::PRESENT
            | (((address_width as u64) & 0x7) << Self::AW_SHIFT)
            | ((Self::PGTT_SL_ONLY & 0x7) << Self::PGTT_SHIFT);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.qwords[0] = qw0;
    }

    /// Set passthrough translation (no page tables)
    pub fn set_passthrough(&mut self, domain_id: u16) {
        self.clear();
        // SECURITY: Set domain_id first, then Present bit and Translation Type.
        self.qwords[1] = (domain_id as u64) & Self::DID_MASK;
        let qw0 = Self::PRESENT | ((Self::PGTT_PT & 0x7) << Self::PGTT_SHIFT);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.qwords[0] = qw0;
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u16 {
        (self.qwords[1] & Self::DID_MASK) as u16
    }
}

// SAFETY: PasidTableEntry with all zeros is not present - valid state
unsafe impl Zeroable for PasidTableEntry {}

/// PASID Table
///
/// Manages PASID entries for Scalable Mode.
/// Each entry is 64 bytes (PasidTableEntry).
pub struct PasidTable {
    /// PASID directory table (4KB, 512 entries)
    pub directory: HardwareTable<PasidDirEntry>,
    /// PASID leaf table (4KB, 64 entries)
    pub table: HardwareTable<PasidTableEntry>,
    /// Size (number of entries, power of 2)
    pub size: usize,
    /// PASID directory size field (PDS)
    pds: u8,
}

impl PasidTable {
    const DIR_ENTRIES: usize = 512;
    const TABLE_ENTRIES: usize = 64;

    /// Create a new PASID table
    pub fn new(size_log2: u8) -> Result<Self, IommuError> {
        // Limit to a single 4KB PASID leaf table (<= 64 entries) for now
        if size_log2 > 6 {
            return Err(IommuError::NotSupported);
        }

        let count = 1usize << size_log2;
        let mut directory = HardwareTable::new(Self::DIR_ENTRIES, None)?;
        let table = HardwareTable::new(Self::TABLE_ENTRIES, None)?;

        // Setup directory entry 0 to point to the leaf table
        let mut dir_entry = PasidDirEntry::new();
        dir_entry.set_table(table.phys_addr());
        if let Some(entry) = directory.get_mut(0) {
            *entry = dir_entry;
        }

        Ok(Self {
            directory,
            table,
            size: count,
            pds: 0,
        })
    }

    /// Get physical address of PASID directory table
    pub fn phys_addr(&self) -> u64 {
        self.directory.phys_addr()
    }

    /// Get PASID directory size field
    pub fn pds(&self) -> u8 {
        self.pds
    }

    /// Setup a PASID entry
    pub fn setup_sl_entry(
        &mut self,
        pasid: u32,
        sl_pt_addr: u64,
        address_width: u8,
        domain_id: u16,
    ) -> Result<(), IommuError> {
        if (pasid as usize) >= self.size || (pasid as usize) >= Self::TABLE_ENTRIES {
            return Err(IommuError::InvalidAddress);
        }

        // Update entry
        if let Some(entry) = self.table.get_mut(pasid as usize) {
            entry.set_sl_pt(sl_pt_addr, address_width, domain_id);
            // Ensure memory is visible
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            Ok(())
        } else {
            Err(IommuError::InvalidAddress)
        }
    }

    /// Setup a passthrough PASID entry
    pub fn setup_passthrough_entry(
        &mut self,
        pasid: u32,
        domain_id: u16,
    ) -> Result<(), IommuError> {
        if (pasid as usize) >= self.size || (pasid as usize) >= Self::TABLE_ENTRIES {
            return Err(IommuError::InvalidAddress);
        }

        if let Some(entry) = self.table.get_mut(pasid as usize) {
            entry.set_passthrough(domain_id);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            Ok(())
        } else {
            Err(IommuError::InvalidAddress)
        }
    }

    /// Read domain ID for a PASID entry (if present)
    pub fn domain_id(&self, pasid: u32) -> Option<u16> {
        if (pasid as usize) >= self.size || (pasid as usize) >= Self::TABLE_ENTRIES {
            return None;
        }
        let entry = self.table.get(pasid as usize)?;
        if entry.is_present() {
            Some(entry.domain_id())
        } else {
            None
        }
    }
}
