// ============================================================================
// kernel/src/io/iommu/intel/tables.rs
// ============================================================================

use crate::io::iommu::tables::{HardwareTable, Zeroable};
use crate::io::iommu::types::IommuError;
use alloc::vec::Vec;

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
    pub fn is_present_low(&self) -> bool {
        (self.lo & 1) != 0
    }

    /// Check if upper context table pointer is present
    pub fn is_present_high(&self) -> bool {
        (self.hi & 1) != 0
    }

    /// Set context table pointer
    pub fn set_context_table(&mut self, addr: u64) {
        self.lo = (addr & !0xFFF) | 1; // Present bit
    }

    /// Set context table pointers for scalable mode (lower and upper halves)
    pub fn set_context_table_pair(&mut self, low_addr: u64, high_addr: u64) {
        self.lo = (low_addr & !0xFFF) | 1; // Present bit
        self.hi = (high_addr & !0xFFF) | 1; // Present bit
    }

    /// Get context table address
    pub fn context_table_addr(&self) -> u64 {
        self.lo & !0xFFF
    }

    /// Get physical address of the entry
    pub fn phys_addr(&self) -> u64 {
        self.lo & !0xFFF
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

    /// Check if entry is fault disabled
    pub fn is_fault_disabled(&self) -> bool {
        (self.lo & 2) != 0
    }

    /// Set second level page table pointer (Translation Type = 00b)
    pub fn set_sl_pt(&mut self, addr: u64, domain_id: u16, agaw: u8) {
        self.lo = (addr & !0xFFF) | 1; // Present
        self.hi = ((domain_id as u64) << 8) | ((agaw as u64) << 0);
    }

    /// Set passthrough (Translation Type = 10b / 2)
    pub fn set_passthrough(&mut self, domain_id: u16) {
        // PT (bit 3:2) = 10b (2). Present (bit 0) = 1.
        self.lo = (2 << 2) | 1;
        // Keep AGAW aligned with the normal 4-level page-table mode used here.
        self.hi = ((domain_id as u64) << 8) | 2;
    }

    /// Get second level page table address
    pub fn sl_pt_addr(&self) -> u64 {
        self.lo & !0xFFF
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
    /// Page Request Enable (QWORD 0, bit 4)
    pub const PRE: u64 = 1 << 4;
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
        self.qwords[0] = (pasid_dir_addr & Self::PASID_DIR_MASK)
            | (((pds as u64) & 0x7) << Self::PDS_SHIFT);
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

    /// Enable Page Request
    pub fn set_pre(&mut self) {
        self.qwords[0] |= Self::PRE;
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
    /// Fault Processing Disable
    pub const FAULT_DISABLE: u64 = 1 << 1;
    /// PASID Table Pointer (bits 12-63)
    pub const TABLE_MASK: u64 = !0xFFF;

    /// Create a new empty entry
    pub const fn new() -> Self {
        Self(0)
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.0 & Self::PRESENT) != 0
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
    /// Fault Processing Disable (QWORD 0, bit 1)
    pub const FAULT_DISABLE: u64 = 1 << 1;
    /// Address Width (QWORD 0, bits 2-4)
    pub const AW_SHIFT: u64 = 2;
    /// Translation Type (QWORD 0, bits 6-8)
    pub const PGTT_SHIFT: u64 = 6;
    /// Second Level Page Table Pointer (QWORD 0, bits 12-63)
    pub const SLPT_MASK: u64 = !0xFFF;
    /// Domain ID (QWORD 1, bits 0-15)
    pub const DID_MASK: u64 = 0xFFFF;

    /// PGTT encodings
    pub const PGTT_FL_ONLY: u64 = 1;
    pub const PGTT_SL_ONLY: u64 = 2;
    pub const PGTT_NESTED: u64 = 3;
    pub const PGTT_PT: u64 = 4;

    /// Create a new empty entry
    pub const fn new() -> Self {
        Self { qwords: [0; 8] }
    }

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
        self.qwords[0] = (addr & Self::SLPT_MASK) | Self::PRESENT;
        self.qwords[0] |= ((address_width as u64) & 0x7) << Self::AW_SHIFT;
        self.qwords[0] |= (Self::PGTT_SL_ONLY & 0x7) << Self::PGTT_SHIFT;
        self.qwords[1] = (domain_id as u64) & Self::DID_MASK;
    }

    /// Set passthrough translation (no page tables)
    pub fn set_passthrough(&mut self, domain_id: u16) {
        self.clear();
        self.qwords[0] = Self::PRESENT | ((Self::PGTT_PT & 0x7) << Self::PGTT_SHIFT);
        self.qwords[1] = (domain_id as u64) & Self::DID_MASK;
    }

    /// Get second level page table address
    pub fn sl_pt_addr(&self) -> u64 {
        self.qwords[0] & Self::SLPT_MASK
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
    /// Allocation bitmap
    allocated: Vec<u64>,
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

        // Allocate bitmap
        let bitmap_len = (count + 63) / 64;
        let mut allocated = Vec::with_capacity(bitmap_len);
        allocated.resize(bitmap_len, 0);

        Ok(Self {
            directory,
            table,
            size: count,
            allocated,
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

        // Mark as allocated
        let word_idx = (pasid as usize) / 64;
        let bit_idx = (pasid as usize) % 64;
        self.allocated[word_idx] |= 1 << bit_idx;

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

        let word_idx = (pasid as usize) / 64;
        let bit_idx = (pasid as usize) % 64;
        self.allocated[word_idx] |= 1 << bit_idx;

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

    /// Allocate the next free PASID (PASID 0 is reserved for RID→PASID mapping)
    pub fn allocate_pasid(&mut self) -> Result<u32, IommuError> {
        // Reserve PASID 0 once up-front so free-bit search can proceed uniformly.
        if !self.allocated.is_empty() {
            self.allocated[0] |= 1u64;
        }

        for word_idx in 0..self.allocated.len() {
            let word = self.allocated[word_idx];
            if word == u64::MAX {
                continue;
            }
            let bit = (!word).trailing_zeros() as usize;
            let pasid = word_idx * 64 + bit;
            if pasid >= self.size {
                return Err(IommuError::OutOfMemory);
            }
            self.allocated[word_idx] |= 1u64 << bit;
            return Ok(pasid as u32);
        }
        Err(IommuError::OutOfMemory)
    }

    /// Free a previously allocated PASID (PASID 0 cannot be freed)
    pub fn free_pasid(&mut self, pasid: u32) -> Result<(), IommuError> {
        if pasid == 0 {
            return Err(IommuError::InvalidAddress);
        }
        if (pasid as usize) >= self.size {
            return Err(IommuError::InvalidAddress);
        }
        let word_idx = (pasid as usize) / 64;
        let bit_idx = (pasid as usize) % 64;
        if self.allocated[word_idx] & (1u64 << bit_idx) == 0 {
            return Err(IommuError::NotMapped);
        }
        if let Some(entry) = self.table.get_mut(pasid as usize) {
            entry.clear();
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        }
        self.allocated[word_idx] &= !(1u64 << bit_idx);
        Ok(())
    }

    /// Check if a PASID is currently allocated
    pub fn is_allocated(&self, pasid: u32) -> bool {
        if (pasid as usize) >= self.size {
            return false;
        }
        let word_idx = (pasid as usize) / 64;
        let bit_idx = (pasid as usize) % 64;
        self.allocated[word_idx] & (1u64 << bit_idx) != 0
    }

    /// Return the number of currently allocated PASIDs
    pub fn allocated_count(&self) -> usize {
        self.allocated.iter().map(|w| w.count_ones() as usize).sum()
    }
}
