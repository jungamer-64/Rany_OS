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

    /// Set context table pointer
    pub fn set_context_table(&mut self, addr: u64) {
        self.lo = (addr & !0xFFF) | 1; // Present bit
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
        self.hi = (domain_id as u64) << 8;
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

/// Scalable Mode Context Entry (128 bytes)
///
/// Used in Scalable Mode Translation (SMTS) for PASID-based translation.
/// Each entry is 128 bytes and points to a PASID table.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct ScalableContextEntry {
    /// 8 QWORDs (64 bytes each half)
    pub qwords: [u64; 16],
}

impl Default for ScalableContextEntry {
    fn default() -> Self {
        Self { qwords: [0; 16] }
    }
}

impl ScalableContextEntry {
    /// Present bit (QWORD 0, bit 0)
    pub const PRESENT: u64 = 1 << 0;
    /// PASID Table Pointer (QWORD 0, bits 12-63)
    pub const PTP_MASK: u64 = !0xFFF;
    /// PASID Table Size (QWORD 1, bits 0-3) - log2 of entries
    pub const PTS_SHIFT: u64 = 0;
    /// RID-PASID (Request ID to PASID mapping, QWORD 1)
    pub const RID_PASID_SHIFT: u64 = 4;
    /// Domain ID (QWORD 8, bits 8-23)
    pub const DID_SHIFT: u64 = 8;

    /// Create a new empty entry
    pub const fn new() -> Self {
        Self { qwords: [0; 16] }
    }

    /// Check if the entry is present
    pub fn is_present(&self) -> bool {
        (self.qwords[0] & Self::PRESENT) != 0
    }

    /// Set the PASID table pointer
    pub fn set_pasid_table(&mut self, pasid_table_addr: u64, size_log2: u8) {
        self.qwords[0] = (pasid_table_addr & Self::PTP_MASK) | Self::PRESENT;
        // Set PASID table size in QWORD 1
        self.qwords[1] = ((size_log2 as u64) & 0xF) << Self::PTS_SHIFT;
    }

    /// Set domain ID
    pub fn set_domain_id(&mut self, domain_id: u16) {
        self.qwords[8] = (self.qwords[8] & !0xFFFF00) | ((domain_id as u64) << Self::DID_SHIFT);
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u16 {
        ((self.qwords[8] >> Self::DID_SHIFT) & 0xFFFF) as u16
    }

    /// Get PASID table pointer
    pub fn pasid_table_addr(&self) -> u64 {
        self.qwords[0] & Self::PTP_MASK
    }
}

// ============================================================================
// PASID Table
// ============================================================================

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
    /// Page Walk Disable (QWORD 0, bit 3)
    pub const PWD: u64 = 1 << 3;
    /// First Level Page Table Pointer (QWORD 0, bits 12-63)
    pub const FLPT_MASK: u64 = !0xFFF;
    /// Address Width (QWORD 1, bits 0-2)
    pub const AW_SHIFT: u64 = 0;
    /// Supervisor Request (QWORD 1, bit 5)
    pub const SRE: u64 = 1 << 5;
    /// Execute Enable (QWORD 1, bit 6)
    pub const EAFE: u64 = 1 << 6;

    /// Create a new empty entry
    pub const fn new() -> Self {
        Self { qwords: [0; 8] }
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.qwords[0] & Self::PRESENT) != 0
    }

    /// Set first level page table pointer
    pub fn set_fl_pt(&mut self, addr: u64, address_width: u8) {
        self.qwords[0] = (addr & Self::FLPT_MASK) | Self::PRESENT;
        self.qwords[1] = ((address_width as u64) & 0x7) << Self::AW_SHIFT;
    }

    /// Set second level page table pointer (for nested translation)
    pub fn set_sl_pt(&mut self, addr: u64, address_width: u8) {
        // Set PWD = 0 (page walk enabled) and point to SL PT
        self.qwords[0] = (addr & Self::FLPT_MASK) | Self::PRESENT;
        self.qwords[1] = ((address_width as u64) & 0x7) << Self::AW_SHIFT;
    }

    /// Get first level page table address
    pub fn fl_pt_addr(&self) -> u64 {
        self.qwords[0] & Self::FLPT_MASK
    }
}

// SAFETY: PasidTableEntry with all zeros is not present - valid state
unsafe impl Zeroable for PasidTableEntry {}

/// PASID Table
///
/// Manages PASID entries for Scalable Mode.
/// Each entry is 64 bytes (PasidTableEntry).
pub struct PasidTable {
    /// Hardware table backing the PASID entries
    pub table: HardwareTable<PasidTableEntry>,
    /// Size (number of entries, power of 2)
    pub size: usize,
    /// Allocation bitmap
    allocated: Vec<u64>,
}

impl PasidTable {
    /// Create a new PASID table
    pub fn new(size_log2: u8) -> Result<Self, IommuError> {
        // Limit max PASID bits to 20 (1M entries)
        if size_log2 > 20 {
            return Err(IommuError::InvalidAddress);
        }

        let count = 1 << size_log2;
        // Allocate hardware table
        let table = HardwareTable::new(count, None)?;

        // Allocate bitmap
        let bitmap_len = (count + 63) / 64;
        let mut allocated = Vec::with_capacity(bitmap_len);
        allocated.resize(bitmap_len, 0);

        Ok(Self {
            table,
            size: count,
            allocated,
        })
    }

    /// Get physical address
    pub fn phys_addr(&self) -> u64 {
        self.table.phys_addr()
    }

    /// Setup a PASID entry
    pub fn setup_entry(
        &mut self,
        pasid: u32,
        fl_pt_addr: u64,
        address_width: u8,
    ) -> Result<(), IommuError> {
        if (pasid as usize) >= self.size {
            return Err(IommuError::InvalidAddress);
        }

        // Mark as allocated
        let word_idx = (pasid as usize) / 64;
        let bit_idx = (pasid as usize) % 64;
        self.allocated[word_idx] |= 1 << bit_idx;

        // Update entry
        if let Some(entry) = self.table.get_mut(pasid as usize) {
            entry.set_fl_pt(fl_pt_addr, address_width);
            // Ensure memory is visible
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            Ok(())
        } else {
            Err(IommuError::InvalidAddress)
        }
    }
}
