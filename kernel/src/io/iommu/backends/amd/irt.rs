// ============================================================================
// kernel/src/io/iommu/amd/irt.rs
// ============================================================================

//! AMD-Vi Interrupt Remapping Table (IRT) management.
//!
//! Each IOMMU unit has a single IRT that maps device interrupt requests to
//! physical APIC destinations.  The table is a flat array of 128-bit entries
//! (IRTE) written to physically contiguous memory and programmed via the
//! Interrupt Remapping Table Base Address Register (MMIO 0x0068).
//!
//! AMD-Vi spec Rev 3.07, Section 2.2.6.

use alloc::vec;
use alloc::vec::Vec;

use crate::io::iommu::core::tables::{HardwareTable, Zeroable};
use crate::io::iommu::types::IommuError;

// ---------------------------------------------------------------------------
// IRTE bit layout (AMD-Vi spec Section 2.2.6, Table 18)
// ---------------------------------------------------------------------------

const IRTE_REMAP_EN: u64 = 1 << 0; // bit 0: RemapEn
const IRTE_SUPPRESS: u64 = 1 << 1; // bit 1: Suppress I/O APIC writes
const IRTE_DM_LOGICAL: u64 = 1 << 2; // bit 2: DM (0=physical, 1=logical)
const IRTE_INT_TYPE_SHIFT: u32 = 3; // bits [5:3]: IntType (delivery mode)
#[allow(dead_code)]
const IRTE_INT_TYPE_MASK: u64 = 0x07 << IRTE_INT_TYPE_SHIFT;
const IRTE_VECTOR_SHIFT: u32 = 8; // bits [15:8]: Vector
#[allow(dead_code)]
const IRTE_VECTOR_MASK: u64 = 0xFF << IRTE_VECTOR_SHIFT;
const IRTE_DESTINATION_SHIFT: u32 = 32; // bits [63:32]: Destination (APIC ID)

/// AMD-Vi IRT size encoding for the table base register.
/// Stored in bits [3:0] of the IRT Base Address register.
/// Encoding: 2^(N+1) entries where N = size field value.
const IRT_SIZE_ENCODE_SHIFT: u32 = 1;

/// Default IRT size: 256 entries (log2 = 8, encoded as 7).
pub(super) const IRT_DEFAULT_SIZE_LOG2: u8 = 8;

// ---------------------------------------------------------------------------
// AMD Interrupt Remapping Table Entry (128-bit)
// ---------------------------------------------------------------------------

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct AmdIrte {
    pub(super) lo: u64,
    pub(super) hi: u64,
}

// SAFETY: All-zeros is valid (RemapEn=0, entry not present).
unsafe impl Zeroable for AmdIrte {}

impl AmdIrte {
    pub const fn new() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Build a fixed-delivery IRTE.
    ///
    /// `vector`: interrupt vector (0-255).
    /// `dest_id`: APIC destination ID.
    /// `logical`: true for logical destination mode.
    pub fn fixed(vector: u8, dest_id: u32, logical: bool) -> Self {
        let mut lo: u64 = IRTE_REMAP_EN;
        if logical {
            lo |= IRTE_DM_LOGICAL;
        }
        // IntType = 0b000 (Fixed) — already zero.
        lo |= (vector as u64) << IRTE_VECTOR_SHIFT;
        lo |= (dest_id as u64) << IRTE_DESTINATION_SHIFT;
        Self { lo, hi: 0 }
    }

    /// Build an IRTE with specified delivery mode.
    pub fn with_delivery_mode(
        vector: u8,
        dest_id: u32,
        logical: bool,
        delivery_mode: u8,
    ) -> Self {
        let mut entry = Self::fixed(vector, dest_id, logical);
        entry.lo &= !IRTE_INT_TYPE_MASK;
        entry.lo |= ((delivery_mode as u64) & 0x07) << IRTE_INT_TYPE_SHIFT;
        entry
    }

    pub fn is_present(&self) -> bool {
        (self.lo & IRTE_REMAP_EN) != 0
    }

    pub fn vector(&self) -> u8 {
        ((self.lo >> IRTE_VECTOR_SHIFT) & 0xFF) as u8
    }

    pub fn destination(&self) -> u32 {
        (self.lo >> IRTE_DESTINATION_SHIFT) as u32
    }

    pub fn is_logical(&self) -> bool {
        (self.lo & IRTE_DM_LOGICAL) != 0
    }
}

// ---------------------------------------------------------------------------
// AMD Interrupt Remapping Table
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct AmdInterruptRemapTable {
    table: HardwareTable<AmdIrte>,
    bitmap: Vec<u64>,
    capacity: u32,
}

impl AmdInterruptRemapTable {
    /// Allocate a new IRT with `2^size_log2` entries.
    ///
    /// The table is backed by page-aligned physically contiguous memory via
    /// `HardwareTable`.
    pub fn new(size_log2: u8) -> Result<Self, IommuError> {
        let count = 1usize
            .checked_shl(size_log2 as u32)
            .ok_or(IommuError::InvalidAddress)?;
        let table = HardwareTable::new(count, None)?;
        let bitmap_len = (count + 63) / 64;
        Ok(Self {
            table,
            bitmap: vec![0u64; bitmap_len],
            capacity: count as u32,
        })
    }

    /// Physical base address of the table (page-aligned).
    pub fn phys_base(&self) -> u64 {
        self.table.phys_addr()
    }

    /// Encode the table base register value for MMIO programming.
    ///
    /// AMD-Vi spec: IRT Base Address Register (MMIO offset 0x0068)
    ///   bits [51:6]: physical base address >> 6
    ///   bits [3:0]:  size encoding (2^(N+1) entries)
    pub fn base_register_value(&self, size_log2: u8) -> u64 {
        let size_field = (size_log2 as u64).saturating_sub(IRT_SIZE_ENCODE_SHIFT as u64) & 0x0F;
        (self.phys_base() & !0x3F) | size_field
    }

    /// Total entry count.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Allocate a free IRTE index.
    pub fn allocate(&mut self) -> Result<u16, IommuError> {
        for (i, word) in self.bitmap.iter().enumerate() {
            if *word != !0u64 {
                let bit = (!*word).trailing_zeros();
                let idx = i * 64 + bit as usize;
                if idx < self.capacity as usize {
                    self.bitmap[i] |= 1u64 << bit;
                    return Ok(idx as u16);
                }
            }
        }
        Err(IommuError::OutOfMemory)
    }

    /// Free a previously allocated IRTE index and clear the entry.
    pub fn free(&mut self, index: u16) -> Result<(), IommuError> {
        let idx = index as usize;
        if idx >= self.capacity as usize {
            return Err(IommuError::InvalidAddress);
        }
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        if word_idx < self.bitmap.len() {
            self.bitmap[word_idx] &= !(1u64 << bit_idx);
        }
        if let Some(entry) = self.table.get_mut(idx) {
            *entry = AmdIrte::new();
        }
        Ok(())
    }

    /// Write an IRTE at the given index.
    pub fn set_entry(&mut self, index: u16, irte: AmdIrte) -> Result<(), IommuError> {
        let entry = self
            .table
            .get_mut(index as usize)
            .ok_or(IommuError::InvalidAddress)?;
        *entry = irte;
        Ok(())
    }

    /// Read the IRTE at the given index.
    pub fn get_entry(&self, index: u16) -> Option<AmdIrte> {
        self.table.get(index as usize).copied()
    }
}

// ---------------------------------------------------------------------------
// AMD Interrupt Remapping MSI message encoding
// ---------------------------------------------------------------------------

/// AMD-Vi spec Section 2.2.5: Interrupt Remapping for MSI/MSI-X
///
/// When interrupt remapping is enabled, device-generated MSI/MSI-X messages
/// encode the IRTE handle (index) instead of the normal destination/vector:
///
///   MSI Address (low 32 bits):
///     bits [31:20] = 0xFEE (MSI address prefix)
///     bits [19:4]  = handle[15:0] (IRTE index bits [19:4] of address)
///     bit  [3]     = handle bit 1 (DM encoding overloaded)
///     bit  [2]     = 1 (interrupt format = remapped)
///     bits [1:0]   = reserved
///
///   MSI Data (low 32 bits):
///     bits [15:0]  = handle[15:0] lower bits
///     bit  [0]     = handle bit 0
///
/// This encoding allows the IOMMU to extract the table index from the MSI
/// message and look up the IRTE for the actual destination/vector.
///
/// Simplified encoding used here (compatible with QEMU AMD IOMMU model):
///   Address = 0xFEE0_0000 | (handle << 2) | 0x04 (bit 2 = remapped format)
///   Data    = 0x0000_0000 (vector/delivery info is in the IRTE, not MSI data)
pub fn encode_remap_msi(handle: u16) -> (u64, u32) {
    let address = 0xFEE0_0000u64 | ((handle as u64) << 2) | 0x04;
    let data = 0u32;
    (address, data)
}

// ---------------------------------------------------------------------------
// Unit-level IRT handle
// ---------------------------------------------------------------------------

/// Per-unit IRT state stored in the driver.
#[derive(Debug)]
pub struct AmdUnitIrt {
    pub(super) table: AmdInterruptRemapTable,
    pub(super) size_log2: u8,
}

impl AmdUnitIrt {
    pub fn new(size_log2: u8) -> Result<Self, IommuError> {
        let table = AmdInterruptRemapTable::new(size_log2)?;
        Ok(Self { table, size_log2 })
    }
}
