// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/ir.rs
// ============================================================================

//! Interrupt Remapping Methods
//!
//! This module contains interrupt remapping methods for `IommuController` via `InterruptRemapper` trait.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::IommuController;
use crate::io::iommu::common::tables::{HardwareTable, Zeroable};
use crate::io::iommu::types::IommuError;

/// Interrupt Remapping Entry (128-bit)
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InterruptRemapEntry {
    pub lo: u64,
    pub hi: u64,
}

impl InterruptRemapEntry {
    pub const fn new() -> Self {
        Self { lo: 0, hi: 0 }
    }

    pub fn fixed(
        vector: u8,
        dest_id: u32,
        logical: bool,
        sid: Option<u16>, // RID/BDF
    ) -> Self {
        // P=1 (bit 0)
        let mut lo = 1;
        // DM (bit 2)
        if logical {
            lo |= 1 << 2;
        }
        // SECURITY: IM (Interrupt Mode) = 0 (bit 15) for remapped interrupts.
        // Bit 15 must be 0; previous implementation incorrectly set it.
        lo &= !(1 << 15);
        // Vector (bits 31:16)
        lo |= (vector as u64) << 16;
        // DestID (bits 63:32)
        // Note: This requires EIME=1 in IRTA register (32-bit Destination ID).
        lo |= (dest_id as u64) << 32;

        let mut hi = 0;
        if let Some(rid) = sid {
            // SVT=1 (Source Validation Type: Verify SID) - bits 81:80 of IRTE (bits 17:16 of hi)
            hi |= 1 << 16;
            // SQ=0 (Source-id Qualifier: Exact match) - bits 83:82 of IRTE (bits 19:18 of hi)
            // (hi |= 0 << 18 is implicit)
            // SID (Source ID) - bits 79:64 of IRTE (bits 15:0 of hi)
            hi |= rid as u64;
        }

        Self { lo, hi }
    }
}

// SAFETY: All-zeros is valid (not present)
unsafe impl Zeroable for InterruptRemapEntry {}

/// Interrupt Remapping Table
pub struct InterruptRemapTable {
    pub table: HardwareTable<InterruptRemapEntry>,
    bitmap: Vec<u64>,
}

impl InterruptRemapTable {
    pub fn allocate(&mut self) -> Option<u16> {
        // Find first free bit
        for (i, &word) in self.bitmap.iter().enumerate() {
            if word != !0 {
                let trailing = (!word).trailing_zeros();
                let idx = i * 64 + trailing as usize;
                if idx < self.table.count() {
                    self.bitmap[i] |= 1 << trailing;
                    return Some(idx as u16);
                }
            }
        }
        None
    }

    pub fn free(&mut self, index: u16) {
        let idx = index as usize;
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        if word_idx < self.bitmap.len() {
            self.bitmap[word_idx] &= !(1 << bit_idx);
        }
    }

    pub fn set(&mut self, index: u16, entry: InterruptRemapEntry) -> bool {
        if let Some(e) = self.table.get_mut(index as usize) {
            // SECURITY: Update IRTE in a safe order.
            let is_present = (entry.lo & 1) != 0;
            let was_present = (unsafe { core::ptr::read_volatile(&e.lo) } & 1) != 0;

            if was_present && is_present {
                // Modifying a present entry: Clear Present bit first.
                unsafe {
                    core::ptr::write_volatile(&mut e.lo, 0);
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            }

            if is_present {
                // Setting to Present=1: Write hi first, then lo.
                unsafe {
                    core::ptr::write_volatile(&mut e.hi, entry.hi);
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                unsafe {
                    core::ptr::write_volatile(&mut e.lo, entry.lo);
                }
            } else {
                // Clearing to Present=0: Write lo first, then hi.
                unsafe {
                    core::ptr::write_volatile(&mut e.lo, entry.lo);
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                unsafe {
                    core::ptr::write_volatile(&mut e.hi, entry.hi);
                }
            }
            true
        } else {
            false
        }
    }
}

pub trait InterruptRemapper {
    /// Check if interrupt remapping is enabled
    fn is_interrupt_remapping_enabled(&self) -> bool;
    /// Allocate an IRTE for a device interrupt
    fn allocate_irte(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        vector: u8,
        dest_id: u32,
        logical: bool,
    ) -> Result<u16, IommuError>;
}

impl InterruptRemapper for IommuController {
    /// Check if interrupt remapping is enabled
    fn is_interrupt_remapping_enabled(&self) -> bool {
        self.ir_enabled.load(Ordering::Acquire)
    }

    /// Allocate an IRTE for a device interrupt
    fn allocate_irte(
        &self,
        _segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        vector: u8,
        dest_id: u32,
        logical: bool,
    ) -> Result<u16, IommuError> {
        let mut guard = self
            .interrupt_remap_table
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let irt = guard.as_mut().ok_or(IommuError::NotPresent)?;

        let index = irt.allocate().ok_or(IommuError::HardwareError)?;

        let rid = ((bus as u16) << 8) | ((device as u16) << 3) | (function as u16);
        let entry = InterruptRemapEntry::fixed(vector, dest_id, logical, Some(rid));
        irt.set(index, entry);

        // Security: Invalidate IEC after allocating IRTE to ensure hardware sees the new entry.
        // Propagation of invalidation errors is critical for security and consistency.
        if let Err(e) = self.invalidate_iec(false, index) {
            irt.set(index, InterruptRemapEntry::new());
            irt.free(index);
            return Err(e);
        }

        Ok(index)
    }
}
