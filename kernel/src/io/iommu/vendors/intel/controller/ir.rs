// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/ir.rs
// ============================================================================

//! Interrupt Remapping Methods
//!
//! This module contains interrupt remapping methods for `IommuController` via `InterruptRemapper` trait.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::IommuController;
use super::qi_ops::InvalidationOps;
use crate::cpu::ApicId;
use crate::io::iommu::common::tables::{HardwareTable, Zeroable};
use crate::io::iommu::types::IommuError;

const INTERRUPT_REMAP_ENTRY_COUNT: usize = 256;
const INTERRUPT_REMAP_TABLE_SIZE_ENCODING: u64 = 7;
const IRTA_EXTENDED_INTERRUPT_MODE: u64 = 1 << 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InterruptRemapMode {
    XApic,
    X2Apic,
}

impl InterruptRemapMode {
    const fn is_extended(self) -> bool {
        matches!(self, Self::X2Apic)
    }

    const fn supports_destination(self, destination: u32) -> bool {
        self.is_extended() || destination <= u8::MAX as u32
    }
}

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
        destination: ApicId,
        logical: bool,
        sid: Option<u16>, // RID/BDF
        mode: InterruptRemapMode,
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
        // DestID (bits 63:32). In xAPIC mode the 8-bit destination occupies
        // bits 47:40; extended mode consumes the full 32-bit field.
        let destination = match mode {
            InterruptRemapMode::XApic => destination.as_u32() << 8,
            InterruptRemapMode::X2Apic => destination.as_u32(),
        };
        lo |= u64::from(destination) << 32;

        let mut hi = 0;
        if let Some(rid) = sid {
            // SQ=0 (Source-id Qualifier: exact match), bits 17:16 of hi.
            // SVT=1 (Source Validation Type: verify SID), bits 19:18 of hi.
            hi |= 1 << 18;
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
    fn new() -> Result<Self, IommuError> {
        Ok(Self {
            table: HardwareTable::new(INTERRUPT_REMAP_ENTRY_COUNT, None)?,
            bitmap: alloc::vec![0; INTERRUPT_REMAP_ENTRY_COUNT.div_ceil(u64::BITS as usize)],
        })
    }

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

fn interrupt_remap_table_address(
    physical_address: u64,
    mode: InterruptRemapMode,
) -> Result<u64, IommuError> {
    if !physical_address.is_multiple_of(4096) {
        return Err(IommuError::InvalidAlignment);
    }
    Ok(physical_address
        | INTERRUPT_REMAP_TABLE_SIZE_ENCODING
        | if mode.is_extended() {
            IRTA_EXTENDED_INTERRUPT_MODE
        } else {
            0
        })
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
        destination: ApicId,
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
        destination: ApicId,
        logical: bool,
    ) -> Result<u16, IommuError> {
        if !self.is_interrupt_remapping_enabled() {
            return Err(IommuError::NotSupported);
        }
        let mode = if self.ir_extended_mode.load(Ordering::Acquire) {
            InterruptRemapMode::X2Apic
        } else {
            InterruptRemapMode::XApic
        };
        if !mode.supports_destination(destination.as_u32()) {
            return Err(IommuError::NotSupported);
        }
        let mut guard = self
            .interrupt_remap_table
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let irt = guard.as_mut().ok_or(IommuError::NotPresent)?;

        let index = irt.allocate().ok_or(IommuError::HardwareError)?;

        let rid = ((bus as u16) << 8) | ((device as u16) << 3) | (function as u16);
        let entry = InterruptRemapEntry::fixed(vector, destination, logical, Some(rid), mode);
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

impl IommuController {
    pub(crate) fn supports_interrupt_remapping(&self) -> bool {
        self.ecap & crate::io::iommu::vendors::intel::registers::ecap_bits::ECAP_IR != 0
    }

    pub(crate) fn supports_extended_interrupt_mode(&self) -> bool {
        self.ecap & crate::io::iommu::vendors::intel::registers::ecap_bits::ECAP_EIM != 0
    }

    pub(crate) fn prepare_interrupt_remapping(
        &mut self,
        mode: InterruptRemapMode,
    ) -> Result<(), IommuError> {
        if !self.supports_interrupt_remapping() || !self.is_queued_invalidation_enabled() {
            return Err(IommuError::NotSupported);
        }
        if mode.is_extended() && !self.supports_extended_interrupt_mode() {
            return Err(IommuError::NotSupported);
        }

        let table = InterruptRemapTable::new()?;
        let mut slot = self
            .interrupt_remap_table
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        if slot.is_some() {
            return Err(IommuError::AlreadyInitialized);
        }
        *slot = Some(table);
        self.ir_extended_mode
            .store(mode.is_extended(), Ordering::Release);
        Ok(())
    }

    pub(crate) unsafe fn enable_interrupt_remapping(&self) -> Result<(), IommuError> {
        if self.is_interrupt_remapping_enabled() {
            return Ok(());
        }
        if !self.is_queued_invalidation_enabled() {
            return Err(IommuError::NotSupported);
        }

        let mode = if self.ir_extended_mode.load(Ordering::Acquire) {
            InterruptRemapMode::X2Apic
        } else {
            InterruptRemapMode::XApic
        };
        let table_address = {
            let table = self
                .interrupt_remap_table
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            let table = table.as_ref().ok_or(IommuError::NotInitialized)?;
            interrupt_remap_table_address(table.table.phys_addr(), mode)?
        };

        use crate::io::iommu::vendors::intel::controller::utils::IommuUtils;
        use crate::io::iommu::vendors::intel::registers::{gcmd_bits, gsts_bits, regs};

        self.write64(regs::IRTA, table_address);
        self.write_gcmd_with_state(gcmd_bits::GCMD_SIRTP);
        self.wait_for_condition(
            || self.read32(regs::GSTS) & gsts_bits::GSTS_IRTPS != 0,
            100_000,
            false,
        )?;
        self.invalidate_iec(true, 0)?;

        self.write_gcmd_with_state(gcmd_bits::GCMD_IRE);
        self.wait_for_condition(
            || self.read32(regs::GSTS) & gsts_bits::GSTS_IRES != 0,
            100_000,
            false,
        )?;
        self.ir_enabled.store(true, Ordering::Release);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irta_encodes_table_size_and_destination_mode() {
        assert_eq!(
            interrupt_remap_table_address(0x1234_5000, InterruptRemapMode::XApic),
            Ok(0x1234_5007)
        );
        assert_eq!(
            interrupt_remap_table_address(0x1234_5000, InterruptRemapMode::X2Apic),
            Ok(0x1234_5807)
        );
    }

    #[test]
    fn irta_rejects_misaligned_table() {
        assert_eq!(
            interrupt_remap_table_address(0x1234_5001, InterruptRemapMode::X2Apic),
            Err(IommuError::InvalidAlignment)
        );
    }

    #[test]
    fn irte_preserves_full_x2apic_destination() {
        let entry = InterruptRemapEntry::fixed(
            0x40,
            ApicId::new(0xfedc_ba98),
            false,
            None,
            InterruptRemapMode::X2Apic,
        );
        assert_eq!(entry.lo >> 32, 0xfedc_ba98);
    }

    #[test]
    fn irte_places_xapic_destination_and_source_validation_fields() {
        let entry = InterruptRemapEntry::fixed(
            0x41,
            ApicId::new(0x5a),
            false,
            Some(0x1234),
            InterruptRemapMode::XApic,
        );
        assert_eq!(entry.lo >> 32, 0x5a00);
        assert_eq!(entry.hi & 0xffff, 0x1234);
        assert_eq!((entry.hi >> 16) & 0b11, 0);
        assert_eq!((entry.hi >> 18) & 0b11, 1);
    }

    #[test]
    fn destination_width_follows_interrupt_remap_mode() {
        assert!(InterruptRemapMode::XApic.supports_destination(255));
        assert!(!InterruptRemapMode::XApic.supports_destination(256));
        assert!(InterruptRemapMode::X2Apic.supports_destination(u32::MAX));
    }
}
