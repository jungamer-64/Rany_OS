//! Interrupt-remapping RAM belongs to one hardware requester cohort.

use crate::cpu::ApicId;
use crate::io::iommu::common::tables::HardwareTable;
use crate::io::iommu::types::IommuError;

pub(super) const TABLE_LOG2: u8 = 9;
pub(super) const DTE_ROUTING_MASK: u64 = (0x000f_ffff_ffff_ffc0) | 0x1f | (3 << 60);
const ENTRIES: usize = 1 << TABLE_LOG2;

#[derive(Clone, Copy, Debug)]
pub(super) enum InterruptMode {
    Basic,
    X2Apic,
}

impl InterruptMode {
    pub(super) fn check_destination(self, destination: ApicId) -> Result<(), IommuError> {
        if matches!(self, Self::Basic) && u8::try_from(destination.as_u32()).is_err() {
            return Err(IommuError::NotSupported);
        }
        Ok(())
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug)]
struct ExtendedEntry {
    low: u64,
    high: u64,
}

// SAFETY: the all-zero entry disables remapping.
unsafe impl crate::mm::value::Zeroable for ExtendedEntry {}

#[derive(Debug)]
enum Entries {
    Basic(HardwareTable<u32>),
    X2Apic(HardwareTable<ExtendedEntry>),
}

#[derive(Debug)]
pub(super) struct InterruptTable {
    entries: Entries,
    allocations: [u64; ENTRIES / 64],
}

fn basic_entry(vector: u8, destination: u8, logical: bool) -> u32 {
    (u32::from(vector) << 16) | (u32::from(destination) << 8) | (u32::from(logical) << 6) | 1
}

fn extended_entry(vector: u8, destination: ApicId, logical: bool) -> ExtendedEntry {
    let destination = u64::from(destination.as_u32());
    ExtendedEntry {
        low: ((destination & 0xff_ffff) << 8) | (u64::from(logical) << 6) | 1,
        high: ((destination >> 24) << 56) | u64::from(vector),
    }
}

impl InterruptTable {
    pub(super) fn new(mode: InterruptMode) -> Result<Self, IommuError> {
        let entries = match mode {
            InterruptMode::Basic => Entries::Basic(HardwareTable::new(ENTRIES, None)?),
            InterruptMode::X2Apic => Entries::X2Apic(HardwareTable::new(ENTRIES, None)?),
        };
        Ok(Self {
            entries,
            allocations: [0; ENTRIES / 64],
        })
    }

    pub(super) fn dte_route(&self) -> u64 {
        let address = match &self.entries {
            Entries::Basic(entries) => entries.phys_addr(),
            Entries::X2Apic(entries) => entries.phys_addr(),
        };
        dte_route(address)
    }

    pub(super) fn install(
        &mut self,
        vector: u8,
        destination: ApicId,
        logical: bool,
    ) -> Result<u16, IommuError> {
        let (word_index, word) = self
            .allocations
            .iter_mut()
            .enumerate()
            .find(|(_, word)| **word != u64::MAX)
            .ok_or(IommuError::OutOfMemory)?;
        let bit = (!*word).trailing_zeros();
        let index = word_index * 64 + bit as usize;
        match &mut self.entries {
            Entries::Basic(entries) => {
                let destination =
                    u8::try_from(destination.as_u32()).map_err(|_| IommuError::NotSupported)?;
                let slot = entries.get_mut(index).expect("admitted IRTE range");
                // SAFETY: the binding owns the aligned word and the slot is retired.
                unsafe {
                    core::ptr::write_volatile(slot, basic_entry(vector, destination, logical))
                };
            }
            Entries::X2Apic(entries) => {
                let entry = extended_entry(vector, destination, logical);
                let slot = entries.get_mut(index).expect("admitted IRTE range");
                // SAFETY: the slot is retired. Publish the vector and upper
                // destination byte before setting RemapEn on the low word.
                unsafe { core::ptr::write_volatile(&mut slot.high, entry.high) };
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                unsafe { core::ptr::write_volatile(&mut slot.low, entry.low) };
            }
        }
        *word |= 1 << bit;
        Ok(index as u16)
    }

    pub(super) fn mask(&mut self, index: u16, vector: u8) -> Result<bool, IommuError> {
        let index = usize::from(index);
        if index >= ENTRIES {
            return Err(IommuError::InvalidAddress);
        }
        if self.allocations[index / 64] & (1 << (index % 64)) == 0 {
            return Ok(false);
        }
        // A different vector can own this slot after a later attachment.
        // Retain the matching vector while hardware completion is pending.
        match &mut self.entries {
            Entries::Basic(entries) => {
                let slot = entries.get_mut(index).expect("admitted IRTE range");
                let value = unsafe { core::ptr::read_volatile(slot) };
                if ((value >> 16) as u8) != vector {
                    return Ok(false);
                }
                unsafe { core::ptr::write_volatile(slot, value & !1) };
            }
            Entries::X2Apic(entries) => {
                let slot = entries.get_mut(index).expect("admitted IRTE range");
                let value = unsafe { core::ptr::read_volatile(&slot.high) };
                if (value as u8) != vector {
                    return Ok(false);
                }
                let low = unsafe { core::ptr::read_volatile(&slot.low) };
                unsafe { core::ptr::write_volatile(&mut slot.low, low & !1) };
            }
        }
        Ok(true)
    }

    pub(super) fn release(&mut self, index: u16) {
        let index = usize::from(index);
        self.allocations[index / 64] &= !(1 << (index % 64));
    }

    /// # Safety
    /// Every DTE pointing to this table has been replaced and its device and
    /// interrupt table caches have completed invalidation.
    pub(super) unsafe fn retire(self) {
        match self.entries {
            Entries::Basic(entries) => unsafe { entries.retire_after_invalidation() },
            Entries::X2Apic(entries) => unsafe { entries.retire_after_invalidation() },
        }
    }
}

fn dte_route(phys: u64) -> u64 {
    phys | (u64::from(TABLE_LOG2) << 1) | 1 | (0b10 << 60)
}

pub(super) fn encode_remap_msi(index: u16) -> (u64, u32) {
    (0xfee0_0000, u32::from(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn msi_message_carries_the_requester_table_index_in_data() {
        assert_eq!(encode_remap_msi(0), (0xfee0_0000, 0));
        assert_eq!(encode_remap_msi(0x1ff), (0xfee0_0000, 0x1ff));
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn dte_uses_requester_table_pointer_length_and_remapping_mode() {
        assert_eq!(dte_route(0x0001_2345_6789_a000), 0x2001_2345_6789_a013);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn basic_entry_encodes_fixed_vector_destination_and_mode() {
        assert_eq!(basic_entry(0x52, 0xab, true), 0x0052_ab41);
        assert_eq!(
            InterruptMode::Basic.check_destination(ApicId::new(0x100)),
            Err(IommuError::NotSupported)
        );
        let extended = extended_entry(0x52, ApicId::new(0x1234_5678), false);
        assert_eq!(
            (extended.low, extended.high),
            (0x3456_7801, 0x1200_0000_0000_0052)
        );
    }
}
