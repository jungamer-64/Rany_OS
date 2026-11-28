// ============================================================================
// kernel/src/io/iommu/vendors/amd/device_table.rs
// ============================================================================

//! AMD-Vi Device Table Entry and Device Table management.

use core::mem::size_of;
use core::ptr::NonNull;

use x86_64::PhysAddr;

use crate::mm::phys::frame_allocator::alloc_contiguous_frames;
use crate::mm::types::PAGE_SIZE_4K;
use crate::mm::virt::mapping::phys_to_virt;
use crate::sync::PoisonLock;

use super::AmdIommuUnit;
use super::registers::*;

use crate::io::iommu::types::IommuError;

pub(super) fn set_dte_bit(entry: &mut AmdDeviceTableEntry, bit: u8) {
    let idx = (bit >> 6) & 0x03;
    let shift = bit & 0x3f;
    entry.data[idx as usize] |= 1u64 << shift;
}

pub(super) fn apply_ivhd_flags(entry: &mut AmdDeviceTableEntry, flags: u8) {
    if (flags & IVHD_INIT_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_INIT_PASS);
    }
    if (flags & IVHD_EINT_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_EINT_PASS);
    }
    if (flags & IVHD_NMI_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_NMI_PASS);
    }
    if (flags & IVHD_SYSMGT1) != 0 {
        set_dte_bit(entry, DEV_ENTRY_SYSMGT1);
    }
    if (flags & IVHD_SYSMGT2) != 0 {
        set_dte_bit(entry, DEV_ENTRY_SYSMGT2);
    }
    if (flags & IVHD_LINT0_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_LINT0_PASS);
    }
    if (flags & IVHD_LINT1_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_LINT1_PASS);
    }
}

#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub(crate) struct AmdDeviceTableEntry {
    pub(super) data: [u64; 4],
}

impl AmdDeviceTableEntry {
    /// V=1 keeps DMA permission checks active even though Mode=0. With
    /// IR=IW=0 all memory requests abort; IV=1, IntCtl=0 also blocks MSI.
    pub(super) const BLOCKED: Self = Self {
        data: [DTE_FLAG_V | DTE_FLAG_TV, 0, 1, 0],
    };

    pub(super) fn translated(domain_id: u16, root: u64, flags: u8) -> Self {
        let mut entry = Self {
            data: [
                DTE_FLAG_V | DTE_FLAG_TV | DTE_FLAG_IR | DTE_FLAG_IW | root,
                u64::from(domain_id),
                0,
                0,
            ],
        };
        apply_ivhd_flags(&mut entry, flags);
        entry
    }

    pub(super) fn set_interrupt_table(&mut self, table: &super::irt::InterruptTable) {
        self.data[2] = (self.data[2] & !super::irt::DTE_ROUTING_MASK) | table.dte_route();
    }
}

#[derive(Debug)]
pub(crate) struct AmdDeviceTable {
    _backing: crate::mm::phys::frame_allocator::PhysicalAllocation,
    phys_base: u64,
    virt_base: NonNull<AmdDeviceTableEntry>,
    size_bytes: u64,
    entry_count: usize,
    lock: PoisonLock<()>,
}

// SAFETY: AmdDeviceTable contains raw pointers to a contiguous region of kernel memory
// which is accessed with proper synchronization using `lock`. It is therefore safe to
// treat the structure as `Send` and `Sync` across threads.
unsafe impl Send for AmdDeviceTable {}
unsafe impl Sync for AmdDeviceTable {}

impl AmdDeviceTable {
    pub(super) fn new(_segment: u16, entry_count: usize) -> Result<Self, IommuError> {
        if entry_count == 0 {
            return Err(IommuError::InvalidAddress);
        }

        debug_assert_eq!(size_of::<AmdDeviceTableEntry>(), DEV_TABLE_ENTRY_SIZE);

        let entry_bytes = size_of::<AmdDeviceTableEntry>() as u64;
        let mut size_bytes = (entry_count as u64)
            .checked_mul(entry_bytes)
            .ok_or(IommuError::InvalidAddress)?;
        if size_bytes < (PAGE_SIZE_4K as u64) {
            size_bytes = PAGE_SIZE_4K as u64;
        }
        size_bytes = size_bytes.next_power_of_two();

        let frame_count = (size_bytes / (PAGE_SIZE_4K as u64)) as usize;
        let phys_base =
            alloc_contiguous_frames(frame_count).map_err(|_| IommuError::OutOfMemory)?;
        let virt_base = phys_to_virt(PhysAddr::new(phys_base.as_u64()));
        let entry_ptr = NonNull::new(virt_base.as_u64() as *mut AmdDeviceTableEntry)
            .ok_or(IommuError::HardwareError)?;

        let entry_count = (size_bytes / entry_bytes) as usize;
        for index in 0..entry_count {
            unsafe {
                entry_ptr
                    .as_ptr()
                    .add(index)
                    .write(AmdDeviceTableEntry::BLOCKED)
            };
        }

        // Security: Register the device table as protected from DMA.
        // This prevents malicious devices from tampering with their own domain/IRT assignments.
        crate::io::iommu::runtime::security::register_protected_region(
            phys_base.as_u64(),
            size_bytes,
            "AMD-Vi Device Table",
        );

        Ok(Self {
            phys_base: phys_base.as_u64(),
            _backing: phys_base,
            virt_base: entry_ptr,
            size_bytes,
            entry_count,
            lock: PoisonLock::new(()),
        })
    }

    pub(super) fn program(&self, unit: &AmdIommuUnit) -> Result<(), IommuError> {
        if (self.phys_base & 0xfff) != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        let size_field = (self.size_bytes >> 12).saturating_sub(1);
        let entry = (self.phys_base & !0xfff) | size_field;
        unit.registers.program_device_table(entry);
        Ok(())
    }

    /// The caller serializes ownership changes for this requester cohort.
    /// Validate every index before modifying any DTE.
    pub(super) fn write_requesters(
        &self,
        requesters: &[u16],
        entry: AmdDeviceTableEntry,
    ) -> Result<(), IommuError> {
        let _guard = self.lock.lock().map_err(|_| IommuError::Poisoned)?;
        if requesters
            .iter()
            .any(|&id| usize::from(id) >= self.entry_count)
        {
            return Err(IommuError::DeviceNotFound);
        }
        for &id in requesters {
            let words = unsafe { self.virt_base.as_ptr().add(usize::from(id)).cast::<u64>() };
            // Disable memory access before modifying a live entry. Publish
            // the new permissions last, after domain and interrupt fields.
            unsafe {
                words.write_volatile(AmdDeviceTableEntry::BLOCKED.data[0]);
                for (index, value) in entry.data.iter().copied().enumerate().skip(1) {
                    words.add(index).write_volatile(value);
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                words.write_volatile(entry.data[0]);
            }
        }
        Ok(())
    }

    pub(super) fn write_interrupt_routes(
        &self,
        requesters: &[u16],
        table: &super::irt::InterruptTable,
    ) -> Result<(), IommuError> {
        let _guard = self.lock.lock().map_err(|_| IommuError::Poisoned)?;
        if requesters
            .iter()
            .any(|&id| usize::from(id) >= self.entry_count)
        {
            return Err(IommuError::DeviceNotFound);
        }
        for &id in requesters {
            // SAFETY: the device-table lock owns all writes to these entries.
            unsafe {
                let word = self
                    .virt_base
                    .as_ptr()
                    .add(usize::from(id))
                    .cast::<u64>()
                    .add(2);
                let previous = word.read_volatile() & !super::irt::DTE_ROUTING_MASK;
                word.write_volatile(previous | table.dte_route());
            }
        }
        Ok(())
    }

    pub(super) fn fill(&self, entry: AmdDeviceTableEntry) -> Result<(), IommuError> {
        let _guard = self.lock.lock().map_err(|_| IommuError::Poisoned)?;
        for idx in 0..self.entry_count {
            unsafe {
                self.virt_base.as_ptr().add(idx).write_volatile(entry);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AmdDeviceTableEntry;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn blocked_dte_keeps_permission_checks_and_aborts_fixed_interrupts() {
        assert_eq!(AmdDeviceTableEntry::BLOCKED.data, [0x3, 0, 0x1, 0]);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn translated_requester_disallows_ats_and_pretranslated_dma() {
        let entry = AmdDeviceTableEntry::translated(0x734, 0x2800, 0);
        assert_eq!(entry.data, [0x6000_0000_0000_2803, 0x734, 0, 0]);
    }
}
