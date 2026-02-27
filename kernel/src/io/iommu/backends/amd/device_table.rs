// ============================================================================
// kernel/src/io/iommu/backends/amd/device_table.rs
// ============================================================================

//! AMD-Vi Device Table Entry and Device Table management.

use core::mem::size_of;
use core::ptr::{self, NonNull};

use x86_64::PhysAddr;

use crate::io::iommu::core::tables::phys_to_virt_usize;
use crate::mm::types::PAGE_SIZE_4K;
use crate::io::mmio::mmio_write_u64;
use crate::mm::phys::frame_allocator::alloc_contiguous_frames;
use crate::mm::virt::mapping::phys_to_virt;
use crate::sync::PoisonLock;

use super::registers::*;
use super::AmdIommuUnit;

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

impl Default for AmdDeviceTableEntry {
    fn default() -> Self {
        Self { data: [0; 4] }
    }
}

#[derive(Debug)]
pub(crate) struct AmdDeviceTable {
    pub(super) segment: u16,
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
    pub(super) fn new(segment: u16, entry_count: usize) -> Result<Self, IommuError> {
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
            alloc_contiguous_frames(frame_count).ok_or(IommuError::OutOfMemory)?;
        let virt_base = phys_to_virt(PhysAddr::new(phys_base.as_u64()));
        let entry_ptr = NonNull::new(virt_base.as_u64() as *mut AmdDeviceTableEntry)
            .ok_or(IommuError::HardwareError)?;

        unsafe {
            ptr::write_bytes(virt_base.as_u64() as *mut u8, 0, size_bytes as usize);
        }

        // Security: Register the device table as protected from DMA.
        // This prevents malicious devices from tampering with their own domain/IRT assignments.
        crate::io::iommu::runtime::security::register_protected_region(
            phys_base.as_u64(),
            size_bytes,
            "AMD-Vi Device Table",
        );

        Ok(Self {
            segment,
            phys_base: phys_base.as_u64(),
            virt_base: entry_ptr,
            size_bytes,
            entry_count: (size_bytes / entry_bytes) as usize,
            lock: PoisonLock::new(()),
        })
    }

    pub(super) fn program(&self, unit: &AmdIommuUnit) -> Result<(), IommuError> {
        if (self.phys_base & 0xfff) != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        let size_field = (self.size_bytes >> 12).saturating_sub(1);
        let entry = (self.phys_base & !0xfff) | size_field;
        let mmio_base = phys_to_virt_usize(unit.base_addr);
        mmio_write_u64(mmio_base + MMIO_DEV_TABLE_OFFSET as usize, entry);
        Ok(())
    }

    pub(super) fn write_entry(&self, devid: u16, entry: AmdDeviceTableEntry) -> Result<(), IommuError> {
        let _guard = self.lock.lock().map_err(|_| IommuError::Poisoned)?;
        let index = devid as usize;
        if index >= self.entry_count {
            return Err(IommuError::DeviceNotFound);
        }
        unsafe {
            self.virt_base.as_ptr().add(index).write_volatile(entry);
        }
        Ok(())
    }

    pub(super) fn clear_entry(&self, devid: u16) -> Result<(), IommuError> {
        self.write_entry(devid, AmdDeviceTableEntry::default())
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
