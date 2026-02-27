// ============================================================================
// kernel/src/io/iommu/amd/event_log.rs
// ============================================================================

//! AMD-Vi Event Log ring buffer structures.

use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::PhysAddr;

use crate::io::iommu::core::tables::phys_to_virt_usize;
use crate::mm::types::PAGE_SIZE_4K;
use crate::io::mmio::{mmio_write_u32, mmio_write_u64};
use crate::mm::phys::frame_allocator::alloc_contiguous_frames;
use crate::mm::virt::mapping::phys_to_virt;

use super::registers::*;
use super::AmdIommuUnit;

use crate::io::iommu::types::IommuError;

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct AmdEventEntry {
    pub(super) data: [u32; 4],
}

impl AmdEventEntry {
    pub(super) fn event_type(&self) -> u8 {
        ((self.data[1] >> EVENT_TYPE_SHIFT) & EVENT_TYPE_MASK) as u8
    }

    pub(super) fn devid(&self) -> u16 {
        ((self.data[0] >> EVENT_DEVID_SHIFT) & EVENT_DEVID_MASK) as u16
    }

    pub(super) fn domain_id(&self) -> u32 {
        (self.data[0] & EVENT_DOMID_MASK_HI) | (self.data[1] & EVENT_DOMID_MASK_LO)
    }

    pub(super) fn flags(&self) -> u16 {
        ((self.data[1] >> EVENT_FLAGS_SHIFT) & EVENT_FLAGS_MASK) as u16
    }

    pub(super) fn address(&self) -> u64 {
        ((self.data[3] as u64) << 32) | (self.data[2] as u64)
    }
}

#[derive(Debug)]
pub(crate) struct AmdEventLog {
    phys_base: u64,
    virt_base: NonNull<u32>,
    size_bytes: u64,
    processing: AtomicBool,
}

// SAFETY: AmdEventLog holds a stable buffer pointer accessed via atomics and MMIO.
unsafe impl Send for AmdEventLog {}
unsafe impl Sync for AmdEventLog {}

impl AmdEventLog {
    pub(super) fn new() -> Result<Self, IommuError> {
        let size_bytes = EVT_BUFFER_BYTES as u64;
        let frame_count = (size_bytes / (PAGE_SIZE_4K as u64)) as usize;
        let phys_base =
            alloc_contiguous_frames(frame_count).ok_or(IommuError::OutOfMemory)?;
        let virt_base = phys_to_virt(PhysAddr::new(phys_base.as_u64()));
        let entry_ptr =
            NonNull::new(virt_base.as_u64() as *mut u32).ok_or(IommuError::HardwareError)?;

        unsafe {
            ptr::write_bytes(virt_base.as_u64() as *mut u8, 0, size_bytes as usize);
        }

        Ok(Self {
            phys_base: phys_base.as_u64(),
            virt_base: entry_ptr,
            size_bytes,
            processing: AtomicBool::new(false),
        })
    }

    pub(super) fn program(&self, unit: &AmdIommuUnit) -> Result<(), IommuError> {
        if (self.phys_base & 0xfff) != 0 {
            return Err(IommuError::InvalidAlignment);
        }
        if self.size_bytes != EVT_BUFFER_BYTES as u64 {
            return Err(IommuError::NotSupported);
        }

        let entry = (self.phys_base & !0xfff) | EVT_BUFFER_SIZE_MASK;
        let mmio_base = phys_to_virt_usize(unit.base_addr);
        mmio_write_u64(mmio_base + MMIO_EVT_BUF_OFFSET as usize, entry);
        mmio_write_u32(mmio_base + MMIO_EVT_HEAD_OFFSET as usize, 0);
        mmio_write_u32(mmio_base + MMIO_EVT_TAIL_OFFSET as usize, 0);
        Ok(())
    }

    pub(super) fn try_lock(&self) -> Option<AmdEventLogGuard<'_>> {
        if self
            .processing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(AmdEventLogGuard { log: self })
        } else {
            None
        }
    }

    pub(super) fn read_entry(&self, offset: u32) -> Option<AmdEventEntry> {
        let offset_end = offset as u64 + EVENT_ENTRY_SIZE as u64;
        if offset_end > self.size_bytes {
            return None;
        }
        let base = self.virt_base.as_ptr() as *const u8;
        let ptr = unsafe { base.add(offset as usize) as *const u32 };
        let mut data = [0u32; 4];
        for idx in 0..4 {
            data[idx] = unsafe { ptr.add(idx).read_volatile() };
        }
        Some(AmdEventEntry { data })
    }
}

pub(super) struct AmdEventLogGuard<'a> {
    log: &'a AmdEventLog,
}

impl Drop for AmdEventLogGuard<'_> {
    fn drop(&mut self) {
        self.log.processing.store(false, Ordering::Release);
    }
}
