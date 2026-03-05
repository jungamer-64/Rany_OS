// ============================================================================
// kernel/src/io/iommu/vendors/amd/cmd.rs
// ============================================================================

// AMD-Vi command buffer and IOTLB invalidation helpers (skeleton).

#![allow(dead_code)]

use core::mem::size_of;
use core::ptr::NonNull;

use crate::io::iommu::types::{DeviceId, IommuError};
use crate::io::iommu::runtime::command::queue::IommuCommandKind;
use crate::io::mmio::{mmio_read_u32, mmio_read_u64, mmio_write_u32, mmio_write_u64};

use super::AmdIommuDriver;

impl AmdIommuDriver {
    pub(crate) fn handle_command_queue_entry(&self, kind: &IommuCommandKind) -> Result<i32, ()> {
        match kind {
            IommuCommandKind::MapRegionDevice {
                device,
                iova,
                phys,
                size,
                read,
                write,
            } => self.handle_map_region_device(*device, *iova, *phys, *size, *read, *write),
            IommuCommandKind::UnmapRegionDevice { device, iova, size: _ } => {
                self.handle_unmap_region_device(*device, *iova)
            }
            IommuCommandKind::InvalidateIotlbGlobal => {
                if self.invalidate_all_entries().is_ok() {
                    Ok(0)
                } else {
                    Err(())
                }
            }
            IommuCommandKind::InvalidateIotlbDomain { .. } => Err(()),
            IommuCommandKind::MapRegion { .. } => Err(()),
            IommuCommandKind::UnmapRegion { .. } => Err(()),
        }
    }

    /// Validate alignment and excluded ranges for a map region request.
    /// On failure, frees the IOVA and returns Err.
    fn validate_map_region_params(
        &self,
        device: DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
    ) -> Result<(), ()> {
        let align = crate::mm::types::PAGE_SIZE_4K as u64;
        if (iova & (align - 1) != 0)
            || (phys & (align - 1) != 0)
            || (size & (align - 1) != 0)
        {
            let _ = self.free_iova_fast(iova, size);
            return Err(());
        }

        // Security: Validate that the physical range does not overlap with the kernel image.
        if crate::io::iommu::runtime::security::validate_dma_region(phys, size).is_err() {
            let _ = self.free_iova_fast(iova, size);
            return Err(());
        }

        if self.reject_excluded_ivmd_range(device, phys, size).is_err() {
            let _ = self.free_iova_fast(iova, size);
            return Err(());
        }
        Ok(())
    }

    /// マップと無効化を実行する
    fn execute_map_and_invalidate(
        &self,
        device: DeviceId,
        domain_id: u16,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<i32, ()> {
        let domain = self.domain_for_id(domain_id).map_err(|_| {
            let _ = self.free_iova_fast(iova, size);
        })?;

        if let Err(err) = domain.map(iova, phys, size, read, write) {
            if err != IommuError::AlreadyMapped && err != IommuError::Poisoned {
                let _ = self.free_iova_fast(iova, size);
            }
            return Err(());
        }

        self.invalidate_domain_pages(domain_id, iova, size).map_err(|_| ())?;
        self.invalidate_domain_device_tlbs(domain_id, Some(iova), Some(size)).map_err(|_| ())?;

        Ok(0)
    }

    /// Handle MapRegionDevice: validate, map, and invalidate.
    fn handle_map_region_device(
        &self,
        device: DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<i32, ()> {
        if size == 0 {
            return Err(());
        }
        self.validate_map_region_params(device, iova, phys, size)?;

        let domain_id = self.domain_id_for_device(device).map_err(|_| {
            let _ = self.free_iova_fast(iova, size);
        })?;

        self.execute_map_and_invalidate(device, domain_id, iova, phys, size, read, write)
    }

    /// Handle UnmapRegionDevice: unmap, invalidate, and free IOVA.
    fn handle_unmap_region_device(
        &self,
        device: DeviceId,
        iova: u64,
    ) -> Result<i32, ()> {
        let domain_id = self.domain_id_for_device(device).map_err(|_| ())?;
        let domain = self.domain_for_id(domain_id).map_err(|_| ())?;

        // 1. Monitor page table releases to detect if paging-structure caches need clearing
        let pts_before = domain.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);

        let mapping = domain.unmap(iova).map_err(|_| ())?;

        let pts_after = domain.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
        let pt_removed = pts_after > pts_before;

        // 2. Invalidate IOMMU
        if pt_removed {
            // SECURITY: If a page table was removed, we MUST perform a domain-wide
            // invalidation to clear cached paging-structure entries (Level 2/3/4 caches).
            // Page-selective invalidation with PDE=1 is intended to clear structures for the
            // specified range, but a domain-wide flush is the safest way to ensure no
            // stale paging structure references remain.
            if let Err(err) = self.invalidate_domain_pages(domain_id, 0, u64::MAX) {
                log::error!("[IOMMU][AMD-Vi] handle_unmap_region_device domain-wide invalidation failed: {:?}. Poisoning domain.", err);
                domain.poison();
                return Err(());
            }
        } else {
            if let Err(err) = self.invalidate_domain_pages(domain_id, iova, mapping.size) {
                log::error!("[IOMMU][AMD-Vi] handle_unmap_region_device IOMMU invalidation failed: {:?}. Poisoning domain.", err);
                domain.poison();
                return Err(());
            }
        }

        if let Err(err) = self.invalidate_domain_device_tlbs(domain_id, Some(iova), Some(mapping.size)) {
            log::error!("[IOMMU][AMD-Vi] handle_unmap_region_device IOTLB invalidation failed: {:?}. Poisoning domain.", err);
            domain.poison();
            return Err(());
        }

        // 3. Reclaim released page tables if any
        if pt_removed {
            let _ = domain.flush(self, self);
        }

        let _ = self.free_iova_fast(iova, mapping.size);
        Ok(0)
    }
}

const MMIO_CMD_BUF_OFFSET: u64 = 0x0008;
const MMIO_CONTROL_OFFSET: u64 = 0x0018;
const MMIO_CMD_HEAD_OFFSET: u64 = 0x2000;
const MMIO_CMD_TAIL_OFFSET: u64 = 0x2008;

const CONTROL_CMDBUF_EN: u64 = 1 << 12;

pub(crate) const CMD_BUFFER_BYTES: usize = 8192;
pub(crate) const CMD_BUFFER_ENTRIES: usize = 512;
const CMD_ENTRY_SIZE: u32 = 16;

const MMIO_CMD_SIZE_SHIFT: u64 = 56;
const MMIO_CMD_SIZE_512: u64 = 0x9 << MMIO_CMD_SIZE_SHIFT;
const MMIO_CMD_PTR_MASK: u64 = 0x7fff0;

const CMD_COMPL_WAIT: u8 = 0x01;
const CMD_INV_DEV_ENTRY: u8 = 0x02;
const CMD_INV_IOMMU_PAGES: u8 = 0x03;
const CMD_INV_IOTLB_PAGES: u8 = 0x04;
const CMD_INV_IRT: u8 = 0x05;
const CMD_COMPLETE_PPR: u8 = 0x07;
const CMD_INV_ALL: u8 = 0x08;

const CMD_COMPL_WAIT_STORE_MASK: u32 = 0x01;
const CMD_COMPL_WAIT_INT_MASK: u32 = 0x02;
const CMD_INV_IOMMU_PAGES_SIZE_MASK: u64 = 0x01;
const CMD_INV_IOMMU_PAGES_PDE_MASK: u32 = 0x02;
const CMD_INV_IOMMU_PAGES_GN_MASK: u32 = 0x04;
const CMD_INV_IOMMU_ALL_PAGES_ADDRESS: u64 = 0x7fff_ffff_ffff_ffff;

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug)]
pub struct AmdCommand {
    pub data: [u32; 4],
}

impl AmdCommand {
    pub const fn zero() -> Self {
        Self { data: [0; 4] }
    }

    fn set_type(&mut self, cmd_type: u8) {
        self.data[1] |= (cmd_type as u32) << 28;
    }

    pub fn completion_wait(store_phys: u64, data: u64, interrupt: bool) -> Self {
        let mut cmd = Self::zero();
        cmd.data[0] = lower32(store_phys) | CMD_COMPL_WAIT_STORE_MASK;
        cmd.data[1] = upper32(store_phys);
        cmd.data[2] = lower32(data);
        cmd.data[3] = upper32(data);
        if interrupt {
            cmd.data[0] |= CMD_COMPL_WAIT_INT_MASK;
        }
        cmd.set_type(CMD_COMPL_WAIT);
        cmd
    }

    pub fn invalidate_device_entry(device_id: u16) -> Self {
        let mut cmd = Self::zero();
        cmd.data[0] = device_id as u32;
        cmd.set_type(CMD_INV_DEV_ENTRY);
        cmd
    }

    pub fn invalidate_iommu_pages(
        domain_id: u16,
        address: u64,
        size: u64,
        pasid: Option<u32>,
    ) -> Self {
        let inv_address = build_inv_address(address, size);
        let mut cmd = Self::zero();
        cmd.data[1] |= domain_id as u32;
        cmd.data[2] = lower32(inv_address) | CMD_INV_IOMMU_PAGES_PDE_MASK;
        cmd.data[3] = upper32(inv_address);
        if let Some(pasid) = pasid {
            cmd.data[0] |= pasid;
            cmd.data[2] |= CMD_INV_IOMMU_PAGES_GN_MASK;
        }
        cmd.set_type(CMD_INV_IOMMU_PAGES);
        cmd
    }

    pub fn invalidate_iotlb_pages(
        device_id: u16,
        qdep: u8,
        address: u64,
        size: u64,
        pasid: Option<u32>,
    ) -> Self {
        let inv_address = build_inv_address(address, size);
        let mut cmd = Self::zero();
        cmd.data[0] = device_id as u32 | ((qdep as u32) << 24);
        // DW1 bits [27:0] are reserved when GN=0; do not write device_id here.
        // set_type() will OR the command type into DW1[31:28].
        cmd.data[2] = lower32(inv_address);
        cmd.data[3] = upper32(inv_address);
        if let Some(pasid) = pasid {
            // AMD-Vi Spec §2.4.3 with GN=1:
            //   DW0[23:16] = PASID[19:12] (8 bits)
            //   DW1[27:16] = PASID[11:0] (12 bits)
            cmd.data[0] |= ((pasid >> 12) & 0xFF) << 16;
            cmd.data[1] |= (pasid & 0xFFF) << 16;
            cmd.data[2] |= CMD_INV_IOMMU_PAGES_GN_MASK;
        }
        cmd.set_type(CMD_INV_IOTLB_PAGES);
        cmd
    }

    pub fn invalidate_all() -> Self {
        let mut cmd = Self::zero();
        cmd.set_type(CMD_INV_ALL);
        cmd
    }

    pub fn invalidate_interrupt_table(device_id: u16) -> Self {
        let mut cmd = Self::zero();
        cmd.data[0] = device_id as u32;
        cmd.set_type(CMD_INV_IRT);
        cmd
    }
}

pub struct AmdCommandBuffer {
    pub(crate) mmio_base: u64,
    pub(crate) phys_base: u64,
    pub(crate) entries: NonNull<AmdCommand>,
    pub(crate) entry_count: usize,
    pub(crate) buffer_bytes: u32,
    pub(crate) tail: u32,
}

impl core::fmt::Debug for AmdCommandBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AmdCommandBuffer")
            .field("phys_base", &self.phys_base)
            .field("entry_count", &self.entry_count)
            .field("tail", &self.tail)
            .finish()
    }
}

unsafe impl Send for AmdCommandBuffer {}
unsafe impl Sync for AmdCommandBuffer {}

impl AmdCommandBuffer {
    pub unsafe fn new(
        mmio_base: u64,
        phys_base: u64,
        virt_base: NonNull<AmdCommand>,
        entry_count: usize,
    ) -> Result<Self, IommuError> {
        if entry_count == 0 {
            return Err(IommuError::InvalidAddress);
        }
        let bytes = size_of::<AmdCommand>()
            .checked_mul(entry_count)
            .ok_or(IommuError::InvalidAddress)?;
        if bytes > CMD_BUFFER_BYTES {
            return Err(IommuError::InvalidAddress);
        }

        Ok(Self {
            mmio_base,
            phys_base,
            entries: virt_base,
            entry_count,
            buffer_bytes: bytes as u32,
            tail: 0,
        })
    }

    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    pub unsafe fn program(&self) -> Result<(), IommuError> {
        if self.entry_count != CMD_BUFFER_ENTRIES {
            return Err(IommuError::NotSupported);
        }
        if (self.phys_base & 0xfff) != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        let base = (self.phys_base & !0xfff) | MMIO_CMD_SIZE_512;
        mmio_write_u64((self.mmio_base + MMIO_CMD_BUF_OFFSET) as usize, base);
        mmio_write_u32((self.mmio_base + MMIO_CMD_TAIL_OFFSET) as usize, 0);
        Ok(())
    }

    pub unsafe fn enable(&self) {
        let mut control = mmio_read_u64((self.mmio_base + MMIO_CONTROL_OFFSET) as usize);
        control |= CONTROL_CMDBUF_EN;
        mmio_write_u64((self.mmio_base + MMIO_CONTROL_OFFSET) as usize, control);
    }

    pub unsafe fn disable(&self) {
        let mut control = mmio_read_u64((self.mmio_base + MMIO_CONTROL_OFFSET) as usize);
        control &= !CONTROL_CMDBUF_EN;
        mmio_write_u64((self.mmio_base + MMIO_CONTROL_OFFSET) as usize, control);
    }

    pub fn submit(&mut self, cmd: AmdCommand) -> Result<u32, IommuError> {
        if self.buffer_bytes == 0 {
            return Err(IommuError::InvalidAddress);
        }
        let head = self.read_head();
        let next_tail = (self.tail + CMD_ENTRY_SIZE) % self.buffer_bytes;
        if next_tail == head {
            return Err(IommuError::OutOfMemory);
        }

        let index = (self.tail / CMD_ENTRY_SIZE) as usize;
        if index >= self.entry_count {
            return Err(IommuError::InvalidAddress);
        }

        unsafe {
            self.entries.as_ptr().add(index).write(cmd);
        }
        self.tail = next_tail;
        self.write_tail(self.tail);
        Ok(self.tail)
    }

    fn read_head(&self) -> u32 {
        let head = mmio_read_u32((self.mmio_base + MMIO_CMD_HEAD_OFFSET) as usize) as u64;
        (head & MMIO_CMD_PTR_MASK) as u32
    }

    fn write_tail(&self, tail: u32) {
        mmio_write_u32((self.mmio_base + MMIO_CMD_TAIL_OFFSET) as usize, tail);
    }
}

fn build_inv_address(address: u64, size: u64) -> u64 {
    let page_size = crate::mm::types::PAGE_SIZE_4K;
    if size <= (page_size as u64) {
        return address & !0xfff;
    }

    let end = address.saturating_add(size.saturating_sub(1));
    let diff = end ^ address;
    let msb = 63 - diff.leading_zeros() as u64;

    let mut inv = if msb > 51 {
        CMD_INV_IOMMU_ALL_PAGES_ADDRESS
    } else {
        address | ((1u64 << msb) - 1)
    };

    inv &= !0xfff;
    inv | CMD_INV_IOMMU_PAGES_SIZE_MASK
}

#[inline]
fn lower32(value: u64) -> u32 {
    value as u32
}

#[inline]
fn upper32(value: u64) -> u32 {
    (value >> 32) as u32
}
