// ============================================================================
// kernel/src/io/iommu/amd/cmd.rs
// ============================================================================

// AMD-Vi command buffer and IOTLB invalidation helpers (skeleton).

#![allow(dead_code)]

use core::mem::size_of;
use core::ptr::NonNull;

use crate::io::iommu::types::IommuError;
use crate::io::mmio::{mmio_read_u32, mmio_read_u64, mmio_write_u32, mmio_write_u64};

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
        cmd.data[1] = device_id as u32;
        cmd.data[2] = lower32(inv_address);
        cmd.data[3] = upper32(inv_address);
        if let Some(pasid) = pasid {
            cmd.data[0] |= ((pasid >> 8) & 0xff) << 16;
            cmd.data[1] |= (pasid & 0xff) << 16;
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
    mmio_base: u64,
    phys_base: u64,
    entries: NonNull<AmdCommand>,
    entry_count: usize,
    buffer_bytes: u32,
    tail: u32,
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
