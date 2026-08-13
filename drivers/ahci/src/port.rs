//! AHCI Port Implementation
//!
//! Manages individual SATA ports and command execution using kernel_api.

extern crate alloc;

// use alloc::boxed::Box;
use core::ptr;
use core::slice;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::service::kernel::instance as kernel;

type DmaBuffer = DmaSlice<CpuOwned>;

use super::command::{CommandHeader, CommandTable, PhysicalRegionDescriptor};
use super::dma_buffer::{AhciDmaReadBuffer, AhciDmaWriteBuffer, AhciIdentifyBuffer};
use super::fis::FisRegH2D;
use super::identify::IdentifyData;
use super::types::{
    AhciError, AhciResult, DeviceType, Lba, PORT_BASE, PORT_SIZE, PX_CI, PX_CLB, PX_CLBU, PX_CMD,
    PX_CMD_CR, PX_CMD_FR, PX_CMD_FRE, PX_CMD_ST, PX_FB, PX_FBU, PX_IE, PX_IS, PX_IS_DHRS,
    PX_IS_DSS, PX_IS_PSS, PX_IS_SDBS, PX_IS_TFES, PX_SACT, PX_SERR, PX_SIG, PX_TFD, PortNumber,
    SectorCount, SlotNumber,
};

/// AHCI Port
pub struct AhciPort {
    port_base: u64,
    device_type: DeviceType,
    /// Command List (1KB aligned 1KB)
    command_list: DmaBuffer,
    /// Received FIS (256B aligned 256B)
    received_fis: DmaBuffer,
    /// Command Tables
    command_tables: [Option<DmaBuffer>; 32],
    device_id: PackedPciLocation,
}

impl AhciPort {
    /// Create a new port
    pub fn new(base: u64, port: PortNumber, device_id: PackedPciLocation) -> Option<Self> {
        let port_base = base + PORT_BASE as u64 + (port.as_u8() as u64 * PORT_SIZE as u64);

        // Allocate DMA memory for Command List (32 headers * 32 bytes = 1024 bytes)
        let command_list = kernel().alloc_dma_for_device(1024, device_id).ok()?;

        // Allocate DMA memory for Received FIS (256 bytes)
        let received_fis = kernel().alloc_dma_for_device(256, device_id).ok()?;

        Some(Self {
            port_base,
            device_type: DeviceType::None,
            command_list,
            received_fis,
            command_tables: Default::default(),
            device_id,
        })
    }

    /// Initialize the port
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn init(&mut self) -> AhciResult<()> {
        self.stop()?;

        let clb = self.command_list.device_address();
        let fb = self.received_fis.device_address();

        self.write_port(PX_CLB, clb as u32);
        self.write_port(PX_CLBU, (clb >> 32) as u32);
        self.write_port(PX_FB, fb as u32);
        self.write_port(PX_FBU, (fb >> 32) as u32);

        self.write_port(PX_SERR, 0xFFFFFFFF);
        self.write_port(PX_IS, 0xFFFFFFFF);
        self.write_port(
            PX_IE,
            PX_IS_DHRS | PX_IS_PSS | PX_IS_DSS | PX_IS_SDBS | PX_IS_TFES,
        );

        self.start()?;

        let sig = self.read_port(PX_SIG);
        self.device_type = DeviceType::from_signature(sig);

        Ok(())
    }

    fn start(&self) -> AhciResult<()> {
        let mut cmd = self.read_port(PX_CMD);
        cmd |= PX_CMD_FRE;
        self.write_port(PX_CMD, cmd);

        cmd = self.read_port(PX_CMD);
        cmd |= PX_CMD_ST;
        self.write_port(PX_CMD, cmd);

        Ok(())
    }

    fn stop(&self) -> AhciResult<()> {
        let mut cmd = self.read_port(PX_CMD);
        cmd &= !PX_CMD_ST;
        self.write_port(PX_CMD, cmd);

        for _ in 0..500 {
            let cmd = self.read_port(PX_CMD);
            if (cmd & PX_CMD_CR) == 0 {
                break;
            }
        }

        cmd = self.read_port(PX_CMD);
        cmd &= !PX_CMD_FRE;
        self.write_port(PX_CMD, cmd);

        for _ in 0..500 {
            let cmd = self.read_port(PX_CMD);
            if (cmd & PX_CMD_FR) == 0 {
                return Ok(());
            }
        }

        Err(AhciError::Timeout)
    }

    fn find_slot(&self) -> Option<SlotNumber> {
        let sact = self.read_port(PX_SACT);
        let ci = self.read_port(PX_CI);
        let busy = sact | ci;

        for i in 0..32 {
            if (busy & (1 << i)) == 0 {
                return Some(SlotNumber(i));
            }
        }

        None
    }

    /// Execute IDENTIFY command
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub fn identify(&mut self) -> AhciResult<IdentifyData> {
        let slot = self.find_slot().ok_or(AhciError::NoFreeSlot)?;
        let identify_buf = {
            let device_id = self.device_id;
            AhciIdentifyBuffer::new(device_id).ok_or(AhciError::DmaAllocationFailed)?
        };

        let cmd_table = self.get_or_alloc_command_table(slot)?;
        let buffer_phys = identify_buf.device_addr().as_u64();

        // Build Command Table in DMA memory
        {
            // Clear
            unsafe { ptr::write_bytes(cmd_table as *mut CommandTable, 0, 1) };

            // Setup FIS
            let fis = FisRegH2D::identify();
            unsafe {
                ptr::copy_nonoverlapping(
                    &fis as *const _ as *const u8,
                    cmd_table.cfis.as_mut_ptr(),
                    core::mem::size_of::<FisRegH2D>(),
                );
            }

            // Setup PRDT
            cmd_table.prdt[0] = PhysicalRegionDescriptor::new(buffer_phys, 512, true);
        }

        // Setup Command Header
        {
            let headers = unsafe {
                slice::from_raw_parts_mut(self.command_list.as_ptr() as *mut CommandHeader, 32)
            };
            let header = &mut headers[slot.as_usize()];
            header.set_flags(5, false, false, false);
            header.prdtl = 1;
            header.prdbc = 0;
            header.set_ctba(
                self.command_tables[slot.as_usize()]
                    .as_ref()
                    .ok_or(AhciError::InternalError)?
                    .device_address(),
            );
        }

        self.write_port(PX_CI, 1 << slot.as_u8());
        self.wait_completion(slot)?;

        // Free Command Table buffer for this slot (we allocated it above)
        if let Some(cmd_buf) = self.command_tables[slot.as_usize()].take() {
            drop(cmd_buf);
        }

        Ok(IdentifyData::from_words(
            &identify_buf.finish_and_get_words(),
        ))
    }

    /// Synchronous read (existing)
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub fn read_sectors(&mut self, lba: Lba, count: SectorCount, buf: &mut [u8]) -> AhciResult<()> {
        if buf.len() < count.to_bytes() as usize {
            return Err(AhciError::InvalidParameter);
        }

        let slot = self.find_slot().ok_or(AhciError::NoFreeSlot)?;
        let dma_buf = {
            let device_id = self.device_id;
            AhciDmaReadBuffer::new(count.as_u32() as usize, device_id)
                .ok_or(AhciError::DmaAllocationFailed)?
        };

        let cmd_table = self.get_or_alloc_command_table(slot)?;
        let buffer_phys = dma_buf
            .device_addr()
            .ok_or(AhciError::InternalError)?
            .as_u64();

        {
            unsafe { ptr::write_bytes(cmd_table as *mut CommandTable, 0, 1) };

            let fis = FisRegH2D::read_dma_ext(lba, count);
            unsafe {
                ptr::copy_nonoverlapping(
                    &fis as *const _ as *const u8,
                    cmd_table.cfis.as_mut_ptr(),
                    core::mem::size_of::<FisRegH2D>(),
                );
            }

            cmd_table.prdt[0] =
                PhysicalRegionDescriptor::new(buffer_phys, count.to_bytes() as u32, true);
        }

        {
            let headers = unsafe {
                slice::from_raw_parts_mut(self.command_list.as_ptr() as *mut CommandHeader, 32)
            };
            let header = &mut headers[slot.as_usize()];
            header.set_flags(5, false, false, false);
            header.prdtl = 1;
            header.prdbc = 0;
            header.set_ctba(
                self.command_tables[slot.as_usize()]
                    .as_ref()
                    .ok_or(AhciError::InternalError)?
                    .device_address(),
            );
        }

        self.write_port(PX_CI, 1 << slot.as_u8());
        self.wait_completion(slot)?;

        // Copy data back
        buf.copy_from_slice(dma_buf.data());

        // Free the command table buffer for this slot
        if let Some(cmd_buf) = self.command_tables[slot.as_usize()].take() {
            drop(cmd_buf);
        }

        Ok(())
    }

    /// Write sectors
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the device cannot accept the operation.
    pub fn write_sectors(&mut self, lba: Lba, count: SectorCount, buf: &[u8]) -> AhciResult<()> {
        if buf.len() < count.to_bytes() as usize {
            return Err(AhciError::InvalidParameter);
        }

        let slot = self.find_slot().ok_or(AhciError::NoFreeSlot)?;
        let dma_buf = {
            let device_id = self.device_id;
            AhciDmaWriteBuffer::with_data(buf, device_id).ok_or(AhciError::DmaAllocationFailed)?
        };

        let cmd_table = self.get_or_alloc_command_table(slot)?;
        let buffer_phys = dma_buf
            .device_addr()
            .ok_or(AhciError::InternalError)?
            .as_u64();

        {
            unsafe { ptr::write_bytes(cmd_table as *mut CommandTable, 0, 1) };

            let fis = FisRegH2D::write_dma_ext(lba, count);
            unsafe {
                ptr::copy_nonoverlapping(
                    &fis as *const _ as *const u8,
                    cmd_table.cfis.as_mut_ptr(),
                    core::mem::size_of::<FisRegH2D>(),
                );
            }

            cmd_table.prdt[0] =
                PhysicalRegionDescriptor::new(buffer_phys, count.to_bytes() as u32, true);
        }

        {
            let headers = unsafe {
                slice::from_raw_parts_mut(self.command_list.as_ptr() as *mut CommandHeader, 32)
            };
            let header = &mut headers[slot.as_usize()];
            header.set_flags(5, true, false, false); // W=1
            header.prdtl = 1;
            header.prdbc = 0;
            header.set_ctba(
                self.command_tables[slot.as_usize()]
                    .as_ref()
                    .ok_or(AhciError::InternalError)?
                    .device_address(),
            );
        }

        self.write_port(PX_CI, 1 << slot.as_u8());
        let result = self.wait_completion(slot);

        // Free the command table buffer for this slot regardless of result
        if let Some(cmd_buf) = self.command_tables[slot.as_usize()].take() {
            drop(cmd_buf);
        }

        result
    }

    /// Start a read transfer using a device-visible DMA address (non-blocking)
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub fn start_read_dma(
        &mut self,
        lba: Lba,
        count: SectorCount,
        dma_addr: u64,
        bytes: u32,
    ) -> AhciResult<SlotNumber> {
        let slot = self.find_slot().ok_or(AhciError::NoFreeSlot)?;
        let cmd_table = self.get_or_alloc_command_table(slot)?;

        unsafe {
            ptr::write_bytes(cmd_table as *mut CommandTable, 0, 1);

            let fis = FisRegH2D::read_dma_ext(lba, count);
            ptr::copy_nonoverlapping(
                &fis as *const _ as *const u8,
                cmd_table.cfis.as_mut_ptr(),
                core::mem::size_of::<FisRegH2D>(),
            );

            cmd_table.prdt[0] = PhysicalRegionDescriptor::new(dma_addr, bytes, true);
        }

        unsafe {
            let headers =
                slice::from_raw_parts_mut(self.command_list.as_ptr() as *mut CommandHeader, 32);
            let header = &mut headers[slot.as_usize()];
            header.set_flags(5, false, false, false);
            header.prdtl = 1;
            header.prdbc = 0;
            header.set_ctba(
                self.command_tables[slot.as_usize()]
                    .as_ref()
                    .ok_or(AhciError::InternalError)?
                    .device_address(),
            );
        }

        self.write_port(PX_CI, 1 << slot.as_u8());

        Ok(slot)
    }

    /// Start a write transfer using a device-visible DMA address (non-blocking)
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the device cannot accept the operation.
    pub fn start_write_dma(
        &mut self,
        lba: Lba,
        count: SectorCount,
        dma_addr: u64,
        bytes: u32,
    ) -> AhciResult<SlotNumber> {
        let slot = self.find_slot().ok_or(AhciError::NoFreeSlot)?;
        let cmd_table = self.get_or_alloc_command_table(slot)?;

        unsafe {
            ptr::write_bytes(cmd_table as *mut CommandTable, 0, 1);

            let fis = FisRegH2D::write_dma_ext(lba, count);
            ptr::copy_nonoverlapping(
                &fis as *const _ as *const u8,
                cmd_table.cfis.as_mut_ptr(),
                core::mem::size_of::<FisRegH2D>(),
            );

            cmd_table.prdt[0] = PhysicalRegionDescriptor::new(dma_addr, bytes, true);
        }

        unsafe {
            let headers =
                slice::from_raw_parts_mut(self.command_list.as_ptr() as *mut CommandHeader, 32);
            let header = &mut headers[slot.as_usize()];
            header.set_flags(5, true, false, false);
            header.prdtl = 1;
            header.prdbc = 0;
            header.set_ctba(
                self.command_tables[slot.as_usize()]
                    .as_ref()
                    .ok_or(AhciError::InternalError)?
                    .device_address(),
            );
        }

        self.write_port(PX_CI, 1 << slot.as_u8());

        Ok(slot)
    }

    /// Finish and clean up a completed transfer for the given slot. Returns transferred bytes.
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub fn finish_transfer(&mut self, slot: SlotNumber) -> AhciResult<usize> {
        // Check for task file errors
        let tfd = self.read_port(PX_TFD);
        let status = (tfd & 0xFF) as u8;
        let error = ((tfd >> 8) & 0xFF) as u8;

        if (status & 0x01) != 0 {
            return Err(AhciError::TaskFileError(error));
        }

        // Read prdbc from header to determine bytes transferred
        let headers = unsafe {
            slice::from_raw_parts_mut(self.command_list.as_ptr() as *mut CommandHeader, 32)
        };
        let header = &mut headers[slot.as_usize()];
        let transferred = header.prdbc as usize;

        // Free command table buffer
        if let Some(cmd_buf) = self.command_tables[slot.as_usize()].take() {
            drop(cmd_buf);
        }

        Ok(transferred)
    }

    fn get_or_alloc_command_table(&mut self, slot: SlotNumber) -> AhciResult<&mut CommandTable> {
        if self.command_tables[slot.as_usize()].is_none() {
            let buffer = kernel()
                .alloc_dma_for_device(core::mem::size_of::<CommandTable>(), self.device_id)
                .ok();
            self.command_tables[slot.as_usize()] = buffer;
        }

        let cmd_table_buf = self.command_tables[slot.as_usize()]
            .as_mut()
            .ok_or(AhciError::DmaAllocationFailed)?;

        Ok(unsafe { &mut *(cmd_table_buf.as_ptr() as *mut CommandTable) })
    }

    /// # Errors
    ///
    /// Returns an error if the device is not ready, times out, or reports a failed completion.
    pub fn wait_completion(&self, slot: SlotNumber) -> AhciResult<()> {
        let slot_mask = 1u32 << slot.as_u8();

        for _ in 0..1000000 {
            let ci = self.read_port(PX_CI);
            if (ci & slot_mask) == 0 {
                let tfd = self.read_port(PX_TFD);
                let status = (tfd & 0xFF) as u8;
                let error = ((tfd >> 8) & 0xFF) as u8;

                if (status & 0x01) != 0 {
                    return Err(AhciError::TaskFileError(error));
                }
                return Ok(());
            }

            let is = self.read_port(PX_IS);
            if (is & PX_IS_TFES) != 0 {
                let tfd = self.read_port(PX_TFD);
                let error = ((tfd >> 8) & 0xFF) as u8;
                return Err(AhciError::TaskFileError(error));
            }
        }

        Err(AhciError::Timeout)
    }

    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }

    pub fn read_port(&self, offset: u32) -> u32 {
        hal::mmio::mmio_read_u32((self.port_base + offset as u64) as usize)
    }

    pub fn write_port(&self, offset: u32, value: u32) {
        hal::mmio::mmio_write_u32((self.port_base + offset as u64) as usize, value)
    }
}

impl Drop for AhciPort {
    fn drop(&mut self) {
        // Option fields and owned DMA slices reclaim themselves on drop.
        for entry in self.command_tables.iter_mut() {
            let _ = entry.take();
        }
    }
}
