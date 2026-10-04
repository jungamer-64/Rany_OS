//! Register operations tied to the device's retained BAR mapping.
//!
//! Queue doorbells retain only a fixed-width register. DMA ring RAM is not
//! contained in this module and requires its own ownership/completion protocol.

#![deny(unsafe_code)]

use alloc::sync::Arc;
use core::sync::atomic::{Ordering, fence};
use hal::mmio::{MappedMmio, MmioAccessError, OwnedMmioRegister, WriteOnly};

use crate::regs::{init_seg, uar};
mod geometry;
use geometry::checked_uar_offset;

pub(crate) struct InitializationRegisters {
    mapping: Arc<MappedMmio>,
}

impl InitializationRegisters {
    /// Checks all initialization registers without performing device I/O.
    pub(crate) fn validate(mapping: &MappedMmio) -> Result<(), MmioAccessError> {
        let region = mapping.region();
        for offset in [
            init_seg::FW_REV,
            init_seg::CMDIF_REV_FW_SUB,
            init_seg::INITIALIZING,
            init_seg::HEALTH_COUNTER,
            init_seg::INTERNAL_TIMER_H,
            init_seg::INTERNAL_TIMER_L,
            init_seg::CMDQ_ADDR_H,
            init_seg::CMDQ_ADDR_L_SZ,
            init_seg::CMDQ_DOORBELL,
        ] {
            region.read_only::<u32>(offset)?;
        }
        region.write_only::<u32>(init_seg::SW_RESET)?;
        for offset in (0..64).step_by(4) {
            region.read_only::<u32>(init_seg::HEALTH_BUFFER + offset)?;
        }
        Ok(())
    }

    pub(crate) fn new(mapping: MappedMmio) -> Self {
        Self {
            mapping: Arc::new(mapping),
        }
    }

    fn read_be32(&self, offset: usize) -> Result<u32, MmioAccessError> {
        Ok(u32::from_be(
            self.mapping.region().read_only::<u32>(offset)?.read(),
        ))
    }

    pub(crate) fn revisions(&self) -> Result<(u32, u32), MmioAccessError> {
        Ok((
            self.read_be32(init_seg::FW_REV)?,
            self.read_be32(init_seg::CMDIF_REV_FW_SUB)?,
        ))
    }

    pub(crate) fn initializing(&self) -> Result<u32, MmioAccessError> {
        self.read_be32(init_seg::INITIALIZING)
    }

    pub(crate) fn command_revision(&self) -> Result<u32, MmioAccessError> {
        self.read_be32(init_seg::CMDIF_REV_FW_SUB)
    }

    pub(crate) fn command_layout(&self) -> Result<u32, MmioAccessError> {
        self.read_be32(init_seg::CMDQ_ADDR_L_SZ)
    }

    pub(crate) fn health_counter(&self) -> Result<u32, MmioAccessError> {
        self.read_be32(init_seg::HEALTH_COUNTER)
    }

    pub(crate) fn health_buffer(&self) -> Result<[u8; 64], MmioAccessError> {
        let mut bytes = [0; 64];
        for (i, word) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            word.copy_from_slice(
                &self
                    .read_be32(init_seg::HEALTH_BUFFER + i * 4)?
                    .to_be_bytes(),
            );
        }
        Ok(bytes)
    }

    /// Samples high/low/high once. A rollover is not a coherent timestamp.
    pub(crate) fn timer_sample(&self) -> Result<Option<u64>, MmioAccessError> {
        let high = self.read_be32(init_seg::INTERNAL_TIMER_H)?;
        let low = self.read_be32(init_seg::INTERNAL_TIMER_L)?;
        let high_after = self.read_be32(init_seg::INTERNAL_TIMER_H)?;
        Ok((high == high_after).then_some((u64::from(high) << 32) | u64::from(low)))
    }

    /// Requests reset; it does not establish quiescence or revoke DMA leases.
    pub(crate) fn request_reset(&mut self) -> Result<(), MmioAccessError> {
        self.mapping
            .region()
            .write_only::<u32>(init_seg::SW_RESET)?
            .write(1u32.to_be());
        hal::mmio::sfence();
        Ok(())
    }

    pub(crate) fn command(&self) -> Result<CommandRegisters, MmioAccessError> {
        Ok(CommandRegisters {
            address_high: self.mapping.owned_write_only(init_seg::CMDQ_ADDR_H)?,
            address_low: self.mapping.owned_write_only(init_seg::CMDQ_ADDR_L_SZ)?,
            doorbell: self.mapping.owned_write_only(init_seg::CMDQ_DOORBELL)?,
        })
    }

    /// Accepts a UAR grant from this function's current command completion.
    ///
    /// # Safety
    /// `number` must come from a successful, token-validated ALLOC_UAR response
    /// on this device/function. The device owner must retain the allocation and
    /// not deallocate/reassign it while a derived queue doorbell remains live.
    #[expect(
        unsafe_code,
        reason = "firmware allocation is a hardware fact, not address geometry"
    )]
    pub(crate) unsafe fn granted_uar(&self, number: u32) -> Result<UarRegisters, MmioAccessError> {
        let offset = checked_uar_offset(self.mapping.len(), number)?;
        // Validate all supported doorbell widths before granting queue access.
        self.mapping
            .region()
            .write_only::<u32>(offset + uar::EQ_DOORBELL)?;
        self.mapping
            .region()
            .write_only::<u64>(offset + uar::CQ_DOORBELL)?;
        self.mapping
            .region()
            .write_only::<u64>(offset + uar::BLUEFLAME)?;
        Ok(UarRegisters {
            mapping: Arc::clone(&self.mapping),
            number,
            offset,
        })
    }
}

pub(crate) struct CommandRegisters {
    address_high: OwnedMmioRegister<u32, WriteOnly>,
    address_low: OwnedMmioRegister<u32, WriteOnly>,
    doorbell: OwnedMmioRegister<u32, WriteOnly>,
}

impl CommandRegisters {
    /// Programs a prevalidated page-aligned command DMA base, high then low.
    /// Firmware layout bits are read before programming; this is not an RMW.
    pub(crate) fn program_address(&mut self, high: u32, low: u32) {
        self.address_high.write(high.to_be());
        fence(Ordering::Release);
        self.address_low.write(low.to_be());
    }

    /// Slot zero only. Publication barriers are the command owner's duty.
    pub(crate) fn submit_slot_zero(&mut self) {
        self.doorbell.write(1u32.to_be());
    }
}

pub(crate) struct UarRegisters {
    mapping: Arc<MappedMmio>,
    number: u32,
    offset: usize,
}

impl UarRegisters {
    pub(crate) fn number(&self) -> u32 {
        self.number
    }

    pub(crate) fn eq(&self) -> Result<EqDoorbell, MmioAccessError> {
        Ok(EqDoorbell(
            self.mapping
                .owned_write_only(self.offset + uar::EQ_DOORBELL)?,
        ))
    }
    pub(crate) fn cq(&self) -> Result<CqDoorbell, MmioAccessError> {
        Ok(CqDoorbell(
            self.mapping
                .owned_write_only(self.offset + uar::CQ_DOORBELL)?,
        ))
    }
    pub(crate) fn sq(&self) -> Result<SqDoorbell, MmioAccessError> {
        Ok(SqDoorbell(
            self.mapping
                .owned_write_only(self.offset + uar::BLUEFLAME)?,
        ))
    }
}

pub(crate) struct EqDoorbell(OwnedMmioRegister<u32, WriteOnly>);
impl EqDoorbell {
    pub(crate) fn acknowledge(&mut self, eqn: u32, consumer: u32) {
        let value = (eqn & 0xff) | ((consumer & 0x00ff_ffff) << 8);
        self.0.write(value.to_be());
    }
}

pub(crate) struct CqDoorbell(OwnedMmioRegister<u64, WriteOnly>);
impl CqDoorbell {
    /// One 64-bit bus transaction containing two big-endian protocol words.
    pub(crate) fn arm(&mut self, arm_word: u32, cqn: u32) {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&arm_word.to_be_bytes());
        bytes[4..].copy_from_slice(&cqn.to_be_bytes());
        self.0.write(u64::from_ne_bytes(bytes));
    }
}

pub(crate) struct SqDoorbell(OwnedMmioRegister<u64, WriteOnly>);
impl SqDoorbell {
    /// The first eight WQE bytes are already in device representation.
    pub(crate) fn publish_control_word(&mut self, native_word: u64) {
        self.0.write(native_word);
    }
}
