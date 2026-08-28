//! AHCI register operations; no caller-selected offsets or generic RMW escape.

#![forbid(unsafe_code)]

use hal::mmio::{MappedMmio, MmioAccessError};

use super::protocol::PortObservation;
use crate::types::*;

#[derive(Debug)]
pub(super) struct PortRegisters(MappedMmio);

impl PortRegisters {
    pub(super) fn new(mapping: MappedMmio) -> Result<Self, (MmioAccessError, MappedMmio)> {
        // All registers below have the same width/alignment and lie in this
        // checked prefix. Derivation cannot later fail: the mapping cannot shrink.
        if let Err(error) = mapping
            .region()
            .read_only::<u32>(0)
            .and_then(|_| mapping.region().read_only::<u32>(PX_CI as usize))
        {
            return Err((error, mapping));
        }
        Ok(Self(mapping))
    }

    fn read(&self, offset: u32) -> u32 {
        self.0
            .region()
            .read_only::<u32>(offset as usize)
            .expect("validated AHCI register offset")
            .read()
    }

    fn write(&self, offset: u32, value: u32) {
        self.0
            .region()
            .write_only::<u32>(offset as usize)
            .expect("validated AHCI register offset")
            .write(value);
    }

    pub(super) fn into_mapping(self) -> MappedMmio {
        self.0
    }

    pub(super) fn observe(&self) -> PortObservation {
        let issued = self.read(PX_CI);
        PortObservation {
            issued,
            sata_active: self.read(PX_SACT),
            sata_status: self.read(PX_SSTS),
            interrupt_status: self.read(PX_IS),
            task_file: self.read(PX_TFD),
            // Read engine state last, so an observed stopped engine cannot
            // turn a reset-cleared CI into an ordinary completion.
            command: self.read(PX_CMD),
        }
    }

    pub(super) fn device_type(&self) -> DeviceType {
        DeviceType::from_signature(self.read(PX_SIG))
    }

    pub(super) fn stop(&mut self, polls: core::num::NonZeroUsize) -> Result<(), ()> {
        self.write(PX_IE, 0);
        self.write(PX_CMD, self.read(PX_CMD) & !PX_CMD_ST);
        let mut stopped = false;
        for _ in 0..polls.get() {
            if self.read(PX_CMD) & PX_CMD_CR == 0 {
                stopped = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !stopped {
            return Err(());
        }
        self.write(PX_CMD, self.read(PX_CMD) & !PX_CMD_FRE);
        for _ in 0..polls.get() {
            if self.read(PX_CMD) & (PX_CMD_ST | PX_CMD_CR | PX_CMD_FRE | PX_CMD_FR) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(())
    }

    pub(super) fn start(
        &mut self,
        list: kernel_api::dma::DmaDeviceAddress,
        received_fis: kernel_api::dma::DmaDeviceAddress,
    ) {
        self.write(PX_CLB, list.get() as u32);
        self.write(PX_CLBU, (list.get() >> 32) as u32);
        self.write(PX_FB, received_fis.get() as u32);
        self.write(PX_FBU, (received_fis.get() >> 32) as u32);
        self.write(PX_SERR, self.read(PX_SERR));
        self.write(PX_IS, self.read(PX_IS));
        // Completion is polled; interrupts remain disabled until an IRQ owner
        // is explicitly installed. Preserve device-specific CMD controls.
        self.write(PX_CMD, self.read(PX_CMD) | PX_CMD_FRE);
        self.write(PX_CMD, self.read(PX_CMD) | PX_CMD_ST);
    }

    pub(super) fn issue(&mut self) {
        self.write(PX_CI, 1);
    }

    pub(super) fn acknowledge_completion(&mut self) {
        self.write(PX_IS, self.read(PX_IS));
    }
}
