use hal::{MappedMmio, MmioAccessError, MmioRegister, WriteOnly};
use kernel_api::dma::DmaDeviceAddress;

const CAP: usize = 0x00;
const CC: usize = 0x14;
const CSTS: usize = 0x1c;
const AQA: usize = 0x24;
const ASQ: usize = 0x28;
const ACQ: usize = 0x30;
const DOORBELL_BASE: usize = 0x1000;

/// Failure while validating the controller register aperture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeRegisterError {
    /// A required property does not fit or is misaligned.
    Access(MmioAccessError),
    /// CAP advertises an unsupported or overflowing doorbell stride.
    InvalidDoorbellStride,
    /// The requested queue has no complete doorbell register in this BAR.
    DoorbellOutOfRange,
    /// Admin queue depth is outside the controller contract.
    InvalidQueueDepth,
}

impl From<MmioAccessError> for NvmeRegisterError {
    fn from(value: MmioAccessError) -> Self {
        Self::Access(value)
    }
}

/// Controller capabilities needed by queue and initialization code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllerCapabilities {
    raw: u64,
    doorbell_stride: usize,
}

impl ControllerCapabilities {
    fn parse(raw: u64) -> Result<Self, NvmeRegisterError> {
        let exponent = ((raw >> 32) & 0xf) as u32;
        let doorbell_stride = 4usize
            .checked_shl(exponent)
            .ok_or(NvmeRegisterError::InvalidDoorbellStride)?;
        Ok(Self {
            raw,
            doorbell_stride,
        })
    }

    /// Maximum queue entries supported by the controller.
    pub const fn max_queue_entries(self) -> u32 {
        (self.raw as u16 as u32) + 1
    }

    /// Doorbell register spacing in bytes.
    pub const fn doorbell_stride(self) -> usize {
        self.doorbell_stride
    }

    /// Controller timeout unit in 500 ms intervals.
    pub const fn timeout_units(self) -> u8 {
        ((self.raw >> 24) & 0xff) as u8
    }
}

/// Integer interpretation of the controller status property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllerStatus(u32);

impl ControllerStatus {
    /// Controller ready state.
    pub const fn ready(self) -> bool {
        self.0 & 1 != 0
    }

    /// Controller fatal status.
    pub const fn fatal(self) -> bool {
        self.0 & 2 != 0
    }
}

/// Owns the complete NVMe controller register aperture.
pub struct NvmeRegisters {
    mapping: MappedMmio,
    capabilities: ControllerCapabilities,
}

impl NvmeRegisters {
    /// Validate mandatory properties and CAP-derived doorbell geometry.
    ///
    /// # Errors
    /// Returns the original mapping together with the failed validation.
    pub fn new(mapping: MappedMmio) -> Result<Self, (NvmeRegisterError, MappedMmio)> {
        let capability = match mapping.region().read_only::<u64>(CAP) {
            Ok(register) => register.read(),
            Err(error) => return Err((error.into(), mapping)),
        };
        for offset in [CC, AQA] {
            if let Err(error) = mapping.region().read_write::<u32>(offset) {
                return Err((error.into(), mapping));
            }
        }
        if let Err(error) = mapping.region().read_only::<u32>(CSTS) {
            return Err((error.into(), mapping));
        }
        for offset in [ASQ, ACQ] {
            if let Err(error) = mapping.region().read_write::<u64>(offset) {
                return Err((error.into(), mapping));
            }
        }
        let capabilities = match ControllerCapabilities::parse(capability) {
            Ok(capabilities) => capabilities,
            Err(error) => return Err((error, mapping)),
        };
        Ok(Self {
            mapping,
            capabilities,
        })
    }

    /// Parsed CAP fields used by queue setup.
    pub const fn capabilities(&self) -> ControllerCapabilities {
        self.capabilities
    }

    /// Observe CSTS without reinterpreting device bits as an enum.
    ///
    /// # Errors
    /// Returns a geometry error if the retained mapping no longer admits the
    /// mandatory 32-bit status access.
    pub fn status(&self) -> Result<ControllerStatus, NvmeRegisterError> {
        Ok(ControllerStatus(
            self.mapping.region().read_only::<u32>(CSTS)?.read(),
        ))
    }

    /// Request controller disable while preserving defined CC configuration.
    ///
    /// # Errors
    /// Returns a geometry error before writing if CC cannot be derived from the
    /// retained mapping.
    pub fn request_disable(&self) -> Result<(), NvmeRegisterError> {
        let mut register = self.mapping.region().read_write::<u32>(CC)?;
        let value = register.read() & !1;
        register.write(value);
        Ok(())
    }

    /// Program Admin Queue properties while the controller is disabled.
    ///
    /// # Errors
    /// Rejects an invalid depth or a mapping that does not admit all complete
    /// AQA, ASQ, and ACQ accesses. Every derivation completes before any write.
    pub fn program_admin_queue(
        &self,
        depth: u16,
        submission: DmaDeviceAddress,
        completion: DmaDeviceAddress,
    ) -> Result<(), NvmeRegisterError> {
        if depth < 2 || u32::from(depth) > self.capabilities.max_queue_entries() {
            return Err(NvmeRegisterError::InvalidQueueDepth);
        }
        let entries = u32::from(depth - 1);
        let region = self.mapping.region();
        let mut aqa = region.read_write::<u32>(AQA)?;
        let mut asq = region.read_write::<u64>(ASQ)?;
        let mut acq = region.read_write::<u64>(ACQ)?;
        aqa.write(entries | (entries << 16));
        asq.write(submission.get());
        acq.write(completion.get());
        Ok(())
    }

    /// Enable the NVM command set with 64-byte SQ and 16-byte CQ entries.
    ///
    /// # Errors
    /// Returns a geometry error before writing if CC cannot be derived from the
    /// retained mapping.
    pub fn enable_nvm(&self) -> Result<(), NvmeRegisterError> {
        let value = 1 | (6 << 16) | (4 << 20);
        self.mapping.region().read_write::<u32>(CC)?.write(value);
        Ok(())
    }

    pub(crate) fn submission_doorbell(
        &self,
        queue: u16,
    ) -> Result<MmioRegister<'_, u32, WriteOnly>, NvmeRegisterError> {
        self.doorbell(queue, false)
    }

    pub(crate) fn completion_doorbell(
        &self,
        queue: u16,
    ) -> Result<MmioRegister<'_, u32, WriteOnly>, NvmeRegisterError> {
        self.doorbell(queue, true)
    }

    fn doorbell(
        &self,
        queue: u16,
        completion: bool,
    ) -> Result<MmioRegister<'_, u32, WriteOnly>, NvmeRegisterError> {
        let slot = usize::from(queue)
            .checked_mul(2)
            .and_then(|value| value.checked_add(usize::from(completion)))
            .ok_or(NvmeRegisterError::DoorbellOutOfRange)?;
        let offset = slot
            .checked_mul(self.capabilities.doorbell_stride)
            .and_then(|value| value.checked_add(DOORBELL_BASE))
            .ok_or(NvmeRegisterError::DoorbellOutOfRange)?;
        self.mapping
            .region()
            .write_only::<u32>(offset)
            .map_err(|_| NvmeRegisterError::DoorbellOutOfRange)
    }
}
