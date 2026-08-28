use kernel_api::dma::{DmaByteCount, DmaDeviceAddress};

const COMMAND_DWORDS: usize = 16;

/// NVM command opcode accepted by the production I/O path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IoOpcode {
    /// Flush volatile write cache state.
    Flush = 0x00,
    /// Write logical blocks from host memory.
    Write = 0x01,
    /// Read logical blocks into host memory.
    Read = 0x02,
}

/// Direction of an NVMe transfer relative to the controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferDirection {
    /// Controller writes the DMA allocation.
    Read,
    /// Controller reads the DMA allocation.
    Write,
}

/// Validated device-independent input for one NVM read or write command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoTransfer {
    direction: TransferDirection,
    namespace: u32,
    start_lba: u64,
    block_count: u16,
    logical_bytes: DmaByteCount,
}

impl IoTransfer {
    /// Validate the non-zero command quantities before DMA preparation.
    pub fn new(
        direction: TransferDirection,
        namespace: u32,
        start_lba: u64,
        block_count: u16,
        logical_bytes: usize,
    ) -> Option<Self> {
        if namespace == 0 || block_count == 0 {
            return None;
        }
        Some(Self {
            direction,
            namespace,
            start_lba,
            block_count,
            logical_bytes: DmaByteCount::new(logical_bytes)?,
        })
    }

    pub(crate) const fn direction(self) -> TransferDirection {
        self.direction
    }

    pub(crate) const fn logical_bytes(self) -> DmaByteCount {
        self.logical_bytes
    }
}

/// Raw completion status retained as an integer bitfield.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionStatus(u16);

impl CompletionStatus {
    /// Phase tag written by the controller.
    pub const fn phase(self) -> bool {
        self.0 & 1 != 0
    }

    /// Status code excluding the phase tag.
    pub const fn code(self) -> u16 {
        self.0 >> 1
    }

    /// Whether the command completed without an NVMe status error.
    pub const fn is_success(self) -> bool {
        self.code() == 0
    }
}

/// A completion entry parsed from four scalar DMA reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeCompletion {
    result: u32,
    submission_head: u16,
    submission_queue: u16,
    command_id: u16,
    status: CompletionStatus,
}

impl NvmeCompletion {
    pub(crate) const fn from_dwords(dwords: [u32; 4]) -> Self {
        Self {
            result: dwords[0],
            submission_head: dwords[2] as u16,
            submission_queue: (dwords[2] >> 16) as u16,
            command_id: dwords[3] as u16,
            status: CompletionStatus((dwords[3] >> 16) as u16),
        }
    }

    /// Command-specific result dword.
    pub const fn result(self) -> u32 {
        self.result
    }

    /// New submission queue head reported by the controller.
    pub const fn submission_head(self) -> u16 {
        self.submission_head
    }

    /// Submission queue identifier reported by the controller.
    pub const fn submission_queue(self) -> u16 {
        self.submission_queue
    }

    /// Host-assigned command identifier.
    pub const fn command_id(self) -> u16 {
        self.command_id
    }

    /// Completion status including its phase tag.
    pub const fn status(self) -> CompletionStatus {
        self.status
    }
}

pub(crate) struct NvmeCommand {
    dwords: [u32; COMMAND_DWORDS],
}

impl NvmeCommand {
    pub(crate) fn transfer(
        command_id: u16,
        transfer: IoTransfer,
        prp1: DmaDeviceAddress,
        prp2: Option<DmaDeviceAddress>,
    ) -> Self {
        let opcode = match transfer.direction {
            TransferDirection::Read => IoOpcode::Read,
            TransferDirection::Write => IoOpcode::Write,
        };
        let mut dwords = [0; COMMAND_DWORDS];
        dwords[0] = u32::from(opcode as u8) | (u32::from(command_id) << 16);
        dwords[1] = transfer.namespace;
        let prp1 = prp1.get();
        dwords[6] = prp1 as u32;
        dwords[7] = (prp1 >> 32) as u32;
        if let Some(prp2) = prp2 {
            let prp2 = prp2.get();
            dwords[8] = prp2 as u32;
            dwords[9] = (prp2 >> 32) as u32;
        }
        dwords[10] = transfer.start_lba as u32;
        dwords[11] = (transfer.start_lba >> 32) as u32;
        dwords[12] = u32::from(transfer.block_count - 1);
        Self { dwords }
    }

    pub(crate) fn flush(command_id: u16, namespace: u32) -> Option<Self> {
        if namespace == 0 {
            return None;
        }
        let mut dwords = [0; COMMAND_DWORDS];
        dwords[0] = u32::from(IoOpcode::Flush as u8) | (u32::from(command_id) << 16);
        dwords[1] = namespace;
        Some(Self { dwords })
    }

    pub(crate) const fn dwords(&self) -> &[u32; COMMAND_DWORDS] {
        &self.dwords
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_encoding_uses_zero_based_block_count_and_typed_prps() {
        let transfer = IoTransfer::new(TransferDirection::Read, 7, 0x1122_3344_5566_7788, 8, 4096)
            .expect("valid transfer");
        let command = NvmeCommand::transfer(
            9,
            transfer,
            DmaDeviceAddress::from_abi(0x1000),
            Some(DmaDeviceAddress::from_abi(0x2000)),
        );
        assert_eq!(command.dwords[0], 0x0009_0002);
        assert_eq!(command.dwords[1], 7);
        assert_eq!(command.dwords[6], 0x1000);
        assert_eq!(command.dwords[8], 0x2000);
        assert_eq!(command.dwords[10], 0x5566_7788);
        assert_eq!(command.dwords[11], 0x1122_3344);
        assert_eq!(command.dwords[12], 7);
    }

    #[test]
    fn completion_keeps_device_tags_as_checked_integer_fields() {
        let completion = NvmeCompletion::from_dwords([0x55, 0, 3 | (4 << 16), 9 | (1 << 16)]);
        assert_eq!(completion.result(), 0x55);
        assert_eq!(completion.submission_head(), 3);
        assert_eq!(completion.submission_queue(), 4);
        assert_eq!(completion.command_id(), 9);
        assert!(completion.status().phase());
        assert!(completion.status().is_success());
    }
}
