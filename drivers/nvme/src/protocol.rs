use core::num::NonZeroU16;

use kernel_api::dma::{DmaByteCount, DmaDeviceAddress};

const COMMAND_DWORDS: usize = 16;
const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum AdminOpcode {
    CreateIoSubmissionQueue = 0x01,
    CreateIoCompletionQueue = 0x05,
    Identify = 0x06,
    SetFeatures = 0x09,
}

const NUMBER_OF_QUEUES_FEATURE: u32 = 0x07;

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

/// Validated Admin command whose command identifier is assigned by the queue.
pub(crate) struct AdminCommand {
    dwords: [u32; COMMAND_DWORDS],
}

impl AdminCommand {
    pub(crate) fn request_io_queues(requested: NonZeroU16) -> Self {
        let zero_based = u32::from(requested.get() - 1);
        let mut dwords = [0; COMMAND_DWORDS];
        dwords[0] = u32::from(AdminOpcode::SetFeatures as u8);
        dwords[10] = NUMBER_OF_QUEUES_FEATURE;
        dwords[11] = zero_based | (zero_based << 16);
        Self { dwords }
    }

    pub(crate) fn create_io_completion_queue(
        queue_id: u16,
        depth: u16,
        address: DmaDeviceAddress,
    ) -> Option<Self> {
        if queue_id == 0 || depth < 2 || !address.get().is_multiple_of(PAGE_SIZE) {
            return None;
        }
        let mut dwords = [0; COMMAND_DWORDS];
        dwords[0] = u32::from(AdminOpcode::CreateIoCompletionQueue as u8);
        encode_prp1(&mut dwords, address);
        dwords[10] = u32::from(queue_id) | (u32::from(depth - 1) << 16);
        // PC=1; this polling queue does not enable an interrupt vector.
        dwords[11] = 1;
        Some(Self { dwords })
    }

    pub(crate) fn create_io_submission_queue(
        queue_id: u16,
        depth: u16,
        completion_queue_id: u16,
        address: DmaDeviceAddress,
    ) -> Option<Self> {
        if queue_id == 0
            || completion_queue_id == 0
            || depth < 2
            || !address.get().is_multiple_of(PAGE_SIZE)
        {
            return None;
        }
        let mut dwords = [0; COMMAND_DWORDS];
        dwords[0] = u32::from(AdminOpcode::CreateIoSubmissionQueue as u8);
        encode_prp1(&mut dwords, address);
        dwords[10] = u32::from(queue_id) | (u32::from(depth - 1) << 16);
        // CQID selects the already-created completion queue; PC=1.
        dwords[11] = (u32::from(completion_queue_id) << 16) | 1;
        Some(Self { dwords })
    }

    pub(crate) fn with_command_id(mut self, command_id: u16) -> NvmeCommand {
        self.dwords[0] |= u32::from(command_id) << 16;
        NvmeCommand {
            dwords: self.dwords,
        }
    }
}

fn encode_prp1(dwords: &mut [u32; COMMAND_DWORDS], address: DmaDeviceAddress) {
    let address = address.get();
    dwords[6] = address as u32;
    dwords[7] = (address >> 32) as u32;
}

impl NvmeCommand {
    pub(crate) fn identify_namespace(
        command_id: u16,
        namespace: u32,
        address: DmaDeviceAddress,
    ) -> Option<Self> {
        if namespace == 0 || !address.get().is_multiple_of(PAGE_SIZE) {
            return None;
        }
        let mut dwords = [0; COMMAND_DWORDS];
        dwords[0] = u32::from(AdminOpcode::Identify as u8) | (u32::from(command_id) << 16);
        dwords[1] = namespace;
        encode_prp1(&mut dwords, address);
        // CNS=00h selects the NVM Command Set Identify Namespace data.
        dwords[10] = 0;
        Some(Self { dwords })
    }

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
        encode_prp1(&mut dwords, prp1);
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

    #[test]
    fn queue_admin_commands_encode_validated_zero_based_geometry() {
        let requested = NonZeroU16::new(4).expect("non-zero request");
        let request = AdminCommand::request_io_queues(requested).with_command_id(7);
        assert_eq!(request.dwords[0], 0x0007_0009);
        assert_eq!(request.dwords[10], 0x07);
        assert_eq!(request.dwords[11], 0x0003_0003);

        let completion =
            AdminCommand::create_io_completion_queue(2, 64, DmaDeviceAddress::from_abi(0x8000))
                .expect("aligned completion queue")
                .with_command_id(5);
        assert_eq!(completion.dwords[0], 0x0005_0005);
        assert_eq!(completion.dwords[6], 0x8000);
        assert_eq!(completion.dwords[10], 0x003f_0002);
        assert_eq!(completion.dwords[11], 1);

        let submission =
            AdminCommand::create_io_submission_queue(2, 64, 2, DmaDeviceAddress::from_abi(0x9000))
                .expect("aligned submission queue")
                .with_command_id(6);
        assert_eq!(submission.dwords[0], 0x0006_0001);
        assert_eq!(submission.dwords[10], 0x003f_0002);
        assert_eq!(submission.dwords[11], 0x0002_0001);
    }

    #[test]
    fn queue_admin_commands_reject_ambient_or_unaligned_memory() {
        assert!(
            AdminCommand::create_io_completion_queue(0, 64, DmaDeviceAddress::from_abi(0x8000))
                .is_none()
        );
        assert!(
            AdminCommand::create_io_submission_queue(1, 1, 1, DmaDeviceAddress::from_abi(0x8001))
                .is_none()
        );
    }

    #[test]
    fn identify_namespace_requires_a_named_namespace_and_page_buffer() {
        let command = NvmeCommand::identify_namespace(3, 7, DmaDeviceAddress::from_abi(0x1_0000))
            .expect("valid identify command");
        assert_eq!(command.dwords[0], 0x0003_0006);
        assert_eq!(command.dwords[1], 7);
        assert_eq!(command.dwords[6], 0x0001_0000);
        assert_eq!(command.dwords[10], 0);
        assert!(
            NvmeCommand::identify_namespace(1, 0, DmaDeviceAddress::from_abi(0x1000)).is_none()
        );
        assert!(
            NvmeCommand::identify_namespace(1, 1, DmaDeviceAddress::from_abi(0x1001)).is_none()
        );
    }
}
