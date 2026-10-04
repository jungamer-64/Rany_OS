use crate::protocol::{IoTransfer, PAGE_BYTES, TransferDirection};
use kernel_api::abi::driver::{AbiBlockCommandKind, AbiBlockSubmission, AbiError};
use kernel_api::dma::DmaDeviceAddress;

use kernel_api::dma::{CompletedDmaLease, CpuDmaLease, DmaLeaseError, DmaQueueIdentity};

use crate::controller::NvmeAdminController;
use crate::protocol::{CompletionStatus, NvmeCompletion};
use crate::queue::{CompletedCommand, CompletedOwnership, PollError, SubmitError};

const IDENTIFY_BYTES: usize = 4096;
const NAMESPACE_SIZE_OFFSET: usize = 0;
const NAMESPACE_LBA_FORMAT_COUNT_OFFSET: usize = 25;
const NAMESPACE_FORMATTED_LBA_OFFSET: usize = 26;
const LBA_FORMATS_OFFSET: usize = 128;
const LBA_FORMAT_BYTES: usize = 4;

/// Checked failure while interpreting NVM Identify Namespace bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespaceParseError {
    /// The DMA allocation did not contain the complete 4096-byte structure.
    Truncated,
    /// NSZE reported no addressable logical blocks.
    EmptyNamespace,
    /// FLBAS selected an LBA format not admitted by NLBAF.
    InvalidFormatIndex,
    /// The selected LBA format's byte range overflowed the structure.
    InvalidFormatRange,
    /// The selected LBA data exponent was unavailable or unsupported.
    InvalidBlockSize,
    /// The namespace requires metadata that this block path cannot transfer.
    MetadataUnsupported,
}

/// Validated geometry for one NVM namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespaceInfo {
    controller: DmaQueueIdentity,
    namespace: u32,
    block_count: u64,
    block_size: u32,
}

pub(crate) enum BlockCommand {
    Transfer {
        transfer: IoTransfer,
        address: DmaDeviceAddress,
        prp2: Option<DmaDeviceAddress>,
    },
    Flush,
}

impl NamespaceInfo {
    // Interpret a host publication against this identified controller generation.
    // The notification carries lease identity only; it grants no CPU DMA access.
    pub(crate) fn admit_submission(
        self,
        input: &AbiBlockSubmission,
    ) -> Result<BlockCommand, AbiError> {
        if input.request_id == 0 || input.generation != self.controller.generation() {
            return Err(AbiError::InvalidParam);
        }
        if input.command == AbiBlockCommandKind::Flush as u32 {
            return if input.bytes == 0
                && input.blocks == 0
                && input.lease_id == 0
                && input.iova == 0
            {
                Ok(BlockCommand::Flush)
            } else {
                Err(AbiError::InvalidParam)
            };
        }
        let direction = match input.command {
            value if value == AbiBlockCommandKind::Read as u32 => TransferDirection::Read,
            value if value == AbiBlockCommandKind::Write as u32 => TransferDirection::Write,
            _ => return Err(AbiError::NotSupported),
        };
        let transfer = IoTransfer::for_namespace(self, direction, input.lba, input.blocks)
            .map_err(|_| AbiError::InvalidParam)?;
        if input.bytes != transfer.logical_byte_count().get()
            || input.bytes > PAGE_BYTES
            || input.lease_id == 0
            || input.iova == 0
            || !input.iova.is_multiple_of(4)
            || input.iova.checked_add(input.bytes as u64).is_none()
        {
            return Err(AbiError::InvalidParam);
        }
        let first_bytes = PAGE_BYTES - (input.iova as usize & (PAGE_BYTES - 1));
        let address = DmaDeviceAddress::from_abi(input.iova);
        let prp2 = if input.bytes > first_bytes {
            Some(
                address
                    .checked_add(first_bytes)
                    .ok_or(AbiError::InvalidAddress)?,
            )
        } else {
            None
        };
        Ok(BlockCommand::Transfer {
            transfer,
            address,
            prp2,
        })
    }

    pub(crate) const fn controller_identity(self) -> DmaQueueIdentity {
        self.controller
    }

    /// Namespace identifier used for later commands.
    pub const fn namespace(self) -> u32 {
        self.namespace
    }

    /// Total number of formatted logical blocks.
    pub const fn block_count(self) -> u64 {
        self.block_count
    }

    /// User-data bytes in one logical block.
    pub const fn block_size(self) -> u32 {
        self.block_size
    }

    /// Checked namespace capacity in bytes.
    pub const fn byte_capacity(self) -> Option<u64> {
        self.block_count.checked_mul(self.block_size as u64)
    }

    fn parse(
        controller: DmaQueueIdentity,
        namespace: u32,
        bytes: &[u8],
    ) -> Result<Self, NamespaceParseError> {
        if bytes.len() < IDENTIFY_BYTES {
            return Err(NamespaceParseError::Truncated);
        }
        let block_count = u64::from_le_bytes(
            bytes[NAMESPACE_SIZE_OFFSET..NAMESPACE_SIZE_OFFSET + 8]
                .try_into()
                .map_err(|_| NamespaceParseError::Truncated)?,
        );
        if block_count == 0 {
            return Err(NamespaceParseError::EmptyNamespace);
        }
        let format_count_zero_based = bytes[NAMESPACE_LBA_FORMAT_COUNT_OFFSET];
        let formatted = bytes[NAMESPACE_FORMATTED_LBA_OFFSET];
        let lower_index = formatted & 0x0f;
        let upper_index = if format_count_zero_based < 16 {
            0
        } else {
            (formatted >> 1) & 0x30
        };
        let format_index = lower_index | upper_index;
        if format_index > format_count_zero_based || format_index >= 64 {
            return Err(NamespaceParseError::InvalidFormatIndex);
        }
        let format_offset = usize::from(format_index)
            .checked_mul(LBA_FORMAT_BYTES)
            .and_then(|offset| offset.checked_add(LBA_FORMATS_OFFSET))
            .ok_or(NamespaceParseError::InvalidFormatRange)?;
        let format_end = format_offset
            .checked_add(LBA_FORMAT_BYTES)
            .ok_or(NamespaceParseError::InvalidFormatRange)?;
        let format = u32::from_le_bytes(
            bytes
                .get(format_offset..format_end)
                .ok_or(NamespaceParseError::InvalidFormatRange)?
                .try_into()
                .map_err(|_| NamespaceParseError::InvalidFormatRange)?,
        );
        let metadata_bytes = format as u16;
        if metadata_bytes != 0 {
            return Err(NamespaceParseError::MetadataUnsupported);
        }
        let exponent = (format >> 16) & 0xff;
        if exponent < 9 {
            return Err(NamespaceParseError::InvalidBlockSize);
        }
        let block_size = 1u32
            .checked_shl(exponent)
            .ok_or(NamespaceParseError::InvalidBlockSize)?;
        Ok(Self {
            controller,
            namespace,
            block_count,
            block_size,
        })
    }
}

/// Identify submission failure retaining controller and DMA pre-acceptance state.
pub struct IdentifySubmitError {
    /// Driver submission failure retaining the CPU or prepared lease.
    pub cause: SubmitError,
    /// Ready Admin controller; the queue was not notified on this error path.
    pub controller: NvmeAdminController,
}

impl core::fmt::Debug for IdentifySubmitError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IdentifySubmitError")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

/// Accepted Identify Namespace request awaiting its completion.
pub struct IdentifyNamespaceRequest {
    controller: NvmeAdminController,
    namespace: u32,
    command_id: u16,
}

/// Successful identify result retaining the returned CPU allocation.
pub struct IdentifiedNamespace {
    controller: NvmeAdminController,
    info: NamespaceInfo,
    buffer: CpuDmaLease,
}

impl IdentifiedNamespace {
    /// Consume the result into controller, parsed geometry, and reusable buffer.
    pub fn into_parts(self) -> (NvmeAdminController, NamespaceInfo, CpuDmaLease) {
        (self.controller, self.info, self.buffer)
    }
}

/// Result of observing one Identify completion.
pub enum IdentifyNamespacePoll {
    /// No completion with the expected phase was visible.
    Waiting(IdentifyNamespaceRequest),
    /// The namespace bytes were returned and validated.
    Ready(IdentifiedNamespace),
}

/// Identify completion/parse failure retaining all reachable owners.
pub enum IdentifyNamespaceError {
    /// Completion parsing failed; the request and in-flight lease remain owned.
    Poll {
        cause: PollError,
        request: IdentifyNamespaceRequest,
    },
    /// A different control completion was consumed while identify remains pending.
    UnexpectedControl {
        controller: NvmeAdminController,
        completion: NvmeCompletion,
    },
    /// A different transfer completion was consumed; its ownership is retained.
    UnexpectedTransfer {
        controller: NvmeAdminController,
        completion: NvmeCompletion,
        ownership: CompletedOwnership,
    },
    /// An externally owned notification appeared on the Admin queue; retain
    /// its unique metadata and the controller rather than discarding it.
    UnexpectedNotification {
        controller: NvmeAdminController,
        completion: NvmeCompletion,
        notification: crate::CompletionNotification,
    },
    /// The Identify command completed with an NVMe error status.
    ControllerRejected {
        controller: NvmeAdminController,
        status: CompletionStatus,
        ownership: CompletedOwnership,
    },
    /// Hardware completion was proven, but CPU access could not be restored.
    OwnershipBlocked {
        controller: NvmeAdminController,
        cause: DmaLeaseError,
        completed: CompletedDmaLease,
    },
    /// CPU ownership returned, but the namespace structure was invalid.
    Parse {
        controller: NvmeAdminController,
        cause: NamespaceIdentifyError,
        buffer: CpuDmaLease,
    },
}

impl core::fmt::Debug for IdentifyNamespaceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedNotification { completion, .. } => formatter
                .debug_tuple("UnexpectedNotification")
                .field(completion)
                .finish(),
            Self::Poll { cause, .. } => formatter.debug_tuple("Poll").field(cause).finish(),
            Self::UnexpectedControl { completion, .. } => formatter
                .debug_tuple("UnexpectedControl")
                .field(completion)
                .finish(),
            Self::UnexpectedTransfer { completion, .. } => formatter
                .debug_tuple("UnexpectedTransfer")
                .field(completion)
                .finish(),
            Self::ControllerRejected { status, .. } => formatter
                .debug_tuple("ControllerRejected")
                .field(status)
                .finish(),
            Self::OwnershipBlocked { cause, .. } => formatter
                .debug_tuple("OwnershipBlocked")
                .field(cause)
                .finish(),
            Self::Parse { cause, .. } => formatter.debug_tuple("Parse").field(cause).finish(),
        }
    }
}

/// Registry access or namespace-byte validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespaceIdentifyError {
    /// CPU lease access failed in the resource registry.
    Dma(DmaLeaseError),
    /// Identify bytes violated the NVM namespace representation.
    Data(NamespaceParseError),
}

impl NvmeAdminController {
    /// Submit one 4096-byte Identify Namespace transfer.
    ///
    /// # Errors
    /// Returns the controller and exact CPU/prepared DMA state if the command
    /// did not cross the Admin doorbell boundary.
    pub fn identify_namespace(
        self,
        namespace: u32,
        buffer: CpuDmaLease,
    ) -> Result<IdentifyNamespaceRequest, IdentifySubmitError> {
        let submission =
            match self
                .admin_queue
                .submit_identify_namespace(&self.registers, namespace, buffer)
            {
                Ok(submission) => submission,
                Err(cause) => {
                    return Err(IdentifySubmitError {
                        cause,
                        controller: self,
                    });
                }
            };
        Ok(IdentifyNamespaceRequest {
            controller: self,
            namespace,
            command_id: submission.command_id(),
        })
    }
}

impl IdentifyNamespaceRequest {
    /// Observe one Admin completion without imposing a wait policy.
    ///
    /// # Errors
    /// Every error retains the controller and any DMA owner that has left the
    /// queue. An accepted command is not made retryable by a parse/poll error.
    pub fn poll(self) -> Result<IdentifyNamespacePoll, IdentifyNamespaceError> {
        let completed = match self
            .controller
            .admin_queue
            .poll_completion(&self.controller.registers)
        {
            Ok(completed) => completed,
            Err(cause) => {
                return Err(IdentifyNamespaceError::Poll {
                    cause,
                    request: self,
                });
            }
        };
        let Some(completed) = completed else {
            return Ok(IdentifyNamespacePoll::Waiting(self));
        };
        let (completion, ownership) = match completed {
            CompletedCommand::Notification {
                completion,
                notification,
            } => {
                return Err(IdentifyNamespaceError::UnexpectedNotification {
                    controller: self.controller,
                    completion,
                    notification,
                });
            }
            CompletedCommand::Control(completion) => {
                return Err(IdentifyNamespaceError::UnexpectedControl {
                    controller: self.controller,
                    completion,
                });
            }
            CompletedCommand::Transfer {
                completion,
                ownership,
            } => (completion, ownership),
        };
        if completion.command_id() != self.command_id {
            return Err(IdentifyNamespaceError::UnexpectedTransfer {
                controller: self.controller,
                completion,
                ownership,
            });
        }
        if !completion.status().is_success() {
            return Err(IdentifyNamespaceError::ControllerRejected {
                controller: self.controller,
                status: completion.status(),
                ownership,
            });
        }
        let buffer = match ownership {
            CompletedOwnership::Cpu(buffer) => buffer,
            CompletedOwnership::Blocked { cause, completed } => {
                return Err(IdentifyNamespaceError::OwnershipBlocked {
                    controller: self.controller,
                    cause,
                    completed,
                });
            }
        };
        let identity = self.controller.admin_queue.identity();
        let info = match buffer.read(|bytes| NamespaceInfo::parse(identity, self.namespace, bytes))
        {
            Ok(Ok(info)) => info,
            Ok(Err(cause)) => {
                return Err(IdentifyNamespaceError::Parse {
                    controller: self.controller,
                    cause: NamespaceIdentifyError::Data(cause),
                    buffer,
                });
            }
            Err(cause) => {
                return Err(IdentifyNamespaceError::Parse {
                    controller: self.controller,
                    cause: NamespaceIdentifyError::Dma(cause),
                    buffer,
                });
            }
        };
        Ok(IdentifyNamespacePoll::Ready(IdentifiedNamespace {
            controller: self.controller,
            info,
            buffer,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{IoTransfer, NvmeCommand, TransferDirection, TransferRangeError};
    use kernel_api::abi::driver::PackedPciLocation;
    use kernel_api::dma::DmaDeviceAddress;

    fn identity(generation: u64) -> DmaQueueIdentity {
        DmaQueueIdentity::new(PackedPciLocation::new(0, 0, 1, 0), 0, generation)
            .expect("non-null controller generation")
    }

    fn identify_bytes(blocks: u64, format_index: u8, exponent: u8, metadata: u16) -> [u8; 4096] {
        let mut bytes = [0; 4096];
        bytes[0..8].copy_from_slice(&blocks.to_le_bytes());
        bytes[NAMESPACE_LBA_FORMAT_COUNT_OFFSET] = format_index;
        bytes[NAMESPACE_FORMATTED_LBA_OFFSET] =
            (format_index & 0x0f) | ((format_index & 0x30) << 1);
        let offset = LBA_FORMATS_OFFSET + usize::from(format_index) * LBA_FORMAT_BYTES;
        let format = u32::from(metadata) | (u32::from(exponent) << 16);
        bytes[offset..offset + 4].copy_from_slice(&format.to_le_bytes());
        bytes
    }

    #[test]
    fn namespace_geometry_uses_selected_lba_format() {
        let bytes = identify_bytes(0x1234, 2, 12, 0);
        let info = NamespaceInfo::parse(identity(1), 7, &bytes).expect("valid namespace");
        assert_eq!(info.namespace(), 7);
        assert_eq!(info.block_count(), 0x1234);
        assert_eq!(info.block_size(), 4096);
        assert_eq!(info.byte_capacity(), Some(0x1234 * 4096));

        let extended = identify_bytes(8, 17, 9, 0);
        assert_eq!(
            NamespaceInfo::parse(identity(1), 1, &extended)
                .expect("extended format index")
                .block_size(),
            512
        );
    }

    #[test]
    fn namespace_geometry_rejects_metadata_and_invalid_exponents() {
        assert_eq!(
            NamespaceInfo::parse(identity(1), 1, &identify_bytes(8, 0, 9, 8)),
            Err(NamespaceParseError::MetadataUnsupported)
        );
        assert_eq!(
            NamespaceInfo::parse(identity(1), 1, &identify_bytes(8, 0, 8, 0)),
            Err(NamespaceParseError::InvalidBlockSize)
        );
    }

    #[test]
    fn namespace_geometry_rejects_empty_and_out_of_range_formats() {
        assert_eq!(
            NamespaceInfo::parse(identity(1), 1, &identify_bytes(0, 0, 9, 0)),
            Err(NamespaceParseError::EmptyNamespace)
        );
        let mut bytes = identify_bytes(8, 0, 9, 0);
        bytes[NAMESPACE_FORMATTED_LBA_OFFSET] = 1;
        assert_eq!(
            NamespaceInfo::parse(identity(1), 1, &bytes),
            Err(NamespaceParseError::InvalidFormatIndex)
        );
    }

    #[test]
    fn transfer_length_and_encoding_follow_identified_geometry() {
        let namespace = NamespaceInfo::parse(identity(3), 7, &identify_bytes(u64::MAX, 0, 9, 0))
            .expect("valid geometry");
        let transfer =
            IoTransfer::for_namespace(namespace, TransferDirection::Read, 0x1122_3344_5566_7788, 8)
                .expect("in-range transfer");
        assert_eq!(transfer.logical_byte_count().get(), 4096);
        assert!(transfer.belongs_to(identity(3)));
        assert!(!transfer.belongs_to(identity(4)));
        let command = NvmeCommand::transfer(
            9,
            transfer,
            DmaDeviceAddress::from_abi(0x1000),
            Some(DmaDeviceAddress::from_abi(0x2000)),
        );
        let words = command.dwords();
        assert_eq!(words[0], 0x0009_0002);
        assert_eq!(words[1], 7);
        assert_eq!(words[6], 0x1000);
        assert_eq!(words[8], 0x2000);
        assert_eq!(words[10], 0x5566_7788);
        assert_eq!(words[11], 0x1122_3344);
        assert_eq!(words[12], 7);

        let large_blocks = NamespaceInfo::parse(identity(3), 7, &identify_bytes(8, 0, 12, 0))
            .expect("4096-byte blocks");
        assert_eq!(
            IoTransfer::for_namespace(large_blocks, TransferDirection::Write, 7, 1)
                .expect("last block")
                .logical_byte_count()
                .get(),
            4096
        );
    }

    #[test]
    fn transfer_range_rejects_empty_overflowing_and_outside_intervals() {
        let namespace = NamespaceInfo::parse(identity(1), 1, &identify_bytes(8, 0, 9, 0))
            .expect("valid geometry");
        assert_eq!(
            IoTransfer::for_namespace(namespace, TransferDirection::Read, 0, 0),
            Err(TransferRangeError::Empty)
        );
        assert_eq!(
            IoTransfer::for_namespace(namespace, TransferDirection::Read, u64::MAX, 1),
            Err(TransferRangeError::LbaOverflow)
        );
        assert_eq!(
            IoTransfer::for_namespace(namespace, TransferDirection::Read, 7, 2),
            Err(TransferRangeError::OutsideNamespace)
        );
    }
    fn namespace() -> NamespaceInfo {
        // NSZE=64, one format, 512-byte data blocks, no metadata.
        let mut bytes = [0; 4096];
        bytes[..8].copy_from_slice(&64u64.to_le_bytes());
        bytes[130] = 9;
        let identity =
            kernel_api::dma::DmaQueueIdentity::new(PackedPciLocation::new(0, 0, 3, 0), 0, 11)
                .expect("fixture queue");
        NamespaceInfo::parse(identity, 1, &bytes).expect("literal Identify Namespace vector")
    }

    extern "C" fn activation_must_not_run(_cookie: *mut core::ffi::c_void) -> i32 {
        panic!("validation must not consume the activation cookie");
    }

    fn submission() -> AbiBlockSubmission {
        AbiBlockSubmission {
            request_id: 17,
            command: AbiBlockCommandKind::Read as u32,
            lba: 63,
            blocks: 1,
            bytes: 512,
            iova: 0x1ff0,
            lease_id: 5,
            generation: 11,
            activation: core::ptr::null_mut(),
            activate: activation_must_not_run,
        }
    }

    #[test]
    fn admitted_transfer_encodes_two_page_prps_without_cpu_authority() {
        let BlockCommand::Transfer {
            transfer,
            address,
            prp2,
        } = namespace()
            .admit_submission(&submission())
            .expect("last complete namespace block")
        else {
            panic!("read must remain a transfer");
        };
        assert_eq!(transfer.logical_byte_count().get(), 512);
        assert_eq!(address.get(), 0x1ff0);
        assert_eq!(prp2.map(DmaDeviceAddress::get), Some(0x2000));
    }

    #[test]
    fn submission_validation_rejects_stale_or_outside_geometry_before_activation() {
        let namespace = namespace();
        let mut input = submission();
        assert!(matches!(
            namespace.admit_submission(&AbiBlockSubmission {
                generation: 12,
                ..input
            }),
            Err(AbiError::InvalidParam)
        ));
        input.blocks = 0;
        assert!(namespace.admit_submission(&input).is_err());
        input.blocks = 1;
        input.lba = 64;
        assert!(namespace.admit_submission(&input).is_err());
        input.lba = u64::MAX;
        assert!(namespace.admit_submission(&input).is_err());
    }

    #[test]
    fn transfer_extent_alignment_and_inline_capacity_are_admission_conditions() {
        let namespace = namespace();
        let mut input = submission();
        input.bytes = 511;
        assert!(namespace.admit_submission(&input).is_err());
        input.bytes = 512;
        input.iova = 0x1001;
        assert!(namespace.admit_submission(&input).is_err());
        input.iova = u64::MAX - 3;
        assert!(namespace.admit_submission(&input).is_err());
        input.iova = 0x1000;
        input.lba = 0;
        input.blocks = 9;
        input.bytes = 4608;
        assert!(namespace.admit_submission(&input).is_err());
    }

    #[test]
    fn flush_has_a_notification_and_no_transfer_allocation() {
        let mut input = submission();
        input.command = AbiBlockCommandKind::Flush as u32;
        assert!(namespace().admit_submission(&input).is_err());
        input.blocks = 0;
        input.bytes = 0;
        input.iova = 0;
        input.lease_id = 0;
        assert!(matches!(
            namespace().admit_submission(&input),
            Ok(BlockCommand::Flush)
        ));
        input.command = AbiBlockCommandKind::Discard as u32;
        assert!(matches!(
            namespace().admit_submission(&input),
            Err(AbiError::NotSupported)
        ));
    }
}
