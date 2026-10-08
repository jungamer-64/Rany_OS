use super::*;
use core::num::NonZeroU32;
use kernel_api::service::storage::BlockTransferError;

/// A checked block extent. This kernel handle describes routing and bounds;
/// application opens additionally require the resource registry's authority.
#[derive(Debug, Clone, Copy)]
pub struct DirectBlockHandle {
    device: IoDeviceId,
    start_block: u64,
    block_count: u64,
    block_size: NonZeroU32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockSpan {
    lba: u64,
    blocks: u16,
    bytes: usize,
}

impl DirectBlockHandle {
    /// # Errors
    /// Rejects zero geometry, overflowing extents and byte capacities.
    pub fn new(
        device: IoDeviceId,
        start_block: u64,
        block_count: u64,
        block_size: u32,
    ) -> FsResult<Self> {
        let block_size = NonZeroU32::new(block_size).ok_or(FsError::InvalidArgument)?;
        if block_count == 0
            || start_block.checked_add(block_count).is_none()
            || block_count
                .checked_mul(u64::from(block_size.get()))
                .is_none()
        {
            return Err(FsError::InvalidArgument);
        }
        Ok(Self {
            device,
            start_block,
            block_count,
            block_size,
        })
    }

    pub const fn block_count(&self) -> u64 {
        self.block_count
    }
    pub const fn block_size(&self) -> u32 {
        self.block_size.get()
    }

    /// Empty operations are allowed at the end of the extent. Nonempty DMA
    /// transfers must fit completely; silently clipping a lease changes what
    /// its returned completion means.
    fn span(&self, offset: u64, bytes: usize) -> FsResult<BlockSpan> {
        let size = self.block_size.get() as usize;
        if bytes % size != 0 || offset > self.block_count {
            return Err(FsError::InvalidArgument);
        }
        let blocks = u64::try_from(bytes / size).map_err(|_| FsError::InvalidArgument)?;
        if blocks > self.block_count - offset {
            return Err(FsError::InvalidArgument);
        }
        Ok(BlockSpan {
            lba: self
                .start_block
                .checked_add(offset)
                .ok_or(FsError::InvalidArgument)?,
            blocks: u16::try_from(blocks).map_err(|_| FsError::InvalidArgument)?,
            bytes,
        })
    }

    async fn transfer(
        &self,
        offset: u64,
        buffer: CpuDmaLease,
        direction: TransferDirection,
    ) -> BlockTransferOutcome {
        let span = match self.span(offset, buffer.byte_count().get()) {
            Ok(span) => span,
            Err(_) => {
                return BlockTransferOutcome::Returned {
                    result: Err(BlockTransferError::InvalidRange),
                    buffer,
                };
            }
        };
        let command = match direction {
            TransferDirection::Read => IoCommand::BlockRead {
                lba: span.lba,
                blocks: span.blocks,
                buffer,
            },
            TransferDirection::Write => IoCommand::BlockWrite {
                lba: span.lba,
                blocks: span.blocks,
                buffer,
            },
        };
        transfer_outcome(
            hybrid_coordinator()
                .submit_io_command(self.device, command, IoPriority::Normal)
                .await,
        )
    }

    pub async fn read_blocks_dma(&self, offset: u64, buffer: CpuDmaLease) -> BlockTransferOutcome {
        self.transfer(offset, buffer, TransferDirection::Read).await
    }

    pub async fn write_blocks_dma(&self, offset: u64, buffer: CpuDmaLease) -> BlockTransferOutcome {
        self.transfer(offset, buffer, TransferDirection::Write)
            .await
    }

    pub async fn flush(&self) -> FsResult<()> {
        control_result(
            hybrid_coordinator()
                .submit_io_command(self.device, IoCommand::Flush, IoPriority::High)
                .await,
        )
    }

    pub async fn discard(&self, offset: u64, count: u64) -> FsResult<()> {
        let bytes = count
            .checked_mul(u64::from(self.block_size.get()))
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or(FsError::InvalidArgument)?;
        let span = self.span(offset, bytes)?;
        if span.blocks == 0 {
            return Ok(());
        }
        control_result(
            hybrid_coordinator()
                .submit_io_command(
                    self.device,
                    IoCommand::Discard {
                        lba: span.lba,
                        blocks: span.blocks,
                    },
                    IoPriority::Normal,
                )
                .await,
        )
    }
}

enum TransferDirection {
    Read,
    Write,
}

fn transfer_error(cause: IoError) -> BlockTransferError {
    match cause {
        IoError::DeviceError => BlockTransferError::DeviceFailure,
        IoError::Timeout => BlockTransferError::Timeout,
        IoError::Cancelled => BlockTransferError::Cancelled,
        IoError::InvalidParameter => BlockTransferError::InvalidRange,
        IoError::NoResources => BlockTransferError::NoResources,
        IoError::Busy => BlockTransferError::Busy,
        IoError::NotSupported => BlockTransferError::NotSupported,
    }
}

fn transfer_outcome(completion: IoCompletion) -> BlockTransferOutcome {
    match completion {
        IoCompletion::TransferReturned { result, buffer } => BlockTransferOutcome::Returned {
            result: result.map_err(transfer_error),
            buffer,
        },
        IoCompletion::OutcomeUnknown { cause, .. } => BlockTransferOutcome::Retained {
            cause: transfer_error(cause),
            reason: BlockTransferRetention::CompletionUncertain,
        },
        IoCompletion::AuthorityQuarantined { cause, .. } => BlockTransferOutcome::Retained {
            cause: transfer_error(cause),
            reason: BlockTransferRetention::AuthorityQuarantined,
        },
        IoCompletion::Control { .. } => BlockTransferOutcome::Retained {
            cause: BlockTransferError::DeviceFailure,
            reason: BlockTransferRetention::CompletionUncertain,
        },
    }
}

pub(super) fn map_io_error(cause: IoError) -> FsError {
    map_transfer_error(transfer_error(cause))
}

fn map_transfer_error(cause: BlockTransferError) -> FsError {
    match cause {
        BlockTransferError::InvalidRange => FsError::InvalidArgument,
        BlockTransferError::NotSupported => FsError::NotSupported,
        BlockTransferError::Cancelled => FsError::Interrupted,
        _ => FsError::IoError,
    }
}

fn finalize(buffer: CpuDmaLease) -> FsResult<()> {
    io_scheduler()
        .finalize_transfer(buffer)
        .map_err(|_| FsError::IoError)
}

fn control_result(completion: IoCompletion) -> FsResult<()> {
    match completion {
        IoCompletion::Control { result } => result.map(|_| ()).map_err(map_io_error),
        IoCompletion::TransferReturned { buffer, .. } => {
            finalize(buffer)?;
            Err(FsError::IoError)
        }
        IoCompletion::OutcomeUnknown { cause, .. }
        | IoCompletion::AuthorityQuarantined { cause, .. } => Err(map_io_error(cause)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn extent_and_command_boundaries_are_checked() {
        assert!(
            DirectBlockHandle::new(
                IoDeviceId::Nvme {
                    controller: 0,
                    namespace: 1
                },
                0,
                1,
                0
            )
            .is_err()
        );
        assert!(
            DirectBlockHandle::new(
                IoDeviceId::Nvme {
                    controller: 0,
                    namespace: 1
                },
                u64::MAX,
                1,
                512
            )
            .is_err()
        );
        let range = DirectBlockHandle::new(
            IoDeviceId::Nvme {
                controller: 0,
                namespace: 1,
            },
            17,
            100_000,
            512,
        )
        .unwrap();
        assert_eq!(range.span(100_000, 0).unwrap().blocks, 0);
        assert!(range.span(100_000, 512).is_err());
        assert!(range.span(0, 513).is_err());
        assert_eq!(range.span(0, 65_535 * 512).unwrap().blocks, u16::MAX);
        assert!(range.span(0, 65_536 * 512).is_err());
    }
}
