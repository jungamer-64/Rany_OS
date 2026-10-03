//! One retained block-device owner and a checked WAL extent. Transfers use
//! scheduler-owned CPU/DMA leases and never resolve the device after admission.

#![forbid(unsafe_code)]

use super::{WalError, WalStorage, WalStorageError};
use crate::io::io_scheduler::{
    DeviceId, DeviceOps, IoCommand, IoCompletion, IoPriority, io_scheduler,
};
use alloc::{boxed::Box, sync::Arc};
use core::{future::Future, pin::Pin};
use kernel_api::dma::{CpuDmaLease, DmaAllocationRequest, DmaDirection};
use kernel_api::service::storage::BlockTransferError;

pub struct BlockWalStorage {
    device: DeviceId,
    owner: Arc<dyn DeviceOps>,
    first_block: u64,
    block_count: u64,
    block_size: u32,
    max_blocks: u16,
    byte_len: u64,
}

enum Transfer {
    Read,
    Write,
}

impl BlockWalStorage {
    /// Retains the actual registered owner and validates the complete extent
    /// against its discovered geometry. Withdrawal cannot switch this lease
    /// to a replacement device with the same locator.
    /// # Errors
    /// Rejects missing/closed devices, overflowing bounds and unsupported
    /// logical sector sizes that cannot isolate WAL publication pages.
    pub fn open(device: DeviceId, first_block: u64, block_count: u64) -> Result<Self, WalError> {
        let owner = io_scheduler()
            .get_device_ops(device)
            .ok_or(WalError::BackendUnavailable)?;
        let geometry = owner.block_geometry().ok_or(WalError::BackendUnavailable)?;
        if !owner.is_ready() || block_count == 0 {
            return Err(WalError::InvalidConfig);
        }
        let end = first_block
            .checked_add(block_count)
            .ok_or(WalError::InvalidConfig)?;
        let block_size = geometry.block_size.get();
        if end > geometry.block_count.get() || 4096 % block_size != 0 {
            return Err(WalError::InvalidConfig);
        }
        let byte_len = block_count
            .checked_mul(u64::from(block_size))
            .ok_or(WalError::InvalidConfig)?;
        Ok(Self {
            device,
            owner,
            first_block,
            block_count,
            block_size,
            max_blocks: geometry.max_transfer_blocks.get(),
            byte_len,
        })
    }

    fn validate(&self, offset: u64, bytes: usize) -> Result<(), WalStorageError> {
        let end = offset
            .checked_add(u64::try_from(bytes).map_err(|_| WalStorageError::InvalidRange)?)
            .ok_or(WalStorageError::InvalidRange)?;
        if end > self.byte_len {
            return Err(WalStorageError::InvalidRange);
        }
        Ok(())
    }

    fn allocate(
        &self,
        bytes: usize,
        direction: DmaDirection,
    ) -> Result<CpuDmaLease, WalStorageError> {
        let request =
            DmaAllocationRequest::new(bytes, direction).ok_or(WalStorageError::InvalidRange)?;
        self.owner
            .allocate_transfer(request)
            .map_err(|cause| WalStorageError::Io(transfer_error(cause)))
    }

    async fn transfer(
        &self,
        block: u64,
        blocks: u16,
        buffer: CpuDmaLease,
        transfer: Transfer,
    ) -> Result<CpuDmaLease, WalStorageError> {
        let expected = buffer.byte_count().get();
        let end = block
            .checked_add(u64::from(blocks))
            .ok_or(WalStorageError::InvalidRange)?;
        if blocks == 0 || end > self.block_count || blocks > self.max_blocks {
            io_scheduler()
                .finalize_transfer(buffer)
                .map_err(WalStorageError::Close)?;
            return Err(WalStorageError::InvalidRange);
        }
        let lba = self.first_block + block;
        let command = match transfer {
            Transfer::Write => IoCommand::BlockWrite {
                lba,
                blocks,
                buffer,
            },
            Transfer::Read => IoCommand::BlockRead {
                lba,
                blocks,
                buffer,
            },
        };
        match io_scheduler()
            .submit_to_device(
                self.device,
                Arc::clone(&self.owner),
                command,
                IoPriority::High,
            )
            .await
        {
            IoCompletion::TransferReturned { result, buffer } => match result {
                Ok(actual) if actual == expected => Ok(buffer),
                result => {
                    io_scheduler()
                        .finalize_transfer(buffer)
                        .map_err(WalStorageError::Close)?;
                    match result {
                        Err(cause) => Err(WalStorageError::Io(transfer_error(cause))),
                        Ok(actual) => Err(WalStorageError::ShortTransfer { expected, actual }),
                    }
                }
            },
            IoCompletion::OutcomeUnknown { cause, .. } => {
                Err(WalStorageError::OutcomeUnknown(transfer_error(cause)))
            }
            IoCompletion::AuthorityQuarantined { cause, .. } => {
                Err(WalStorageError::AuthorityRetained(transfer_error(cause)))
            }
            IoCompletion::Control { .. } => Err(WalStorageError::OutcomeUnknown(
                BlockTransferError::DeviceFailure,
            )),
        }
    }

    async fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), WalStorageError> {
        self.validate(offset, out.len())?;
        let sector = self.block_size as usize;
        let mut copied = 0;
        // LOOP_PROOF: mode=bounded; reason=Each completed block transfer advances the output cursor by a positive number of bytes within the checked extent.;
        while copied < out.len() {
            let position = offset + copied as u64;
            let block = position / u64::from(self.block_size);
            let in_block = (position % u64::from(self.block_size)) as usize;
            let remaining = out.len() - copied;
            let max = usize::from(self.max_blocks) * sector;
            let bytes = remaining.min(max - in_block);
            let blocks = (in_block + bytes).div_ceil(sector);
            let dma_bytes = blocks * sector;
            let buffer = self.allocate(dma_bytes, DmaDirection::FromDevice)?;
            let buffer = self
                .transfer(block, blocks as u16, buffer, Transfer::Read)
                .await?;
            let copy = buffer.read(|view| {
                out[copied..copied + bytes].copy_from_slice(&view[in_block..in_block + bytes])
            });
            io_scheduler()
                .finalize_transfer(buffer)
                .map_err(WalStorageError::Close)?;
            copy.map_err(WalStorageError::Close)?;
            copied += bytes;
        }
        Ok(())
    }

    async fn write(&mut self, offset: u64, bytes: &[u8]) -> Result<(), WalStorageError> {
        self.validate(offset, bytes.len())?;
        let sector = self.block_size as usize;
        // Publication pages are isolated from committed pages. Unaligned RMW
        // could tear a preceding transaction even if its root remains valid.
        if offset % u64::from(self.block_size) != 0 || bytes.len() % sector != 0 {
            return Err(WalStorageError::InvalidRange);
        }
        let mut copied = 0;
        // LOOP_PROOF: mode=bounded; reason=Each owned write advances by a positive complete-sector chunk within the input slice.;
        while copied < bytes.len() {
            let len = (bytes.len() - copied).min(usize::from(self.max_blocks) * sector);
            let block = offset / u64::from(self.block_size) + (copied / sector) as u64;
            let mut buffer = self.allocate(len, DmaDirection::ToDevice)?;
            let copy = buffer.copy_from_slice(&bytes[copied..copied + len]);
            if let Err(cause) = copy {
                io_scheduler()
                    .finalize_transfer(buffer)
                    .map_err(WalStorageError::Close)?;
                return Err(WalStorageError::Close(cause));
            }
            let buffer = self
                .transfer(block, (len / sector) as u16, buffer, Transfer::Write)
                .await?;
            io_scheduler()
                .finalize_transfer(buffer)
                .map_err(WalStorageError::Close)?;
            copied += len;
        }
        Ok(())
    }
}

impl WalStorage for BlockWalStorage {
    fn byte_len(&self) -> u64 {
        self.byte_len
    }
    fn read_at<'a>(
        &'a mut self,
        offset: u64,
        out: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), WalStorageError>> + Send + 'a>> {
        Box::pin(self.read(offset, out))
    }
    fn write_at<'a>(
        &'a mut self,
        offset: u64,
        bytes: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), WalStorageError>> + Send + 'a>> {
        Box::pin(self.write(offset, bytes))
    }
    fn sync(&mut self) -> Pin<Box<dyn Future<Output = Result<(), WalStorageError>> + Send + '_>> {
        Box::pin(async {
            match io_scheduler()
                .submit_to_device(
                    self.device,
                    Arc::clone(&self.owner),
                    IoCommand::Flush,
                    IoPriority::High,
                )
                .await
            {
                IoCompletion::Control { result } => result
                    .map(|_| ())
                    .map_err(|cause| WalStorageError::Io(transfer_error(cause))),
                IoCompletion::OutcomeUnknown { cause, .. } => {
                    Err(WalStorageError::OutcomeUnknown(transfer_error(cause)))
                }
                IoCompletion::AuthorityQuarantined { cause, .. } => {
                    Err(WalStorageError::AuthorityRetained(transfer_error(cause)))
                }
                IoCompletion::TransferReturned { buffer, .. } => {
                    io_scheduler()
                        .finalize_transfer(buffer)
                        .map_err(WalStorageError::Close)?;
                    Err(WalStorageError::OutcomeUnknown(
                        BlockTransferError::DeviceFailure,
                    ))
                }
            }
        })
    }
}

fn transfer_error(cause: crate::io::io_scheduler::IoError) -> BlockTransferError {
    use crate::io::io_scheduler::IoError;
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
