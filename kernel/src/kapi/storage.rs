use super::*;

pub(crate) fn open_direct_with_token(
    device_id: u64,
    start_block: u64,
    block_count: u64,
    token: Option<u64>,
) -> Result<DirectBlockHandle, KapiError> {
    if block_count == 0 {
        return Err(KapiError::IoError);
    }

    let nsid = if device_id == 0 { 1 } else { device_id as u32 };
    let block_size = crate::resource_registry::nvme::standalone_namespace_info(nsid)
        .map(|info| info.block_size)
        .or_else(|| crate::drivers::nvme::with_driver(|driver| driver.namespace_block_size(nsid)))
        .unwrap_or(512);

    let caller = context::current_subject().domain.as_u64();
    if let Some(t) = token {
        if !crate::security::capability::manager().validate_token(
            caller,
            t,
            crate::security::capability::CAP_DMA,
        ) {
            return Err(KapiError::PermissionDenied);
        }
        if crate::security::capability::manager()
            .increment_in_flight(t)
            .is_err()
        {
            return Err(KapiError::PermissionDenied);
        }
    }

    let id = crate::resource_registry::direct_block::register_open(
        device_id,
        start_block,
        block_count,
        block_size,
        caller,
        token,
    );
    Ok(DirectBlockHandle::new_with_id(
        device_id,
        start_block,
        block_count,
        block_size,
        id,
    ))
}

pub(crate) fn close_direct(handle: DirectBlockHandle) -> Result<(), KapiError> {
    let id = handle.open_id();
    if id == 0 {
        return Err(KapiError::InvalidHandle);
    }

    let caller = context::current_subject().domain.as_u64();
    match crate::resource_registry::direct_block::unregister_if_owner_or_admin(id, caller) {
        Some(entry) => {
            if let Some(t) = entry.token {
                let _ = crate::security::capability::manager().decrement_in_flight(t);
            }
            Ok(())
        }
        None => Err(KapiError::InvalidHandle),
    }
}

pub(crate) fn read_blocks_dma(
    handle: DirectBlockHandle,
    block_offset: u64,
    buffer: DmaBuffer,
) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>> {
    Box::pin(async move {
        let direct = crate::fs::DirectBlockHandle::new(
            handle.device_id(),
            handle.start_block(),
            handle.block_count(),
            handle.block_size(),
        );
        direct
            .read_blocks_dma(block_offset, buffer)
            .await
            .map_err(|_| KapiError::IoError)
    })
}

pub(crate) fn write_blocks_dma(
    handle: DirectBlockHandle,
    block_offset: u64,
    buffer: DmaBuffer,
) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>> {
    Box::pin(async move {
        let direct = crate::fs::DirectBlockHandle::new(
            handle.device_id(),
            handle.start_block(),
            handle.block_count(),
            handle.block_size(),
        );
        direct
            .write_blocks_dma(block_offset, buffer)
            .await
            .map_err(|_| KapiError::IoError)
    })
}

pub(crate) fn flush_direct(
    handle: DirectBlockHandle,
) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
    Box::pin(async move {
        let direct = crate::fs::DirectBlockHandle::new(
            handle.device_id(),
            handle.start_block(),
            handle.block_count(),
            handle.block_size(),
        );
        direct.flush().await.map_err(|_| KapiError::IoError)
    })
}

pub(crate) fn discard_direct(
    handle: DirectBlockHandle,
    block_offset: u64,
    block_count: u64,
) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
    Box::pin(async move {
        let direct = crate::fs::DirectBlockHandle::new(
            handle.device_id(),
            handle.start_block(),
            handle.block_count(),
            handle.block_size(),
        );
        direct
            .discard(block_offset, block_count)
            .await
            .map_err(|_| KapiError::IoError)
    })
}

pub(crate) fn block_size(device_id: u64) -> Option<u64> {
    let nsid = if device_id == 0 { 1 } else { device_id as u32 };
    crate::resource_registry::nvme::standalone_namespace_info(nsid)
        .map(|info| info.block_size as u64)
        .or_else(|| {
            crate::drivers::nvme::with_driver(|driver| driver.namespace_block_size(nsid) as u64)
        })
}

pub(crate) fn sgl_max_entries(device_id: u64) -> Option<usize> {
    let nsid = if device_id == 0 { 1 } else { device_id as u32 };
    crate::resource_registry::nvme::standalone_namespace_info(nsid)
        .map(|info| info.max_sgl_entries as usize)
        .or_else(|| {
            crate::drivers::nvme::global::with_driver(
                |driver: &crate::drivers::nvme::NvmePollingDriver| driver.sgl_max_entries(),
            )
            .flatten()
        })
}

pub(crate) fn submit_rw(request: NvmeRwRequest, io_type: NvmeIoType) -> KapiResult<NvmeIoHandle> {
    use crate::io::io_scheduler::{DeviceId as IoDeviceId, DmaBufHandle, IoCommand, IoPriority};

    let device = IoDeviceId::Nvme {
        controller: 0,
        namespace: request.namespace_id,
    };

    let priority = match request.priority {
        NvmeIoPriority::Background => IoPriority::Background,
        NvmeIoPriority::Idle => IoPriority::Idle,
        NvmeIoPriority::Normal => IoPriority::Normal,
        NvmeIoPriority::High => IoPriority::High,
        NvmeIoPriority::Realtime => IoPriority::Realtime,
    };

    let command = match io_type {
        NvmeIoType::Read => IoCommand::BlockRead {
            lba: request.lba,
            blocks: request.blocks,
            bytes: request.bytes,
            buf: DmaBufHandle {
                iova: request.prp1,
                len: request.bytes,
            },
        },
        NvmeIoType::Write => IoCommand::BlockWrite {
            lba: request.lba,
            blocks: request.blocks,
            bytes: request.bytes,
            buf: DmaBufHandle {
                iova: request.prp1,
                len: request.bytes,
            },
        },
        NvmeIoType::Flush => IoCommand::Flush,
        NvmeIoType::Discard => IoCommand::Discard {
            lba: request.lba,
            blocks: request.blocks as u16,
        },
    };

    let future =
        crate::io::io_scheduler::hybrid_coordinator().submit_io_command(device, command, priority);
    Ok(NvmeIoHandle::new(future.request_id().0))
}

pub(crate) fn wait_io(handle: NvmeIoHandle) -> Pin<Box<dyn Future<Output = NvmeIoResult> + Send>> {
    use crate::io::io_scheduler::{IoRequestId, IoResult as SchedIoResult};

    let request_id = IoRequestId(handle.request_id());
    Box::pin(async move {
        loop {
            if let Some(result) = crate::io::io_scheduler::io_scheduler().take_result(request_id) {
                return match result {
                    SchedIoResult::Success(bytes) => NvmeIoResult::Success(bytes),
                    SchedIoResult::Error(e) => match e {
                        crate::io::io_scheduler::IoError::Timeout => NvmeIoResult::Timeout,
                        crate::io::io_scheduler::IoError::Cancelled => NvmeIoResult::Cancelled,
                        crate::io::io_scheduler::IoError::InvalidParameter => {
                            NvmeIoResult::InvalidParameter
                        }
                        _ => NvmeIoResult::DeviceError,
                    },
                };
            }
            core::hint::spin_loop();
        }
    })
}

pub(crate) fn register_completion_hook(
    handle: NvmeIoHandle,
    hook: Box<dyn FnOnce(NvmeIoResult) + Send>,
) {
    use crate::io::io_scheduler::{CompletionHook, IoRequestId, IoResult as SchedIoResult};

    let request_id = IoRequestId(handle.request_id());
    let wrapper: CompletionHook = Box::new(move |result: SchedIoResult| {
        let converted = match result {
            SchedIoResult::Success(bytes) => NvmeIoResult::Success(bytes),
            SchedIoResult::Error(e) => match e {
                crate::io::io_scheduler::IoError::Timeout => NvmeIoResult::Timeout,
                crate::io::io_scheduler::IoError::Cancelled => NvmeIoResult::Cancelled,
                crate::io::io_scheduler::IoError::InvalidParameter => {
                    NvmeIoResult::InvalidParameter
                }
                _ => NvmeIoResult::DeviceError,
            },
        };
        hook(converted);
    });

    crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, wrapper);
}
