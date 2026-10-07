use super::*;

fn map_open_error(error: crate::resource_registry::direct_block::NvmeOpenError) -> KapiError {
    match error {
        crate::resource_registry::direct_block::NvmeOpenError::InvalidHandle => {
            KapiError::InvalidHandle
        }
        crate::resource_registry::direct_block::NvmeOpenError::PermissionDenied => {
            KapiError::PermissionDenied
        }
    }
}

fn resolve_direct_handle(
    handle: DirectBlockHandle,
) -> Result<crate::fs::DirectBlockHandle, KapiError> {
    let open_id = handle.open_id();
    if open_id == 0 {
        return Err(KapiError::InvalidHandle);
    }

    let caller = current_subject().domain.as_u64();
    let entry = crate::resource_registry::direct_block::lookup_open_owned(open_id, caller)
        .map_err(map_open_error)?;

    if entry.device_id != handle.device_id()
        || entry.start_block != handle.start_block()
        || entry.block_count != handle.block_count()
        || entry.block_size != handle.block_size()
    {
        return Err(KapiError::InvalidHandle);
    }

    let device = crate::io::io_scheduler::DeviceId::from_storage_id(entry.device_id)
        .ok_or(KapiError::InvalidHandle)?;
    crate::fs::DirectBlockHandle::new(
        device,
        entry.start_block,
        entry.block_count,
        entry.block_size,
    )
    .map_err(|_| KapiError::InvalidHandle)
}

pub(super) fn open_direct_with_token(
    device_id: u64,
    start_block: u64,
    block_count: u64,
    token: Option<u64>,
) -> Result<DirectBlockHandle, KapiError> {
    let device = crate::io::io_scheduler::DeviceId::from_storage_id(device_id)
        .ok_or(KapiError::InvalidHandle)?;
    let geometry = crate::io::io_scheduler::io_scheduler()
        .get_device_ops(device)
        .ok_or(KapiError::NotFound)?
        .block_geometry()
        .ok_or(KapiError::Busy)?;
    let end = start_block
        .checked_add(block_count)
        .ok_or(KapiError::InvalidHandle)?;
    if block_count == 0 || end > geometry.block_count.get() {
        return Err(KapiError::InvalidHandle);
    }
    let block_size = geometry.block_size.get();

    let caller = current_subject().domain.as_u64();
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

pub(super) fn close_direct(handle: DirectBlockHandle) -> Result<(), KapiError> {
    let id = handle.open_id();
    if id == 0 {
        return Err(KapiError::InvalidHandle);
    }

    let caller = current_subject().domain.as_u64();
    match crate::resource_registry::direct_block::unregister_if_owner_or_admin(id, caller) {
        Ok(entry) => {
            if let Some(t) = entry.token {
                let _ = crate::security::capability::manager().decrement_in_flight(t);
            }
            Ok(())
        }
        Err(err) => Err(map_open_error(err)),
    }
}

pub(super) fn read_blocks_dma(
    handle: DirectBlockHandle,
    block_offset: u64,
    buffer: CpuDmaLease,
) -> Pin<Box<dyn Future<Output = kernel_api::service::storage::BlockTransferOutcome> + Send>> {
    Box::pin(async move {
        match resolve_direct_handle(handle) {
            Ok(direct) => direct.read_blocks_dma(block_offset, buffer).await,
            Err(cause) => kernel_api::service::storage::BlockTransferOutcome::Returned {
                result: Err(kernel_api::service::storage::BlockTransferError::Admission(
                    cause,
                )),
                buffer,
            },
        }
    })
}

pub(super) fn write_blocks_dma(
    handle: DirectBlockHandle,
    block_offset: u64,
    buffer: CpuDmaLease,
) -> Pin<Box<dyn Future<Output = kernel_api::service::storage::BlockTransferOutcome> + Send>> {
    Box::pin(async move {
        match resolve_direct_handle(handle) {
            Ok(direct) => direct.write_blocks_dma(block_offset, buffer).await,
            Err(cause) => kernel_api::service::storage::BlockTransferOutcome::Returned {
                result: Err(kernel_api::service::storage::BlockTransferError::Admission(
                    cause,
                )),
                buffer,
            },
        }
    })
}

pub(super) fn flush_direct(
    handle: DirectBlockHandle,
) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
    Box::pin(async move {
        let direct = resolve_direct_handle(handle)?;
        direct.flush().await.map_err(|_| KapiError::IoError)
    })
}

pub(super) fn discard_direct(
    handle: DirectBlockHandle,
    block_offset: u64,
    block_count: u64,
) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
    Box::pin(async move {
        let direct = resolve_direct_handle(handle)?;
        direct
            .discard(block_offset, block_count)
            .await
            .map_err(|_| KapiError::IoError)
    })
}

pub(super) fn block_size(device_id: u64) -> Option<u64> {
    let device = crate::io::io_scheduler::DeviceId::from_storage_id(device_id)?;
    crate::io::io_scheduler::io_scheduler()
        .get_device_ops(device)?
        .block_geometry()
        .map(|geometry| u64::from(geometry.block_size.get()))
}

pub(super) fn sgl_max_entries(_device_id: u64) -> Option<usize> {
    // This device path describes transfers with PRPs, without an SGL grant.
    None
}
