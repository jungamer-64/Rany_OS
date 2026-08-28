use super::*;

pub(super) fn create_channel() -> Result<(ChannelHandle, ChannelHandle), KapiError> {
    let owner = current_subject().domain.as_u64();
    let (writer_id, reader_id) = crate::resource_registry::ipc::create_channel(owner);
    Ok((ChannelHandle::new(writer_id), ChannelHandle::new(reader_id)))
}

pub(super) fn close(channel: ChannelHandle) -> Result<(), KapiError> {
    let caller = current_subject().domain.as_u64();
    crate::resource_registry::ipc::unregister_channel_owned(channel.id(), caller)
}

pub(super) fn current_domain() -> kernel_api::ipc::DomainId {
    kernel_api::ipc::DomainId::new(current_subject().domain.as_u64())
}

pub(super) fn exchange_alloc_raw(
    size: usize,
    align: usize,
) -> Result<(NonNull<u8>, kernel_api::ipc::DomainId), KapiError> {
    let layout = core::alloc::Layout::from_size_align(size.max(1), align.max(1))
        .map_err(|_| KapiError::InvalidHandle)?;
    let owner = current_subject().domain;
    let ptr =
        crate::mm::cache::exchange_heap::allocate_raw(layout).ok_or(KapiError::OutOfMemory)?;
    crate::sas::register_object(ptr.as_ptr() as usize, layout.size(), owner);
    Ok((ptr, kernel_api::ipc::DomainId::new(owner.as_u64())))
}

pub(super) fn exchange_dealloc_raw(
    ptr: NonNull<u8>,
    owner: kernel_api::ipc::DomainId,
    size: usize,
    align: usize,
) -> Result<(), KapiError> {
    let caller = current_subject().domain.as_u64();
    if owner != kernel_api::ipc::DomainId::KERNEL && caller != owner.as_u64() {
        return Err(KapiError::PermissionDenied);
    }
    if owner != kernel_api::ipc::DomainId::KERNEL
        && crate::sas::get_owner(ptr.as_ptr() as usize)
            != Some(crate::domain::DomainId::new(owner.as_u64()))
    {
        return Err(KapiError::PermissionDenied);
    }

    let layout = core::alloc::Layout::from_size_align(size.max(1), align.max(1))
        .map_err(|_| KapiError::InvalidHandle)?;
    crate::sas::unregister_any(ptr.as_ptr() as usize);
    unsafe {
        crate::mm::cache::exchange_heap::deallocate_raw(ptr, layout);
    }
    Ok(())
}

pub(super) fn exchange_transfer_raw(
    ptr: NonNull<u8>,
    from: kernel_api::ipc::DomainId,
    to: kernel_api::ipc::DomainId,
) -> Result<(), KapiError> {
    let caller = current_subject().domain.as_u64();
    if from != kernel_api::ipc::DomainId::KERNEL && caller != from.as_u64() {
        return Err(KapiError::PermissionDenied);
    }
    crate::sas::transfer_ownership(
        ptr.as_ptr() as usize,
        crate::domain::DomainId::new(from.as_u64()),
        crate::domain::DomainId::new(to.as_u64()),
    )
    .map_err(|_| KapiError::PermissionDenied)
}

pub(super) fn send_raw(
    channel: ChannelHandle,
    mut raw: kernel_api::abi::driver::AbiRRefRaw,
) -> Result<(), KapiError> {
    let caller = current_subject().domain;
    let ptr = NonNull::new(raw.ptr).ok_or(KapiError::InvalidHandle)?;
    if let Err(err) = exchange_transfer_raw(
        ptr,
        kernel_api::ipc::DomainId::new(caller.as_u64()),
        kernel_api::ipc::DomainId::KERNEL,
    ) {
        crate::resource_registry::ipc::drop_abi_rref_raw(raw);
        return Err(err);
    }

    raw.owner = kernel_api::ipc::DomainId::KERNEL.as_u64();
    if let Err(err) = crate::resource_registry::ipc::send_raw(channel, caller.as_u64(), raw) {
        if crate::sas::transfer_ownership(
            ptr.as_ptr() as usize,
            crate::domain::DomainId::KERNEL,
            caller,
        )
        .is_ok()
        {
            raw.owner = caller.as_u64();
        }
        crate::resource_registry::ipc::drop_abi_rref_raw(raw);
        return Err(err);
    }
    Ok(())
}

pub(super) fn recv_raw(
    channel: ChannelHandle,
) -> Result<kernel_api::abi::driver::AbiRRefRaw, KapiError> {
    let caller = current_subject().domain;
    let mut raw = crate::resource_registry::ipc::recv_raw(channel, caller.as_u64())?;
    let ptr = NonNull::new(raw.ptr).ok_or(KapiError::InvalidHandle)?;
    exchange_transfer_raw(
        ptr,
        kernel_api::ipc::DomainId::KERNEL,
        kernel_api::ipc::DomainId::new(caller.as_u64()),
    )?;
    raw.owner = caller.as_u64();
    Ok(raw)
}
