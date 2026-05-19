use super::*;

pub(crate) unsafe fn release_dma_buffer(dma_handle_id: u64) {
    if let Err(err) = release_dma_buffer_checked(dma_handle_id) {
        log::warn!(
            "[KAPI] release_dma_buffer ignored invalid DMA release: handle={} err={:?}",
            dma_handle_id,
            err
        );
    }
}

pub(crate) fn release_dma_buffer_checked(dma_handle_id: u64) -> Result<(), KapiError> {
    if dma_handle_id == 0 {
        return Err(KapiError::InvalidHandle);
    }

    let caller = context::current_subject().domain.as_u64();

    match crate::resource_registry::dma::release_owned(dma_handle_id, caller) {
        Ok(()) => Ok(()),
        Err(crate::resource_registry::dma::DmaReleaseError::ForeignOwner { owner }) => {
            log::error!(
                "[KAPI][SECURITY] release_dma_buffer: Domain {} tried to drop DMA handle {} owned by Domain {}",
                caller,
                dma_handle_id,
                owner
            );
            Err(KapiError::PermissionDenied)
        }
        Err(crate::resource_registry::dma::DmaReleaseError::UnknownHandle) => {
            log::info!(
                "[KAPI] release_dma_buffer: unknown DMA handle: {}\n",
                dma_handle_id
            );
            Err(KapiError::InvalidHandle)
        }
    }
}
