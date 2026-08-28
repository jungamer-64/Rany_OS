use super::*;

pub(crate) fn release_dma_buffer_checked(dma_handle_id: u64) -> Result<(), KapiError> {
    let lease = DmaLeaseId::from_abi(dma_handle_id).ok_or(KapiError::InvalidHandle)?;
    let caller = current_subject().domain;

    crate::resource_registry::dma::close_owned(lease, caller).map_err(|error| match error {
        kernel_api::dma::DmaLeaseError::ForeignOwner => KapiError::PermissionDenied,
        kernel_api::dma::DmaLeaseError::StaleLease => KapiError::InvalidHandle,
        kernel_api::dma::DmaLeaseError::IommuFailure => KapiError::IoError,
        kernel_api::dma::DmaLeaseError::InvalidState
        | kernel_api::dma::DmaLeaseError::QueueMismatch => KapiError::ResourceExhausted,
        kernel_api::dma::DmaLeaseError::NotSupported
        | kernel_api::dma::DmaLeaseError::AuthorityViolation => KapiError::NotSupported,
    })
}
