use super::*;

pub(crate) fn register_port(
    owner: DomainId,
    dma_device: crate::io::iommu::types::DeviceId,
    registration: &AbiNetPortRegistration,
) -> kernel_api::error::KapiResult<u64> {
    NETDEV_PORTS.register(owner, dma_device, registration)
}

pub(crate) fn unregister_port(owner: DomainId, handle: u64) -> Result<(), AbiErrorCode> {
    NETDEV_PORTS.unregister(owner, handle)
}

pub(crate) fn cleanup_owner(owner: DomainId) -> Result<usize, NetOwnerCleanupError> {
    NETDEV_PORTS.cleanup_owner(owner)
}
