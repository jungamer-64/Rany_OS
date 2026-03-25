use super::*;

pub(crate) fn register_namespace(
    owner: DomainId,
    registration: &AbiNvmeNamespaceRegistration,
) -> Result<u64, AbiErrorCode> {
    NVME_NAMESPACES.register(owner, registration)
}

pub(crate) fn unregister_namespace(owner: DomainId, handle: u64) -> Result<(), AbiErrorCode> {
    NVME_NAMESPACES.unregister(owner, handle)
}

pub(crate) fn cleanup_owner(owner: DomainId) -> usize {
    NVME_NAMESPACES.cleanup_owner(owner)
}

pub(crate) fn standalone_namespace_info(namespace_id: u32) -> Option<AbiNvmeNamespaceInfo> {
    NvmeNamespaceRegistry::lookup(namespace_id)
}
