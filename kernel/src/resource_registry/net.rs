use super::*;

pub(crate) fn register_port(
    owner: DomainId,
    registration: &AbiNetPortRegistrationV5,
) -> Result<u64, AbiErrorCode> {
    NETDEV_PORTS.register(owner, registration)
}

pub(crate) fn unregister_port(owner: DomainId, handle: u64) -> Result<(), AbiErrorCode> {
    NETDEV_PORTS.unregister(owner, handle)
}

pub(crate) fn cleanup_owner(owner: DomainId) -> usize {
    NETDEV_PORTS.cleanup_owner(owner)
}
