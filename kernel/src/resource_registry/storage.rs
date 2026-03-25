use super::*;

pub(crate) fn register_block_device(
    owner: DomainId,
    registration: &AbiBlockDeviceRegistration,
) -> Result<u64, AbiErrorCode> {
    BLOCK_DEVICES.register(owner, registration)
}

pub(crate) fn unregister_block_device(owner: DomainId, handle: u64) -> Result<(), AbiErrorCode> {
    BLOCK_DEVICES.unregister(owner, handle)
}

pub(crate) fn cleanup_owner(owner: DomainId) -> usize {
    BLOCK_DEVICES.cleanup_owner(owner)
}

pub(crate) fn standalone_storage_devices() -> Vec<StorageDeviceInfo> {
    BLOCK_DEVICES.storage_devices()
}
