use crate::domain::DomainId;
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use kernel_api::abi::driver::AbiError as AbiErrorCode;
use kernel_api::abi::driver::{
    AbiBlockDeviceRegistration, AbiNetPortRegistrationV3, AbiNvmeNamespaceRegistration,
    PackedPciLocation,
};
use kernel_api::error::KapiError;

pub(crate) fn unpack_device_id(locator: PackedPciLocation) -> IommuDeviceId {
    IommuDeviceId {
        segment: locator.segment(),
        bus: locator.bus(),
        device: locator.device(),
        function: locator.function(),
    }
}

pub(crate) fn authorize_pci_locator_for_domain(
    caller: DomainId,
    requested: PackedPciLocation,
    bound_locator: Option<PackedPciLocation>,
) -> Result<(), KapiError> {
    if requested.is_null() {
        log::warn!("[KAPI] alloc_dma_for_device rejected null PCI locator");
        return Err(KapiError::NotSupported);
    }

    if caller == DomainId::KERNEL {
        return Ok(());
    }

    let Some(bound_locator) = bound_locator else {
        log::error!(
            "[KAPI][SECURITY] Domain {} requested DMA for PCI locator 0x{:x} without a bound driver device",
            caller,
            requested.raw()
        );
        return Err(KapiError::PermissionDenied);
    };

    if bound_locator.is_null() || bound_locator != requested {
        log::error!(
            "[KAPI][SECURITY] Domain {} requested DMA for PCI locator 0x{:x} but owns 0x{:x}",
            caller,
            requested.raw(),
            bound_locator.raw()
        );
        return Err(KapiError::PermissionDenied);
    }

    Ok(())
}

pub(crate) fn authorize_dma_device_for_current_subject(
    device_id: PackedPciLocation,
) -> Result<IommuDeviceId, KapiError> {
    let caller = crate::task::context::current_subject().domain;
    let bound_locator = if caller == DomainId::KERNEL {
        None
    } else {
        let manager = crate::driver_domain::driver_domain_manager();
        let Some(driver_domain_id) = manager.find_by_domain(caller) else {
            authorize_pci_locator_for_domain(caller, device_id, None)?;
            unreachable!("non-kernel domains without a bound driver device must be rejected");
        };
        Some(
            manager
                .with_cell(driver_domain_id, |cell| {
                    cell.abi_driver_context.pci_location()
                })
                .map_err(|err| {
                    log::error!(
                        "[KAPI][SECURITY] Failed to resolve PCI locator for domain {}: {:?}",
                        caller,
                        err
                    );
                    KapiError::PermissionDenied
                })?,
        )
    };

    authorize_pci_locator_for_domain(caller, device_id, bound_locator)?;
    Ok(unpack_device_id(device_id))
}

pub(crate) fn current_driver_domain() -> Result<DomainId, KapiError> {
    let domain = crate::task::context::current_subject().domain;
    if domain == DomainId::KERNEL {
        return Err(KapiError::PermissionDenied);
    }
    if crate::driver_domain::driver_domain_manager()
        .find_by_domain(domain)
        .is_none()
    {
        return Err(KapiError::PermissionDenied);
    }
    Ok(domain)
}

fn map_registry_error(error: AbiErrorCode) -> KapiError {
    match error {
        AbiErrorCode::PermissionDenied => KapiError::PermissionDenied,
        AbiErrorCode::DeviceBusy => KapiError::ResourceExhausted,
        AbiErrorCode::DeviceNotFound => KapiError::NotFound,
        AbiErrorCode::NotSupported => KapiError::NotSupported,
        AbiErrorCode::InvalidParam => KapiError::InvalidHandle,
        _ => KapiError::IoError,
    }
}

pub(crate) fn register_block_device_for_current_subject(
    registration: &AbiBlockDeviceRegistration,
) -> Result<u64, KapiError> {
    let owner = current_driver_domain()?;
    crate::resource_registry::storage::register_block_device(owner, registration)
        .map_err(map_registry_error)
}

pub(crate) fn unregister_block_device_for_current_subject(handle: u64) -> Result<(), KapiError> {
    let owner = current_driver_domain()?;
    crate::resource_registry::storage::unregister_block_device(owner, handle)
        .map_err(map_registry_error)
}

pub(crate) fn register_nvme_namespace_for_current_subject(
    registration: &AbiNvmeNamespaceRegistration,
) -> Result<u64, KapiError> {
    let owner = current_driver_domain()?;
    crate::resource_registry::nvme::register_namespace(owner, registration)
        .map_err(map_registry_error)
}

pub(crate) fn unregister_nvme_namespace_for_current_subject(handle: u64) -> Result<(), KapiError> {
    let owner = current_driver_domain()?;
    crate::resource_registry::nvme::unregister_namespace(owner, handle).map_err(map_registry_error)
}

pub(crate) fn register_netdev_port_for_current_subject(
    registration: &AbiNetPortRegistrationV3,
) -> Result<u64, KapiError> {
    let owner = current_driver_domain()?;
    crate::resource_registry::net::register_port(owner, registration).map_err(map_registry_error)
}

pub(crate) fn unregister_netdev_port_for_current_subject(handle: u64) -> Result<(), KapiError> {
    let owner = current_driver_domain()?;
    crate::resource_registry::net::unregister_port(owner, handle).map_err(map_registry_error)
}
