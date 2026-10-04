//! Configuration observations are authorized separately from register grants.

use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::pci_config::{PciConfigReadError, PciConfigSnapshot};

pub(super) fn read_config(
    device: PackedPciLocation,
) -> Result<PciConfigSnapshot, PciConfigReadError> {
    if device.is_null() || !device.is_canonical() {
        return Err(PciConfigReadError::InvalidDevice);
    }
    super::device_registration::authorize_pci_device_for_current_subject(device)
        .map_err(|_| PciConfigReadError::PermissionDenied)?;
    if device.segment() != 0 {
        return Err(PciConfigReadError::Unavailable);
    }
    let bdf =
        crate::drivers::pci::BdfAddress::new(device.bus(), device.device(), device.function());
    let pin = crate::drivers::pci::resource::retain(bdf).map_err(|cause| match cause {
        crate::drivers::pci::resource::FunctionResourceError::Absent => {
            PciConfigReadError::DeviceAbsent
        }
        crate::drivers::pci::resource::FunctionResourceError::Busy => {
            PciConfigReadError::ResourceBusy
        }
        crate::drivers::pci::resource::FunctionResourceError::Exhausted => {
            PciConfigReadError::ResourceExhausted
        }
    })?;
    PciConfigSnapshot::from_bytes(device, pin.conventional_configuration())
}
