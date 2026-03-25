use super::ExoKernel;

pub(crate) fn register_builtin_service_providers(exokernel: &'static ExoKernel) {
    let registry = crate::provider_registry::provider_registry();
    registry.register_builtin_storage(exokernel);
    registry.register_builtin_netdev(exokernel);
    registry.register_builtin_input(exokernel);
    registry.register_builtin_serial(exokernel);
}

pub(crate) fn time_service() -> Option<&'static dyn kernel_api::service::time::TimeService> {
    crate::provider_registry::time_service()
}

pub(crate) fn acpi_service() -> Option<&'static dyn kernel_api::service::platform::AcpiServices> {
    crate::provider_registry::acpi_service()
}

pub(crate) fn pci_service() -> Option<&'static dyn kernel_api::service::platform::PciServices> {
    crate::provider_registry::pci_service()
}

pub(crate) fn apic_service() -> Option<&'static dyn kernel_api::service::platform::ApicServices> {
    crate::provider_registry::apic_service()
}

pub(crate) fn storage_service() -> Option<&'static dyn kernel_api::service::storage::StorageServices>
{
    crate::provider_registry::storage_service()
}

pub(crate) fn netdev_service() -> Option<&'static dyn kernel_api::service::netdev::NetDeviceServices>
{
    crate::provider_registry::netdev_service()
}

pub(crate) fn input_service() -> Option<&'static dyn kernel_api::service::input::InputServices> {
    crate::provider_registry::input_service()
}

pub(crate) fn serial_service() -> Option<&'static dyn kernel_api::service::serial::SerialServices> {
    crate::provider_registry::serial_service()
}
