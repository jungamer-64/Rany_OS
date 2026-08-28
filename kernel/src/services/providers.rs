use super::KernelServiceHost;

pub(super) fn install_builtin_providers(host: &'static KernelServiceHost) {
    let registry = crate::provider_registry::provider_registry();
    registry.register_builtin_storage(host);
    registry.register_builtin_netdev(host);
    registry.register_builtin_input(host);
    registry.register_builtin_serial(host);
}

pub(super) fn time_service() -> Option<&'static dyn kernel_api::service::time::TimeService> {
    crate::provider_registry::time_service()
}

pub(super) fn acpi_service() -> Option<&'static dyn kernel_api::service::platform::AcpiServices> {
    crate::provider_registry::acpi_service()
}

pub(super) fn pci_service() -> Option<&'static dyn kernel_api::service::platform::PciServices> {
    crate::provider_registry::pci_service()
}

pub(super) fn apic_service() -> Option<&'static dyn kernel_api::service::platform::ApicServices> {
    crate::provider_registry::apic_service()
}

pub(super) fn storage_service() -> Option<&'static dyn kernel_api::service::storage::StorageServices>
{
    crate::provider_registry::storage_service()
}

pub(super) fn netdev_service() -> Option<&'static dyn kernel_api::service::netdev::NetDeviceServices>
{
    crate::provider_registry::netdev_service()
}

pub(super) fn input_service() -> Option<&'static dyn kernel_api::service::input::InputServices> {
    crate::provider_registry::input_service()
}

pub(super) fn serial_service() -> Option<&'static dyn kernel_api::service::serial::SerialServices> {
    crate::provider_registry::serial_service()
}
