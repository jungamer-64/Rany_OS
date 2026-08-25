//! Provider-backed platform boundary.

pub mod acpi_hotplug;
pub mod apic;
pub mod firmware;
pub mod pci;

pub fn register_builtin_services() {
    pci::register_builtin_service();
    apic::register_builtin_service();
}
