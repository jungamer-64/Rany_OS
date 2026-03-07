//! Provider-backed platform boundary.

pub mod acpi;
pub mod apic;
pub mod pci;

pub fn register_builtin_services() {
    acpi::register_builtin_service();
    pci::register_builtin_service();
    apic::register_builtin_service();
}
