//! Provider-backed platform boundary.

pub mod apic;
pub mod pci;

pub fn register_builtin_services() {
    pci::register_builtin_service();
    apic::register_builtin_service();
}
