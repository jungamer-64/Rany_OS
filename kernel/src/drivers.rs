//! Kernel/driver boundary namespace.
//!
//! New kernel code should access device-facing functionality through
//! `crate::drivers::*` or generic service registries.
//!
//! `crate::io::*` remains the home of kernel-owned I/O infrastructure:
//! DMA/IOMMU services, interrupt routing, logging, and HAL convenience
//! re-exports. Device-facing access for kernel code lives here.
//!
//! Ownership split:
//! - `crate::drivers::*`: kernel-owned driver boundary shims and integration
//! - external `*_driver` crates: device-family implementations outside kernel
//! - `crate::io::*`: shared I/O runtime owned by the kernel framework

pub mod ahci {
    pub use crate::io::ahci::*;
}
pub mod apic {
    pub use crate::io::apic::*;
}
pub mod hid {
    pub use crate::io::hid::*;
}
pub mod ide {
    pub use crate::io::ide::*;
}
pub mod nvme {
    pub use crate::io::nvme::*;
}
pub mod pci {
    pub use crate::io::pci::*;
}
pub mod serial {
    pub use crate::io::serial::*;
}
pub mod usb {
    pub use crate::io::usb::*;
}
pub mod time;
