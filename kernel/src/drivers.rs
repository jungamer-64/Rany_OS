//! Kernel/driver boundary namespace.
//!
//! New kernel code should access device-facing functionality through
//! `crate::drivers::*`.
//!
//! `crate::io::*` remains the home of kernel-owned I/O infrastructure:
//! DMA/IOMMU services, interrupt routing, logging, and HAL convenience
//! re-exports. Device-facing access for kernel code lives here.
//!
//! Ownership split:
//! - `crate::drivers::*`: device/bus drivers and their kernel integration
//! - `crate::io::*`: shared I/O runtime owned by the kernel framework

pub mod acpi {
    pub use crate::io::acpi::*;
}
pub mod ahci {
    pub use crate::io::ahci::*;
}
pub mod apic {
    pub use crate::io::apic::*;
}
pub mod gpu {
    pub use crate::io::gpu::*;
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
pub mod virtio {
    pub use crate::io::virtio::*;
}
pub mod time;
