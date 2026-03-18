//! Kernel/driver boundary namespace.
//!
//! New kernel code should access device-facing functionality through
//! `crate::drivers::*`.
//!
//! `crate::io::*` remains the home of kernel-owned I/O infrastructure:
//! DMA/IOMMU services, interrupt routing, logging, and HAL convenience
//! re-exports. Device modules remain available under `crate::io::*` as
//! compatibility shims, but the stable boundary for kernel code is this
//! module.
//!
//! Ownership split:
//! - `crate::drivers::*`: device/bus drivers and their kernel integration
//! - `crate::io::*`: shared I/O runtime owned by the kernel framework

pub use crate::io::acpi;
pub use crate::io::ahci;
pub use crate::io::apic;
pub use crate::io::gpu;
pub use crate::io::hid;
pub use crate::io::ide;
pub use crate::io::nvme;
pub use crate::io::pci;
pub use crate::io::serial;
pub use crate::io::usb;
pub use crate::io::virtio;
pub mod time;
