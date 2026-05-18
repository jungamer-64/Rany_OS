//! System Integration Module for ExoRust Kernel
//!
//! This module integrates all kernel subsystems during boot:
//! - ACPI-based hardware discovery
//! - PCI/PCIe device initialization
//! - APIC/IOAPIC interrupt routing setup
//! - Generic PCI driver-domain binding
//! - Security context binding to domains
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use kernel_api::service::platform::PciDeviceInfo;

pub mod device_manager;
pub mod interrupt_routing;
pub mod security_integration;
// Re-exports
mod system_impl;
pub use device_manager::{DeviceInfo, DeviceManager};
pub use interrupt_routing::InterruptRouter;
pub use security_integration::SecurityIntegration;
pub use system_impl::*;

fn register_pci_dma_width(dev: &PciDeviceInfo, bits: u8) {
    let device = crate::io::iommu::types::DeviceId::new(
        dev.segment,
        dev.bdf.bus(),
        dev.bdf.device(),
        dev.bdf.function(),
    );
    if let Err(err) = crate::io::iommu::api::register_device_dma_width(device, bits) {
        log::warn!(
            "[INTEGRATION] Failed to register DMA width for {}: {:?}",
            dev.bdf,
            err
        );
    }
}

/// Integration status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationStatus {
    /// Not initialized
    Uninitialized,
    /// ACPI tables parsed
    AcpiParsed,
    /// PCI bus scanned
    PciScanned,
    /// Interrupts configured
    InterruptsConfigured,
    /// Devices initialized
    DevicesInitialized,
    /// Security bound
    SecurityBound,
    /// Fully integrated
    Complete,
    /// Failed
    Failed,
}

/// Integration error
#[derive(Debug, Clone)]
pub enum IntegrationError {
    /// ACPI initialization failed
    AcpiError(String),
    /// PCI initialization failed
    PciError(String),
    /// Interrupt configuration failed
    InterruptError(String),
    /// Device initialization failed
    DeviceError(String),
    /// Security binding failed
    SecurityError(String),
}

/// System integration controller
pub struct SystemIntegration {
    /// Current status
    status: IntegrationStatus,
    /// Device manager
    device_manager: DeviceManager,
    /// Interrupt router
    interrupt_router: InterruptRouter,
    /// Security integration
    security: SecurityIntegration,
    /// Boot log
    boot_log: Vec<String>,
}
