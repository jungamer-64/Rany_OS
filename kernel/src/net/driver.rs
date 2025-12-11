// ============================================================================
// kernel/src/net/driver.rs - VirtIO-Net Driver Wrapper
// ============================================================================
//!
//! VirtIO-Net driver implementing the Driver trait for DriverRegistry integration.
//!
//! This wraps the existing driver_bridge functionality to work with the
//! unified DriverRegistry system.

use kernel_api::driver::{Driver, DriverType, DriverVersion, DeviceId};
use kernel_api::error::{KapiError, KapiResult};
use alloc::vec::Vec;

/// VirtIO-Net driver wrapper for DriverRegistry
pub struct VirtioNetDriver {
    initialized: bool,
}

impl VirtioNetDriver {
    /// Create a new VirtIO-Net driver
    pub fn new() -> Self {
        Self { initialized: false }
    }
}

impl Driver for VirtioNetDriver {
    fn name(&self) -> &str {
        "virtio-net"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Network
    }

    fn probe(&mut self) -> KapiResult<()> {
        // Check if VirtIO-Net device is available
        if super::driver_bridge::is_initialized() {
            self.initialized = true;
            return Ok(());
        }
        
        // Try to initialize the bridge
        match super::driver_bridge::init_bridge() {
            Ok(()) => {
                self.initialized = true;
                Ok(())
            }
            Err(_) => Err(KapiError::NotFound),
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::NotSupported);
        }
        
        // Bridge is already started during probe
        log::info!(target: "net", "VirtIO-Net driver started");
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        log::info!(target: "net", "VirtIO-Net driver stopped");
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        // VirtIO-Net PCI device ID
        static DEVICES: [DeviceId; 1] = [
            DeviceId {
                vendor: 0x1AF4,
                device: 0x1000, // VirtIO-Net (legacy)
                subsystem_vendor: None,
                subsystem_device: None,
            },
        ];
        &DEVICES
    }
}

impl Default for VirtioNetDriver {
    fn default() -> Self {
        Self::new()
    }
}
