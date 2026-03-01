// ============================================================================
// kernel/src/net/driver.rs - VirtIO-Net Driver Wrapper
// ============================================================================
//!
//! VirtIO-Net driver implementing the Driver trait for DriverRegistry integration.
//!
//! This wraps the existing driver_bridge functionality to work with the
//! unified DriverRegistry system.

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::init_virtio_net_for_device;

/// VirtIO-Net driver wrapper for DriverRegistry
pub struct VirtioNetDriver {
    initialized: bool,
    mmio_base: Option<u64>,
    iommu_id: Option<IommuDeviceId>,
}

impl VirtioNetDriver {
    /// Create a new VirtIO-Net driver (legacy default)
    pub fn new() -> Self {
        Self { 
            initialized: false,
            mmio_base: None,
            iommu_id: None,
        }
    }

    /// Create a new VirtIO-Net driver with specific device configuration
    pub fn new_with_device(mmio_base: u64, iommu_id: IommuDeviceId) -> Self {
        Self {
            initialized: false,
            mmio_base: Some(mmio_base),
            iommu_id: Some(iommu_id),
        }
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
        // debug: show current config (early_print to avoid loss on hang)
        crate::io::log::early_print(&alloc::format!("[DEBUG] VirtioNetDriver::probe mmio_base={:?} iommu_id={:?}\n", self.mmio_base, self.iommu_id));

        // If specific device info is provided, initialize the device first
        if let (Some(base), Some(id)) = (self.mmio_base, self.iommu_id) {
            log::info!(target: "net", "Probing VirtIO-Net at {:#x}", base);
            match init_virtio_net_for_device(base as usize, id) {
                Ok(_) => {
                    log::info!(target: "net", "VirtIO-Net device initialized");
                }
                Err(e) => {
                    log::error!(target: "net", "Failed to initialize VirtIO-Net device: {:?}", e);
                    return Err(KapiError::IoError);
                }
            }
        }

        // Check if VirtIO-Net device is available (global instance)
        if crate::net::runtime::bridge::is_initialized() {
            self.initialized = true;
            // quick ping test to verify network connectivity; this runs in
            // driver probe context so it can exercise the transmit path.
            // We log at INFO so it appears even in noisy boots.
            match crate::net::runtime::bridge::send_real_icmp_echo([10, 0, 2, 2], 1) {
                Ok(rtt) => {
                    log::info!(target: "net", "Probe ping success rtt={}", rtt);
                }
                Err(e) => {
                    log::warn!(target: "net", "Probe ping failed: {:?}", e);
                }
            }
            return Ok(());
        }

        // Initialize the bridge (connects global device to stack)
        match crate::net::runtime::bridge::init_bridge() {
            Ok(()) => {
                self.initialized = true;
                Ok(())
            }
            Err(_) => Err(KapiError::NotFound),
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
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
        static DEVICES: [DeviceId; 1] = [DeviceId {
            vendor: 0x1AF4,
            device: 0x1000, // VirtIO-Net (legacy)
            subsystem_vendor: None,
            subsystem_device: None,
        }];
        &DEVICES
    }
}

impl Default for VirtioNetDriver {
    fn default() -> Self {
        Self::new()
    }
}
