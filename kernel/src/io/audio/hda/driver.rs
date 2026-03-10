// ============================================================================
// src/io/audio/hda/driver.rs - HDA Driver Wrapper
// ============================================================================
//!
//! Driver trait implementation for Intel HD Audio.

use core::sync::atomic::Ordering;

use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use crate::io::audio::hda::{HdaController, global};

/// Intel HD Audio Driver
pub struct HdaDriver {
    irq: u8,
    mmio_base: u64,
    pci_locator: PackedPciLocation,
    initialized: bool,
}

impl HdaDriver {
    /// Create a new HDA Driver instance
    pub fn new(mmio_base: u64, irq: u8, pci_locator: PackedPciLocation) -> Self {
        Self {
            irq,
            mmio_base,
            pci_locator,
            initialized: false,
        }
    }
}

impl Driver for HdaDriver {
    fn name(&self) -> &str {
        "intel-hda"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Other // Or create Audio type if available, using Other for now
    }

    fn probe(&mut self) -> KapiResult<()> {
        log::info!(target: "hda", "Probing Intel HD Audio...");

        // Create and initialize controller
        let mut controller = HdaController::new(self.mmio_base, self.pci_locator);
        match controller.init() {
            Ok(_) => {
                // Register global instance
                *global::HDA_DRIVER.lock().unwrap_or_else(|e| e.into_inner()) = Some(controller);

                // Store IRQ
                if self.irq > 0 && self.irq < 16 {
                    global::HDA_IRQ.store(self.irq, Ordering::SeqCst);
                }

                self.initialized = true;
                log::info!(target: "hda", "Driver initialized successfully");
                Ok(())
            }
            Err(e) => {
                log::error!(target: "hda", "Initialization failed: {:?}", e);
                Err(KapiError::IoError)
            }
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
        }

        // Ensure interrupts are enabled if needed, usually done in init
        global::enable_irq();

        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        global::disable_irq();
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        // HDA generic class match is usually preferred, but we can list specific IDs if known.
        // Since integration module finds by class, this list is informational or for precise matching.
        static DEVICES: [DeviceId; 1] = [DeviceId {
            vendor: 0x8086, // Intel
            device: 0x2668, // ICH6 (example)
            subsystem_vendor: None,
            subsystem_device: None,
        }];
        &DEVICES
    }
}
