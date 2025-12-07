//! System Integration Module for ExoRust Kernel
//!
//! This module integrates all kernel subsystems during boot:
//! - ACPI-based hardware discovery
//! - PCI/PCIe device initialization
//! - APIC/IOAPIC interrupt routing setup
//! - VirtIO device detection and MSI/MSI-X configuration
//! - Security context binding to domains

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub mod device_manager;
pub mod interrupt_routing;
pub mod security_integration;

// Re-exports
pub use device_manager::{DeviceInfo, DeviceManager};
pub use interrupt_routing::InterruptRouter;
pub use security_integration::SecurityIntegration;

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

impl SystemIntegration {
    /// Create a new system integration controller
    pub fn new() -> Self {
        SystemIntegration {
            status: IntegrationStatus::Uninitialized,
            device_manager: DeviceManager::new(),
            interrupt_router: InterruptRouter::new(),
            security: SecurityIntegration::new(),
            boot_log: Vec::new(),
        }
    }

    /// Run full system integration
    pub fn integrate(&mut self) -> Result<(), IntegrationError> {
        self.log("Starting system integration...");

        // Phase 1: Parse ACPI tables
        self.integrate_acpi()?;

        // Phase 2: Scan PCI bus and configure devices
        self.integrate_pci()?;

        // Phase 3: Configure interrupt routing
        self.integrate_interrupts()?;

        // Phase 4: Initialize detected devices
        self.integrate_devices()?;

        // Phase 5: Bind security contexts
        self.integrate_security()?;

        self.status = IntegrationStatus::Complete;
        self.log("System integration complete!");

        Ok(())
    }

    /// Phase 1: ACPI integration
    fn integrate_acpi(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 1: ACPI integration");

        // Get ACPI information
        let local_apics = crate::io::acpi::local_apics();
        let io_apics = crate::io::acpi::io_apics();
        let pcie_ecam = crate::io::acpi::pcie_ecam_regions();

        self.log(&alloc::format!(
            "  Found {} processor(s)",
            local_apics.len()
        ));
        self.log(&alloc::format!("  Found {} I/O APIC(s)", io_apics.len()));
        self.log(&alloc::format!(
            "  Found {} PCIe ECAM region(s)",
            pcie_ecam.len()
        ));

        // Store APIC information for interrupt routing
        for apic in &io_apics {
            self.interrupt_router
                .add_io_apic(apic.id, apic.address, apic.gsi_base);
        }

        // Store interrupt overrides
        let overrides = crate::io::acpi::interrupt_overrides();
        for ovr in &overrides {
            self.interrupt_router
                .add_override(ovr.source, ovr.gsi, ovr.polarity, ovr.trigger_mode);
        }

        self.status = IntegrationStatus::AcpiParsed;
        Ok(())
    }

    /// Phase 2: PCI integration
    fn integrate_pci(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 2: PCI bus integration");

        // Initialize PCI bus
        crate::io::pci_init();

        // Get all PCI devices
        let devices = crate::io::pci_devices();
        self.log(&alloc::format!("  Found {} PCI device(s)", devices.len()));

        // Categorize devices
        let mut storage_count = 0;
        let mut network_count = 0;
        let mut virtio_count = 0;

        for dev in &devices {
            // Register device
            let device_info = DeviceInfo::from_pci_device(dev);
            self.device_manager.register(device_info);

            // Count by type
            match dev.class_code.class {
                0x01 => storage_count += 1, // Mass Storage
                0x02 => network_count += 1, // Network
                _ => {}
            }

            if dev.is_virtio() {
                virtio_count += 1;
            }
        }

        self.log(&alloc::format!("  Storage controllers: {}", storage_count));
        self.log(&alloc::format!("  Network controllers: {}", network_count));
        self.log(&alloc::format!("  VirtIO devices: {}", virtio_count));

        self.status = IntegrationStatus::PciScanned;
        Ok(())
    }

    /// Phase 3: Interrupt integration
    fn integrate_interrupts(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 3: Interrupt routing configuration");

        // Configure IOAPIC redirection entries
        let routes = self.interrupt_router.configure_routing();
        self.log(&alloc::format!(
            "  Configured {} interrupt route(s)",
            routes
        ));

        // Allocate MSI vectors for capable devices
        let msi_devices: Vec<_> = self
            .device_manager
            .get_msi_capable()
            .into_iter()
            .map(|d| (d.id, d.name.clone(), d.pci_location))
            .collect();
        self.log(&alloc::format!(
            "  {} device(s) support MSI/MSI-X",
            msi_devices.len()
        ));

        // Get PCI devices with MSI capability and allocate vectors
        let pci_devices = crate::io::pci_devices();
        for pci_dev in &pci_devices {
            for (dev_id, dev_name, pci_loc) in &msi_devices {
                if pci_loc
                    .map(|l| {
                        l.bus == pci_dev.bdf.bus()
                            && l.device == pci_dev.bdf.device()
                            && l.function == pci_dev.bdf.function()
                    })
                    .unwrap_or(false)
                {
                    if let Some(vector) = crate::io::allocate_vector(pci_dev.bdf) {
                        self.interrupt_router.add_msi_route(*dev_id, vector);
                        self.log(&alloc::format!(
                            "    Device {} -> vector {}",
                            dev_name,
                            vector
                        ));
                    }
                    break;
                }
            }
        }

        self.status = IntegrationStatus::InterruptsConfigured;
        Ok(())
    }

    /// Phase 4: Device initialization
    fn integrate_devices(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 4: Device initialization");

        // Initialize VirtIO devices
        let virtio_devices = crate::io::pci_find_virtio_devices();
        for dev in virtio_devices {
            match dev.device_id.0 {
                0x1001 | 0x1042 => {
                    // VirtIO Block Device
                    self.log(&alloc::format!(
                        "  Initializing VirtIO-Blk at {:02x}:{:02x}.{}",
                        dev.bdf.bus(),
                        dev.bdf.device(),
                        dev.bdf.function()
                    ));
                    dev.enable_bus_master();
                    dev.enable_memory_space();
                }
                0x1000 | 0x1041 => {
                    // VirtIO Network Device
                    self.log(&alloc::format!(
                        "  Initializing VirtIO-Net at {:02x}:{:02x}.{}",
                        dev.bdf.bus(),
                        dev.bdf.device(),
                        dev.bdf.function()
                    ));
                    dev.enable_bus_master();
                    dev.enable_memory_space();
                }
                _ => {}
            }
        }

        // Initialize NVMe controllers
        let nvme_devices = crate::io::pci_find_by_class(0x01, 0x08);
        for dev in nvme_devices {
            self.log(&alloc::format!(
                "  Initializing NVMe controller at {:02x}:{:02x}.{}",
                dev.bdf.bus(),
                dev.bdf.device(),
                dev.bdf.function()
            ));
            dev.enable_bus_master();
            dev.enable_memory_space();
        }

        self.status = IntegrationStatus::DevicesInitialized;
        Ok(())
    }

    /// Phase 5: Security integration
    fn integrate_security(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 5: Security context binding");

        // Bind devices to security contexts
        self.security.bind_all_devices(&self.device_manager);

        // Create device-specific capability sets
        let device_count = self.device_manager.device_count();
        self.log(&alloc::format!(
            "  Bound {} device(s) to security contexts",
            device_count
        ));

        self.status = IntegrationStatus::SecurityBound;
        Ok(())
    }

    /// Get integration status
    pub fn status(&self) -> IntegrationStatus {
        self.status
    }

    /// Get boot log
    pub fn boot_log(&self) -> &[String] {
        &self.boot_log
    }

    /// Get device manager
    pub fn device_manager(&self) -> &DeviceManager {
        &self.device_manager
    }

    /// Get interrupt router
    pub fn interrupt_router(&self) -> &InterruptRouter {
        &self.interrupt_router
    }

    /// Add log entry
    fn log(&mut self, msg: &str) {
        crate::log!("[INTEGRATION] {}\n", msg);
        self.boot_log.push(String::from(msg));
    }
}

impl Default for SystemIntegration {
    fn default() -> Self {
        Self::new()
    }
}

// Global integration instance
static SYSTEM_INTEGRATION: Mutex<Option<SystemIntegration>> = Mutex::new(None);

/// Initialize system integration
pub fn init() -> Result<(), IntegrationError> {
    let mut integration = SystemIntegration::new();
    let result = integration.integrate();

    *SYSTEM_INTEGRATION.lock() = Some(integration);

    result
}

/// Get integration status
pub fn status() -> IntegrationStatus {
    SYSTEM_INTEGRATION
        .lock()
        .as_ref()
        .map(|i| i.status())
        .unwrap_or(IntegrationStatus::Uninitialized)
}

/// Get boot log
pub fn boot_log() -> Vec<String> {
    SYSTEM_INTEGRATION
        .lock()
        .as_ref()
        .map(|i| i.boot_log().to_vec())
        .unwrap_or_default()
}
