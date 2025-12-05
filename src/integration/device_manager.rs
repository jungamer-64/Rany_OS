//! Device Manager for ExoRust Kernel
//!
//! Manages all discovered hardware devices and their drivers.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::io::pci_compat::PciDevice;

/// Device type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Storage device (NVMe, AHCI, VirtIO-Blk)
    Storage,
    /// Network device (VirtIO-Net, Intel NIC)
    Network,
    /// Display device (GPU, VGA)
    Display,
    /// USB controller
    Usb,
    /// PCIe bridge
    Bridge,
    /// Input device
    Input,
    /// Serial/COM port
    Serial,
    /// Timer device
    Timer,
    /// Unknown device type
    Unknown,
}

/// Device status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Device detected but not initialized
    Detected,
    /// Device is initializing
    Initializing,
    /// Device is ready for use
    Ready,
    /// Device has failed
    Failed,
    /// Device is disabled
    Disabled,
}

/// Device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Unique device ID
    pub id: u64,
    /// Device name
    pub name: String,
    /// Device type
    pub device_type: DeviceType,
    /// Device status
    pub status: DeviceStatus,
    /// PCI bus location (if PCI device)
    pub pci_location: Option<PciLocation>,
    /// MSI capability
    pub msi_capable: bool,
    /// MSI-X capability
    pub msix_capable: bool,
    /// Assigned interrupt vector
    pub interrupt_vector: Option<u8>,
    /// Base addresses
    pub base_addresses: Vec<u64>,
}

/// PCI device location
#[derive(Debug, Clone, Copy)]
pub struct PciLocation {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl DeviceInfo {
    /// Create device info from PCI device
    pub fn from_pci_device(dev: &PciDevice) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);

        let device_type = Self::classify_pci_device(dev);
        let name = Self::generate_device_name(dev, device_type);

        // Collect base addresses
        let mut base_addresses = Vec::new();
        for bar in &dev.bars {
            if let Some(addr) = bar.address() {
                base_addresses.push(addr);
            }
        }

        DeviceInfo {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            name,
            device_type,
            status: DeviceStatus::Detected,
            pci_location: Some(PciLocation {
                bus: dev.bus,
                device: dev.device,
                function: dev.function,
            }),
            msi_capable: dev.msi_capability().is_some(),
            msix_capable: dev.msix_capability().is_some(),
            interrupt_vector: None,
            base_addresses,
        }
    }

    /// Classify PCI device type
    fn classify_pci_device(dev: &PciDevice) -> DeviceType {
        // Check for VirtIO devices first
        if dev.vendor_id == 0x1AF4 {
            return match dev.device_id {
                0x1000 | 0x1041 => DeviceType::Network, // VirtIO Network
                0x1001 | 0x1042 => DeviceType::Storage, // VirtIO Block
                0x1050 => DeviceType::Display,          // VirtIO GPU
                0x1052 => DeviceType::Input,            // VirtIO Input
                _ => DeviceType::Unknown,
            };
        }

        // Classify by PCI class code
        match dev.class {
            0x01 => DeviceType::Storage, // Mass Storage
            0x02 => DeviceType::Network, // Network
            0x03 => DeviceType::Display, // Display
            0x06 => DeviceType::Bridge,  // Bridge
            0x0C => {
                // Serial Bus
                match dev.subclass {
                    0x03 => DeviceType::Usb, // USB
                    _ => DeviceType::Unknown,
                }
            }
            _ => DeviceType::Unknown,
        }
    }

    /// Generate device name
    fn generate_device_name(dev: &PciDevice, device_type: DeviceType) -> String {
        let type_str = match device_type {
            DeviceType::Storage => "storage",
            DeviceType::Network => "net",
            DeviceType::Display => "gpu",
            DeviceType::Usb => "usb",
            DeviceType::Bridge => "bridge",
            DeviceType::Input => "input",
            DeviceType::Serial => "serial",
            DeviceType::Timer => "timer",
            DeviceType::Unknown => "dev",
        };

        alloc::format!(
            "{}{:02x}{:02x}{}",
            type_str,
            dev.bus,
            dev.device,
            dev.function
        )
    }
}

/// Device manager
pub struct DeviceManager {
    /// All registered devices
    devices: Vec<DeviceInfo>,
}

impl DeviceManager {
    /// Create a new device manager
    pub fn new() -> Self {
        DeviceManager {
            devices: Vec::new(),
        }
    }

    /// Register a new device
    pub fn register(&mut self, device: DeviceInfo) {
        self.devices.push(device);
    }

    /// Get device by ID
    pub fn get(&self, id: u64) -> Option<&DeviceInfo> {
        self.devices.iter().find(|d| d.id == id)
    }

    /// Get mutable device by ID
    pub fn get_mut(&mut self, id: u64) -> Option<&mut DeviceInfo> {
        self.devices.iter_mut().find(|d| d.id == id)
    }

    /// Get all devices
    pub fn all(&self) -> &[DeviceInfo] {
        &self.devices
    }

    /// Get devices by type
    pub fn by_type(&self, device_type: DeviceType) -> Vec<&DeviceInfo> {
        self.devices
            .iter()
            .filter(|d| d.device_type == device_type)
            .collect()
    }

    /// Get MSI-capable devices
    pub fn get_msi_capable(&self) -> Vec<&DeviceInfo> {
        self.devices
            .iter()
            .filter(|d| d.msi_capable || d.msix_capable)
            .collect()
    }

    /// Get device count
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Update device status
    pub fn update_status(&mut self, id: u64, status: DeviceStatus) {
        if let Some(dev) = self.get_mut(id) {
            dev.status = status;
        }
    }

    /// Assign interrupt vector
    pub fn assign_interrupt(&mut self, id: u64, vector: u8) {
        if let Some(dev) = self.get_mut(id) {
            dev.interrupt_vector = Some(vector);
        }
    }

    /// Get storage devices
    pub fn storage_devices(&self) -> Vec<&DeviceInfo> {
        self.by_type(DeviceType::Storage)
    }

    /// Get network devices
    pub fn network_devices(&self) -> Vec<&DeviceInfo> {
        self.by_type(DeviceType::Network)
    }
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}
