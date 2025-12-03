//! PCI Bus Support for ExoRust
//!
//! This module implements PCI configuration space access and device enumeration
//! for device driver initialization.

use alloc::vec::Vec;
use core::fmt;
use spin::Mutex;
use x86_64::instructions::port::Port;

extern crate alloc;

/// PCI configuration address port
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
/// PCI configuration data port
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// PCI configuration space access
static PCI_CONFIG: Mutex<PciConfig> = Mutex::new(PciConfig::new());

/// PCI configuration space accessor
struct PciConfig {
    address_port: Port<u32>,
    data_port: Port<u32>,
}

impl PciConfig {
    const fn new() -> Self {
        PciConfig {
            address_port: Port::new(PCI_CONFIG_ADDRESS),
            data_port: Port::new(PCI_CONFIG_DATA),
        }
    }

    /// Read a 32-bit value from PCI configuration space
    fn read(&mut self, bus: u8, device: u8, function: u8, offset: u8) -> u32 {
        let address = Self::make_address(bus, device, function, offset);
        unsafe {
            self.address_port.write(address);
            self.data_port.read()
        }
    }

    /// Write a 32-bit value to PCI configuration space
    fn write(&mut self, bus: u8, device: u8, function: u8, offset: u8, value: u32) {
        let address = Self::make_address(bus, device, function, offset);
        unsafe {
            self.address_port.write(address);
            self.data_port.write(value);
        }
    }

    /// Create a PCI configuration address
    fn make_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
        ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((function as u32) << 8)
            | ((offset as u32) & 0xFC)
            | 0x80000000 // Enable bit
    }
}

/// Read from PCI configuration space
pub fn pci_read(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    PCI_CONFIG.lock().read(bus, device, function, offset)
}

/// Write to PCI configuration space
pub fn pci_write(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    PCI_CONFIG
        .lock()
        .write(bus, device, function, offset, value);
}

/// Read a 16-bit value from PCI configuration space
pub fn pci_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let dword = pci_read(bus, device, function, offset & 0xFC);
    let shift = (offset & 2) * 8;
    (dword >> shift) as u16
}

/// Read an 8-bit value from PCI configuration space
pub fn pci_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let dword = pci_read(bus, device, function, offset & 0xFC);
    let shift = (offset & 3) * 8;
    (dword >> shift) as u8
}

/// PCI device class codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciClass {
    /// Unclassified device
    Unclassified,
    /// Mass storage controller
    MassStorage,
    /// Network controller
    Network,
    /// Display controller
    Display,
    /// Multimedia controller
    Multimedia,
    /// Memory controller
    Memory,
    /// Bridge device
    Bridge,
    /// Simple communication controller
    SimpleCommunication,
    /// Base system peripheral
    BaseSystemPeripheral,
    /// Input device controller
    InputDevice,
    /// Docking station
    DockingStation,
    /// Processor
    Processor,
    /// Serial bus controller
    SerialBus,
    /// Wireless controller
    Wireless,
    /// Intelligent controller
    Intelligent,
    /// Satellite communication controller
    SatelliteCommunication,
    /// Encryption controller
    Encryption,
    /// Signal processing controller
    SignalProcessing,
    /// Processing accelerator
    ProcessingAccelerator,
    /// Non-essential instrumentation
    NonEssentialInstrumentation,
    /// Unknown
    Unknown(u8),
}

impl From<u8> for PciClass {
    fn from(value: u8) -> Self {
        match value {
            0x00 => PciClass::Unclassified,
            0x01 => PciClass::MassStorage,
            0x02 => PciClass::Network,
            0x03 => PciClass::Display,
            0x04 => PciClass::Multimedia,
            0x05 => PciClass::Memory,
            0x06 => PciClass::Bridge,
            0x07 => PciClass::SimpleCommunication,
            0x08 => PciClass::BaseSystemPeripheral,
            0x09 => PciClass::InputDevice,
            0x0A => PciClass::DockingStation,
            0x0B => PciClass::Processor,
            0x0C => PciClass::SerialBus,
            0x0D => PciClass::Wireless,
            0x0E => PciClass::Intelligent,
            0x0F => PciClass::SatelliteCommunication,
            0x10 => PciClass::Encryption,
            0x11 => PciClass::SignalProcessing,
            0x12 => PciClass::ProcessingAccelerator,
            0x13 => PciClass::NonEssentialInstrumentation,
            _ => PciClass::Unknown(value),
        }
    }
}

/// PCI Base Address Register (BAR)
#[derive(Debug, Clone, Copy)]
pub enum PciBar {
    /// Memory-mapped I/O
    Memory {
        /// Base address
        address: u64,
        /// Size in bytes
        size: u64,
        /// Is prefetchable
        prefetchable: bool,
        /// Is 64-bit
        is_64bit: bool,
    },
    /// Port I/O
    Io {
        /// Port base address
        port: u32,
        /// Size in bytes
        size: u32,
    },
    /// Not present
    None,
}

impl PciBar {
    /// Get the base address
    pub fn address(&self) -> Option<u64> {
        match self {
            PciBar::Memory { address, .. } => Some(*address),
            PciBar::Io { port, .. } => Some(*port as u64),
            PciBar::None => None,
        }
    }

    /// Get the size
    pub fn size(&self) -> Option<u64> {
        match self {
            PciBar::Memory { size, .. } => Some(*size),
            PciBar::Io { size, .. } => Some(*size as u64),
            PciBar::None => None,
        }
    }
}

/// PCI device information
#[derive(Clone)]
pub struct PciDevice {
    /// Bus number
    pub bus: u8,
    /// Device number
    pub device: u8,
    /// Function number
    pub function: u8,
    /// Vendor ID
    pub vendor_id: u16,
    /// Device ID
    pub device_id: u16,
    /// Class code
    pub class: u8,
    /// Subclass code
    pub subclass: u8,
    /// Programming interface
    pub prog_if: u8,
    /// Revision ID
    pub revision: u8,
    /// Header type
    pub header_type: u8,
    /// Interrupt line
    pub interrupt_line: u8,
    /// Interrupt pin
    pub interrupt_pin: u8,
    /// Base Address Registers
    pub bars: [PciBar; 6],
}

impl PciDevice {
    /// Read device information from configuration space
    pub fn read(bus: u8, device: u8, function: u8) -> Option<Self> {
        let vendor_device = pci_read(bus, device, function, 0x00);
        let vendor_id = vendor_device as u16;

        // Check if device exists
        if vendor_id == 0xFFFF {
            return None;
        }

        let device_id = (vendor_device >> 16) as u16;

        let class_revision = pci_read(bus, device, function, 0x08);
        let revision = class_revision as u8;
        let prog_if = (class_revision >> 8) as u8;
        let subclass = (class_revision >> 16) as u8;
        let class = (class_revision >> 24) as u8;

        let header_bist = pci_read(bus, device, function, 0x0C);
        let header_type = ((header_bist >> 16) as u8) & 0x7F;

        let interrupt = pci_read(bus, device, function, 0x3C);
        let interrupt_line = interrupt as u8;
        let interrupt_pin = (interrupt >> 8) as u8;

        // Read BARs
        let mut bars = [PciBar::None; 6];
        let max_bars = if header_type == 0 { 6 } else { 2 };

        let mut i = 0;
        while i < max_bars {
            let bar_offset = (0x10 + i * 4) as u8;
            let bar_value = pci_read(bus, device, function, bar_offset);

            if bar_value == 0 {
                i += 1;
                continue;
            }

            if (bar_value & 1) == 0 {
                // Memory BAR
                let is_64bit = ((bar_value >> 1) & 3) == 2;
                let prefetchable = ((bar_value >> 3) & 1) != 0;

                // Get size by writing all 1s and reading back
                pci_write(bus, device, function, bar_offset, 0xFFFFFFFF);
                let size_mask = pci_read(bus, device, function, bar_offset);
                pci_write(bus, device, function, bar_offset, bar_value);

                let mut address = (bar_value & 0xFFFFFFF0) as u64;
                let mut size = (!((size_mask & 0xFFFFFFF0) as u64)).wrapping_add(1);

                if is_64bit && i + 1 < max_bars {
                    // 64-bit BAR spans two registers
                    let bar_high = pci_read(bus, device, function, bar_offset + 4);
                    address |= (bar_high as u64) << 32;

                    pci_write(bus, device, function, bar_offset + 4, 0xFFFFFFFF);
                    let size_high = pci_read(bus, device, function, bar_offset + 4);
                    pci_write(bus, device, function, bar_offset + 4, bar_high);

                    if size_high != 0 {
                        let full_mask =
                            ((size_high as u64) << 32) | (size_mask as u64 & 0xFFFFFFF0);
                        size = (!full_mask).wrapping_add(1);
                    }

                    bars[i] = PciBar::Memory {
                        address,
                        size,
                        prefetchable,
                        is_64bit: true,
                    };
                    i += 2;
                    continue;
                }

                bars[i] = PciBar::Memory {
                    address,
                    size: size & 0xFFFFFFFF,
                    prefetchable,
                    is_64bit: false,
                };
            } else {
                // I/O BAR
                let port = bar_value & 0xFFFFFFFC;

                pci_write(bus, device, function, bar_offset, 0xFFFFFFFF);
                let size_mask = pci_read(bus, device, function, bar_offset);
                pci_write(bus, device, function, bar_offset, bar_value);

                let size = (!((size_mask & 0xFFFFFFFC) as u32)).wrapping_add(1) & 0xFFFF;

                bars[i] = PciBar::Io { port, size };
            }

            i += 1;
        }

        Some(PciDevice {
            bus,
            device,
            function,
            vendor_id,
            device_id,
            class,
            subclass,
            prog_if,
            revision,
            header_type,
            interrupt_line,
            interrupt_pin,
            bars,
        })
    }

    /// Get PCI class
    pub fn pci_class(&self) -> PciClass {
        PciClass::from(self.class)
    }

    /// Enable bus mastering
    pub fn enable_bus_master(&self) {
        let command = pci_read16(self.bus, self.device, self.function, 0x04);
        let new_command = command | 0x04; // Bus Master Enable
        let dword = pci_read(self.bus, self.device, self.function, 0x04);
        pci_write(
            self.bus,
            self.device,
            self.function,
            0x04,
            (dword & 0xFFFF0000) | (new_command as u32),
        );
    }

    /// Enable memory space access
    pub fn enable_memory_space(&self) {
        let command = pci_read16(self.bus, self.device, self.function, 0x04);
        let new_command = command | 0x02; // Memory Space Enable
        let dword = pci_read(self.bus, self.device, self.function, 0x04);
        pci_write(
            self.bus,
            self.device,
            self.function,
            0x04,
            (dword & 0xFFFF0000) | (new_command as u32),
        );
    }

    /// Enable I/O space access
    pub fn enable_io_space(&self) {
        let command = pci_read16(self.bus, self.device, self.function, 0x04);
        let new_command = command | 0x01; // I/O Space Enable
        let dword = pci_read(self.bus, self.device, self.function, 0x04);
        pci_write(
            self.bus,
            self.device,
            self.function,
            0x04,
            (dword & 0xFFFF0000) | (new_command as u32),
        );
    }

    /// Disable interrupts
    pub fn disable_interrupts(&self) {
        let command = pci_read16(self.bus, self.device, self.function, 0x04);
        let new_command = command | 0x400; // Interrupt Disable
        let dword = pci_read(self.bus, self.device, self.function, 0x04);
        pci_write(
            self.bus,
            self.device,
            self.function,
            0x04,
            (dword & 0xFFFF0000) | (new_command as u32),
        );
    }

    /// Get MSI capability offset (if present)
    pub fn msi_capability(&self) -> Option<u8> {
        self.find_capability(0x05)
    }

    /// Get MSI-X capability offset (if present)
    pub fn msix_capability(&self) -> Option<u8> {
        self.find_capability(0x11)
    }

    /// Find a capability by ID
    fn find_capability(&self, cap_id: u8) -> Option<u8> {
        let status = pci_read16(self.bus, self.device, self.function, 0x06);

        // Check if capabilities list is present
        if (status & 0x10) == 0 {
            return None;
        }

        let mut cap_ptr = pci_read8(self.bus, self.device, self.function, 0x34);

        while cap_ptr != 0 {
            let cap_header = pci_read(self.bus, self.device, self.function, cap_ptr);
            let id = cap_header as u8;

            if id == cap_id {
                return Some(cap_ptr);
            }

            cap_ptr = (cap_header >> 8) as u8;
        }

        None
    }
}

impl fmt::Debug for PciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PCI {:02x}:{:02x}.{} {:04x}:{:04x} class={:02x}:{:02x}:{:02x}",
            self.bus,
            self.device,
            self.function,
            self.vendor_id,
            self.device_id,
            self.class,
            self.subclass,
            self.prog_if
        )
    }
}

impl fmt::Display for PciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// PCI bus scanner
pub struct PciBus {
    /// Discovered devices
    devices: Vec<PciDevice>,
}

impl PciBus {
    /// Create a new PCI bus scanner
    pub fn new() -> Self {
        PciBus {
            devices: Vec::new(),
        }
    }

    /// Scan all PCI buses
    pub fn scan(&mut self) {
        self.devices.clear();

        // Check if PCI host bridge supports multiple buses
        let header_type = pci_read8(0, 0, 0, 0x0E);

        if (header_type & 0x80) == 0 {
            // Single PCI host controller
            self.scan_bus(0);
        } else {
            // Multiple PCI host controllers
            for function in 0..8 {
                if pci_read16(0, 0, function, 0x00) != 0xFFFF {
                    self.scan_bus(function);
                }
            }
        }
    }

    /// Scan a single PCI bus
    fn scan_bus(&mut self, bus: u8) {
        for device in 0..32 {
            self.scan_device(bus, device);
        }
    }

    /// Scan a single PCI device
    fn scan_device(&mut self, bus: u8, device: u8) {
        if let Some(dev) = PciDevice::read(bus, device, 0) {
            // Check for multi-function device
            let multifunction = (dev.header_type & 0x80) != 0;
            self.devices.push(dev);

            if multifunction {
                for function in 1..8 {
                    if let Some(dev) = PciDevice::read(bus, device, function) {
                        self.devices.push(dev);
                    }
                }
            }
        }
    }

    /// Get all discovered devices
    pub fn devices(&self) -> &[PciDevice] {
        &self.devices
    }

    /// Find devices by class
    pub fn find_by_class(&self, class: u8, subclass: u8) -> Vec<&PciDevice> {
        self.devices
            .iter()
            .filter(|d| d.class == class && d.subclass == subclass)
            .collect()
    }

    /// Find devices by vendor and device ID
    pub fn find_by_id(&self, vendor_id: u16, device_id: u16) -> Vec<&PciDevice> {
        self.devices
            .iter()
            .filter(|d| d.vendor_id == vendor_id && d.device_id == device_id)
            .collect()
    }

    /// Find network controllers
    pub fn find_network_controllers(&self) -> Vec<&PciDevice> {
        self.find_by_class(0x02, 0x00)
    }

    /// Find storage controllers
    pub fn find_storage_controllers(&self) -> Vec<&PciDevice> {
        let mut result = Vec::new();
        // NVMe (class 01, subclass 08)
        result.extend(self.find_by_class(0x01, 0x08));
        // SATA AHCI (class 01, subclass 06)
        result.extend(self.find_by_class(0x01, 0x06));
        // SCSI (class 01, subclass 00)
        result.extend(self.find_by_class(0x01, 0x00));
        result
    }

    /// Find VirtIO devices
    pub fn find_virtio_devices(&self) -> Vec<&PciDevice> {
        self.devices
            .iter()
            .filter(|d| d.vendor_id == 0x1AF4 && (0x1000..=0x107F).contains(&d.device_id))
            .collect()
    }
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Global PCI bus instance
static PCI_BUS: Mutex<Option<PciBus>> = Mutex::new(None);

/// Initialize PCI bus and scan for devices
pub fn init() {
    let mut bus = PciBus::new();
    bus.scan();

    *PCI_BUS.lock() = Some(bus);
}

/// Get all PCI devices
pub fn devices() -> Vec<PciDevice> {
    PCI_BUS
        .lock()
        .as_ref()
        .map(|b| b.devices().to_vec())
        .unwrap_or_default()
}

/// Find devices by class
pub fn find_by_class(class: u8, subclass: u8) -> Vec<PciDevice> {
    PCI_BUS
        .lock()
        .as_ref()
        .map(|b| {
            b.find_by_class(class, subclass)
                .into_iter()
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Find VirtIO devices
pub fn find_virtio_devices() -> Vec<PciDevice> {
    PCI_BUS
        .lock()
        .as_ref()
        .map(|b| b.find_virtio_devices().into_iter().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_class() {
        assert_eq!(PciClass::from(0x01), PciClass::MassStorage);
        assert_eq!(PciClass::from(0x02), PciClass::Network);
        assert_eq!(PciClass::from(0x06), PciClass::Bridge);
    }
}
