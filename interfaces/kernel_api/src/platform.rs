// ============================================================================
// kernel_api/src/platform.rs - Platform provider traits and portable types
// ============================================================================

extern crate alloc;

use crate::abi::driver::PackedPciLocation;
use crate::{KapiResult, service::kernel};
use alloc::vec::Vec;
use core::fmt;

// ============================================================================
// ACPI data
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalApicInfo {
    pub processor_id: u8,
    pub apic_id: u8,
    pub enabled: bool,
    pub online_capable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicInfo {
    pub id: u8,
    pub address: u64,
    pub gsi_base: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptOverrideInfo {
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub polarity: u8,
    pub trigger_mode: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcieEcamInfo {
    pub base_address: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

// ============================================================================
// PCI data
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct BdfAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl BdfAddress {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device: device & 0x1F,
            function: function & 0x07,
        }
    }

    pub const fn bus(&self) -> u8 {
        self.bus
    }

    pub const fn device(&self) -> u8 {
        self.device
    }

    pub const fn function(&self) -> u8 {
        self.function
    }

    pub const fn to_u16(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | self.function as u16
    }

    pub const fn from_u16(raw: u16) -> Self {
        Self {
            bus: (raw >> 8) as u8,
            device: ((raw >> 3) & 0x1F) as u8,
            function: (raw & 0x07) as u8,
        }
    }
}

impl fmt::Display for BdfAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}.{:x}",
            self.bus, self.device, self.function
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct VendorId(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct DeviceId(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ClassCode {
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

impl ClassCode {
    pub const fn new(class: u8, subclass: u8, prog_if: u8) -> Self {
        Self {
            class,
            subclass,
            prog_if,
        }
    }

    pub fn is_xhci(&self) -> bool {
        self.class == 0x0C && self.subclass == 0x03 && self.prog_if == 0x30
    }

    pub fn is_nvme(&self) -> bool {
        self.class == 0x01 && self.subclass == 0x08 && self.prog_if == 0x02
    }
}

impl fmt::Display for ClassCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}.{:02x}",
            self.class, self.subclass, self.prog_if
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    Memory32 {
        base: u64,
        size: u64,
        prefetchable: bool,
    },
    Memory64 {
        base: u64,
        size: u64,
        prefetchable: bool,
    },
    Io {
        base: u64,
        size: u64,
    },
}

impl Bar {
    pub fn base(&self) -> u64 {
        match self {
            Self::Memory32 { base, .. } | Self::Memory64 { base, .. } | Self::Io { base, .. } => {
                *base
            }
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            Self::Memory32 { size, .. } | Self::Memory64 { size, .. } | Self::Io { size, .. } => {
                *size
            }
        }
    }

    pub fn is_memory(&self) -> bool {
        matches!(self, Self::Memory32 { .. } | Self::Memory64 { .. })
    }

    pub fn is_io(&self) -> bool {
        matches!(self, Self::Io { .. })
    }

    pub fn is_prefetchable(&self) -> bool {
        matches!(
            self,
            Self::Memory32 {
                prefetchable: true,
                ..
            } | Self::Memory64 {
                prefetchable: true,
                ..
            }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciDeviceInfo {
    pub segment: u16,
    pub bdf: BdfAddress,
    pub vendor_id: VendorId,
    pub device_id: DeviceId,
    pub revision_id: u8,
    pub class_code: ClassCode,
    pub header_type: u8,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub bars: [Option<Bar>; 6],
    pub capabilities: Vec<(u8, u8)>,
    pub msi_cap_offset: Option<u8>,
    pub msix_cap_offset: Option<u8>,
    pub pcie_cap_offset: Option<u8>,
    pub iommu_domain_id: Option<u16>,
}

impl PciDeviceInfo {
    pub const fn packed_locator(&self) -> PackedPciLocation {
        PackedPciLocation::new(
            self.segment,
            self.bdf.bus(),
            self.bdf.device(),
            self.bdf.function(),
        )
    }

    pub fn is_multifunction(&self) -> bool {
        (self.header_type & 0x80) != 0
    }

    pub fn header_type_value(&self) -> u8 {
        self.header_type & 0x7F
    }

    pub fn supports_msi(&self) -> bool {
        self.msi_cap_offset.is_some()
    }

    pub fn supports_msix(&self) -> bool {
        self.msix_cap_offset.is_some()
    }

    pub fn is_pcie(&self) -> bool {
        self.pcie_cap_offset.is_some()
    }

    pub fn enable_bus_master(&self) {
        if let Some(pci) = try_pci() {
            let _ = pci.set_bus_master(self.bdf, true);
        }
    }

    pub fn disable_bus_master(&self) {
        if let Some(pci) = try_pci() {
            let _ = pci.set_bus_master(self.bdf, false);
        }
    }

    pub fn enable_memory_space(&self) {
        if let Some(pci) = try_pci() {
            let _ = pci.set_memory_space(self.bdf, true);
        }
    }

    pub fn disable_memory_space(&self) {
        if let Some(pci) = try_pci() {
            let _ = pci.set_memory_space(self.bdf, false);
        }
    }

    pub fn enable_io_space(&self) {
        if let Some(pci) = try_pci() {
            let _ = pci.set_io_space(self.bdf, true);
        }
    }

    pub fn disable_io_space(&self) {
        if let Some(pci) = try_pci() {
            let _ = pci.set_io_space(self.bdf, false);
        }
    }

    pub fn disable_intx(&self) {
        if let Some(pci) = try_pci() {
            let _ = pci.disable_intx(self.bdf);
        }
    }
}

// ============================================================================
// Provider traits
// ============================================================================

pub trait AcpiServices: Send + Sync {
    fn local_apics(&self) -> Vec<LocalApicInfo>;
    fn io_apics(&self) -> Vec<IoApicInfo>;
    fn interrupt_overrides(&self) -> Vec<InterruptOverrideInfo>;
    fn pcie_ecam_regions(&self) -> Vec<PcieEcamInfo>;
    fn local_apic_address(&self) -> Option<u64>;
}

pub trait PciServices: Send + Sync {
    fn scan_all_devices(&self) -> Vec<PciDeviceInfo>;
    fn find_by_class(&self, class: u8, subclass: u8) -> Vec<PciDeviceInfo>;
    /// # Errors
    ///
    /// Returns an error if the device is absent or its command register cannot
    /// be updated.
    fn set_bus_master(&self, bdf: BdfAddress, enabled: bool) -> KapiResult<()>;
    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or cannot be completed.
    fn set_memory_space(&self, bdf: BdfAddress, enabled: bool) -> KapiResult<()>;
    /// # Errors
    ///
    /// Returns an error if the device is absent or its command register cannot
    /// be updated.
    fn set_io_space(&self, bdf: BdfAddress, enabled: bool) -> KapiResult<()>;
    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or cannot be completed.
    fn disable_intx(&self, bdf: BdfAddress) -> KapiResult<()>;
}

pub trait ApicServices: Send + Sync {
    fn local_apic_id(&self) -> u32;
}

// ============================================================================
// Provider lookup helpers
// ============================================================================

#[inline]
pub fn try_acpi() -> Option<&'static dyn AcpiServices> {
    if !kernel::is_installed() {
        return None;
    }

    kernel::instance().platform_acpi()
}

#[inline]
/// # Panics
///
/// Panics if ACPI services have not been installed.
pub fn acpi() -> &'static dyn AcpiServices {
    try_acpi().expect("AcpiServices not installed")
}

#[inline]
pub fn try_pci() -> Option<&'static dyn PciServices> {
    if !kernel::is_installed() {
        return None;
    }

    kernel::instance().platform_pci()
}

#[inline]
/// # Panics
///
/// Panics if PCI services have not been installed.
pub fn pci() -> &'static dyn PciServices {
    try_pci().expect("PciServices not installed")
}

#[inline]
pub fn try_apic() -> Option<&'static dyn ApicServices> {
    if !kernel::is_installed() {
        return None;
    }

    kernel::instance().platform_apic()
}

#[inline]
/// # Panics
///
/// Panics if APIC services have not been installed.
pub fn apic() -> &'static dyn ApicServices {
    try_apic().expect("ApicServices not installed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_bdf_roundtrip() {
        let bdf = BdfAddress::new(0x12, 0x03, 0x04);
        assert_eq!(BdfAddress::from_u16(bdf.to_u16()), bdf);
    }
}
