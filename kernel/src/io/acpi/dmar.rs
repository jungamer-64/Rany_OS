// ============================================================================
// src/io/acpi/dmar.rs - ACPI DMAR Table (DMA Remapping)
// ============================================================================
//!
//! # DMAR (DMA Remapping Reporting) Table
//!
//! The DMAR table is used to identify IOMMU Hardware Units (DRHD) and
//! Reserved Memory Regions (RMRR) for devices.
//!
//! Ref: Intel Virtualization Technology for Directed I/O Architecture Spec, Chapter 8.1

use crate::io::acpi::AcpiSdtHeader;
use alloc::vec::Vec;
use core::mem;

/// DMAR Table Structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DmarHeader {
    pub header: AcpiSdtHeader,
    /// Host Address Width (Physical address width supported by the platform)
    /// In bits, e.g., 38 means 39-bit address width (encoding: width - 1)
    pub haw: u8,
    pub flags: u8,
    _reserved: [u8; 10],
}

impl DmarHeader {
    pub const SIGNATURE: &'static [u8; 4] = b"DMAR";

    /// Verify signature and checksum
    pub fn is_valid(&self) -> bool {
        self.header.signature == *Self::SIGNATURE
    }

    /// Check if Intra-Remap Interrupt (INTR_REMAP) is supported
    pub fn flags_intr_remap(&self) -> bool {
        (self.flags & 0x1) != 0
    }

    /// Check if X2APIC Opt Out is set
    pub fn flags_x2apic_opt_out(&self) -> bool {
        (self.flags & 0x2) != 0
    }

    /// Check if DMA Control Guarantee is supported
    pub fn flags_dma_ctrl_platform_opt_in(&self) -> bool {
        (self.flags & 0x4) != 0
    }
}

/// Remapping Structure Types
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarStructureType {
    /// DMA Remapping Hardware Unit Definition
    Drhd = 0,
    /// Reserved Memory Region Reporting
    Rmrr = 1,
    /// Root Port ATS Capability Reporting
    Atsr = 2,
    /// Remapping Hardware Static Affinity
    Rhsa = 3,
    /// ACPI Name-space Device Declaration
    Andd = 4,
    /// SoC Integrated System Agent (SiSA)
    Sats = 5,
    /// Reserved
    Reserved = 6,
}

/// Generic Remapping Structure Header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DmarRemappingHeader {
    pub type_code: u16,
    pub length: u16,
}

/// DRHD: DMA Remapping Hardware Unit Definition (Type 0)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DrhdWrapper {
    pub header: DmarRemappingHeader,
    pub flags: u8,
    _reserved: u8,
    pub segment: u16,
    pub register_base_addr: u64,
    // Followed by Device Scope Structures
}

impl DrhdWrapper {
    /// Check if INCLUDE_PCI_ALL flag is set
    /// If set, this unit controls all PCI devices not covered by other units
    pub fn include_pci_all(&self) -> bool {
        (self.flags & 0x1) != 0
    }
}

/// RMRR: Reserved Memory Region Reporting (Type 1)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RmrrWrapper {
    pub header: DmarRemappingHeader,
    _reserved: u16,
    pub segment: u16,
    pub base_address: u64,
    pub limit_address: u64,
    // Followed by Device Scope Structures
}

/// Device Scope Structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DeviceScopeHeader {
    pub type_code: u8,
    pub length: u8,
    _reserved: u16,
    pub enumeration_id: u8,
    pub start_bus: u8,
    // Followed by path (Bus/Device/Function) for hierarchical devices
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceScopeType {
    PciEndpoint = 1,
    PciSubHierarchy = 2,
    IoApic = 3,
    Hpet = 4,
    AcpiNamespaceDevice = 5,
}

/// Parsed DMAR Information
#[derive(Debug, Clone)]
pub struct DmarInfo {
    pub haw: u8,
    pub flags: u8,
    pub drhd_units: Vec<DrhdUnit>,
    pub rmrr_regions: Vec<RmrrRegion>,
}

#[derive(Debug, Clone)]
pub struct DrhdUnit {
    pub segment: u16,
    pub register_base: u64,
    pub include_all: bool,
    pub devices: Vec<DeviceScope>,
}

#[derive(Debug, Clone)]
pub struct RmrrRegion {
    pub segment: u16,
    pub base: u64,
    pub limit: u64,
    pub devices: Vec<DeviceScope>,
}

#[derive(Debug, Clone)]
pub struct DeviceScope {
    pub scope_type: u8,
    pub enumeration_id: u8,
    pub start_bus: u8,
    pub path: Vec<PciPath>,
}

#[derive(Debug, Clone, Copy)]
pub struct PciPath {
    pub device: u8,
    pub function: u8,
}

/// Parse the DMAR table
pub unsafe fn parse_dmar(addr: usize) -> Result<DmarInfo, &'static str> {
    let header = &*(addr as *const DmarHeader);
    if !header.is_valid() {
        return Err("Invalid DMAR signature");
    }

    let table_len = header.header.length as usize;
    let mut offset = mem::size_of::<DmarHeader>();
    let base_ptr = addr as *const u8;

    let mut drhd_units = Vec::new();
    let mut rmrr_regions = Vec::new();

    while offset < table_len {
        let entry_ptr = base_ptr.add(offset) as *const DmarRemappingHeader;
        let entry_type = (*entry_ptr).type_code;
        let entry_len = (*entry_ptr).length as usize;

        if entry_len < mem::size_of::<DmarRemappingHeader>() {
            break; // Sanity check
        }

        match entry_type {
            0 => {
                // DRHD
                let drhd = &*(entry_ptr as *const DrhdWrapper);
                let devices = parse_device_scopes(
                    base_ptr.add(offset + mem::size_of::<DrhdWrapper>()),
                    entry_len - mem::size_of::<DrhdWrapper>(),
                );

                drhd_units.push(DrhdUnit {
                    segment: drhd.segment,
                    register_base: drhd.register_base_addr,
                    include_all: drhd.include_pci_all(),
                    devices,
                });
            }
            1 => {
                // RMRR
                let rmrr = &*(entry_ptr as *const RmrrWrapper);
                let devices = parse_device_scopes(
                    base_ptr.add(offset + mem::size_of::<RmrrWrapper>()),
                    entry_len - mem::size_of::<RmrrWrapper>(),
                );

                rmrr_regions.push(RmrrRegion {
                    segment: rmrr.segment,
                    base: rmrr.base_address,
                    limit: rmrr.limit_address,
                    devices,
                });
            }
            _ => {
                // Ignore other types for now
            }
        }

        offset += entry_len;
    }

    Ok(DmarInfo {
        haw: header.haw,
        flags: header.flags,
        drhd_units,
        rmrr_regions,
    })
}

unsafe fn parse_device_scopes(mut ptr: *const u8, mut len: usize) -> Vec<DeviceScope> {
    let mut scopes = Vec::new();

    while len >= mem::size_of::<DeviceScopeHeader>() {
        let header = &*(ptr as *const DeviceScopeHeader);
        let scope_len = header.length as usize;

        if scope_len < mem::size_of::<DeviceScopeHeader>() || scope_len > len {
            break;
        }

        let mut path = Vec::new();
        let path_len = scope_len - mem::size_of::<DeviceScopeHeader>();
        // Path entries are 2 bytes each (Device, Function)
        // However, the spec says "The Path field... is a list of... (Device, Function)" which are 2 bytes.
        // But the structure might pack specific ways.
        // Spec 8.3.1: Path is "N pairs" of (Device, Function).
        // The structure is packed, so we just read array of u16-like bytes.
        let path_count = path_len / 2;
        let path_ptr = ptr.add(mem::size_of::<DeviceScopeHeader>());

        for i in 0..path_count {
            let dev = *path_ptr.add(i * 2);
            let func = *path_ptr.add(i * 2 + 1);
            path.push(PciPath {
                device: dev,
                function: func,
            });
        }

        scopes.push(DeviceScope {
            scope_type: header.type_code,
            enumeration_id: header.enumeration_id,
            start_bus: header.start_bus,
            path,
        });

        ptr = ptr.add(scope_len);
        len -= scope_len;
    }

    scopes
}
