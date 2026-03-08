// Minimal DMAR (DMA Remapping) table parser
// This is intentionally small and only extracts the pieces the kernel needs:
// - DRHD units (register base, segment, include_all, device scopes)
// - RMRR regions (segment, base, limit, device scopes)

#![allow(dead_code)]
#![allow(clippy::pub_underscore_fields)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::ptr_as_ptr)]

use alloc::vec::Vec;
use core::mem;

use crate::tables::AcpiSdtHeader;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DmarHeader {
    pub header: AcpiSdtHeader,
    pub haw: u8,
    pub flags: u8,
    pub _reserved: [u8; 10],
}

impl DmarHeader {
    pub const SIGNATURE: &'static [u8; 4] = b"DMAR";

    pub fn is_valid(&self) -> bool {
        self.header.signature == *Self::SIGNATURE
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DmarRemappingHeader {
    pub type_code: u16,
    pub length: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DrhdWrapper {
    pub header: DmarRemappingHeader,
    pub flags: u8,
    pub _reserved: u8,
    pub segment: u16,
    pub register_base_addr: u64,
}

impl DrhdWrapper {
    pub const fn include_pci_all(&self) -> bool {
        (self.flags & 0x1) != 0
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RmrrWrapper {
    pub header: DmarRemappingHeader,
    pub _reserved: u16,
    pub segment: u16,
    pub base_address: u64,
    pub limit_address: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DeviceScopeHeader {
    pub type_code: u8,
    pub length: u8,
    pub _reserved: u16,
    pub enumeration_id: u8,
    pub start_bus: u8,
}

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

/// Parse a DMAR table located at `addr` (physical/virtual pointer address)
/// Parse a DMAR table located at `addr` (physical/virtual pointer address)
pub unsafe fn parse_dmar(addr: usize) -> Result<DmarInfo, &'static str> {
    let header = unsafe { &*(addr as *const DmarHeader) };
    if !header.is_valid() {
        return Err("Invalid DMAR signature");
    }

    let table_len = header.header.length as usize;
    let mut offset = mem::size_of::<DmarHeader>();
    let base_ptr = addr as *const u8;

    let mut drhd_units = Vec::new();
    let mut rmrr_regions = Vec::new();

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while offset < table_len {
        let entry_ptr = unsafe { base_ptr.add(offset) } as *const DmarRemappingHeader;
        let entry_type = unsafe { (*entry_ptr).type_code };
        let entry_len = unsafe { (*entry_ptr).length } as usize;

        if entry_len < mem::size_of::<DmarRemappingHeader>() {
            break; // sanity
        }

        match entry_type {
            0 => {
                let drhd = unsafe { &*(entry_ptr as *const DrhdWrapper) };
                let devices = unsafe {
                    parse_device_scopes(
                        base_ptr.add(offset + mem::size_of::<DrhdWrapper>()),
                        entry_len - mem::size_of::<DrhdWrapper>(),
                    )
                };
                drhd_units.push(DrhdUnit {
                    segment: drhd.segment,
                    register_base: drhd.register_base_addr,
                    include_all: drhd.include_pci_all(),
                    devices,
                });
            }
            1 => {
                let rmrr = unsafe { &*(entry_ptr as *const RmrrWrapper) };
                let devices = unsafe {
                    parse_device_scopes(
                        base_ptr.add(offset + mem::size_of::<RmrrWrapper>()),
                        entry_len - mem::size_of::<RmrrWrapper>(),
                    )
                };
                rmrr_regions.push(RmrrRegion {
                    segment: rmrr.segment,
                    base: rmrr.base_address,
                    limit: rmrr.limit_address,
                    devices,
                });
            }
            _ => {}
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

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while len >= mem::size_of::<DeviceScopeHeader>() {
        let header = unsafe { &*(ptr as *const DeviceScopeHeader) };
        let scope_len = header.length as usize;

        if scope_len < mem::size_of::<DeviceScopeHeader>() || scope_len > len {
            break;
        }

        let mut path = Vec::new();
        let path_len = scope_len - mem::size_of::<DeviceScopeHeader>();
        let path_count = path_len / 2;
        let path_ptr = unsafe { ptr.add(mem::size_of::<DeviceScopeHeader>()) };

        for i in 0..path_count {
            let dev = unsafe { *path_ptr.add(i * 2) };
            let func = unsafe { *path_ptr.add(i * 2 + 1) };
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

        ptr = unsafe { ptr.add(scope_len) };
        len -= scope_len;
    }

    scopes
}
