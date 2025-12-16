// Minimal DMAR (DMA Remapping) table parser
// This is intentionally small and only extracts the pieces the kernel needs:
// - DRHD units (register base, segment, include_all, device scopes)
// - RMRR regions (segment, base, limit, device scopes)

#![allow(dead_code)]

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
    pub fn include_pci_all(&self) -> bool {
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
            break; // sanity
        }

        match entry_type {
            0 => {
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

    while len >= mem::size_of::<DeviceScopeHeader>() {
        let header = &*(ptr as *const DeviceScopeHeader);
        let scope_len = header.length as usize;

        if scope_len < mem::size_of::<DeviceScopeHeader>() || scope_len > len {
            break;
        }

        let mut path = Vec::new();
        let path_len = scope_len - mem::size_of::<DeviceScopeHeader>();
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn test_parse_minimal_dmar() {
        // Build a minimal DMAR table with a single RMRR entry (no scopes)
        let mut buf: Vec<u8> = Vec::new();

        // LocalSdtHeader (signature + length placeholder)
        let mut header = LocalSdtHeader {
            signature: *b"DMAR",
            length: 0, // patch later
            revision: 1,
            checksum: 0,
            oem_id: [0; 6],
            oem_table_id: [0; 8],
            oem_revision: 0,
            creator_id: 0,
            creator_revision: 0,
        };

        // DMAR header
        let dmar = DmarHeader {
            header,
            haw: 0,
            flags: 0,
            _reserved: [0; 10],
        };

        // Append DMAR header bytes
        let dmar_bytes = unsafe {
            core::slice::from_raw_parts(&dmar as *const DmarHeader as *const u8, mem::size_of::<DmarHeader>())
        };
        buf.extend_from_slice(dmar_bytes);

        // RMRR entry (type=1)
        let rmrr = RmrrWrapper {
            header: DmarRemappingHeader { type_code: 1, length: mem::size_of::<RmrrWrapper>() as u16 },
            _reserved: 0,
            segment: 0,
            base_address: 0x1000,
            limit_address: 0x1fff,
        };
        let rmrr_bytes = unsafe {
            core::slice::from_raw_parts(&rmrr as *const RmrrWrapper as *const u8, mem::size_of::<RmrrWrapper>())
        };
        buf.extend_from_slice(rmrr_bytes);

        // Patch length
        let total_len = buf.len() as u32;
        let len_bytes = total_len.to_le_bytes();
        buf[4..8].copy_from_slice(&len_bytes);

        // Parse
        let ptr = buf.as_ptr() as usize;
        let info = unsafe { parse_dmar(ptr) }.expect("parse should succeed");
        assert_eq!(info.rmrr_regions.len(), 1);
        assert_eq!(info.drhd_units.len(), 0);
        assert_eq!(info.rmrr_regions[0].base, 0x1000);
    }
}
