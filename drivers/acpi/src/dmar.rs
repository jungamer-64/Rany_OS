use alloc::vec::Vec;

use crate::{AcpiError, AcpiErrorKind};

const DMAR_FIXED_LENGTH: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarInfo {
    pub host_address_width: u8,
    pub flags: u8,
    pub drhd_units: Vec<DrhdUnit>,
    pub rmrr_regions: Vec<RmrrRegion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrhdUnit {
    pub segment: u16,
    pub register_base: u64,
    pub include_all: bool,
    pub devices: Vec<DeviceScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmrrRegion {
    pub segment: u16,
    pub base: u64,
    pub limit: u64,
    pub devices: Vec<DeviceScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceScope {
    pub scope_type: u8,
    pub enumeration_id: u8,
    pub start_bus: u8,
    pub path: Vec<PciPath>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciPath {
    pub device: u8,
    pub function: u8,
}

/// Parses an owned, checksum-validated DMAR table body.
///
/// # Errors
///
/// Returns a typed error for a non-DMAR signature, malformed remapping unit,
/// truncated device scope, or invalid PCI path encoding.
pub fn parse(bytes: &[u8]) -> Result<DmarInfo, AcpiError> {
    if bytes.len() < DMAR_FIXED_LENGTH || bytes.get(0..4) != Some(b"DMAR") {
        return Err(error(
            "DMAR fixed header is missing or has the wrong signature",
        ));
    }
    let declared = read_u32(bytes, 4)? as usize;
    if declared != bytes.len() {
        return Err(error("DMAR length does not match catalog bytes"));
    }

    let mut drhd_units = Vec::new();
    let mut rmrr_regions = Vec::new();
    let mut offset = DMAR_FIXED_LENGTH;
    while offset < bytes.len() {
        let kind = read_u16(bytes, offset)?;
        let length = usize::from(read_u16(bytes, offset + 2)?);
        let end = offset
            .checked_add(length)
            .filter(|end| length >= 4 && *end <= bytes.len())
            .ok_or_else(|| error("DMAR remapping structure length is invalid"))?;
        let structure = &bytes[offset..end];
        match kind {
            0 => {
                if structure.len() < 16 {
                    return Err(error("DMAR DRHD structure is truncated"));
                }
                drhd_units.push(DrhdUnit {
                    segment: read_u16(structure, 6)?,
                    register_base: read_u64(structure, 8)?,
                    include_all: structure[4] & 1 != 0,
                    devices: parse_scopes(&structure[16..])?,
                });
            }
            1 => {
                if structure.len() < 24 {
                    return Err(error("DMAR RMRR structure is truncated"));
                }
                let base = read_u64(structure, 8)?;
                let limit = read_u64(structure, 16)?;
                if limit < base {
                    return Err(error("DMAR RMRR limit precedes its base"));
                }
                rmrr_regions.push(RmrrRegion {
                    segment: read_u16(structure, 6)?,
                    base,
                    limit,
                    devices: parse_scopes(&structure[24..])?,
                });
            }
            _ => {}
        }
        offset = end;
    }

    Ok(DmarInfo {
        host_address_width: bytes[36],
        flags: bytes[37],
        drhd_units,
        rmrr_regions,
    })
}

fn parse_scopes(mut bytes: &[u8]) -> Result<Vec<DeviceScope>, AcpiError> {
    let mut scopes = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 6 {
            return Err(error("DMAR device scope header is truncated"));
        }
        let length = usize::from(bytes[1]);
        if length < 6 || length > bytes.len() || !(length - 6).is_multiple_of(2) {
            return Err(error("DMAR device scope length is invalid"));
        }
        let path = bytes[6..length]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|entry| PciPath {
                device: entry[0],
                function: entry[1],
            })
            .collect();
        scopes.push(DeviceScope {
            scope_type: bytes[0],
            enumeration_id: bytes[4],
            start_bus: bytes[5],
            path,
        });
        bytes = &bytes[length..];
    }
    Ok(scopes)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AcpiError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| error("DMAR u16 field is truncated"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AcpiError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| error("DMAR u32 field is truncated"))?;
    Ok(u32::from_le_bytes(
        value
            .try_into()
            .map_err(|_| error("DMAR u32 field is malformed"))?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AcpiError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| error("DMAR u64 field is truncated"))?;
    Ok(u64::from_le_bytes(
        value
            .try_into()
            .map_err(|_| error("DMAR u64 field is malformed"))?,
    ))
}

fn error(detail: &'static str) -> AcpiError {
    AcpiError::table(AcpiErrorKind::InvalidLength, *b"DMAR", detail)
}
