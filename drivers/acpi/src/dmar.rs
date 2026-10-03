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

impl DmarInfo {
    const INTERRUPT_REMAPPING: u8 = 1 << 0;
    const X2APIC_OPT_OUT: u8 = 1 << 1;

    /// Returns whether firmware permits interrupt remapping for this host.
    pub const fn supports_interrupt_remapping(&self) -> bool {
        self.flags & Self::INTERRUPT_REMAPPING != 0
    }

    /// Returns whether firmware requires the operating system to avoid x2APIC mode.
    pub const fn x2apic_opt_out(&self) -> bool {
        self.flags & Self::X2APIC_OPT_OUT != 0
    }
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
    // LOOP_PROOF: mode=condition; reason=Each validated next offset consumes at least four bytes from the finite table and malformed lengths return before advancing.;
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
    // LOOP_PROOF: mode=condition; reason=Each validated scope consumes at least six bytes from the remaining finite slice and malformed or truncated scopes return an error.;
    while !bytes.is_empty() {
        if bytes.len() < 6 {
            return Err(error("DMAR device scope header is truncated"));
        }
        let length = usize::from(bytes[1]);
        if length < 6 || length > bytes.len() || !(length - 6).is_multiple_of(2) {
            return Err(error("DMAR device scope length is invalid"));
        }
        if matches!(bytes[0], 1..=4) && length == 6 {
            return Err(AcpiError::table(
                AcpiErrorKind::InvalidEncoding,
                *b"DMAR",
                "DMAR PCI device scope has an empty path",
            ));
        }
        let mut path = Vec::new();
        for entry in bytes[6..length].as_chunks::<2>().0 {
            if entry[0] >= 32 || entry[1] >= 8 {
                return Err(AcpiError::table(
                    AcpiErrorKind::InvalidEncoding,
                    *b"DMAR",
                    "DMAR PCI path coordinates exceed device/function widths",
                ));
            }
            path.push(PciPath {
                device: entry[0],
                function: entry[1],
            });
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multibridge_pci_path_without_collapsing_its_start_bus() {
        // Independent device-scope bytes: type=endpoint, length=10, bus=2,
        // followed by a bridge at 3.0 and an endpoint at 31.7.
        let scopes = parse_scopes(&[1, 10, 0, 0, 0, 2, 3, 0, 31, 7]).unwrap();
        assert_eq!(scopes[0].start_bus, 2);
        assert_eq!(
            scopes[0].path,
            [
                PciPath {
                    device: 3,
                    function: 0
                },
                PciPath {
                    device: 31,
                    function: 7
                }
            ]
        );
    }

    #[test]
    fn invalid_pci_coordinates_and_missing_path_are_encoding_failures() {
        for bytes in [
            &[1, 8, 0, 0, 0, 0, 32, 0][..],
            &[1, 8, 0, 0, 0, 0, 31, 8][..],
            &[1, 6, 0, 0, 0, 0][..],
        ] {
            assert_eq!(
                parse_scopes(bytes).unwrap_err().kind,
                AcpiErrorKind::InvalidEncoding
            );
        }
        assert_eq!(
            parse_scopes(&[1, 7, 0, 0, 0, 0, 3]).unwrap_err().kind,
            AcpiErrorKind::InvalidLength
        );
    }
}
