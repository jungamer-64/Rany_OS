use alloc::vec::Vec;

use crate::{AcpiError, AcpiErrorKind};

const IVRS_FIXED_LENGTH: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IvrsInfo {
    pub info: u32,
    pub ivhds: Vec<IvhdInfo>,
    pub ivmds: Vec<IvmdInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IvhdInfo {
    pub block_type: u8,
    pub flags: u8,
    pub length: u16,
    pub device_id: u16,
    pub capability_offset: u16,
    pub iommu_base: u64,
    pub pci_segment: u16,
    pub iommu_info: u16,
    pub iommu_feature: u32,
    pub device_entries: Vec<IvhdDeviceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IvmdInfo {
    pub block_type: u8,
    pub flags: u8,
    pub length: u16,
    pub device_id: u16,
    pub aux: u16,
    pub pci_segment: u16,
    pub range_start: u64,
    pub range_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IvhdDeviceEntry {
    All {
        flags: u8,
    },
    Select {
        devid: u16,
        flags: u8,
    },
    Range {
        start: u16,
        end: u16,
        flags: u8,
    },
    Alias {
        devid: u16,
        alias: u16,
        flags: u8,
    },
    AliasRange {
        start: u16,
        end: u16,
        alias: u16,
        flags: u8,
    },
    ExtSelect {
        devid: u16,
        flags: u8,
        ext_flags: u32,
    },
    ExtRange {
        start: u16,
        end: u16,
        flags: u8,
        ext_flags: u32,
    },
    Special {
        devid: u16,
        flags: u8,
        handle: u8,
        variety: u8,
    },
    AcpiHid {
        devid: u16,
        flags: u8,
    },
}

/// Parses an owned, checksum-validated IVRS table body.
///
/// # Errors
///
/// Returns a typed error for malformed IVHD/IVMD structures, truncated device
/// entries, invalid ranges, or unsupported variable-width encodings.
pub fn parse(bytes: &[u8]) -> Result<IvrsInfo, AcpiError> {
    if bytes.len() < IVRS_FIXED_LENGTH || bytes.get(0..4) != Some(b"IVRS") {
        return Err(error(
            "IVRS fixed header is missing or has the wrong signature",
        ));
    }
    if read_u32(bytes, 4)? as usize != bytes.len() {
        return Err(error("IVRS length does not match catalog bytes"));
    }

    let mut ivhds = Vec::new();
    let mut ivmds = Vec::new();
    let mut offset = IVRS_FIXED_LENGTH;
    while offset < bytes.len() {
        let block_type = bytes[offset];
        let length = usize::from(read_u16(bytes, offset + 2)?);
        let end = offset
            .checked_add(length)
            .filter(|end| length >= 4 && *end <= bytes.len())
            .ok_or_else(|| error("IVRS block length is invalid"))?;
        let block = &bytes[offset..end];
        if matches!(block_type, 0x10 | 0x11 | 0x40 | 0x41) {
            let header_length = if block_type == 0x10 { 24 } else { 40 };
            if length < header_length {
                return Err(error("IVHD block is shorter than its type-specific header"));
            }
            ivhds.push(IvhdInfo {
                block_type,
                flags: block[1],
                length: length as u16,
                device_id: read_u16(block, 4)?,
                capability_offset: read_u16(block, 6)?,
                iommu_base: read_u64(block, 8)?,
                pci_segment: read_u16(block, 16)?,
                iommu_info: read_u16(block, 18)?,
                iommu_feature: read_u32(block, 20)?,
                device_entries: parse_device_entries(&block[header_length..])?,
            });
        } else if matches!(block_type, 0x20..=0x22) {
            if length < 32 {
                return Err(error("IVMD block is truncated"));
            }
            ivmds.push(IvmdInfo {
                block_type,
                flags: block[1],
                length: length as u16,
                device_id: read_u16(block, 4)?,
                aux: read_u16(block, 6)?,
                pci_segment: read_u16(block, 8)?,
                range_start: read_u64(block, 16)?,
                range_length: read_u64(block, 24)?,
            });
        }
        offset = end;
    }

    Ok(IvrsInfo {
        info: read_u32(bytes, 36)?,
        ivhds,
        ivmds,
    })
}

#[derive(Debug, Clone, Copy)]
enum PendingRange {
    Normal {
        start: u16,
        flags: u8,
    },
    Alias {
        start: u16,
        alias: u16,
        flags: u8,
    },
    Extended {
        start: u16,
        flags: u8,
        ext_flags: u32,
    },
}

fn parse_device_entries(mut bytes: &[u8]) -> Result<Vec<IvhdDeviceEntry>, AcpiError> {
    let mut entries = Vec::new();
    let mut pending = None;
    while !bytes.is_empty() {
        let kind = bytes[0];
        let length = entry_length(kind, bytes)?;
        let entry = &bytes[..length];
        let devid = read_u16(entry, 1)?;
        let flags = entry[3];
        let extended = if length >= 8 { read_u32(entry, 4)? } else { 0 };
        match kind {
            0x01 => entries.push(IvhdDeviceEntry::All { flags }),
            0x02 => entries.push(IvhdDeviceEntry::Select { devid, flags }),
            0x03 => {
                pending = Some(PendingRange::Normal {
                    start: devid,
                    flags,
                })
            }
            0x04 => entries.push(close_range(pending.take(), devid)?),
            0x42 => entries.push(IvhdDeviceEntry::Alias {
                devid,
                alias: ((extended >> 8) & 0xffff) as u16,
                flags,
            }),
            0x43 => {
                pending = Some(PendingRange::Alias {
                    start: devid,
                    alias: ((extended >> 8) & 0xffff) as u16,
                    flags,
                });
            }
            0x46 => entries.push(IvhdDeviceEntry::ExtSelect {
                devid,
                flags,
                ext_flags: extended,
            }),
            0x47 => {
                pending = Some(PendingRange::Extended {
                    start: devid,
                    flags,
                    ext_flags: extended,
                });
            }
            0x48 => entries.push(IvhdDeviceEntry::Special {
                devid: ((extended >> 8) & 0xffff) as u16,
                flags,
                handle: extended as u8,
                variety: (extended >> 24) as u8,
            }),
            0xf0 => entries.push(IvhdDeviceEntry::AcpiHid { devid, flags }),
            _ => {}
        }
        bytes = &bytes[length..];
    }
    if pending.is_some() {
        return Err(error("IVHD range start has no range end"));
    }
    Ok(entries)
}

fn close_range(pending: Option<PendingRange>, end: u16) -> Result<IvhdDeviceEntry, AcpiError> {
    match pending.ok_or_else(|| error("IVHD range end has no matching start"))? {
        PendingRange::Normal { start, flags } if start <= end => {
            Ok(IvhdDeviceEntry::Range { start, end, flags })
        }
        PendingRange::Alias {
            start,
            alias,
            flags,
        } if start <= end => Ok(IvhdDeviceEntry::AliasRange {
            start,
            end,
            alias,
            flags,
        }),
        PendingRange::Extended {
            start,
            flags,
            ext_flags,
        } if start <= end => Ok(IvhdDeviceEntry::ExtRange {
            start,
            end,
            flags,
            ext_flags,
        }),
        _ => Err(error("IVHD device range end precedes its start")),
    }
}

fn entry_length(kind: u8, bytes: &[u8]) -> Result<usize, AcpiError> {
    let length = if kind < 0x80 {
        4usize << (kind >> 6)
    } else if kind == 0xf0 {
        let uid_length = usize::from(
            *bytes
                .get(21)
                .ok_or_else(|| error("IVHD ACPI HID entry is shorter than its fixed header"))?,
        );
        22usize
            .checked_add(uid_length)
            .ok_or_else(|| error("IVHD ACPI HID entry length overflowed"))?
    } else {
        return Err(error("unsupported IVHD variable-width entry"));
    };
    if length < 4 || length > bytes.len() {
        return Err(error("IVHD device entry is truncated"));
    }
    Ok(length)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AcpiError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| error("IVRS u16 field is truncated"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AcpiError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| error("IVRS u32 field is truncated"))?;
    Ok(u32::from_le_bytes(
        value
            .try_into()
            .map_err(|_| error("IVRS u32 field is malformed"))?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AcpiError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| error("IVRS u64 field is truncated"))?;
    Ok(u64::from_le_bytes(
        value
            .try_into()
            .map_err(|_| error("IVRS u64 field is malformed"))?,
    ))
}

fn error(detail: &'static str) -> AcpiError {
    AcpiError::table(AcpiErrorKind::InvalidLength, *b"IVRS", detail)
}
