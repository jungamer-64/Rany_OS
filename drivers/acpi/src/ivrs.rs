// Minimal IVRS (AMD-Vi) table parser.
// Extracts IVHD entries with IOMMU base address, segment, and device scopes
// for early AMD-Vi bring-up.

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
pub struct IvrsHeader {
    pub header: AcpiSdtHeader,
    pub info: u32,
    pub _reserved: u64,
}

impl IvrsHeader {
    pub const SIGNATURE: &'static [u8; 4] = b"IVRS";

    pub fn is_valid(&self) -> bool {
        self.header.signature == *Self::SIGNATURE
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IvrsBlockHeader {
    pub block_type: u8,
    pub flags: u8,
    pub length: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IvhdHeader {
    pub header: IvrsBlockHeader,
    pub device_id: u16,
    pub capability_offset: u16,
    pub iommu_base: u64,
    pub pci_segment: u16,
    pub iommu_info: u16,
    pub iommu_feature: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IvmdHeader {
    pub header: IvrsBlockHeader,
    pub device_id: u16,
    pub aux: u16,
    pub pci_segment: u16,
    pub _reserved: [u8; 6],
    pub range_start: u64,
    pub range_length: u64,
}

#[derive(Debug, Clone)]
pub struct IvrsInfo {
    pub info: u32,
    pub ivhds: Vec<IvhdInfo>,
    pub ivmds: Vec<IvmdInfo>,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

pub(crate) const IVHD_TYPE_10: u8 = 0x10;
const IVHD_TYPE_11: u8 = 0x11;
const IVHD_TYPE_40: u8 = 0x40;
const IVHD_TYPE_41: u8 = 0x41;

const fn is_ivhd(block_type: u8) -> bool {
    matches!(
        block_type,
        IVHD_TYPE_10 | IVHD_TYPE_11 | IVHD_TYPE_40 | IVHD_TYPE_41
    )
}

const IVMD_TYPE_ALL: u8 = 0x20;
const IVMD_TYPE: u8 = 0x21;
pub(crate) const IVMD_TYPE_RANGE: u8 = 0x22;

pub(crate) const IVMD_FLAG_UNITY_MAP: u8 = 0x01;
pub(crate) const IVMD_FLAG_IR: u8 = 0x02;
pub(crate) const IVMD_FLAG_IW: u8 = 0x04;
const IVMD_FLAG_EXCL_RANGE: u8 = 0x08;

const fn is_ivmd(block_type: u8) -> bool {
    matches!(block_type, IVMD_TYPE_ALL | IVMD_TYPE | IVMD_TYPE_RANGE)
}

const IVHD_DEV_ALL: u8 = 0x01;
pub(crate) const IVHD_DEV_SELECT: u8 = 0x02;
pub(crate) const IVHD_DEV_SELECT_RANGE_START: u8 = 0x03;
pub(crate) const IVHD_DEV_RANGE_END: u8 = 0x04;
pub(crate) const IVHD_DEV_ALIAS: u8 = 0x42;
pub(crate) const IVHD_DEV_ALIAS_RANGE: u8 = 0x43;
pub(crate) const IVHD_DEV_EXT_SELECT: u8 = 0x46;
pub(crate) const IVHD_DEV_EXT_SELECT_RANGE: u8 = 0x47;
const IVHD_DEV_SPECIAL: u8 = 0x48;
const IVHD_DEV_ACPI_HID: u8 = 0xf0;

const fn ivhd_header_size(block_type: u8) -> Option<usize> {
    match block_type {
        IVHD_TYPE_10 => Some(mem::size_of::<IvhdHeader>()),
        IVHD_TYPE_11 | IVHD_TYPE_40 | IVHD_TYPE_41 => Some(mem::size_of::<IvhdHeader>() + 16),
        _ => None,
    }
}

const unsafe fn read_u16(ptr: *const u8) -> u16 {
    u16::from_le_bytes([unsafe { *ptr }, unsafe { *ptr.add(1) }])
}

const unsafe fn read_u32(ptr: *const u8) -> u32 {
    u32::from_le_bytes([
        unsafe { *ptr },
        unsafe { *ptr.add(1) },
        unsafe { *ptr.add(2) },
        unsafe { *ptr.add(3) },
    ])
}

const fn ivhd_entry_length(
    entry_type: u8,
    entry_ptr: *const u8,
    remaining: usize,
) -> Option<usize> {
    if remaining < mem::size_of::<u32>() {
        return None;
    }

    if entry_type < 0x80 {
        let len = 4usize << (entry_type >> 6);
        if len == 0 || len > remaining {
            return None;
        }
        return Some(len);
    }

    if entry_type == IVHD_DEV_ACPI_HID {
        if remaining < 22 {
            return None;
        }
        let uid_len = unsafe { *entry_ptr.add(21) } as usize;
        let len = 22 + uid_len;
        if len > remaining {
            return None;
        }
        return Some(len);
    }

    None
}

#[derive(Debug, Clone, Copy)]
enum PendingRangeKind {
    Normal,
    Alias,
    Extended,
}

#[derive(Debug, Clone, Copy)]
struct PendingRange {
    kind: PendingRangeKind,
    start: u16,
    flags: u8,
    ext_flags: u32,
    alias: Option<u16>,
}

fn close_pending_range(pending: Option<PendingRange>, end_devid: u16) -> Option<IvhdDeviceEntry> {
    let pending = pending?;
    Some(match pending.kind {
        PendingRangeKind::Normal => IvhdDeviceEntry::Range {
            start: pending.start,
            end: end_devid,
            flags: pending.flags,
        },
        PendingRangeKind::Alias => {
            let alias = pending.alias?;
            IvhdDeviceEntry::AliasRange {
                start: pending.start,
                end: end_devid,
                alias,
                flags: pending.flags,
            }
        }
        PendingRangeKind::Extended => IvhdDeviceEntry::ExtRange {
            start: pending.start,
            end: end_devid,
            flags: pending.flags,
            ext_flags: pending.ext_flags,
        },
    })
}

unsafe fn parse_ivhd_device_entries(ptr: *const u8, len: usize) -> Vec<IvhdDeviceEntry> {
    let mut entries = Vec::new();
    let end = unsafe { ptr.add(len) };
    let mut cursor = ptr;
    let mut pending_range: Option<PendingRange> = None;

    while cursor < end {
        let remaining = end as usize - cursor as usize;
        let entry_type = unsafe { *cursor };
        let entry_len = match ivhd_entry_length(entry_type, cursor, remaining) {
            Some(len) => len,
            None => break,
        };

        if entry_len < mem::size_of::<u32>() || entry_len > remaining {
            break;
        }

        let devid = unsafe { read_u16(cursor.add(1)) };
        let flags = unsafe { *cursor.add(3) };
        let ext = if entry_len >= 8 {
            unsafe { read_u32(cursor.add(4)) }
        } else {
            0
        };

        match entry_type {
            IVHD_DEV_ALL => entries.push(IvhdDeviceEntry::All { flags }),
            IVHD_DEV_SELECT => entries.push(IvhdDeviceEntry::Select { devid, flags }),
            IVHD_DEV_SELECT_RANGE_START => {
                pending_range = Some(PendingRange {
                    kind: PendingRangeKind::Normal,
                    start: devid,
                    flags,
                    ext_flags: 0,
                    alias: None,
                });
            }
            IVHD_DEV_RANGE_END => {
                if let Some(entry) = close_pending_range(pending_range.take(), devid) {
                    entries.push(entry);
                }
            }
            IVHD_DEV_ALIAS => {
                let alias = ((ext >> 8) & 0xffff) as u16;
                entries.push(IvhdDeviceEntry::Alias {
                    devid,
                    alias,
                    flags,
                });
            }
            IVHD_DEV_ALIAS_RANGE => {
                let alias = ((ext >> 8) & 0xffff) as u16;
                pending_range = Some(PendingRange {
                    kind: PendingRangeKind::Alias,
                    start: devid,
                    flags,
                    ext_flags: 0,
                    alias: Some(alias),
                });
            }
            IVHD_DEV_EXT_SELECT => entries.push(IvhdDeviceEntry::ExtSelect {
                devid,
                flags,
                ext_flags: ext,
            }),
            IVHD_DEV_EXT_SELECT_RANGE => {
                pending_range = Some(PendingRange {
                    kind: PendingRangeKind::Extended,
                    start: devid,
                    flags,
                    ext_flags: ext,
                    alias: None,
                });
            }
            IVHD_DEV_SPECIAL => {
                let handle = (ext & 0xff) as u8;
                let special_devid = ((ext >> 8) & 0xffff) as u16;
                let variety = ((ext >> 24) & 0xff) as u8;
                entries.push(IvhdDeviceEntry::Special {
                    devid: special_devid,
                    flags,
                    handle,
                    variety,
                });
            }
            IVHD_DEV_ACPI_HID => {
                entries.push(IvhdDeviceEntry::AcpiHid { devid, flags });
            }
            _ => {}
        }

        cursor = unsafe { cursor.add(entry_len) };
    }

    entries
}

/// Parse an IVRS table located at `addr` (physical/virtual pointer address)
pub unsafe fn parse_ivrs(addr: usize) -> Result<IvrsInfo, &'static str> {
    let header = unsafe { &*(addr as *const IvrsHeader) };
    if !header.is_valid() {
        return Err("Invalid IVRS signature");
    }

    let table_len = header.header.length as usize;
    if table_len < mem::size_of::<IvrsHeader>() {
        return Err("IVRS length too small");
    }

    let mut offset = mem::size_of::<IvrsHeader>();
    let base_ptr = addr as *const u8;
    let mut ivhds = Vec::new();
    let mut ivmds = Vec::new();

    while offset + mem::size_of::<IvrsBlockHeader>() <= table_len {
        let entry_ptr = unsafe { base_ptr.add(offset) } as *const IvrsBlockHeader;
        let entry_len = unsafe { (*entry_ptr).length } as usize;
        let entry_type = unsafe { (*entry_ptr).block_type };

        if entry_len < mem::size_of::<IvrsBlockHeader>() {
            break;
        }
        if offset + entry_len > table_len {
            break;
        }

        // SAFETY: entry_ptr is validated above
        unsafe { process_ivrs_block(entry_ptr, entry_type, entry_len, &mut ivhds, &mut ivmds) };

        offset += entry_len;
    }

    Ok(IvrsInfo {
        info: header.info,
        ivhds,
        ivmds,
    })
}

/// Parse a single IVRS block (IVHD or IVMD) and push to the appropriate list
unsafe fn process_ivrs_block(
    entry_ptr: *const IvrsBlockHeader,
    entry_type: u8,
    entry_len: usize,
    ivhds: &mut Vec<IvhdInfo>,
    ivmds: &mut Vec<IvmdInfo>,
) {
    if is_ivhd(entry_type) {
        let header_size = match ivhd_header_size(entry_type) {
            Some(size) => size,
            None => return,
        };
        if entry_len < header_size {
            return;
        }

        let ivhd = &*(entry_ptr as *const IvhdHeader);
        let devices = parse_ivhd_device_entries(
            (entry_ptr as *const u8).add(header_size),
            entry_len - header_size,
        );
        ivhds.push(IvhdInfo {
            block_type: ivhd.header.block_type,
            flags: ivhd.header.flags,
            length: ivhd.header.length,
            device_id: ivhd.device_id,
            capability_offset: ivhd.capability_offset,
            iommu_base: ivhd.iommu_base,
            pci_segment: ivhd.pci_segment,
            iommu_info: ivhd.iommu_info,
            iommu_feature: ivhd.iommu_feature,
            device_entries: devices,
        });
    } else if is_ivmd(entry_type) {
        if entry_len < mem::size_of::<IvmdHeader>() {
            return;
        }
        let ivmd = &*(entry_ptr as *const IvmdHeader);
        ivmds.push(IvmdInfo {
            block_type: ivmd.header.block_type,
            flags: ivmd.header.flags,
            length: ivmd.header.length,
            device_id: ivmd.device_id,
            aux: ivmd.aux,
            pci_segment: ivmd.pci_segment,
            range_start: ivmd.range_start,
            range_length: ivmd.range_length,
        });
    }
}
