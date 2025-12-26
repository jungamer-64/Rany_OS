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
    All { flags: u8 },
    Select { devid: u16, flags: u8 },
    Range { start: u16, end: u16, flags: u8 },
    Alias { devid: u16, alias: u16, flags: u8 },
    AliasRange { start: u16, end: u16, alias: u16, flags: u8 },
    ExtSelect { devid: u16, flags: u8, ext_flags: u32 },
    ExtRange { start: u16, end: u16, flags: u8, ext_flags: u32 },
    Special { devid: u16, flags: u8, handle: u8, variety: u8 },
    AcpiHid { devid: u16, flags: u8 },
}

const IVHD_TYPE_10: u8 = 0x10;
const IVHD_TYPE_11: u8 = 0x11;
const IVHD_TYPE_40: u8 = 0x40;
const IVHD_TYPE_41: u8 = 0x41;

fn is_ivhd(block_type: u8) -> bool {
    matches!(block_type, IVHD_TYPE_10 | IVHD_TYPE_11 | IVHD_TYPE_40 | IVHD_TYPE_41)
}

const IVMD_TYPE_ALL: u8 = 0x20;
const IVMD_TYPE: u8 = 0x21;
const IVMD_TYPE_RANGE: u8 = 0x22;

const IVMD_FLAG_UNITY_MAP: u8 = 0x01;
const IVMD_FLAG_IR: u8 = 0x02;
const IVMD_FLAG_IW: u8 = 0x04;
const IVMD_FLAG_EXCL_RANGE: u8 = 0x08;

fn is_ivmd(block_type: u8) -> bool {
    matches!(block_type, IVMD_TYPE_ALL | IVMD_TYPE | IVMD_TYPE_RANGE)
}

const IVHD_DEV_ALL: u8 = 0x01;
const IVHD_DEV_SELECT: u8 = 0x02;
const IVHD_DEV_SELECT_RANGE_START: u8 = 0x03;
const IVHD_DEV_RANGE_END: u8 = 0x04;
const IVHD_DEV_ALIAS: u8 = 0x42;
const IVHD_DEV_ALIAS_RANGE: u8 = 0x43;
const IVHD_DEV_EXT_SELECT: u8 = 0x46;
const IVHD_DEV_EXT_SELECT_RANGE: u8 = 0x47;
const IVHD_DEV_SPECIAL: u8 = 0x48;
const IVHD_DEV_ACPI_HID: u8 = 0xf0;

fn ivhd_header_size(block_type: u8) -> Option<usize> {
    match block_type {
        IVHD_TYPE_10 => Some(mem::size_of::<IvhdHeader>()),
        IVHD_TYPE_11 | IVHD_TYPE_40 | IVHD_TYPE_41 => Some(mem::size_of::<IvhdHeader>() + 16),
        _ => None,
    }
}

unsafe fn read_u16(ptr: *const u8) -> u16 {
    u16::from_le_bytes([unsafe { *ptr }, unsafe { *ptr.add(1) }])
}

unsafe fn read_u32(ptr: *const u8) -> u32 {
    u32::from_le_bytes([
        unsafe { *ptr },
        unsafe { *ptr.add(1) },
        unsafe { *ptr.add(2) },
        unsafe { *ptr.add(3) },
    ])
}

fn ivhd_entry_length(entry_type: u8, entry_ptr: *const u8, remaining: usize) -> Option<usize> {
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
                if let Some(pending) = pending_range.take() {
                    match pending.kind {
                        PendingRangeKind::Normal => {
                            entries.push(IvhdDeviceEntry::Range {
                                start: pending.start,
                                end: devid,
                                flags: pending.flags,
                            });
                        }
                        PendingRangeKind::Alias => {
                            if let Some(alias) = pending.alias {
                                entries.push(IvhdDeviceEntry::AliasRange {
                                    start: pending.start,
                                    end: devid,
                                    alias,
                                    flags: pending.flags,
                                });
                            }
                        }
                        PendingRangeKind::Extended => {
                            entries.push(IvhdDeviceEntry::ExtRange {
                                start: pending.start,
                                end: devid,
                                flags: pending.flags,
                                ext_flags: pending.ext_flags,
                            });
                        }
                    }
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

        if is_ivhd(entry_type) {
            let header_size = match ivhd_header_size(entry_type) {
                Some(size) => size,
                None => {
                    offset += entry_len;
                    continue;
                }
            };
            if entry_len < header_size {
                offset += entry_len;
                continue;
            }

            let ivhd = unsafe { &*(entry_ptr as *const IvhdHeader) };
            let devices = unsafe {
                parse_ivhd_device_entries(
                    (entry_ptr as *const u8).add(header_size),
                    entry_len - header_size,
                )
            };
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
                offset += entry_len;
                continue;
            }
            let ivmd = unsafe { &*(entry_ptr as *const IvmdHeader) };
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

        offset += entry_len;
    }

    Ok(IvrsInfo {
        info: header.info,
        ivhds,
        ivmds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn push_entry(buf: &mut Vec<u8>, entry_type: u8, devid: u16, flags: u8, ext: Option<u32>) {
        buf.push(entry_type);
        buf.extend_from_slice(&devid.to_le_bytes());
        buf.push(flags);
        if let Some(ext) = ext {
            buf.extend_from_slice(&ext.to_le_bytes());
        }
    }

    #[test]
    fn test_parse_ivrs_ivhd_device_entries() {
        let mut entries = Vec::new();

        push_entry(&mut entries, IVHD_DEV_SELECT, 0x0102, 0xaa, None);
        push_entry(
            &mut entries,
            IVHD_DEV_SELECT_RANGE_START,
            0x0200,
            0x11,
            None,
        );
        push_entry(&mut entries, IVHD_DEV_RANGE_END, 0x0203, 0x00, None);
        push_entry(
            &mut entries,
            IVHD_DEV_ALIAS,
            0x0300,
            0x22,
            Some((0x0310u32) << 8),
        );
        push_entry(
            &mut entries,
            IVHD_DEV_ALIAS_RANGE,
            0x0400,
            0x33,
            Some((0x0410u32) << 8),
        );
        push_entry(&mut entries, IVHD_DEV_RANGE_END, 0x0402, 0x00, None);
        push_entry(
            &mut entries,
            IVHD_DEV_EXT_SELECT,
            0x0500,
            0x44,
            Some(0xaabbccdd),
        );
        push_entry(
            &mut entries,
            IVHD_DEV_EXT_SELECT_RANGE,
            0x0600,
            0x55,
            Some(0x11223344),
        );
        push_entry(&mut entries, IVHD_DEV_RANGE_END, 0x0602, 0x00, None);

        let ivhd_len = mem::size_of::<IvhdHeader>() + entries.len();
        let ivhd = IvhdHeader {
            header: IvrsBlockHeader {
                block_type: IVHD_TYPE_10,
                flags: 0,
                length: ivhd_len as u16,
            },
            device_id: 0,
            capability_offset: 0,
            iommu_base: 0xfee00000,
            pci_segment: 0,
            iommu_info: 0,
            iommu_feature: 0,
        };

        let ivrs_len = mem::size_of::<IvrsHeader>() + ivhd_len;
        let ivrs = IvrsHeader {
            header: AcpiSdtHeader {
                signature: *b"IVRS",
                length: ivrs_len as u32,
                revision: 1,
                checksum: 0,
                oem_id: [0; 6],
                oem_table_id: [0; 8],
                oem_revision: 0,
                creator_id: 0,
                creator_revision: 0,
            },
            info: 0,
            _reserved: 0,
        };

        let mut buf = Vec::new();
        let ivrs_bytes = unsafe {
            core::slice::from_raw_parts(
                &ivrs as *const IvrsHeader as *const u8,
                mem::size_of::<IvrsHeader>(),
            )
        };
        buf.extend_from_slice(ivrs_bytes);

        let ivhd_bytes = unsafe {
            core::slice::from_raw_parts(
                &ivhd as *const IvhdHeader as *const u8,
                mem::size_of::<IvhdHeader>(),
            )
        };
        buf.extend_from_slice(ivhd_bytes);
        buf.extend_from_slice(&entries);

        let info = unsafe { parse_ivrs(buf.as_ptr() as usize) }.expect("parse should succeed");
        assert_eq!(info.ivhds.len(), 1);
        assert!(info.ivmds.is_empty());
        let ivhd_info = &info.ivhds[0];
        assert_eq!(ivhd_info.device_entries.len(), 6);

        match &ivhd_info.device_entries[0] {
            IvhdDeviceEntry::Select { devid, flags } => {
                assert_eq!(*devid, 0x0102);
                assert_eq!(*flags, 0xaa);
            }
            _ => panic!("expected select entry"),
        }

        match &ivhd_info.device_entries[1] {
            IvhdDeviceEntry::Range { start, end, flags } => {
                assert_eq!(*start, 0x0200);
                assert_eq!(*end, 0x0203);
                assert_eq!(*flags, 0x11);
            }
            _ => panic!("expected range entry"),
        }

        match &ivhd_info.device_entries[2] {
            IvhdDeviceEntry::Alias { devid, alias, flags } => {
                assert_eq!(*devid, 0x0300);
                assert_eq!(*alias, 0x0310);
                assert_eq!(*flags, 0x22);
            }
            _ => panic!("expected alias entry"),
        }

        match &ivhd_info.device_entries[3] {
            IvhdDeviceEntry::AliasRange { start, end, alias, flags } => {
                assert_eq!(*start, 0x0400);
                assert_eq!(*end, 0x0402);
                assert_eq!(*alias, 0x0410);
                assert_eq!(*flags, 0x33);
            }
            _ => panic!("expected alias range entry"),
        }

        match &ivhd_info.device_entries[4] {
            IvhdDeviceEntry::ExtSelect {
                devid,
                flags,
                ext_flags,
            } => {
                assert_eq!(*devid, 0x0500);
                assert_eq!(*flags, 0x44);
                assert_eq!(*ext_flags, 0xaabbccdd);
            }
            _ => panic!("expected ext select entry"),
        }

        match &ivhd_info.device_entries[5] {
            IvhdDeviceEntry::ExtRange {
                start,
                end,
                flags,
                ext_flags,
            } => {
                assert_eq!(*start, 0x0600);
                assert_eq!(*end, 0x0602);
                assert_eq!(*flags, 0x55);
                assert_eq!(*ext_flags, 0x11223344);
            }
            _ => panic!("expected ext range entry"),
        }
    }

    #[test]
    fn test_parse_ivrs_ivmd_range() {
        let ivmd = IvmdHeader {
            header: IvrsBlockHeader {
                block_type: IVMD_TYPE_RANGE,
                flags: IVMD_FLAG_UNITY_MAP | IVMD_FLAG_IR | IVMD_FLAG_IW,
                length: mem::size_of::<IvmdHeader>() as u16,
            },
            device_id: 0x0100,
            aux: 0x010f,
            pci_segment: 0,
            _reserved: [0; 6],
            range_start: 0x1000,
            range_length: 0x2000,
        };

        let ivrs_len = mem::size_of::<IvrsHeader>() + mem::size_of::<IvmdHeader>();
        let ivrs = IvrsHeader {
            header: AcpiSdtHeader {
                signature: *b"IVRS",
                length: ivrs_len as u32,
                revision: 1,
                checksum: 0,
                oem_id: [0; 6],
                oem_table_id: [0; 8],
                oem_revision: 0,
                creator_id: 0,
                creator_revision: 0,
            },
            info: 0,
            _reserved: 0,
        };

        let mut buf = Vec::new();
        let ivrs_bytes = unsafe {
            core::slice::from_raw_parts(
                &ivrs as *const IvrsHeader as *const u8,
                mem::size_of::<IvrsHeader>(),
            )
        };
        buf.extend_from_slice(ivrs_bytes);

        let ivmd_bytes = unsafe {
            core::slice::from_raw_parts(
                &ivmd as *const IvmdHeader as *const u8,
                mem::size_of::<IvmdHeader>(),
            )
        };
        buf.extend_from_slice(ivmd_bytes);

        let info = unsafe { parse_ivrs(buf.as_ptr() as usize) }.expect("parse should succeed");
        assert!(info.ivhds.is_empty());
        assert_eq!(info.ivmds.len(), 1);

        let ivmd_info = &info.ivmds[0];
        assert_eq!(ivmd_info.block_type, IVMD_TYPE_RANGE);
        assert_eq!(ivmd_info.flags, IVMD_FLAG_UNITY_MAP | IVMD_FLAG_IR | IVMD_FLAG_IW);
        assert_eq!(ivmd_info.device_id, 0x0100);
        assert_eq!(ivmd_info.aux, 0x010f);
        assert_eq!(ivmd_info.pci_segment, 0);
        assert_eq!(ivmd_info.range_start, 0x1000);
        assert_eq!(ivmd_info.range_length, 0x2000);
    }
}
