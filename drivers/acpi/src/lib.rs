#![allow(clippy::cargo_common_metadata)]
#![no_std]
#![allow(clippy::must_use_candidate)] // ACPI accessor methods
#![allow(clippy::doc_markdown)] // ACPI table names: RSDT, XSDT, FADT, MADT, MCFG etc

extern crate alloc;

pub mod dmar;
pub mod info;
pub mod ivrs;
pub mod parser;
pub mod tables;

// Re-export commonly used items
pub use info::{AcpiInfo, InterruptOverrideInfo, IoApicInfo, LocalApicInfo, PcieEcamInfo};
pub use parser::{
    AcpiParser, find_table_global, init, interrupt_overrides, io_apics, local_apic_address,
    local_apics, pcie_ecam_regions, processor_count, set_hhdm_offset,
};
pub use tables::{
    AcpiError, AcpiSdtHeader, Fadt, Madt, MadtEntryHeader, MadtEntryType, MadtInterruptOverride,
    MadtIoApic, MadtLocalApic, MadtLocalApicOverride, Mcfg, McfgEntry, RSDP_SIGNATURE, Rsdp,
    signature,
};
// DMAR parsing info
pub use dmar::DmarInfo;
pub use ivrs::{IvmdInfo, IvrsInfo};

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use alloc::vec::Vec;
    use core::mem;

    use crate::dmar::{DmarHeader, DmarRemappingHeader, RmrrWrapper, parse_dmar};
    use crate::ivrs::{
        IVHD_DEV_ALIAS, IVHD_DEV_ALIAS_RANGE, IVHD_DEV_EXT_SELECT, IVHD_DEV_EXT_SELECT_RANGE,
        IVHD_DEV_RANGE_END, IVHD_DEV_SELECT, IVHD_DEV_SELECT_RANGE_START, IVHD_TYPE_10,
        IVMD_TYPE_RANGE, IvhdDeviceEntry, IvhdHeader, IvmdHeader, IvrsBlockHeader, IvrsHeader,
        parse_ivrs,
    };
    use crate::tables::{AcpiSdtHeader, MadtEntryType};

    const IVMD_FLAG_UNITY_MAP: u8 = 0x01;
    const IVMD_FLAG_IR: u8 = 0x02;
    const IVMD_FLAG_IW: u8 = 0x04;

    pub const fn madt_entry_type_smoke() -> bool {
        MadtEntryType::LocalApic as u8 == 0 && MadtEntryType::IoApic as u8 == 1
    }

    fn push_entry(buf: &mut Vec<u8>, entry_type: u8, devid: u16, flags: u8, ext: Option<u32>) {
        buf.push(entry_type);
        buf.extend_from_slice(&devid.to_le_bytes());
        buf.push(flags);
        if let Some(ext) = ext {
            buf.extend_from_slice(&ext.to_le_bytes());
        }
    }

    #[allow(clippy::too_many_lines)]
    fn ivrs_parse_ivhd_smoke() -> bool {
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
            Some(0xaabb_ccdd),
        );
        push_entry(
            &mut entries,
            IVHD_DEV_EXT_SELECT_RANGE,
            0x0600,
            0x55,
            Some(0x1122_3344),
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
            iommu_base: 0xfee0_0000,
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
                (&raw const ivrs).cast::<u8>(),
                mem::size_of::<IvrsHeader>(),
            )
        };
        buf.extend_from_slice(ivrs_bytes);

        let ivhd_bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw const ivhd).cast::<u8>(),
                mem::size_of::<IvhdHeader>(),
            )
        };
        buf.extend_from_slice(ivhd_bytes);
        buf.extend_from_slice(&entries);

        let Ok(info) = (unsafe { parse_ivrs(buf.as_ptr() as usize) }) else {
            return false;
        };

        if info.ivhds.is_empty() {
            return false;
        }

        if info.ivhds.len() != 1 {
            return false;
        }
        if !info.ivmds.is_empty() {
            return false;
        }
        let ivhd_info = &info.ivhds[0];
        if ivhd_info.device_entries.len() != 6 {
            return false;
        }

        match &ivhd_info.device_entries[0] {
            IvhdDeviceEntry::Select { devid, flags } => {
                if *devid != 0x0102 || *flags != 0xaa {
                    return false;
                }
            }
            _ => return false,
        }

        match &ivhd_info.device_entries[1] {
            IvhdDeviceEntry::Range { start, end, flags } => {
                if *start != 0x0200 || *end != 0x0203 || *flags != 0x11 {
                    return false;
                }
            }
            _ => return false,
        }

        match &ivhd_info.device_entries[2] {
            IvhdDeviceEntry::Alias {
                devid,
                alias,
                flags,
            } => {
                if *devid != 0x0300 || *alias != 0x0310 || *flags != 0x22 {
                    return false;
                }
            }
            _ => return false,
        }

        match &ivhd_info.device_entries[3] {
            IvhdDeviceEntry::AliasRange {
                start,
                end,
                alias,
                flags,
            } => {
                if *start != 0x0400 || *end != 0x0402 || *alias != 0x0410 || *flags != 0x33 {
                    return false;
                }
            }
            _ => return false,
        }

        match &ivhd_info.device_entries[4] {
            IvhdDeviceEntry::ExtSelect {
                devid,
                flags,
                ext_flags,
            } => {
                if *devid != 0x0500 || *flags != 0x44 || *ext_flags != 0xaabb_ccdd {
                    return false;
                }
            }
            _ => return false,
        }

        match &ivhd_info.device_entries[5] {
            IvhdDeviceEntry::ExtRange {
                start,
                end,
                flags,
                ext_flags,
            } => {
                if *start != 0x0600 || *end != 0x0602 || *flags != 0x55 || *ext_flags != 0x1122_3344
                {
                    return false;
                }
            }
            _ => return false,
        }

        true
    }

    fn ivrs_parse_ivmd_smoke() -> bool {
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
                (&raw const ivrs).cast::<u8>(),
                mem::size_of::<IvrsHeader>(),
            )
        };
        buf.extend_from_slice(ivrs_bytes);

        let ivmd_bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw const ivmd).cast::<u8>(),
                mem::size_of::<IvmdHeader>(),
            )
        };
        buf.extend_from_slice(ivmd_bytes);

        let Ok(info) = (unsafe { parse_ivrs(buf.as_ptr() as usize) }) else {
            return false;
        };
        if info.ivmds.len() != 1 {
            return false;
        }

        let ivmd_info = &info.ivmds[0];
        ivmd_info.block_type == IVMD_TYPE_RANGE
            && ivmd_info.flags == (IVMD_FLAG_UNITY_MAP | IVMD_FLAG_IR | IVMD_FLAG_IW)
            && ivmd_info.device_id == 0x0100
            && ivmd_info.aux == 0x010f
            && ivmd_info.pci_segment == 0
            && ivmd_info.range_start == 0x1000
            && ivmd_info.range_length == 0x2000
    }

    fn dmar_parse_minimal_smoke() -> bool {
        let header = AcpiSdtHeader {
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

        let dmar = DmarHeader {
            header,
            haw: 0,
            flags: 0,
            _reserved: [0; 10],
        };

        let mut buf = Vec::new();
        let dmar_bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw const dmar).cast::<u8>(),
                mem::size_of::<DmarHeader>(),
            )
        };
        buf.extend_from_slice(dmar_bytes);

        let rmrr = RmrrWrapper {
            header: DmarRemappingHeader {
                type_code: 1,
                length: mem::size_of::<RmrrWrapper>() as u16,
            },
            _reserved: 0,
            segment: 0,
            base_address: 0x1000,
            limit_address: 0x1fff,
        };
        let rmrr_bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw const rmrr).cast::<u8>(),
                mem::size_of::<RmrrWrapper>(),
            )
        };
        buf.extend_from_slice(rmrr_bytes);

        // Patch length
        let total_len = buf.len() as u32;
        let len_bytes = total_len.to_le_bytes();
        buf[4..8].copy_from_slice(&len_bytes);

        let Ok(info) = (unsafe { parse_dmar(buf.as_ptr() as usize) }) else {
            return false;
        };

        info.rmrr_regions.len() == 1
            && info.drhd_units.is_empty()
            && info.rmrr_regions[0].base == 0x1000
    }
    #[test]
    fn madt_entry_type_smoke_test() {
        assert!(madt_entry_type_smoke());
    }

    #[test]
    fn ivrs_parse_ivhd_smoke_test() {
        assert!(ivrs_parse_ivhd_smoke());
    }

    #[test]
    fn ivrs_parse_ivmd_smoke_test() {
        assert!(ivrs_parse_ivmd_smoke());
    }

    #[test]
    fn dmar_parse_minimal_smoke_test() {
        assert!(dmar_parse_minimal_smoke());
    }
}
