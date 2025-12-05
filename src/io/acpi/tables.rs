// ============================================================================
// src/io/acpi/tables.rs - ACPI Table Structures
// ============================================================================
//!
//! ACPI テーブル構造体定義
//!
//! RSDP, SDT Header, MADT, MCFG, FADTなどのテーブル構造体を定義。

#![allow(dead_code)]

use core::slice;
use core::str;

// ============================================================================
// Constants and Signatures
// ============================================================================

/// RSDP signature "RSD PTR "
pub const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// ACPI table signatures
pub mod signature {
    pub const RSDT: [u8; 4] = *b"RSDT";
    pub const XSDT: [u8; 4] = *b"XSDT";
    pub const MADT: [u8; 4] = *b"APIC";
    pub const FADT: [u8; 4] = *b"FACP";
    pub const MCFG: [u8; 4] = *b"MCFG";
    pub const HPET: [u8; 4] = *b"HPET";
    pub const SRAT: [u8; 4] = *b"SRAT";
    pub const SLIT: [u8; 4] = *b"SLIT";
    pub const BGRT: [u8; 4] = *b"BGRT";
    pub const DMAR: [u8; 4] = *b"DMAR";
}

// ============================================================================
// Error Types
// ============================================================================

/// ACPI error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// RSDP not found
    RsdpNotFound,
    /// Invalid RSDP checksum
    InvalidRsdpChecksum,
    /// Invalid table checksum
    InvalidTableChecksum,
    /// Table not found
    TableNotFound,
    /// Invalid table structure
    InvalidTable,
    /// Unsupported ACPI version
    UnsupportedVersion,
}

// ============================================================================
// RSDP - Root System Description Pointer
// ============================================================================

/// Root System Description Pointer (RSDP) structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Rsdp {
    /// "RSD PTR " signature
    pub signature: [u8; 8],
    /// Checksum for first 20 bytes
    pub checksum: u8,
    /// OEM ID
    pub oem_id: [u8; 6],
    /// Revision (0 = ACPI 1.0, 2 = ACPI 2.0+)
    pub revision: u8,
    /// Physical address of RSDT
    pub rsdt_address: u32,
    // Extended fields (ACPI 2.0+)
    /// Length of entire RSDP structure
    pub length: u32,
    /// Physical address of XSDT
    pub xsdt_address: u64,
    /// Extended checksum
    pub extended_checksum: u8,
    /// Reserved
    pub reserved: [u8; 3],
}

impl Rsdp {
    /// Validate the RSDP checksum
    pub fn validate(&self) -> bool {
        let bytes = unsafe { slice::from_raw_parts(self as *const _ as *const u8, 20) };
        let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }

    /// Validate extended checksum (ACPI 2.0+)
    pub fn validate_extended(&self) -> bool {
        if self.revision < 2 {
            return true;
        }
        let bytes =
            unsafe { slice::from_raw_parts(self as *const _ as *const u8, self.length as usize) };
        let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }

    /// Check if ACPI 2.0 or later
    pub fn is_xsdt_available(&self) -> bool {
        self.revision >= 2 && self.xsdt_address != 0
    }
}

// ============================================================================
// SDT Header - System Description Table Header
// ============================================================================

/// ACPI System Description Table Header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AcpiSdtHeader {
    /// Table signature
    pub signature: [u8; 4],
    /// Length of entire table
    pub length: u32,
    /// Revision
    pub revision: u8,
    /// Checksum (all bytes must sum to 0)
    pub checksum: u8,
    /// OEM ID
    pub oem_id: [u8; 6],
    /// OEM table ID
    pub oem_table_id: [u8; 8],
    /// OEM revision
    pub oem_revision: u32,
    /// Creator ID
    pub creator_id: u32,
    /// Creator revision
    pub creator_revision: u32,
}

impl AcpiSdtHeader {
    /// Get signature as string
    pub fn signature_str(&self) -> &str {
        str::from_utf8(&self.signature).unwrap_or("????")
    }

    /// Validate table checksum
    pub fn validate(&self) -> bool {
        let bytes =
            unsafe { slice::from_raw_parts(self as *const _ as *const u8, self.length as usize) };
        let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }
}

// ============================================================================
// MADT - Multiple APIC Description Table
// ============================================================================

/// Multiple APIC Description Table (MADT) entry types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MadtEntryType {
    /// Processor Local APIC
    LocalApic = 0,
    /// I/O APIC
    IoApic = 1,
    /// Interrupt Source Override
    InterruptSourceOverride = 2,
    /// Non-maskable Interrupt Source
    NmiSource = 3,
    /// Local APIC NMI
    LocalApicNmi = 4,
    /// Local APIC Address Override
    LocalApicAddressOverride = 5,
    /// Processor Local x2APIC
    LocalX2Apic = 9,
}

/// MADT entry header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtEntryHeader {
    /// Entry type
    pub entry_type: u8,
    /// Entry length
    pub length: u8,
}

/// MADT Local APIC entry (type 0)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApic {
    pub header: MadtEntryHeader,
    /// ACPI Processor ID
    pub processor_id: u8,
    /// Local APIC ID
    pub apic_id: u8,
    /// Flags (bit 0 = enabled, bit 1 = online capable)
    pub flags: u32,
}

impl MadtLocalApic {
    /// Check if processor is enabled
    pub fn is_enabled(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Check if processor is online capable
    pub fn is_online_capable(&self) -> bool {
        self.flags & 2 != 0
    }
}

/// MADT I/O APIC entry (type 1)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtIoApic {
    pub header: MadtEntryHeader,
    /// I/O APIC ID
    pub io_apic_id: u8,
    /// Reserved
    pub reserved: u8,
    /// I/O APIC Address
    pub io_apic_address: u32,
    /// Global System Interrupt Base
    pub gsi_base: u32,
}

/// MADT Interrupt Source Override entry (type 2)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtInterruptOverride {
    pub header: MadtEntryHeader,
    /// Bus (always 0 for ISA)
    pub bus: u8,
    /// Source IRQ
    pub source: u8,
    /// Global System Interrupt
    pub gsi: u32,
    /// Flags
    pub flags: u16,
}

/// MADT Local APIC Address Override entry (type 5)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApicOverride {
    pub header: MadtEntryHeader,
    pub reserved: u16,
    pub address: u64,
}

/// MADT structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Madt {
    pub header: AcpiSdtHeader,
    /// Local APIC address
    pub local_apic_address: u32,
    /// Flags (bit 0 = PCAT_COMPAT - dual 8259 PICs installed)
    pub flags: u32,
}

impl Madt {
    /// Check if system has legacy 8259 PICs
    pub fn has_legacy_pics(&self) -> bool {
        self.flags & 1 != 0
    }
}

// ============================================================================
// MCFG - Memory-mapped Configuration Space
// ============================================================================

/// MCFG entry (PCI Express Enhanced Configuration)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct McfgEntry {
    /// Base address of enhanced configuration mechanism
    pub base_address: u64,
    /// PCI Segment Group Number
    pub segment_group: u16,
    /// Start PCI bus number
    pub start_bus: u8,
    /// End PCI bus number
    pub end_bus: u8,
    /// Reserved
    pub reserved: u32,
}

/// MCFG table structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Mcfg {
    pub header: AcpiSdtHeader,
    /// Reserved
    pub reserved: u64,
}

// ============================================================================
// FADT - Fixed ACPI Description Table
// ============================================================================

/// Fixed ACPI Description Table (FADT)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Fadt {
    pub header: AcpiSdtHeader,
    /// Physical address of FACS
    pub firmware_ctrl: u32,
    /// Physical address of DSDT
    pub dsdt: u32,
    /// Reserved in ACPI 2.0+
    pub reserved1: u8,
    /// Preferred power management profile
    pub preferred_pm_profile: u8,
    /// System Control Interrupt
    pub sci_int: u16,
    /// SMI Command Port
    pub smi_cmd: u32,
    /// ACPI Enable value
    pub acpi_enable: u8,
    /// ACPI Disable value
    pub acpi_disable: u8,
    /// S4BIOS Request value
    pub s4bios_req: u8,
    /// PSTATE Control
    pub pstate_cnt: u8,
    /// PM1a Event Block
    pub pm1a_evt_blk: u32,
    /// PM1b Event Block
    pub pm1b_evt_blk: u32,
    /// PM1a Control Block
    pub pm1a_cnt_blk: u32,
    /// PM1b Control Block
    pub pm1b_cnt_blk: u32,
    /// PM2 Control Block
    pub pm2_cnt_blk: u32,
    /// PM Timer Block
    pub pm_tmr_blk: u32,
    /// GPE0 Block
    pub gpe0_blk: u32,
    /// GPE1 Block
    pub gpe1_blk: u32,
    /// PM1 Event Length
    pub pm1_evt_len: u8,
    /// PM1 Control Length
    pub pm1_cnt_len: u8,
    /// PM2 Control Length
    pub pm2_cnt_len: u8,
    /// PM Timer Length
    pub pm_tmr_len: u8,
    /// GPE0 Block Length
    pub gpe0_blk_len: u8,
    /// GPE1 Block Length
    pub gpe1_blk_len: u8,
    /// GPE1 Base
    pub gpe1_base: u8,
    /// C-State Control
    pub cst_cnt: u8,
    /// P_LVL2 Latency
    pub p_lvl2_lat: u16,
    /// P_LVL3 Latency
    pub p_lvl3_lat: u16,
    /// Flush Size
    pub flush_size: u16,
    /// Flush Stride
    pub flush_stride: u16,
    /// Duty Cycle Offset
    pub duty_offset: u8,
    /// Duty Cycle Width
    pub duty_width: u8,
    /// Day Alarm Index
    pub day_alrm: u8,
    /// Month Alarm Index
    pub mon_alrm: u8,
    /// Century Index
    pub century: u8,
    /// Boot Architecture Flags (ACPI 2.0+)
    pub iapc_boot_arch: u16,
    /// Reserved
    pub reserved2: u8,
    /// Fixed feature flags
    pub flags: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_madt_entry_type() {
        assert_eq!(MadtEntryType::LocalApic as u8, 0);
        assert_eq!(MadtEntryType::IoApic as u8, 1);
    }
}
