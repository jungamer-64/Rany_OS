// ============================================================================
// src/io/acpi/parser.rs - ACPI Table Parser
// ============================================================================
//!
//! ACPI テーブルパーサー
//!
//! RSDP検索、RSDT/XSDTパース、MADT/MCFGパースを実装。

#![allow(dead_code)]

use alloc::vec::Vec;
use core::ptr;
use spin::Mutex;

use super::tables::*;
use super::info::*;

// ============================================================================
// ACPI Parser
// ============================================================================

/// ACPI table parser
pub struct AcpiParser {
    /// RSDP physical address
    rsdp_address: u64,
    /// Parsed info
    info: Option<AcpiInfo>,
}

impl AcpiParser {
    /// Create a new ACPI parser
    pub fn new(rsdp_address: u64) -> Self {
        AcpiParser {
            rsdp_address,
            info: None,
        }
    }

    /// Search for RSDP in BIOS memory regions
    ///
    /// # Safety
    /// This function reads from physical memory addresses
    pub unsafe fn find_rsdp() -> Option<u64> { unsafe {
        // Search in EBDA (Extended BIOS Data Area)
        let ebda_ptr = *(0x40E as *const u16) as u64;
        let ebda_start = ebda_ptr << 4;

        if let Some(addr) = Self::search_region(ebda_start, ebda_start + 1024) {
            return Some(addr);
        }

        // Search in BIOS ROM area (0xE0000 - 0xFFFFF)
        Self::search_region(0xE0000, 0x100000)
    }}

    /// Search for RSDP signature in a memory region
    unsafe fn search_region(start: u64, end: u64) -> Option<u64> { unsafe {
        let mut addr = start;
        while addr < end {
            let ptr = addr as *const [u8; 8];
            if &*ptr == RSDP_SIGNATURE {
                // Validate checksum
                let rsdp = &*(addr as *const Rsdp);
                if rsdp.validate() {
                    return Some(addr);
                }
            }
            addr += 16; // RSDP is always aligned to 16 bytes
        }
        None
    }}

    /// Parse ACPI tables
    ///
    /// # Safety
    /// This function reads from physical memory addresses
    pub unsafe fn parse(&mut self) -> Result<&AcpiInfo, AcpiError> { unsafe {
        let rsdp = &*(self.rsdp_address as *const Rsdp);

        if !rsdp.validate() {
            return Err(AcpiError::InvalidRsdpChecksum);
        }

        let mut info = AcpiInfo::new(rsdp.revision);

        // Get table addresses from XSDT (ACPI 2.0+) or RSDT (ACPI 1.0)
        let table_addresses = if rsdp.is_xsdt_available() {
            self.parse_xsdt(rsdp.xsdt_address)?
        } else {
            self.parse_rsdt(rsdp.rsdt_address as u64)?
        };

        // Parse individual tables
        for &table_addr in &table_addresses {
            let header = &*(table_addr as *const AcpiSdtHeader);

            if header.signature == signature::MADT {
                self.parse_madt(table_addr, &mut info)?;
            } else if header.signature == signature::MCFG {
                self.parse_mcfg(table_addr, &mut info)?;
            }
        }

        self.info = Some(info);
        // SAFETY: 直前で Some(info) を設定したため、unwrap は必ず成功する。
        Ok(unsafe { self.info.as_ref().unwrap_unchecked() })
    }}

    /// Parse RSDT (Root System Description Table)
    unsafe fn parse_rsdt(&self, rsdt_address: u64) -> Result<Vec<u64>, AcpiError> { unsafe {
        let header = &*(rsdt_address as *const AcpiSdtHeader);

        if header.signature != signature::RSDT {
            return Err(AcpiError::InvalidTable);
        }

        if !header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }

        let entry_count = (header.length as usize - core::mem::size_of::<AcpiSdtHeader>()) / 4;
        let entries_ptr =
            (rsdt_address as usize + core::mem::size_of::<AcpiSdtHeader>()) as *const u32;

        let mut addresses = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let addr = ptr::read_unaligned(entries_ptr.add(i));
            addresses.push(addr as u64);
        }

        Ok(addresses)
    }}

    /// Parse XSDT (Extended System Description Table)
    unsafe fn parse_xsdt(&self, xsdt_address: u64) -> Result<Vec<u64>, AcpiError> { unsafe {
        let header = &*(xsdt_address as *const AcpiSdtHeader);

        if header.signature != signature::XSDT {
            return Err(AcpiError::InvalidTable);
        }

        if !header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }

        let entry_count = (header.length as usize - core::mem::size_of::<AcpiSdtHeader>()) / 8;
        let entries_ptr =
            (xsdt_address as usize + core::mem::size_of::<AcpiSdtHeader>()) as *const u64;

        let mut addresses = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let addr = ptr::read_unaligned(entries_ptr.add(i));
            addresses.push(addr);
        }

        Ok(addresses)
    }}

    /// Parse MADT (Multiple APIC Description Table)
    unsafe fn parse_madt(&self, madt_address: u64, info: &mut AcpiInfo) -> Result<(), AcpiError> { unsafe {
        let madt = &*(madt_address as *const Madt);

        if !madt.header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }

        info.local_apic_address = madt.local_apic_address as u64;
        info.has_legacy_pics = madt.has_legacy_pics();

        // Parse MADT entries
        let entries_start = madt_address as usize + core::mem::size_of::<Madt>();
        let entries_end = madt_address as usize + madt.header.length as usize;

        let mut offset = entries_start;
        while offset < entries_end {
            let entry_header = &*(offset as *const MadtEntryHeader);

            match entry_header.entry_type {
                0 => {
                    // Local APIC
                    let entry = &*(offset as *const MadtLocalApic);
                    info.local_apics.push(LocalApicInfo {
                        processor_id: entry.processor_id,
                        apic_id: entry.apic_id,
                        enabled: entry.is_enabled(),
                        online_capable: entry.is_online_capable(),
                    });
                }
                1 => {
                    // I/O APIC
                    let entry = &*(offset as *const MadtIoApic);
                    info.io_apics.push(IoApicInfo {
                        id: entry.io_apic_id,
                        address: entry.io_apic_address as u64,
                        gsi_base: entry.gsi_base,
                    });
                }
                2 => {
                    // Interrupt Source Override
                    let entry = &*(offset as *const MadtInterruptOverride);
                    info.interrupt_overrides.push(InterruptOverrideInfo {
                        bus: entry.bus,
                        source: entry.source,
                        gsi: entry.gsi,
                        polarity: (entry.flags & 0x3) as u8,
                        trigger_mode: ((entry.flags >> 2) & 0x3) as u8,
                    });
                }
                5 => {
                    // Local APIC Address Override
                    let entry = &*(offset as *const MadtLocalApicOverride);
                    info.local_apic_address = entry.address;
                }
                _ => {}
            }

            offset += entry_header.length as usize;
            if entry_header.length == 0 {
                break; // Prevent infinite loop
            }
        }

        Ok(())
    }}

    /// Parse MCFG (Memory-mapped Configuration space)
    unsafe fn parse_mcfg(&self, mcfg_address: u64, info: &mut AcpiInfo) -> Result<(), AcpiError> { unsafe {
        let mcfg = &*(mcfg_address as *const Mcfg);

        if !mcfg.header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }

        // Parse MCFG entries
        let entries_start = mcfg_address as usize + core::mem::size_of::<Mcfg>();
        let entries_end = mcfg_address as usize + mcfg.header.length as usize;

        let entry_size = core::mem::size_of::<McfgEntry>();
        let mut offset = entries_start;

        while offset + entry_size <= entries_end {
            let entry = &*(offset as *const McfgEntry);
            info.pcie_ecam.push(PcieEcamInfo {
                base_address: entry.base_address,
                segment: entry.segment_group,
                start_bus: entry.start_bus,
                end_bus: entry.end_bus,
            });
            offset += entry_size;
        }

        Ok(())
    }}

    /// Get parsed ACPI info
    pub fn info(&self) -> Option<&AcpiInfo> {
        self.info.as_ref()
    }
}

// ============================================================================
// Global ACPI State
// ============================================================================

/// Global ACPI information
static ACPI_INFO: Mutex<Option<AcpiInfo>> = Mutex::new(None);

/// Initialize ACPI from RSDP address
///
/// # Safety
/// The rsdp_address must point to a valid RSDP structure
pub unsafe fn init(rsdp_address: u64) -> Result<(), AcpiError> { unsafe {
    let mut parser = AcpiParser::new(rsdp_address);
    let info = parser.parse()?;
    *ACPI_INFO.lock() = Some(info.clone());
    Ok(())
}}

/// Get local APIC address
pub fn local_apic_address() -> Option<u64> {
    ACPI_INFO.lock().as_ref().map(|i| i.local_apic_address)
}

/// Get list of processor local APICs
pub fn local_apics() -> Vec<LocalApicInfo> {
    ACPI_INFO
        .lock()
        .as_ref()
        .map(|i| i.local_apics.clone())
        .unwrap_or_default()
}

/// Get list of I/O APICs
pub fn io_apics() -> Vec<IoApicInfo> {
    ACPI_INFO
        .lock()
        .as_ref()
        .map(|i| i.io_apics.clone())
        .unwrap_or_default()
}

/// Get interrupt overrides
pub fn interrupt_overrides() -> Vec<InterruptOverrideInfo> {
    ACPI_INFO
        .lock()
        .as_ref()
        .map(|i| i.interrupt_overrides.clone())
        .unwrap_or_default()
}

/// Get PCIe ECAM regions
pub fn pcie_ecam_regions() -> Vec<PcieEcamInfo> {
    ACPI_INFO
        .lock()
        .as_ref()
        .map(|i| i.pcie_ecam.clone())
        .unwrap_or_default()
}

/// Get number of processors
pub fn processor_count() -> usize {
    ACPI_INFO
        .lock()
        .as_ref()
        .map(|i| i.local_apics.iter().filter(|a| a.enabled).count())
        .unwrap_or(1)
}
