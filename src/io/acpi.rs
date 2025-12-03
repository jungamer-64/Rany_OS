//! ACPI Table Parser for ExoRust
//!
//! This module implements parsing of ACPI tables for system configuration
//! discovery (MADT, MCFG, FADT, etc.)

use core::ptr;
use core::slice;
use core::str;
use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;

extern crate alloc;

/// RSDP signature "RSD PTR "
const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

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
        let bytes = unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, 20)
        };
        let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }
    
    /// Validate extended checksum (ACPI 2.0+)
    pub fn validate_extended(&self) -> bool {
        if self.revision < 2 {
            return true;
        }
        let bytes = unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, self.length as usize)
        };
        let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }
    
    /// Check if ACPI 2.0 or later
    pub fn is_xsdt_available(&self) -> bool {
        self.revision >= 2 && self.xsdt_address != 0
    }
}

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
        let bytes = unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, self.length as usize)
        };
        let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }
}

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
    /// Local x2APIC NMI
    LocalX2ApicNmi = 10,
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

/// Processor Local APIC entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApic {
    pub header: MadtEntryHeader,
    /// ACPI processor UID
    pub processor_id: u8,
    /// Local APIC ID
    pub apic_id: u8,
    /// Flags (bit 0: enabled, bit 1: online capable)
    pub flags: u32,
}

impl MadtLocalApic {
    /// Check if processor is enabled
    pub fn is_enabled(&self) -> bool {
        (self.flags & 1) != 0
    }
    
    /// Check if processor is online capable
    pub fn is_online_capable(&self) -> bool {
        (self.flags & 2) != 0
    }
}

/// I/O APIC entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtIoApic {
    pub header: MadtEntryHeader,
    /// I/O APIC ID
    pub io_apic_id: u8,
    /// Reserved
    pub reserved: u8,
    /// I/O APIC address
    pub io_apic_address: u32,
    /// Global System Interrupt Base
    pub gsi_base: u32,
}

/// Interrupt Source Override entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtInterruptOverride {
    pub header: MadtEntryHeader,
    /// Bus source (0 = ISA)
    pub bus: u8,
    /// Source IRQ
    pub source: u8,
    /// Global System Interrupt
    pub gsi: u32,
    /// Flags
    pub flags: u16,
}

/// MADT table
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Madt {
    pub header: AcpiSdtHeader,
    /// Local APIC address
    pub local_apic_address: u32,
    /// Flags
    pub flags: u32,
    // Followed by MADT entries
}

impl Madt {
    /// Check if legacy PICs are present
    pub fn has_legacy_pics(&self) -> bool {
        (self.flags & 1) != 0
    }
}

/// PCI Express Enhanced Configuration Mechanism entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct McfgEntry {
    /// Base address of enhanced configuration space
    pub base_address: u64,
    /// PCI segment group number
    pub segment_group: u16,
    /// Start PCI bus number
    pub start_bus: u8,
    /// End PCI bus number
    pub end_bus: u8,
    /// Reserved
    pub reserved: u32,
}

/// MCFG table
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Mcfg {
    pub header: AcpiSdtHeader,
    /// Reserved
    pub reserved: u64,
    // Followed by MCFG entries
}

/// Fixed ACPI Description Table (FADT)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Fadt {
    pub header: AcpiSdtHeader,
    /// Physical address of FACS
    pub firmware_ctrl: u32,
    /// Physical address of DSDT
    pub dsdt: u32,
    /// Reserved (ACPI 1.0)
    pub reserved: u8,
    /// Preferred PM profile
    pub preferred_pm_profile: u8,
    /// SCI interrupt
    pub sci_interrupt: u16,
    /// SMI command port
    pub smi_command: u32,
    /// ACPI enable value
    pub acpi_enable: u8,
    /// ACPI disable value
    pub acpi_disable: u8,
    /// S4BIOS request value
    pub s4bios_req: u8,
    /// P-state control
    pub pstate_control: u8,
    /// PM1a event block address
    pub pm1a_event_block: u32,
    /// PM1b event block address
    pub pm1b_event_block: u32,
    /// PM1a control block address
    pub pm1a_control_block: u32,
    /// PM1b control block address
    pub pm1b_control_block: u32,
    /// PM2 control block address
    pub pm2_control_block: u32,
    /// PM timer block address
    pub pm_timer_block: u32,
    /// GPE0 block address
    pub gpe0_block: u32,
    /// GPE1 block address
    pub gpe1_block: u32,
    /// PM1 event length
    pub pm1_event_length: u8,
    /// PM1 control length
    pub pm1_control_length: u8,
    /// PM2 control length
    pub pm2_control_length: u8,
    /// PM timer length
    pub pm_timer_length: u8,
    /// GPE0 block length
    pub gpe0_block_length: u8,
    /// GPE1 block length
    pub gpe1_block_length: u8,
    /// GPE1 base
    pub gpe1_base: u8,
    /// C-state control
    pub cstate_control: u8,
    /// Worst case C2 latency
    pub worst_c2_latency: u16,
    /// Worst case C3 latency
    pub worst_c3_latency: u16,
    /// Flush size
    pub flush_size: u16,
    /// Flush stride
    pub flush_stride: u16,
    /// Duty cycle offset
    pub duty_offset: u8,
    /// Duty cycle width
    pub duty_width: u8,
    /// Day alarm
    pub day_alarm: u8,
    /// Month alarm
    pub month_alarm: u8,
    /// Century
    pub century: u8,
    /// Boot architecture flags (ACPI 2.0+)
    pub boot_architecture_flags: u16,
    /// Reserved2
    pub reserved2: u8,
    /// Flags
    pub flags: u32,
    // Extended fields follow (ACPI 2.0+)
}

/// Parsed ACPI information
#[derive(Debug, Clone)]
pub struct AcpiInfo {
    /// Local APIC address
    pub local_apic_address: u64,
    /// List of processor local APICs
    pub local_apics: Vec<LocalApicInfo>,
    /// List of I/O APICs
    pub io_apics: Vec<IoApicInfo>,
    /// List of interrupt overrides
    pub interrupt_overrides: Vec<InterruptOverrideInfo>,
    /// PCIe ECAM base addresses
    pub pcie_ecam: Vec<PcieEcamInfo>,
    /// Has legacy PICs
    pub has_legacy_pics: bool,
    /// ACPI revision
    pub revision: u8,
}

/// Local APIC information
#[derive(Debug, Clone, Copy)]
pub struct LocalApicInfo {
    /// Processor ID
    pub processor_id: u8,
    /// APIC ID
    pub apic_id: u8,
    /// Is enabled
    pub enabled: bool,
    /// Is online capable
    pub online_capable: bool,
}

/// I/O APIC information
#[derive(Debug, Clone, Copy)]
pub struct IoApicInfo {
    /// I/O APIC ID
    pub id: u8,
    /// Base address
    pub address: u64,
    /// Global System Interrupt base
    pub gsi_base: u32,
}

/// Interrupt override information
#[derive(Debug, Clone, Copy)]
pub struct InterruptOverrideInfo {
    /// Bus (0 = ISA)
    pub bus: u8,
    /// Source IRQ
    pub source: u8,
    /// Global System Interrupt
    pub gsi: u32,
    /// Polarity (0 = conform, 1 = high, 3 = low)
    pub polarity: u8,
    /// Trigger mode (0 = conform, 1 = edge, 3 = level)
    pub trigger_mode: u8,
}

/// PCIe ECAM information
#[derive(Debug, Clone, Copy)]
pub struct PcieEcamInfo {
    /// ECAM base address
    pub base_address: u64,
    /// PCI segment group
    pub segment: u16,
    /// Start bus number
    pub start_bus: u8,
    /// End bus number
    pub end_bus: u8,
}

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
    pub unsafe fn find_rsdp() -> Option<u64> {
        // Search in EBDA (Extended BIOS Data Area)
        let ebda_ptr = *(0x40E as *const u16) as u64;
        let ebda_start = ebda_ptr << 4;
        
        if let Some(addr) = Self::search_region(ebda_start, ebda_start + 1024) {
            return Some(addr);
        }
        
        // Search in BIOS ROM area (0xE0000 - 0xFFFFF)
        Self::search_region(0xE0000, 0x100000)
    }
    
    /// Search for RSDP signature in a memory region
    unsafe fn search_region(start: u64, end: u64) -> Option<u64> {
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
    }
    
    /// Parse ACPI tables
    /// 
    /// # Safety
    /// This function reads from physical memory addresses
    pub unsafe fn parse(&mut self) -> Result<&AcpiInfo, AcpiError> {
        let rsdp = &*(self.rsdp_address as *const Rsdp);
        
        if !rsdp.validate() {
            return Err(AcpiError::InvalidRsdpChecksum);
        }
        
        let mut info = AcpiInfo {
            local_apic_address: 0,
            local_apics: Vec::new(),
            io_apics: Vec::new(),
            interrupt_overrides: Vec::new(),
            pcie_ecam: Vec::new(),
            has_legacy_pics: false,
            revision: rsdp.revision,
        };
        
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
        // unwrap_unchecked() でパニックコード生成を回避。
        Ok(unsafe { self.info.as_ref().unwrap_unchecked() })
    }
    
    /// Parse RSDT (Root System Description Table)
    unsafe fn parse_rsdt(&self, rsdt_address: u64) -> Result<Vec<u64>, AcpiError> {
        let header = &*(rsdt_address as *const AcpiSdtHeader);
        
        if header.signature != signature::RSDT {
            return Err(AcpiError::InvalidTable);
        }
        
        if !header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }
        
        let entry_count = (header.length as usize - core::mem::size_of::<AcpiSdtHeader>()) / 4;
        let entries_ptr = (rsdt_address as usize + core::mem::size_of::<AcpiSdtHeader>()) as *const u32;
        
        let mut addresses = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let addr = ptr::read_unaligned(entries_ptr.add(i));
            addresses.push(addr as u64);
        }
        
        Ok(addresses)
    }
    
    /// Parse XSDT (Extended System Description Table)
    unsafe fn parse_xsdt(&self, xsdt_address: u64) -> Result<Vec<u64>, AcpiError> {
        let header = &*(xsdt_address as *const AcpiSdtHeader);
        
        if header.signature != signature::XSDT {
            return Err(AcpiError::InvalidTable);
        }
        
        if !header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }
        
        let entry_count = (header.length as usize - core::mem::size_of::<AcpiSdtHeader>()) / 8;
        let entries_ptr = (xsdt_address as usize + core::mem::size_of::<AcpiSdtHeader>()) as *const u64;
        
        let mut addresses = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let addr = ptr::read_unaligned(entries_ptr.add(i));
            addresses.push(addr);
        }
        
        Ok(addresses)
    }
    
    /// Parse MADT (Multiple APIC Description Table)
    unsafe fn parse_madt(&self, madt_address: u64, info: &mut AcpiInfo) -> Result<(), AcpiError> {
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
                    #[repr(C, packed)]
                    struct LocalApicOverride {
                        header: MadtEntryHeader,
                        reserved: u16,
                        address: u64,
                    }
                    let entry = &*(offset as *const LocalApicOverride);
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
    }
    
    /// Parse MCFG (Memory-mapped Configuration space)
    unsafe fn parse_mcfg(&self, mcfg_address: u64, info: &mut AcpiInfo) -> Result<(), AcpiError> {
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
    }
    
    /// Get parsed ACPI info
    pub fn info(&self) -> Option<&AcpiInfo> {
        self.info.as_ref()
    }
}

/// Global ACPI information
static ACPI_INFO: Mutex<Option<AcpiInfo>> = Mutex::new(None);

/// Initialize ACPI from RSDP address
/// 
/// # Safety
/// The rsdp_address must point to a valid RSDP structure
pub unsafe fn init(rsdp_address: u64) -> Result<(), AcpiError> {
    let mut parser = AcpiParser::new(rsdp_address);
    let info = parser.parse()?;
    *ACPI_INFO.lock() = Some(info.clone());
    Ok(())
}

/// Get local APIC address
pub fn local_apic_address() -> Option<u64> {
    ACPI_INFO.lock().as_ref().map(|i| i.local_apic_address)
}

/// Get list of processor local APICs
pub fn local_apics() -> Vec<LocalApicInfo> {
    ACPI_INFO.lock()
        .as_ref()
        .map(|i| i.local_apics.clone())
        .unwrap_or_default()
}

/// Get list of I/O APICs
pub fn io_apics() -> Vec<IoApicInfo> {
    ACPI_INFO.lock()
        .as_ref()
        .map(|i| i.io_apics.clone())
        .unwrap_or_default()
}

/// Get interrupt overrides
pub fn interrupt_overrides() -> Vec<InterruptOverrideInfo> {
    ACPI_INFO.lock()
        .as_ref()
        .map(|i| i.interrupt_overrides.clone())
        .unwrap_or_default()
}

/// Get PCIe ECAM regions
pub fn pcie_ecam_regions() -> Vec<PcieEcamInfo> {
    ACPI_INFO.lock()
        .as_ref()
        .map(|i| i.pcie_ecam.clone())
        .unwrap_or_default()
}

/// Get number of processors
pub fn processor_count() -> usize {
    ACPI_INFO.lock()
        .as_ref()
        .map(|i| i.local_apics.iter().filter(|a| a.enabled).count())
        .unwrap_or(1)
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
