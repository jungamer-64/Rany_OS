// ============================================================================
// src/io/acpi/parser.rs - ACPI Table Parser
// ============================================================================
//!
//! ACPI テーブルパーサー
//!
//! `RSDP`検索、`RSDT`/`XSDT`パース、`MADT`/`MCFG`パースを実装。

// Allow common patterns in ACPI parsing code
#![allow(dead_code)]
#![allow(clippy::cast_possible_truncation)] // u64->usize: intentional for 64-bit kernel
#![allow(clippy::cast_lossless)] // u32->u64 for address calculations
#![allow(clippy::unused_self)] // ACPI table methods need &self for API consistency
#![allow(clippy::ptr_as_ptr)] // Raw pointer casts in ACPI table parsing
#![allow(clippy::unnecessary_cast)] // Sometimes needed for clarity in ACPI code
#![allow(clippy::missing_panics_doc)] // Internal implementation
#![allow(clippy::missing_errors_doc)] // Internal implementation
#![allow(clippy::missing_const_for_fn)] // Many functions can't be const due to pointer operations
#![allow(clippy::map_unwrap_or)] // Kept for readability
#![allow(clippy::use_self)] // Explicit type names for clarity in ACPI parsing
#![allow(clippy::must_use_candidate)] // Parser internal methods

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::info::{AcpiInfo, InterruptOverrideInfo, IoApicInfo, LocalApicInfo, PcieEcamInfo};
use super::tables::{
    AcpiError, AcpiSdtHeader, Madt, MadtEntryHeader, MadtInterruptOverride, MadtIoApic,
    MadtLocalApic, MadtLocalApicOverride, Mcfg, McfgEntry, Rsdp, signature,
};

// ============================================================================
// HHDM (Higher Half Direct Map) Configuration
// ============================================================================

/// Physical memory offset for HHDM translation.
/// Must be set before parsing ACPI tables.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Set the HHDM offset for physical-to-virtual translation.
/// This must be called before `init()` if the kernel uses HHDM.
pub fn set_hhdm_offset(offset: u64) {
    HHDM_OFFSET.store(offset, Ordering::SeqCst);
}

/// Convert a physical address to virtual address using HHDM offset.
#[inline]
fn phys_to_virt(phys: u64) -> u64 {
    let offset = HHDM_OFFSET.load(Ordering::Relaxed);
    if offset == 0 {
        // No HHDM configured, assume identity mapping
        phys
    } else {
        phys + offset
    }
}

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
    pub const fn new(rsdp_address: u64) -> Self {
        AcpiParser {
            rsdp_address,
            info: None,
        }
    }

    /// Parse ACPI tables
    ///
    /// # Safety
    /// This function reads from physical memory addresses
    pub unsafe fn parse(&mut self) -> Result<&AcpiInfo, AcpiError> {
        let rsdp = unsafe { &*(self.rsdp_address as *const Rsdp) };

        if !rsdp.validate() {
            return Err(AcpiError::InvalidRsdpChecksum);
        }

        let mut info = AcpiInfo::new(rsdp.revision);

        // Get table addresses from XSDT (ACPI 2.0+) or RSDT (ACPI 1.0)
        let table_addresses = if rsdp.is_xsdt_available() {
            unsafe { self.parse_xsdt(phys_to_virt(rsdp.xsdt_address))? }
        } else {
            unsafe { self.parse_rsdt(phys_to_virt(rsdp.rsdt_address as u64))? }
        };

        for &table_addr in &table_addresses {
            unsafe { self.dispatch_table(table_addr, &mut info)? };
        }

        self.info = Some(info);
        // 直前で Some(info) を設定したため、unwrap は必ず成功する。
        Ok(self.info.as_ref().unwrap())
    }

    /// Dispatch a single ACPI table to its appropriate parser.
    ///
    /// # Safety
    /// Caller must ensure `table_addr` points to a valid ACPI SDT header.
    unsafe fn dispatch_table(&mut self, table_addr: u64, info: &mut AcpiInfo) -> Result<(), AcpiError> {
        let header = unsafe { &*(table_addr as *const AcpiSdtHeader) };
        if header.signature == signature::MADT {
            unsafe { self.parse_madt(table_addr, info)? };
        } else if header.signature == signature::MCFG {
            unsafe { self.parse_mcfg(table_addr, info)? };
        } else if header.signature == signature::SRAT {
            unsafe { self.parse_srat(table_addr, info)? };
        }
        Ok(())
    }

    /// Parse RSDT (Root System Description Table)
    unsafe fn parse_rsdt(&self, rsdt_address: u64) -> Result<Vec<u64>, AcpiError> {
        let header = unsafe { &*(rsdt_address as *const AcpiSdtHeader) };

        if header.signature != signature::RSDT {
            return Err(AcpiError::InvalidTable);
        }

        if !header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }

        let entry_count = (header.length as usize - core::mem::size_of::<AcpiSdtHeader>()) / 4;

        // Removed unnecessary unsafe block around pointer arithmetic
        let entries_ptr =
            (rsdt_address as usize + core::mem::size_of::<AcpiSdtHeader>()) as *const u32;

        let mut addresses = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let phys_addr = unsafe { core::ptr::read_unaligned(entries_ptr.add(i) as *const u32) };
            // Convert physical table address to virtual
            addresses.push(phys_to_virt(phys_addr as u64));
        }

        Ok(addresses)
    }

    /// Parse XSDT (Extended System Description Table)
    unsafe fn parse_xsdt(&self, xsdt_address: u64) -> Result<Vec<u64>, AcpiError> {
        let header = unsafe { &*(xsdt_address as *const AcpiSdtHeader) };

        if header.signature != signature::XSDT {
            return Err(AcpiError::InvalidTable);
        }

        if !header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }

        let entry_count = (header.length as usize - core::mem::size_of::<AcpiSdtHeader>()) / 8;

        // Removed unnecessary unsafe block
        let entries_ptr =
            (xsdt_address as usize + core::mem::size_of::<AcpiSdtHeader>()) as *const u64;

        let mut addresses = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let phys_addr = unsafe { core::ptr::read_unaligned(entries_ptr.add(i) as *const u64) };
            // Convert physical table address to virtual
            addresses.push(phys_to_virt(phys_addr));
        }

        Ok(addresses)
    }

    /// Parse MADT (Multiple APIC Description Table)
    unsafe fn parse_madt(&self, madt_address: u64, info: &mut AcpiInfo) -> Result<(), AcpiError> {
        let madt = unsafe { &*(madt_address as *const Madt) };

        if !madt.header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }

        info.local_apic_address = madt.local_apic_address as u64;
        info.has_legacy_pics = madt.has_legacy_pics();

        // Parse MADT entries
        // Removed unnecessary unsafe block
        let entries_start = madt_address as usize + core::mem::size_of::<Madt>();
        let entries_end = madt_address as usize + madt.header.length as usize;

        let mut offset = entries_start;
        while offset < entries_end {
            let entry_header = unsafe { &*(offset as *const MadtEntryHeader) };

            match entry_header.entry_type {
                0 => {
                    // Local APIC
                    let entry = unsafe { &*(offset as *const MadtLocalApic) };
                    info.local_apics.push(LocalApicInfo {
                        processor_id: entry.processor_id,
                        apic_id: entry.apic_id,
                        enabled: entry.is_enabled(),
                        online_capable: entry.is_online_capable(),
                    });
                }
                1 => {
                    // I/O APIC
                    let entry = unsafe { &*(offset as *const MadtIoApic) };
                    info.io_apics.push(IoApicInfo {
                        id: entry.io_apic_id,
                        address: entry.io_apic_address as u64,
                        gsi_base: entry.gsi_base,
                    });
                }
                2 => {
                    // Interrupt Source Override
                    let entry = unsafe { &*(offset as *const MadtInterruptOverride) };
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
                    let entry = unsafe { &*(offset as *const MadtLocalApicOverride) };
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
        let mcfg = unsafe { &*(mcfg_address as *const Mcfg) };

        if !mcfg.header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }

        // Parse MCFG entries
        // Removed unnecessary unsafe block
        let entries_start = mcfg_address as usize + core::mem::size_of::<Mcfg>();
        let entries_end = mcfg_address as usize + mcfg.header.length as usize;

        let entry_size = core::mem::size_of::<McfgEntry>();
        let mut offset = entries_start;

        while offset + entry_size <= entries_end {
            let entry = unsafe { &*(offset as *const McfgEntry) };
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

    /// Parse a Processor Local APIC/SAPIC Affinity entry from SRAT.
    unsafe fn parse_srat_processor_affinity(
        offset: usize,
        entry_len: usize,
        info: &mut AcpiInfo,
    ) {
        let apic_id = unsafe { core::ptr::read((offset + 3) as *const u8) };
        let proximity = if entry_len >= 8 {
            unsafe { core::ptr::read_unaligned((offset + 4) as *const u32) }
        } else if entry_len >= 3 {
            (unsafe { core::ptr::read((offset + 2) as *const u8) }) as u32
        } else {
            0u32
        };
        info.cpu_proximity.push((apic_id, proximity));
    }

    /// Parse a Memory Affinity entry from SRAT.
    unsafe fn parse_srat_memory_affinity(
        offset: usize,
        entry_len: usize,
        info: &mut AcpiInfo,
    ) {
        if entry_len < 24 {
            return;
        }
        let proximity =
            unsafe { core::ptr::read_unaligned((offset + 2) as *const u32) };
        if entry_len < 24 + 8 {
            return;
        }
        let base =
            unsafe { core::ptr::read_unaligned((offset + 8) as *const u64) };
        let length =
            unsafe { core::ptr::read_unaligned((offset + 16) as *const u64) };
        let flags = if entry_len >= 28 {
            unsafe { core::ptr::read_unaligned((offset + 24) as *const u32) }
        } else {
            1u32
        };
        if flags & 0x1 != 0 {
            info.numa_memory.push((base, length, proximity));
        }
    }

    /// Parse SRAT (System Resource Affinity Table) for NUMA topology
    unsafe fn parse_srat(&self, srat_address: u64, info: &mut AcpiInfo) -> Result<(), AcpiError> {
        let header = unsafe { &*(srat_address as *const AcpiSdtHeader) };

        if !header.validate() {
            return Err(AcpiError::InvalidTableChecksum);
        }

        let entries_start = srat_address as usize + core::mem::size_of::<AcpiSdtHeader>();
        let entries_end = srat_address as usize + header.length as usize;

        let mut offset = entries_start;
        while offset + 2 <= entries_end {
            let entry_type = unsafe { core::ptr::read(offset as *const u8) };
            let entry_len = unsafe { core::ptr::read((offset + 1) as *const u8) } as usize;
            if entry_len == 0 || offset + entry_len > entries_end {
                break;
            }

            match entry_type {
                0 => unsafe { Self::parse_srat_processor_affinity(offset, entry_len, info) },
                1 => unsafe { Self::parse_srat_memory_affinity(offset, entry_len, info) },
                _ => {}
            }

            offset += entry_len;
        }

        Ok(())
    }

    /// Find a table by its signature
    /// Returns the virtual address of the table if found (HHDM translated)
    pub fn find_table(&self, signature: &[u8; 4]) -> Result<usize, AcpiError> {
        let rsdp = unsafe { &*(self.rsdp_address as *const Rsdp) };
        if !rsdp.validate() {
            return Err(AcpiError::InvalidRsdpChecksum);
        }

        // Apply HHDM translation to physical XSDT/RSDT addresses
        let table_addresses = if rsdp.is_xsdt_available() {
            unsafe { self.parse_xsdt(phys_to_virt(rsdp.xsdt_address))? }
        } else {
            unsafe { self.parse_rsdt(phys_to_virt(rsdp.rsdt_address as u64))? }
        };

        for &table_addr in &table_addresses {
            let header = unsafe { &*(table_addr as *const AcpiSdtHeader) };
            if header.signature == *signature {
                return Ok(table_addr as usize);
            }
        }

        Err(AcpiError::InvalidTable) // Or NotFound if we had it
    }

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
pub unsafe fn init(rsdp_address: u64) -> Result<AcpiParser, AcpiError> {
    let mut parser = AcpiParser::new(rsdp_address);
    let info = unsafe { parser.parse()? };
    *ACPI_INFO.lock() = Some(info.clone());
    Ok(parser)
}

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

/// Get NUMA memory regions discovered via SRAT
/// Returns a Vec of (base, length, proximity_domain)
pub fn numa_memory_regions() -> alloc::vec::Vec<(u64, u64, u32)> {
    ACPI_INFO
        .lock()
        .as_ref()
        .map(|i| i.numa_memory.clone())
        .unwrap_or_default()
}

/// Get CPU proximity affinities discovered via SRAT
/// Returns a Vec of (apic_id, proximity_domain)
pub fn numa_cpu_proximity() -> alloc::vec::Vec<(u8, u32)> {
    ACPI_INFO
        .lock()
        .as_ref()
        .map(|i| i.cpu_proximity.clone())
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
