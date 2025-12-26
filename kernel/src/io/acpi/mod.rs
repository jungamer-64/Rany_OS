// ============================================================================
// src/io/acpi/mod.rs - ACPI Module
// ============================================================================
//!
//! ACPI Table Parser for ExoRust
//!
//! This module implements parsing of ACPI tables for system configuration
//! discovery (MADT, MCFG, FADT, etc.)
//!
//! ## Module Structure
//!
//! - `tables` - ACPI table structure definitions (RSDP, SDT, MADT, MCFG, FADT)
//! - `info` - Parsed information structures (AcpiInfo, LocalApicInfo, etc.)
//! - `parser` - ACPI table parser and global API

#![allow(dead_code)]

// Re-export from acpi_driver crate
pub use acpi_driver::info;
pub use acpi_driver::parser;
pub use acpi_driver::tables;

// Re-export commonly used items from the driver
pub use acpi_driver::info::{
    AcpiInfo, InterruptOverrideInfo, IoApicInfo, LocalApicInfo, PcieEcamInfo,
};
pub use acpi_driver::parser::{
    AcpiParser, init, interrupt_overrides, io_apics, local_apic_address, local_apics,
    numa_cpu_proximity, numa_memory_regions, pcie_ecam_regions, processor_count, set_hhdm_offset,
};
pub use acpi_driver::tables::{
    AcpiError, AcpiSdtHeader, Fadt, Madt, MadtEntryHeader, MadtEntryType, MadtInterruptOverride,
    MadtIoApic, MadtLocalApic, MadtLocalApicOverride, Mcfg, McfgEntry, RSDP_SIGNATURE, Rsdp,
    signature,
};

// DMAR (IOMMU) support
pub mod dmar;
pub mod ivrs;
