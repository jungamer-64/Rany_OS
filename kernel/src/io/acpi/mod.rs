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

pub mod info;
pub mod parser;
pub mod tables;

// Re-export commonly used items
pub use info::{AcpiInfo, InterruptOverrideInfo, IoApicInfo, LocalApicInfo, PcieEcamInfo};
pub use parser::{
    init, interrupt_overrides, io_apics, local_apic_address, local_apics, pcie_ecam_regions,
    processor_count, AcpiParser,
};
pub use tables::{
    signature, AcpiError, AcpiSdtHeader, Fadt, Madt, MadtEntryHeader, MadtEntryType,
    MadtInterruptOverride, MadtIoApic, MadtLocalApic, MadtLocalApicOverride, Mcfg, McfgEntry, Rsdp,
    RSDP_SIGNATURE,
};
