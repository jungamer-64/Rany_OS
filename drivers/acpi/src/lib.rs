#![no_std]
#![allow(dead_code)]
#![allow(clippy::must_use_candidate)] // ACPI accessor methods
#![allow(clippy::doc_markdown)] // ACPI table names: RSDT, XSDT, FADT, MADT, MCFG etc

extern crate alloc;

pub mod info;
pub mod parser;
pub mod tables;

// Re-export commonly used items
pub use info::{AcpiInfo, InterruptOverrideInfo, IoApicInfo, LocalApicInfo, PcieEcamInfo};
pub use parser::{
    AcpiParser, init, interrupt_overrides, io_apics, local_apic_address, local_apics,
    pcie_ecam_regions, processor_count,
};
pub use tables::{
    AcpiError, AcpiSdtHeader, Fadt, Madt, MadtEntryHeader, MadtEntryType, MadtInterruptOverride,
    MadtIoApic, MadtLocalApic, MadtLocalApicOverride, Mcfg, McfgEntry, RSDP_SIGNATURE, Rsdp,
    signature,
};
