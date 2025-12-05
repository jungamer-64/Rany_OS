// ============================================================================
// src/io/acpi/info.rs - ACPI Information Structures
// ============================================================================
//!
//! ACPI パース結果の情報構造体
//!
//! Local APIC, I/O APIC, 割り込みオーバーライド, PCIe ECAM情報など。

#![allow(dead_code)]

use alloc::vec::Vec;

// ============================================================================
// Parsed Information Structures
// ============================================================================

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

impl AcpiInfo {
    /// Create a new empty AcpiInfo
    pub fn new(revision: u8) -> Self {
        Self {
            local_apic_address: 0,
            local_apics: Vec::new(),
            io_apics: Vec::new(),
            interrupt_overrides: Vec::new(),
            pcie_ecam: Vec::new(),
            has_legacy_pics: false,
            revision,
        }
    }
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
