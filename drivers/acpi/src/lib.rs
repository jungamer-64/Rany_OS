//! Workspace-owned ACPI runtime.
//!
//! The table ownership and AML object model originate from the design of the
//! rust-osdev `acpi` crate 6.1.1. RanyOS owns this implementation so table
//! cataloguing, resumable AML execution, and SCI/GPE dispatch share one error
//! model and one namespace.
#![no_std]

extern crate alloc;

pub mod aml;
pub mod dmar;
mod error;
mod events;
pub mod ivrs;
mod runtime;
mod tables;

pub use error::{AcpiError, AcpiErrorKind, AmlError, AmlErrorKind};
pub use events::{
    CpuFirmwareEvent, GpeController, GpeEvent, GpeNumber, GpeQueue, GpeTrigger, NotifyCode,
};
pub use runtime::{AcpiRuntime, AcpiRuntimeState, CpuNamespaceDevice, FirmwareUid, MatProcessor};
pub use tables::{
    AcpiMemory, AcpiTable, FirmwareCpuEntry, HhdmAcpiMemory, InterruptOverride, IoApicEntry,
    McfgAllocation, NumaCpuAffinity, NumaMemoryAffinity, SdtHeader, TableCatalog, TableSignature,
};
