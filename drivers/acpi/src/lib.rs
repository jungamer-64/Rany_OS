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
pub use runtime::{
    AcpiRuntime, AcpiRuntimeState, CpuNamespaceBinding, FirmwareUid, MatProcessor,
    NamespaceBinding, decode_device_status, decode_firmware_uid, decode_mat_processor,
    decode_proximity_domain,
};
pub use tables::{
    AcpiMemory, AcpiTable, FirmwareCpuEntry, FixedEventDescription, GenericAddress,
    GenericAddressSpace, GpeRegisterBlock, HhdmAcpiMemory, InterruptOverride, InterruptPolarity,
    InterruptTriggerMode, IoApicEntry, McfgAllocation, NfitSpaKind, NfitSpaRange, NumaCpuAffinity,
    NumaMemoryAffinity, RegisterAccessSize, SdtHeader, TableCatalog, TableSignature,
};
