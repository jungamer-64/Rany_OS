//! Kernel composition boundary for the capability-owned AHCI driver.
//!
//! Register mappings and DMA leases are acquired by kernel resource owners and
//! then consumed by `AhciController`. This module does not expose numeric DMA
//! addresses, duplicate DMA buffers, or an ambient scheduler registry.

mod runtime;

pub(crate) use ahci_driver::controller::{
    AhciAcquisition, AhciAcquisitionPoll, AhciController, ControllerOpenError,
};
pub(crate) use ahci_driver::{AhciError, DmaAddressWidth, PORT_DMA_BYTES, PortNumber};
pub(crate) use runtime::{
    AhciPoller, AhciPortOps, AhciRuntime, AhciRuntimeShutdown, PortAdmission, RuntimeShutdownCause,
    RuntimeShutdownStartError,
};
