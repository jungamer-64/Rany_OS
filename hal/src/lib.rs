//! Owner-bound register and port access primitives for the kernel's device boundary.
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

extern crate alloc;

// re-export modules
pub mod mmio;
pub mod port_io;

pub use mmio::{
    MappedMmio, MmioAccessError, MmioRegion, MmioRegionError, MmioRegister, ReadOnly, ReadWrite,
    WriteOnly,
};
pub use port_io::{IoPort, IoPortError, IoPortRange, PortValue};
