//! The graphics service owns queues, fenced operations and backing allocations.
//! Cancellation and uncertain publication retain the same instance until reset.
#![deny(unsafe_code)]

pub mod defs;
mod device;
mod protocol;
mod queue;
pub use device::*;
pub use protocol::GpuDeviceError;
#[cfg(test)]
mod tests;
