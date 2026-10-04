//! Retained register authority and indivisible selector transactions.
//!
//! Queue programming consumes prepared shared RAM. The resulting queue owns its
//! doorbell, so notification neither selects a queue nor recovers an aperture
//! from an address. Reset is requested separately from observing status zero.

use crate::defs::VirtioDeviceType;
use crate::queue_memory::{ConfiguredQueueMemory, QueueConfiguration, QueueConfigureError};
use hal::MmioAccessError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Access(MmioAccessError),
    InvalidMagic,
    UnsupportedVersion,
    DeviceNotFound,
    DeviceError,
    FeatureNegotiationFailed,
    InvalidQueueIndex,
    QueueAlreadyEnabled,
    QueueSetupFailed,
    ConfigAccessFailed,
    OutOfResources,
    Timeout,
}

impl From<MmioAccessError> for TransportError {
    fn from(cause: MmioAccessError) -> Self {
        Self::Access(cause)
    }
}

pub type TransportResult<T> = Result<T, TransportError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportType {
    Mmio,
    PciModern,
}

/// Register operations shared by modern PCI and MMIO devices. Implementations
/// serialize each feature-bank and queue-selector transaction internally.
/// Configuration offsets remain fallible, including alignment and width checks.
pub trait VirtioTransport: Send + Sync + core::fmt::Debug {
    fn device_type(&self) -> VirtioDeviceType;
    fn transport_type(&self) -> TransportType;
    fn status(&self) -> u8;
    fn request_reset(&self);
    fn add_status(&self, bits: u8);
    fn device_features(&self) -> u64;
    fn set_driver_features(&self, features: u64);
    fn config_generation(&self) -> u32;
    fn queue_count(&self) -> Option<u16>;
    fn queue_capacity(&self, index: u16) -> TransportResult<u16>;

    /// Reserve all register accesses and the notification capability before
    /// activating RAM. On failure no queue is published; the prepared owner is
    /// returned. After activation register publication cannot fail locally.
    fn configure_queue(
        &self,
        configuration: QueueConfiguration,
        interrupt_vector: Option<u16>,
    ) -> Result<ConfiguredQueueMemory, QueueConfigureError>;

    /// One read/ack transaction. PCI ISR reads acknowledge the interrupt; MMIO
    /// uses the captured status value in its write-only acknowledgement register.
    fn acknowledge_interrupt(&self) -> u32;
    fn read_config_u8(&self, offset: usize) -> TransportResult<u8>;
    fn read_config_u16(&self, offset: usize) -> TransportResult<u16>;
    fn read_config_u32(&self, offset: usize) -> TransportResult<u32>;
    fn write_config_u8(&self, offset: usize, value: u8) -> TransportResult<()>;
    fn write_config_u16(&self, offset: usize, value: u16) -> TransportResult<()>;
    fn write_config_u32(&self, offset: usize, value: u32) -> TransportResult<()>;
}
