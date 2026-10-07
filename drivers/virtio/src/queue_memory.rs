//! Split-ring geometry and the unique RAM owner across register publication.
//!
//! All metadata and doorbell validation precedes shared activation. Activation
//! disables CPU references before queue registers can expose the allocation.
use hal::mmio::OwnedMmioRegister;
mod allocation;
pub(crate) use allocation::{SharedAllocation, dma_error};

use hal::WriteOnly;
use kernel_api::dma::{
    CpuDmaLease, DmaDeviceAddress, DmaDirection, DmaLeaseError, DmaQueueIdentity,
    DmaTransitionError, PreparedSharedDmaLease, SharedDmaLease,
};

use crate::transport::TransportError;

/// Layout of a split ring, including the optional event-index words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitQueueLayout {
    size: u16,
    available: usize,
    used: usize,
    byte_count: usize,
}

impl SplitQueueLayout {
    /// Derive all byte coordinates from the power-of-two descriptor count.
    ///
    /// # Errors
    /// Rejects zero, non-power-of-two, or counts above the split-ring limit.
    pub fn new(size: u16) -> Result<Self, TransportError> {
        if size == 0 || !size.is_power_of_two() || size > 32768 {
            return Err(TransportError::QueueSetupFailed);
        }
        let count = usize::from(size);
        let available = count * 16;
        let used = (available + 6 + count * 2 + 3) & !3;
        let byte_count = used + 6 + count * 8;
        Ok(Self {
            size,
            available,
            used,
            byte_count,
        })
    }

    pub const fn size(self) -> u16 {
        self.size
    }
    pub const fn available_offset(self) -> usize {
        self.available
    }
    pub const fn used_offset(self) -> usize {
        self.used
    }
    pub const fn byte_count(self) -> usize {
        self.byte_count
    }
}

/// Admission failure retains CPU or prepared-shared allocation authority.
#[derive(Debug)]
pub enum QueuePrepareError {
    InvalidMemory {
        memory: CpuDmaLease,
    },
    Cpu {
        cause: DmaLeaseError,
        memory: CpuDmaLease,
    },
    Prepared {
        cause: DmaLeaseError,
        memory: PreparedSharedDmaLease,
    },
}

/// Completion notification selected before shared RAM activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueInterrupt {
    Polled,
    Platform,
    Msix(u16),
}

impl QueueInterrupt {
    fn available_flags(self) -> u16 {
        match self {
            Self::Polled => 1, // VIRTQ_AVAIL_F_NO_INTERRUPT
            Self::Platform | Self::Msix(_) => 0,
        }
    }
}

/// Initialized queue RAM that has not been exposed in device registers.
#[derive(Debug)]
pub struct QueueConfiguration {
    identity: DmaQueueIdentity,
    layout: SplitQueueLayout,
    addresses: [DmaDeviceAddress; 3],
    interrupt: QueueInterrupt,
    memory: PreparedSharedDmaLease,
}

impl QueueConfiguration {
    /// Initialize RAM and establish its device and queue generation before I/O.
    ///
    /// # Errors
    /// Returns every allocation owner on size, direction, initialization,
    /// preparation, address alignment, or descriptor validation failure.
    pub(crate) fn prepare(
        identity: DmaQueueIdentity,
        layout: SplitQueueLayout,
        interrupt: QueueInterrupt,
        mut memory: CpuDmaLease,
    ) -> Result<Self, QueuePrepareError> {
        if memory.byte_count().get() < layout.byte_count()
            || memory.direction() != DmaDirection::Bidirectional
        {
            return Err(QueuePrepareError::InvalidMemory { memory });
        }
        if let Err(cause) = memory.write(|bytes| {
            bytes[..layout.byte_count()].fill(0);
            bytes[layout.available_offset()..layout.available_offset() + 2]
                .copy_from_slice(&interrupt.available_flags().to_le_bytes());
        }) {
            return Err(QueuePrepareError::Cpu { cause, memory });
        }
        let memory = memory.prepare_shared(identity).map_err(|failure| {
            let (cause, memory) = failure.into_parts();
            QueuePrepareError::Cpu { cause, memory }
        })?;
        let address = match memory.descriptor() {
            Ok(descriptor) => descriptor.device_address(),
            Err(cause) => return Err(QueuePrepareError::Prepared { cause, memory }),
        };
        if !address.get().is_multiple_of(16) {
            return Err(QueuePrepareError::Prepared {
                cause: DmaLeaseError::InvalidAlignment,
                memory,
            });
        }
        let addresses = match (
            address.checked_add(layout.available_offset()),
            address.checked_add(layout.used_offset()),
            address.checked_add(layout.byte_count()),
        ) {
            (Some(available), Some(used), Some(_)) => [address, available, used],
            _ => {
                return Err(QueuePrepareError::Prepared {
                    cause: DmaLeaseError::InvalidRange,
                    memory,
                });
            }
        };
        Ok(Self {
            identity,
            layout,
            addresses,
            interrupt,
            memory,
        })
    }

    /// Cancel unpublished RAM preparation before explicit allocation close.
    ///
    /// # Errors
    /// Returns the prepared allocation for retry when cancellation fails.
    pub fn abort(self) -> Result<CpuDmaLease, DmaTransitionError<PreparedSharedDmaLease>> {
        self.memory.abort()
    }

    pub(crate) const fn identity(&self) -> DmaQueueIdentity {
        self.identity
    }
    pub(crate) const fn interrupt(&self) -> QueueInterrupt {
        self.interrupt
    }
    pub(crate) const fn layout(&self) -> SplitQueueLayout {
        self.layout
    }
    pub(crate) const fn descriptor_address(&self) -> DmaDeviceAddress {
        self.addresses[0]
    }
    pub(crate) const fn available_address(&self) -> DmaDeviceAddress {
        self.addresses[1]
    }
    pub(crate) const fn used_address(&self) -> DmaDeviceAddress {
        self.addresses[2]
    }

    pub(crate) fn activate(
        self,
        doorbell: QueueDoorbell,
    ) -> Result<ConfiguredQueueMemory, QueueConfigureError> {
        let Self {
            identity,
            layout,
            addresses,
            interrupt,
            memory,
        } = self;
        match memory.activate() {
            Ok(memory) => Ok(ConfiguredQueueMemory {
                identity,
                layout,
                memory,
                doorbell,
            }),
            Err(failure) => {
                let (cause, memory) = failure.into_parts();
                Err(QueueConfigureError {
                    cause: QueueConfigureCause::Dma(cause),
                    configuration: Self {
                        identity,
                        layout,
                        addresses,
                        interrupt,
                        memory,
                    },
                })
            }
        }
    }
}

/// A configuration error occurs before any register exposes queue RAM.
#[derive(Debug)]
pub struct QueueConfigureError {
    pub cause: QueueConfigureCause,
    pub configuration: QueueConfiguration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueConfigureCause {
    Transport(TransportError),
    Dma(DmaLeaseError),
}

/// Register-programmed RAM and its queue-specific notification capability.
/// The split queue takes this owner before publishing descriptor heads. Dropping
/// it while live abandons the registry owner; it does not prove DMA retirement.
#[derive(Debug)]
pub struct ConfiguredQueueMemory {
    pub(crate) identity: DmaQueueIdentity,
    pub(crate) layout: SplitQueueLayout,
    pub(crate) memory: SharedDmaLease,
    pub(crate) doorbell: QueueDoorbell,
}

pub(crate) enum QueueDoorbell {
    Mmio {
        index: u16,
        register: OwnedMmioRegister<u32, WriteOnly>,
    },
    Pci {
        index: u16,
        register: OwnedMmioRegister<u16, WriteOnly>,
    },
}

impl core::fmt::Debug for QueueDoorbell {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Mmio { index, .. } => formatter.debug_tuple("MmioDoorbell").field(index).finish(),
            Self::Pci { index, .. } => formatter.debug_tuple("PciDoorbell").field(index).finish(),
        }
    }
}

impl QueueDoorbell {
    pub(crate) fn notify(&mut self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        match self {
            Self::Mmio { index, register } => register.write(u32::from(*index)),
            Self::Pci { index, register } => register.write(*index),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_policy_controls_device_notification_request() {
        assert_eq!(QueueInterrupt::Polled.available_flags(), 1);
        assert_eq!(QueueInterrupt::Platform.available_flags(), 0);
        assert_eq!(QueueInterrupt::Msix(7).available_flags(), 0);
    }

    #[test]
    fn split_layout_matches_literal_protocol_coordinates() {
        let small = SplitQueueLayout::new(1).expect("one descriptor");
        assert_eq!(
            (
                small.available_offset(),
                small.used_offset(),
                small.byte_count()
            ),
            (16, 24, 38)
        );
        let full = SplitQueueLayout::new(256).expect("256 descriptors");
        assert_eq!(
            (
                full.available_offset(),
                full.used_offset(),
                full.byte_count()
            ),
            (4096, 4616, 6670)
        );
        let largest = SplitQueueLayout::new(32768).expect("split ring limit");
        assert_eq!(largest.byte_count(), 851982);
    }

    #[test]
    fn split_layout_admission_rejects_invalid_descriptor_counts() {
        for size in [0, 3, 255, 65535] {
            assert_eq!(
                SplitQueueLayout::new(size),
                Err(TransportError::QueueSetupFailed)
            );
        }
    }
}
