//! Header/control RAM and the command ring share one activation and retirement
//! owner. Partial transitions retain their completed stage, without allocating
//! after hardware publication. Scalar protocol access never lends shared RAM.

use crate::core::{
    PreparedSplitVirtQueue, QueueBuildError, QueueSegment, RetiredVirtQueue, SplitVirtQueue,
};
use crate::queue_memory::{
    QueueConfigureCause, QueueInterrupt, QueuePrepareError, SplitQueueLayout,
};
use crate::transport::VirtioTransport;
use alloc::vec::Vec;
use kernel_api::dma::{
    CpuDmaLease, DmaDeviceAddress, DmaDirection, DmaLeaseError, DmaLeaseId, DmaQueueIdentity,
    DmaQuiesceWitness, PreparedSharedDmaLease, SharedDmaLease,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetProtocolKind {
    Transmit,
    Control,
}

#[derive(Debug, Clone, Copy)]
pub struct NetCommandLayout {
    ring: SplitQueueLayout,
    kind: NetProtocolKind,
    slots: usize,
    stride: usize,
}

impl NetCommandLayout {
    /// # Errors
    /// Protocol queues require 2..=256 descriptors, with one header and at
    /// least one payload/ACK descriptor for each admitted command.
    pub fn new(
        kind: NetProtocolKind,
        descriptors: u16,
    ) -> Result<Self, kernel_api::abi::driver::AbiError> {
        use kernel_api::abi::driver::AbiError;
        if !(2..=256).contains(&descriptors) {
            return Err(AbiError::InvalidParam);
        }
        let ring = SplitQueueLayout::new(descriptors).map_err(|_| AbiError::InvalidParam)?;
        let (slots, stride) = match kind {
            NetProtocolKind::Transmit => (usize::from(descriptors) / 2, 16),
            NetProtocolKind::Control => (1, 8),
        };
        Ok(Self {
            ring,
            kind,
            slots,
            stride,
        })
    }
    pub const fn ring(self) -> SplitQueueLayout {
        self.ring
    }
    pub const fn kind(self) -> NetProtocolKind {
        self.kind
    }
    pub const fn slot_count(self) -> usize {
        self.slots
    }
    pub const fn protocol_byte_count(self) -> usize {
        self.slots * self.stride
    }
    pub(crate) fn slot_offset(self, slot: usize) -> Result<usize, DmaLeaseError> {
        if slot >= self.slots {
            Err(DmaLeaseError::InvalidRange)
        } else {
            Ok(slot * self.stride)
        }
    }
}

#[derive(Debug)]
pub struct PreparedNetProtocolRam {
    pub(crate) identity: DmaQueueIdentity,
    pub(crate) layout: NetCommandLayout,
    pub(crate) address: DmaDeviceAddress,
    memory: PreparedSharedDmaLease,
}

impl PreparedNetProtocolRam {
    fn prepare(
        identity: DmaQueueIdentity,
        layout: NetCommandLayout,
        mut memory: CpuDmaLease,
    ) -> Result<Self, QueuePrepareError> {
        if memory.byte_count().get() < layout.protocol_byte_count()
            || memory.direction() != DmaDirection::Bidirectional
        {
            return Err(QueuePrepareError::InvalidMemory { memory });
        }
        if let Err(cause) = memory.write(|bytes| bytes[..layout.protocol_byte_count()].fill(0)) {
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
        if address.get() == 0
            || !address.get().is_multiple_of(8)
            || address.checked_add(layout.protocol_byte_count()).is_none()
        {
            return Err(QueuePrepareError::Prepared {
                cause: DmaLeaseError::InvalidRange,
                memory,
            });
        }
        Ok(Self {
            identity,
            layout,
            address,
            memory,
        })
    }

    /// # Errors
    /// Failed cancellation retains this initialized, unpublished owner.
    pub fn abort(self) -> Result<CpuDmaLease, NetProtocolAbortError> {
        let Self {
            identity,
            layout,
            address,
            memory,
        } = self;
        memory.abort().map_err(|failure| {
            let (cause, memory) = failure.into_parts();
            NetProtocolAbortError {
                cause,
                memory: Self {
                    identity,
                    layout,
                    address,
                    memory,
                },
            }
        })
    }
}

#[derive(Debug)]
pub struct NetProtocolAbortError {
    pub cause: DmaLeaseError,
    pub memory: PreparedNetProtocolRam,
}

#[derive(Debug)]
pub enum NetCommandBuildError {
    MetadataAllocation {
        ring: CpuDmaLease,
        protocol: CpuDmaLease,
    },
    Protocol {
        cause: QueuePrepareError,
        ring: CpuDmaLease,
    },
    Ring {
        cause: QueueBuildError,
        protocol: PreparedNetProtocolRam,
    },
}

#[derive(Debug)]
pub struct PreparedNetCommandQueue<T> {
    protocol: PreparedNetProtocolRam,
    ring: PreparedSplitVirtQueue<T>,
    segments: Vec<QueueSegment>,
}

impl<T> PreparedNetCommandQueue<T> {
    /// Reserve command/descriptor scratch before any device can observe RAM.
    ///
    /// # Errors
    /// Every allocation and preparation failure returns both RAM owners at
    /// their actual CPU/prepared stage. Packet submission performs no allocation.
    #[expect(
        clippy::result_large_err,
        reason = "failed preparation returns CPU or prepared RAM owners without allocating another error holder"
    )]
    pub fn prepare(
        identity: DmaQueueIdentity,
        layout: NetCommandLayout,
        interrupt: QueueInterrupt,
        ring: CpuDmaLease,
        protocol: CpuDmaLease,
    ) -> Result<Self, NetCommandBuildError> {
        let mut segments = Vec::new();
        if segments
            .try_reserve_exact(usize::from(layout.ring.size()))
            .is_err()
        {
            return Err(NetCommandBuildError::MetadataAllocation { ring, protocol });
        }
        let protocol = match PreparedNetProtocolRam::prepare(identity, layout, protocol) {
            Ok(protocol) => protocol,
            Err(cause) => return Err(NetCommandBuildError::Protocol { cause, ring }),
        };
        let ring = match PreparedSplitVirtQueue::prepare(identity, layout.ring, interrupt, ring) {
            Ok(ring) => ring,
            Err(cause) => return Err(NetCommandBuildError::Ring { cause, protocol }),
        };
        Ok(Self {
            protocol,
            ring,
            segments,
        })
    }

    pub fn into_unpublished(self) -> (PreparedSplitVirtQueue<T>, PreparedNetProtocolRam) {
        (self.ring, self.protocol)
    }

    /// # Errors
    /// Failure returns the exact protocol activation stage and original ring.
    #[expect(
        clippy::result_large_err,
        reason = "activation failure returns both admitted RAM owners without cleanup allocation"
    )]
    pub fn activate(
        self,
        transport: &dyn VirtioTransport,
    ) -> Result<NetCommandQueue<T>, NetCommandActivationError<T>> {
        let Self {
            protocol,
            ring,
            segments,
        } = self;
        let PreparedNetProtocolRam {
            identity,
            layout,
            address,
            memory,
        } = protocol;
        let memory = match memory.activate() {
            Ok(memory) => memory,
            Err(failure) => {
                let (cause, memory) = failure.into_parts();
                return Err(NetCommandActivationError::Protocol {
                    cause,
                    queue: Self {
                        protocol: PreparedNetProtocolRam {
                            identity,
                            layout,
                            address,
                            memory,
                        },
                        ring,
                        segments,
                    },
                });
            }
        };
        PartiallyActivatedNetCommandQueue {
            identity,
            layout,
            address,
            protocol: memory,
            ring,
            segments,
        }
        .activate(transport)
    }
}

#[derive(Debug)]
pub enum NetCommandActivationError<T> {
    Protocol {
        cause: DmaLeaseError,
        queue: PreparedNetCommandQueue<T>,
    },
    Ring {
        cause: QueueConfigureCause,
        queue: PartiallyActivatedNetCommandQueue<T>,
    },
}

#[derive(Debug)]
pub struct PartiallyActivatedNetCommandQueue<T> {
    identity: DmaQueueIdentity,
    layout: NetCommandLayout,
    address: DmaDeviceAddress,
    protocol: SharedDmaLease,
    ring: PreparedSplitVirtQueue<T>,
    segments: Vec<QueueSegment>,
}

impl<T> PartiallyActivatedNetCommandQueue<T> {
    pub const fn identity(&self) -> DmaQueueIdentity {
        self.identity
    }
    pub fn protocol_lease_id(&self) -> DmaLeaseId {
        self.protocol.lease_id()
    }
    /// # Errors
    /// Retains the active protocol owner if ring activation fails again.
    #[expect(
        clippy::result_large_err,
        reason = "retry preserves the completed protocol activation and admitted ring metadata"
    )]
    pub fn activate(
        self,
        transport: &dyn VirtioTransport,
    ) -> Result<NetCommandQueue<T>, NetCommandActivationError<T>> {
        let Self {
            identity,
            layout,
            address,
            protocol,
            ring,
            segments,
        } = self;
        match ring.activate(transport) {
            Ok(ring) => Ok(NetCommandQueue {
                layout,
                address,
                protocol,
                ring,
                segments,
            }),
            Err(failure) => Err(NetCommandActivationError::Ring {
                cause: failure.cause,
                queue: Self {
                    identity,
                    layout,
                    address,
                    protocol,
                    ring: failure.queue,
                    segments,
                },
            }),
        }
    }
    /// # Errors
    /// A failed observed stop retains both protocol and unpublished ring owners.
    #[expect(
        clippy::result_large_err,
        reason = "partial cleanup returns existing activated RAM and prepared ring on failure"
    )]
    pub fn quiesce(
        self,
        witness: DmaQuiesceWitness,
    ) -> Result<(CpuDmaLease, PreparedSplitVirtQueue<T>), NetPartialRetireError<T>> {
        let Self {
            identity,
            layout,
            address,
            protocol,
            ring,
            segments,
        } = self;
        match protocol.quiesce(witness) {
            Ok(memory) => Ok((memory, ring)),
            Err(failure) => {
                let (cause, protocol) = failure.into_parts();
                Err(NetPartialRetireError {
                    cause,
                    queue: Self {
                        identity,
                        layout,
                        address,
                        protocol,
                        ring,
                        segments,
                    },
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct NetPartialRetireError<T> {
    pub cause: DmaLeaseError,
    pub queue: PartiallyActivatedNetCommandQueue<T>,
}

#[derive(Debug)]
pub struct NetCommandQueue<T> {
    pub(crate) layout: NetCommandLayout,
    pub(crate) address: DmaDeviceAddress,
    pub(crate) protocol: SharedDmaLease,
    pub(crate) ring: SplitVirtQueue<T>,
    pub(crate) segments: Vec<QueueSegment>,
}

impl<T> NetCommandQueue<T> {
    pub const fn identity(&self) -> DmaQueueIdentity {
        self.ring.identity()
    }
    pub const fn layout(&self) -> NetCommandLayout {
        self.layout
    }
    pub fn protocol_lease_id(&self) -> DmaLeaseId {
        self.protocol.lease_id()
    }
    pub fn ring_lease_id(&self) -> DmaLeaseId {
        self.ring.lease_id()
    }

    /// End shared RAM access after the device owner's stop observation.
    /// Command owners still require their separate packet/control finalization.
    ///
    /// # Errors
    /// Distinguishes unchanged activation from CPU protocol RAM with a retained
    /// ring. Retry never repeats the successful protocol transition.
    #[expect(
        clippy::result_large_err,
        reason = "retirement preserves every command owner and the completed protocol RAM stage"
    )]
    pub fn quiesce(
        self,
        protocol_witness: DmaQuiesceWitness,
        ring_witness: DmaQuiesceWitness,
    ) -> Result<RetiredNetCommandQueue<T>, NetCommandRetireError<T>> {
        let Self {
            layout,
            address,
            protocol,
            ring,
            segments,
        } = self;
        let protocol = match protocol.quiesce(protocol_witness) {
            Ok(protocol) => protocol,
            Err(failure) => {
                let (cause, protocol) = failure.into_parts();
                return Err(NetCommandRetireError::Protocol {
                    cause,
                    queue: Self {
                        layout,
                        address,
                        protocol,
                        ring,
                        segments,
                    },
                });
            }
        };
        NetCommandRingRetirement { protocol, ring }
            .quiesce(ring_witness)
            .map_err(NetCommandRetireError::Ring)
    }
}

#[derive(Debug)]
pub enum NetCommandRetireError<T> {
    Protocol {
        cause: DmaLeaseError,
        queue: NetCommandQueue<T>,
    },
    Ring(NetCommandRingRetireError<T>),
}

#[derive(Debug)]
pub struct NetCommandRingRetirement<T> {
    pub protocol: CpuDmaLease,
    ring: SplitVirtQueue<T>,
}

#[derive(Debug)]
pub struct NetCommandRingRetireError<T> {
    pub cause: DmaLeaseError,
    pub retirement: NetCommandRingRetirement<T>,
}

impl<T> NetCommandRingRetirement<T> {
    pub const fn identity(&self) -> DmaQueueIdentity {
        self.ring.identity()
    }
    pub fn ring_lease_id(&self) -> DmaLeaseId {
        self.ring.lease_id()
    }
    /// # Errors
    /// Ring RAM failure returns its exact partial owner and accepted commands.
    #[expect(
        clippy::result_large_err,
        reason = "ring-only retry retains command owners and already retired protocol RAM"
    )]
    pub fn quiesce(
        self,
        witness: DmaQuiesceWitness,
    ) -> Result<RetiredNetCommandQueue<T>, NetCommandRingRetireError<T>> {
        let Self { protocol, ring } = self;
        match ring.quiesce(witness) {
            Ok(ring) => Ok(RetiredNetCommandQueue { protocol, ring }),
            Err(failure) => Err(NetCommandRingRetireError {
                cause: failure.cause,
                retirement: Self {
                    protocol,
                    ring: failure.queue,
                },
            }),
        }
    }
}

#[derive(Debug)]
pub struct RetiredNetCommandQueue<T> {
    pub protocol: CpuDmaLease,
    pub ring: RetiredVirtQueue<T>,
}
