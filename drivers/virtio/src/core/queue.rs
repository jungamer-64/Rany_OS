//! A split queue's host metadata is authoritative for descriptor and command
//! ownership. Shared ring RAM never lends a Rust reference. Used-ring indices,
//! heads and writable lengths are checked before consuming an accepted owner.

use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};
use kernel_api::dma::{
    CpuDmaLease, DmaByteCount, DmaDeviceAddress, DmaLeaseError, DmaLeaseId, DmaQueueIdentity,
    DmaQuiesceWitness, DmaTransitionError, PreparedSharedDmaLease,
};

use crate::queue_memory::{
    ConfiguredQueueMemory, QueueConfiguration, QueueConfigureCause, QueueInterrupt,
    QueuePrepareError, SplitQueueLayout,
};
use crate::transport::VirtioTransport;

pub(crate) const MAX_SPLIT_QUEUE_DESCRIPTORS: usize = 256;

#[derive(Debug)]
enum Slot<T> {
    Free,
    Reserved,
    Head {
        owner: T,
        next: Option<u16>,
        writable_bytes: u32,
    },
    Link {
        next: Option<u16>,
    },
}

/// Queue RAM and all host metadata admitted before device publication.
#[derive(Debug)]
pub struct PreparedSplitVirtQueue<T> {
    configuration: QueueConfiguration,
    slots: Vec<Slot<T>>,
}

#[derive(Debug)]
pub enum QueueBuildError {
    DescriptorLimit { memory: CpuDmaLease },
    MetadataAllocation { memory: CpuDmaLease },
    Memory(QueuePrepareError),
}

#[derive(Debug)]
pub struct QueueActivationError<T> {
    pub cause: QueueConfigureCause,
    pub queue: PreparedSplitVirtQueue<T>,
}

impl<T> PreparedSplitVirtQueue<T> {
    pub const fn identity(&self) -> DmaQueueIdentity {
        self.configuration.identity()
    }

    pub const fn capacity(&self) -> u16 {
        self.configuration.layout().size()
    }

    /// Reserve command ownership slots before preparing the shared allocation.
    /// The implementation admits at most 256 descriptors per queue.
    ///
    /// # Errors
    /// Returns the allocation for policy or metadata exhaustion, and the exact
    /// CPU/prepared owner for every RAM preparation failure.
    pub fn prepare(
        identity: DmaQueueIdentity,
        layout: SplitQueueLayout,
        interrupt: QueueInterrupt,
        memory: CpuDmaLease,
    ) -> Result<Self, QueueBuildError> {
        let count = usize::from(layout.size());
        if count > MAX_SPLIT_QUEUE_DESCRIPTORS {
            return Err(QueueBuildError::DescriptorLimit { memory });
        }
        let mut slots = Vec::new();
        if slots.try_reserve_exact(count).is_err() {
            return Err(QueueBuildError::MetadataAllocation { memory });
        }
        slots.resize_with(count, || Slot::Free);
        let configuration = QueueConfiguration::prepare(identity, layout, interrupt, memory)
            .map_err(QueueBuildError::Memory)?;
        Ok(Self {
            configuration,
            slots,
        })
    }

    /// Release admission metadata and cancel unpublished queue preparation.
    ///
    /// # Errors
    /// Retains the prepared allocation if the registry rejects cancellation.
    pub fn abort(self) -> Result<CpuDmaLease, DmaTransitionError<PreparedSharedDmaLease>> {
        self.configuration.abort()
    }

    /// Consume prepared RAM into one register-programmed queue.
    ///
    /// # Errors
    /// Returns the complete prepared queue if register validation or shared
    /// activation fails. No device can access this queue on that error path.
    #[expect(
        clippy::result_large_err,
        reason = "failed activation returns the existing prepared RAM and metadata without another allocation"
    )]
    pub fn activate(
        self,
        transport: &dyn VirtioTransport,
    ) -> Result<SplitVirtQueue<T>, QueueActivationError<T>> {
        let Self {
            configuration,
            slots,
        } = self;
        match transport.configure_queue(configuration) {
            Ok(memory) => Ok(SplitVirtQueue {
                memory,
                slots,
                available_index: 0,
                used_index: 0,
                pending: 0,
                fault: None,
            }),
            Err(failure) => Err(QueueActivationError {
                cause: failure.cause,
                queue: Self {
                    configuration: failure.configuration,
                    slots,
                },
            }),
        }
    }
}

/// Scalar descriptor metadata; constructing this value grants no DMA authority.
#[derive(Clone, Copy, Debug)]
pub struct QueueSegment {
    address: DmaDeviceAddress,
    bytes: u32,
    writable: bool,
}

impl QueueSegment {
    /// Describe a nonempty extent with a representable split-ring byte length.
    ///
    /// # Errors
    /// Rejects address zero, overflowing extents or byte counts above u32::MAX.
    pub fn new(
        address: DmaDeviceAddress,
        bytes: DmaByteCount,
        writable: bool,
    ) -> Result<Self, QueueAdmissionError> {
        let length = u32::try_from(bytes.get()).map_err(|_| QueueAdmissionError::InvalidSegment)?;
        if address.get() == 0 || address.checked_add(bytes.get()).is_none() {
            return Err(QueueAdmissionError::InvalidSegment);
        }
        Ok(Self {
            address,
            bytes: length,
            writable,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueAdmissionError {
    EmptyChain,
    InvalidSegment,
    QueueFull,
    Faulted(QueueFault),
    Dma(DmaLeaseError),
}

#[derive(Debug)]
pub struct QueueSubmitError<T, E> {
    pub owner: T,
    pub cause: QueueSubmitCause<E>,
}

#[derive(Debug)]
pub enum QueueSubmitCause<E> {
    Admission(QueueAdmissionError),
    Activation(E),
}

/// Command activation failed before the available ring could expose it.
#[derive(Debug)]
pub struct QueueCommandActivationError<T, E> {
    pub owner: T,
    pub cause: E,
}

/// An activated owner stays in the queue for either publication outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueSubmitOutcome {
    Published { head: u16 },
    PublicationUncertain { head: u16, cause: DmaLeaseError },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueFault {
    Dma(DmaLeaseError),
    UsedIndex,
    UsedHead(u32),
    UsedLength { actual: u32, maximum: u32 },
}

/// One validated used entry and its unique accepted command owner.
#[derive(Debug)]
pub struct QueueCompletion<T> {
    pub head: u16,
    pub written_bytes: u32,
    pub owner: T,
}

/// One queue owns descriptor state, accepted command owners, RAM and doorbell.
#[derive(Debug)]
pub struct SplitVirtQueue<T> {
    memory: ConfiguredQueueMemory,
    slots: Vec<Slot<T>>,
    available_index: u16,
    used_index: u16,
    // Projection of Head slots, updated with the same exclusive transitions.
    pending: u16,
    fault: Option<QueueFault>,
}

impl<T> SplitVirtQueue<T> {
    pub const fn identity(&self) -> DmaQueueIdentity {
        self.memory.identity
    }
    /// Shared allocation identity used with a device owner's stop observation.
    pub fn lease_id(&self) -> DmaLeaseId {
        self.memory.memory.lease_id()
    }
    pub const fn capacity(&self) -> u16 {
        self.memory.layout.size()
    }
    pub const fn pending_count(&self) -> u16 {
        self.pending
    }

    /// Set interrupt delivery for the retained queue before the caller's idle
    /// recheck. No queue selection or descriptor allocation occurs here.
    ///
    /// # Errors
    /// Shared RAM access failure leaves the caller responsible for polling.
    pub fn set_interrupts_enabled(&mut self, enabled: bool) -> Result<(), DmaLeaseError> {
        let mut available = self
            .memory
            .memory
            .window(self.memory.layout.available_offset(), 2)?;
        available.write_u16(0, u16::from(!enabled))
    }

    /// Publish one chain after storage is reserved and its DMA owner is activated.
    /// Rejection returns that owner; uncertain publication retains it in the queue.
    ///
    /// # Safety
    /// Every segment must identify a DMA extent admitted for this queue's device
    /// and generation. The activated owner must keep those extents mapped through
    /// validated completion or device reset. `activate` must disable conflicting CPU access
    /// and finish cache preparation before success; failure must have no device
    /// publication effect. No available notification may precede DRIVER_OK.
    ///
    /// # Errors
    /// Admission or activation failure occurs before available-ring publication
    /// and returns the unchanged owner. After activation an uncertain write keeps
    /// the owner here and faults the queue; it cannot be submitted again.
    pub unsafe fn publish<P, E>(
        &mut self,
        segments: &[QueueSegment],
        owner: P,
        activate: impl FnOnce(P) -> Result<T, QueueCommandActivationError<P, E>>,
    ) -> Result<QueueSubmitOutcome, QueueSubmitError<P, E>> {
        let writable_bytes = match validate_chain(segments, self.capacity(), self.fault) {
            Ok(bytes) => bytes,
            Err(cause) => {
                return Err(QueueSubmitError {
                    owner,
                    cause: QueueSubmitCause::Admission(cause),
                });
            }
        };
        let mut reserved = [0u16; MAX_SPLIT_QUEUE_DESCRIPTORS];
        let mut count = 0;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if matches!(slot, Slot::Free) {
                *slot = Slot::Reserved;
                reserved[count] = index as u16;
                count += 1;
                if count == segments.len() {
                    break;
                }
            }
        }
        if count != segments.len() {
            self.release_reservation(&reserved[..count]);
            return Err(QueueSubmitError {
                owner,
                cause: QueueSubmitCause::Admission(QueueAdmissionError::QueueFull),
            });
        }
        for (position, segment) in segments.iter().enumerate() {
            let next = reserved
                .get(position + 1)
                .copied()
                .filter(|_| position + 1 < count);
            if let Err(cause) = self.write_descriptor(reserved[position], *segment, next) {
                self.release_reservation(&reserved[..count]);
                self.fault = Some(QueueFault::Dma(cause));
                return Err(QueueSubmitError {
                    owner,
                    cause: QueueSubmitCause::Admission(QueueAdmissionError::Dma(cause)),
                });
            }
        }
        let owner = match activate(owner) {
            Ok(owner) => owner,
            Err(failure) => {
                self.release_reservation(&reserved[..count]);
                return Err(QueueSubmitError {
                    owner: failure.owner,
                    cause: QueueSubmitCause::Activation(failure.cause),
                });
            }
        };
        let head = reserved[0];
        self.slots[usize::from(head)] = Slot::Head {
            owner,
            next: reserved.get(1).copied().filter(|_| count > 1),
            writable_bytes,
        };
        for position in 1..count {
            self.slots[usize::from(reserved[position])] = Slot::Link {
                next: reserved
                    .get(position + 1)
                    .copied()
                    .filter(|_| position + 1 < count),
            };
        }
        self.pending += 1;
        let mut publish = || -> Result<(), DmaLeaseError> {
            let layout = self.memory.layout;
            let mut window = self.memory.memory.window(
                layout.available_offset(),
                6 + usize::from(layout.size()) * 2,
            )?;
            window.write_u16(
                4 + usize::from(self.available_index % layout.size()) * 2,
                head,
            )?;
            fence(Ordering::Release);
            window.write_u16(2, self.available_index.wrapping_add(1))
        };
        if let Err(cause) = publish() {
            self.fault = Some(QueueFault::Dma(cause));
            return Ok(QueueSubmitOutcome::PublicationUncertain { head, cause });
        }
        self.available_index = self.available_index.wrapping_add(1);
        self.memory.doorbell.notify();
        Ok(QueueSubmitOutcome::Published { head })
    }

    fn release_reservation(&mut self, reserved: &[u16]) {
        for index in reserved {
            self.slots[usize::from(*index)] = Slot::Free;
        }
    }

    fn write_descriptor(
        &mut self,
        index: u16,
        segment: QueueSegment,
        next: Option<u16>,
    ) -> Result<(), DmaLeaseError> {
        let mut window = self.memory.memory.window(usize::from(index) * 16, 16)?;
        window.write_u64(0, segment.address.get())?;
        window.write_u32(8, segment.bytes)?;
        let flags = (u16::from(segment.writable) * 2) | u16::from(next.is_some());
        window.write_u16(12, flags)?;
        window.write_u16(14, next.unwrap_or(0))
    }

    /// Consume at most one used entry after validating its complete ownership tag.
    ///
    /// # Errors
    /// Device index/head/length errors and shared RAM failures retain every
    /// accepted owner and permanently fault this queue until retirement.
    pub fn poll_completion(&mut self) -> Result<Option<QueueCompletion<T>>, QueueFault> {
        if let Some(cause) = self.fault {
            return Err(cause);
        }
        let observation = (|| -> Result<Option<(u32, u32)>, QueueFault> {
            let layout = self.memory.layout;
            let window = self
                .memory
                .memory
                .window(layout.used_offset(), 6 + usize::from(layout.size()) * 8)
                .map_err(QueueFault::Dma)?;
            let index = window.read_u16(2).map_err(QueueFault::Dma)?;
            if used_distance(index, self.used_index, self.pending)? == 0 {
                return Ok(None);
            }
            fence(Ordering::Acquire);
            let offset = 4 + usize::from(self.used_index % layout.size()) * 8;
            Ok(Some((
                window.read_u32(offset).map_err(QueueFault::Dma)?,
                window.read_u32(offset + 4).map_err(QueueFault::Dma)?,
            )))
        })();
        let (head, bytes) = match observation {
            Ok(Some(completed)) => completed,
            Ok(None) => return Ok(None),
            Err(cause) => {
                self.fault = Some(cause);
                return Err(cause);
            }
        };
        let head = match validate_used_entry(&self.slots, head, bytes) {
            Ok(head) => head,
            Err(cause) => {
                self.fault = Some(cause);
                return Err(cause);
            }
        };
        let completed = core::mem::replace(&mut self.slots[usize::from(head)], Slot::Free);
        let Slot::Head {
            owner, mut next, ..
        } = completed
        else {
            unreachable!("the exclusive queue owner retains its validated Head slot");
        };
        // LOOP_PROOF: mode=bounded; reason=Only host-created links belonging to this head are followed, and each visit consumes one descriptor from the queue-sized chain budget.;
        for _ in 1..self.capacity() {
            let Some(index) = next else {
                break;
            };
            let link = core::mem::replace(&mut self.slots[usize::from(index)], Slot::Free);
            let Slot::Link { next: following } = link else {
                unreachable!("accepted chains contain only exclusively owned host links");
            };
            next = following;
        }
        self.used_index = self.used_index.wrapping_add(1);
        self.pending -= 1;
        Ok(Some(QueueCompletion {
            head,
            written_bytes: bytes,
            owner,
        }))
    }

    /// Recover queue RAM after the device owner proves that all accesses stopped.
    /// Accepted command owners remain separate aborted operations, without a
    /// fabricated hardware completion or restored transfer-buffer authority.
    ///
    /// # Errors
    /// Returns this complete queue if the RAM quiescence transition fails.
    #[expect(
        clippy::result_large_err,
        reason = "a failed quiescence returns every accepted owner and live queue resource without a fallible cleanup allocation"
    )]
    pub fn quiesce(
        self,
        witness: DmaQuiesceWitness,
    ) -> Result<RetiredVirtQueue<T>, QueueRetireError<T>> {
        let Self {
            memory,
            slots,
            available_index,
            used_index,
            pending,
            fault,
        } = self;
        let ConfiguredQueueMemory {
            identity,
            layout,
            memory,
            doorbell,
        } = memory;
        match memory.quiesce(witness) {
            Ok(memory) => Ok(RetiredVirtQueue {
                memory,
                commands: slots.into_iter(),
            }),
            Err(failure) => {
                let (cause, memory) = failure.into_parts();
                Err(QueueRetireError {
                    cause,
                    queue: Self {
                        memory: ConfiguredQueueMemory {
                            identity,
                            layout,
                            memory,
                            doorbell,
                        },
                        slots,
                        available_index,
                        used_index,
                        pending,
                        fault,
                    },
                })
            }
        }
    }
}

fn used_distance(index: u16, consumed: u16, pending: u16) -> Result<u16, QueueFault> {
    let count = index.wrapping_sub(consumed);
    if count > pending {
        Err(QueueFault::UsedIndex)
    } else {
        Ok(count)
    }
}

fn validate_used_entry<T>(slots: &[Slot<T>], head: u32, bytes: u32) -> Result<u16, QueueFault> {
    let index = usize::try_from(head).map_err(|_| QueueFault::UsedHead(head))?;
    let Some(Slot::Head { writable_bytes, .. }) = slots.get(index) else {
        return Err(QueueFault::UsedHead(head));
    };
    if bytes > *writable_bytes {
        return Err(QueueFault::UsedLength {
            actual: bytes,
            maximum: *writable_bytes,
        });
    }
    u16::try_from(head).map_err(|_| QueueFault::UsedHead(head))
}

fn validate_chain(
    segments: &[QueueSegment],
    capacity: u16,
    fault: Option<QueueFault>,
) -> Result<u32, QueueAdmissionError> {
    if let Some(cause) = fault {
        return Err(QueueAdmissionError::Faulted(cause));
    }
    if segments.is_empty() {
        return Err(QueueAdmissionError::EmptyChain);
    }
    if segments.len() > usize::from(capacity) {
        return Err(QueueAdmissionError::QueueFull);
    }
    segments
        .iter()
        .filter(|segment| segment.writable)
        .try_fold(0u32, |sum, segment| {
            sum.checked_add(segment.bytes)
                .ok_or(QueueAdmissionError::InvalidSegment)
        })
}

#[derive(Debug)]
pub struct QueueRetireError<T> {
    pub cause: DmaLeaseError,
    pub queue: SplitVirtQueue<T>,
}

#[derive(Debug)]
pub struct RetiredVirtQueue<T> {
    pub memory: CpuDmaLease,
    commands: alloc::vec::IntoIter<Slot<T>>,
}

impl<T> RetiredVirtQueue<T> {
    /// Consume one reset-aborted command owner. This never reports completion.
    pub fn next_aborted(&mut self) -> Option<T> {
        for slot in self.commands.by_ref() {
            if let Slot::Head { owner, .. } = slot {
                return Some(owner);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn segment(bytes: usize, writable: bool) -> QueueSegment {
        QueueSegment::new(
            DmaDeviceAddress::from_abi(0x1000),
            DmaByteCount::new(bytes).expect("nonzero fixture"),
            writable,
        )
        .expect("representable segment")
    }

    #[test]
    fn chain_lengths_count_only_device_writable_extents() {
        assert_eq!(
            validate_chain(
                &[segment(16, false), segment(512, true), segment(1, true)],
                8,
                None
            ),
            Ok(513)
        );
        assert_eq!(
            validate_chain(
                &[segment(16, false), segment(512, false), segment(1, true)],
                8,
                None
            ),
            Ok(1)
        );
    }
    #[test]
    fn descriptor_admission_preserves_capacity_and_length_failure_reasons() {
        assert_eq!(
            validate_chain(&[], 8, None),
            Err(QueueAdmissionError::EmptyChain)
        );
        assert_eq!(
            validate_chain(&[segment(1, false); 9], 8, None),
            Err(QueueAdmissionError::QueueFull)
        );
        assert_eq!(
            validate_chain(
                &[segment(u32::MAX as usize, true), segment(1, true)],
                8,
                None
            ),
            Err(QueueAdmissionError::InvalidSegment)
        );
        assert!(
            QueueSegment::new(
                DmaDeviceAddress::from_abi(u64::MAX),
                DmaByteCount::new(1).expect("one byte"),
                false
            )
            .is_err()
        );
    }

    #[test]
    fn used_entry_requires_an_accepted_head_and_complete_writable_length() {
        let slots = [
            Slot::Head {
                owner: 19,
                next: Some(1),
                writable_bytes: 513,
            },
            Slot::Link { next: None },
            Slot::Free,
        ];
        assert_eq!(validate_used_entry(&slots, 0, 513), Ok(0));
        assert_eq!(
            validate_used_entry(&slots, 0, 514),
            Err(QueueFault::UsedLength {
                actual: 514,
                maximum: 513
            })
        );
        for head in [1, 2, 65536, u32::MAX] {
            assert_eq!(
                validate_used_entry(&slots, head, 0),
                Err(QueueFault::UsedHead(head))
            );
        }
    }

    #[test]
    fn used_index_wraps_without_authorizing_more_than_accepted_commands() {
        assert_eq!(used_distance(0, u16::MAX, 1), Ok(1));
        assert_eq!(used_distance(0, u16::MAX, 0), Err(QueueFault::UsedIndex));
        assert_eq!(used_distance(7, 3, 3), Err(QueueFault::UsedIndex));
        assert_eq!(used_distance(7, 7, 3), Ok(0));
    }
}
