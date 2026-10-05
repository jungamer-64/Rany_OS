//! Packet leases move with accepted split-ring heads. RX completion publishes
//! only the validated initialized prefix; TX completion and reset keep their
//! distinct outcomes until the host acknowledges the exact lease notification.
#![deny(unsafe_code)]

use kernel_api::abi::driver::{AbiError, CpuRxLease, PostedRxLease};
use kernel_api::dma::{
    CpuDmaLease, DmaLeaseError, DmaLeaseId, DmaQueueIdentity, DmaQuiesceWitness,
};

use crate::core::{
    PreparedSplitVirtQueue, QueueActivationError, QueueAdmissionError, QueueCompletion, QueueFault,
    QueueSegment, QueueSubmitCause, QueueSubmitOutcome, RetiredVirtQueue, SplitVirtQueue,
};
use crate::transport::VirtioTransport;

use super::{NET_HEADER_BYTES, NetConfiguration};

#[derive(Debug)]
pub struct NetRxQueue {
    configuration: NetConfiguration,
    ring: SplitVirtQueue<PostedRxLease>,
    retained: Option<PostedRxLease>,
}

impl NetRxQueue {
    /// Bind negotiated RX framing to its register-programmed split queue.
    ///
    /// # Errors
    /// A foreign queue index or transport activation failure returns the exact
    /// prepared ring, with no packet lease or queue descriptor published.
    #[expect(
        clippy::result_large_err,
        reason = "activation failure retains the admitted packet queue RAM and metadata"
    )]
    pub fn activate(
        configuration: NetConfiguration,
        ring: PreparedSplitVirtQueue<PostedRxLease>,
        transport: &dyn VirtioTransport,
    ) -> Result<Self, QueueActivationError<PostedRxLease>> {
        let index = ring.identity().index();
        if index & 1 != 0 || index / 2 >= configuration.offered_pairs().get() {
            return Err(QueueActivationError {
                cause: crate::queue_memory::QueueConfigureCause::Transport(
                    crate::transport::TransportError::QueueSetupFailed,
                ),
                queue: ring,
            });
        }
        Ok(Self {
            configuration,
            ring: ring.activate(transport)?,
            retained: None,
        })
    }

    pub const fn identity(&self) -> DmaQueueIdentity {
        self.ring.identity()
    }
    pub fn ring_lease_id(&self) -> DmaLeaseId {
        self.ring.lease_id()
    }
    pub const fn capacity(&self) -> u16 {
        self.ring.capacity()
    }

    /// Reserve the descriptor before transferring the CPU packet lease.
    ///
    /// # Errors
    /// Pre-publication failure returns the unpublished CPU owner. Both accepted
    /// and uncertain publication retain packet storage inside the queue.
    ///
    /// # Safety
    /// This lease must belong to this queue's retained port runtime and admitted
    /// device mappings. DRIVER_OK and MQ enablement must precede posting; the
    /// packet region remains valid until completion or observed device stop.
    #[expect(
        unsafe_code,
        reason = "hardware publication transfers one retained packet lease after split-ring reservation"
    )]
    pub unsafe fn post(&mut self, lease: CpuRxLease) -> Result<QueueSubmitOutcome, NetRxPostError> {
        if self.retained.is_some() {
            return Err(NetRxPostError {
                cause: AbiError::IoError,
                lease,
            });
        }
        let region = lease.device_region();
        if region.writable_len < self.configuration.receive_buffer_bytes() {
            return Err(NetRxPostError {
                cause: AbiError::InvalidParam,
                lease,
            });
        }
        let segment = match packet_segment(region.device_addr, region.writable_len, true) {
            Ok(segment) => segment,
            Err(cause) => {
                return Err(NetRxPostError {
                    cause: admission_status(cause),
                    lease,
                });
            }
        };
        // SAFETY: the caller retains the correct port mapping/backing. Split
        // metadata and descriptors are reserved before this one owner is armed.
        let result = unsafe {
            self.ring.publish(&[segment], lease, |lease| {
                Ok::<
                    _,
                    crate::core::QueueCommandActivationError<CpuRxLease, core::convert::Infallible>,
                >(lease.arm())
            })
        };
        result.map_err(|failure| NetRxPostError {
            lease: failure.owner,
            cause: match failure.cause {
                QueueSubmitCause::Admission(cause) => admission_status(cause),
                QueueSubmitCause::Activation(never) => match never {},
            },
        })
    }

    /// End device ownership using the split queue's validated used entry. The
    /// small wire header is read from the completed prefix; packet bytes remain
    /// in their framework backing through delivery.
    ///
    /// # Errors
    /// Ring corruption retains active owners. Invalid framing discards only a
    /// hardware-completed packet. Failed ownership conversion retains its lease
    /// for device stop and blocks further posting/completion on this queue.
    #[expect(
        unsafe_code,
        reason = "a validated matching split-ring used head grants RX prefix ownership"
    )]
    pub fn poll(&mut self) -> Result<Option<NetRxFrame>, NetRxPollError> {
        if self.retained.is_some() {
            return Err(NetRxPollError::Lease(AbiError::IoError));
        }
        let Some(QueueCompletion {
            written_bytes,
            owner,
            ..
        }) = self.ring.poll_completion().map_err(NetRxPollError::Ring)?
        else {
            return Ok(None);
        };
        let capacity = owner.device_region().writable_len;
        // SAFETY: the split queue validated the accepted head and full writable
        // extent, then acquired used-ring visibility. Unmerged RX completes one
        // packet lease and initializes exactly the device's written prefix.
        let completed = match unsafe { owner.complete(written_bytes as usize) } {
            Ok(completed) => completed,
            Err(failure) => {
                self.retained = Some(failure.lease);
                return Err(NetRxPollError::Lease(failure.cause));
            }
        };
        let header: [u8; NET_HEADER_BYTES] = completed
            .bytes()
            .get(..NET_HEADER_BYTES)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(NetRxPollError::Frame(AbiError::IoError))?;
        let layout = self
            .configuration
            .receive_layout(header, written_bytes, capacity)
            .map_err(NetRxPollError::Frame)?;
        Ok(Some(NetRxFrame {
            lease: completed,
            meta: kernel_api::abi::driver::AbiNetRxMeta::new(
                self.identity().index() / 2,
                layout,
                0,
            ),
        }))
    }

    /// # Errors
    /// Preserves shared RAM failure for the caller's polling recovery path.
    pub fn set_interrupts_enabled(&mut self, enabled: bool) -> Result<(), DmaLeaseError> {
        self.ring.set_interrupts_enabled(enabled)
    }

    /// # Errors
    /// RAM retirement failure retains this queue and every packet owner.
    ///
    /// # Safety
    /// The device owner must observe stop of this exact generation and fence
    /// every packet DMA, in addition to the ring allocation named by witness.
    #[expect(
        unsafe_code,
        clippy::result_large_err,
        reason = "observed packet DMA stop is a caller obligation; failed RAM retirement retains every packet and queue owner inline"
    )]
    pub unsafe fn quiesce(
        self,
        witness: DmaQuiesceWitness,
    ) -> Result<RetiredNetRxQueue, NetRxRetireError> {
        let Self {
            configuration,
            ring,
            retained,
        } = self;
        match ring.quiesce(witness) {
            Ok(ring) => Ok(RetiredNetRxQueue { ring, retained }),
            Err(failure) => Err(NetRxRetireError {
                cause: failure.cause,
                queue: Self {
                    configuration,
                    ring: failure.queue,
                    retained,
                },
            }),
        }
    }
}

#[derive(Debug)]
pub struct NetRxPostError {
    pub cause: AbiError,
    pub lease: CpuRxLease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetRxPollError {
    Ring(QueueFault),
    Frame(AbiError),
    Lease(AbiError),
}

#[derive(Debug)]
pub struct NetRxFrame {
    lease: kernel_api::abi::driver::CompletedRxLease,
    meta: kernel_api::abi::driver::AbiNetRxMeta,
}

impl NetRxFrame {
    /// The initialized packet window and its owner move into the framework.
    /// Every outcome consumes the driver's completed lease.
    pub fn submit(self) -> AbiError {
        self.lease.submit(self.meta)
    }
}

#[derive(Debug)]
pub struct NetRxRetireError {
    pub cause: DmaLeaseError,
    pub queue: NetRxQueue,
}

#[derive(Debug)]
pub struct RetiredNetRxQueue {
    ring: RetiredVirtQueue<PostedRxLease>,
    retained: Option<PostedRxLease>,
}

impl RetiredNetRxQueue {
    /// Returns one reset-aborted owner without claiming packet completion.
    #[expect(
        unsafe_code,
        reason = "construction requires observed quiescence of every retained packet DMA region"
    )]
    pub fn next_packet(&mut self) -> Option<CpuRxLease> {
        let lease = self.retained.take().or_else(|| self.ring.next_aborted())?;
        // SAFETY: quiesce required observed packet DMA stop for this exact queue
        // generation; the retired owner retains every untranslated packet lease.
        Some(unsafe { lease.quiesce() })
    }

    /// Extract RAM only after the caller has returned every packet lease.
    ///
    /// # Errors
    /// Returns the owner if any packet remains, preserving finalization duties.
    pub fn into_memory(mut self) -> Result<CpuDmaLease, Self> {
        if self.retained.is_some() {
            return Err(self);
        }
        if let Some(lease) = self.ring.next_aborted() {
            self.retained = Some(lease);
            return Err(self);
        }
        Ok(self.ring.memory)
    }
}

fn packet_segment(
    address: u64,
    bytes: usize,
    writable: bool,
) -> Result<QueueSegment, QueueAdmissionError> {
    let bytes =
        kernel_api::dma::DmaByteCount::new(bytes).ok_or(QueueAdmissionError::InvalidSegment)?;
    QueueSegment::new(
        kernel_api::dma::DmaDeviceAddress::from_abi(address),
        bytes,
        writable,
    )
}

fn admission_status(cause: QueueAdmissionError) -> AbiError {
    match cause {
        QueueAdmissionError::QueueFull => AbiError::DeviceBusy,
        QueueAdmissionError::EmptyChain | QueueAdmissionError::InvalidSegment => {
            AbiError::InvalidParam
        }
        QueueAdmissionError::Faulted(_) | QueueAdmissionError::Dma(_) => AbiError::IoError,
    }
}

#[derive(Debug)]
pub struct NetQueueBindError<T> {
    pub cause: AbiError,
    pub queue: super::NetCommandQueue<T>,
}

/// The framework's accepted packet lease remains live until a matching used
/// entry or device stop permits its exactly-once completion notification.
#[derive(Debug)]
pub struct NetTxNotification {
    lease: kernel_api::service::netdev::TxLeaseId,
    slot: usize,
    outcome: Option<kernel_api::abi::driver::AbiTxDeviceOutcome>,
}

#[derive(Debug)]
pub struct NetTxNotifyError {
    pub cause: AbiError,
    pub notification: NetTxNotification,
}

impl NetTxNotification {
    /// # Errors
    /// Callback failure returns the same notification, retaining its outcome.
    ///
    /// # Safety
    /// Stop must have ended this packet's device reads, and the runtime cookie,
    /// packet backing and callback code must remain retained through this call.
    #[expect(
        unsafe_code,
        reason = "only an observed device stop authorizes an aborted packet's runtime completion"
    )]
    pub unsafe fn finish_after_stop(
        mut self,
        runtime: kernel_api::abi::driver::AbiNetPortRuntime,
    ) -> Result<(), NetTxNotifyError> {
        if self.outcome.is_none() {
            self.outcome = Some(kernel_api::abi::driver::AbiTxDeviceOutcome::OUTCOME_UNKNOWN);
        }
        // SAFETY: the caller retains this runtime and establishes device stop;
        // an existing hardware completion keeps its known outcome unchanged.
        let status = unsafe { self.deliver(runtime) };
        if status.is_success() {
            Ok(())
        } else {
            Err(NetTxNotifyError {
                cause: status,
                notification: self,
            })
        }
    }

    #[expect(
        unsafe_code,
        reason = "notification delivery requires the retained foreign callback runtime and a known device release"
    )]
    unsafe fn deliver(&self, runtime: kernel_api::abi::driver::AbiNetPortRuntime) -> AbiError {
        let Some(outcome) = self.outcome else {
            return AbiError::DeviceBusy;
        };
        // SAFETY: the caller retains the runtime and packet owner through this
        // synchronous callback and proved the device ended its packet access.
        AbiError::from_raw(unsafe {
            (runtime.complete_tx_lease)(runtime.runtime_cookie, self.lease.get(), outcome)
        })
    }
}

#[derive(Debug)]
pub struct NetTxQueue {
    configuration: NetConfiguration,
    queue: super::NetCommandQueue<NetTxNotification>,
    occupied: [bool; 128],
    unreported: Option<NetTxNotification>,
}

impl NetTxQueue {
    /// # Errors
    /// Wrong protocol role or pair index returns both activated RAM owners.
    #[expect(
        clippy::result_large_err,
        reason = "binding rejects without dropping activated RAM or allocating a cleanup holder"
    )]
    pub fn bind(
        configuration: NetConfiguration,
        queue: super::NetCommandQueue<NetTxNotification>,
    ) -> Result<Self, NetQueueBindError<NetTxNotification>> {
        let index = queue.identity().index();
        if queue.layout().kind() != super::NetProtocolKind::Transmit
            || index & 1 == 0
            || index / 2 >= configuration.offered_pairs().get()
        {
            return Err(NetQueueBindError {
                cause: AbiError::InvalidParam,
                queue,
            });
        }
        Ok(Self {
            configuration,
            queue,
            occupied: [false; 128],
            unreported: None,
        })
    }

    pub const fn identity(&self) -> DmaQueueIdentity {
        self.queue.identity()
    }
    pub const fn maximum_segments(&self) -> u16 {
        self.queue.ring.capacity() - 1
    }
    pub fn pending_count(&self) -> usize {
        usize::from(self.queue.ring.pending_count()) + usize::from(self.unreported.is_some())
    }

    /// Synchronously borrow descriptors; retain only lease identity and protocol
    /// slot after acceptance. Packet payload is never read or copied here.
    ///
    /// # Errors
    /// Rejection has no publication effect and retains no packet lease. Both
    /// successful outcomes accept DMA ownership; uncertain publication requires
    /// device stop before its eventual OutcomeUnknown notification.
    ///
    /// # Safety
    /// The host retains immutable descriptor storage for this call and packet
    /// backing/read mappings until completion. DRIVER_OK and pair enablement
    /// precede submission. The runtime used for completion owns this TX lease.
    #[expect(
        unsafe_code,
        reason = "retained scatter-gather descriptors are borrowed only through the synchronous host callback"
    )]
    pub unsafe fn submit(
        &mut self,
        input: &kernel_api::abi::driver::AbiNetTxSubmission,
        meta: kernel_api::abi::driver::AbiNetTxMeta,
    ) -> Result<QueueSubmitOutcome, AbiError> {
        if meta.has_vlan_tag
            || meta.flags != 0
            || (meta.has_queue_index && meta.queue_index != self.identity().index() / 2)
        {
            return Err(AbiError::NotSupported);
        }
        let lease = input.lease_id().ok_or(AbiError::InvalidParam)?;
        // SAFETY: the host retains every initialized immutable descriptor for
        // this call; only its scalar device address and byte count are copied.
        let segments = unsafe { input.segments() }.ok_or(AbiError::InvalidParam)?;
        self.configuration
            .admit_transmit(segments, usize::from(self.maximum_segments()))?;
        let slot = self.occupied[..self.queue.layout.slot_count()]
            .iter()
            .position(|used| !used)
            .ok_or(AbiError::DeviceBusy)?;
        let offset = self
            .queue
            .layout
            .slot_offset(slot)
            .map_err(|_| AbiError::IoError)?;
        let mut header = self
            .queue
            .protocol
            .window(offset, NET_HEADER_BYTES)
            .map_err(|_| AbiError::IoError)?;
        header.write_u64(0, 0).map_err(|_| AbiError::IoError)?;
        header.write_u32(8, 0).map_err(|_| AbiError::IoError)?;
        let address = self
            .queue
            .address
            .checked_add(offset)
            .ok_or(AbiError::InvalidAddress)?;
        self.queue.segments.clear();
        self.queue.segments.push(
            packet_segment(address.get(), NET_HEADER_BYTES, false).map_err(admission_status)?,
        );
        for segment in segments.iter() {
            self.queue.segments.push(
                packet_segment(segment.device_addr(), segment.len().get(), false)
                    .map_err(admission_status)?,
            );
        }
        let notification = NetTxNotification {
            lease,
            slot,
            outcome: None,
        };
        // SAFETY: admitted packet mappings and protocol RAM remain retained by
        // the host/queue. Reserved scratch was acquired before RAM activation.
        let result = unsafe {
            self.queue
                .ring
                .publish(&self.queue.segments, notification, |owner| {
                    Ok::<
                        _,
                        crate::core::QueueCommandActivationError<
                            NetTxNotification,
                            core::convert::Infallible,
                        >,
                    >(owner)
                })
        };
        match result {
            Ok(outcome) => {
                self.occupied[slot] = true;
                Ok(outcome)
            }
            Err(failure) => Err(match failure.cause {
                QueueSubmitCause::Admission(cause) => admission_status(cause),
                QueueSubmitCause::Activation(never) => match never {},
            }),
        }
    }

    /// # Errors
    /// Ring corruption retains active packets; callback failure retains the
    /// completed notification and header slot before consuming a later entry.
    ///
    /// # Safety
    /// The issuing runtime cookie, code and packet backing remain retained
    /// through this synchronous callback and until each notification succeeds.
    #[expect(
        unsafe_code,
        reason = "the host retains the callback runtime for validated used-ring packet completion"
    )]
    pub unsafe fn poll(
        &mut self,
        runtime: kernel_api::abi::driver::AbiNetPortRuntime,
    ) -> Result<bool, NetTxPollError> {
        if self.unreported.is_none()
            && let Some(completion) = self
                .queue
                .ring
                .poll_completion()
                .map_err(NetTxPollError::Ring)?
        {
            let mut notification = completion.owner;
            notification.outcome = Some(kernel_api::abi::driver::AbiTxDeviceOutcome::TRANSMITTED);
            self.unreported = Some(notification);
        }
        deliver_tx_notification(&mut self.unreported, &mut self.occupied, |notification| {
            // SAFETY: a matching used head ended the packet's device reads; the
            // caller retains the issuing runtime and code throughout delivery.
            unsafe { notification.deliver(runtime) }
        })
    }

    /// # Errors
    /// Shared RAM failure leaves the caller responsible for continued polling.
    pub fn set_interrupts_enabled(&mut self, enabled: bool) -> Result<(), DmaLeaseError> {
        self.queue.ring.set_interrupts_enabled(enabled)
    }

    /// Separate retained hardware owners from an already completed notification
    /// for a stop state machine. This grants no packet or RAM quiescence.
    pub fn into_stopping(
        self,
    ) -> (
        super::NetCommandQueue<NetTxNotification>,
        Option<NetTxNotification>,
    ) {
        (self.queue, self.unreported)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetTxPollError {
    Ring(QueueFault),
    Notification(AbiError),
}

fn deliver_tx_notification(
    unreported: &mut Option<NetTxNotification>,
    occupied: &mut [bool],
    deliver: impl FnOnce(&NetTxNotification) -> AbiError,
) -> Result<bool, NetTxPollError> {
    let Some(notification) = unreported.as_ref() else {
        return Ok(false);
    };
    let Some(slot) = occupied.get_mut(notification.slot) else {
        return Err(NetTxPollError::Notification(AbiError::InvalidParam));
    };
    let result = deliver(notification);
    if !result.is_success() {
        return Err(NetTxPollError::Notification(result));
    }
    *slot = false;
    *unreported = None;
    Ok(true)
}

#[derive(Debug)]
pub struct NetControlQueue {
    configuration: NetConfiguration,
    queue: super::NetCommandQueue<super::QueuePairCommand>,
    unreported: Option<QueueCompletion<super::QueuePairCommand>>,
}

impl NetControlQueue {
    /// # Errors
    /// Protocol role/index disagreement returns all activated RAM owners.
    #[expect(
        clippy::result_large_err,
        reason = "binding failure preserves the activated control queue and its header RAM"
    )]
    pub fn bind(
        configuration: NetConfiguration,
        queue: super::NetCommandQueue<super::QueuePairCommand>,
    ) -> Result<Self, NetQueueBindError<super::QueuePairCommand>> {
        if queue.layout().kind() != super::NetProtocolKind::Control
            || configuration.control_queue_index().ok() != Some(queue.identity().index())
        {
            return Err(NetQueueBindError {
                cause: AbiError::InvalidParam,
                queue,
            });
        }
        Ok(Self {
            configuration,
            queue,
            unreported: None,
        })
    }
    pub const fn identity(&self) -> DmaQueueIdentity {
        self.queue.identity()
    }

    /// # Errors
    /// Admission/write failure returns the control request before publication.
    ///
    /// # Safety
    /// DRIVER_OK must be established for this device; the retained queue is its
    /// negotiated control queue and all protocol RAM is admitted for that device.
    #[expect(
        unsafe_code,
        reason = "the admitted control request publishes retained scalar protocol RAM through its split ring"
    )]
    pub unsafe fn submit(
        &mut self,
        command: super::QueuePairCommand,
    ) -> Result<QueueSubmitOutcome, NetControlSubmitError> {
        let result = (|| {
            if self.queue.ring.pending_count() != 0 || self.unreported.is_some() {
                return Err(AbiError::DeviceBusy);
            }
            if command.pairs() > self.configuration.offered_pairs() {
                return Err(AbiError::InvalidParam);
            }
            let mut data = self
                .queue
                .protocol
                .window(0, 8)
                .map_err(|_| AbiError::IoError)?;
            data.write_u32(0, u32::from_le_bytes(command.encode()))
                .map_err(|_| AbiError::IoError)?;
            data.write_u8(4, u8::MAX).map_err(|_| AbiError::IoError)?;
            self.queue.segments.clear();
            self.queue.segments.push(
                packet_segment(self.queue.address.get(), 4, false).map_err(admission_status)?,
            );
            let ack = self
                .queue
                .address
                .checked_add(4)
                .ok_or(AbiError::InvalidAddress)?;
            self.queue
                .segments
                .push(packet_segment(ack.get(), 1, true).map_err(admission_status)?);
            Ok(())
        })();
        if let Err(cause) = result {
            return Err(NetControlSubmitError { cause, command });
        }
        // SAFETY: the queue retains admitted protocol/header RAM throughout
        // activation, publication and ACK parsing. The caller establishes DRIVER_OK.
        let result = unsafe {
            self.queue
                .ring
                .publish(&self.queue.segments, command, |owner| {
                    Ok::<
                        _,
                        crate::core::QueueCommandActivationError<
                            super::QueuePairCommand,
                            core::convert::Infallible,
                        >,
                    >(owner)
                })
        };
        result.map_err(|failure| NetControlSubmitError {
            command: failure.owner,
            cause: match failure.cause {
                QueueSubmitCause::Admission(cause) => admission_status(cause),
                QueueSubmitCause::Activation(never) => match never {},
            },
        })
    }

    /// # Errors
    /// A failed ACK read retains the same consumed completion for retry. A
    /// malformed/rejected ACK returns its completed request and grants no pair
    /// enablement; ring corruption keeps the active command in the ring.
    pub fn poll(&mut self) -> Result<Option<super::EnabledQueuePairs>, NetControlPollError> {
        if self.unreported.is_none() {
            self.unreported = self
                .queue
                .ring
                .poll_completion()
                .map_err(NetControlPollError::Ring)?;
        }
        deliver_control_ack(&mut self.unreported, || {
            self.queue
                .protocol
                .window(4, 1)
                .and_then(|data| data.read_u8(0))
        })
    }

    pub fn into_stopping(
        self,
    ) -> (
        super::NetCommandQueue<super::QueuePairCommand>,
        Option<QueueCompletion<super::QueuePairCommand>>,
    ) {
        (self.queue, self.unreported)
    }
}

#[derive(Debug)]
pub struct NetControlSubmitError {
    pub cause: AbiError,
    pub command: super::QueuePairCommand,
}

#[derive(Debug)]
pub enum NetControlPollError {
    Ring(QueueFault),
    Status(DmaLeaseError),
    Rejected(super::QueuePairCommand),
}

fn deliver_control_ack(
    unreported: &mut Option<QueueCompletion<super::QueuePairCommand>>,
    read_status: impl FnOnce() -> Result<u8, DmaLeaseError>,
) -> Result<Option<super::EnabledQueuePairs>, NetControlPollError> {
    if unreported.is_none() {
        return Ok(None);
    }
    let status = read_status().map_err(NetControlPollError::Status)?;
    let Some(completion) = unreported.take() else {
        return Ok(None);
    };
    completion
        .owner
        .acknowledge(completion.written_bytes, status)
        .map(Some)
        .map_err(NetControlPollError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_api::abi::driver::AbiTxDeviceOutcome;
    use kernel_api::service::netdev::TxLeaseId;

    #[test]
    fn tx_notification_retry_preserves_lease_outcome_and_protocol_slot() {
        let mut occupied = [false, true, false];
        let mut notification = Some(NetTxNotification {
            lease: TxLeaseId::new(19).unwrap(),
            slot: 1,
            outcome: Some(AbiTxDeviceOutcome::TRANSMITTED),
        });
        assert_eq!(
            deliver_tx_notification(&mut notification, &mut occupied, |record| {
                assert_eq!(record.lease.get(), 19);
                assert_eq!(record.outcome, Some(AbiTxDeviceOutcome::TRANSMITTED));
                AbiError::DeviceBusy
            }),
            Err(NetTxPollError::Notification(AbiError::DeviceBusy))
        );
        assert!(occupied[1]);
        assert!(notification.is_some());
        assert_eq!(
            deliver_tx_notification(&mut notification, &mut occupied, |record| {
                assert_eq!(record.lease.get(), 19);
                assert_eq!(record.outcome, Some(AbiTxDeviceOutcome::TRANSMITTED));
                AbiError::Success
            }),
            Ok(true)
        );
        assert!(!occupied[1]);
        assert!(notification.is_none());
        assert_eq!(
            deliver_tx_notification(&mut notification, &mut occupied, |_| panic!(
                "acknowledged notification cannot be replayed"
            )),
            Ok(false)
        );
    }
}
