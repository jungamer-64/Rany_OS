// ============================================================================
// kernel/src/net/runtime/device/tx.rs - Per-port transmit admission
// ============================================================================
//! Per-port transmit admission and DMA lease state.
//!
//! An admitted frame is held only as device-visible regions. Owned packets are
//! consumed into regions and retained payloads are frozen, so no CPU handle can
//! write the transmitted bytes while a region exists. The regions keep the
//! backing out of its allocator until the driver's exactly-once completion, or
//! a successful port stop, releases them. Nothing is returned to a sender: a
//! sender that must retransmit keeps its own retained handle.
//!
//! Each lease moves through `Queued -> Submitting -> DeviceOwned -> Free` in
//! one slab owned by its port. A synchronous completion during submission is
//! recorded on the `Submitting` state and applied when the submission returns.
//!
//! A port with several TX queues keeps one FIFO and one worker per queue.
//! A frame's flow hash selects its queue, so the frames of one flow, and the
//! fragments of one datagram, stay in submission order.

extern crate alloc;

use crate::sync::PoisonLock;
use crate::sync::atomic_waker::AtomicWaker;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;
use kernel_api::resource::net::{
    PacketByteCount, PacketDmaRegion, PacketPayload, PacketPayloadFront, PacketRef,
    RetainedPayload, RetainedPayloadFront,
};
use kernel_api::service::netdev::{NetTxMeta, TxDeviceOutcome, TxLeaseId};

/// Number of frames a port may hold between admission and completion.
pub(crate) const TX_LEASE_CAPACITY: usize = 1024;

/// Upper bound on descriptors per frame, independent of what a device reports,
/// so lease storage stays bounded per port.
pub(crate) const TX_FRAME_MAX_SEGMENTS: usize = 16;

/// Leading body bytes that may be moved into a frame header to fit a device's
/// descriptor fan-out. Only protocol headers held in their own segment fit.
const TX_HEADER_COALESCE_MAX: usize = 64;

/// Upper bound on the TX queues a port drives, independent of the device.
pub(crate) const TX_MAX_QUEUES: usize = 8;

/// L3 body of a frame.
#[derive(Debug)]
pub(crate) enum TxBody {
    /// The sender gives up these bytes; they may still be extended in place.
    Owned(PacketPayload),
    /// Frozen bytes whose owner keeps a handle of its own.
    Retained(RetainedPayload),
}

impl TxBody {
    pub(crate) const fn payload(&self) -> &PacketPayload {
        match self {
            Self::Owned(payload) => payload,
            Self::Retained(retained) => retained.payload(),
        }
    }

    pub(crate) const fn total_len(&self) -> usize {
        self.payload().total_len()
    }

    pub(crate) fn into_retained(self) -> RetainedPayload {
        match self {
            Self::Owned(payload) => payload.into_retained(),
            Self::Retained(retained) => retained,
        }
    }

    fn segment_count(&self) -> usize {
        self.payload().segments().len()
    }

    /// Split off the first `len` bytes, keeping the variant of each part.
    fn try_take_front(self, len: PacketByteCount) -> Result<(Self, Self), Self> {
        match self {
            Self::Owned(payload) => match payload.try_take_front(len) {
                Ok(PacketPayloadFront::Prefix { front, remainder }) => {
                    Ok((Self::Owned(front), Self::Owned(remainder)))
                }
                Ok(PacketPayloadFront::Whole(payload)) => Err(Self::Owned(payload)),
                Err(error) => Err(Self::Owned(error.into_owner())),
            },
            Self::Retained(retained) => match retained.try_take_front(len) {
                Ok(RetainedPayloadFront::Prefix { front, remainder }) => {
                    Ok((Self::Retained(front), Self::Retained(remainder)))
                }
                Ok(RetainedPayloadFront::Whole(retained)) => Err(Self::Retained(retained)),
                Err(error) => Err(Self::Retained(error.into_owner())),
            },
        }
    }

    fn push_dma_regions(self, regions: &mut Vec<PacketDmaRegion>) {
        match self {
            Self::Owned(payload) => regions.extend(payload.into_dma_regions()),
            Self::Retained(retained) => regions.extend(retained.into_dma_regions()),
        }
    }
}

/// One wire frame: an optional generated header followed by its body.
#[derive(Debug)]
pub(crate) struct TxFrame {
    header: Option<PacketRef>,
    body: TxBody,
    /// Selects the TX queue; frames without one use the port's first queue.
    flow_hash: Option<u32>,
}

impl TxFrame {
    /// A frame whose bytes, headers included, are all in `payload`.
    pub(crate) const fn whole(payload: PacketPayload) -> Self {
        Self {
            header: None,
            body: TxBody::Owned(payload),
            flow_hash: None,
        }
    }

    /// A generated header packet followed by `body`.
    pub(crate) fn with_header(header: PacketRef, body: TxBody) -> Self {
        Self {
            header: (!header.is_empty()).then_some(header),
            body,
            flow_hash: None,
        }
    }

    /// Keep this frame on the TX queue of `flow_hash`.
    pub(crate) const fn in_flow(mut self, flow_hash: u32) -> Self {
        self.flow_hash = Some(flow_hash);
        self
    }

    pub(crate) fn total_len(&self) -> usize {
        self.header.as_ref().map_or(0, PacketRef::len) + self.body.total_len()
    }

    pub(crate) fn into_parts(self) -> (Option<PacketRef>, TxBody) {
        (self.header, self.body)
    }

    fn segment_count(&self) -> usize {
        usize::from(self.header.is_some()) + self.body.segment_count()
    }

    /// Fit the frame to `max_segments` descriptors by moving its smallest
    /// leading body segments into the header's tailroom. At most
    /// `TX_HEADER_COALESCE_MAX` bytes are copied; every other body byte stays
    /// in its segment. A frame that cannot fit is returned unchanged.
    fn fit_segments(mut self, max_segments: usize) -> Result<Self, Self> {
        let excess = self.segment_count().saturating_sub(max_segments);
        if excess == 0 {
            return Ok(self);
        }
        let Some(header) = self.header.as_ref() else {
            return Err(self);
        };
        let segments = self.body.payload().segments();
        // The body must keep at least one segment of its own.
        if excess >= segments.len() {
            return Err(self);
        }
        let moved_len: usize = segments[..excess].iter().map(PacketRef::len).sum();
        if moved_len > TX_HEADER_COALESCE_MAX || moved_len > header.tailroom() {
            return Err(self);
        }
        let Some(take) = PacketByteCount::new(moved_len) else {
            return Err(self);
        };
        let (front, remainder) = match self.body.try_take_front(take) {
            Ok(parts) => parts,
            Err(body) => {
                self.body = body;
                return Err(self);
            }
        };
        let Some(header) = self.header.as_mut() else {
            unreachable!("header presence was checked before splitting the body");
        };
        let header_len = header.len();
        if header.try_resize(header_len + moved_len).is_err() {
            unreachable!("header tailroom was checked before splitting the body");
        }
        let mut cursor = header_len;
        for segment in front.payload().segments() {
            let data = segment.data();
            header.data_mut()[cursor..cursor + data.len()].copy_from_slice(data);
            cursor += data.len();
        }
        self.body = remainder;
        Ok(self)
    }

    fn push_dma_regions(self, regions: &mut Vec<PacketDmaRegion>) {
        if let Some(header) = self.header
            && let Ok(region) = header.into_dma_region()
        {
            regions.push(region);
        }
        self.body.push_dma_regions(regions);
    }
}

/// Why a frame was not admitted. A rejected frame carries no device access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxAdmissionCause {
    /// The routed interface is not operational.
    InterfaceDown,
    /// No port is bound to the routed interface.
    PortUnavailable,
    /// The port is stopping or stopped and admits no new DMA work.
    PortStopped,
    /// Every lease of the port is outstanding.
    QueueFull,
    /// The frame needs more descriptors than the port accepts.
    TooManySegments,
    /// Lease descriptor storage could not be reserved.
    ResourceExhausted,
}

impl TxAdmissionCause {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InterfaceDown => "network interface is not operational",
            Self::PortUnavailable => "no device port is bound to the interface",
            Self::PortStopped => "device port admits no new transmissions",
            Self::QueueFull => "device TX leases are exhausted",
            Self::TooManySegments => "frame exceeds the device descriptor limit",
            Self::ResourceExhausted => "TX lease descriptor storage is unavailable",
        }
    }
}

/// A rejected frame, returned unchanged with its cause.
pub(crate) struct TxAdmissionError {
    cause: TxAdmissionCause,
    frame: TxFrame,
}

impl TxAdmissionError {
    pub(crate) const fn new(cause: TxAdmissionCause, frame: TxFrame) -> Self {
        Self { cause, frame }
    }

    pub(crate) const fn cause(&self) -> TxAdmissionCause {
        self.cause
    }

    pub(crate) fn into_frame(self) -> TxFrame {
        self.frame
    }
}

/// A completion that did not match an outstanding lease of this port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxCompletionError {
    /// The identifier names no outstanding lease of this port.
    UnknownLease,
    /// The lease is still queued and was never handed to the driver.
    NotSubmitted,
    /// The lease already received its completion.
    AlreadyCompleted,
}

impl TxCompletionError {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownLease => "TX lease does not belong to this port",
            Self::NotSubmitted => "TX lease was not submitted to the device",
            Self::AlreadyCompleted => "TX lease was already completed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxSlotState {
    Free,
    Queued,
    /// The regions are in the submitting worker's scratch. A completion that
    /// arrives before the driver call returns is recorded here.
    Submitting {
        completed: Option<TxDeviceOutcome>,
    },
    DeviceOwned,
}

struct TxSlot {
    generation: u32,
    state: TxSlotState,
    regions: Vec<PacketDmaRegion>,
    meta: NetTxMeta,
}

struct TxSlab {
    slots: Vec<TxSlot>,
    free: Vec<u32>,
    /// Admitted leases of each TX queue, oldest first.
    queued: Vec<VecDeque<u32>>,
    closed: bool,
}

impl TxSlab {
    fn lease_id(&self, index: u32) -> TxLeaseId {
        let raw = (u64::from(self.slots[index as usize].generation) << 32) | (u64::from(index) + 1);
        TxLeaseId::new(raw).unwrap_or_else(|| unreachable!("slot index encoding is non-zero"))
    }

    fn slot_index(&self, lease_id: TxLeaseId) -> Option<u32> {
        let raw = lease_id.get();
        let index = u32::try_from((raw & u64::from(u32::MAX)).checked_sub(1)?).ok()?;
        let generation = (raw >> 32) as u32;
        let slot = self.slots.get(index as usize)?;
        (slot.generation == generation && slot.state != TxSlotState::Free).then_some(index)
    }

    /// Release the slot's regions, returning backing to its allocators.
    fn free_slot(&mut self, index: u32) {
        let slot = &mut self.slots[index as usize];
        slot.regions.clear();
        slot.state = TxSlotState::Free;
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(index);
    }
}

/// Outcome counts of this port's leases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxLeaseStats {
    pub admitted: u64,
    pub transmitted: u64,
    pub not_transmitted: u64,
    pub outcome_unknown: u64,
    pub driver_rejected: u64,
    pub released_unsubmitted: u64,
    pub released_by_stop: u64,
}

#[derive(Default)]
struct TxLeaseCounters {
    admitted: AtomicU64,
    transmitted: AtomicU64,
    not_transmitted: AtomicU64,
    outcome_unknown: AtomicU64,
    driver_rejected: AtomicU64,
    released_unsubmitted: AtomicU64,
    released_by_stop: AtomicU64,
}

impl TxLeaseCounters {
    fn record_outcome(&self, outcome: TxDeviceOutcome) {
        let counter = match outcome {
            TxDeviceOutcome::Transmitted => &self.transmitted,
            TxDeviceOutcome::NotTransmitted => &self.not_transmitted,
            TxDeviceOutcome::OutcomeUnknown => &self.outcome_unknown,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Lease storage could not be allocated when the port was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TxPortAllocationError;

/// Transmit state of one port.
pub(crate) struct NetPortTx {
    slab: PoisonLock<TxSlab>,
    /// One per TX queue, woken when that queue gains a lease or the port closes.
    wakers: Vec<AtomicWaker>,
    max_segments: usize,
    counters: TxLeaseCounters,
}

impl NetPortTx {
    /// # Errors
    /// Fails when the lease table cannot be reserved.
    pub(crate) fn new(
        device_max_segments: usize,
        device_queues: usize,
    ) -> Result<Self, TxPortAllocationError> {
        let queues = device_queues.clamp(1, TX_MAX_QUEUES);
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(TX_LEASE_CAPACITY)
            .map_err(|_| TxPortAllocationError)?;
        let mut free = Vec::new();
        free.try_reserve_exact(TX_LEASE_CAPACITY)
            .map_err(|_| TxPortAllocationError)?;
        let mut queued = Vec::new();
        queued
            .try_reserve_exact(queues)
            .map_err(|_| TxPortAllocationError)?;
        let mut wakers = Vec::new();
        wakers
            .try_reserve_exact(queues)
            .map_err(|_| TxPortAllocationError)?;
        for _ in 0..queues {
            let mut fifo = VecDeque::new();
            fifo.try_reserve_exact(TX_LEASE_CAPACITY)
                .map_err(|_| TxPortAllocationError)?;
            queued.push(fifo);
            wakers.push(AtomicWaker::new());
        }
        for index in (0..TX_LEASE_CAPACITY as u32).rev() {
            slots.push(TxSlot {
                generation: 0,
                state: TxSlotState::Free,
                regions: Vec::new(),
                meta: NetTxMeta::default(),
            });
            free.push(index);
        }
        Ok(Self {
            slab: PoisonLock::new(TxSlab {
                slots,
                free,
                queued,
                closed: false,
            }),
            wakers,
            max_segments: device_max_segments.clamp(1, TX_FRAME_MAX_SEGMENTS),
            counters: TxLeaseCounters::default(),
        })
    }

    pub(crate) const fn max_segments(&self) -> usize {
        self.max_segments
    }

    pub(crate) fn queue_count(&self) -> usize {
        self.wakers.len()
    }

    pub(crate) fn stats(&self) -> TxLeaseStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        TxLeaseStats {
            admitted: load(&self.counters.admitted),
            transmitted: load(&self.counters.transmitted),
            not_transmitted: load(&self.counters.not_transmitted),
            outcome_unknown: load(&self.counters.outcome_unknown),
            driver_rejected: load(&self.counters.driver_rejected),
            released_unsubmitted: load(&self.counters.released_unsubmitted),
            released_by_stop: load(&self.counters.released_by_stop),
        }
    }

    /// Admit `frame` for transmission.
    ///
    /// # Errors
    /// Returns the unchanged frame when the port is closed, every lease is
    /// outstanding, the frame cannot fit the descriptor limit, or descriptor
    /// storage cannot be reserved.
    pub(crate) fn admit(&self, frame: TxFrame, meta: NetTxMeta) -> Result<(), TxAdmissionError> {
        let queue = frame
            .flow_hash
            .map_or(0, |hash| hash as usize % self.queue_count());
        let frame = frame
            .fit_segments(self.max_segments)
            .map_err(|frame| TxAdmissionError::new(TxAdmissionCause::TooManySegments, frame))?;
        let mut slab = self.slab.lock().unwrap_or_else(|error| error.into_inner());
        if slab.closed {
            return Err(TxAdmissionError::new(TxAdmissionCause::PortStopped, frame));
        }
        let Some(&index) = slab.free.last() else {
            return Err(TxAdmissionError::new(TxAdmissionCause::QueueFull, frame));
        };
        let slot = &mut slab.slots[index as usize];
        if slot.regions.capacity() < self.max_segments
            && slot
                .regions
                .try_reserve_exact(self.max_segments - slot.regions.capacity())
                .is_err()
        {
            return Err(TxAdmissionError::new(
                TxAdmissionCause::ResourceExhausted,
                frame,
            ));
        }
        frame.push_dma_regions(&mut slot.regions);
        slot.meta = NetTxMeta {
            queue_index: Some(queue as u16),
            ..meta
        };
        slot.state = TxSlotState::Queued;
        slab.free.pop();
        slab.queued[queue].push_back(index);
        drop(slab);
        self.counters.admitted.fetch_add(1, Ordering::Relaxed);
        self.wakers[queue].wake();
        Ok(())
    }

    /// Move the oldest lease queued on `queue` to `Submitting`, handing its
    /// regions to `scratch` for the descriptor visit. `scratch` must be empty.
    pub(crate) fn begin_submission(
        &self,
        queue: usize,
        scratch: &mut Vec<PacketDmaRegion>,
    ) -> Option<(TxLeaseId, NetTxMeta)> {
        let mut slab = self.slab.lock().unwrap_or_else(|error| error.into_inner());
        let index = slab.queued.get_mut(queue)?.pop_front()?;
        let lease_id = slab.lease_id(index);
        let slot = &mut slab.slots[index as usize];
        core::mem::swap(scratch, &mut slot.regions);
        slot.state = TxSlotState::Submitting { completed: None };
        Some((lease_id, slot.meta))
    }

    /// Apply the driver's answer to a submission begun by `begin_submission`.
    /// Acceptance keeps the regions until completion; rejection releases them.
    pub(crate) fn finish_submission(
        &self,
        lease_id: TxLeaseId,
        accepted: bool,
        scratch: &mut Vec<PacketDmaRegion>,
    ) {
        let mut slab = self.slab.lock().unwrap_or_else(|error| error.into_inner());
        let Some(index) = slab.slot_index(lease_id) else {
            scratch.clear();
            return;
        };
        let TxSlotState::Submitting { completed } = slab.slots[index as usize].state else {
            scratch.clear();
            return;
        };
        match (accepted, completed) {
            (true, None) => {
                let slot = &mut slab.slots[index as usize];
                core::mem::swap(scratch, &mut slot.regions);
                slot.state = TxSlotState::DeviceOwned;
            }
            (true, Some(outcome)) => {
                self.counters.record_outcome(outcome);
                scratch.clear();
                slab.free_slot(index);
            }
            (false, _) => {
                self.counters
                    .driver_rejected
                    .fetch_add(1, Ordering::Relaxed);
                scratch.clear();
                slab.free_slot(index);
            }
        }
    }

    /// Record the driver's exactly-once completion of an accepted lease.
    ///
    /// # Errors
    /// A lease of another port, a queued lease or a repeated completion is
    /// rejected without changing any lease.
    pub(crate) fn complete(
        &self,
        lease_id: TxLeaseId,
        outcome: TxDeviceOutcome,
    ) -> Result<(), TxCompletionError> {
        let mut slab = self.slab.lock().unwrap_or_else(|error| error.into_inner());
        let index = slab
            .slot_index(lease_id)
            .ok_or(TxCompletionError::UnknownLease)?;
        match slab.slots[index as usize].state {
            TxSlotState::Submitting { completed: None } => {
                slab.slots[index as usize].state = TxSlotState::Submitting {
                    completed: Some(outcome),
                };
                Ok(())
            }
            TxSlotState::Submitting { completed: Some(_) } => {
                Err(TxCompletionError::AlreadyCompleted)
            }
            TxSlotState::DeviceOwned => {
                self.counters.record_outcome(outcome);
                slab.free_slot(index);
                Ok(())
            }
            TxSlotState::Queued => Err(TxCompletionError::NotSubmitted),
            TxSlotState::Free => Err(TxCompletionError::UnknownLease),
        }
    }

    /// Stop admitting frames and release every lease not yet handed to the
    /// driver. Leases the driver may access are kept.
    pub(crate) fn close_and_release_queued(&self) {
        let mut slab = self.slab.lock().unwrap_or_else(|error| error.into_inner());
        slab.closed = true;
        for queue in 0..slab.queued.len() {
            // LOOP_PROOF: mode=condition; reason=Each iteration removes one index from the finite queued list under the slab lock, which no producer holds.;
            while let Some(index) = slab.queued[queue].pop_front() {
                slab.free_slot(index);
                self.counters
                    .released_unsubmitted
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(slab);
        for waker in &self.wakers {
            waker.wake();
        }
    }

    /// Release every accepted lease after the driver proved that device
    /// access to them has ended. A lease still being submitted is released by
    /// its worker when the submission returns.
    pub(crate) fn release_after_stop(&self) {
        let mut slab = self.slab.lock().unwrap_or_else(|error| error.into_inner());
        for index in 0..slab.slots.len() as u32 {
            if slab.slots[index as usize].state == TxSlotState::DeviceOwned {
                slab.free_slot(index);
                self.counters
                    .released_by_stop
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn has_queued(&self, queue: usize) -> bool {
        self.slab
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .queued
            .get(queue)
            .is_some_and(|fifo| !fifo.is_empty())
    }

    pub(crate) fn register_waker(&self, queue: usize, waker: &Waker) {
        if let Some(queue_waker) = self.wakers.get(queue) {
            queue_waker.register(waker);
        }
    }
}
