// ============================================================================
// kernel/src/net/runtime/device/mod.rs - ランタイム / device モジュール
// ============================================================================
//! Shared network port runtime.
//!
//! This layer owns port registration, interface binding, TX queuing, ISR-safe
//! event delivery, and the runtime object exposed to driver adapters.

extern crate alloc;

use crate::net::l2::ethernet::MacAddress as StackMacAddress;
use crate::net::l3::ipv4::Ipv4Config;
use crate::net::runtime::NetRuntimeHandle;
#[cfg(test)]
use crate::net::runtime::context::default_runtime_context;
use crate::net::runtime::context::{self, NetRuntimeContext, NetRuntimeGeneration, NetRuntimeId};
use crate::net::runtime::manager::{self, NetIfId};
use crate::net::runtime::stack::{self, NetworkConfig};
use crate::sync::atomic_waker::AtomicWaker;
use crate::sync::lockfree::MpmcRingBuffer;
use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::num::NonZeroUsize;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use kernel_api::resource::net::{PacketByteCount, PacketPayload, PacketRef};
use kernel_api::service::netdev::{
    MacAddress, NETDEV_FLAG_ADMIN_UP, NETDEV_FLAG_BOUND_PORT, NETDEV_FLAG_HEALTHY,
    NETDEV_FLAG_LINK_UP, NETDEV_FLAG_PRIMARY, NetDeviceInfo, NetDevicePort, NetDriverEvent,
    NetLogLevel, NetPortId, NetPortRegistration, NetPortRuntimeCookie, NetPortRuntimeHandle,
    NetPortRuntimeOps, NetPortStats, NetRxMeta, NetTxMeta, NetTxSegment, NonEmptyTxSegments,
    PrimaryPortPolicy, ReceivedPacket, RxBuffer, TxDeviceOutcome, TxLeaseId, TxSubmission,
};

const NET_DEVICE_TX_QUEUE_CAPACITY: usize = 1024;
const NET_DEVICE_EVENT_QUEUE_CAPACITY: usize = 256;

type TxCompletionResult = Result<(), &'static str>;

const fn tx_outcome_result(outcome: TxDeviceOutcome) -> TxCompletionResult {
    match outcome {
        TxDeviceOutcome::Transmitted => Ok(()),
        TxDeviceOutcome::NotTransmitted => Err("device did not transmit packet"),
        TxDeviceOutcome::OutcomeUnknown => Err("device TX outcome is unknown"),
    }
}

pub(crate) struct TxCompletionState {
    result: PoisonLock<Option<TxCompletionResult>>,
    waker: AtomicWaker,
}

impl TxCompletionState {
    fn new() -> Self {
        Self {
            result: PoisonLock::new(None),
            waker: AtomicWaker::new(),
        }
    }

    fn complete(&self, result: TxCompletionResult) {
        if let Ok(mut slot) = self.result.lock() {
            *slot = Some(result);
        }
        self.waker.wake();
    }
}

pub(crate) struct TxLeaseState {
    if_id: NetIfId,
    owners: TxPayloadOwners,
    descriptor_plan: TxDescriptorPlan,
    completion_id: Option<u64>,
    owner_group_id: Option<u64>,
    phase: TxLeasePhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxLeasePhase {
    Queued,
    Submitting,
    DeviceOwned,
}

impl TxLeaseState {
    fn new(
        if_id: NetIfId,
        owners: TxPayloadOwners,
        descriptor_plan: TxDescriptorPlan,
        completion_id: Option<u64>,
    ) -> Self {
        Self {
            if_id,
            owners,
            descriptor_plan,
            completion_id,
            owner_group_id: None,
            phase: TxLeasePhase::Queued,
        }
    }

    fn grouped(
        if_id: NetIfId,
        owners: TxPayloadOwners,
        descriptor_plan: TxDescriptorPlan,
        owner_group_id: u64,
    ) -> Self {
        Self {
            if_id,
            owners,
            descriptor_plan,
            completion_id: None,
            owner_group_id: Some(owner_group_id),
            phase: TxLeasePhase::Queued,
        }
    }
}

pub(crate) struct TxOwnerGroupState {
    owners: TxPayloadOwners,
    completion_id: Option<u64>,
    remaining_leases: TxOwnerGroupLeaseCount,
    outcome: TxDeviceOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TxOwnerGroupLeaseCount(NonZeroUsize);

impl TxOwnerGroupLeaseCount {
    pub(crate) const fn new(leases: usize) -> Option<Self> {
        match NonZeroUsize::new(leases) {
            Some(leases) => Some(Self(leases)),
            None => None,
        }
    }

    const fn get(self) -> usize {
        self.0.get()
    }
}

pub(crate) struct TxPayloadOwners {
    payload: PacketPayload,
}

impl TxPayloadOwners {
    pub(crate) fn from_payload(payload: PacketPayload) -> Option<Self> {
        Some(Self { payload })
    }

    pub(crate) fn from_packets(packets: Vec<PacketRef>) -> Option<Self> {
        PacketPayload::try_from_segments(packets)
            .ok()
            .map(|payload| Self { payload })
    }

    fn as_packets(&self) -> &[PacketRef] {
        self.payload.segments()
    }

    fn total_len(&self) -> Option<usize> {
        self.payload
            .segments()
            .iter()
            .try_fold(0usize, |total, packet| total.checked_add(packet.len()))
    }

    fn into_payload(self) -> PacketPayload {
        self.payload
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TxPayloadWindowBounds {
    offset: usize,
    len: PacketByteCount,
}

impl TxPayloadWindowBounds {
    pub(crate) fn checked(
        owners: &TxPayloadOwners,
        offset: usize,
        len: PacketByteCount,
    ) -> Option<Self> {
        let total_len = owners.total_len()?;
        if offset > total_len || len.get() > total_len.saturating_sub(offset) {
            return None;
        }
        Some(Self { offset, len })
    }

    const fn offset(self) -> usize {
        self.offset
    }

    const fn len(self) -> usize {
        self.len.get()
    }
}

pub(crate) struct TxPayloadLease {
    owners: TxPayloadOwners,
    descriptor_plan: TxDescriptorPlan,
}

#[derive(Clone, Copy, Debug)]
enum TxDescriptorPlan {
    FullPayload,
    HeaderAndOwnerWindow(TxPayloadWindowBounds),
}

impl TxPayloadLease {
    pub(crate) fn from_payload(payload: PacketPayload) -> Result<Self, PacketPayload> {
        let owners = TxPayloadOwners { payload };
        Ok(Self {
            owners,
            descriptor_plan: TxDescriptorPlan::FullPayload,
        })
    }

    pub(crate) fn from_header_and_owner_window(
        header: PacketRef,
        owners: &TxPayloadOwners,
        bounds: TxPayloadWindowBounds,
    ) -> Option<Self> {
        if TxPayloadWindowBounds::checked(owners, bounds.offset, bounds.len)? != bounds {
            return None;
        }
        let owners = TxPayloadOwners::from_payload(PacketPayload::try_single(header).ok()?)?;
        Some(Self {
            owners,
            descriptor_plan: TxDescriptorPlan::HeaderAndOwnerWindow(bounds),
        })
    }

    fn into_parts(self) -> (TxPayloadOwners, TxDescriptorPlan) {
        (self.owners, self.descriptor_plan)
    }
}

impl TxOwnerGroupState {
    fn new(
        owners: TxPayloadOwners,
        completion_id: Option<u64>,
        remaining_leases: TxOwnerGroupLeaseCount,
    ) -> Self {
        Self {
            owners,
            completion_id,
            remaining_leases,
            outcome: TxDeviceOutcome::Transmitted,
        }
    }

    fn complete_one(&mut self, outcome: TxDeviceOutcome) -> bool {
        self.outcome = match (self.outcome, outcome) {
            (TxDeviceOutcome::OutcomeUnknown, _) | (_, TxDeviceOutcome::OutcomeUnknown) => {
                TxDeviceOutcome::OutcomeUnknown
            }
            (TxDeviceOutcome::NotTransmitted, _) | (_, TxDeviceOutcome::NotTransmitted) => {
                TxDeviceOutcome::NotTransmitted
            }
            _ => TxDeviceOutcome::Transmitted,
        };
        let remaining = self.remaining_leases.get();
        if remaining == 1 {
            return true;
        }
        self.remaining_leases =
            TxOwnerGroupLeaseCount::new(remaining - 1).expect("remaining lease stays non-zero");
        false
    }

    fn into_parts(self) -> (TxPayloadOwners, Option<u64>, TxDeviceOutcome) {
        (self.owners, self.completion_id, self.outcome)
    }
}

fn complete_tx_owner_group_in(
    runtime: NetRuntimeHandle,
    group_id: u64,
    outcome: TxDeviceOutcome,
) -> bool {
    let completed = {
        let mut groups = runtime_context_for(runtime)
            .tx_owner_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(group) = groups.get_mut(&group_id) else {
            return false;
        };
        if !group.complete_one(outcome) {
            return true;
        }
        groups.remove(&group_id)
    };

    let Some(group) = completed else {
        return false;
    };
    let (owners, completion_id, final_outcome) = group.into_parts();
    if let Some(completion_id) = completion_id {
        let _owner_returned = crate::net::l4::tcp::retransmit::complete_tx_owner(
            runtime,
            completion_id,
            owners.into_payload(),
            final_outcome,
        );
        let _ = complete_tx_request_in(runtime, completion_id, tx_outcome_result(final_outcome));
    }
    true
}

pub(crate) fn register_tx_owner_group_in(
    runtime: NetRuntimeHandle,
    owners: TxPayloadOwners,
    remaining_leases: TxOwnerGroupLeaseCount,
    completion_id: Option<u64>,
) -> u64 {
    let group_id = runtime_context_for(runtime)
        .tx_owner_group_next_id
        .fetch_add(1, Ordering::Relaxed);
    runtime_context_for(runtime)
        .tx_owner_groups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            group_id,
            TxOwnerGroupState::new(owners, completion_id, remaining_leases),
        );
    group_id
}

pub(crate) fn unregister_tx_owner_group_in(runtime: NetRuntimeHandle, group_id: u64) {
    runtime_context_for(runtime)
        .tx_owner_groups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&group_id);
}

pub struct TxCompletionFuture {
    runtime: NetRuntimeHandle,
    completion_id: u64,
}

impl Future for TxCompletionFuture {
    type Output = TxCompletionResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let completion = self.as_ref().get_ref();
        let context = runtime_context_for(completion.runtime);
        let mut ready = None;
        let mut missing = false;

        {
            let completions = context
                .tx_completions
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(state) = completions.get(&completion.completion_id) {
                if let Ok(mut slot) = state.result.lock() {
                    ready = slot.take();
                }
                if ready.is_none() {
                    state.waker.register(cx.waker());
                    if let Ok(mut slot) = state.result.lock() {
                        ready = slot.take();
                    }
                }
            } else {
                missing = true;
            }
        }

        if let Some(result) = ready {
            context
                .tx_completions
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&completion.completion_id);
            return Poll::Ready(result);
        }
        if missing {
            return Poll::Ready(Err("tx completion missing"));
        }
        Poll::Pending
    }
}

impl Drop for TxCompletionFuture {
    fn drop(&mut self) {
        runtime_context_for(self.runtime)
            .tx_completions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.completion_id);
    }
}

fn runtime_context_for(runtime: NetRuntimeHandle) -> &'static NetRuntimeContext {
    runtime.context()
}

fn device_manager_in(runtime: NetRuntimeHandle) -> &'static PoisonRwLock<NetDeviceManager> {
    &runtime_context_for(runtime).device_manager
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetDeviceBinding {
    pub port_id: NetPortId,
    pub if_id: NetIfId,
}

#[derive(Debug)]
pub(crate) struct TxRequest {
    pub(crate) lease_id: TxLeaseId,
    pub(crate) meta: NetTxMeta,
}

pub struct NetTxQueue {
    queue: MpmcRingBuffer<TxRequest, NET_DEVICE_TX_QUEUE_CAPACITY>,
    waker: AtomicWaker,
}

impl NetTxQueue {
    pub const CAPACITY: usize = NET_DEVICE_TX_QUEUE_CAPACITY;

    pub fn new() -> Self {
        Self {
            queue: MpmcRingBuffer::new(),
            waker: AtomicWaker::new(),
        }
    }

    fn push(&self, request: TxRequest) -> Result<(), TxRequest> {
        match self.queue.push(request) {
            Ok(()) => {
                self.waker.wake();
                Ok(())
            }
            Err(request) => Err(request),
        }
    }

    fn pop(&self) -> Option<TxRequest> {
        self.queue.pop()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub const fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn wake(&self) {
        self.waker.wake();
    }

    pub fn wait(&self) -> NetTxQueueWaitFuture<'_> {
        NetTxQueueWaitFuture { queue: self }
    }
}

pub(crate) struct RegisteredTx {
    runtime: NetRuntimeHandle,
    request: Option<TxRequest>,
    rollback_reason: TxCompletionResult,
}

impl RegisteredTx {
    fn new(runtime: NetRuntimeHandle, request: TxRequest) -> Self {
        Self {
            runtime,
            request: Some(request),
            rollback_reason: Err("device TX request was not queued"),
        }
    }

    fn commit_to_queue(mut self, queue: &NetTxQueue) -> Result<(), Self> {
        let request = self
            .request
            .take()
            .expect("registered TX request missing before commit");
        match queue.push(request) {
            Ok(()) => {
                core::mem::forget(self);
                Ok(())
            }
            Err(request) => {
                self.rollback_reason = Err("device TX queue full");
                self.request = Some(request);
                Err(self)
            }
        }
    }

    fn into_request(mut self) -> TxRequest {
        let request = self
            .request
            .take()
            .expect("registered TX request missing before handoff");
        core::mem::forget(self);
        request
    }

    fn into_rejected_payload(mut self) -> PacketPayload {
        let request = self
            .request
            .take()
            .expect("registered TX request missing before rejection");
        let lease = runtime_context_for(self.runtime)
            .tx_leases
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&request.lease_id)
            .expect("registered TX lease missing before queue admission");
        core::mem::forget(self);
        lease.owners.into_payload()
    }
}

impl Drop for RegisteredTx {
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            let reason = self
                .rollback_reason
                .err()
                .unwrap_or("device TX request was not queued");
            let _ = reject_tx_lease_in(self.runtime, request.lease_id, reason);
        }
    }
}

pub struct NetEventSink {
    queue: MpmcRingBuffer<NetDriverEvent, NET_DEVICE_EVENT_QUEUE_CAPACITY>,
    waker: AtomicWaker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventWakeContext {
    Task,
    Interrupt,
}

impl NetEventSink {
    pub const CAPACITY: usize = NET_DEVICE_EVENT_QUEUE_CAPACITY;

    pub fn new() -> Self {
        Self {
            queue: MpmcRingBuffer::new(),
            waker: AtomicWaker::new(),
        }
    }

    fn push(&self, event: NetDriverEvent, context: EventWakeContext) -> bool {
        match self.queue.push(event) {
            Ok(()) => {
                match context {
                    EventWakeContext::Task => self.waker.wake(),
                    EventWakeContext::Interrupt => self.waker.wake_from_isr(),
                }
                true
            }
            Err(_) => false,
        }
    }

    pub fn pop(&self) -> Option<NetDriverEvent> {
        self.queue.pop()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub const fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn wake(&self) {
        self.waker.wake();
    }

    pub fn wait(&self) -> NetEventWaitFuture<'_> {
        NetEventWaitFuture { sink: self }
    }
}

pub struct NetTxQueueWaitFuture<'a> {
    queue: &'a NetTxQueue,
}

impl Future for NetTxQueueWaitFuture<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.queue.is_empty() {
            return Poll::Ready(());
        }
        self.queue.waker.register(cx.waker());
        if !self.queue.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

pub struct NetEventWaitFuture<'a> {
    sink: &'a NetEventSink,
}

impl Future for NetEventWaitFuture<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.sink.is_empty() {
            return Poll::Ready(());
        }
        self.sink.waker.register(cx.waker());
        if !self.sink.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

pub fn register_tx_completion_in(runtime: NetRuntimeHandle) -> (u64, TxCompletionFuture) {
    let context = runtime_context_for(runtime);
    let completion_id = context
        .tx_completion_next_id
        .fetch_add(1, Ordering::Relaxed);
    context
        .tx_completions
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(completion_id, TxCompletionState::new());
    (
        completion_id,
        TxCompletionFuture {
            runtime,
            completion_id,
        },
    )
}

pub fn complete_tx_request_in(
    runtime: NetRuntimeHandle,
    completion_id: u64,
    result: TxCompletionResult,
) -> bool {
    let completions = runtime_context_for(runtime)
        .tx_completions
        .read()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(state) = completions.get(&completion_id) {
        state.complete(result);
        true
    } else {
        false
    }
}

fn packet_to_tx_segment(packet: &PacketRef) -> Option<NetTxSegment> {
    let len = PacketByteCount::new(packet.len())?;
    NetTxSegment::from_dma(
        packet.data().as_ptr(),
        packet.phys_addr().as_u64(),
        packet.device_address(),
        len,
    )
}

fn append_tx_payload_segments(
    descriptors: &mut Vec<NetTxSegment>,
    packets: &[PacketRef],
    max_segments: usize,
) -> Option<()> {
    for packet in packets {
        if descriptors.len() >= max_segments {
            return None;
        }
        descriptors.push(packet_to_tx_segment(packet)?);
    }
    Some(())
}

fn append_tx_payload_window_segments(
    descriptors: &mut Vec<NetTxSegment>,
    packets: &[PacketRef],
    bounds: TxPayloadWindowBounds,
    max_segments: usize,
) -> Option<()> {
    let mut cursor = 0usize;
    let offset = bounds.offset();
    let window_end = offset.checked_add(bounds.len())?;
    for packet in packets {
        let packet_start = cursor;
        let packet_end = cursor.checked_add(packet.len())?;
        cursor = packet_end;
        if packet_end <= offset || packet_start >= window_end {
            continue;
        }
        let local_start = offset.saturating_sub(packet_start);
        let local_end = packet.len().min(window_end.saturating_sub(packet_start));
        if local_start >= local_end {
            continue;
        }
        if descriptors.len() >= max_segments {
            return None;
        }
        let descriptor_len = PacketByteCount::new(local_end - local_start)?;
        let cpu_ptr = unsafe { packet.data().as_ptr().add(local_start) };
        let physical_addr = packet
            .phys_addr()
            .as_u64()
            .checked_add(local_start as u64)?;
        let device_addr = packet.device_address().checked_add(local_start as u64)?;
        descriptors.push(NetTxSegment::from_dma(
            cpu_ptr,
            physical_addr,
            device_addr,
            descriptor_len,
        )?);
    }

    Some(())
}

fn build_tx_descriptors_in(
    runtime: NetRuntimeHandle,
    lease_id: TxLeaseId,
    descriptors: &mut Vec<NetTxSegment>,
    max_segments: usize,
) -> Option<()> {
    descriptors.clear();
    let leases = runtime_context_for(runtime)
        .tx_leases
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let lease = leases.get(&lease_id)?;
    match lease.descriptor_plan {
        TxDescriptorPlan::FullPayload => {
            append_tx_payload_segments(descriptors, lease.owners.as_packets(), max_segments)?;
        }
        TxDescriptorPlan::HeaderAndOwnerWindow(bounds) => {
            append_tx_payload_segments(descriptors, lease.owners.as_packets(), max_segments)?;
            let group_id = lease.owner_group_id?;
            let groups = runtime_context_for(runtime)
                .tx_owner_groups
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let group = groups.get(&group_id)?;
            append_tx_payload_window_segments(
                descriptors,
                group.owners.as_packets(),
                bounds,
                max_segments,
            )?;
        }
    }
    (!descriptors.is_empty()).then_some(())
}

fn next_tx_lease_id(runtime: NetRuntimeHandle) -> TxLeaseId {
    let context = runtime_context_for(runtime);
    // LOOP_PROOF: mode=condition; reason=Only the single zero value is skipped after counter wrap.;
    loop {
        let raw = context.tx_lease_next_id.fetch_add(1, Ordering::Relaxed);
        if let Some(id) = TxLeaseId::new(raw) {
            return id;
        }
    }
}

pub(crate) fn register_grouped_tx_payload_lease_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    lease: TxPayloadLease,
    owner_group_id: u64,
    meta: NetTxMeta,
) -> Option<TxRequest> {
    let (owners, descriptor_plan) = lease.into_parts();
    let lease_id = next_tx_lease_id(runtime);
    runtime_context_for(runtime)
        .tx_leases
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            lease_id,
            TxLeaseState::grouped(if_id, owners, descriptor_plan, owner_group_id),
        );
    Some(TxRequest { lease_id, meta })
}

pub(crate) fn register_tx_payload_lease_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    lease: TxPayloadLease,
    completion_id: Option<u64>,
    meta: NetTxMeta,
) -> Option<RegisteredTx> {
    let (owners, descriptor_plan) = lease.into_parts();
    let lease_id = next_tx_lease_id(runtime);
    let state = TxLeaseState::new(if_id, owners, descriptor_plan, completion_id);
    runtime_context_for(runtime)
        .tx_leases
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(lease_id, state);
    Some(RegisteredTx::new(runtime, TxRequest { lease_id, meta }))
}

fn register_payload_tx_request_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    payload: PacketPayload,
    meta: NetTxMeta,
    completion_id: Option<u64>,
) -> Result<RegisteredTx, PacketPayload> {
    let lease = TxPayloadLease::from_payload(payload)?;
    register_tx_payload_lease_in(runtime, if_id, lease, completion_id, meta)
        .ok_or_else(|| unreachable!("TX lease identifiers are always non-zero"))
}

pub fn complete_tx_lease_in(
    runtime: NetRuntimeHandle,
    lease_id: TxLeaseId,
    outcome: TxDeviceOutcome,
) -> bool {
    let lease = {
        let mut leases = runtime_context_for(runtime)
            .tx_leases
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(state) = leases.get(&lease_id) else {
            return false;
        };
        if state.phase == TxLeasePhase::Queued {
            return false;
        }
        leases.remove(&lease_id)
    };
    finalize_tx_lease_in(runtime, lease, outcome)
}

fn finalize_tx_lease_in(
    runtime: NetRuntimeHandle,
    lease: Option<TxLeaseState>,
    outcome: TxDeviceOutcome,
) -> bool {
    let Some(lease) = lease else {
        return false;
    };
    if let Some(owner_group_id) = lease.owner_group_id {
        let _ = complete_tx_owner_group_in(runtime, owner_group_id, outcome);
        return true;
    }
    if let Some(completion_id) = lease.completion_id {
        let _owner_returned = crate::net::l4::tcp::retransmit::complete_tx_owner(
            runtime,
            completion_id,
            lease.owners.into_payload(),
            outcome,
        );
        let _ = complete_tx_request_in(runtime, completion_id, tx_outcome_result(outcome));
    }
    true
}

#[derive(Clone, Copy)]
enum TxLeaseReleaseScope {
    QueuedOnly,
    All,
}

fn release_interface_tx_leases_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    scope: TxLeaseReleaseScope,
    outcome: TxDeviceOutcome,
) {
    loop {
        let lease = {
            let mut leases = runtime_context_for(runtime)
                .tx_leases
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let lease_id = leases.iter().find_map(|(lease_id, lease)| {
                let phase_matches = match scope {
                    TxLeaseReleaseScope::QueuedOnly => lease.phase == TxLeasePhase::Queued,
                    TxLeaseReleaseScope::All => true,
                };
                (lease.if_id == if_id && phase_matches).then_some(*lease_id)
            });
            lease_id.and_then(|lease_id| leases.remove(&lease_id))
        };
        let Some(lease) = lease else {
            break;
        };
        let _ = finalize_tx_lease_in(runtime, Some(lease), outcome);
    }
}

fn reject_tx_lease_in(
    runtime: NetRuntimeHandle,
    lease_id: TxLeaseId,
    reason: &'static str,
) -> bool {
    let lease = runtime_context_for(runtime)
        .tx_leases
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&lease_id);
    let _ = reason;
    finalize_tx_lease_in(runtime, lease, TxDeviceOutcome::NotTransmitted)
}

pub(crate) fn reject_registered_tx_lease_in(
    runtime: NetRuntimeHandle,
    lease_id: TxLeaseId,
    reason: &'static str,
) -> bool {
    reject_tx_lease_in(runtime, lease_id, reason)
}

fn begin_tx_submission_in(runtime: NetRuntimeHandle, lease_id: TxLeaseId) -> bool {
    let mut leases = runtime_context_for(runtime)
        .tx_leases
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(lease) = leases.get_mut(&lease_id) else {
        return false;
    };
    if lease.phase != TxLeasePhase::Queued {
        return false;
    }
    lease.phase = TxLeasePhase::Submitting;
    true
}

fn mark_tx_device_owned_in(runtime: NetRuntimeHandle, lease_id: TxLeaseId) -> bool {
    let mut leases = runtime_context_for(runtime)
        .tx_leases
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(lease) = leases.get_mut(&lease_id) else {
        // A synchronous completion may have released the lease before submit
        // returned; absence is therefore a valid accepted outcome.
        return true;
    };
    if lease.phase != TxLeasePhase::Submitting {
        return false;
    }
    lease.phase = TxLeasePhase::DeviceOwned;
    true
}

#[derive(Clone, Copy)]
struct RuntimeHandleId {
    runtime_id: NetRuntimeId,
    generation: NetRuntimeGeneration,
}

impl RuntimeHandleId {
    fn from_context(context: &'static NetRuntimeContext) -> Option<Self> {
        Some(Self {
            runtime_id: context.id(),
            generation: context.generation(),
        })
    }

    fn from_cookie(cookie: NetPortRuntimeCookie) -> Option<Self> {
        let raw = u64::try_from(cookie.as_raw()).ok()?.checked_sub(1)?;
        let id = raw & u32::MAX as u64;
        let generation = raw >> 32;
        let generation = u32::try_from(generation).ok()?;
        Some(Self {
            runtime_id: NetRuntimeId(id),
            generation: NetRuntimeGeneration::from_raw(generation),
        })
    }

    fn into_cookie(self) -> Option<NetPortRuntimeCookie> {
        let id = u32::try_from(self.runtime_id.0).ok()? as u64;
        let raw = ((self.generation.raw() as u64) << 32) | id;
        NetPortRuntimeCookie::from_raw(usize::try_from(raw.checked_add(1)?).ok()?)
    }

    fn context(self) -> Option<&'static NetRuntimeContext> {
        context::runtime_with_generation(self.runtime_id, self.generation)
            .map(NetRuntimeHandle::context)
    }
}

fn runtime_context_from_cookie(
    cookie: NetPortRuntimeCookie,
) -> Result<&'static NetRuntimeContext, &'static str> {
    RuntimeHandleId::from_cookie(cookie)
        .and_then(RuntimeHandleId::context)
        .ok_or("network runtime cookie is not registered")
}

fn runtime_handle_for_port(
    context: &'static NetRuntimeContext,
    port_id: NetPortId,
) -> NetPortRuntimeHandle {
    NetPortRuntimeHandle::new(
        RuntimeHandleId::from_context(context)
            .and_then(RuntimeHandleId::into_cookie)
            .expect("runtime ids are stored as non-zero driver cookies"),
        port_id,
        &NET_PORT_RUNTIME_OPS,
    )
}

fn current_if_for_port(
    context: &'static NetRuntimeContext,
    port_id: NetPortId,
) -> Result<NetIfId, &'static str> {
    context
        .device_manager
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .port_map
        .get(&port_id)
        .copied()
        .ok_or("device port not registered")
}

fn runtime_lease_rx_buffer(cookie: NetPortRuntimeCookie, _: NetPortId) -> Option<RxBuffer> {
    let context = runtime_context_from_cookie(cookie).ok()?;
    let packet = crate::net::datapath::mempool::alloc_packet_in(context.handle())?;
    RxBuffer::try_from_empty_packet(packet).ok()
}

fn runtime_submit_rx(
    cookie: NetPortRuntimeCookie,
    port_id: NetPortId,
    received: ReceivedPacket,
) -> Result<(), &'static str> {
    let context = runtime_context_from_cookie(cookie)?;
    let if_id = current_if_for_port(context, port_id)?;
    if !manager::is_interface_operational_in(context.handle(), if_id) {
        return Err("network interface is not operational");
    }
    let (mut packet, meta) = received.into_parts();
    if meta.flags() & kernel_api::netdev::NET_RX_FLAG_IP_CSUM_VERIFIED != 0 {
        packet.meta_mut().set_ip_csum_verified();
    }
    if meta.flags() & kernel_api::netdev::NET_RX_FLAG_L4_CSUM_VERIFIED != 0 {
        packet.meta_mut().set_l4_csum_verified();
    }
    crate::net::runtime::bridge::process_received_packet_zero_copy_for_interface_in(
        context.handle(),
        if_id,
        packet,
        meta.layout().header_len(),
        meta.layout().payload_len(),
    );
    Ok(())
}

fn runtime_complete_tx_lease(
    cookie: NetPortRuntimeCookie,
    _port_id: NetPortId,
    lease_id: TxLeaseId,
    outcome: TxDeviceOutcome,
) -> Result<(), &'static str> {
    let runtime = runtime_context_from_cookie(cookie)?.handle();
    if complete_tx_lease_in(runtime, lease_id, outcome) {
        Ok(())
    } else {
        Err("tx lease not registered")
    }
}

fn runtime_schedule_event(
    cookie: NetPortRuntimeCookie,
    port_id: NetPortId,
    event: NetDriverEvent,
) -> Result<(), &'static str> {
    let runtime = runtime_context_from_cookie(cookie)?.handle();
    let queued = match crate::cpu::CurrentCpu::acquire() {
        Some(current_cpu) if current_cpu.in_interrupt() => {
            enqueue_event_from_isr_in(runtime, port_id, event)
        }
        Some(_) => enqueue_event_in(runtime, port_id, event),
        None => return Err("CPU-local execution context unavailable"),
    };
    if queued {
        Ok(())
    } else {
        Err("port event queue full")
    }
}

fn runtime_update_link(
    cookie: NetPortRuntimeCookie,
    port_id: NetPortId,
    up: bool,
) -> Result<(), &'static str> {
    let runtime = runtime_context_from_cookie(cookie)?.handle();
    let if_id = current_if_for_port(runtime_context_for(runtime), port_id)?;
    let previous_primary = manager::primary_interface_in(runtime);
    let link_state = if up {
        manager::LinkState::Up
    } else {
        manager::LinkState::Down
    };
    manager::set_interface_link_state_in(runtime, if_id, link_state)
        .map_err(|_| "failed to update interface link state")?;

    if up {
        if let Ok(Some(iface)) = manager::get_interface_in(runtime, if_id) {
            if let Some(config) = iface.config {
                if let Err(error) =
                    crate::net::services::dhcp::ensure_interface_runtime_in(runtime, if_id, config)
                {
                    log::warn!(
                        target: "net::device",
                        "DHCP runtime start failed for if{} after link-up: {}",
                        if_id.0,
                        error
                    );
                }
            }
        }
        if let Err(error) = crate::net::services::dhcp::restart_interface_runtime_in(runtime, if_id)
        {
            log::warn!(
                target: "net::device",
                "DHCP runtime restart failed for if{} after link-up: {}",
                if_id.0,
                error
            );
        }
        let primary = manager::primary_interface_in(runtime);
        if primary == Some(if_id) {
            log::info!(
                target: "net::device",
                "[NET] link_up: port={} if{} role=primary",
                port_id.as_u64(),
                if_id.0
            );
        } else {
            log::info!(
                target: "net::device",
                "[NET] secondary_rejoined: port={} if{}",
                port_id.as_u64(),
                if_id.0
            );
        }
    } else {
        log::warn!(
            target: "net::device",
            "[NET] link_down: port={} if{}",
            port_id.as_u64(),
            if_id.0
        );
        handle_interface_departure_in(runtime, if_id, FailoverReason::LinkDown, previous_primary);
    }

    Ok(())
}

fn runtime_log(level: NetLogLevel, message: &str) {
    match level {
        NetLogLevel::Error => log::error!(target: "net::device", "{}", message),
        NetLogLevel::Warn => log::warn!(target: "net::device", "{}", message),
        NetLogLevel::Info => log::info!(target: "net::device", "{}", message),
        NetLogLevel::Debug => log::debug!(target: "net::device", "{}", message),
        NetLogLevel::Trace => log::trace!(target: "net::device", "{}", message),
    }
}

static NET_PORT_RUNTIME_OPS: NetPortRuntimeOps = NetPortRuntimeOps::new(
    runtime_lease_rx_buffer,
    runtime_submit_rx,
    runtime_complete_tx_lease,
    runtime_schedule_event,
    runtime_update_link,
    runtime_log,
);

pub struct NetDeviceHandle {
    driver: Box<dyn NetDevicePort>,
    binding: PoisonLock<NetDeviceBinding>,
    owner_runtime: NetRuntimeHandle,
    runtime: NetPortRuntimeHandle,
    tx_queue: Box<NetTxQueue>,
    event_sink: Box<NetEventSink>,
    driver_gate: PoisonLock<()>,
    active: AtomicBool,
    tx_worker_started: AtomicBool,
    event_worker_started: AtomicBool,
}

impl NetDeviceHandle {
    fn new(
        driver: Box<dyn NetDevicePort>,
        binding: NetDeviceBinding,
        context: &'static NetRuntimeContext,
    ) -> Self {
        Self {
            driver,
            owner_runtime: NetRuntimeHandle::new(context),
            runtime: runtime_handle_for_port(context, binding.port_id),
            binding: PoisonLock::new(binding),
            tx_queue: Box::new(NetTxQueue::new()),
            event_sink: Box::new(NetEventSink::new()),
            driver_gate: PoisonLock::new(()),
            active: AtomicBool::new(true),
            tx_worker_started: AtomicBool::new(false),
            event_worker_started: AtomicBool::new(false),
        }
    }

    pub fn binding(&self) -> NetDeviceBinding {
        match self.binding.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    pub fn driver(&self) -> &dyn NetDevicePort {
        self.driver.as_ref()
    }

    pub fn info(&self) -> NetDeviceInfo {
        self.info_in(self.owner_runtime)
    }

    fn info_in(&self, runtime: NetRuntimeHandle) -> NetDeviceInfo {
        let binding = self.binding();
        let mut info = self.driver.info();
        let stats = self.driver.stats();
        info.port_id = binding.port_id;
        info.if_id = Some(binding.if_id.0);
        info.flags |= NETDEV_FLAG_BOUND_PORT;
        if stats.initialized {
            info.flags |= NETDEV_FLAG_LINK_UP;
        }
        if stats.initialized || stats.rx_packets > 0 || stats.tx_packets > 0 {
            info.flags |= NETDEV_FLAG_HEALTHY;
        }
        if manager::primary_interface_in(runtime) == Some(binding.if_id) {
            info.flags |= NETDEV_FLAG_PRIMARY;
        }
        if let Ok(Some(interface)) = manager::get_interface_in(runtime, binding.if_id) {
            if matches!(
                interface.administrative_state,
                manager::AdministrativeState::Enabled
            ) {
                info.flags |= NETDEV_FLAG_ADMIN_UP;
            } else {
                info.flags &= !NETDEV_FLAG_ADMIN_UP;
            }
        }
        info
    }

    pub fn enqueue_tx(&self, payload: PacketPayload, meta: NetTxMeta) -> Result<(), PacketPayload> {
        self.enqueue_tx_in(self.owner_runtime, payload, meta, None)
    }

    fn enqueue_tx_in(
        &self,
        runtime: NetRuntimeHandle,
        payload: PacketPayload,
        meta: NetTxMeta,
        completion_id: Option<u64>,
    ) -> Result<(), PacketPayload> {
        let _driver_guard = self
            .driver_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !self.active.load(Ordering::Acquire) {
            return Err(payload);
        }
        if payload.segments().len() > usize::from(self.driver.info().max_tx_segments.get()) {
            return Err(payload);
        }
        let registered = register_payload_tx_request_in(
            runtime,
            self.binding().if_id,
            payload,
            meta,
            completion_id,
        )?;
        registered
            .commit_to_queue(&self.tx_queue)
            .map_err(RegisteredTx::into_rejected_payload)
    }

    pub(crate) fn enqueue_tx_request(&self, request: TxRequest) -> Result<(), TxRequest> {
        let _driver_guard = self
            .driver_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !self.active.load(Ordering::Acquire) {
            return Err(request);
        }
        self.tx_queue.push(request)
    }

    pub fn enqueue_event(&self, event: NetDriverEvent) -> bool {
        self.event_sink.push(event, EventWakeContext::Task)
    }

    pub fn enqueue_event_from_isr(&self, event: NetDriverEvent) -> bool {
        self.event_sink.push(event, EventWakeContext::Interrupt)
    }

    fn rebind(&self, binding: NetDeviceBinding) -> Result<(), &'static str> {
        self.driver.bind(binding.if_id.0)?;
        match self.binding.lock() {
            Ok(mut guard) => {
                *guard = binding;
            }
            Err(poisoned) => {
                *poisoned.into_inner() = binding;
            }
        }
        Ok(())
    }

    fn stop(&self) -> Result<(), &'static str> {
        self.active.store(false, Ordering::Release);
        self.tx_queue.wake();
        self.event_sink.wake();
        let _driver_guard = self
            .driver_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        release_interface_tx_leases_in(
            self.owner_runtime,
            self.binding().if_id,
            TxLeaseReleaseScope::QueuedOnly,
            TxDeviceOutcome::NotTransmitted,
        );
        self.driver.stop()?;
        release_interface_tx_leases_in(
            self.owner_runtime,
            self.binding().if_id,
            TxLeaseReleaseScope::All,
            TxDeviceOutcome::OutcomeUnknown,
        );
        Ok(())
    }
}

fn with_port_handle_in<R>(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    f: impl FnOnce(&NetDeviceHandle) -> R,
) -> Option<R> {
    let handle = device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .get(&if_id)
        .cloned()?;
    Some(f(handle.as_ref()))
}

fn pop_tx_request_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> Option<TxRequest> {
    with_port_handle_in(runtime, if_id, |handle| handle.tx_queue.pop()).flatten()
}

fn pop_driver_event_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> Option<NetDriverEvent> {
    with_port_handle_in(runtime, if_id, |handle| handle.event_sink.pop()).flatten()
}

fn start_workers_for_port_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Result<(), &'static str> {
    let start = with_port_handle_in(runtime, if_id, |handle| {
        (
            !handle.tx_worker_started.swap(true, Ordering::AcqRel),
            !handle.event_worker_started.swap(true, Ordering::AcqRel),
        )
    });
    let Some((start_tx, start_event)) = start else {
        return Err("device handle missing before worker startup");
    };
    if start_tx {
        crate::task::spawn(tx_worker(runtime, if_id), crate::task::TaskPlacement::Any)
            .map_err(|_| "failed to spawn network TX worker")?;
    }
    if start_event {
        crate::task::spawn(
            event_worker(runtime, if_id),
            crate::task::TaskPlacement::Any,
        )
        .map_err(|_| "failed to spawn network event worker")?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum DeviceQueueKind {
    Tx,
    Event,
}

struct DeviceQueueWaitFuture {
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    kind: DeviceQueueKind,
}

impl DeviceQueueWaitFuture {
    const fn new(runtime: NetRuntimeHandle, if_id: NetIfId, kind: DeviceQueueKind) -> Self {
        Self {
            runtime,
            if_id,
            kind,
        }
    }
}

impl Future for DeviceQueueWaitFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let ready = with_port_handle_in(self.runtime, self.if_id, |handle| {
            if !handle.active.load(Ordering::Acquire) {
                return true;
            }
            match self.kind {
                DeviceQueueKind::Tx => {
                    if !handle.tx_queue.is_empty() {
                        return true;
                    }
                    handle.tx_queue.waker.register(cx.waker());
                    !handle.tx_queue.is_empty()
                }
                DeviceQueueKind::Event => {
                    if !handle.event_sink.is_empty() {
                        return true;
                    }
                    handle.event_sink.waker.register(cx.waker());
                    !handle.event_sink.is_empty()
                }
            }
        })
        .unwrap_or(true);
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

async fn tx_worker(runtime: NetRuntimeHandle, if_id: NetIfId) {
    enum SubmissionAttempt {
        Accepted,
        Rejected(NetPortId, &'static str),
        LeaseUnavailable,
        InvalidTransition,
    }

    let max_segments = with_port_handle_in(runtime, if_id, |handle| {
        usize::from(handle.driver.info().max_tx_segments.get())
    })
    .unwrap_or(1);
    let mut descriptor_scratch = Vec::new();
    if descriptor_scratch.try_reserve_exact(max_segments).is_err() {
        log::error!(target: "net::device", "failed to reserve TX descriptor scratch");
        return;
    }
    loop {
        if !with_port_handle_in(runtime, if_id, |handle| {
            handle.active.load(Ordering::Acquire)
        })
        .unwrap_or(false)
        {
            break;
        }

        let mut pending = pop_tx_request_in(runtime, if_id);
        if pending.is_none() {
            DeviceQueueWaitFuture::new(runtime, if_id, DeviceQueueKind::Tx).await;
            pending = pop_tx_request_in(runtime, if_id);
        }

        while let Some(request) = pending {
            if !with_port_handle_in(runtime, if_id, |handle| {
                handle.active.load(Ordering::Acquire)
            })
            .unwrap_or(false)
            {
                return;
            }

            if build_tx_descriptors_in(
                runtime,
                request.lease_id,
                &mut descriptor_scratch,
                max_segments,
            )
            .is_none()
            {
                let _ = reject_tx_lease_in(
                    runtime,
                    request.lease_id,
                    "TX descriptor plan exceeds the device segment limit",
                );
                pending = pop_tx_request_in(runtime, if_id);
                continue;
            }
            let segments = NonEmptyTxSegments::new(&descriptor_scratch)
                .expect("validated TX descriptor plan is non-empty");
            let submission = TxSubmission::new(request.lease_id, segments);
            let attempt = with_port_handle_in(runtime, if_id, |handle| {
                let _driver_guard = handle
                    .driver_gate
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if !handle.active.load(Ordering::Acquire)
                    || !begin_tx_submission_in(runtime, request.lease_id)
                {
                    return SubmissionAttempt::LeaseUnavailable;
                }
                let port_id = handle.binding().port_id;
                match handle.driver.submit_tx_chain(submission, request.meta) {
                    Err(error) => {
                        let _ = reject_tx_lease_in(runtime, request.lease_id, error);
                        SubmissionAttempt::Rejected(port_id, error)
                    }
                    Ok(()) if mark_tx_device_owned_in(runtime, request.lease_id) => {
                        SubmissionAttempt::Accepted
                    }
                    Ok(()) => SubmissionAttempt::InvalidTransition,
                }
            });
            match attempt {
                Some(SubmissionAttempt::Rejected(port_id, err)) => {
                    log::warn!(
                        target: "net::device",
                        "device port={} TX submission failed: {}",
                        port_id.as_u64(),
                        err
                    );
                }
                Some(SubmissionAttempt::InvalidTransition) => {
                    log::error!(
                        target: "net::device",
                        "accepted TX lease {} has an invalid ownership transition",
                        request.lease_id.get()
                    );
                }
                Some(SubmissionAttempt::Accepted) | Some(SubmissionAttempt::LeaseUnavailable) => {}
                None => {
                    let _ = reject_tx_lease_in(runtime, request.lease_id, "device handle missing");
                    return;
                }
            }
            pending = pop_tx_request_in(runtime, if_id);
        }
    }
}

async fn event_worker(runtime: NetRuntimeHandle, if_id: NetIfId) {
    loop {
        if !with_port_handle_in(runtime, if_id, |handle| {
            handle.active.load(Ordering::Acquire)
        })
        .unwrap_or(false)
        {
            break;
        }

        let mut pending = pop_driver_event_in(runtime, if_id);
        if pending.is_none() {
            DeviceQueueWaitFuture::new(runtime, if_id, DeviceQueueKind::Event).await;
            pending = pop_driver_event_in(runtime, if_id);
        }

        while let Some(event) = pending {
            if !with_port_handle_in(runtime, if_id, |handle| {
                handle.active.load(Ordering::Acquire)
            })
            .unwrap_or(false)
            {
                return;
            }

            let handled = with_port_handle_in(runtime, if_id, |handle| {
                let _driver_guard = handle
                    .driver_gate
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if !handle.active.load(Ordering::Acquire) {
                    return None;
                }
                let binding = handle.binding();
                let result = match event {
                    NetDriverEvent::Poll => handle.driver.poll(binding.if_id.0),
                    _ => handle.driver.handle_event(binding.if_id.0, event),
                };
                Some((binding.port_id, result))
            });
            match handled {
                Some(Some((port_id, Err(err)))) => {
                    log::warn!(
                        target: "net::device",
                        "device port={} event {:?} failed: {}",
                        port_id.as_u64(),
                        event,
                        err
                    );
                }
                Some(Some((_, Ok(())))) => {}
                Some(None) | None => return,
            }
            pending = pop_driver_event_in(runtime, if_id);
        }
    }
}

#[derive(Default)]
pub struct NetDeviceManager {
    handles: BTreeMap<NetIfId, Arc<NetDeviceHandle>>,
    port_map: BTreeMap<NetPortId, NetIfId>,
    quarantined: Vec<Arc<NetDeviceHandle>>,
}

impl NetDeviceManager {
    pub const fn new() -> Self {
        Self {
            handles: BTreeMap::new(),
            port_map: BTreeMap::new(),
            quarantined: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailoverReason {
    LinkDown,
    Unregister,
}

impl FailoverReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LinkDown => "link_down",
            Self::Unregister => "unregister",
        }
    }
}

fn handle_interface_departure_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    reason: FailoverReason,
    previous_primary: Option<NetIfId>,
) {
    let release_sent = crate::net::services::dhcp::release_interface_in(runtime, if_id);
    if release_sent {
        log::info!(
            target: "net::device",
            "[NET] dhcp_release_best_effort: if{} reason={}",
            if_id.0,
            reason.as_str()
        );
    }

    if previous_primary != Some(if_id) {
        return;
    }

    if let Some(new_if) = manager::primary_interface_in(runtime) {
        log::info!(
            target: "net::device",
            "[NET] primary_failover: old=if{} new=if{} reason={}",
            if_id.0,
            new_if.0,
            reason.as_str()
        );
    } else {
        log::warn!(
            target: "net::device",
            "[NET] primary_cleared: old=if{} reason={}",
            if_id.0,
            reason.as_str()
        );
    }
}

pub fn ensure_stack_initialized_in(runtime: NetRuntimeHandle) -> Result<(), &'static str> {
    if runtime_context_for(runtime)
        .stack_initialized
        .load(Ordering::Acquire)
    {
        return Ok(());
    }

    if runtime_context_for(runtime)
        .stack_initialized
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(());
    }

    if let Err(err) = crate::net::runtime::transport::ensure_tcp_runtime_initialized_in(runtime) {
        runtime_context_for(runtime)
            .stack_initialized
            .store(false, Ordering::Release);
        log::warn!(target: "net::device", "TCP runtime init failed: {:?}", err);
        return Err("network secure entropy unavailable");
    }

    if let Err(err) = crate::net::datapath::mempool::init_net_mempool_in(runtime, 1024) {
        log::warn!(target: "net::device", "mempool init failed: {}", err);
    }

    manager::init_network_manager_in(runtime);
    if let Err(error) = stack::init_in(runtime) {
        runtime_context_for(runtime)
            .stack_initialized
            .store(false, Ordering::Release);
        log::warn!(target: "net::device", "per-CPU stack resource init failed: {:?}", error);
        return Err("network CPU resources unavailable");
    }

    if let Err(err) = crate::net::api::dhcp::init_dhcp_runtime_in(runtime) {
        log::warn!(target: "net::device", "DHCP runtime init failed: {}", err);
    }

    Ok(())
}

pub fn is_initialized_in(runtime: NetRuntimeHandle) -> bool {
    runtime_context_for(runtime)
        .stack_initialized
        .load(Ordering::Acquire)
}

fn interface_for_port(
    runtime: NetRuntimeHandle,
    port_id: NetPortId,
    config: NetworkConfig,
    port_name: &'static str,
    primary_preference: manager::PrimaryPreference,
) -> Result<NetIfId, &'static str> {
    let if_id = if let Some(existing) = lookup_if_by_port_id_in(runtime, port_id) {
        manager::set_primary_preference_in(runtime, existing, primary_preference)
            .map_err(|_| "failed to update network interface preference")?;
        manager::set_interface_config_in(runtime, existing, config)
            .map_err(|_| "failed to configure existing network interface")?;
        existing
    } else {
        let if_id = manager::register_interface_in(runtime, port_name, primary_preference)
            .map_err(|_| "failed to register network interface")?;
        if manager::set_interface_config_in(runtime, if_id, config).is_err() {
            let _ = manager::unregister_interface_in(runtime, if_id);
            return Err("failed to configure new network interface");
        }
        if_id
    };

    Ok(if_id)
}

fn rollback_interface_registration_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    crate::net::services::dhcp::unregister_interface_runtime_in(runtime, if_id);
    let _ = manager::unregister_interface_in(runtime, if_id);
    crate::net::runtime::bridge::remove_stack_glue_interface_in(runtime, if_id);
}

fn rollback_port_registration_in(runtime: NetRuntimeHandle, if_id: NetIfId, port_id: NetPortId) {
    let removed = {
        let mut guard = device_manager_in(runtime)
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if guard.port_map.get(&port_id) == Some(&if_id) {
            guard.port_map.remove(&port_id);
        }
        guard.handles.remove(&if_id)
    };
    if let Some(handle) = removed {
        if let Err(error) = handle.stop() {
            log::error!(
                target: "net::device",
                "port rollback could not prove DMA quiescence: {}",
                error
            );
            device_manager_in(runtime)
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .quarantined
                .push(handle);
        }
    }
    rollback_interface_registration_in(runtime, if_id);
}

const fn manager_primary_preference(policy: PrimaryPortPolicy) -> manager::PrimaryPreference {
    match policy {
        PrimaryPortPolicy::Prefer => manager::PrimaryPreference::Prefer,
        PrimaryPortPolicy::Auto => manager::PrimaryPreference::Auto,
        PrimaryPortPolicy::Never => manager::PrimaryPreference::Never,
    }
}

fn default_config_for_port(info: NetDeviceInfo) -> NetworkConfig {
    let mac_bytes = if info.mac == MacAddress::ZERO {
        MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    } else {
        info.mac
    };
    let mac = StackMacAddress::new(*mac_bytes.as_bytes());

    NetworkConfig {
        mac,
        ipv4: Ipv4Config::default(),
        ipv6: Some(crate::net::l3::ipv6::Ipv6Config::from_mac(mac.as_bytes())),
        icmp_echo_enabled: true,
        icmp_redirect_enabled: false,
        icmpv6_redirect_enabled: false,
    }
}

pub fn register_port_in(
    runtime: NetRuntimeHandle,
    registration: NetPortRegistration,
) -> Result<NetIfId, &'static str> {
    let driver = registration.driver;
    let info = registration.info;
    let config = default_config_for_port(info);
    ensure_stack_initialized_in(runtime)?;

    let primary_preference = manager_primary_preference(registration.primary_policy);
    if let Some(existing) = lookup_if_by_port_id_in(runtime, info.port_id) {
        manager::set_primary_preference_in(runtime, existing, primary_preference)
            .map_err(|_| "failed to update network interface preference")?;
        return Ok(existing);
    }

    let base = driver.info();
    let if_id = interface_for_port(
        runtime,
        info.port_id,
        config,
        base.driver_name,
        primary_preference,
    )?;
    let binding = NetDeviceBinding {
        port_id: info.port_id,
        if_id,
    };
    let handle = Arc::new(NetDeviceHandle::new(
        driver,
        binding,
        runtime_context_for(runtime),
    ));
    if let Err(err) = handle.driver.bind(if_id.0) {
        rollback_interface_registration_in(runtime, if_id);
        return Err(err);
    }
    let runtime_handle = handle.runtime;

    {
        let mut guard = device_manager_in(runtime)
            .write()
            .unwrap_or_else(|e| e.into_inner());
        guard.port_map.insert(info.port_id, if_id);
        guard.handles.insert(if_id, handle);
    }

    if let Some(start_result) =
        with_port_handle_in(runtime, if_id, |handle| handle.driver.start(runtime_handle))
    {
        if let Err(err) = start_result {
            rollback_port_registration_in(runtime, if_id, info.port_id);
            return Err(err);
        }
    } else {
        rollback_port_registration_in(runtime, if_id, info.port_id);
        return Err("device handle missing after registration");
    }

    let initial_link_state = if info.flags & NETDEV_FLAG_LINK_UP != 0 {
        manager::LinkState::Up
    } else {
        manager::LinkState::Down
    };
    manager::set_interface_link_state_in(runtime, if_id, initial_link_state)
        .map_err(|_| "failed to publish initial network link state")?;

    if let Err(error) = start_workers_for_port_in(runtime, if_id) {
        rollback_port_registration_in(runtime, if_id, info.port_id);
        return Err(error);
    }

    if let Err(err) =
        crate::net::services::dhcp::ensure_interface_runtime_in(runtime, if_id, config)
    {
        log::warn!(
            target: "net::device",
            "DHCP interface runtime init failed for if{}: {}",
            if_id.0,
            err
        );
    }

    Ok(if_id)
}

pub fn unregister_port_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> Result<bool, &'static str> {
    let previous_primary = manager::primary_interface_in(runtime);
    let handle = device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .get(&if_id)
        .cloned();

    if let Some(handle) = handle {
        let stop_result = handle.stop();
        let _ = manager::set_interface_link_state_in(runtime, if_id, manager::LinkState::Down);
        handle_interface_departure_in(runtime, if_id, FailoverReason::Unregister, previous_primary);
        stop_result?;
        {
            let mut guard = device_manager_in(runtime)
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if guard
                .handles
                .get(&if_id)
                .is_some_and(|current| Arc::ptr_eq(current, &handle))
            {
                guard.handles.remove(&if_id);
                guard.port_map.remove(&handle.binding().port_id);
            } else {
                return Ok(false);
            }
        }
        crate::net::services::dhcp::unregister_interface_runtime_in(runtime, if_id);
        let _ = manager::unregister_interface_in(runtime, if_id);
        crate::net::runtime::bridge::remove_stack_glue_interface_in(runtime, if_id);
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn lookup_if_by_port_id_in(runtime: NetRuntimeHandle, port_id: NetPortId) -> Option<NetIfId> {
    device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .port_map
        .get(&port_id)
        .copied()
}

pub fn list_port_infos_in(runtime: NetRuntimeHandle) -> Vec<NetDeviceInfo> {
    device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .values()
        .map(|handle| handle.info_in(runtime))
        .collect()
}

pub fn port_info_in(runtime: NetRuntimeHandle, port_id: NetPortId) -> Option<NetDeviceInfo> {
    let if_id = lookup_if_by_port_id_in(runtime, port_id)?;
    with_port_handle_in(runtime, if_id, |handle| handle.info_in(runtime))
}

pub fn port_stats_in(runtime: NetRuntimeHandle, port_id: NetPortId) -> Option<NetPortStats> {
    let if_id = lookup_if_by_port_id_in(runtime, port_id)?;
    port_stats_for_interface_in(runtime, if_id)
}

pub fn port_stats_for_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<NetPortStats> {
    with_port_handle_in(runtime, if_id, |handle| handle.driver().stats())
}

pub fn list_port_ids_in(runtime: NetRuntimeHandle) -> Vec<NetPortId> {
    device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .port_map
        .keys()
        .copied()
        .collect()
}

pub fn transmit_packet_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    payload: PacketPayload,
    meta: NetTxMeta,
) -> Result<(), PacketPayload> {
    transmit_packet_observed_in(runtime, if_id, payload, meta, None)
}

pub(crate) fn transmit_packet_observed_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    payload: PacketPayload,
    meta: NetTxMeta,
    completion_id: Option<u64>,
) -> Result<(), PacketPayload> {
    if !manager::is_interface_operational_in(runtime, if_id) {
        return Err(payload);
    }
    let mut pending = Some(payload);
    let queued = with_port_handle_in(runtime, if_id, |handle| {
        handle.enqueue_tx_in(
            runtime,
            pending.take().expect("TX payload is consumed once"),
            meta,
            completion_id,
        )
    });
    queued.unwrap_or_else(|| Err(pending.expect("missing device leaves TX payload untouched")))
}

pub(crate) fn transmit_registered_tx_request_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    request: TxRequest,
) -> bool {
    let lease_id = request.lease_id;
    if !manager::is_interface_operational_in(runtime, if_id) {
        let _ = reject_tx_lease_in(runtime, lease_id, "network interface is not operational");
        return false;
    }
    let queued = with_port_handle_in(runtime, if_id, |handle| handle.enqueue_tx_request(request));
    match queued {
        Some(Ok(())) => true,
        Some(Err(request)) => {
            let _ = reject_tx_lease_in(runtime, request.lease_id, "device TX queue full");
            false
        }
        None => {
            let _ = reject_tx_lease_in(runtime, lease_id, "device handle missing");
            false
        }
    }
}

pub fn enqueue_event_in(
    runtime: NetRuntimeHandle,
    port_id: NetPortId,
    event: NetDriverEvent,
) -> bool {
    let Some(if_id) = lookup_if_by_port_id_in(runtime, port_id) else {
        return false;
    };
    with_port_handle_in(runtime, if_id, |handle| handle.enqueue_event(event)).unwrap_or(false)
}

pub fn enqueue_event_from_isr_in(
    runtime: NetRuntimeHandle,
    port_id: NetPortId,
    event: NetDriverEvent,
) -> bool {
    let Some(if_id) = lookup_if_by_port_id_in(runtime, port_id) else {
        return false;
    };
    with_port_handle_in(runtime, if_id, |handle| {
        handle.enqueue_event_from_isr(event)
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::runtime::context::default_runtime;
    use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};

    struct FakeDriverState {
        bind_calls: AtomicUsize,
        last_if_id: AtomicU16,
        last_event_queue: AtomicU16,
        poll_calls: AtomicUsize,
        stop_calls: AtomicUsize,
        tx_packets: AtomicU64,
        rx_packets: AtomicU64,
        initialized: AtomicBool,
        runtime: PoisonLock<Option<NetPortRuntimeHandle>>,
    }

    impl FakeDriverState {
        const fn new() -> Self {
            Self {
                bind_calls: AtomicUsize::new(0),
                last_if_id: AtomicU16::new(0),
                last_event_queue: AtomicU16::new(u16::MAX),
                poll_calls: AtomicUsize::new(0),
                stop_calls: AtomicUsize::new(0),
                tx_packets: AtomicU64::new(0),
                rx_packets: AtomicU64::new(0),
                initialized: AtomicBool::new(false),
                runtime: PoisonLock::new(None),
            }
        }

        fn set_stats(&self, tx_packets: u64, rx_packets: u64, initialized: bool) {
            self.tx_packets.store(tx_packets, Ordering::Release);
            self.rx_packets.store(rx_packets, Ordering::Release);
            self.initialized.store(initialized, Ordering::Release);
        }

        fn update_link(&self, up: bool) -> Result<(), &'static str> {
            let runtime = self
                .runtime
                .lock()
                .map_err(|_| "fake runtime lock poisoned")?
                .ok_or("fake runtime not installed")?;
            runtime.update_link(up)
        }

        fn submit_rx(&self, packet: PacketRef, meta: NetRxMeta) -> Result<(), &'static str> {
            let runtime = self
                .runtime
                .lock()
                .map_err(|_| "fake runtime lock poisoned")?
                .ok_or("fake runtime not installed")?;
            let buffer = runtime
                .lease_rx_buffer()
                .ok_or("fake driver could not lease RX storage")?;
            let region = buffer.writable_region();
            if packet.len() > region.writable_len() {
                return Err("fake RX packet exceeds writable DMA region");
            }
            // SAFETY: the RX lease grants exclusive write access to the
            // advertised region until completion consumes it.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    packet.data().as_ptr(),
                    region.cpu_ptr(),
                    packet.len(),
                );
            }
            let received = buffer
                .complete(meta)
                .map_err(|_| "fake RX completion layout is invalid")?;
            runtime.submit_rx(received)
        }
    }

    struct FakeDriver {
        state: &'static FakeDriverState,
        driver_name: &'static str,
        start_error: Option<&'static str>,
        stop_error: Option<&'static str>,
    }

    impl FakeDriver {
        const fn new(state: &'static FakeDriverState) -> Self {
            Self {
                state,
                driver_name: "fake",
                start_error: None,
                stop_error: None,
            }
        }

        const fn with_start_error(
            state: &'static FakeDriverState,
            driver_name: &'static str,
            start_error: &'static str,
        ) -> Self {
            Self {
                state,
                driver_name,
                start_error: Some(start_error),
                stop_error: None,
            }
        }

        const fn with_stop_error(
            state: &'static FakeDriverState,
            driver_name: &'static str,
            stop_error: &'static str,
        ) -> Self {
            Self {
                state,
                driver_name,
                start_error: None,
                stop_error: Some(stop_error),
            }
        }
    }

    fn fake_driver() -> (&'static FakeDriverState, Box<dyn NetDevicePort>) {
        let state = Box::leak(Box::new(FakeDriverState::new()));
        (state, Box::new(FakeDriver::new(state)))
    }

    fn fake_driver_with_start_error(
        driver_name: &'static str,
        start_error: &'static str,
    ) -> (&'static FakeDriverState, Box<dyn NetDevicePort>) {
        let state = Box::leak(Box::new(FakeDriverState::new()));
        (
            state,
            Box::new(FakeDriver::with_start_error(
                state,
                driver_name,
                start_error,
            )),
        )
    }

    fn fake_driver_with_stop_error(
        driver_name: &'static str,
        stop_error: &'static str,
    ) -> (&'static FakeDriverState, Box<dyn NetDevicePort>) {
        let state = Box::leak(Box::new(FakeDriverState::new()));
        (
            state,
            Box::new(FakeDriver::with_stop_error(state, driver_name, stop_error)),
        )
    }

    impl NetDevicePort for FakeDriver {
        fn info(&self) -> NetDeviceInfo {
            NetDeviceInfo {
                port_id: NetPortId::new(0x9009),
                if_id: None,
                driver_name: self.driver_name,
                queue_pairs: 1,
                max_tx_segments: core::num::NonZeroU16::new(8)
                    .expect("fake segment limit is non-zero"),
                mtu: stack::MTU as u32,
                mac: MacAddress::from_octets(0, 1, 2, 3, 4, 5),
                flags: NETDEV_FLAG_HEALTHY,
            }
        }

        fn start(&self, runtime: NetPortRuntimeHandle) -> Result<(), &'static str> {
            if let Some(error) = self.start_error {
                Err(error)
            } else {
                *self
                    .state
                    .runtime
                    .lock()
                    .map_err(|_| "fake runtime lock poisoned")? = Some(runtime);
                Ok(())
            }
        }

        fn bind(&self, if_id: u16) -> Result<(), &'static str> {
            self.state.bind_calls.fetch_add(1, Ordering::Relaxed);
            self.state.last_if_id.store(if_id, Ordering::Release);
            Ok(())
        }

        fn submit_tx_chain(
            &self,
            _submission: TxSubmission<'_>,
            _meta: NetTxMeta,
        ) -> Result<(), &'static str> {
            Ok(())
        }

        fn poll(&self, if_id: u16) -> Result<(), &'static str> {
            self.state.last_if_id.store(if_id, Ordering::Release);
            self.state.poll_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn handle_event(&self, if_id: u16, event: NetDriverEvent) -> Result<(), &'static str> {
            self.state.last_if_id.store(if_id, Ordering::Release);
            if let NetDriverEvent::QueueWake { queue_index } = event {
                self.state
                    .last_event_queue
                    .store(queue_index, Ordering::Release);
            }
            Ok(())
        }

        fn stats(&self) -> NetPortStats {
            NetPortStats {
                tx_packets: self.state.tx_packets.load(Ordering::Acquire),
                rx_packets: self.state.rx_packets.load(Ordering::Acquire),
                tx_errors: 0,
                rx_errors: 0,
                initialized: self.state.initialized.load(Ordering::Acquire),
            }
        }

        fn stop(&self) -> Result<(), &'static str> {
            let stop_index = self.state.stop_calls.fetch_add(1, Ordering::Relaxed);
            match (self.stop_error, stop_index) {
                (Some(error), 0) => Err(error),
                _ => Ok(()),
            }
        }
    }

    fn test_port_id(index: u16) -> NetPortId {
        NetPortId::new(0x9000 + u64::from(index))
    }

    fn register_test_port(
        index: u16,
        driver: Box<dyn NetDevicePort>,
        primary_policy: PrimaryPortPolicy,
    ) -> Result<NetIfId, &'static str> {
        let info = NetDeviceInfo {
            port_id: test_port_id(index),
            driver_name: "fake",
            queue_pairs: 1,
            mtu: stack::MTU as u32,
            mac: MacAddress::from_octets(0, 1, 2, 3, 4, index as u8),
            flags: NETDEV_FLAG_HEALTHY | NETDEV_FLAG_ADMIN_UP | NETDEV_FLAG_LINK_UP,
            ..NetDeviceInfo::default()
        };
        register_port_in(
            default_runtime(),
            NetPortRegistration::new(info, driver, primary_policy),
        )
    }

    fn unregister_test_port(if_id: NetIfId) -> bool {
        unregister_port_in(default_runtime(), if_id).expect("fake driver quiesces during stop")
    }

    #[derive(Clone, Copy)]
    struct TestPacketRefState {
        ptr: *mut u8,
        len: usize,
        capacity: usize,
        device_addr: u64,
        release_counter: *const AtomicUsize,
    }

    unsafe fn test_packet_state(
        storage: &kernel_api::resource::net::PacketRefStorage,
    ) -> &TestPacketRefState {
        unsafe { storage.as_state_ref::<TestPacketRefState>() }
    }

    unsafe fn test_packet_state_mut(
        storage: &mut kernel_api::resource::net::PacketRefStorage,
    ) -> &mut TestPacketRefState {
        unsafe { storage.as_state_mut::<TestPacketRefState>() }
    }

    unsafe fn test_packet_data_ptr(
        storage: &kernel_api::resource::net::PacketRefStorage,
    ) -> *const u8 {
        unsafe { test_packet_state(storage).ptr.cast_const() }
    }

    unsafe fn test_packet_data_mut_ptr(
        storage: &mut kernel_api::resource::net::PacketRefStorage,
    ) -> *mut u8 {
        unsafe { test_packet_state_mut(storage).ptr }
    }

    unsafe fn test_packet_len(storage: &kernel_api::resource::net::PacketRefStorage) -> usize {
        unsafe { test_packet_state(storage).len }
    }

    unsafe fn test_packet_set_len(
        storage: &mut kernel_api::resource::net::PacketRefStorage,
        len: usize,
    ) -> bool {
        let state = unsafe { test_packet_state_mut(storage) };
        if len > state.capacity {
            return false;
        }
        state.len = len;
        true
    }

    unsafe fn test_packet_capacity(storage: &kernel_api::resource::net::PacketRefStorage) -> usize {
        unsafe { test_packet_state(storage).capacity }
    }

    unsafe fn test_packet_phys_addr(storage: &kernel_api::resource::net::PacketRefStorage) -> u64 {
        unsafe { test_packet_state(storage).device_addr }
    }

    unsafe fn test_packet_device_address(
        storage: &kernel_api::resource::net::PacketRefStorage,
    ) -> u64 {
        unsafe { test_packet_state(storage).device_addr }
    }

    unsafe fn test_packet_headroom(_: &kernel_api::resource::net::PacketRefStorage) -> usize {
        0
    }

    unsafe fn test_packet_advance(
        storage: &mut kernel_api::resource::net::PacketRefStorage,
        size: PacketByteCount,
    ) -> bool {
        let state = unsafe { test_packet_state_mut(storage) };
        let size = size.get();
        if size > state.len {
            return false;
        }
        state.ptr = unsafe { state.ptr.add(size) };
        state.len -= size;
        state.device_addr = state.device_addr.wrapping_add(size as u64);
        true
    }

    unsafe fn test_packet_retreat(
        _storage: &mut kernel_api::resource::net::PacketRefStorage,
        _size: PacketByteCount,
    ) -> bool {
        false
    }

    unsafe fn test_packet_drop(storage: &mut kernel_api::resource::net::PacketRefStorage) {
        let counter = unsafe { test_packet_state(storage) }.release_counter;
        if let Some(counter) = unsafe { counter.as_ref() } {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    unsafe fn test_packet_split_front(
        storage: &kernel_api::resource::net::PacketRefStorage,
        len: PacketByteCount,
    ) -> Option<(
        kernel_api::resource::net::PacketRefStorage,
        kernel_api::resource::net::PacketRefStorage,
    )> {
        let state = *unsafe { test_packet_state(storage) };
        let len = len.get();
        if len == 0 || len >= state.len {
            return None;
        }
        let front = TestPacketRefState { len, ..state };
        let remainder = TestPacketRefState {
            ptr: unsafe { state.ptr.add(len) },
            len: state.len - len,
            capacity: state.capacity.saturating_sub(len),
            device_addr: state.device_addr.wrapping_add(len as u64),
            release_counter: state.release_counter,
        };
        Some((
            unsafe { kernel_api::resource::net::PacketRefStorage::from_state(front) },
            unsafe { kernel_api::resource::net::PacketRefStorage::from_state(remainder) },
        ))
    }

    static TEST_PACKET_REF_VTABLE: kernel_api::resource::net::PacketRefVTable =
        kernel_api::resource::net::PacketRefVTable {
            data_ptr: test_packet_data_ptr,
            data_mut_ptr: test_packet_data_mut_ptr,
            len: test_packet_len,
            resize: test_packet_set_len,
            data_capacity: test_packet_capacity,
            phys_addr: test_packet_phys_addr,
            device_address: test_packet_device_address,
            headroom: test_packet_headroom,
            advance: test_packet_advance,
            retreat: test_packet_retreat,
            split_front: test_packet_split_front,
            drop_storage: test_packet_drop,
        };

    fn test_packet_ref_with_device_addr(len: usize, device_addr: u64) -> PacketRef {
        let backing = Box::leak(Box::new([0u8; 64]));
        let state = TestPacketRefState {
            ptr: backing.as_mut_ptr(),
            len,
            capacity: backing.len(),
            device_addr,
            release_counter: core::ptr::null(),
        };
        unsafe {
            PacketRef::from_opaque_parts(
                kernel_api::resource::net::PacketRefStorage::from_state(state),
                &TEST_PACKET_REF_VTABLE,
            )
        }
    }

    fn test_counted_packet_ref(
        len: usize,
        device_addr: u64,
        release_counter: &AtomicUsize,
    ) -> PacketRef {
        let backing = Box::leak(Box::new([0u8; 64]));
        let state = TestPacketRefState {
            ptr: backing.as_mut_ptr(),
            len,
            capacity: backing.len(),
            device_addr,
            release_counter: core::ptr::from_ref(release_counter),
        };
        unsafe {
            PacketRef::from_opaque_parts(
                kernel_api::resource::net::PacketRefStorage::from_state(state),
                &TEST_PACKET_REF_VTABLE,
            )
        }
    }

    fn test_tx_segment(device_addr: u64, len: usize) -> NetTxSegment {
        static TEST_TX_BYTES: [u8; 64] = [0; 64];
        NetTxSegment::from_dma(
            TEST_TX_BYTES.as_ptr(),
            device_addr,
            device_addr,
            PacketByteCount::new(len).expect("test segment length is non-zero"),
        )
        .expect("test descriptor is valid")
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_queue_roundtrip_smoke() {
        let _ = crate::net::datapath::mempool::init_net_mempool(16);
        let queue = NetTxQueue::new();
        let request = TxRequest {
            lease_id: TxLeaseId::new(1).expect("non-zero lease"),
            meta: NetTxMeta::default(),
        };
        assert_eq!(queue.capacity(), NetTxQueue::CAPACITY);
        assert_eq!(queue.len(), 0);
        assert!(queue.push(request).is_ok());
        assert_eq!(queue.len(), 1);
        assert!(queue.pop().is_some());
        assert!(queue.pop().is_none());
        assert_eq!(queue.len(), 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn event_sink_from_isr_roundtrip_smoke() {
        let sink = NetEventSink::new();
        assert_eq!(sink.capacity(), NetEventSink::CAPACITY);
        assert_eq!(sink.len(), 0);
        assert!(sink.push(
            NetDriverEvent::QueueWake { queue_index: 7 },
            EventWakeContext::Task,
        ));
        assert_eq!(sink.len(), 1);
        assert_eq!(
            sink.pop(),
            Some(NetDriverEvent::QueueWake { queue_index: 7 })
        );
        assert!(sink.pop().is_none());
        assert_eq!(sink.len(), 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn schedule_event_from_interrupt_context_enqueues_successfully() {
        let (_, driver) = fake_driver();
        let if_id =
            register_test_port(89, driver, PrimaryPortPolicy::Never).expect("register port");

        let result = with_port_handle_in(default_runtime(), if_id, |handle| {
            handle.enqueue_event_from_isr(NetDriverEvent::QueueWake { queue_index: 3 })
        })
        .expect("handle");

        assert!(result);
        assert_eq!(
            with_port_handle_in(default_runtime(), if_id, |handle| handle.event_sink.pop())
                .flatten(),
            Some(NetDriverEvent::QueueWake { queue_index: 3 })
        );

        let _ = unregister_test_port(if_id);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn device_handle_rebind_updates_binding_smoke() {
        let (state, driver) = fake_driver();
        let handle = NetDeviceHandle::new(
            driver,
            NetDeviceBinding {
                port_id: test_port_id(9),
                if_id: NetIfId(1),
            },
            default_runtime_context(),
        );

        handle
            .rebind(NetDeviceBinding {
                port_id: test_port_id(9),
                if_id: NetIfId(22),
            })
            .expect("rebind");

        assert_eq!(handle.binding().if_id, NetIfId(22));
        assert_eq!(state.bind_calls.load(Ordering::Relaxed), 1);
        assert_eq!(state.last_if_id.load(Ordering::Acquire), 22);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn register_port_exposes_snapshot_smoke() {
        let (state, driver) = fake_driver();
        state.set_stats(11, 7, true);

        let if_id =
            register_test_port(90, driver, PrimaryPortPolicy::Never).expect("register port");

        let info = port_info_in(default_runtime(), test_port_id(90)).expect("port info");
        let stats = port_stats_in(default_runtime(), test_port_id(90)).expect("port stats");

        assert_eq!(
            lookup_if_by_port_id_in(default_runtime(), test_port_id(90)),
            Some(if_id)
        );
        assert_eq!(info.port_id, test_port_id(90));
        assert_eq!(info.if_id, Some(if_id.0));
        assert_eq!(stats.tx_packets, 11);
        assert_eq!(stats.rx_packets, 7);
        assert!(list_port_ids_in(default_runtime()).contains(&test_port_id(90)));

        assert!(unregister_test_port(if_id));
        assert_eq!(state.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn register_port_rolls_back_device_state_when_driver_start_fails() {
        let (_state, driver) = fake_driver_with_start_error("start-fail", "start failed");

        assert_eq!(
            register_test_port(88, driver, PrimaryPortPolicy::Never),
            Err("start failed")
        );
        assert_eq!(
            lookup_if_by_port_id_in(default_runtime(), test_port_id(88)),
            None
        );
        assert!(!list_port_ids_in(default_runtime()).contains(&test_port_id(88)));
        assert!(
            manager::list_interfaces_in(default_runtime())
                .expect("manager query")
                .iter()
                .all(|iface| iface.name != "start-fail")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn duplicate_port_registration_preserves_the_canonical_interface() {
        let (_, driver_a) = fake_driver();
        let (_, duplicate_driver) = fake_driver();

        let if_id =
            register_test_port(86, driver_a, PrimaryPortPolicy::Auto).expect("register first port");
        let duplicate = register_test_port(86, duplicate_driver, PrimaryPortPolicy::Prefer)
            .expect("repeat registration");

        assert_eq!(duplicate, if_id);
        assert_eq!(
            lookup_if_by_port_id_in(default_runtime(), test_port_id(86)),
            Some(if_id)
        );
        assert_eq!(
            manager::primary_interface_in(default_runtime()),
            Some(if_id)
        );
        assert!(unregister_test_port(if_id));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn register_port_prefer_primary_updates_primary_selection_smoke() {
        let (_, driver_a) = fake_driver();
        let (_, driver_b) = fake_driver();

        let if_a =
            register_test_port(91, driver_a, PrimaryPortPolicy::Auto).expect("register first port");
        let if_b = register_test_port(92, driver_b, PrimaryPortPolicy::Prefer)
            .expect("register second port");

        assert_eq!(manager::primary_interface_in(default_runtime()), Some(if_b));
        assert!(
            port_info_in(default_runtime(), test_port_id(92))
                .expect("primary info")
                .flags
                & NETDEV_FLAG_PRIMARY
                != 0
        );

        assert!(unregister_test_port(if_b));
        assert_eq!(manager::primary_interface_in(default_runtime()), Some(if_a));
        assert!(unregister_test_port(if_a));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn primary_link_callback_promotes_secondary() {
        let (state_a, driver_a) = fake_driver();
        let (_, driver_b) = fake_driver();

        let if_a =
            register_test_port(93, driver_a, PrimaryPortPolicy::Auto).expect("register first port");
        let if_b = register_test_port(94, driver_b, PrimaryPortPolicy::Auto)
            .expect("register second port");
        assert_eq!(manager::primary_interface_in(default_runtime()), Some(if_a));

        state_a.update_link(false).expect("publish link down");

        assert_eq!(manager::primary_interface_in(default_runtime()), Some(if_b));
        assert!(!manager::is_interface_operational_in(
            default_runtime(),
            if_a
        ));
        assert!(manager::is_interface_operational_in(
            default_runtime(),
            if_b
        ));
        let payload = PacketPayload::try_single(test_packet_ref_with_device_addr(1, 0x4000))
            .expect("test payload is non-empty");
        assert!(
            transmit_packet_in(default_runtime(), if_a, payload, NetTxMeta::default(),).is_err()
        );

        assert!(unregister_test_port(if_b));
        assert!(unregister_test_port(if_a));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn unregister_primary_without_survivor_clears_primary_runtime() {
        let (_, driver) = fake_driver();
        let if_a = register_test_port(95, driver, PrimaryPortPolicy::Auto).expect("register port");
        assert_eq!(manager::primary_interface_in(default_runtime()), Some(if_a));

        assert!(unregister_test_port(if_a));
        assert_eq!(manager::primary_interface_in(default_runtime()), None);
        assert!(
            manager::get_interface_in(default_runtime(), if_a)
                .expect("manager query")
                .is_none()
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn recovered_interface_does_not_reclaim_primary_after_failover() {
        let (state_a, driver_a) = fake_driver();
        let (_, driver_b) = fake_driver();

        let if_a =
            register_test_port(96, driver_a, PrimaryPortPolicy::Auto).expect("register first port");
        let if_b = register_test_port(97, driver_b, PrimaryPortPolicy::Auto)
            .expect("register second port");

        assert_eq!(manager::primary_interface_in(default_runtime()), Some(if_a));
        state_a.update_link(false).expect("publish link down");
        assert_eq!(manager::primary_interface_in(default_runtime()), Some(if_b));

        state_a.update_link(true).expect("publish link recovery");
        assert_eq!(manager::primary_interface_in(default_runtime()), Some(if_b));

        assert!(unregister_test_port(if_b));
        assert!(unregister_test_port(if_a));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn stopped_interface_rejects_rx_at_the_device_boundary() {
        let (state, driver) = fake_driver();
        let if_id = register_test_port(98, driver, PrimaryPortPolicy::Auto).expect("register port");
        state.update_link(false).expect("publish link down");

        let frame_len = PacketByteCount::new(14).expect("non-empty frame");
        let layout = kernel_api::service::netdev::NetRxFrameLayout::whole_payload(frame_len)
            .expect("valid frame layout");
        let packet = test_packet_ref_with_device_addr(frame_len.get(), 0x3000);
        assert_eq!(
            state.submit_rx(packet, NetRxMeta::new(0, layout, 0)),
            Err("network interface is not operational")
        );

        assert!(unregister_test_port(if_id));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_completion_future_resolves_success() {
        let (completion_id, future) = register_tx_completion_in(default_runtime());
        assert!(complete_tx_request_in(
            default_runtime(),
            completion_id,
            Ok(())
        ));
        assert_eq!(crate::task::block_on(future), Ok(()));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_completion_future_resolves_error() {
        let (completion_id, future) = register_tx_completion_in(default_runtime());
        assert!(complete_tx_request_in(
            default_runtime(),
            completion_id,
            Err("submit failed")
        ));
        assert_eq!(crate::task::block_on(future), Err("submit failed"));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_payload_lease_derives_descriptor_for_each_owner() {
        let first = test_packet_ref_with_device_addr(8, 0x1000);
        let second = test_packet_ref_with_device_addr(16, 0x2000);
        let payload = PacketPayload::try_pair(first, second).expect("non-empty test segments");

        let lease = TxPayloadLease::from_payload(payload).expect("payload lease");
        let registered = register_tx_payload_lease_in(
            default_runtime(),
            NetIfId(1),
            lease,
            None,
            NetTxMeta::default(),
        )
        .expect("registered test lease");
        let request = registered.into_request();
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(2)
            .expect("descriptor scratch");
        assert!(
            build_tx_descriptors_in(default_runtime(), request.lease_id, &mut descriptors, 2,)
                .is_some()
        );
        assert_eq!(descriptors.len(), 2);
        assert_eq!(descriptors[0].device_addr().get(), 0x1000);
        assert_eq!(descriptors[0].len().get(), 8);
        assert_eq!(descriptors[1].device_addr().get(), 0x2000);
        assert_eq!(descriptors[1].len().get(), 16);
        assert!(reject_registered_tx_lease_in(
            default_runtime(),
            request.lease_id,
            "test cleanup",
        ));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_descriptor_plan_rejects_invalid_packet_descriptor() {
        let payload = PacketPayload::try_single(test_packet_ref_with_device_addr(8, 0))
            .expect("non-empty test packet");
        let lease = TxPayloadLease::from_payload(payload).expect("payload lease");
        let registered = register_tx_payload_lease_in(
            default_runtime(),
            NetIfId(1),
            lease,
            None,
            NetTxMeta::default(),
        )
        .expect("registered test lease");
        let request = registered.into_request();
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(1)
            .expect("descriptor scratch");
        assert!(
            build_tx_descriptors_in(default_runtime(), request.lease_id, &mut descriptors, 1,)
                .is_none()
        );
        assert!(reject_registered_tx_lease_in(
            default_runtime(),
            request.lease_id,
            "test cleanup",
        ));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn packet_window_descriptors_reference_original_packet_range() {
        let _ = crate::net::datapath::mempool::init_net_mempool(16);
        let mut packet = crate::net::datapath::mempool::alloc_packet().expect("packet");
        packet.try_resize(32).expect("test packet resize succeeds");
        let base_ptr = packet.data().as_ptr() as usize;
        let base_device_addr = packet.device_address();
        let owners = TxPayloadOwners::from_packets(alloc::vec![packet]).expect("owners");
        let header = test_packet_ref_with_device_addr(8, 0x40);

        let bounds = TxPayloadWindowBounds::checked(
            &owners,
            8,
            PacketByteCount::new(16).expect("non-empty window"),
        )
        .expect("owner-bound window");
        let lease = TxPayloadLease::from_header_and_owner_window(header, &owners, bounds)
            .expect("fragment lease");
        let group_id = register_tx_owner_group_in(
            default_runtime(),
            owners,
            TxOwnerGroupLeaseCount::new(1).expect("one lease"),
            None,
        );
        let request = register_grouped_tx_payload_lease_in(
            default_runtime(),
            NetIfId(1),
            lease,
            group_id,
            NetTxMeta::default(),
        )
        .expect("registered fragment lease");
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(2)
            .expect("descriptor scratch");
        assert!(
            build_tx_descriptors_in(default_runtime(), request.lease_id, &mut descriptors, 2,)
                .is_some()
        );
        let payload_descriptor = &descriptors[1];

        assert_eq!(descriptors.len(), 2);
        assert_eq!(payload_descriptor.cpu_ptr(), (base_ptr + 8) as *const u8);
        assert_eq!(payload_descriptor.device_addr().get(), base_device_addr + 8);
        assert_eq!(payload_descriptor.len().get(), 16);
        assert!(reject_registered_tx_lease_in(
            default_runtime(),
            request.lease_id,
            "test cleanup",
        ));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn packet_window_descriptor_rejects_device_address_overflow() {
        let packet = test_packet_ref_with_device_addr(16, u64::MAX - 4);
        let owners = TxPayloadOwners::from_packets(alloc::vec![packet]).expect("owners");
        let header = test_packet_ref_with_device_addr(8, 0x40);

        let bounds = TxPayloadWindowBounds::checked(
            &owners,
            8,
            PacketByteCount::new(4).expect("non-empty window"),
        )
        .expect("owner-bound window");
        let lease = TxPayloadLease::from_header_and_owner_window(header, &owners, bounds)
            .expect("bounds are valid independently of DMA arithmetic");
        let group_id = register_tx_owner_group_in(
            default_runtime(),
            owners,
            TxOwnerGroupLeaseCount::new(1).expect("one lease"),
            None,
        );
        let request = register_grouped_tx_payload_lease_in(
            default_runtime(),
            NetIfId(1),
            lease,
            group_id,
            NetTxMeta::default(),
        )
        .expect("registered fragment lease");
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(2)
            .expect("descriptor scratch");
        assert!(
            build_tx_descriptors_in(default_runtime(), request.lease_id, &mut descriptors, 2,)
                .is_none()
        );
        assert!(reject_registered_tx_lease_in(
            default_runtime(),
            request.lease_id,
            "test cleanup",
        ));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_owner_group_completes_after_all_fragment_leases() {
        let _ = crate::net::datapath::mempool::init_net_mempool(16);
        let mut owner = crate::net::datapath::mempool::alloc_packet().expect("owner");
        owner.try_resize(32).expect("test owner resize succeeds");
        let mut header_a = crate::net::datapath::mempool::alloc_packet().expect("header a");
        header_a
            .try_resize(8)
            .expect("first test header resize succeeds");
        let mut header_b = crate::net::datapath::mempool::alloc_packet().expect("header b");
        header_b
            .try_resize(8)
            .expect("second test header resize succeeds");
        let (completion_id, future) = register_tx_completion_in(default_runtime());
        let owners = TxPayloadOwners::from_packets(alloc::vec![owner]).expect("non-empty owner");
        let group_id = register_tx_owner_group_in(
            default_runtime(),
            owners,
            TxOwnerGroupLeaseCount::new(2).expect("non-zero leases"),
            Some(completion_id),
        );
        let request_a = register_grouped_tx_payload_lease_in(
            default_runtime(),
            NetIfId(1),
            TxPayloadLease::from_payload(
                PacketPayload::try_single(header_a).expect("non-empty first header"),
            )
            .expect("request a lease"),
            group_id,
            NetTxMeta::default(),
        )
        .expect("request a");
        let request_b = register_grouped_tx_payload_lease_in(
            default_runtime(),
            NetIfId(1),
            TxPayloadLease::from_payload(
                PacketPayload::try_single(header_b).expect("non-empty second header"),
            )
            .expect("request b lease"),
            group_id,
            NetTxMeta::default(),
        )
        .expect("request b");

        assert!(
            default_runtime_context()
                .tx_owner_groups
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&group_id)
        );
        assert!(begin_tx_submission_in(
            default_runtime(),
            request_a.lease_id
        ));
        assert!(complete_tx_lease_in(
            default_runtime(),
            request_a.lease_id,
            TxDeviceOutcome::Transmitted,
        ));
        assert!(
            default_runtime_context()
                .tx_owner_groups
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&group_id)
        );
        assert!(begin_tx_submission_in(
            default_runtime(),
            request_b.lease_id
        ));
        assert!(complete_tx_lease_in(
            default_runtime(),
            request_b.lease_id,
            TxDeviceOutcome::NotTransmitted,
        ));
        assert!(
            !default_runtime_context()
                .tx_owner_groups
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&group_id)
        );
        assert_eq!(
            crate::task::block_on(future),
            Err("device did not transmit packet")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn accepted_tx_lease_retains_backing_until_exactly_one_completion() {
        let releases = AtomicUsize::new(0);
        let payload = PacketPayload::try_single(test_counted_packet_ref(8, 0x9100, &releases))
            .expect("counted payload is non-empty");
        let lease = TxPayloadLease::from_payload(payload).expect("payload lease");
        let request = register_tx_payload_lease_in(
            default_runtime(),
            NetIfId(301),
            lease,
            None,
            NetTxMeta::default(),
        )
        .expect("registered lease")
        .into_request();

        assert_eq!(releases.load(Ordering::SeqCst), 0);
        assert!(begin_tx_submission_in(default_runtime(), request.lease_id));
        assert!(mark_tx_device_owned_in(default_runtime(), request.lease_id));
        assert_eq!(releases.load(Ordering::SeqCst), 0);

        assert!(complete_tx_lease_in(
            default_runtime(),
            request.lease_id,
            TxDeviceOutcome::Transmitted,
        ));
        assert_eq!(releases.load(Ordering::SeqCst), 1);
        assert!(!complete_tx_lease_in(
            default_runtime(),
            request.lease_id,
            TxDeviceOutcome::Transmitted,
        ));
        assert_eq!(releases.load(Ordering::SeqCst), 1);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn synchronous_completion_consumes_submitting_lease_without_recycling_early() {
        let releases = AtomicUsize::new(0);
        let payload = PacketPayload::try_single(test_counted_packet_ref(8, 0x9200, &releases))
            .expect("counted payload is non-empty");
        let request = register_tx_payload_lease_in(
            default_runtime(),
            NetIfId(302),
            TxPayloadLease::from_payload(payload).expect("payload lease"),
            None,
            NetTxMeta::default(),
        )
        .expect("registered lease")
        .into_request();

        assert!(begin_tx_submission_in(default_runtime(), request.lease_id));
        assert_eq!(releases.load(Ordering::SeqCst), 0);
        assert!(complete_tx_lease_in(
            default_runtime(),
            request.lease_id,
            TxDeviceOutcome::Transmitted,
        ));
        assert_eq!(releases.load(Ordering::SeqCst), 1);
        assert!(mark_tx_device_owned_in(default_runtime(), request.lease_id));
        assert!(!complete_tx_lease_in(
            default_runtime(),
            request.lease_id,
            TxDeviceOutcome::Transmitted,
        ));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn rejected_tx_lease_returns_backing_without_device_ownership() {
        let releases = AtomicUsize::new(0);
        let payload = PacketPayload::try_single(test_counted_packet_ref(8, 0x9300, &releases))
            .expect("counted payload is non-empty");
        let request = register_tx_payload_lease_in(
            default_runtime(),
            NetIfId(303),
            TxPayloadLease::from_payload(payload).expect("payload lease"),
            None,
            NetTxMeta::default(),
        )
        .expect("registered lease")
        .into_request();

        assert_eq!(releases.load(Ordering::SeqCst), 0);
        assert!(reject_registered_tx_lease_in(
            default_runtime(),
            request.lease_id,
            "fake driver rejected request",
        ));
        assert_eq!(releases.load(Ordering::SeqCst), 1);
        assert!(!complete_tx_lease_in(
            default_runtime(),
            request.lease_id,
            TxDeviceOutcome::Transmitted,
        ));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn successful_stop_releases_queued_and_device_owned_leases_after_quiesce() {
        let (state, driver) = fake_driver();
        let if_id = NetIfId(304);
        let handle = NetDeviceHandle::new(
            driver,
            NetDeviceBinding {
                port_id: test_port_id(304),
                if_id,
            },
            default_runtime_context(),
        );
        let queued_releases = AtomicUsize::new(0);
        let queued_payload =
            PacketPayload::try_single(test_counted_packet_ref(8, 0x9400, &queued_releases))
                .expect("queued payload is non-empty");
        assert!(
            handle
                .enqueue_tx(queued_payload, NetTxMeta::default())
                .is_ok()
        );

        let owned_releases = AtomicUsize::new(0);
        let owned_payload =
            PacketPayload::try_single(test_counted_packet_ref(8, 0x9500, &owned_releases))
                .expect("owned payload is non-empty");
        let owned_request = register_tx_payload_lease_in(
            default_runtime(),
            if_id,
            TxPayloadLease::from_payload(owned_payload).expect("owned payload lease"),
            None,
            NetTxMeta::default(),
        )
        .expect("registered owned lease")
        .into_request();
        assert!(begin_tx_submission_in(
            default_runtime(),
            owned_request.lease_id
        ));
        assert!(mark_tx_device_owned_in(
            default_runtime(),
            owned_request.lease_id
        ));

        assert_eq!(queued_releases.load(Ordering::SeqCst), 0);
        assert_eq!(owned_releases.load(Ordering::SeqCst), 0);
        handle.stop().expect("fake driver quiesces");
        assert_eq!(state.stop_calls.load(Ordering::Relaxed), 1);
        assert_eq!(queued_releases.load(Ordering::SeqCst), 1);
        assert_eq!(owned_releases.load(Ordering::SeqCst), 1);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn failed_stop_keeps_port_and_device_owned_lease_quarantined_until_completion() {
        let (_state, driver) = fake_driver_with_stop_error("stop-fail", "quiesce failed");
        let if_id = register_test_port(85, driver, PrimaryPortPolicy::Never)
            .expect("register stop-failure port");
        let releases = AtomicUsize::new(0);
        let payload = PacketPayload::try_single(test_counted_packet_ref(8, 0x9600, &releases))
            .expect("counted payload is non-empty");
        let request = register_tx_payload_lease_in(
            default_runtime(),
            if_id,
            TxPayloadLease::from_payload(payload).expect("payload lease"),
            None,
            NetTxMeta::default(),
        )
        .expect("registered lease")
        .into_request();
        assert!(begin_tx_submission_in(default_runtime(), request.lease_id));
        assert!(mark_tx_device_owned_in(default_runtime(), request.lease_id));

        assert_eq!(
            unregister_port_in(default_runtime(), if_id),
            Err("quiesce failed")
        );
        assert_eq!(
            lookup_if_by_port_id_in(default_runtime(), test_port_id(85)),
            Some(if_id)
        );
        assert_eq!(releases.load(Ordering::SeqCst), 0);
        assert!(
            default_runtime_context()
                .tx_leases
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .contains_key(&request.lease_id)
        );

        assert!(complete_tx_lease_in(
            default_runtime(),
            request.lease_id,
            TxDeviceOutcome::OutcomeUnknown,
        ));
        assert_eq!(releases.load(Ordering::SeqCst), 1);
        assert!(unregister_test_port(if_id));
        assert_eq!(
            lookup_if_by_port_id_in(default_runtime(), test_port_id(85)),
            None
        );
    }
}
