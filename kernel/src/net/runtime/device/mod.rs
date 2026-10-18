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
    NetPortRuntimeOps, NetPortStats, NetRxMeta, NetTxMeta, PrimaryPortPolicy, ReceivedPacket,
    RxBuffer, TxDeviceOutcome, TxLeaseId, TxPacketSubmission,
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

fn packet_to_tx_region(packet: &PacketRef) -> Option<kernel_api::resource::net::PacketDmaRegion> {
    packet
        .dma_region(0, PacketByteCount::new(packet.len())?)
        .ok()
}

fn append_tx_payload_segments(
    descriptors: &mut Vec<kernel_api::resource::net::PacketDmaRegion>,
    packets: &[PacketRef],
    max_segments: usize,
) -> Option<()> {
    for packet in packets {
        if descriptors.len() >= max_segments {
            return None;
        }
        descriptors.push(packet_to_tx_region(packet)?);
    }
    Some(())
}

fn append_tx_payload_window_segments(
    descriptors: &mut Vec<kernel_api::resource::net::PacketDmaRegion>,
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
        descriptors.push(packet.dma_region(local_start, descriptor_len).ok()?);
    }

    Some(())
}

fn build_tx_descriptors_in(
    runtime: NetRuntimeHandle,
    lease_id: TxLeaseId,
    descriptors: &mut Vec<kernel_api::resource::net::PacketDmaRegion>,
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
    // LOOP_PROOF: mode=event; reason=Every atomic fetch advances the identifier sequence and the call returns at the next nonzero identifier.;
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
    // LOOP_PROOF: mode=event; reason=Port stop has closed admission under driver_gate, each iteration removes one retained lease, and an empty matching set ends finalization.;
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
        if let Ok(Some(iface)) = manager::get_interface_in(runtime, if_id)
            && let Some(config) = iface.config
            && let Err(error) =
                crate::net::services::dhcp::ensure_interface_runtime_in(runtime, if_id, config)
        {
            log::warn!(
                target: "net::device",
                "DHCP runtime start failed for if{} after link-up: {}",
                if_id.0,
                error
            );
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

    fn stop(&self) -> kernel_api::error::KapiResult<()> {
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
        crate::task::spawn(tx_worker(runtime, if_id), crate::task::TaskOptions::any())
            .map_err(|_| "failed to spawn network TX worker")?;
    }
    if start_event {
        crate::task::spawn(
            event_worker(runtime, if_id),
            crate::task::TaskOptions::any(),
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
    // LOOP_PROOF: mode=event; reason=The TX worker awaits its queue when empty, consumes accepted requests, and returns after its port owner closes admission.;
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

        // LOOP_PROOF: mode=condition; reason=Each iteration consumes one queued TX request and returns on closed admission or an unavailable port, with queue exhaustion ending the batch.;
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
                // SAFETY: Submitting is published above. The registry retains
                // CPU-inaccessible packet owners until rejection or completion;
                // counted regions keep the backing live through synchronous
                // completion without holding the lease registry lock.
                let submission =
                    unsafe { TxPacketSubmission::new(request.lease_id, &descriptor_scratch) }
                        .expect("validated nonempty packet regions");
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
            descriptor_scratch.clear();
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
    // LOOP_PROOF: mode=event; reason=The port owner controls worker lifetime, an empty event queue is awaited, and closed admission terminates the worker.;
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

        // LOOP_PROOF: mode=condition; reason=Each handled event is removed from the bounded port queue, and queue exhaustion or closed admission ends this batch.;
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
}

impl NetDeviceManager {
    pub const fn new() -> Self {
        Self {
            handles: BTreeMap::new(),
            port_map: BTreeMap::new(),
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

/// Registration failure distinguishes completed rollback from an interface
/// whose callbacks or DMA remain owned by the runtime for shutdown retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetPortRegistrationError {
    NotPublished(&'static str),
    /// Startup had side effects, followed by acknowledged shutdown/release.
    Released(&'static str),
    Retained {
        if_id: NetIfId,
        cause: &'static str,
        shutdown: kernel_api::error::KapiError,
    },
}

impl core::fmt::Display for NetPortRegistrationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotPublished(cause) | Self::Released(cause) => f.write_str(cause),
            Self::Retained {
                if_id,
                cause,
                shutdown,
            } => write!(f, "{cause}; if{} retained: {shutdown}", if_id.0),
        }
    }
}

fn finish_failed_registration(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    cause: &'static str,
) -> NetPortRegistrationError {
    match unregister_port_in(runtime, if_id) {
        Ok(true) => NetPortRegistrationError::Released(cause),
        outcome => NetPortRegistrationError::Retained {
            if_id,
            cause,
            shutdown: match outcome {
                Err(cause) => cause,
                Ok(false) => kernel_api::error::KapiError::NotFound,
                Ok(true) => unreachable!(),
            },
        },
    }
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
) -> Result<NetIfId, NetPortRegistrationError> {
    let driver = registration.driver;
    let info = registration.info;
    let config = default_config_for_port(info);
    ensure_stack_initialized_in(runtime).map_err(NetPortRegistrationError::NotPublished)?;

    let primary_preference = manager_primary_preference(registration.primary_policy);
    if let Some(existing) = lookup_if_by_port_id_in(runtime, info.port_id) {
        manager::set_primary_preference_in(runtime, existing, primary_preference).map_err(
            |_| {
                NetPortRegistrationError::NotPublished(
                    "failed to update network interface preference",
                )
            },
        )?;
        return Ok(existing);
    }

    let base = driver.info();
    let if_id = interface_for_port(
        runtime,
        info.port_id,
        config,
        base.driver_name,
        primary_preference,
    )
    .map_err(NetPortRegistrationError::NotPublished)?;
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
        return Err(NetPortRegistrationError::NotPublished(err));
    }
    let runtime_handle = handle.runtime;

    {
        let mut guard = device_manager_in(runtime)
            .write()
            .unwrap_or_else(|e| e.into_inner());
        guard.port_map.insert(info.port_id, if_id);
        guard.handles.insert(if_id, handle);
    }

    // Seed link state before start can report a fresher hardware observation.
    // Start callbacks own subsequent updates, including synchronous link-up.
    let initial_link_state = if info.flags & NETDEV_FLAG_LINK_UP != 0 {
        manager::LinkState::Up
    } else {
        manager::LinkState::Down
    };
    if manager::set_interface_link_state_in(runtime, if_id, initial_link_state).is_err() {
        return Err(finish_failed_registration(
            runtime,
            if_id,
            "failed to publish initial network link state",
        ));
    }

    if let Some(start_result) =
        with_port_handle_in(runtime, if_id, |handle| handle.driver.start(runtime_handle))
    {
        if let Err(err) = start_result {
            return Err(finish_failed_registration(runtime, if_id, err));
        }
    } else {
        return Err(finish_failed_registration(
            runtime,
            if_id,
            "device handle missing after registration",
        ));
    }

    if let Err(error) = start_workers_for_port_in(runtime, if_id) {
        return Err(finish_failed_registration(runtime, if_id, error));
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

pub fn unregister_port_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> kernel_api::error::KapiResult<bool> {
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

#[cfg(feature = "qemu-test-export")]
pub(crate) mod qemu_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_queue_roundtrip_smoke() {
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
}
