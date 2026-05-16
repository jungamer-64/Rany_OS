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
use crate::net::runtime::context::{NetRuntimeContext, default_runtime, default_runtime_context};
use crate::net::runtime::manager::{self, NetIfId};
use crate::net::runtime::stack::{self, NetworkConfig};
use crate::per_cpu::in_interrupt_context;
use crate::sync::atomic_waker::AtomicWaker;
use crate::sync::lockfree::MpmcRingBuffer;
use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use kernel_api::resource::net::{PacketPayload, PacketRef};
use kernel_api::service::netdev::{
    MacAddress, NETDEV_FLAG_ADMIN_UP, NETDEV_FLAG_BOUND_PORT, NETDEV_FLAG_HEALTHY,
    NETDEV_FLAG_LINK_UP, NETDEV_FLAG_PRIMARY, NetDeviceInfo, NetDevicePort, NetDriverEvent,
    NetLogLevel, NetPortId, NetPortRegistration, NetPortRuntimeHandle, NetPortRuntimeOps,
    NetPortStats, NetRxMeta, NetTxCompletionPolicy, NetTxMeta, NetTxSegment, PrimaryPortPolicy,
    TxLeaseId, TxSubmission,
};

const NET_DEVICE_TX_QUEUE_CAPACITY: usize = 1024;
const NET_DEVICE_EVENT_QUEUE_CAPACITY: usize = 256;

type TxCompletionResult = Result<(), &'static str>;

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
    keepalive: Vec<PacketRef>,
    completion_id: Option<u64>,
    owner_group_id: Option<u64>,
}

impl TxLeaseState {
    fn new(keepalive: Vec<PacketRef>, completion_id: Option<u64>) -> Self {
        Self {
            keepalive,
            completion_id,
            owner_group_id: None,
        }
    }

    fn grouped(keepalive: Vec<PacketRef>, owner_group_id: u64) -> Self {
        Self {
            keepalive,
            completion_id: None,
            owner_group_id: Some(owner_group_id),
        }
    }
}

pub(crate) struct TxOwnerGroupState {
    keepalive: Vec<PacketRef>,
    completion_id: Option<u64>,
    remaining_leases: usize,
    result: TxCompletionResult,
}

impl TxOwnerGroupState {
    fn new(keepalive: Vec<PacketRef>, completion_id: Option<u64>, remaining_leases: usize) -> Self {
        Self {
            keepalive,
            completion_id,
            remaining_leases,
            result: Ok(()),
        }
    }

    fn complete_one(&mut self, result: TxCompletionResult) -> bool {
        if self.result.is_ok() {
            self.result = result;
        }
        self.remaining_leases = self.remaining_leases.saturating_sub(1);
        self.remaining_leases == 0
    }

    fn into_parts(self) -> (Vec<PacketRef>, Option<u64>, TxCompletionResult) {
        (self.keepalive, self.completion_id, self.result)
    }
}

fn complete_tx_owner_group_in(
    runtime: NetRuntimeHandle,
    group_id: u64,
    result: TxCompletionResult,
) -> bool {
    let completed = {
        let mut groups = runtime_context_for(runtime)
            .tx_owner_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(group) = groups.get_mut(&group_id) else {
            return false;
        };
        if !group.complete_one(result) {
            return true;
        }
        groups.remove(&group_id)
    };

    let Some(group) = completed else {
        return false;
    };
    let (keepalive, completion_id, final_result) = group.into_parts();
    if let Some(completion_id) = completion_id {
        let _owner_returned = crate::net::l4::tcp::retransmit::complete_tx_owner(
            completion_id,
            keepalive,
            final_result,
        );
        let _ = complete_tx_request_in(runtime, completion_id, final_result);
    }
    true
}

pub(crate) fn register_tx_owner_group_in(
    runtime: NetRuntimeHandle,
    keepalive: Vec<PacketRef>,
    remaining_leases: usize,
    completion_id: Option<u64>,
) -> Option<u64> {
    if keepalive.is_empty() || remaining_leases == 0 {
        return None;
    }
    let group_id = runtime_context_for(runtime)
        .tx_owner_group_next_id
        .fetch_add(1, Ordering::Relaxed);
    runtime_context_for(runtime)
        .tx_owner_groups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            group_id,
            TxOwnerGroupState::new(keepalive, completion_id, remaining_leases),
        );
    Some(group_id)
}

pub(crate) fn unregister_tx_owner_group_in(runtime: NetRuntimeHandle, group_id: u64) {
    runtime_context_for(runtime)
        .tx_owner_groups
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&group_id);
}

pub(crate) fn packet_window_to_tx_segments(
    packets: &[PacketRef],
    offset: usize,
    len: usize,
) -> Option<Vec<NetTxSegment>> {
    if len == 0 {
        return None;
    }

    let mut descriptors = Vec::new();
    let mut cursor = 0usize;
    let window_end = offset.checked_add(len)?;
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
        let descriptor_len = local_end - local_start;
        let cpu_ptr = unsafe { packet.data().as_ptr().add(local_start) };
        descriptors.push(NetTxSegment::new(
            cpu_ptr,
            packet.device_address().saturating_add(local_start as u64),
            descriptor_len,
        ));
    }

    (!descriptors.is_empty()).then_some(descriptors)
}

pub(crate) fn register_grouped_tx_lease_in(
    runtime: NetRuntimeHandle,
    keepalive: Vec<PacketRef>,
    owner_group_id: u64,
    descriptors: Vec<NetTxSegment>,
    meta: NetTxMeta,
) -> Option<TxRequest> {
    if descriptors.is_empty() {
        return None;
    }
    let lease_id = runtime_context_for(runtime)
        .tx_lease_next_id
        .fetch_add(1, Ordering::Relaxed);
    runtime_context_for(runtime)
        .tx_leases
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(lease_id, TxLeaseState::grouped(keepalive, owner_group_id));
    Some(TxRequest {
        lease_id,
        descriptors,
        meta,
    })
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

fn runtime_context() -> &'static NetRuntimeContext {
    default_runtime_context()
}

fn runtime_context_for(runtime: NetRuntimeHandle) -> &'static NetRuntimeContext {
    runtime.context()
}

fn device_manager() -> &'static PoisonRwLock<NetDeviceManager> {
    &runtime_context().device_manager
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
    pub(crate) descriptors: Vec<NetTxSegment>,
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

    fn push(&self, request: TxRequest) -> bool {
        match self.queue.push(request) {
            Ok(()) => {
                self.waker.wake();
                true
            }
            Err(_) => false,
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

pub struct NetEventSink {
    queue: MpmcRingBuffer<NetDriverEvent, NET_DEVICE_EVENT_QUEUE_CAPACITY>,
    waker: AtomicWaker,
}

impl NetEventSink {
    pub const CAPACITY: usize = NET_DEVICE_EVENT_QUEUE_CAPACITY;

    pub fn new() -> Self {
        Self {
            queue: MpmcRingBuffer::new(),
            waker: AtomicWaker::new(),
        }
    }

    pub fn push(&self, event: NetDriverEvent) -> bool {
        match self.queue.push(event) {
            Ok(()) => {
                if in_interrupt_context() {
                    self.waker.wake_from_isr();
                } else {
                    self.waker.wake();
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
    (!packet.is_empty()).then_some(NetTxSegment::new(
        packet.data().as_ptr(),
        packet.device_address(),
        packet.len(),
    ))
}

fn payload_to_keepalive_and_descriptors(
    payload: PacketPayload,
) -> Option<(Vec<PacketRef>, Vec<NetTxSegment>)> {
    let keepalive = payload.into_segments();
    let descriptors: Vec<NetTxSegment> =
        keepalive.iter().filter_map(packet_to_tx_segment).collect();
    (!descriptors.is_empty()).then_some((keepalive, descriptors))
}

pub(crate) fn register_tx_lease_in(
    runtime: NetRuntimeHandle,
    keepalive: Vec<PacketRef>,
    descriptors: Vec<NetTxSegment>,
    completion_id: Option<u64>,
) -> Option<TxRequest> {
    if descriptors.is_empty() {
        return None;
    }

    let lease_id = runtime_context_for(runtime)
        .tx_lease_next_id
        .fetch_add(1, Ordering::Relaxed);
    let state = TxLeaseState::new(keepalive, completion_id);
    runtime_context_for(runtime)
        .tx_leases
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(lease_id, state);
    Some(TxRequest {
        lease_id,
        descriptors,
        meta: NetTxMeta::default(),
    })
}

fn register_payload_tx_request_in(
    runtime: NetRuntimeHandle,
    payload: PacketPayload,
    meta: NetTxMeta,
) -> Option<TxRequest> {
    let (keepalive, descriptors) = payload_to_keepalive_and_descriptors(payload)?;
    let mut request = register_tx_lease_in(runtime, keepalive, descriptors, meta.completion_id)?;
    request.meta = meta;
    Some(request)
}

pub fn complete_tx_lease_in(
    runtime: NetRuntimeHandle,
    lease_id: TxLeaseId,
    result: TxCompletionResult,
) -> bool {
    let lease = runtime_context_for(runtime)
        .tx_leases
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&lease_id);
    if let Some(lease) = lease {
        if let Some(owner_group_id) = lease.owner_group_id {
            return complete_tx_owner_group_in(runtime, owner_group_id, result);
        }
        if let Some(completion_id) = lease.completion_id {
            let _owner_returned = crate::net::l4::tcp::retransmit::complete_tx_owner(
                completion_id,
                lease.keepalive,
                result,
            );
            let _ = complete_tx_request_in(runtime, completion_id, result);
            return true;
        }
        true
    } else {
        false
    }
}

fn runtime_context_from_cookie(cookie: usize) -> &'static NetRuntimeContext {
    unsafe { &*(cookie as *const NetRuntimeContext) }
}

fn runtime_handle_for_port(
    context: &'static NetRuntimeContext,
    port_id: NetPortId,
) -> NetPortRuntimeHandle {
    NetPortRuntimeHandle::new(
        context as *const NetRuntimeContext as usize,
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

fn runtime_alloc_packet(_: usize, _: NetPortId) -> Option<PacketRef> {
    crate::net::datapath::mempool::alloc_packet()
}

fn runtime_submit_rx(
    cookie: usize,
    port_id: NetPortId,
    packet: PacketRef,
    meta: NetRxMeta,
) -> Result<(), &'static str> {
    let context = runtime_context_from_cookie(cookie);
    let if_id = current_if_for_port(context, port_id)?;
    crate::net::runtime::bridge::process_received_packet_zero_copy_for_interface_in(
        context.handle(),
        if_id,
        packet,
        meta.header_len as usize,
        meta.payload_len as usize,
    );
    Ok(())
}

fn runtime_schedule_event(
    cookie: usize,
    port_id: NetPortId,
    event: NetDriverEvent,
) -> Result<(), &'static str> {
    let runtime = runtime_context_from_cookie(cookie).handle();
    let queued = if in_interrupt_context() {
        enqueue_event_from_isr_in(runtime, port_id, event)
    } else {
        enqueue_event_in(runtime, port_id, event)
    };
    if queued {
        Ok(())
    } else {
        Err("port event queue full")
    }
}

fn runtime_update_link(cookie: usize, port_id: NetPortId, up: bool) -> Result<(), &'static str> {
    let runtime = runtime_context_from_cookie(cookie).handle();
    let if_id = current_if_for_port(runtime_context_for(runtime), port_id)?;
    let result = if up {
        manager::set_interface_up_in(runtime, if_id)
    } else {
        manager::set_interface_down_in(runtime, if_id)
    };
    result.map_err(|_| "failed to update interface link state")?;

    if up {
        if let Ok(Some(iface)) = manager::get_interface_in(runtime, if_id) {
            if let Some(config) = iface.config {
                let _ = crate::net::services::dhcp::ensure_interface_runtime(if_id, config);
            }
        }
        let _ = crate::net::services::dhcp::restart_interface_runtime(if_id);
        if primary_if_in(runtime) == Some(if_id) {
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
        handle_interface_departure(if_id, FailoverReason::LinkDown);
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
    runtime_alloc_packet,
    runtime_submit_rx,
    runtime_schedule_event,
    runtime_update_link,
    runtime_log,
);

pub struct NetDeviceHandle {
    driver: Box<dyn NetDevicePort>,
    binding: PoisonLock<NetDeviceBinding>,
    runtime: NetPortRuntimeHandle,
    tx_queue: NetTxQueue,
    event_sink: NetEventSink,
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
            runtime: runtime_handle_for_port(context, binding.port_id),
            binding: PoisonLock::new(binding),
            tx_queue: NetTxQueue::new(),
            event_sink: NetEventSink::new(),
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
        if primary_if_in(default_runtime()) == Some(binding.if_id) {
            info.flags |= NETDEV_FLAG_PRIMARY;
        }
        if let Ok(Some(interface)) = manager::get_interface_in(default_runtime(), binding.if_id) {
            if interface.admin_up {
                info.flags |= NETDEV_FLAG_ADMIN_UP;
            } else {
                info.flags &= !NETDEV_FLAG_ADMIN_UP;
            }
        }
        info
    }

    pub fn enqueue_tx(&self, payload: PacketPayload, meta: NetTxMeta) -> bool {
        register_payload_tx_request_in(default_runtime(), payload, meta)
            .is_some_and(|request| self.tx_queue.push(request))
    }

    pub(crate) fn enqueue_tx_request(&self, request: TxRequest) -> bool {
        self.tx_queue.push(request)
    }

    pub fn enqueue_event(&self, event: NetDriverEvent) -> bool {
        self.event_sink.push(event)
    }

    pub fn enqueue_event_from_isr(&self, event: NetDriverEvent) -> bool {
        self.event_sink.push(event)
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

    fn stop(&self) {
        self.active.store(false, Ordering::Release);
        self.tx_queue.wake();
        self.event_sink.wake();
        self.driver.stop();
    }
}

fn with_port_handle_in<R>(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    f: impl FnOnce(&NetDeviceHandle) -> R,
) -> Option<R> {
    device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .get(&if_id)
        .map(f)
}

fn pop_tx_request_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> Option<TxRequest> {
    with_port_handle_in(runtime, if_id, |handle| handle.tx_queue.pop()).flatten()
}

fn pop_driver_event_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> Option<NetDriverEvent> {
    with_port_handle_in(runtime, if_id, |handle| handle.event_sink.pop()).flatten()
}

fn start_workers_for_port_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    let start = with_port_handle_in(runtime, if_id, |handle| {
        (
            !handle.tx_worker_started.swap(true, Ordering::AcqRel),
            !handle.event_worker_started.swap(true, Ordering::AcqRel),
        )
    });
    let Some((start_tx, start_event)) = start else {
        return;
    };
    if start_tx {
        crate::task::spawn_task(crate::task::Task::new(tx_worker(runtime, if_id)));
    }
    if start_event {
        crate::task::spawn_task(crate::task::Task::new(event_worker(runtime, if_id)));
    }
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

            let completion_policy = request.meta.completion_policy;
            let submission = TxSubmission::new(request.lease_id, &request.descriptors);
            let submitted = with_port_handle_in(runtime, if_id, |handle| {
                (
                    handle.binding().port_id,
                    handle.driver.submit_tx_chain(submission, request.meta),
                )
            });
            match submitted {
                Some((port_id, Err(err))) => {
                    let _ = complete_tx_lease_in(runtime, request.lease_id, Err(err));
                    log::warn!(
                        target: "net::device",
                        "device port={} TX submission failed: {}",
                        port_id.as_u64(),
                        err
                    );
                }
                Some((_, Ok(())))
                    if completion_policy == NetTxCompletionPolicy::QueueAcceptance =>
                {
                    let _ = complete_tx_lease_in(runtime, request.lease_id, Ok(()));
                }
                Some((_, Ok(()))) => {}
                None => {
                    let _ = complete_tx_lease_in(
                        runtime,
                        request.lease_id,
                        Err("device handle missing"),
                    );
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
                let binding = handle.binding();
                let result = match event {
                    NetDriverEvent::Poll => handle.driver.poll(binding.if_id.0),
                    _ => handle.driver.handle_event(binding.if_id.0, event),
                };
                (binding.port_id, result)
            });
            match handled {
                Some((port_id, Err(err))) => {
                    log::warn!(
                        target: "net::device",
                        "device port={} event {:?} failed: {}",
                        port_id.as_u64(),
                        event,
                        err
                    );
                }
                Some((_, Ok(()))) => {}
                None => return,
            }
            pending = pop_driver_event_in(runtime, if_id);
        }
    }
}

#[derive(Default)]
pub struct NetDeviceManager {
    handles: BTreeMap<NetIfId, NetDeviceHandle>,
    port_map: BTreeMap<NetPortId, NetIfId>,
    primary: Option<NetIfId>,
}

impl NetDeviceManager {
    pub const fn new() -> Self {
        Self {
            handles: BTreeMap::new(),
            port_map: BTreeMap::new(),
            primary: None,
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

fn apply_runtime_network_config(config: &NetworkConfig) {
    if let Ok(mut guard) = stack::stack_in(default_runtime()).lock() {
        if let Some(stack) = guard.as_mut() {
            stack.set_config(*config);
        }
    }

    crate::net::services::dhcp::update_runtime_mac(config.mac);
}

fn sync_runtime_config_for_interface(if_id: NetIfId) {
    let config = match manager::get_interface_in(default_runtime(), if_id) {
        Ok(Some(iface)) => iface.config,
        _ => None,
    };
    if let Some(config) = config {
        apply_runtime_network_config(&config);
    }
}

fn clear_runtime_network_config() {
    if let Ok(mut guard) = stack::stack_in(default_runtime()).lock() {
        if let Some(stack) = guard.as_mut() {
            let mut config = stack.config();
            config.ipv4 = Ipv4Config::default();
            stack.set_config(config);
            crate::net::services::dhcp::update_runtime_mac(config.mac);
        }
    }
}

fn config_supports_failover(config: &NetworkConfig) -> bool {
    !config.ipv4.address.is_any()
        || !config.ipv4.gateway.is_any()
        || config.ipv4.dns.is_some()
        || config
            .ipv6
            .is_some_and(|ipv6| ipv6.global.is_some() || ipv6.gateway.is_some())
}

fn interface_supports_failover(if_id: NetIfId) -> bool {
    if crate::net::services::dhcp::has_bound_lease(if_id) {
        return true;
    }

    manager::get_interface_in(default_runtime(), if_id)
        .ok()
        .flatten()
        .and_then(|iface| iface.config)
        .is_some_and(|config| config_supports_failover(&config))
}

fn select_surviving_primary(excluding_if: NetIfId) -> Option<NetIfId> {
    let candidates: Vec<NetIfId> = device_manager()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .keys()
        .copied()
        .filter(|if_id| *if_id != excluding_if)
        .collect();

    candidates.into_iter().find(|if_id| {
        manager::get_interface_in(default_runtime(), *if_id)
            .ok()
            .flatten()
            .is_some_and(|iface| iface.admin_up && interface_supports_failover(*if_id))
    })
}

fn set_primary_slot(primary: Option<NetIfId>) {
    set_primary_slot_in(default_runtime(), primary);
}

fn set_primary_slot_in(runtime: NetRuntimeHandle, primary: Option<NetIfId>) {
    device_manager_in(runtime)
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .primary = primary;
}

fn apply_primary_runtime_for_interface(if_id: NetIfId) -> Result<(), &'static str> {
    let runtime = default_runtime();
    if let Some(lease) = crate::net::services::dhcp::lease_for_interface(if_id) {
        let dns_server = manager::get_interface_in(runtime, if_id)
            .ok()
            .flatten()
            .and_then(|iface| iface.config)
            .and_then(|config| config.ipv4.dns);
        let mut guard = stack::stack_in(runtime)
            .lock()
            .map_err(|_| "network stack poisoned")?;
        let stack = guard.as_mut().ok_or("network stack unavailable")?;
        stack.apply_dhcp_v4_lease_for_interface(&lease, if_id, true, dns_server);
        if let Ok(Some(iface)) = manager::get_interface_in(runtime, if_id) {
            if let Some(config) = iface.config {
                crate::net::services::dhcp::update_runtime_mac(config.mac);
            }
        }
        return Ok(());
    }

    sync_runtime_config_for_interface(if_id);
    Ok(())
}

fn clear_interface_runtime_for_failover(if_id: NetIfId, clear_primary_runtime: bool) {
    if let Ok(mut guard) = stack::stack_in(default_runtime()).lock() {
        if let Some(stack) = guard.as_mut() {
            stack.clear_dhcp_v4_lease_for_interface(if_id, clear_primary_runtime);
            if clear_primary_runtime {
                if let Ok(Some(iface)) = manager::get_interface_in(default_runtime(), if_id) {
                    if let Some(config) = iface.config {
                        crate::net::services::dhcp::update_runtime_mac(config.mac);
                    }
                }
            }
            return;
        }
    }

    if clear_primary_runtime {
        clear_runtime_network_config();
    }
}

fn handle_interface_departure(if_id: NetIfId, reason: FailoverReason) {
    let was_primary = primary_if_in(default_runtime()) == Some(if_id);
    let candidate = was_primary
        .then(|| select_surviving_primary(if_id))
        .flatten();

    let release_sent = crate::net::services::dhcp::release_interface(if_id);
    if release_sent {
        log::info!(
            target: "net::device",
            "[NET] dhcp_release_best_effort: if{} reason={}",
            if_id.0,
            reason.as_str()
        );
    }

    clear_interface_runtime_for_failover(if_id, was_primary && candidate.is_none());

    if !was_primary {
        return;
    }

    crate::net::services::dhcp::clear_primary_interface(if_id);

    if let Some(new_if) = candidate {
        set_primary_slot(Some(new_if));
        runtime_context()
            .dhcp_bound_primary_selected
            .store(true, Ordering::Release);
        crate::net::services::dhcp::mark_primary_interface(new_if);
        if let Err(err) = apply_primary_runtime_for_interface(new_if) {
            log::warn!(
                target: "net::device",
                "failed to synchronize promoted primary if{}: {}",
                new_if.0,
                err
            );
        }
        log::info!(
            target: "net::device",
            "[NET] primary_failover: old=if{} new=if{} reason={}",
            if_id.0,
            new_if.0,
            reason.as_str()
        );
    } else {
        set_primary_slot(None);
        runtime_context()
            .dhcp_bound_primary_selected
            .store(false, Ordering::Release);
        log::warn!(
            target: "net::device",
            "[NET] primary_cleared: old=if{} reason={}",
            if_id.0,
            reason.as_str()
        );
    }
}

pub fn ensure_stack_initialized(config: NetworkConfig) -> Result<(), &'static str> {
    let runtime = default_runtime();
    if runtime_context().stack_initialized.load(Ordering::Acquire) {
        return Ok(());
    }

    if runtime_context()
        .stack_initialized
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(());
    }

    if let Err(err) = crate::net::datapath::mempool::init_net_mempool(1024) {
        log::warn!(target: "net::device", "mempool init failed: {}", err);
    }

    stack::init_in(runtime, config);
    manager::init_network_manager_in(runtime);

    match stack::stack_in(runtime).lock() {
        Ok(mut guard) => {
            let Some(stack) = guard.as_mut() else {
                runtime_context()
                    .stack_initialized
                    .store(false, Ordering::Release);
                return Err("network stack unavailable");
            };
            stack.set_transmit_fn_with_completion(
                crate::net::runtime::bridge::transmit_from_stack,
                true,
            );
        }
        Err(_) => {
            runtime_context()
                .stack_initialized
                .store(false, Ordering::Release);
            return Err("network stack poisoned");
        }
    }

    if let Err(err) = crate::net::api::dhcp::init_dhcp_runtime() {
        log::warn!(target: "net::device", "DHCP runtime init failed: {}", err);
    }

    Ok(())
}

pub fn is_initialized() -> bool {
    runtime_context().stack_initialized.load(Ordering::Acquire)
}

fn interface_for_port(
    port_id: NetPortId,
    config: NetworkConfig,
    port_name: &'static str,
) -> Result<NetIfId, &'static str> {
    let runtime = default_runtime();
    let if_id = if let Some(existing) = lookup_if_by_port_id_in(runtime, port_id) {
        let _ = manager::set_interface_config_in(runtime, existing, config);
        existing
    } else {
        let if_id = manager::register_interface_in(runtime, port_name)
            .map_err(|_| "failed to register network interface")?;
        let _ = manager::set_interface_config_in(runtime, if_id, config);
        if_id
    };

    if let Ok(mut guard) = stack::stack_in(default_runtime()).lock() {
        if let Some(stack) = guard.as_mut() {
            stack.register_interface_state(if_id, config);
        }
    }

    Ok(if_id)
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

fn should_select_as_primary(
    current_primary: Option<NetIfId>,
    policy: PrimaryPortPolicy,
    info: NetDeviceInfo,
) -> bool {
    match policy {
        PrimaryPortPolicy::Prefer => true,
        PrimaryPortPolicy::Auto => {
            current_primary.is_none() && info.flags & NETDEV_FLAG_HEALTHY != 0
        }
        PrimaryPortPolicy::Never => false,
    }
}

pub fn register_port(registration: NetPortRegistration) -> Result<NetIfId, &'static str> {
    let driver = registration.driver;
    let info = registration.info;
    let config = default_config_for_port(info);
    ensure_stack_initialized(config)?;

    if let Some(existing) = lookup_if_by_port_id_in(default_runtime(), info.port_id) {
        if registration.primary_policy == PrimaryPortPolicy::Prefer {
            set_primary_interface_in(default_runtime(), existing);
        }
        return Ok(existing);
    }

    let base = driver.info();
    let if_id = interface_for_port(info.port_id, config, base.driver_name)?;
    let binding = NetDeviceBinding {
        port_id: info.port_id,
        if_id,
    };
    let handle = NetDeviceHandle::new(driver, binding, runtime_context());
    handle.driver.bind(if_id.0)?;
    let runtime_handle = handle.runtime;

    let selected_as_primary = {
        let mut guard = device_manager().write().unwrap_or_else(|e| e.into_inner());
        let selected_as_primary =
            should_select_as_primary(guard.primary, registration.primary_policy, info);
        guard.port_map.insert(info.port_id, if_id);
        guard.handles.insert(if_id, handle);
        if selected_as_primary {
            guard.primary = Some(if_id);
        }
        selected_as_primary
    };

    if let Some(start_result) = with_port_handle_in(default_runtime(), if_id, |handle| {
        handle.driver.start(runtime_handle)
    }) {
        start_result?;
    } else {
        return Err("device handle missing after registration");
    }
    start_workers_for_port_in(default_runtime(), if_id);

    if selected_as_primary {
        apply_runtime_network_config(&config);
        if let Ok(mut guard) = stack::stack_in(default_runtime()).lock() {
            if let Some(stack) = guard.as_mut() {
                stack.set_primary_interface_state(Some(if_id));
            }
        }
    }

    if let Err(err) = crate::net::services::dhcp::ensure_interface_runtime(if_id, config) {
        log::warn!(
            target: "net::device",
            "DHCP interface runtime init failed for if{}: {}",
            if_id.0,
            err
        );
    }

    Ok(if_id)
}

pub fn bind_port_interface(port_id: NetPortId, if_id: NetIfId) -> Result<(), &'static str> {
    let bound_if_id = {
        let guard = device_manager().read().unwrap_or_else(|e| e.into_inner());
        let Some(bound_if_id) = guard.port_map.get(&port_id).copied() else {
            return Err("device port not registered");
        };
        bound_if_id
    };

    let binding = NetDeviceBinding { port_id, if_id };
    let handle = {
        let mut guard = device_manager().write().unwrap_or_else(|e| e.into_inner());
        guard
            .handles
            .remove(&bound_if_id)
            .ok_or("device handle missing")?
    };
    if let Err(err) = handle.rebind(binding) {
        device_manager()
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .handles
            .insert(bound_if_id, handle);
        return Err(err);
    }

    let mut guard = device_manager().write().unwrap_or_else(|e| e.into_inner());
    guard.port_map.insert(port_id, if_id);
    if guard.primary == Some(bound_if_id) {
        guard.primary = Some(if_id);
    }
    guard.handles.insert(if_id, handle);
    Ok(())
}

pub fn unregister_port(if_id: NetIfId) -> bool {
    let handle = {
        let mut guard = device_manager().write().unwrap_or_else(|e| e.into_inner());
        let handle = guard.handles.remove(&if_id);
        if let Some(handle) = handle.as_ref() {
            guard.port_map.remove(&handle.binding().port_id);
        }
        handle
    };

    if let Some(handle) = handle {
        let _ = manager::set_interface_down_in(default_runtime(), if_id);
        handle_interface_departure(if_id, FailoverReason::Unregister);
        crate::net::services::dhcp::unregister_interface_runtime(if_id);
        if let Ok(mut guard) = stack::stack_in(default_runtime()).lock() {
            if let Some(stack) = guard.as_mut() {
                stack.unregister_interface_state(if_id);
            }
        }
        handle.stop();
        true
    } else {
        false
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

pub fn list_port_infos() -> Vec<NetDeviceInfo> {
    device_manager()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .values()
        .map(NetDeviceHandle::info)
        .collect()
}

pub fn port_info(port_id: NetPortId) -> Option<NetDeviceInfo> {
    let if_id = lookup_if_by_port_id_in(default_runtime(), port_id)?;
    with_port_handle_in(default_runtime(), if_id, NetDeviceHandle::info)
}

pub fn port_stats(port_id: NetPortId) -> Option<NetPortStats> {
    let if_id = lookup_if_by_port_id_in(default_runtime(), port_id)?;
    port_stats_for_interface_in(default_runtime(), if_id)
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

pub fn primary_if_in(runtime: NetRuntimeHandle) -> Option<NetIfId> {
    device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .primary
}

pub fn set_primary_interface_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    set_primary_slot_in(runtime, Some(if_id));
    if let Ok(mut guard) = runtime_context_for(runtime).stack.lock() {
        if let Some(stack) = guard.as_mut() {
            stack.set_primary_interface_state(Some(if_id));
        }
    }
    if let Err(err) = apply_primary_runtime_for_interface(if_id) {
        log::warn!(
            target: "net::device",
            "failed to synchronize primary if{}: {}",
            if_id.0,
            err
        );
        sync_runtime_config_for_interface(if_id);
    }
}

fn claim_bound_primary_slot_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> bool {
    if runtime_context_for(runtime)
        .dhcp_bound_primary_selected
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        set_primary_slot_in(runtime, Some(if_id));
        true
    } else {
        false
    }
}

pub(crate) fn claim_bound_primary_interface_with_stack_state_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    stack: &mut stack::NetworkStack,
) -> bool {
    // DHCP lease binding runs under NETWORK_STACK; reuse that guard to avoid
    // self-deadlocking on the global stack lock during primary selection.
    if claim_bound_primary_slot_in(runtime, if_id) {
        stack.set_primary_interface_state(Some(if_id));
        true
    } else {
        false
    }
}

pub fn transmit_packet(if_id: Option<NetIfId>, payload: PacketPayload, meta: NetTxMeta) -> bool {
    let resolved_if = if_id.or_else(|| primary_if_in(default_runtime()));
    let Some(resolved_if) = resolved_if else {
        if let Some(completion_id) = meta.completion_id {
            let _ = complete_tx_request_in(
                default_runtime(),
                completion_id,
                Err("network interface unavailable"),
            );
        }
        return false;
    };
    if with_port_handle_in(default_runtime(), resolved_if, |handle| {
        handle.enqueue_tx(payload, meta)
    })
    .unwrap_or(false)
    {
        true
    } else {
        if let Some(completion_id) = meta.completion_id {
            let _ = complete_tx_request_in(
                default_runtime(),
                completion_id,
                Err("device TX queue full"),
            );
        }
        false
    }
}

pub(crate) fn transmit_registered_tx_request_in(
    runtime: NetRuntimeHandle,
    if_id: Option<NetIfId>,
    request: TxRequest,
) -> bool {
    let lease_id = request.lease_id;
    let resolved_if = if_id.or_else(|| primary_if_in(runtime));
    let Some(resolved_if) = resolved_if else {
        let _ = complete_tx_lease_in(runtime, lease_id, Err("network interface unavailable"));
        return false;
    };
    if with_port_handle_in(runtime, resolved_if, |handle| {
        handle.enqueue_tx_request(request)
    })
    .unwrap_or(false)
    {
        true
    } else {
        let _ = complete_tx_lease_in(runtime, lease_id, Err("device TX queue full"));
        false
    }
}

fn enqueue_event_in(runtime: NetRuntimeHandle, port_id: NetPortId, event: NetDriverEvent) -> bool {
    let Some(if_id) = lookup_if_by_port_id_in(runtime, port_id) else {
        return false;
    };
    with_port_handle_in(runtime, if_id, |handle| handle.enqueue_event(event)).unwrap_or(false)
}

pub fn enqueue_event(port_id: NetPortId, event: NetDriverEvent) -> bool {
    enqueue_event_in(default_runtime(), port_id, event)
}

fn enqueue_event_from_isr_in(
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

pub fn enqueue_event_from_isr(port_id: NetPortId, event: NetDriverEvent) -> bool {
    enqueue_event_from_isr_in(default_runtime(), port_id, event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::l3::ipv4::Ipv4Address;
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
            }
        }

        fn set_stats(&self, tx_packets: u64, rx_packets: u64, initialized: bool) {
            self.tx_packets.store(tx_packets, Ordering::Release);
            self.rx_packets.store(rx_packets, Ordering::Release);
            self.initialized.store(initialized, Ordering::Release);
        }
    }

    struct FakeDriver {
        state: &'static FakeDriverState,
    }

    impl FakeDriver {
        const fn new(state: &'static FakeDriverState) -> Self {
            Self { state }
        }
    }

    fn fake_driver() -> (&'static FakeDriverState, Box<dyn NetDevicePort>) {
        let state = Box::leak(Box::new(FakeDriverState::new()));
        (state, Box::new(FakeDriver::new(state)))
    }

    impl NetDevicePort for FakeDriver {
        fn info(&self) -> NetDeviceInfo {
            NetDeviceInfo {
                port_id: NetPortId::new(0x9009),
                if_id: None,
                driver_name: "fake",
                queue_pairs: 1,
                mtu: stack::MTU as u32,
                mac: MacAddress::from_octets(0, 1, 2, 3, 4, 5),
                flags: NETDEV_FLAG_HEALTHY,
            }
        }

        fn start(&self, _runtime: NetPortRuntimeHandle) -> Result<(), &'static str> {
            Ok(())
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

        fn stop(&self) {
            self.state.stop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn sample_lease(host: u8) -> crate::net::services::dhcp::DhcpLease {
        crate::net::services::dhcp::DhcpLease {
            ip_address: Ipv4Address::new([10, 0, 0, host]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Some(Ipv4Address::new([10, 0, 0, 1])),
            dns_servers: alloc::vec![Ipv4Address::new([1, 1, 1, host])],
            server_ip: Ipv4Address::new([10, 0, 0, 254]),
            lease_time: 3600,
            t1: 1800,
            t2: 3150,
            hostname: None,
            domain_name: None,
            obtained_at: 0,
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
            flags: NETDEV_FLAG_HEALTHY,
            ..NetDeviceInfo::default()
        };
        register_port(NetPortRegistration::new(info, driver, primary_policy))
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_queue_roundtrip_smoke() {
        let _ = crate::net::datapath::mempool::init_net_mempool(16);
        let queue = NetTxQueue::new();
        let request = TxRequest {
            lease_id: 1,
            descriptors: alloc::vec![NetTxSegment::new(core::ptr::null(), 0, 1)],
            meta: NetTxMeta::default(),
        };
        assert_eq!(queue.capacity(), NetTxQueue::CAPACITY);
        assert_eq!(queue.len(), 0);
        assert!(queue.push(request));
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
        assert!(sink.push(NetDriverEvent::QueueWake { queue_index: 7 }));
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
        unsafe {
            crate::per_cpu::init_per_cpu(1);
        }

        let (_, driver) = fake_driver();
        let if_id =
            register_test_port(89, driver, PrimaryPortPolicy::Never).expect("register port");

        crate::per_cpu::enter_interrupt();
        let result = with_port_handle_in(default_runtime(), if_id, |handle| {
            handle
                .runtime
                .schedule_event(NetDriverEvent::QueueWake { queue_index: 3 })
        })
        .expect("handle");
        crate::per_cpu::exit_interrupt();

        assert_eq!(result, Ok(()));
        assert_eq!(
            with_port_handle_in(default_runtime(), if_id, |handle| handle.event_sink.pop())
                .flatten(),
            Some(NetDriverEvent::QueueWake { queue_index: 3 })
        );

        let _ = unregister_port(if_id);
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
            runtime_context(),
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

        let info = port_info(test_port_id(90)).expect("port info");
        let stats = port_stats(test_port_id(90)).expect("port stats");

        assert_eq!(
            lookup_if_by_port_id_in(default_runtime(), test_port_id(90)),
            Some(if_id)
        );
        assert_eq!(info.port_id, test_port_id(90));
        assert_eq!(info.if_id, Some(if_id.0));
        assert_eq!(stats.tx_packets, 11);
        assert_eq!(stats.rx_packets, 7);
        assert!(list_port_ids_in(default_runtime()).contains(&test_port_id(90)));

        assert!(unregister_port(if_id));
        assert_eq!(state.stop_calls.load(Ordering::Relaxed), 1);
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

        assert_eq!(primary_if_in(default_runtime()), Some(if_b));
        assert!(
            port_info(test_port_id(92)).expect("primary info").flags & NETDEV_FLAG_PRIMARY != 0
        );

        assert!(unregister_port(if_b));
        assert_eq!(primary_if_in(default_runtime()), Some(if_a));
        assert!(unregister_port(if_a));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn primary_link_down_promotes_secondary_and_updates_runtime_config() {
        let (_, driver_a) = fake_driver();
        let (_, driver_b) = fake_driver();

        let if_a =
            register_test_port(93, driver_a, PrimaryPortPolicy::Auto).expect("register first port");
        let if_b = register_test_port(94, driver_b, PrimaryPortPolicy::Auto)
            .expect("register second port");

        let lease_a = sample_lease(10);
        let lease_b = sample_lease(20);
        crate::net::services::dhcp::interface_v4_client(if_a)
            .expect("dhcp client a")
            .set_lease_for_test(lease_a);
        crate::net::services::dhcp::interface_v4_client(if_b)
            .expect("dhcp client b")
            .set_lease_for_test(lease_b);

        set_primary_interface_in(default_runtime(), if_a);
        if let Ok(mut guard) = stack::stack_in(default_runtime()).lock() {
            let stack = guard.as_mut().expect("stack");
            stack.apply_dhcp_v4_lease_for_interface(&lease_b, if_b, false);
        }

        assert!(manager::set_interface_down_in(default_runtime(), if_a).is_ok());
        handle_interface_departure(if_a, FailoverReason::LinkDown);

        assert_eq!(primary_if_in(default_runtime()), Some(if_b));
        assert_eq!(
            crate::net::services::dhcp::primary_interface_if_id(),
            Some(if_b)
        );

        let cfg = stack::stack_in(default_runtime())
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|stack| stack.config()))
            .expect("stack config");
        assert_eq!(cfg.ipv4.address, lease_b.ip_address);
        assert_eq!(cfg.ipv4.gateway, lease_b.gateway.expect("gateway"));
        assert_eq!(cfg.ipv4.dns, lease_b.dns_servers.first().copied());

        let old_cfg = manager::get_interface_in(default_runtime(), if_a)
            .expect("manager query")
            .expect("interface a")
            .config
            .expect("config a");
        assert!(old_cfg.ipv4.address.is_any());
        assert!(old_cfg.ipv4.gateway.is_any());
        assert!(old_cfg.ipv4.dns.is_none());

        let route =
            manager::lookup_ipv4_route_in(default_runtime(), Ipv4Address::new([8, 8, 8, 8]))
                .expect("lookup route")
                .expect("default route");
        assert_eq!(route.if_id, if_b);

        assert!(unregister_port(if_b));
        assert!(unregister_port(if_a));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn unregister_primary_without_survivor_clears_primary_runtime() {
        let (_, driver) = fake_driver();
        let if_a = register_test_port(95, driver, PrimaryPortPolicy::Auto).expect("register port");

        let lease_a = sample_lease(30);
        crate::net::services::dhcp::interface_v4_client(if_a)
            .expect("dhcp client a")
            .set_lease_for_test(lease_a);
        set_primary_interface_in(default_runtime(), if_a);

        assert!(unregister_port(if_a));
        assert_eq!(primary_if_in(default_runtime()), None);

        let cfg = stack::stack_in(default_runtime())
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|stack| stack.config()))
            .expect("stack config");
        assert!(cfg.ipv4.address.is_any());
        assert!(cfg.ipv4.gateway.is_any());
        assert!(cfg.ipv4.dns.is_none());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn recovered_interface_does_not_reclaim_primary_after_failover() {
        let (_, driver_a) = fake_driver();
        let (_, driver_b) = fake_driver();

        let if_a =
            register_test_port(96, driver_a, PrimaryPortPolicy::Auto).expect("register first port");
        let if_b = register_test_port(97, driver_b, PrimaryPortPolicy::Auto)
            .expect("register second port");

        let lease_a = sample_lease(40);
        let lease_b = sample_lease(50);
        crate::net::services::dhcp::interface_v4_client(if_a)
            .expect("dhcp client a")
            .set_lease_for_test(lease_a);
        crate::net::services::dhcp::interface_v4_client(if_b)
            .expect("dhcp client b")
            .set_lease_for_test(lease_b);

        set_primary_interface_in(default_runtime(), if_a);
        if let Ok(mut guard) = stack::stack_in(default_runtime()).lock() {
            let stack = guard.as_mut().expect("stack");
            stack.apply_dhcp_v4_lease_for_interface(&lease_b, if_b, false);
        }

        assert!(manager::set_interface_down_in(default_runtime(), if_a).is_ok());
        handle_interface_departure(if_a, FailoverReason::LinkDown);
        assert_eq!(primary_if_in(default_runtime()), Some(if_b));

        assert!(manager::set_interface_up_in(default_runtime(), if_a).is_ok());
        assert!(!claim_bound_primary_slot_in(default_runtime(), if_a));
        assert_eq!(primary_if_in(default_runtime()), Some(if_b));

        assert!(unregister_port(if_b));
        assert!(unregister_port(if_a));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn claim_bound_primary_interface_with_stack_state_updates_primary_without_global_lock() {
        runtime_context()
            .dhcp_bound_primary_selected
            .store(false, Ordering::Release);

        let (_, driver_a) = fake_driver();
        let (_, driver_b) = fake_driver();

        let if_a =
            register_test_port(98, driver_a, PrimaryPortPolicy::Auto).expect("register first port");
        let if_b = register_test_port(99, driver_b, PrimaryPortPolicy::Auto)
            .expect("register second port");

        let mut test_stack = stack::NetworkStack::new(NetworkConfig::default());
        test_stack.register_interface_state(if_a, NetworkConfig::default());
        test_stack.register_interface_state(if_b, NetworkConfig::default());

        assert!(claim_bound_primary_interface_with_stack_state_in(
            default_runtime(),
            if_b,
            &mut test_stack
        ));
        assert_eq!(primary_if_in(default_runtime()), Some(if_b));
        assert_eq!(test_stack.resolve_ingress_if(None), if_b);

        assert!(unregister_port(if_b));
        assert!(unregister_port(if_a));
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
    fn packet_window_descriptors_reference_original_packet_range() {
        let _ = crate::net::datapath::mempool::init_net_mempool(16);
        let mut packet = crate::net::datapath::mempool::alloc_packet().expect("packet");
        assert!(packet.set_len(32));
        let base_ptr = packet.data().as_ptr() as usize;
        let base_device_addr = packet.device_address();
        let packets = alloc::vec![packet];

        let descriptors = packet_window_to_tx_segments(&packets, 8, 16).expect("window");

        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].cpu_ptr, base_ptr + 8);
        assert_eq!(descriptors[0].device_addr, base_device_addr + 8);
        assert_eq!(descriptors[0].len, 16);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_owner_group_completes_after_all_fragment_leases() {
        let _ = crate::net::datapath::mempool::init_net_mempool(16);
        let mut owner = crate::net::datapath::mempool::alloc_packet().expect("owner");
        assert!(owner.set_len(32));
        let mut header_a = crate::net::datapath::mempool::alloc_packet().expect("header a");
        assert!(header_a.set_len(8));
        let mut header_b = crate::net::datapath::mempool::alloc_packet().expect("header b");
        assert!(header_b.set_len(8));
        let (completion_id, future) = register_tx_completion_in(default_runtime());
        let group_id = register_tx_owner_group_in(
            default_runtime(),
            alloc::vec![owner],
            2,
            Some(completion_id),
        )
        .expect("owner group");
        let request_a = register_grouped_tx_lease_in(
            default_runtime(),
            alloc::vec![header_a],
            group_id,
            alloc::vec![NetTxSegment::new(core::ptr::null(), 0, 8)],
            NetTxMeta::default(),
        )
        .expect("request a");
        let request_b = register_grouped_tx_lease_in(
            default_runtime(),
            alloc::vec![header_b],
            group_id,
            alloc::vec![NetTxSegment::new(core::ptr::null(), 8, 8)],
            NetTxMeta::default(),
        )
        .expect("request b");

        assert!(
            runtime_context()
                .tx_owner_groups
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&group_id)
        );
        assert!(complete_tx_lease_in(
            default_runtime(),
            request_a.lease_id,
            Ok(())
        ));
        assert!(
            runtime_context()
                .tx_owner_groups
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&group_id)
        );
        assert!(complete_tx_lease_in(
            default_runtime(),
            request_b.lease_id,
            Err("fragment failed")
        ));
        assert!(
            !runtime_context()
                .tx_owner_groups
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&group_id)
        );
        assert_eq!(crate::task::block_on(future), Err("fragment failed"));
    }
}
