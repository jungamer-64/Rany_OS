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
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use core::task::{Context, Poll};
use kernel_api::resource::net::PacketRef;
use kernel_api::service::netdev::{
    MacAddress, NETDEV_FLAG_ADMIN_UP, NETDEV_FLAG_BOUND_PORT, NETDEV_FLAG_HEALTHY,
    NETDEV_FLAG_LINK_UP, NETDEV_FLAG_PRIMARY, NetDeviceInfo, NetDevicePort, NetDriverEvent,
    NetLogLevel, NetPortKind, NetPortRuntime, NetPortStats, NetRxMeta, NetTxCompletionPolicy,
    NetTxMeta,
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

pub struct TxCompletionFuture {
    state: Arc<TxCompletionState>,
}

impl Future for TxCompletionFuture {
    type Output = TxCompletionResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Ok(mut slot) = self.state.result.lock() {
            if let Some(result) = slot.take() {
                return Poll::Ready(result);
            }
        }
        self.state.waker.register(cx.waker());
        if let Ok(mut slot) = self.state.result.lock() {
            if let Some(result) = slot.take() {
                return Poll::Ready(result);
            }
        }
        Poll::Pending
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetDeviceKey {
    Virtio(u8),
    Mlx5(u8),
}

impl NetDeviceKey {
    pub const fn port_id(self) -> u64 {
        match self {
            Self::Virtio(index) => 0x_0001_0000 | index as u64,
            Self::Mlx5(index) => 0x_0002_0000 | index as u64,
        }
    }

    pub const fn kind(self) -> NetPortKind {
        match self {
            Self::Virtio(_) => NetPortKind::Virtio,
            Self::Mlx5(_) => NetPortKind::Mlx5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetDeviceBinding {
    pub key: NetDeviceKey,
    pub if_id: NetIfId,
    pub kind: NetPortKind,
    pub virtio_index: Option<u8>,
}

#[derive(Debug)]
struct TxRequest {
    packet: PacketRef,
    meta: NetTxMeta,
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

    pub fn push(&self, packet: PacketRef, meta: NetTxMeta) -> bool {
        match self.queue.push(TxRequest { packet, meta }) {
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
                self.waker.wake();
                true
            }
            Err(_) => false,
        }
    }

    pub fn push_from_isr(&self, event: NetDriverEvent) -> bool {
        match self.queue.push(event) {
            Ok(()) => {
                self.waker.wake_from_isr();
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

pub fn register_tx_completion() -> (u64, TxCompletionFuture) {
    register_tx_completion_in(default_runtime())
}

pub fn register_tx_completion_in(runtime: NetRuntimeHandle) -> (u64, TxCompletionFuture) {
    let context = runtime_context_for(runtime);
    let completion_id = context
        .tx_completion_next_id
        .fetch_add(1, Ordering::Relaxed);
    let state = Arc::new(TxCompletionState::new());
    context
        .tx_completions
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(completion_id, state.clone());
    (completion_id, TxCompletionFuture { state })
}

pub fn complete_tx_request(completion_id: u64, result: TxCompletionResult) -> bool {
    complete_tx_request_in(default_runtime(), completion_id, result)
}

pub fn complete_tx_request_in(
    runtime: NetRuntimeHandle,
    completion_id: u64,
    result: TxCompletionResult,
) -> bool {
    let state = runtime_context_for(runtime)
        .tx_completions
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&completion_id);
    if let Some(state) = state {
        state.complete(result);
        true
    } else {
        false
    }
}

struct PortRuntimeHandle {
    key: NetDeviceKey,
    if_id: AtomicU16,
    context: &'static NetRuntimeContext,
}

impl PortRuntimeHandle {
    fn new(key: NetDeviceKey, if_id: NetIfId, context: &'static NetRuntimeContext) -> Self {
        Self {
            key,
            if_id: AtomicU16::new(if_id.0),
            context,
        }
    }

    fn current_if_id(&self) -> NetIfId {
        NetIfId(self.if_id.load(Ordering::Acquire))
    }

    fn set_if_id(&self, if_id: NetIfId) {
        self.if_id.store(if_id.0, Ordering::Release);
    }

    fn alloc_packet_for_current_interface(&self) -> Option<PacketRef> {
        match self.key {
            NetDeviceKey::Mlx5(index) => {
                crate::net::runtime::bridge::mlx5_bridge::alloc_packet_for_index(index)
            }
            _ => crate::net::datapath::mempool::alloc_packet(),
        }
    }
}

impl NetPortRuntime for PortRuntimeHandle {
    fn alloc_packet(&self) -> Option<PacketRef> {
        self.alloc_packet_for_current_interface()
    }

    fn submit_rx(&self, packet: PacketRef, meta: NetRxMeta) -> Result<(), &'static str> {
        crate::net::runtime::bridge::process_received_packet_zero_copy_for_interface_in(
            self.context.handle(),
            self.current_if_id(),
            packet,
            meta.header_len as usize,
            meta.payload_len as usize,
        );
        Ok(())
    }

    fn schedule_event(&self, event: NetDriverEvent) -> Result<(), &'static str> {
        let queued = if in_interrupt_context() {
            enqueue_event_from_isr(self.key, event)
        } else {
            enqueue_event(self.key, event)
        };
        if queued {
            Ok(())
        } else {
            Err("port event queue full")
        }
    }

    fn update_link(&self, up: bool) -> Result<(), &'static str> {
        let if_id = self.current_if_id();
        let result = if up {
            manager::set_interface_up(if_id)
        } else {
            manager::set_interface_down(if_id)
        };
        result.map_err(|_| "failed to update interface link state")?;

        if up {
            if let Ok(Some(iface)) = manager::get_interface(if_id) {
                if let Some(config) = iface.config {
                    let _ = crate::net::services::dhcp::ensure_interface_runtime(if_id, config);
                }
            }
            let _ = crate::net::services::dhcp::restart_interface_runtime(if_id);
            if primary_if() == Some(if_id) {
                log::info!(
                    target: "net::device",
                    "[NET] link_up: key={:?} if{} role=primary",
                    self.key,
                    if_id.0
                );
            } else {
                log::info!(
                    target: "net::device",
                    "[NET] secondary_rejoined: key={:?} if{}",
                    self.key,
                    if_id.0
                );
            }
        } else {
            log::warn!(
                target: "net::device",
                "[NET] link_down: key={:?} if{}",
                self.key,
                if_id.0
            );
            handle_interface_departure(if_id, FailoverReason::LinkDown);
        }

        Ok(())
    }

    fn log(&self, level: NetLogLevel, message: &str) {
        match level {
            NetLogLevel::Error => log::error!(target: "net::device", "{}", message),
            NetLogLevel::Warn => log::warn!(target: "net::device", "{}", message),
            NetLogLevel::Info => log::info!(target: "net::device", "{}", message),
            NetLogLevel::Debug => log::debug!(target: "net::device", "{}", message),
            NetLogLevel::Trace => log::trace!(target: "net::device", "{}", message),
        }
    }
}

pub struct NetDeviceHandle {
    driver: Arc<dyn NetDevicePort>,
    binding: PoisonLock<NetDeviceBinding>,
    runtime: Arc<PortRuntimeHandle>,
    tx_queue: Arc<NetTxQueue>,
    event_sink: Arc<NetEventSink>,
    active: AtomicBool,
    tx_worker_started: AtomicBool,
    event_worker_started: AtomicBool,
}

impl NetDeviceHandle {
    fn new(
        driver: Arc<dyn NetDevicePort>,
        binding: NetDeviceBinding,
        context: &'static NetRuntimeContext,
    ) -> Arc<Self> {
        Arc::new(Self {
            driver,
            runtime: Arc::new(PortRuntimeHandle::new(binding.key, binding.if_id, context)),
            binding: PoisonLock::new(binding),
            tx_queue: Arc::new(NetTxQueue::new()),
            event_sink: Arc::new(NetEventSink::new()),
            active: AtomicBool::new(true),
            tx_worker_started: AtomicBool::new(false),
            event_worker_started: AtomicBool::new(false),
        })
    }

    pub fn binding(&self) -> NetDeviceBinding {
        match self.binding.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    pub fn driver(&self) -> &Arc<dyn NetDevicePort> {
        &self.driver
    }

    pub fn info(&self) -> NetDeviceInfo {
        let binding = self.binding();
        let mut info = self.driver.info();
        let stats = self.driver.stats();
        info.port_id = binding.key.port_id();
        info.if_id = Some(binding.if_id.0);
        info.kind = binding.kind;
        info.flags |= NETDEV_FLAG_BOUND_PORT;
        if stats.initialized {
            info.flags |= NETDEV_FLAG_LINK_UP;
        }
        if stats.initialized || stats.rx_packets > 0 || stats.tx_packets > 0 {
            info.flags |= NETDEV_FLAG_HEALTHY;
        }
        if primary_if() == Some(binding.if_id) {
            info.flags |= NETDEV_FLAG_PRIMARY;
        }
        if let Ok(Some(interface)) = manager::get_interface(binding.if_id) {
            if interface.admin_up {
                info.flags |= NETDEV_FLAG_ADMIN_UP;
            } else {
                info.flags &= !NETDEV_FLAG_ADMIN_UP;
            }
        }
        info
    }

    pub fn enqueue_tx(&self, packet: PacketRef, meta: NetTxMeta) -> bool {
        self.tx_queue.push(packet, meta)
    }

    pub fn enqueue_event(&self, event: NetDriverEvent) -> bool {
        self.event_sink.push(event)
    }

    pub fn enqueue_event_from_isr(&self, event: NetDriverEvent) -> bool {
        self.event_sink.push_from_isr(event)
    }

    pub fn start_workers(self: &Arc<Self>) {
        if !self.tx_worker_started.swap(true, Ordering::AcqRel) {
            crate::task::spawn_task(crate::task::Task::new(tx_worker(self.clone())));
        }
        if !self.event_worker_started.swap(true, Ordering::AcqRel) {
            crate::task::spawn_task(crate::task::Task::new(event_worker(self.clone())));
        }
    }

    fn rebind(&self, binding: NetDeviceBinding) -> Result<(), &'static str> {
        self.driver.bind(binding.if_id.0)?;
        self.runtime.set_if_id(binding.if_id);
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

async fn tx_worker(handle: Arc<NetDeviceHandle>) {
    loop {
        if !handle.active.load(Ordering::Acquire) {
            break;
        }

        let mut pending = handle.tx_queue.pop();
        if pending.is_none() {
            handle.tx_queue.wait().await;
            pending = handle.tx_queue.pop();
        }

        while let Some(request) = pending {
            if !handle.active.load(Ordering::Acquire) {
                return;
            }

            let completion_id = request.meta.completion_id;
            let completion_policy = request.meta.completion_policy;
            if let Err(err) = handle.driver.submit_tx(request.packet, request.meta) {
                if let Some(completion_id) = completion_id {
                    let _ = complete_tx_request(completion_id, Err(err));
                }
                log::warn!(
                    target: "net::device",
                    "device {:?} TX submission failed: {}",
                    handle.binding().key,
                    err
                );
            } else if completion_policy == NetTxCompletionPolicy::QueueAcceptance {
                if let Some(completion_id) = completion_id {
                    let _ = complete_tx_request(completion_id, Ok(()));
                }
            }
            pending = handle.tx_queue.pop();
        }
    }
}

async fn event_worker(handle: Arc<NetDeviceHandle>) {
    loop {
        if !handle.active.load(Ordering::Acquire) {
            break;
        }

        let mut pending = handle.event_sink.pop();
        if pending.is_none() {
            handle.event_sink.wait().await;
            pending = handle.event_sink.pop();
        }

        while let Some(event) = pending {
            if !handle.active.load(Ordering::Acquire) {
                return;
            }

            let if_id = handle.binding().if_id.0;
            let result = match event {
                NetDriverEvent::Poll => handle.driver.poll(if_id),
                _ => handle.driver.handle_event(if_id, event),
            };
            if let Err(err) = result {
                log::warn!(
                    target: "net::device",
                    "device {:?} event {:?} failed: {}",
                    handle.binding().key,
                    event,
                    err
                );
            }
            pending = handle.event_sink.pop();
        }
    }
}

#[derive(Default)]
pub struct NetDeviceManager {
    handles: BTreeMap<NetIfId, Arc<NetDeviceHandle>>,
    key_map: BTreeMap<NetDeviceKey, NetIfId>,
    primary: Option<NetIfId>,
}

impl NetDeviceManager {
    pub const fn new() -> Self {
        Self {
            handles: BTreeMap::new(),
            key_map: BTreeMap::new(),
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
    if let Ok(mut guard) = stack::stack().lock() {
        if let Some(stack) = guard.as_mut() {
            stack.set_config(config.clone());
        }
    }

    crate::net::services::dhcp::update_runtime_mac(config.mac);
}

fn sync_runtime_config_for_interface(if_id: NetIfId) {
    let config = match manager::get_interface(if_id) {
        Ok(Some(iface)) => iface.config,
        _ => None,
    };
    if let Some(config) = config {
        apply_runtime_network_config(&config);
    }
}

fn clear_runtime_network_config() {
    if let Ok(mut guard) = stack::stack().lock() {
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

    manager::get_interface(if_id)
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
        manager::get_interface(*if_id)
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
    if let Some(lease) = crate::net::services::dhcp::lease_for_interface(if_id) {
        let mut guard = stack::stack()
            .lock()
            .map_err(|_| "network stack poisoned")?;
        let stack = guard.as_mut().ok_or("network stack unavailable")?;
        stack.apply_dhcp_v4_lease_for_interface(&lease, if_id, true);
        if let Ok(Some(iface)) = manager::get_interface(if_id) {
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
    if let Ok(mut guard) = stack::stack().lock() {
        if let Some(stack) = guard.as_mut() {
            stack.clear_dhcp_v4_lease_for_interface(if_id, clear_primary_runtime);
            if clear_primary_runtime {
                if let Ok(Some(iface)) = manager::get_interface(if_id) {
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
    let was_primary = primary_if() == Some(if_id);
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

    stack::init(config);
    manager::init_network_manager();

    match stack::stack().lock() {
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

fn interface_for_key(
    key: NetDeviceKey,
    config: NetworkConfig,
    port_name: &'static str,
) -> Result<NetIfId, &'static str> {
    let if_id = match key {
        NetDeviceKey::Virtio(index) => manager::register_virtio_port(index, Some(config))
            .map_err(|_| "failed to register virtio interface")?,
        NetDeviceKey::Mlx5(_) => {
            if let Some(existing) = lookup_if_by_key(key) {
                let _ = manager::set_interface_config(existing, config);
                existing
            } else {
                let if_id = manager::register_interface(port_name)
                    .map_err(|_| "failed to register network interface")?;
                let _ = manager::set_interface_config(if_id, config);
                if_id
            }
        }
    };

    if let Ok(mut guard) = stack::stack().lock() {
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
    let ipv6 = if info.kind == NetPortKind::Mlx5 {
        None
    } else {
        Some(crate::net::l3::ipv6::Ipv6Config::from_mac(mac.as_bytes()))
    };

    NetworkConfig {
        mac,
        ipv4: Ipv4Config::default(),
        ipv6,
        icmp_echo_enabled: true,
        icmp_redirect_enabled: false,
        icmpv6_redirect_enabled: false,
    }
}

pub fn register_port(
    key: NetDeviceKey,
    driver: Arc<dyn NetDevicePort>,
    config: NetworkConfig,
    make_primary: bool,
) -> Result<NetIfId, &'static str> {
    ensure_stack_initialized(config.clone())?;

    if let Some(existing) = lookup_if_by_key(key) {
        if make_primary {
            set_primary_interface(existing);
        }
        return Ok(existing);
    }

    let base = driver.info();
    let if_id = interface_for_key(key, config.clone(), base.driver_name)?;
    let binding = NetDeviceBinding {
        key,
        if_id,
        kind: key.kind(),
        virtio_index: match key {
            NetDeviceKey::Virtio(index) => Some(index),
            NetDeviceKey::Mlx5(_) => None,
        },
    };
    let handle = NetDeviceHandle::new(driver.clone(), binding, runtime_context());
    driver.bind(if_id.0)?;
    driver.start(handle.runtime.clone())?;
    handle.start_workers();

    let mut selected_as_primary = false;
    {
        let mut guard = device_manager().write().unwrap_or_else(|e| e.into_inner());
        guard.key_map.insert(key, if_id);
        guard.handles.insert(if_id, handle);
        if guard.primary.is_none() || make_primary {
            guard.primary = Some(if_id);
            selected_as_primary = true;
        }
    }

    if selected_as_primary {
        apply_runtime_network_config(&config);
        if let Ok(mut guard) = stack::stack().lock() {
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

pub fn register_port_with_default_config(
    key: NetDeviceKey,
    driver: Arc<dyn NetDevicePort>,
    make_primary: bool,
) -> Result<NetIfId, &'static str> {
    let config = default_config_for_port(driver.info());
    register_port(key, driver, config, make_primary)
}

pub fn bind_port_interface(key: NetDeviceKey, if_id: NetIfId) -> Result<(), &'static str> {
    let handle = {
        let guard = device_manager().read().unwrap_or_else(|e| e.into_inner());
        let Some(bound_if_id) = guard.key_map.get(&key).copied() else {
            return Err("device key not registered");
        };
        guard.handles.get(&bound_if_id).cloned()
    }
    .ok_or("device handle missing")?;

    let binding = NetDeviceBinding {
        key,
        if_id,
        kind: handle.binding().kind,
        virtio_index: handle.binding().virtio_index,
    };
    handle.rebind(binding)?;

    let mut guard = device_manager().write().unwrap_or_else(|e| e.into_inner());
    guard.key_map.insert(key, if_id);
    guard.handles.insert(if_id, handle.clone());
    if let Some(previous) = guard
        .handles
        .iter()
        .find_map(|(current_if, current_handle)| {
            if *current_if != if_id && current_handle.binding().key == key {
                Some(*current_if)
            } else {
                None
            }
        })
    {
        guard.handles.remove(&previous);
    }
    Ok(())
}

pub fn unregister_port(if_id: NetIfId) -> bool {
    let handle = {
        let mut guard = device_manager().write().unwrap_or_else(|e| e.into_inner());
        let handle = guard.handles.remove(&if_id);
        if let Some(handle) = handle.as_ref() {
            guard.key_map.remove(&handle.binding().key);
        }
        handle
    };

    if let Some(handle) = handle {
        let _ = manager::set_interface_down(if_id);
        handle_interface_departure(if_id, FailoverReason::Unregister);
        crate::net::services::dhcp::unregister_interface_runtime(if_id);
        if let Ok(mut guard) = stack::stack().lock() {
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

pub fn lookup_if_by_key(key: NetDeviceKey) -> Option<NetIfId> {
    lookup_if_by_key_in(default_runtime(), key)
}

pub fn lookup_if_by_key_in(runtime: NetRuntimeHandle, key: NetDeviceKey) -> Option<NetIfId> {
    device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .key_map
        .get(&key)
        .copied()
}

pub fn lookup_port(if_id: NetIfId) -> Option<Arc<NetDeviceHandle>> {
    lookup_port_in(default_runtime(), if_id)
}

pub fn lookup_port_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> Option<Arc<NetDeviceHandle>> {
    device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .get(&if_id)
        .cloned()
}

pub fn list_ports() -> Vec<Arc<NetDeviceHandle>> {
    device_manager()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .values()
        .cloned()
        .collect()
}

pub fn list_port_infos() -> Vec<NetDeviceInfo> {
    list_ports()
        .into_iter()
        .map(|handle| handle.info())
        .collect()
}

pub fn port_info(key: NetDeviceKey) -> Option<NetDeviceInfo> {
    let if_id = lookup_if_by_key(key)?;
    let handle = lookup_port(if_id)?;
    Some(handle.info())
}

pub fn port_stats(key: NetDeviceKey) -> Option<NetPortStats> {
    let if_id = lookup_if_by_key(key)?;
    let handle = lookup_port(if_id)?;
    Some(handle.driver().stats())
}

pub fn list_port_keys(kind: Option<NetPortKind>) -> Vec<NetDeviceKey> {
    list_port_keys_in(default_runtime(), kind)
}

pub fn list_port_keys_in(
    runtime: NetRuntimeHandle,
    kind: Option<NetPortKind>,
) -> Vec<NetDeviceKey> {
    device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .key_map
        .keys()
        .copied()
        .filter(|key| kind.is_none_or(|expected| key.kind() == expected))
        .collect()
}

pub fn primary_if() -> Option<NetIfId> {
    primary_if_in(default_runtime())
}

pub fn primary_if_in(runtime: NetRuntimeHandle) -> Option<NetIfId> {
    device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .primary
}

pub fn set_primary_interface(if_id: NetIfId) {
    set_primary_interface_in(default_runtime(), if_id);
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

fn claim_bound_primary_slot(if_id: NetIfId) -> bool {
    claim_bound_primary_slot_in(default_runtime(), if_id)
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

pub(crate) fn claim_bound_primary_interface_with_stack_state(
    if_id: NetIfId,
    stack: &mut stack::NetworkStack,
) -> bool {
    claim_bound_primary_interface_with_stack_state_in(default_runtime(), if_id, stack)
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

pub fn claim_bound_primary_interface(if_id: NetIfId) -> bool {
    if claim_bound_primary_slot(if_id) {
        if let Ok(mut guard) = runtime_context().stack.lock() {
            if let Some(stack) = guard.as_mut() {
                stack.set_primary_interface_state(Some(if_id));
            }
        }
        true
    } else {
        false
    }
}

pub fn transmit_packet(if_id: Option<NetIfId>, packet: PacketRef, meta: NetTxMeta) -> bool {
    let resolved_if = if_id.or_else(primary_if);
    let Some(handle) = resolved_if.and_then(lookup_port) else {
        if let Some(completion_id) = meta.completion_id {
            let _ = complete_tx_request(completion_id, Err("network interface unavailable"));
        }
        return false;
    };
    if handle.enqueue_tx(packet, meta) {
        true
    } else {
        if let Some(completion_id) = meta.completion_id {
            let _ = complete_tx_request(completion_id, Err("device TX queue full"));
        }
        false
    }
}

pub fn transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    transmit_with_meta(if_id, data, NetTxMeta::default())
}

pub fn transmit_with_meta(if_id: Option<NetIfId>, data: &[u8], meta: NetTxMeta) -> bool {
    let resolved_if = if_id.or_else(primary_if);
    let Some(handle) = resolved_if.and_then(lookup_port) else {
        if let Some(completion_id) = meta.completion_id {
            let _ = complete_tx_request(completion_id, Err("network interface unavailable"));
        }
        return false;
    };

    let mut packet = match handle.runtime.alloc_packet() {
        Some(packet) => packet,
        None => {
            if let Some(completion_id) = meta.completion_id {
                let _ = complete_tx_request(completion_id, Err("TX packet allocation failed"));
            }
            return false;
        }
    };

    if data.len() > packet.capacity() {
        if let Some(completion_id) = meta.completion_id {
            let _ = complete_tx_request(completion_id, Err("packet exceeds TX capacity"));
        }
        return false;
    }

    packet.set_len(data.len());
    packet.data_mut()[..data.len()].copy_from_slice(data);
    if handle.enqueue_tx(packet, meta) {
        true
    } else {
        if let Some(completion_id) = meta.completion_id {
            let _ = complete_tx_request(completion_id, Err("device TX queue full"));
        }
        false
    }
}

pub fn enqueue_event(key: NetDeviceKey, event: NetDriverEvent) -> bool {
    let Some(if_id) = lookup_if_by_key(key) else {
        return false;
    };
    let Some(handle) = lookup_port(if_id) else {
        return false;
    };
    handle.enqueue_event(event)
}

pub fn enqueue_event_from_isr(key: NetDeviceKey, event: NetDriverEvent) -> bool {
    let Some(if_id) = lookup_if_by_key(key) else {
        return false;
    };
    let Some(handle) = lookup_port(if_id) else {
        return false;
    };
    handle.enqueue_event_from_isr(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::l3::ipv4::Ipv4Address;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};

    struct FakeDriver {
        bind_calls: AtomicUsize,
        last_if_id: AtomicU16,
        last_event_queue: AtomicU16,
        poll_calls: AtomicUsize,
        stop_calls: AtomicUsize,
        tx_packets: AtomicU64,
        rx_packets: AtomicU64,
        initialized: AtomicBool,
    }

    impl FakeDriver {
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

    impl NetDevicePort for FakeDriver {
        fn info(&self) -> NetDeviceInfo {
            NetDeviceInfo {
                port_id: NetDeviceKey::Virtio(9).port_id(),
                if_id: None,
                kind: NetPortKind::Virtio,
                driver_name: "fake",
                queue_pairs: 1,
                mtu: stack::MTU as u32,
                mac: MacAddress::from_octets(0, 1, 2, 3, 4, 5),
                flags: NETDEV_FLAG_HEALTHY,
            }
        }

        fn start(&self, _runtime: Arc<dyn NetPortRuntime>) -> Result<(), &'static str> {
            Ok(())
        }

        fn bind(&self, if_id: u16) -> Result<(), &'static str> {
            self.bind_calls.fetch_add(1, Ordering::Relaxed);
            self.last_if_id.store(if_id, Ordering::Release);
            Ok(())
        }

        fn submit_tx(&self, _packet: PacketRef, _meta: NetTxMeta) -> Result<(), &'static str> {
            Ok(())
        }

        fn poll(&self, if_id: u16) -> Result<(), &'static str> {
            self.last_if_id.store(if_id, Ordering::Release);
            self.poll_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn handle_event(&self, if_id: u16, event: NetDriverEvent) -> Result<(), &'static str> {
            self.last_if_id.store(if_id, Ordering::Release);
            if let NetDriverEvent::QueueWake { queue_index } = event {
                self.last_event_queue.store(queue_index, Ordering::Release);
            }
            Ok(())
        }

        fn stats(&self) -> NetPortStats {
            NetPortStats {
                tx_packets: self.tx_packets.load(Ordering::Acquire),
                rx_packets: self.rx_packets.load(Ordering::Acquire),
                tx_errors: 0,
                rx_errors: 0,
                initialized: self.initialized.load(Ordering::Acquire),
            }
        }

        fn stop(&self) {
            self.stop_calls.fetch_add(1, Ordering::Relaxed);
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_queue_roundtrip_smoke() {
        let _ = crate::net::datapath::mempool::init_net_mempool(16);
        let queue = NetTxQueue::new();
        let packet = crate::net::datapath::mempool::alloc_packet().expect("packet");
        assert_eq!(queue.capacity(), NetTxQueue::CAPACITY);
        assert_eq!(queue.len(), 0);
        assert!(queue.push(packet, NetTxMeta::default()));
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
        assert!(sink.push_from_isr(NetDriverEvent::QueueWake { queue_index: 7 }));
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

        let driver = Arc::new(FakeDriver::new());
        let if_id = register_port_with_default_config(NetDeviceKey::Virtio(89), driver, false)
            .expect("register port");
        let handle = lookup_port(if_id).expect("handle");

        crate::per_cpu::enter_interrupt();
        let result = handle
            .runtime
            .schedule_event(NetDriverEvent::QueueWake { queue_index: 3 });
        crate::per_cpu::exit_interrupt();

        assert_eq!(result, Ok(()));
        assert_eq!(
            handle.event_sink.pop(),
            Some(NetDriverEvent::QueueWake { queue_index: 3 })
        );

        let _ = unregister_port(if_id);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn device_handle_rebind_updates_binding_smoke() {
        let driver = Arc::new(FakeDriver::new());
        let handle = NetDeviceHandle::new(
            driver.clone(),
            NetDeviceBinding {
                key: NetDeviceKey::Virtio(9),
                if_id: NetIfId(1),
                kind: NetPortKind::Virtio,
                virtio_index: Some(9),
            },
            runtime_context(),
        );

        handle
            .rebind(NetDeviceBinding {
                key: NetDeviceKey::Virtio(9),
                if_id: NetIfId(22),
                kind: NetPortKind::Virtio,
                virtio_index: Some(9),
            })
            .expect("rebind");

        assert_eq!(handle.binding().if_id, NetIfId(22));
        assert_eq!(driver.bind_calls.load(Ordering::Relaxed), 1);
        assert_eq!(driver.last_if_id.load(Ordering::Acquire), 22);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn register_port_with_default_config_exposes_snapshot_smoke() {
        let driver = Arc::new(FakeDriver::new());
        driver.set_stats(11, 7, true);

        let if_id =
            register_port_with_default_config(NetDeviceKey::Virtio(90), driver.clone(), false)
                .expect("register port");

        let info = port_info(NetDeviceKey::Virtio(90)).expect("port info");
        let stats = port_stats(NetDeviceKey::Virtio(90)).expect("port stats");

        assert_eq!(lookup_if_by_key(NetDeviceKey::Virtio(90)), Some(if_id));
        assert_eq!(info.port_id, NetDeviceKey::Virtio(90).port_id());
        assert_eq!(info.if_id, Some(if_id.0));
        assert_eq!(stats.tx_packets, 11);
        assert_eq!(stats.rx_packets, 7);
        assert!(list_port_keys(Some(NetPortKind::Virtio)).contains(&NetDeviceKey::Virtio(90)));

        assert!(unregister_port(if_id));
        assert_eq!(driver.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn register_port_make_primary_updates_primary_selection_smoke() {
        let driver_a = Arc::new(FakeDriver::new());
        let driver_b = Arc::new(FakeDriver::new());

        let if_a = register_port_with_default_config(NetDeviceKey::Virtio(91), driver_a, false)
            .expect("register first port");
        let if_b = register_port_with_default_config(NetDeviceKey::Virtio(92), driver_b, true)
            .expect("register second port");

        assert_eq!(primary_if(), Some(if_b));
        assert!(
            port_info(NetDeviceKey::Virtio(92))
                .expect("primary info")
                .flags
                & NETDEV_FLAG_PRIMARY
                != 0
        );

        assert!(unregister_port(if_b));
        assert_eq!(primary_if(), Some(if_a));
        assert!(unregister_port(if_a));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn primary_link_down_promotes_secondary_and_updates_runtime_config() {
        let driver_a = Arc::new(FakeDriver::new());
        let driver_b = Arc::new(FakeDriver::new());

        let if_a = register_port_with_default_config(NetDeviceKey::Virtio(93), driver_a, false)
            .expect("register first port");
        let if_b = register_port_with_default_config(NetDeviceKey::Virtio(94), driver_b, false)
            .expect("register second port");

        let lease_a = sample_lease(10);
        let lease_b = sample_lease(20);
        crate::net::services::dhcp::interface_v4_client(if_a)
            .expect("dhcp client a")
            .set_lease_for_test(lease_a.clone());
        crate::net::services::dhcp::interface_v4_client(if_b)
            .expect("dhcp client b")
            .set_lease_for_test(lease_b.clone());

        set_primary_interface(if_a);
        if let Ok(mut guard) = stack::stack().lock() {
            let stack = guard.as_mut().expect("stack");
            stack.apply_dhcp_v4_lease_for_interface(&lease_b, if_b, false);
        }

        assert!(manager::set_interface_down(if_a).is_ok());
        handle_interface_departure(if_a, FailoverReason::LinkDown);

        assert_eq!(primary_if(), Some(if_b));
        assert_eq!(
            crate::net::services::dhcp::primary_interface_if_id(),
            Some(if_b)
        );

        let cfg = stack::stack()
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|stack| stack.config()))
            .expect("stack config");
        assert_eq!(cfg.ipv4.address, lease_b.ip_address);
        assert_eq!(cfg.ipv4.gateway, lease_b.gateway.expect("gateway"));
        assert_eq!(cfg.ipv4.dns, lease_b.dns_servers.first().copied());

        let old_cfg = manager::get_interface(if_a)
            .expect("manager query")
            .expect("interface a")
            .config
            .expect("config a");
        assert!(old_cfg.ipv4.address.is_any());
        assert!(old_cfg.ipv4.gateway.is_any());
        assert!(old_cfg.ipv4.dns.is_none());

        let route = manager::lookup_ipv4_route(Ipv4Address::new([8, 8, 8, 8]))
            .expect("lookup route")
            .expect("default route");
        assert_eq!(route.if_id, if_b);

        assert!(unregister_port(if_b));
        assert!(unregister_port(if_a));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn unregister_primary_without_survivor_clears_primary_runtime() {
        let driver = Arc::new(FakeDriver::new());
        let if_a = register_port_with_default_config(NetDeviceKey::Virtio(95), driver, false)
            .expect("register port");

        let lease_a = sample_lease(30);
        crate::net::services::dhcp::interface_v4_client(if_a)
            .expect("dhcp client a")
            .set_lease_for_test(lease_a.clone());
        set_primary_interface(if_a);

        assert!(unregister_port(if_a));
        assert_eq!(primary_if(), None);

        let cfg = stack::stack()
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
        let driver_a = Arc::new(FakeDriver::new());
        let driver_b = Arc::new(FakeDriver::new());

        let if_a = register_port_with_default_config(NetDeviceKey::Virtio(96), driver_a, false)
            .expect("register first port");
        let if_b = register_port_with_default_config(NetDeviceKey::Virtio(97), driver_b, false)
            .expect("register second port");

        let lease_a = sample_lease(40);
        let lease_b = sample_lease(50);
        crate::net::services::dhcp::interface_v4_client(if_a)
            .expect("dhcp client a")
            .set_lease_for_test(lease_a.clone());
        crate::net::services::dhcp::interface_v4_client(if_b)
            .expect("dhcp client b")
            .set_lease_for_test(lease_b.clone());

        set_primary_interface(if_a);
        if let Ok(mut guard) = stack::stack().lock() {
            let stack = guard.as_mut().expect("stack");
            stack.apply_dhcp_v4_lease_for_interface(&lease_b, if_b, false);
        }

        assert!(manager::set_interface_down(if_a).is_ok());
        handle_interface_departure(if_a, FailoverReason::LinkDown);
        assert_eq!(primary_if(), Some(if_b));

        assert!(manager::set_interface_up(if_a).is_ok());
        assert!(!claim_bound_primary_interface(if_a));
        assert_eq!(primary_if(), Some(if_b));

        assert!(unregister_port(if_b));
        assert!(unregister_port(if_a));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn claim_bound_primary_interface_with_stack_state_updates_primary_without_global_lock() {
        runtime_context()
            .dhcp_bound_primary_selected
            .store(false, Ordering::Release);

        let driver_a = Arc::new(FakeDriver::new());
        let driver_b = Arc::new(FakeDriver::new());

        let if_a = register_port_with_default_config(NetDeviceKey::Virtio(98), driver_a, false)
            .expect("register first port");
        let if_b = register_port_with_default_config(NetDeviceKey::Virtio(99), driver_b, false)
            .expect("register second port");

        let mut test_stack = stack::NetworkStack::new(NetworkConfig::default());
        test_stack.register_interface_state(if_a, NetworkConfig::default());
        test_stack.register_interface_state(if_b, NetworkConfig::default());

        assert!(claim_bound_primary_interface_with_stack_state(
            if_b,
            &mut test_stack
        ));
        assert_eq!(primary_if(), Some(if_b));
        assert_eq!(test_stack.resolve_ingress_if(None), if_b);

        assert!(unregister_port(if_b));
        assert!(unregister_port(if_a));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_completion_future_resolves_success() {
        let (completion_id, future) = register_tx_completion();
        assert!(complete_tx_request(completion_id, Ok(())));
        assert_eq!(crate::task::block_on(future), Ok(()));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn tx_completion_future_resolves_error() {
        let (completion_id, future) = register_tx_completion();
        assert!(complete_tx_request(completion_id, Err("submit failed")));
        assert_eq!(crate::task::block_on(future), Err("submit failed"));
    }
}
