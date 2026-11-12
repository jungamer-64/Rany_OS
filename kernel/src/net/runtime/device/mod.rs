// ============================================================================
// kernel/src/net/runtime/device/mod.rs - ランタイム / device モジュール
// ============================================================================
//! Shared network port runtime.
//!
//! This layer owns port registration, interface binding, TX admission, ISR-safe
//! event delivery, and the runtime object exposed to driver adapters.

extern crate alloc;

mod tx;
use tx::NetPortTx;
pub(crate) use tx::{
    TX_FRAME_MAX_SEGMENTS, TxAdmissionCause, TxAdmissionError, TxBody, TxCompletionError, TxFrame,
    TxLeaseStats,
};

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
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use kernel_api::service::netdev::{
    MacAddress, NETDEV_FLAG_ADMIN_UP, NETDEV_FLAG_BOUND_PORT, NETDEV_FLAG_HEALTHY,
    NETDEV_FLAG_LINK_UP, NETDEV_FLAG_PRIMARY, NetDeviceInfo, NetDevicePort, NetDriverEvent,
    NetLogLevel, NetPortId, NetPortRegistration, NetPortRuntimeCookie, NetPortRuntimeHandle,
    NetPortRuntimeOps, NetPortStats, NetTxMeta, PrimaryPortPolicy, ReceivedPacket, RxBuffer,
    TxDeviceOutcome, TxLeaseId, TxPacketSubmission,
};

const NET_DEVICE_EVENT_QUEUE_CAPACITY: usize = 256;

/// RX buffers of one port. Protocol state may retain received buffers up to
/// its own limits (IPv4 and IPv6 reassembly, TCP out-of-order segments and
/// socket receive queues); the pool covers all of them together with the
/// buffers a device keeps posted, so retention cannot starve reception.
pub(crate) const RX_POOL_SLOTS: usize =
    crate::net::l3::ipv4::FragmentReassembler::MAX_HELD_FRAGMENTS
        + crate::net::l3::ipv6::fragment::Ipv6FragmentReassembler::MAX_HELD_FRAGMENTS
        + crate::net::l4::tcp::ooo_queue::GLOBAL_MAX_OOO_SEGMENTS
        + crate::net::l4::socket::RX_SOCKET_RETENTION_LIMIT
        + RX_POSTED_RESERVE;

/// Buffers kept for posting to the device while every retention limit is full.
const RX_POSTED_RESERVE: usize = 256;

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

fn runtime_lease_rx_buffer(cookie: NetPortRuntimeCookie, port_id: NetPortId) -> Option<RxBuffer> {
    let context = runtime_context_from_cookie(cookie).ok()?;
    let if_id = current_if_for_port(context, port_id).ok()?;
    // Each port receives only into its own pool, so a device mapping for RX
    // never covers buffers that another port has received into.
    let packet = with_port_handle_in(context.handle(), if_id, |handle| {
        handle
            .rx_pool
            .alloc(kernel_api::resource::net::DEFAULT_PACKET_HEADROOM)
            .ok()
    })??;
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
    port_id: NetPortId,
    lease_id: TxLeaseId,
    outcome: TxDeviceOutcome,
) -> Result<(), &'static str> {
    let context = runtime_context_from_cookie(cookie)?;
    let if_id = current_if_for_port(context, port_id)?;
    // Only the completing port's own leases are reachable from here.
    with_port_handle_in(context.handle(), if_id, |handle| {
        handle
            .tx
            .complete(lease_id, outcome)
            .map_err(TxCompletionError::as_str)
    })
    .unwrap_or(Err("device port not registered"))
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
    runtime: NetPortRuntimeHandle,
    tx: NetPortTx,
    rx_pool: crate::net::datapath::mempool::PacketPool,
    event_sink: Box<NetEventSink>,
    /// Driver calls hold it shared; stop holds it exclusively, so stop runs
    /// only after every submission and event call has returned.
    driver_gate: PoisonRwLock<()>,
    active: AtomicBool,
    tx_worker_started: AtomicBool,
    event_worker_started: AtomicBool,
}

impl NetDeviceHandle {
    fn new(
        driver: Box<dyn NetDevicePort>,
        binding: NetDeviceBinding,
        context: &'static NetRuntimeContext,
    ) -> Result<Self, (Box<dyn NetDevicePort>, &'static str)> {
        let info = driver.info();
        let tx = match NetPortTx::new(
            usize::from(info.max_tx_segments.get()),
            usize::from(info.queue_pairs),
        ) {
            Ok(tx) => tx,
            Err(_) => return Err((driver, "TX lease storage allocation failed")),
        };
        let Some(rx_geometry) =
            crate::net::datapath::mempool::PacketPoolGeometry::rx(info.mtu, RX_POOL_SLOTS)
        else {
            return Err((driver, "device MTU has no RX buffer geometry"));
        };
        let rx_pool = match crate::net::datapath::mempool::PacketPool::new(
            binding.port_id.as_u64() as u32,
            rx_geometry,
            &crate::cpu::snapshot(),
        ) {
            Ok(pool) => pool,
            Err(_) => return Err((driver, "RX buffer pool allocation failed")),
        };
        Ok(Self {
            driver,
            runtime: runtime_handle_for_port(context, binding.port_id),
            binding: PoisonLock::new(binding),
            tx,
            rx_pool,
            event_sink: Box::new(NetEventSink::new()),
            driver_gate: PoisonRwLock::new(()),
            active: AtomicBool::new(true),
            tx_worker_started: AtomicBool::new(false),
            event_worker_started: AtomicBool::new(false),
        })
    }

    /// Admit `frame` to this port's TX leases.
    ///
    /// # Errors
    /// Returns the unchanged frame with the reason it was not admitted.
    pub(crate) fn transmit(&self, frame: TxFrame, meta: NetTxMeta) -> Result<(), TxAdmissionError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(TxAdmissionError::new(TxAdmissionCause::PortStopped, frame));
        }
        self.tx.admit(frame, meta)
    }

    pub(crate) fn tx_stats(&self) -> TxLeaseStats {
        self.tx.stats()
    }

    pub(crate) const fn max_tx_segments(&self) -> usize {
        self.tx.max_segments()
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

    /// Close admission, release leases the driver never saw, then stop the
    /// driver. Accepted leases are released only after the driver proves
    /// device access ended; a failed stop keeps them for the retry.
    fn stop(&self) -> kernel_api::error::KapiResult<()> {
        self.active.store(false, Ordering::Release);
        self.tx.close_and_release_queued();
        self.event_sink.wake();
        let _driver_guard = self
            .driver_gate
            .write()
            .unwrap_or_else(|error| error.into_inner());
        self.driver.stop()?;
        self.tx.release_after_stop();
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

/// Start the port's TX and event workers. Each worker owns a handle to its
/// port until the port's stop closes admission and wakes it.
fn start_workers_for_port_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Result<(), &'static str> {
    let handle = device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .get(&if_id)
        .cloned()
        .ok_or("device handle missing before worker startup")?;
    if !handle.tx_worker_started.swap(true, Ordering::AcqRel) {
        for queue in 0..handle.tx.queue_count() {
            crate::task::spawn(
                tx_worker(Arc::clone(&handle), queue),
                crate::task::TaskOptions::any(),
            )
            .map_err(|_| "failed to spawn network TX worker")?;
        }
    }
    if !handle.event_worker_started.swap(true, Ordering::AcqRel) {
        crate::task::spawn(event_worker(handle), crate::task::TaskOptions::any())
            .map_err(|_| "failed to spawn network event worker")?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum DeviceQueueKind {
    Tx(usize),
    Event,
}

/// Wait until the port has work of `kind` or stops admitting it.
struct DeviceQueueWaitFuture<'a> {
    handle: &'a NetDeviceHandle,
    kind: DeviceQueueKind,
}

impl DeviceQueueWaitFuture<'_> {
    fn ready(&self) -> bool {
        if !self.handle.active.load(Ordering::Acquire) {
            return true;
        }
        match self.kind {
            DeviceQueueKind::Tx(queue) => self.handle.tx.has_queued(queue),
            DeviceQueueKind::Event => !self.handle.event_sink.is_empty(),
        }
    }
}

impl Future for DeviceQueueWaitFuture<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.ready() {
            return Poll::Ready(());
        }
        match self.kind {
            DeviceQueueKind::Tx(queue) => self.handle.tx.register_waker(queue, cx.waker()),
            DeviceQueueKind::Event => self.handle.event_sink.waker.register(cx.waker()),
        }
        if self.ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Submit the leases of one TX queue of a port, in admission order.
async fn tx_worker(handle: Arc<NetDeviceHandle>, queue: usize) {
    let mut scratch = Vec::new();
    if scratch.try_reserve_exact(handle.max_tx_segments()).is_err() {
        log::error!(target: "net::device", "failed to reserve TX descriptor scratch");
        return;
    }
    // LOOP_PROOF: mode=event; reason=The worker awaits its port's lease queue when empty and returns once the port's stop closes admission.;
    loop {
        if !handle.active.load(Ordering::Acquire) {
            return;
        }
        let Some((lease_id, meta)) = handle.tx.begin_submission(queue, &mut scratch) else {
            DeviceQueueWaitFuture {
                handle: &handle,
                kind: DeviceQueueKind::Tx(queue),
            }
            .await;
            continue;
        };
        let _driver_guard = handle
            .driver_gate
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let result = if handle.active.load(Ordering::Acquire) {
            // SAFETY: the regions come from consumed owners or frozen
            // payloads, so no CPU handle can write them. The lease stays
            // `Submitting` and `scratch` keeps the regions through any
            // synchronous completion until `finish_submission` below.
            match unsafe { TxPacketSubmission::new(lease_id, &scratch) } {
                Some(submission) => handle.driver.submit_tx_chain(submission, meta),
                None => Err("TX lease holds no descriptors"),
            }
        } else {
            Err("device port stopped before submission")
        };
        // Finishing under the driver gate orders it before a concurrent stop.
        handle
            .tx
            .finish_submission(lease_id, result.is_ok(), &mut scratch);
        if let Err(cause) = result {
            log::warn!(
                target: "net::device",
                "device port={} TX submission failed: {}",
                handle.binding().port_id.as_u64(),
                cause
            );
        }
    }
}

async fn event_worker(handle: Arc<NetDeviceHandle>) {
    // LOOP_PROOF: mode=event; reason=The worker awaits its port's event queue when empty and returns once the port's stop closes admission.;
    loop {
        if !handle.active.load(Ordering::Acquire) {
            return;
        }
        let Some(event) = handle.event_sink.pop() else {
            DeviceQueueWaitFuture {
                handle: &handle,
                kind: DeviceQueueKind::Event,
            }
            .await;
            continue;
        };
        let _driver_guard = handle
            .driver_gate
            .read()
            .unwrap_or_else(|error| error.into_inner());
        if !handle.active.load(Ordering::Acquire) {
            return;
        }
        let binding = handle.binding();
        let result = match event {
            NetDriverEvent::Poll => handle.driver.poll(binding.if_id.0),
            _ => handle.driver.handle_event(binding.if_id.0, event),
        };
        if let Err(err) = result {
            log::warn!(
                target: "net::device",
                "device port={} event {:?} failed: {}",
                binding.port_id.as_u64(),
                event,
                err
            );
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

    if let Err(err) = crate::net::datapath::mempool::init_net_mempool_in(runtime) {
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
    let handle = match NetDeviceHandle::new(driver, binding, runtime_context_for(runtime)) {
        Ok(handle) => Arc::new(handle),
        Err((_driver, cause)) => {
            rollback_interface_registration_in(runtime, if_id);
            return Err(NetPortRegistrationError::NotPublished(cause));
        }
    };
    if let Err(err) = handle.driver.bind(if_id.0) {
        rollback_interface_registration_in(runtime, if_id);
        return Err(NetPortRegistrationError::NotPublished(err));
    }
    let runtime_handle = handle.runtime;

    crate::net::runtime::bridge::register_stack_glue_interface_in(runtime, if_id);
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

/// Admit `frame` to the port bound to `if_id`.
///
/// Success means the port holds the frame's regions until the driver's
/// completion; it does not report transmission.
///
/// # Errors
/// Returns the unchanged frame when the interface is down, no port is bound,
/// or the port rejects it.
pub(crate) fn transmit_frame_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    frame: TxFrame,
    meta: NetTxMeta,
) -> Result<(), TxAdmissionError> {
    if !manager::is_interface_operational_in(runtime, if_id) {
        return Err(TxAdmissionError::new(
            TxAdmissionCause::InterfaceDown,
            frame,
        ));
    }
    let manager = device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner());
    match manager.handles.get(&if_id) {
        Some(handle) => handle.transmit(frame, meta),
        None => Err(TxAdmissionError::new(
            TxAdmissionCause::PortUnavailable,
            frame,
        )),
    }
}

pub(crate) fn port_tx_stats_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> Option<TxLeaseStats> {
    with_port_handle_in(runtime, if_id, NetDeviceHandle::tx_stats)
}

/// Descriptors a frame may use on the port bound to `if_id`.
pub(crate) fn port_max_tx_segments_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> Option<usize> {
    device_manager_in(runtime)
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .get(&if_id)
        .map(|handle| handle.max_tx_segments())
}

pub(crate) fn port_rx_pool_stats_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<crate::net::datapath::mempool::MempoolStats> {
    with_port_handle_in(runtime, if_id, |handle| handle.rx_pool.stats())
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
