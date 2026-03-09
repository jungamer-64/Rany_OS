//! Shared network port runtime.
//!
//! This layer owns port registration, interface binding, TX queuing, ISR-safe
//! event delivery, and the runtime object exposed to driver adapters.

extern crate alloc;

use crate::net::runtime::manager::{self, NetIfId};
use crate::net::runtime::stack::{self, NetworkConfig};
use crate::sync::atomic_waker::AtomicWaker;
use crate::sync::lockfree::MpmcRingBuffer;
use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use core::task::{Context, Poll};
use kernel_api::resource::net::PacketRef;
use kernel_api::service::netdev::{
    self as kapi_netdev, MacAddress, NetDeviceInfo, NetDevicePort, NetDriverEvent, NetLogLevel,
    NetPortKind, NetPortRuntime, NetPortStats, NetRxMeta, NetTxMeta, NETDEV_FLAG_ADMIN_UP,
    NETDEV_FLAG_BOUND_PORT, NETDEV_FLAG_HEALTHY, NETDEV_FLAG_LINK_UP, NETDEV_FLAG_PRIMARY,
};

const NET_DEVICE_TX_QUEUE_CAPACITY: usize = 1024;
const NET_DEVICE_EVENT_QUEUE_CAPACITY: usize = 256;

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

    pub fn pop(&self) -> Option<TxRequest> {
        self.queue.pop()
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

struct PortRuntimeHandle {
    key: NetDeviceKey,
    if_id: AtomicU16,
}

impl PortRuntimeHandle {
    fn new(key: NetDeviceKey, if_id: NetIfId) -> Self {
        Self {
            key,
            if_id: AtomicU16::new(if_id.0),
        }
    }

    fn current_if_id(&self) -> NetIfId {
        NetIfId(self.if_id.load(Ordering::Acquire))
    }

    fn set_if_id(&self, if_id: NetIfId) {
        self.if_id.store(if_id.0, Ordering::Release);
    }
}

impl NetPortRuntime for PortRuntimeHandle {
    fn alloc_packet(&self) -> Option<PacketRef> {
        crate::net::datapath::mempool::alloc_packet()
    }

    fn submit_rx(&self, packet: PacketRef, meta: NetRxMeta) -> Result<(), &'static str> {
        crate::net::runtime::bridge::process_received_packet_zero_copy_for_interface(
            self.current_if_id(),
            packet,
            meta.header_len as usize,
            meta.payload_len as usize,
        );
        Ok(())
    }

    fn schedule_event(&self, event: NetDriverEvent) -> Result<(), &'static str> {
        if enqueue_event(self.key, event) {
            Ok(())
        } else {
            Err("port event queue full")
        }
    }

    fn update_link(&self, up: bool) -> Result<(), &'static str> {
        let result = if up {
            manager::set_interface_up(self.current_if_id())
        } else {
            manager::set_interface_down(self.current_if_id())
        };
        result.map_err(|_| "failed to update interface link state")
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
    fn new(driver: Arc<dyn NetDevicePort>, binding: NetDeviceBinding) -> Arc<Self> {
        Arc::new(Self {
            driver,
            runtime: Arc::new(PortRuntimeHandle::new(binding.key, binding.if_id)),
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
            crate::task::Executor::spawn_global(crate::task::Task::new(tx_worker(self.clone())));
        }
        if !self.event_worker_started.swap(true, Ordering::AcqRel) {
            crate::task::Executor::spawn_global(crate::task::Task::new(event_worker(self.clone())));
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

            if let Err(err) = handle.driver.submit_tx(request.packet, request.meta) {
                log::warn!(
                    target: "net::device",
                    "device {:?} TX submission failed: {}",
                    handle.binding().key,
                    err
                );
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

static DEVICE_MANAGER: PoisonRwLock<NetDeviceManager> = PoisonRwLock::new(NetDeviceManager::new());
static STACK_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn ensure_stack_initialized(config: NetworkConfig) -> Result<(), &'static str> {
    if STACK_INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }

    if STACK_INITIALIZED
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
                STACK_INITIALIZED.store(false, Ordering::Release);
                return Err("network stack unavailable");
            };
            stack.set_transmit_fn(crate::net::runtime::bridge::transmit_from_stack);
        }
        Err(_) => {
            STACK_INITIALIZED.store(false, Ordering::Release);
            return Err("network stack poisoned");
        }
    }

    if let Err(err) = crate::net::api::dhcp::init_dhcp_runtime() {
        log::warn!(target: "net::device", "DHCP runtime init failed: {}", err);
    }

    Ok(())
}

pub fn is_initialized() -> bool {
    STACK_INITIALIZED.load(Ordering::Acquire)
}

fn interface_for_key(
    key: NetDeviceKey,
    config: NetworkConfig,
    port_name: &'static str,
) -> Result<NetIfId, &'static str> {
    match key {
        NetDeviceKey::Virtio(index) => manager::register_virtio_port(index, Some(config))
            .map_err(|_| "failed to register virtio interface"),
        NetDeviceKey::Mlx5(_) => {
            if let Some(existing) = lookup_if_by_key(key) {
                let _ = manager::set_interface_config(existing, config);
                Ok(existing)
            } else {
                let if_id = manager::register_interface(port_name)
                    .map_err(|_| "failed to register network interface")?;
                let _ = manager::set_interface_config(if_id, config);
                Ok(if_id)
            }
        }
    }
}

pub fn register_device(
    key: NetDeviceKey,
    driver: Arc<dyn NetDevicePort>,
    config: NetworkConfig,
    make_primary: bool,
) -> Result<NetIfId, &'static str> {
    ensure_stack_initialized(config)?;

    if let Some(existing) = lookup_if_by_key(key) {
        if make_primary {
            set_primary_interface(existing);
        }
        return Ok(existing);
    }

    let base = driver.info();
    let if_id = interface_for_key(key, config, base.driver_name)?;
    let binding = NetDeviceBinding {
        key,
        if_id,
        kind: key.kind(),
        virtio_index: match key {
            NetDeviceKey::Virtio(index) => Some(index),
            NetDeviceKey::Mlx5(_) => None,
        },
    };
    let handle = NetDeviceHandle::new(driver.clone(), binding);
    driver.bind(if_id.0)?;
    driver.start(handle.runtime.clone())?;
    handle.start_workers();

    {
        let mut guard = DEVICE_MANAGER.write().unwrap_or_else(|e| e.into_inner());
        guard.key_map.insert(key, if_id);
        guard.handles.insert(if_id, handle);
        if guard.primary.is_none() || make_primary {
            guard.primary = Some(if_id);
        }
    }

    Ok(if_id)
}

pub fn bind_device_interface(key: NetDeviceKey, if_id: NetIfId) -> Result<(), &'static str> {
    let handle = {
        let guard = DEVICE_MANAGER.read().unwrap_or_else(|e| e.into_inner());
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

    let mut guard = DEVICE_MANAGER.write().unwrap_or_else(|e| e.into_inner());
    guard.key_map.insert(key, if_id);
    guard.handles.insert(if_id, handle.clone());
    if let Some(previous) = guard.handles.iter().find_map(|(current_if, current_handle)| {
        if *current_if != if_id && current_handle.binding().key == key {
            Some(*current_if)
        } else {
            None
        }
    }) {
        guard.handles.remove(&previous);
    }
    Ok(())
}

pub fn unregister_device(if_id: NetIfId) -> bool {
    let handle = {
        let mut guard = DEVICE_MANAGER.write().unwrap_or_else(|e| e.into_inner());
        let handle = guard.handles.remove(&if_id);
        if let Some(handle) = handle.as_ref() {
            guard.key_map.remove(&handle.binding().key);
            if guard.primary == Some(if_id) {
                guard.primary = guard.handles.keys().next().copied();
            }
        }
        handle
    };

    if let Some(handle) = handle {
        handle.stop();
        true
    } else {
        false
    }
}

pub fn lookup_if_by_key(key: NetDeviceKey) -> Option<NetIfId> {
    DEVICE_MANAGER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .key_map
        .get(&key)
        .copied()
}

pub fn lookup_device(if_id: NetIfId) -> Option<Arc<NetDeviceHandle>> {
    DEVICE_MANAGER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .get(&if_id)
        .cloned()
}

pub fn list_devices() -> Vec<Arc<NetDeviceHandle>> {
    DEVICE_MANAGER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .handles
        .values()
        .cloned()
        .collect()
}

pub fn list_port_infos() -> Vec<NetDeviceInfo> {
    list_devices().into_iter().map(|handle| handle.info()).collect()
}

pub fn primary_if() -> Option<NetIfId> {
    DEVICE_MANAGER.read().unwrap_or_else(|e| e.into_inner()).primary
}

pub fn set_primary_interface(if_id: NetIfId) {
    DEVICE_MANAGER.write().unwrap_or_else(|e| e.into_inner()).primary = Some(if_id);
}

pub fn transmit_packet(if_id: Option<NetIfId>, packet: PacketRef, meta: NetTxMeta) -> bool {
    let resolved_if = if_id.or_else(primary_if);
    let Some(handle) = resolved_if.and_then(lookup_device) else {
        return false;
    };
    handle.enqueue_tx(packet, meta)
}

pub fn transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    let mut packet = match crate::net::datapath::mempool::alloc_packet() {
        Some(packet) => packet,
        None => return false,
    };

    if data.len() > packet.capacity() {
        return false;
    }

    packet.set_len(data.len());
    packet.data_mut()[..data.len()].copy_from_slice(data);
    transmit_packet(if_id, packet, NetTxMeta::default())
}

pub fn enqueue_event(key: NetDeviceKey, event: NetDriverEvent) -> bool {
    let Some(if_id) = lookup_if_by_key(key) else {
        return false;
    };
    let Some(handle) = lookup_device(if_id) else {
        return false;
    };
    handle.enqueue_event(event)
}

pub fn enqueue_event_from_isr(key: NetDeviceKey, event: NetDriverEvent) -> bool {
    let Some(if_id) = lookup_if_by_key(key) else {
        return false;
    };
    let Some(handle) = lookup_device(if_id) else {
        return false;
    };
    handle.enqueue_event_from_isr(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

    struct FakeDriver {
        bind_calls: AtomicUsize,
        last_if_id: AtomicU16,
        last_event_queue: AtomicU16,
    }

    impl FakeDriver {
        const fn new() -> Self {
            Self {
                bind_calls: AtomicUsize::new(0),
                last_if_id: AtomicU16::new(0),
                last_event_queue: AtomicU16::new(u16::MAX),
            }
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

        fn handle_event(&self, if_id: u16, event: NetDriverEvent) -> Result<(), &'static str> {
            self.last_if_id.store(if_id, Ordering::Release);
            if let NetDriverEvent::QueueWake { queue_index } = event {
                self.last_event_queue.store(queue_index, Ordering::Release);
            }
            Ok(())
        }

        fn stats(&self) -> NetPortStats {
            NetPortStats::default()
        }

        fn stop(&self) {}
    }

    #[test_case]
    fn tx_queue_roundtrip_smoke() {
        let _ = crate::net::datapath::mempool::init_net_mempool(16);
        let queue = NetTxQueue::new();
        let packet = crate::net::datapath::mempool::alloc_packet().expect("packet");
        assert!(queue.push(packet, NetTxMeta::default()));
        assert!(queue.pop().is_some());
        assert!(queue.pop().is_none());
    }

    #[test_case]
    fn event_sink_from_isr_roundtrip_smoke() {
        let sink = NetEventSink::new();
        assert!(sink.push_from_isr(NetDriverEvent::QueueWake { queue_index: 7 }));
        assert_eq!(
            sink.pop(),
            Some(NetDriverEvent::QueueWake { queue_index: 7 })
        );
        assert!(sink.pop().is_none());
    }

    #[test_case]
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
}
