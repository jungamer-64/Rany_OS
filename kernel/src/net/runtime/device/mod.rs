//! Shared network device runtime.
//!
//! This layer owns device registration, interface binding, TX queuing, and
//! executor-side delivery of deferred device events.

extern crate alloc;

use crate::net::l2::ethernet::MacAddress;
use crate::net::runtime::manager::{self, NetIfId};
use crate::net::runtime::stack::{self, NetworkConfig};
use crate::sync::atomic_waker::AtomicWaker;
use crate::sync::lockfree::MpmcRingBuffer;
use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

const NET_DEVICE_TX_QUEUE_CAPACITY: usize = 1024;
const NET_DEVICE_EVENT_QUEUE_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetDeviceKey {
    Virtio(u8),
    Mlx5(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDeviceKind {
    Virtio,
    Mlx5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDeviceEvent {
    Interrupt,
    QueueWake { queue_index: u16 },
    Poll,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NetDeviceStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_errors: u64,
    pub rx_errors: u64,
    pub initialized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetDeviceBinding {
    pub key: NetDeviceKey,
    pub if_id: NetIfId,
    pub kind: NetDeviceKind,
    pub virtio_index: Option<u8>,
}

#[derive(Debug)]
struct TxRequest {
    data: Vec<u8>,
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

    pub fn push(&self, data: &[u8]) -> bool {
        match self.queue.push(TxRequest { data: data.to_vec() }) {
            Ok(()) => {
                self.waker.wake();
                true
            }
            Err(_) => false,
        }
    }

    pub fn pop(&self) -> Option<Vec<u8>> {
        self.queue.pop().map(|req| req.data)
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

pub struct NetRxEventSink {
    queue: MpmcRingBuffer<NetDeviceEvent, NET_DEVICE_EVENT_QUEUE_CAPACITY>,
    waker: AtomicWaker,
}

impl NetRxEventSink {
    pub fn new() -> Self {
        Self {
            queue: MpmcRingBuffer::new(),
            waker: AtomicWaker::new(),
        }
    }

    pub fn push(&self, event: NetDeviceEvent) -> bool {
        match self.queue.push(event) {
            Ok(()) => {
                self.waker.wake();
                true
            }
            Err(_) => false,
        }
    }

    pub fn push_from_isr(&self, event: NetDeviceEvent) -> bool {
        match self.queue.push(event) {
            Ok(()) => {
                self.waker.wake_from_isr();
                true
            }
            Err(_) => false,
        }
    }

    pub fn pop(&self) -> Option<NetDeviceEvent> {
        self.queue.pop()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn wake(&self) {
        self.waker.wake();
    }

    pub fn wait(&self) -> NetRxEventWaitFuture<'_> {
        NetRxEventWaitFuture { sink: self }
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

pub struct NetRxEventWaitFuture<'a> {
    sink: &'a NetRxEventSink,
}

impl Future for NetRxEventWaitFuture<'_> {
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

pub trait NetDeviceDriver: Send + Sync {
    fn key(&self) -> NetDeviceKey;
    fn kind(&self) -> NetDeviceKind;
    fn port_name(&self) -> &'static str;
    fn mac_address(&self) -> MacAddress;
    fn mtu(&self) -> u32 {
        stack::MTU as u32
    }
    fn health(&self) -> bool;
    fn start(&self, if_id: NetIfId, event_sink: Arc<NetRxEventSink>) -> Result<(), &'static str>;
    fn bind_interface(&self, _if_id: NetIfId) -> Result<(), &'static str> {
        Ok(())
    }
    fn submit_tx(&self, data: &[u8]) -> Result<(), &'static str>;
    fn on_event(&self, if_id: NetIfId, event: NetDeviceEvent) -> Result<(), &'static str>;
    fn stats(&self) -> NetDeviceStats;
    fn stop(&self);
}

pub struct NetDeviceHandle {
    driver: Arc<dyn NetDeviceDriver>,
    binding: PoisonLock<NetDeviceBinding>,
    tx_queue: Arc<NetTxQueue>,
    event_sink: Arc<NetRxEventSink>,
    active: AtomicBool,
    tx_worker_started: AtomicBool,
    event_worker_started: AtomicBool,
}

impl NetDeviceHandle {
    fn new(driver: Arc<dyn NetDeviceDriver>, binding: NetDeviceBinding) -> Arc<Self> {
        Arc::new(Self {
            driver,
            binding: PoisonLock::new(binding),
            tx_queue: Arc::new(NetTxQueue::new()),
            event_sink: Arc::new(NetRxEventSink::new()),
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

    pub fn driver(&self) -> &Arc<dyn NetDeviceDriver> {
        &self.driver
    }

    pub fn enqueue_tx(&self, data: &[u8]) -> bool {
        self.tx_queue.push(data)
    }

    pub fn enqueue_event(&self, event: NetDeviceEvent) -> bool {
        self.event_sink.push(event)
    }

    pub fn enqueue_event_from_isr(&self, event: NetDeviceEvent) -> bool {
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
        self.driver.bind_interface(binding.if_id)?;
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

        while let Some(data) = pending {
            if !handle.active.load(Ordering::Acquire) {
                return;
            }

            if let Err(err) = handle.driver.submit_tx(&data) {
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

            let if_id = handle.binding().if_id;
            if let Err(err) = handle.driver.on_event(if_id, event) {
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
    driver: Arc<dyn NetDeviceDriver>,
    config: NetworkConfig,
    make_primary: bool,
) -> Result<NetIfId, &'static str> {
    ensure_stack_initialized(config)?;

    if let Some(existing) = lookup_if_by_key(driver.key()) {
        if make_primary {
            set_primary_interface(existing);
        }
        return Ok(existing);
    }

    let key = driver.key();
    let kind = driver.kind();
    let if_id = interface_for_key(key, config, driver.port_name())?;
    let binding = NetDeviceBinding {
        key,
        if_id,
        kind,
        virtio_index: match key {
            NetDeviceKey::Virtio(index) => Some(index),
            NetDeviceKey::Mlx5(_) => None,
        },
    };
    let handle = NetDeviceHandle::new(driver.clone(), binding);
    driver.bind_interface(if_id)?;
    driver.start(if_id, handle.event_sink.clone())?;
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
    DEVICE_MANAGER.read().unwrap_or_else(|e| e.into_inner()).key_map.get(&key).copied()
}

pub fn lookup_device(if_id: NetIfId) -> Option<Arc<NetDeviceHandle>> {
    DEVICE_MANAGER.read().unwrap_or_else(|e| e.into_inner()).handles.get(&if_id).cloned()
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

pub fn primary_if() -> Option<NetIfId> {
    DEVICE_MANAGER.read().unwrap_or_else(|e| e.into_inner()).primary
}

pub fn set_primary_interface(if_id: NetIfId) {
    DEVICE_MANAGER.write().unwrap_or_else(|e| e.into_inner()).primary = Some(if_id);
}

pub fn transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    let resolved_if = if_id.or_else(primary_if);
    let Some(handle) = resolved_if.and_then(lookup_device) else {
        return false;
    };
    handle.enqueue_tx(data)
}

pub fn enqueue_event(key: NetDeviceKey, event: NetDeviceEvent) -> bool {
    let Some(if_id) = lookup_if_by_key(key) else {
        return false;
    };
    let Some(handle) = lookup_device(if_id) else {
        return false;
    };
    handle.enqueue_event(event)
}

pub fn enqueue_event_from_isr(key: NetDeviceKey, event: NetDeviceEvent) -> bool {
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

    impl NetDeviceDriver for FakeDriver {
        fn key(&self) -> NetDeviceKey {
            NetDeviceKey::Virtio(9)
        }

        fn kind(&self) -> NetDeviceKind {
            NetDeviceKind::Virtio
        }

        fn port_name(&self) -> &'static str {
            "fake"
        }

        fn mac_address(&self) -> MacAddress {
            MacAddress::from_octets(0, 1, 2, 3, 4, 5)
        }

        fn health(&self) -> bool {
            true
        }

        fn start(
            &self,
            if_id: NetIfId,
            _event_sink: Arc<NetRxEventSink>,
        ) -> Result<(), &'static str> {
            self.last_if_id.store(if_id.0, Ordering::Release);
            Ok(())
        }

        fn bind_interface(&self, if_id: NetIfId) -> Result<(), &'static str> {
            self.bind_calls.fetch_add(1, Ordering::Relaxed);
            self.last_if_id.store(if_id.0, Ordering::Release);
            Ok(())
        }

        fn submit_tx(&self, _data: &[u8]) -> Result<(), &'static str> {
            Ok(())
        }

        fn on_event(&self, _if_id: NetIfId, event: NetDeviceEvent) -> Result<(), &'static str> {
            if let NetDeviceEvent::QueueWake { queue_index } = event {
                self.last_event_queue.store(queue_index, Ordering::Release);
            }
            Ok(())
        }

        fn stats(&self) -> NetDeviceStats {
            NetDeviceStats::default()
        }

        fn stop(&self) {}
    }

    #[test_case]
    fn tx_queue_roundtrip_smoke() {
        let queue = NetTxQueue::new();
        assert!(queue.push(b"hello"));
        assert_eq!(queue.pop().as_deref(), Some(&b"hello"[..]));
        assert!(queue.pop().is_none());
    }

    #[test_case]
    fn rx_event_sink_from_isr_roundtrip_smoke() {
        let sink = NetRxEventSink::new();
        assert!(sink.push_from_isr(NetDeviceEvent::QueueWake { queue_index: 7 }));
        assert_eq!(
            sink.pop(),
            Some(NetDeviceEvent::QueueWake { queue_index: 7 })
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
                kind: NetDeviceKind::Virtio,
                virtio_index: Some(9),
            },
        );

        handle
            .rebind(NetDeviceBinding {
                key: NetDeviceKey::Virtio(9),
                if_id: NetIfId(22),
                kind: NetDeviceKind::Virtio,
                virtio_index: Some(9),
            })
            .expect("rebind");

        assert_eq!(handle.binding().if_id, NetIfId(22));
        assert_eq!(driver.bind_calls.load(Ordering::Relaxed), 1);
        assert_eq!(driver.last_if_id.load(Ordering::Acquire), 22);
    }
}
