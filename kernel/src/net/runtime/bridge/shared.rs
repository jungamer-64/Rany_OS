extern crate alloc;

use crate::net::datapath::mempool::PacketRef;
use crate::net::l2::ethernet::MacAddress;
use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};
use crate::net::runtime::manager::{self, NetIfId};
use crate::net::runtime::stack::{self, NetworkConfig};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use spin::RwLock;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BridgePortStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_errors: u64,
    pub rx_errors: u64,
    pub initialized: bool,
}

pub trait NetBridgePort: Send + Sync {
    fn port_name(&self) -> &'static str;
    fn mac_address(&self) -> MacAddress;
    fn start(&self, dispatch: RxDispatchHandle) -> Result<(), &'static str>;
    fn enqueue_tx(&self, data: &[u8]) -> bool;
    fn stats(&self) -> BridgePortStats;
    fn health(&self) -> bool;
    fn stop(&self);
}

#[derive(Clone, Copy)]
pub struct RxDispatchHandle {
    if_id: NetIfId,
}

impl RxDispatchHandle {
    pub const fn new(if_id: NetIfId) -> Self {
        Self { if_id }
    }

    pub const fn if_id(&self) -> NetIfId {
        self.if_id
    }

    pub fn dispatch_zero_copy(self, packet: PacketRef, header_size: usize, payload_len: usize) {
        super::process_received_packet_zero_copy_for_interface(
            self.if_id,
            packet,
            header_size,
            payload_len,
        );
    }
}

static BRIDGE_PORTS: RwLock<BTreeMap<NetIfId, Arc<dyn NetBridgePort>>> =
    RwLock::new(BTreeMap::new());

pub fn ensure_stack_initialized(config: NetworkConfig) -> Result<(), &'static str> {
    if super::BRIDGE_INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }

    if super::BRIDGE_INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(());
    }

    if let Err(err) = crate::net::datapath::mempool::init_net_mempool(1024) {
        log::warn!("[NET BRIDGE] mempool init failed: {}", err);
    }

    stack::init(config);
    manager::init_network_manager();

    match stack::stack().lock() {
        Ok(mut guard) => {
            let Some(stack) = guard.as_mut() else {
                super::BRIDGE_INITIALIZED.store(false, Ordering::Release);
                return Err("network stack unavailable");
            };
            stack.set_transmit_fn(transmit);
        }
        Err(_) => {
            super::BRIDGE_INITIALIZED.store(false, Ordering::Release);
            return Err("network stack poisoned");
        }
    }

    if let Err(err) = crate::net::api::dhcp::init_dhcp_runtime() {
        log::warn!("[NET BRIDGE] DHCP runtime init failed: {}", err);
    }

    Ok(())
}

pub fn install_port(
    if_id: NetIfId,
    port: Arc<dyn NetBridgePort>,
    make_primary: bool,
) -> Result<(), &'static str> {
    port.start(RxDispatchHandle::new(if_id))?;

    {
        let mut ports = BRIDGE_PORTS.write();
        ports.insert(if_id, port);
    }

    super::ensure_bridge_if_state(if_id, None);
    let mut primary = super::PRIMARY_BRIDGE_IF.write();
    if primary.is_none() || make_primary {
        *primary = Some(if_id);
    }

    Ok(())
}

pub fn remove_port(if_id: NetIfId) {
    if let Some(port) = BRIDGE_PORTS.write().remove(&if_id) {
        port.stop();
    }
}

pub fn lookup_port(if_id: NetIfId) -> Option<Arc<dyn NetBridgePort>> {
    BRIDGE_PORTS.read().get(&if_id).cloned()
}

pub fn transmit(if_id: Option<NetIfId>, data: &[u8]) -> bool {
    let Some(target_if) = if_id.or_else(super::primary_bridge_if) else {
        counters::global().record_error();
        trace::push_event(
            NetLayer::Driver,
            NetEventKind::Error,
            "bridge transmit missing interface",
        );
        return false;
    };

    let Some(port) = lookup_port(target_if) else {
        counters::global().record_error();
        trace::push_event(
            NetLayer::Driver,
            NetEventKind::Error,
            "bridge transmit target not registered",
        );
        return false;
    };

    if port.enqueue_tx(data) {
        super::record_bridge_if_tx(target_if);
        true
    } else {
        counters::global().record_error();
        trace::push_event(
            NetLayer::Driver,
            NetEventKind::Error,
            "bridge transmit enqueue failed",
        );
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicUsize};

    struct FakePort {
        tx_count: AtomicUsize,
        started: AtomicBool,
    }

    impl FakePort {
        const fn new() -> Self {
            Self {
                tx_count: AtomicUsize::new(0),
                started: AtomicBool::new(false),
            }
        }
    }

    impl NetBridgePort for FakePort {
        fn port_name(&self) -> &'static str {
            "fake"
        }

        fn mac_address(&self) -> MacAddress {
            MacAddress::from_octets(0, 1, 2, 3, 4, 5)
        }

        fn start(&self, _dispatch: RxDispatchHandle) -> Result<(), &'static str> {
            self.started.store(true, Ordering::Release);
            Ok(())
        }

        fn enqueue_tx(&self, _data: &[u8]) -> bool {
            self.tx_count.fetch_add(1, Ordering::Relaxed);
            true
        }

        fn stats(&self) -> BridgePortStats {
            BridgePortStats {
                tx_packets: self.tx_count.load(Ordering::Relaxed) as u64,
                rx_packets: 0,
                tx_errors: 0,
                rx_errors: 0,
                initialized: self.started.load(Ordering::Acquire),
            }
        }

        fn health(&self) -> bool {
            self.started.load(Ordering::Acquire)
        }

        fn stop(&self) {
            self.started.store(false, Ordering::Release);
        }
    }

    #[test_case]
    fn install_port_registers_runtime_and_transmit_dispatches() {
        let prev_primary = *super::super::PRIMARY_BRIDGE_IF.read();
        let prev_stats = core::mem::take(&mut *super::super::BRIDGE_IF_STATS.write());
        let port = Arc::new(FakePort::new());
        let if_id = NetIfId(123);

        install_port(if_id, port.clone(), true).expect("install fake port");
        assert!(transmit(Some(if_id), b"hello"));
        assert_eq!(port.stats().tx_packets, 1);

        remove_port(if_id);
        *super::super::PRIMARY_BRIDGE_IF.write() = prev_primary;
        *super::super::BRIDGE_IF_STATS.write() = prev_stats;
    }
}
