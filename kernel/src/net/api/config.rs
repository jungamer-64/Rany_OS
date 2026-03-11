// ============================================================================
// kernel/src/net/api/config.rs - インターフェース別ネットワーク設定・統計
// ============================================================================

use crate::net::runtime::{
    device,
    manager::{self, NetIfId, NetworkInterfaceInfo},
    stack,
};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// Per-interface configuration snapshot for shell and bootstrap consumers.
#[derive(Debug, Clone)]
pub struct InterfaceConfigSnapshot {
    pub if_id: u16,
    pub name: alloc::string::String,
    pub admin_up: bool,
    pub virtio_index: Option<u8>,
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub mac: [u8; 6],
}

/// Legacy single-interface snapshot retained for internal event payloads.
#[derive(Debug, Clone)]
pub struct NetworkConfigSnapshot {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub mac: [u8; 6],
}

/// Per-interface runtime statistics snapshot.
#[derive(Debug, Clone, Copy)]
pub struct InterfaceStatsSnapshot {
    pub if_id: u16,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
}

/// Legacy aggregate stats snapshot retained for internal event payloads.
#[derive(Debug, Clone, Copy)]
pub struct NetworkStatsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
}

/// Lightweight interface summary used by shell and bootstrap flows.
#[derive(Debug, Clone)]
pub struct InterfaceSnapshot {
    pub if_id: u16,
    pub name: alloc::string::String,
    pub admin_up: bool,
    pub virtio_index: Option<u8>,
    pub ip: Option<[u8; 4]>,
    pub mac: Option<[u8; 6]>,
}

fn interface_config_snapshot(iface: NetworkInterfaceInfo) -> Option<InterfaceConfigSnapshot> {
    let config = iface.config?;
    Some(InterfaceConfigSnapshot {
        if_id: iface.if_id.0,
        name: iface.name,
        admin_up: iface.admin_up,
        virtio_index: iface.virtio_index,
        ip: *config.ipv4.address.as_bytes(),
        netmask: *config.ipv4.subnet_mask.as_bytes(),
        gateway: *config.ipv4.gateway.as_bytes(),
        mac: *config.mac.as_bytes(),
    })
}

fn interface_stats_snapshot(if_id: NetIfId) -> Option<InterfaceStatsSnapshot> {
    let mut stack_snapshot = InterfaceStatsSnapshot {
        if_id: if_id.0,
        rx_packets: 0,
        tx_packets: 0,
        rx_bytes: 0,
        tx_bytes: 0,
        rx_errors: 0,
        tx_errors: 0,
        rx_dropped: 0,
    };

    if let Ok(guard) = stack::stack().lock() {
        if let Some(stack) = guard.as_ref() {
            if let Some(stats) = stack.interface_stats(if_id) {
                stack_snapshot.rx_packets =
                    stats.rx_packets.load(core::sync::atomic::Ordering::Relaxed);
                stack_snapshot.tx_packets =
                    stats.tx_packets.load(core::sync::atomic::Ordering::Relaxed);
                stack_snapshot.rx_bytes =
                    stats.rx_bytes.load(core::sync::atomic::Ordering::Relaxed);
                stack_snapshot.tx_bytes =
                    stats.tx_bytes.load(core::sync::atomic::Ordering::Relaxed);
                stack_snapshot.rx_errors =
                    stats.rx_errors.load(core::sync::atomic::Ordering::Relaxed);
                stack_snapshot.rx_dropped =
                    stats.rx_dropped.load(core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    if let Some(port) = device::lookup_port(if_id) {
        let driver_stats = port.driver().stats();
        stack_snapshot.rx_packets = stack_snapshot.rx_packets.max(driver_stats.rx_packets);
        stack_snapshot.tx_packets = stack_snapshot.tx_packets.max(driver_stats.tx_packets);
        stack_snapshot.rx_errors = stack_snapshot.rx_errors.max(driver_stats.rx_errors);
        stack_snapshot.tx_errors = stack_snapshot.tx_errors.max(driver_stats.tx_errors);
        return Some(stack_snapshot);
    }

    if stack_snapshot.rx_packets != 0
        || stack_snapshot.tx_packets != 0
        || stack_snapshot.rx_bytes != 0
        || stack_snapshot.tx_bytes != 0
        || stack_snapshot.rx_errors != 0
        || stack_snapshot.tx_errors != 0
        || stack_snapshot.rx_dropped != 0
    {
        return Some(stack_snapshot);
    }

    None
}

fn interface_summary_snapshot(iface: NetworkInterfaceInfo) -> InterfaceSnapshot {
    let ip = iface.config.map(|config| *config.ipv4.address.as_bytes());
    let mac = iface.config.map(|config| *config.mac.as_bytes());
    InterfaceSnapshot {
        if_id: iface.if_id.0,
        name: iface.name,
        admin_up: iface.admin_up,
        virtio_index: iface.virtio_index,
        ip,
        mac,
    }
}

pub fn primary_interface_config_snapshot() -> Option<NetworkConfigSnapshot> {
    let preferred_if = device::primary_if().or_else(|| {
        manager::list_interfaces()
            .ok()
            .and_then(|ifaces| ifaces.first().map(|iface| iface.if_id))
    })?;
    get_interface_config(preferred_if).map(|cfg| NetworkConfigSnapshot {
        ip: cfg.ip,
        netmask: cfg.netmask,
        gateway: cfg.gateway,
        mac: cfg.mac,
    })
}

pub fn aggregate_network_stats_snapshot() -> Option<NetworkStatsSnapshot> {
    let stats = list_interface_stats();
    if stats.is_empty() {
        return None;
    }
    Some(NetworkStatsSnapshot {
        rx_packets: stats.iter().map(|s| s.rx_packets).sum(),
        tx_packets: stats.iter().map(|s| s.tx_packets).sum(),
        rx_bytes: stats.iter().map(|s| s.rx_bytes).sum(),
        tx_bytes: stats.iter().map(|s| s.tx_bytes).sum(),
        rx_errors: stats.iter().map(|s| s.rx_errors).sum(),
        rx_dropped: stats.iter().map(|s| s.rx_dropped).sum(),
    })
}

pub fn get_interface_config(if_id: NetIfId) -> Option<InterfaceConfigSnapshot> {
    manager::get_interface(if_id)
        .ok()
        .flatten()
        .and_then(interface_config_snapshot)
}

pub fn list_interface_configs() -> alloc::vec::Vec<InterfaceConfigSnapshot> {
    manager::list_interfaces()
        .unwrap_or_default()
        .into_iter()
        .filter_map(interface_config_snapshot)
        .collect()
}

pub fn get_interface_stats(if_id: NetIfId) -> Option<InterfaceStatsSnapshot> {
    interface_stats_snapshot(if_id)
}

pub fn list_interface_stats() -> alloc::vec::Vec<InterfaceStatsSnapshot> {
    manager::list_interfaces()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|iface| interface_stats_snapshot(iface.if_id))
        .collect()
}

pub fn list_interfaces() -> alloc::vec::Vec<InterfaceSnapshot> {
    manager::list_interfaces()
        .unwrap_or_default()
        .into_iter()
        .map(interface_summary_snapshot)
        .collect()
}

pub struct ReadyFuture<T> {
    value: Option<T>,
}

impl<T> ReadyFuture<T> {
    fn new(value: T) -> Self {
        Self { value: Some(value) }
    }
}

impl<T: Unpin> Future for ReadyFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        Poll::Ready(this.value.take().expect("ready future polled after completion"))
    }
}

pub fn get_interface_config_async(if_id: NetIfId) -> ReadyFuture<Option<InterfaceConfigSnapshot>> {
    ReadyFuture::new(get_interface_config(if_id))
}

pub fn list_interface_configs_async() -> ReadyFuture<alloc::vec::Vec<InterfaceConfigSnapshot>> {
    ReadyFuture::new(list_interface_configs())
}

pub fn get_interface_stats_async(if_id: NetIfId) -> ReadyFuture<Option<InterfaceStatsSnapshot>> {
    ReadyFuture::new(get_interface_stats(if_id))
}

pub fn list_interface_stats_async() -> ReadyFuture<alloc::vec::Vec<InterfaceStatsSnapshot>> {
    ReadyFuture::new(list_interface_stats())
}

pub fn list_interfaces_async() -> ReadyFuture<alloc::vec::Vec<InterfaceSnapshot>> {
    ReadyFuture::new(list_interfaces())
}
