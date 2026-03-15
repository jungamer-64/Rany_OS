// ============================================================================
// kernel/src/net/api/config.rs - インターフェース別ネットワーク設定・統計
// ============================================================================

use crate::net::runtime::{
    NetRuntimeHandle, device,
    manager::{self, NetIfId, NetworkInterfaceInfo},
    stack,
};

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

pub(crate) fn interface_config_snapshot(
    iface: NetworkInterfaceInfo,
) -> Option<InterfaceConfigSnapshot> {
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

pub(crate) fn interface_stats_snapshot_with_stack_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    stack: Option<&stack::NetworkStack>,
) -> Option<InterfaceStatsSnapshot> {
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

    if let Some(stack) = stack {
        if let Some(stats) = stack.interface_stats(if_id) {
            stack_snapshot.rx_packets =
                stats.rx_packets.load(core::sync::atomic::Ordering::Relaxed);
            stack_snapshot.tx_packets =
                stats.tx_packets.load(core::sync::atomic::Ordering::Relaxed);
            stack_snapshot.rx_bytes = stats.rx_bytes.load(core::sync::atomic::Ordering::Relaxed);
            stack_snapshot.tx_bytes = stats.tx_bytes.load(core::sync::atomic::Ordering::Relaxed);
            stack_snapshot.rx_errors = stats.rx_errors.load(core::sync::atomic::Ordering::Relaxed);
            stack_snapshot.rx_dropped =
                stats.rx_dropped.load(core::sync::atomic::Ordering::Relaxed);
        }
    }

    if let Some(port) = device::lookup_port_in(runtime, if_id) {
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

pub(crate) fn interface_summary_snapshot(iface: NetworkInterfaceInfo) -> InterfaceSnapshot {
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

pub(crate) fn primary_interface_id_in(runtime: NetRuntimeHandle) -> Option<NetIfId> {
    device::primary_if_in(runtime).or_else(|| {
        manager::list_interfaces_in(runtime)
            .ok()
            .and_then(|ifaces| ifaces.first().map(|iface| iface.if_id))
    })
}

pub(crate) fn aggregate_network_stats_from_list(
    stats: &[InterfaceStatsSnapshot],
) -> Option<NetworkStatsSnapshot> {
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

pub(crate) fn get_interface_config_from_runtime_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<InterfaceConfigSnapshot> {
    manager::get_interface_in(runtime, if_id)
        .ok()
        .flatten()
        .and_then(interface_config_snapshot)
}

pub(crate) fn list_interface_configs_from_runtime_in(
    runtime: NetRuntimeHandle,
) -> alloc::vec::Vec<InterfaceConfigSnapshot> {
    manager::list_interfaces_in(runtime)
        .unwrap_or_default()
        .into_iter()
        .filter_map(interface_config_snapshot)
        .collect()
}

pub(crate) fn get_interface_stats_without_stack_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<InterfaceStatsSnapshot> {
    interface_stats_snapshot_with_stack_in(runtime, if_id, None)
}

pub(crate) fn list_interface_stats_with_stack_in(
    runtime: NetRuntimeHandle,
    stack: Option<&stack::NetworkStack>,
) -> alloc::vec::Vec<InterfaceStatsSnapshot> {
    manager::list_interfaces_in(runtime)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|iface| interface_stats_snapshot_with_stack_in(runtime, iface.if_id, stack))
        .collect()
}

pub(crate) fn list_interfaces_from_runtime_in(
    runtime: NetRuntimeHandle,
) -> alloc::vec::Vec<InterfaceSnapshot> {
    manager::list_interfaces_in(runtime)
        .unwrap_or_default()
        .into_iter()
        .map(interface_summary_snapshot)
        .collect()
}

pub(crate) fn primary_interface_config_snapshot_sync_in(
    runtime: NetRuntimeHandle,
) -> Option<NetworkConfigSnapshot> {
    let preferred_if = primary_interface_id_in(runtime)?;
    get_interface_config_from_runtime_in(runtime, preferred_if).map(|cfg| NetworkConfigSnapshot {
        ip: cfg.ip,
        netmask: cfg.netmask,
        gateway: cfg.gateway,
        mac: cfg.mac,
    })
}

pub(crate) fn aggregate_network_stats_snapshot_sync_in(
    runtime: NetRuntimeHandle,
) -> Option<NetworkStatsSnapshot> {
    aggregate_network_stats_from_list(&list_interface_stats_sync_in(runtime))
}

pub(crate) fn list_interface_stats_sync_in(
    runtime: NetRuntimeHandle,
) -> alloc::vec::Vec<InterfaceStatsSnapshot> {
    if let Ok(guard) = runtime.context().stack.lock() {
        if let Some(stack) = guard.as_ref() {
            return list_interface_stats_with_stack_in(runtime, Some(stack));
        }
    }
    list_interface_stats_with_stack_in(runtime, None)
}

pub async fn primary_interface_config_snapshot_in(
    runtime: NetRuntimeHandle,
) -> Option<NetworkConfigSnapshot> {
    let (result_slot, waker, command_future) =
        stack::new_command_channel::<Option<NetworkConfigSnapshot>>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::GetPrimaryInterfaceConfig {
        result_slot,
        waker,
    };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn aggregate_network_stats_snapshot_in(
    runtime: NetRuntimeHandle,
) -> Option<NetworkStatsSnapshot> {
    let (result_slot, waker, command_future) =
        stack::new_command_channel::<Option<NetworkStatsSnapshot>>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::GetAggregateNetworkStats {
        result_slot,
        waker,
    };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn get_interface_config_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<InterfaceConfigSnapshot> {
    let (result_slot, waker, command_future) =
        stack::new_command_channel::<Option<InterfaceConfigSnapshot>>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::GetInterfaceConfig {
        if_id: if_id.0,
        result_slot,
        waker,
    };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn list_interface_configs_in(
    runtime: NetRuntimeHandle,
) -> alloc::vec::Vec<InterfaceConfigSnapshot> {
    let (result_slot, waker, command_future) =
        stack::new_command_channel::<alloc::vec::Vec<InterfaceConfigSnapshot>>();
    let event =
        crate::net::l4::endpoint::event::NetworkEvent::ListInterfaceConfigs { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn get_interface_stats_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<InterfaceStatsSnapshot> {
    let (result_slot, waker, command_future) =
        stack::new_command_channel::<Option<InterfaceStatsSnapshot>>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::GetInterfaceStats {
        if_id: if_id.0,
        result_slot,
        waker,
    };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn list_interface_stats_in(
    runtime: NetRuntimeHandle,
) -> alloc::vec::Vec<InterfaceStatsSnapshot> {
    let (result_slot, waker, command_future) =
        stack::new_command_channel::<alloc::vec::Vec<InterfaceStatsSnapshot>>();
    let event =
        crate::net::l4::endpoint::event::NetworkEvent::ListInterfaceStats { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn list_interfaces_in(runtime: NetRuntimeHandle) -> alloc::vec::Vec<InterfaceSnapshot> {
    let (result_slot, waker, command_future) =
        stack::new_command_channel::<alloc::vec::Vec<InterfaceSnapshot>>();
    let event =
        crate::net::l4::endpoint::event::NetworkEvent::ListInterfaces { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

#[cfg(test)]
mod tests {
    use crate::net::runtime::{create_runtime, default_runtime, reset_runtime_registry_for_tests};
    use core::future::Future;

    fn run_with_event_task_in<F>(
        runtime: crate::net::runtime::NetRuntimeHandle,
        future: F,
    ) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        crate::net::l4::endpoint::event::reset_event_system_for_tests_in(runtime);

        let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
        let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let mut executor = crate::task::TestExecutor::new();

        let result_slot_clone = result_slot.clone();
        let completed_clone = completed.clone();
        executor.spawn(crate::task::Task::new(async move {
            let output = future.await;
            let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(output);
            completed_clone.store(true, core::sync::atomic::Ordering::Release);
        }));
        executor.spawn(crate::task::Task::new(async move {
            crate::net::l4::endpoint::tcp_rx::network_event_task_in(runtime).await;
        }));

        let mut output = None;
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if completed.load(core::sync::atomic::Ordering::Acquire) {
                output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                break;
            }
        }

        crate::net::l4::endpoint::event::reset_event_system_for_tests_in(runtime);
        output.expect("network config test future timed out")
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn list_interfaces_completes_with_event_task() {
        let interfaces = {
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output = super::list_interfaces_in(default_runtime()).await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::l4::endpoint::tcp_rx::network_event_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            output.expect("list_interfaces test timed out")
        };
        assert!(interfaces.is_empty());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn list_interfaces_uses_runtime_local_manager() {
        reset_runtime_registry_for_tests();

        let runtime_a = default_runtime();
        let runtime_b = create_runtime();

        manager::init_network_manager_in(runtime_a);
        manager::init_network_manager_in(runtime_b);

        manager::register_interface_in(runtime_a, "rt-a0").expect("runtime a interface");
        manager::register_interface_in(runtime_b, "rt-b0").expect("runtime b interface");
        manager::register_interface_in(runtime_b, "rt-b1").expect("runtime b interface");

        let interfaces = run_with_event_task_in(runtime_b, super::list_interfaces_in(runtime_b));

        let names: alloc::vec::Vec<_> = interfaces.into_iter().map(|iface| iface.name).collect();
        assert_eq!(
            names,
            alloc::vec![
                alloc::string::String::from("rt-b0"),
                alloc::string::String::from("rt-b1")
            ]
        );
    }
}
