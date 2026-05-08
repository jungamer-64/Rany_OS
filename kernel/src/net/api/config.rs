// ============================================================================
// kernel/src/net/api/config.rs - インターフェース別ネットワーク設定・統計
// ============================================================================

use crate::net::runtime::{
    NetRuntimeHandle, device,
    manager::{self, NetIfId, NetworkInterfaceInfo},
    stack,
};

/// Per-interface configuration snapshot for shell and bootstrap consumers.
#[derive(Debug)]
pub struct InterfaceConfigSnapshot {
    pub if_id: u16,
    pub name: alloc::string::String,
    pub admin_up: bool,
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

/// Lightweight interface summary used by shell and bootstrap flows.
#[derive(Debug)]
pub struct InterfaceSnapshot {
    pub if_id: u16,
    pub name: alloc::string::String,
    pub admin_up: bool,
    pub ip: Option<[u8; 4]>,
    pub mac: Option<[u8; 6]>,
}

pub(crate) fn interface_config_snapshot(
    iface: NetworkInterfaceInfo,
) -> Option<InterfaceConfigSnapshot> {
    let config = iface.config?;
    Some(InterfaceConfigSnapshot {
        if_id: iface.if_id.0,
        name: alloc::string::String::from(iface.name),
        admin_up: iface.admin_up,
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

    if let Some(driver_stats) = device::port_stats_for_interface_in(runtime, if_id) {
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
        name: alloc::string::String::from(iface.name),
        admin_up: iface.admin_up,
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

pub(crate) fn primary_interface_config_from_runtime_in(
    runtime: NetRuntimeHandle,
) -> Option<InterfaceConfigSnapshot> {
    let preferred_if = primary_interface_id_in(runtime)?;
    get_interface_config_from_runtime_in(runtime, preferred_if)
}

pub(crate) fn list_interface_stats_from_runtime_in(
    runtime: NetRuntimeHandle,
) -> alloc::vec::Vec<InterfaceStatsSnapshot> {
    if let Ok(guard) = runtime.context().stack.lock() {
        if let Some(stack) = guard.as_ref() {
            return list_interface_stats_with_stack_in(runtime, Some(stack));
        }
    }
    list_interface_stats_with_stack_in(runtime, None)
}

pub async fn primary_interface_config_in(
    runtime: NetRuntimeHandle,
) -> Option<InterfaceConfigSnapshot> {
    let (reply, command_future) = crate::net::runtime::command::new_command_channel_in::<
        Option<InterfaceConfigSnapshot>,
    >(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::GetPrimaryInterfaceConfig { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn get_interface_config_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<InterfaceConfigSnapshot> {
    let (reply, command_future) = crate::net::runtime::command::new_command_channel_in::<
        Option<InterfaceConfigSnapshot>,
    >(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::GetInterfaceConfig {
            if_id: if_id.0,
            reply,
        },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn list_interface_configs_in(
    runtime: NetRuntimeHandle,
) -> alloc::vec::Vec<InterfaceConfigSnapshot> {
    let (reply, command_future) = crate::net::runtime::command::new_command_channel_in::<
        alloc::vec::Vec<InterfaceConfigSnapshot>,
    >(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::ListInterfaceConfigs { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn get_interface_stats_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<InterfaceStatsSnapshot> {
    let (reply, command_future) = crate::net::runtime::command::new_command_channel_in::<
        Option<InterfaceStatsSnapshot>,
    >(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::GetInterfaceStats {
            if_id: if_id.0,
            reply,
        },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn list_interface_stats_in(
    runtime: NetRuntimeHandle,
) -> alloc::vec::Vec<InterfaceStatsSnapshot> {
    let (reply, command_future) = crate::net::runtime::command::new_command_channel_in::<
        alloc::vec::Vec<InterfaceStatsSnapshot>,
    >(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::ListInterfaceStats { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn list_interfaces_in(runtime: NetRuntimeHandle) -> alloc::vec::Vec<InterfaceSnapshot> {
    let (reply, command_future) = crate::net::runtime::command::new_command_channel_in::<
        alloc::vec::Vec<InterfaceSnapshot>,
    >(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::ListInterfaces { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
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
        F: Future,
    {
        crate::net::runtime::command::reset_command_system_for_tests_in(runtime);
        let mut executor = crate::task::TestExecutor::new();
        executor.spawn(crate::task::Task::new(async move {
            crate::net::runtime::command_loop::runtime_command_task_in(runtime).await;
        }));

        let waker = crate::net::l4::test_support::noop_waker();
        let mut cx = core::task::Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if let core::task::Poll::Ready(output) = Future::poll(future.as_mut(), &mut cx) {
                crate::net::runtime::command::reset_command_system_for_tests_in(runtime);
                return output;
            }
        }

        crate::net::runtime::command::reset_command_system_for_tests_in(runtime);
        panic!("network config test future timed out")
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn list_interfaces_completes_with_event_task() {
        let interfaces = run_with_event_task_in(
            default_runtime(),
            super::list_interfaces_in(default_runtime()),
        );
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
