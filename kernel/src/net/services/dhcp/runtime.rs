// ============================================================================
// kernel/src/net/services/dhcp/runtime.rs - サービス / DHCP / ランタイム
// ============================================================================

use super::v4::{DHCP_CLIENT_PORT, DhcpAckResult, DhcpClient, DhcpResponseResult};
use super::v6::{DHCPV6_CLIENT_PORT, DhcpV6Client};
use crate::net::l2::ethernet::MacAddress;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::stack::NetworkConfig;
use crate::sync::PoisonLock;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

const INVALID_IF_ID: u16 = u16::MAX;

struct DhcpInterfaceRuntime {
    if_id: NetIfId,
    config: NetworkConfig,
    v4: DhcpClient,
    v6: DhcpV6Client,
    active: AtomicBool,
    suspended: AtomicBool,
    drive_started: AtomicBool,
    v6_drive_started: AtomicBool,
}

impl DhcpInterfaceRuntime {
    fn new(runtime: NetRuntimeHandle, if_id: NetIfId, config: NetworkConfig) -> &'static Self {
        Box::leak(Box::new(Self {
            if_id,
            config,
            v4: DhcpClient::new(runtime, config.mac),
            v6: DhcpV6Client::new(runtime, config.mac),
            active: AtomicBool::new(true),
            suspended: AtomicBool::new(false),
            drive_started: AtomicBool::new(false),
            v6_drive_started: AtomicBool::new(false),
        }))
    }

    fn mac(&self) -> MacAddress {
        self.config.mac
    }
}

pub(crate) struct DhcpRuntimeState {
    interface_runtimes: PoisonLock<BTreeMap<NetIfId, &'static DhcpInterfaceRuntime>>,
    v4_dispatcher_started: AtomicBool,
    v6_dispatcher_started: AtomicBool,
    primary_if_id: AtomicU16,
}

impl DhcpRuntimeState {
    pub const fn new() -> Self {
        Self {
            interface_runtimes: PoisonLock::new(BTreeMap::new()),
            v4_dispatcher_started: AtomicBool::new(false),
            v6_dispatcher_started: AtomicBool::new(false),
            primary_if_id: AtomicU16::new(INVALID_IF_ID),
        }
    }
}

pub(crate) fn runtime_state_for(runtime: NetRuntimeHandle) -> &'static DhcpRuntimeState {
    &runtime.context().dhcp
}

pub(crate) fn primary_v6_client_in(runtime: NetRuntimeHandle) -> Option<&'static DhcpV6Client> {
    primary_interface_runtime_in(runtime).map(|runtime| &runtime.v6)
}

pub(crate) fn ensure_interface_runtime_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    config: NetworkConfig,
) -> Result<(), &'static str> {
    ensure_v4_dispatcher_task_in(runtime);
    ensure_v6_dispatcher_task_in(runtime);

    let interface_runtime = {
        let mut guard = runtime_state_for(runtime)
            .interface_runtimes
            .lock()
            .map_err(|_| "DHCP interface runtime lock poisoned")?;
        if let Some(existing) = guard.get(&if_id) {
            existing.active.store(true, Ordering::Release);
            existing.suspended.store(false, Ordering::Release);
            *existing
        } else {
            let interface_runtime = DhcpInterfaceRuntime::new(runtime, if_id, config);
            guard.insert(if_id, interface_runtime);
            interface_runtime
        }
    };

    if !interface_runtime.drive_started.swap(true, Ordering::AcqRel) {
        crate::task::spawn_task(crate::task::Task::new(dhcp_v4_drive_task(
            interface_runtime,
        )));
    }

    if !interface_runtime
        .v6_drive_started
        .swap(true, Ordering::AcqRel)
    {
        crate::task::spawn_task(crate::task::Task::new(dhcp_v6_drive_task(
            interface_runtime,
        )));
    }

    Ok(())
}

pub(crate) fn unregister_interface_runtime_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    let removed = runtime_state_for(runtime)
        .interface_runtimes
        .lock()
        .ok()
        .and_then(|mut guard| guard.remove(&if_id));
    if let Some(interface_runtime) = removed {
        interface_runtime.active.store(false, Ordering::Release);
    }
    clear_primary_interface_in(runtime, if_id);
}

pub(crate) fn mark_primary_interface_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    runtime_state_for(runtime)
        .primary_if_id
        .store(if_id.0, Ordering::Release);
}

pub(crate) fn clear_primary_interface_in(runtime: NetRuntimeHandle, if_id: NetIfId) {
    let state = runtime_state_for(runtime);
    if state.primary_if_id.load(Ordering::Acquire) == if_id.0 {
        state.primary_if_id.store(INVALID_IF_ID, Ordering::Release);
    }
}

fn interface_runtime_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<&'static DhcpInterfaceRuntime> {
    runtime_state_for(runtime)
        .interface_runtimes
        .lock()
        .ok()
        .and_then(|guard| guard.get(&if_id).copied())
}

pub(crate) fn interface_v4_client_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<&'static DhcpClient> {
    interface_runtime_in(runtime, if_id).map(|runtime| &runtime.v4)
}

pub(crate) fn lease_for_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<super::DhcpLease> {
    interface_v4_client_in(runtime, if_id).and_then(|client| client.lease())
}

pub(crate) fn has_bound_lease_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> bool {
    lease_for_interface_in(runtime, if_id).is_some()
}

pub(crate) fn release_interface_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> bool {
    let Some(interface_runtime) = interface_runtime_in(runtime, if_id) else {
        return false;
    };
    interface_runtime.suspended.store(true, Ordering::Release);
    interface_runtime.v4.release_on(Some(if_id))
}

pub(crate) fn restart_interface_runtime_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Result<(), &'static str> {
    ensure_v4_dispatcher_task_in(runtime);

    let Some(interface_runtime) = interface_runtime_in(runtime, if_id) else {
        return Err("DHCP interface runtime missing");
    };

    interface_runtime.active.store(true, Ordering::Release);
    interface_runtime.suspended.store(false, Ordering::Release);

    if !interface_runtime.drive_started.swap(true, Ordering::AcqRel) {
        crate::task::spawn_task(crate::task::Task::new(dhcp_v4_drive_task(
            interface_runtime,
        )));
    }

    interface_runtime
        .v4
        .force_renew_or_restart(crate::task::current_tick());
    Ok(())
}

fn primary_interface_runtime_in(
    runtime: NetRuntimeHandle,
) -> Option<&'static DhcpInterfaceRuntime> {
    let state = runtime_state_for(runtime);
    let primary_if = state.primary_if_id.load(Ordering::Acquire);
    let guard = state.interface_runtimes.lock().ok()?;
    if primary_if != INVALID_IF_ID {
        if let Some(runtime) = guard.get(&NetIfId(primary_if)) {
            return Some(*runtime);
        }
    }
    guard
        .values()
        .find(|runtime| {
            runtime.active.load(Ordering::Acquire) && !runtime.suspended.load(Ordering::Acquire)
        })
        .copied()
}

pub(crate) fn primary_v4_client_in(runtime: NetRuntimeHandle) -> Option<&'static DhcpClient> {
    primary_interface_runtime_in(runtime).map(|runtime| &runtime.v4)
}

fn find_runtime_for_v4_payload_in(
    runtime: NetRuntimeHandle,
    packet: &kernel_api::resource::net::PacketPayload,
) -> Option<&'static DhcpInterfaceRuntime> {
    let guard = runtime_state_for(runtime).interface_runtimes.lock().ok()?;
    for runtime in guard.values() {
        if runtime.active.load(Ordering::Acquire)
            && !runtime.suspended.load(Ordering::Acquire)
            && runtime.v4.matches_response_payload(packet)
        {
            return Some(*runtime);
        }
    }
    None
}

fn find_runtime_for_v6_payload_in(
    runtime: NetRuntimeHandle,
    packet: &kernel_api::resource::net::PacketPayload,
) -> Option<&'static DhcpInterfaceRuntime> {
    let guard = runtime_state_for(runtime).interface_runtimes.lock().ok()?;
    for runtime in guard.values() {
        if runtime.active.load(Ordering::Acquire)
            && !runtime.suspended.load(Ordering::Acquire)
            && runtime.v6.matches_response_payload(packet)
        {
            return Some(*runtime);
        }
    }
    None
}

fn ensure_v4_dispatcher_task_in(runtime: NetRuntimeHandle) {
    if runtime_state_for(runtime)
        .v4_dispatcher_started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        crate::task::spawn_task(crate::task::Task::new(dhcp_v4_dispatcher_task(runtime)));
    }
}

fn ensure_v6_dispatcher_task_in(runtime: NetRuntimeHandle) {
    if runtime_state_for(runtime)
        .v6_dispatcher_started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        crate::task::spawn_task(crate::task::Task::new(dhcp_v6_dispatcher_task(runtime)));
    }
}

async fn dhcp_v4_drive_task(runtime: &'static DhcpInterfaceRuntime) {
    log::info!(
        "[NET] DHCPv4 interface task started: if{} mac={}",
        runtime.if_id.0,
        runtime.mac()
    );

    while runtime.active.load(Ordering::Acquire) {
        if runtime.suspended.load(Ordering::Acquire) {
            crate::task::sleep_ms(200).await;
            continue;
        }

        let now = crate::task::current_tick();
        if let Err(err) = runtime
            .v4
            .drive_on_interface(runtime.if_id, now, 1000)
            .await
        {
            log::warn!(
                "[NET] DHCPv4 interface drive failed: if{} err={}",
                runtime.if_id.0,
                err
            );
        }
        crate::task::sleep_ms(200).await;
    }

    runtime.drive_started.store(false, Ordering::Release);
}

async fn dhcp_v6_drive_task(runtime: &'static DhcpInterfaceRuntime) {
    log::info!(
        "[NET] DHCPv6 interface task started: if{} mac={}",
        runtime.if_id.0,
        runtime.mac()
    );

    while runtime.active.load(Ordering::Acquire) {
        if runtime.suspended.load(Ordering::Acquire) {
            crate::task::sleep_ms(200).await;
            continue;
        }

        let now = crate::task::current_tick();
        if let Err(err) = runtime.v6.check_timeout(Some(runtime.if_id), now, 1000) {
            log::warn!(
                "[NET] DHCPv6 interface check failed: if{} err={}",
                runtime.if_id.0,
                err
            );
        }
        crate::task::sleep_ms(1000).await;
    }

    runtime.v6_drive_started.store(false, Ordering::Release);
}

async fn dhcp_v4_dispatcher_task(runtime: NetRuntimeHandle) {
    let socket = match crate::net::l4::udp::UdpEndpoint::bind_in(
        runtime,
        crate::net::types::InterfaceScope::Any,
        DHCP_CLIENT_PORT,
        None,
    ) {
        Ok(socket) => socket,
        Err(_) => {
            log::error!("[NET] DHCPv4 dispatcher failed to bind UDP port 68");
            runtime_state_for(runtime)
                .v4_dispatcher_started
                .store(false, Ordering::Release);
            return;
        }
    };

    log::info!("[NET] DHCPv4 dispatcher task started");

    loop {
        match socket.recv().await {
            Some((_if_id, _src, _ttl, packet)) => {
                let now = crate::task::current_tick();
                let process =
                    find_runtime_for_v4_payload_in(runtime, &packet).map(|interface_runtime| {
                        let result = interface_runtime.v4.process_response_payload(packet, now);
                        (interface_runtime, result)
                    });
                let Some((interface_runtime, result)) = process else {
                    continue;
                };

                match result {
                    Ok(DhcpResponseResult::Ack(result)) => {
                        let DhcpAckResult { lease, applied } = result;
                        log::info!(
                            "[NET] DHCPv4 ACK received: if{} mac={} ip={:?}",
                            interface_runtime.if_id.0,
                            interface_runtime.mac(),
                            lease.ip_address
                        );
                        crate::net::runtime::command::enqueue_command_ignore_in(
                            runtime,
                            crate::net::runtime::command::RuntimeCommand::Control(
                                crate::net::runtime::command::ControlCommand::DhcpApplyLease {
                                    if_id: Some(interface_runtime.if_id.0),
                                    config: applied,
                                },
                            ),
                        );
                    }
                    Ok(DhcpResponseResult::Offer(lease)) => {
                        log::info!(
                            "[NET] DHCPv4 OFFER received: if{} mac={} ip={:?} server={:?}",
                            interface_runtime.if_id.0,
                            interface_runtime.mac(),
                            lease.ip_address,
                            lease.server_ip
                        );
                    }
                    Ok(DhcpResponseResult::Nak) => {
                        log::warn!(
                            "[NET] DHCPv4 NAK received: if{} mac={}",
                            interface_runtime.if_id.0,
                            interface_runtime.mac()
                        );
                    }
                    Err(err) => {
                        log::warn!(
                            "[NET] DHCPv4 response error: if{} mac={} err={}",
                            interface_runtime.if_id.0,
                            interface_runtime.mac(),
                            err
                        );
                    }
                }
            }
            None => {
                log::warn!("[NET] DHCPv4 dispatcher socket closed unexpectedly");
                runtime_state_for(runtime)
                    .v4_dispatcher_started
                    .store(false, Ordering::Release);
                break;
            }
        }
    }
}

async fn dhcp_v6_dispatcher_task(runtime: NetRuntimeHandle) {
    let socket = match crate::net::l4::udp::UdpEndpoint::bind_in(
        runtime,
        crate::net::types::InterfaceScope::Any,
        DHCPV6_CLIENT_PORT,
        None,
    ) {
        Ok(socket) => socket,
        Err(_) => {
            log::error!("[NET] DHCPv6 dispatcher failed to bind UDP port 546");
            runtime_state_for(runtime)
                .v6_dispatcher_started
                .store(false, Ordering::Release);
            return;
        }
    };

    log::info!("[NET] DHCPv6 dispatcher task started");

    loop {
        match socket.recv().await {
            Some((_if_id, src, _ttl, packet)) => {
                let src_v6 = match src {
                    crate::net::l4::udp::UdpAddr::V6 { ip, .. } => ip,
                    _ => continue,
                };

                let process =
                    find_runtime_for_v6_payload_in(runtime, &packet).map(|interface_runtime| {
                        let handled = interface_runtime.v6.handle_packet_payload(
                            Some(interface_runtime.if_id),
                            packet,
                            src_v6,
                        );
                        (interface_runtime, handled)
                    });
                let Some((interface_runtime, handled)) = process else {
                    continue;
                };

                if handled {
                    log::info!(
                        "[NET] DHCPv6 packet handled: if{} mac={}",
                        interface_runtime.if_id.0,
                        interface_runtime.mac()
                    );
                }
            }
            None => {
                log::warn!("[NET] DHCPv6 dispatcher socket closed unexpectedly");
                runtime_state_for(runtime)
                    .v6_dispatcher_started
                    .store(false, Ordering::Release);
                break;
            }
        }
    }
}

pub fn update_runtime_mac(_mac_address: MacAddress) {
    // TODO: Support dynamic MAC address update for all interface clients
}
