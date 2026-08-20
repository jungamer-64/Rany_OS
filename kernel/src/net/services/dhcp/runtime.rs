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
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DhcpRuntimeError {
    StatePoisoned,
    MissingInterface,
    Spawn(crate::task::SpawnError),
}

impl fmt::Display for DhcpRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StatePoisoned => formatter.write_str("DHCP runtime state is poisoned"),
            Self::MissingInterface => formatter.write_str("DHCP interface runtime is missing"),
            Self::Spawn(error) => write!(formatter, "failed to schedule DHCP task: {error:?}"),
        }
    }
}

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
            v4: DhcpClient::new(runtime, if_id, config.mac),
            v6: DhcpV6Client::new(runtime, if_id, config.mac),
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
}

impl DhcpRuntimeState {
    pub const fn new() -> Self {
        Self {
            interface_runtimes: PoisonLock::new(BTreeMap::new()),
            v4_dispatcher_started: AtomicBool::new(false),
            v6_dispatcher_started: AtomicBool::new(false),
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
) -> Result<(), DhcpRuntimeError> {
    ensure_v4_dispatcher_task_in(runtime)?;
    ensure_v6_dispatcher_task_in(runtime)?;

    let interface_runtime = {
        let mut guard = runtime_state_for(runtime)
            .interface_runtimes
            .lock()
            .map_err(|_| DhcpRuntimeError::StatePoisoned)?;
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
        if let Err(error) = crate::task::spawn(
            dhcp_v4_drive_task(interface_runtime),
            crate::task::TaskPlacement::Any,
        ) {
            interface_runtime
                .drive_started
                .store(false, Ordering::Release);
            return Err(DhcpRuntimeError::Spawn(error));
        }
    }

    if !interface_runtime
        .v6_drive_started
        .swap(true, Ordering::AcqRel)
    {
        if let Err(error) = crate::task::spawn(
            dhcp_v6_drive_task(interface_runtime),
            crate::task::TaskPlacement::Any,
        ) {
            interface_runtime
                .v6_drive_started
                .store(false, Ordering::Release);
            return Err(DhcpRuntimeError::Spawn(error));
        }
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
    interface_runtime.v4.release()
}

pub(crate) fn restart_interface_runtime_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Result<(), DhcpRuntimeError> {
    ensure_v4_dispatcher_task_in(runtime)?;

    let Some(interface_runtime) = interface_runtime_in(runtime, if_id) else {
        return Err(DhcpRuntimeError::MissingInterface);
    };

    interface_runtime.active.store(true, Ordering::Release);
    interface_runtime.suspended.store(false, Ordering::Release);

    if !interface_runtime.drive_started.swap(true, Ordering::AcqRel) {
        if let Err(error) = crate::task::spawn(
            dhcp_v4_drive_task(interface_runtime),
            crate::task::TaskPlacement::Any,
        ) {
            interface_runtime
                .drive_started
                .store(false, Ordering::Release);
            return Err(DhcpRuntimeError::Spawn(error));
        }
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
    let primary_if = crate::net::runtime::manager::primary_interface_in(runtime)?;
    let guard = state.interface_runtimes.lock().ok()?;
    guard.get(&primary_if).copied().filter(|runtime| {
        runtime.active.load(Ordering::Acquire) && !runtime.suspended.load(Ordering::Acquire)
    })
}

pub(crate) fn primary_v4_client_in(runtime: NetRuntimeHandle) -> Option<&'static DhcpClient> {
    primary_interface_runtime_in(runtime).map(|runtime| &runtime.v4)
}

fn ensure_v4_dispatcher_task_in(runtime: NetRuntimeHandle) -> Result<(), DhcpRuntimeError> {
    if runtime_state_for(runtime)
        .v4_dispatcher_started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        if let Err(error) = crate::task::spawn(
            dhcp_v4_dispatcher_task(runtime),
            crate::task::TaskPlacement::Any,
        ) {
            runtime_state_for(runtime)
                .v4_dispatcher_started
                .store(false, Ordering::Release);
            return Err(DhcpRuntimeError::Spawn(error));
        }
    }
    Ok(())
}

fn ensure_v6_dispatcher_task_in(runtime: NetRuntimeHandle) -> Result<(), DhcpRuntimeError> {
    if runtime_state_for(runtime)
        .v6_dispatcher_started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        if let Err(error) = crate::task::spawn(
            dhcp_v6_dispatcher_task(runtime),
            crate::task::TaskPlacement::Any,
        ) {
            runtime_state_for(runtime)
                .v6_dispatcher_started
                .store(false, Ordering::Release);
            return Err(DhcpRuntimeError::Spawn(error));
        }
    }
    Ok(())
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
        if let Err(err) = runtime.v4.drive(now, 1000).await {
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
        if let Err(err) = runtime.v6.check_timeout(now, 1000) {
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
            Some((if_id, _src, _ttl, packet)) => {
                let now = crate::task::current_tick();
                let process = interface_runtime_in(runtime, if_id)
                    .filter(|interface_runtime| {
                        interface_runtime.active.load(Ordering::Acquire)
                            && !interface_runtime.suspended.load(Ordering::Acquire)
                            && interface_runtime.v4.matches_response_payload(&packet)
                    })
                    .map(|interface_runtime| {
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
                        let _ = crate::net::runtime::command::try_enqueue_command_in(
                            runtime,
                            crate::net::runtime::command::RuntimeCommand::Control(
                                crate::net::runtime::command::ControlCommand::DhcpApplyLease {
                                    if_id: interface_runtime.if_id,
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
            Some((if_id, src, _ttl, packet)) => {
                let src_v6 = match src {
                    crate::net::l4::udp::UdpAddr::V6 { ip, .. } => ip,
                    _ => continue,
                };

                let process = interface_runtime_in(runtime, if_id)
                    .filter(|interface_runtime| {
                        interface_runtime.active.load(Ordering::Acquire)
                            && !interface_runtime.suspended.load(Ordering::Acquire)
                            && interface_runtime.v6.matches_response_payload(&packet)
                    })
                    .map(|interface_runtime| {
                        let handled = interface_runtime.v6.handle_packet_payload(packet, src_v6);
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
