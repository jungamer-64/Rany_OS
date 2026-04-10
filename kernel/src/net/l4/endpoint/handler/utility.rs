// ============================================================================
// kernel/src/net/l4/endpoint/handler/utility.rs
// ============================================================================
//! NetworkEventHandler Utility/Config/Firewall系メソッド

use crate::net::l2::ethernet::MacAddress;
use crate::net::l4::endpoint::event::NetworkEvent;
use crate::net::l4::endpoint::handler::common::finish_command;
use crate::net::l4::endpoint::handler::{EventHandleResult, NetworkEventHandler};
use crate::net::l4::endpoint::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;

impl NetworkEventHandler {
    pub(super) fn handle_utility_event_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        event: NetworkEvent,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            NetworkEvent::IcmpEcho {
                target,
                sequence,
                result_slot,
                waker,
            } => {
                let target_ip = crate::net::l3::ipv4::Ipv4Address::new(target);
                let result = stack
                    .send_icmp_echo_request(target_ip, sequence)
                    .map_err(|_| ());
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::ArpProbe { target_ip } => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                stack.send_arp_probe(ip);
                EventHandleResult::Success
            }
            NetworkEvent::ArpResolveCheck {
                target_ip,
                requester_mac,
                result_slot,
                waker,
            } => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                let now = stack.current_time();
                let result = stack.arp_resolve(ip, now).map(|mac| {
                    let req_mac = MacAddress::new(requester_mac);
                    mac != req_mac && !mac.is_broadcast()
                });
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpApplyLease {
                if_id,
                ip,
                subnet,
                gateway,
                dns_servers,
                hostname,
            } => {
                let lease = crate::net::services::dhcp::DhcpLease {
                    ip_address: crate::net::l3::ipv4::Ipv4Address::new(ip),
                    subnet_mask: crate::net::l3::ipv4::Ipv4Address::new(subnet),
                    gateway: Some(crate::net::l3::ipv4::Ipv4Address::new(gateway)),
                    dns_servers: dns_servers
                        .iter()
                        .map(|a| crate::net::l3::ipv4::Ipv4Address::new(*a))
                        .collect(),
                    server_ip: crate::net::l3::ipv4::Ipv4Address::ANY,
                    lease_time: 0,
                    t1: 0,
                    t2: 0,
                    hostname: if hostname.is_empty() {
                        None
                    } else {
                        crate::net::payload::PayloadSpan::from_bytes(&hostname)
                    },
                    domain_name: None,
                    obtained_at: crate::task::current_tick(),
                };
                let target_if = if_id.map(NetIfId);
                let selected_primary = target_if
                    .map(|if_id| {
                        crate::net::runtime::device::claim_bound_primary_interface_with_stack_state_in(
                            runtime,
                            if_id,
                            stack,
                        )
                    })
                    .unwrap_or(false);
                if let Some(if_id) = target_if {
                    let is_primary = selected_primary
                        || crate::net::runtime::device::primary_if_in(runtime) == Some(if_id);
                    if is_primary {
                        crate::net::services::dhcp::mark_primary_interface(if_id);

                        // DNSサーバーを更新
                        if !lease.dns_servers.is_empty() {
                            crate::net::services::dns::set_ipv4_servers(lease.dns_servers.clone());
                        }

                        // mDNS のローカル IP を更新
                        if let Ok(mut guard) =
                            crate::net::services::mdns::service_in(runtime).lock()
                        {
                            if let Some(ref mut mdns) = *guard {
                                mdns.set_local_ip(lease.ip_address);
                            }
                        }
                    }
                    stack.apply_dhcp_v4_lease_for_interface(&lease, if_id, is_primary);
                    log::info!(
                        "[NET] DHCP lease bound: if{} primary={} ip={}",
                        if_id.0,
                        is_primary,
                        lease.ip_address
                    );
                } else {
                    stack.apply_dhcp_v4_lease(&lease);
                }
                EventHandleResult::Success
            }
            NetworkEvent::DhcpV6ApplyLease {
                if_id,
                addr,
                dns_servers,
                domain_search: _,
            } => {
                let ipv6_addr = crate::net::l3::ipv6::Ipv6Address::new(addr);
                stack.enqueue_apply_ipv6_global_address(ipv6_addr);

                let is_primary = if_id
                    .map(|id| {
                        crate::net::runtime::device::primary_if_in(runtime) == Some(NetIfId(id))
                    })
                    .unwrap_or(true);

                if is_primary {
                    // DNSサーバーを更新
                    if !dns_servers.is_empty() {
                        let v6_servers = dns_servers
                            .iter()
                            .map(|a| crate::net::l3::ipv6::Ipv6Address::new(*a))
                            .collect();
                        crate::net::services::dns::set_ipv6_servers(v6_servers);
                    }
                }

                log::info!(
                    "[NET] DHCPv6 lease applied: if{:?} addr={}",
                    if_id,
                    ipv6_addr
                );
                EventHandleResult::Success
            }
            NetworkEvent::GetLinkLocal { result_slot, waker } => {
                let result = stack.config().ipv6.map(|config| config.link_local.octets());
                finish_command(result_slot, waker, result)
            }
            NetworkEvent::GetPrimaryInterfaceConfig { result_slot, waker } => {
                let result =
                    crate::net::api::config::primary_interface_config_from_runtime_in(runtime);
                finish_command(result_slot, waker, result)
            }
            NetworkEvent::GetInterfaceConfig {
                if_id,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::get_interface_config_from_runtime_in(
                    runtime,
                    NetIfId(if_id),
                ),
            ),
            NetworkEvent::ListInterfaceConfigs { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::list_interface_configs_from_runtime_in(runtime),
            ),
            NetworkEvent::GetInterfaceStats {
                if_id,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::interface_stats_snapshot_with_stack_in(
                    runtime,
                    NetIfId(if_id),
                    Some(stack),
                ),
            ),
            NetworkEvent::ListInterfaceStats { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::list_interface_stats_with_stack_in(runtime, Some(stack)),
            ),
            NetworkEvent::ListInterfaces { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::list_interfaces_from_runtime_in(runtime),
            ),
            NetworkEvent::GetNetworkSnapshot { result_slot, waker } => {
                finish_command(result_slot, waker, crate::net::obs::snapshot())
            }
            NetworkEvent::GetNetworkRecentEvents {
                limit,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::obs::snapshot()
                    .recent_events
                    .into_iter()
                    .take(limit)
                    .collect(),
            ),
            NetworkEvent::FirewallEnable { result_slot, waker } => {
                finish_command(result_slot, waker, crate::net::security::firewall::enable())
            }
            NetworkEvent::FirewallDisable { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::security::firewall::disable(),
            ),
            NetworkEvent::FirewallStatus { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_status_text(),
            ),
            NetworkEvent::FirewallListRules { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_list_rules_text(),
            ),
            NetworkEvent::FirewallStats { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_stats_text(),
            ),
            NetworkEvent::FirewallAddRule {
                rule,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::security::firewall::add_rule(rule).map_err(alloc::string::String::from),
            ),
            NetworkEvent::FirewallRemoveRule {
                id,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::security::firewall::remove_rule(id)
                    .map_err(alloc::string::String::from),
            ),
            NetworkEvent::FirewallClearRules { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::security::firewall::clear_rules().map_err(alloc::string::String::from),
            ),
            NetworkEvent::FirewallSetDefaultPolicy {
                direction,
                action,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::security::firewall::set_default_policy(direction, action)
                    .map_err(alloc::string::String::from),
            ),
            NetworkEvent::GetArpCache { result_slot, waker } => {
                let entries: alloc::vec::Vec<_> = stack
                    .arp_cache()
                    .iter()
                    .map(|(ip, mac)| crate::net::api::connections::ArpCacheEntry {
                        ip: *ip.as_bytes(),
                        mac: *mac.as_bytes(),
                        complete: true,
                    })
                    .collect();
                finish_command(result_slot, waker, entries)
            }
            NetworkEvent::ArpInsert { ip, mac } => {
                let now = crate::time::get_uptime_ms();
                let ipv4 = crate::net::l3::ipv4::Ipv4Address::new(ip);
                let mac_addr = MacAddress::new(mac);
                stack.arp_cache_insert(ipv4, mac_addr, now);
                EventHandleResult::Success
            }
            NetworkEvent::GetUdpEndpoints { result_slot, waker } => {
                let mut result = alloc::vec::Vec::new();
                if let Some(manager) = crate::net::l4::endpoint::manager::ENDPOINT_MANAGER
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                {
                    manager.for_each(|endpoint| {
                        if endpoint.socket_type()
                            != crate::net::l4::endpoint::types::EndpointType::Udp
                        {
                            return;
                        }
                        let inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
                        let Some(local_addr) = inner.local_addr else {
                            return;
                        };
                        result.push(crate::net::api::connections::UdpEndpointInfo {
                            local_addr: alloc::format!("*:{}", local_addr.port()),
                            remote_addr: alloc::string::String::from("*:*"),
                        });
                    });
                }
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            _ => EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition),
        }
    }
}
