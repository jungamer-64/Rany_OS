// ============================================================================
// kernel/src/net/runtime/command_handler/utility.rs - ランタイム / コマンドハンドラ / 補助処理
// ============================================================================
//! RuntimeCommandHandler Utility/Config/Firewall系メソッド

use crate::net::l2::ethernet::MacAddress;
use crate::net::l4::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::RuntimeCommand;
use crate::net::runtime::command_handler::common::finish_command;
use crate::net::runtime::command_handler::{EventHandleResult, RuntimeCommandHandler};
use crate::net::runtime::manager::NetIfId;

impl RuntimeCommandHandler {
    pub(super) fn handle_utility_event_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        event: RuntimeCommand,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::IcmpEcho {
                target,
                sequence,
                reply,
            }) => {
                let target_ip = crate::net::l3::ipv4::Ipv4Address::new(target);
                let result = stack
                    .send_icmp_echo_request(target_ip, sequence)
                    .map_err(|_| ());
                finish_command(reply, result)
            }
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::ArpProbe {
                target_ip,
            }) => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                stack.send_arp_probe(ip);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpResolveCheck {
                    target_ip,
                    requester_mac,
                    reply,
                },
            ) => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                let now = stack.current_time();
                let result = stack.arp_resolve(ip, now).map(|mac| {
                    let req_mac = MacAddress::new(requester_mac);
                    mac != req_mac && !mac.is_broadcast()
                });
                finish_command(reply, result)
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpApplyLease { if_id, config },
            ) => {
                let crate::net::services::dhcp::DhcpV4AppliedConfig {
                    ip_address,
                    subnet_mask,
                    gateway,
                    dns_servers,
                    metadata_payload: _,
                    hostname: _,
                    domain_name: _,
                } = config;
                let lease = crate::net::services::dhcp::DhcpLease {
                    ip_address,
                    subnet_mask,
                    gateway,
                    server_ip: crate::net::l3::ipv4::Ipv4Address::ANY,
                    lease_time: 0,
                    t1: 0,
                    t2: 0,
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
                        if !dns_servers.is_empty() {
                            crate::net::services::dns::set_ipv4_servers(&dns_servers);
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
                    stack.apply_dhcp_v4_lease_for_interface(
                        &lease,
                        if_id,
                        is_primary,
                        dns_servers.first().copied(),
                    );
                    log::info!(
                        "[NET] DHCP lease bound: if{} primary={} ip={}",
                        if_id.0,
                        is_primary,
                        lease.ip_address
                    );
                } else {
                    stack.apply_dhcp_v4_lease(&lease, dns_servers.first().copied());
                }
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpV6ApplyLease { if_id, config },
            ) => {
                let crate::net::services::dhcp::DhcpV6AppliedConfig {
                    addr: ipv6_addr,
                    dns_servers,
                    domain_search: _,
                } = config;
                stack.enqueue_apply_ipv6_global_address(ipv6_addr);

                let is_primary = if_id
                    .map(|id| {
                        crate::net::runtime::device::primary_if_in(runtime) == Some(NetIfId(id))
                    })
                    .unwrap_or(true);

                if is_primary {
                    // DNSサーバーを更新
                    if !dns_servers.is_empty() {
                        crate::net::services::dns::set_ipv6_servers(&dns_servers);
                    }
                }

                log::info!(
                    "[NET] DHCPv6 lease applied: if{:?} addr={}",
                    if_id,
                    ipv6_addr
                );
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetLinkLocal { reply },
            ) => {
                let result = stack.config().ipv6.map(|config| config.link_local.octets());
                finish_command(reply, result)
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetPrimaryInterfaceConfig {
                    reply,
                },
            ) => {
                let result =
                    crate::net::api::config::primary_interface_config_from_runtime_in(runtime);
                finish_command(reply, result)
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetInterfaceConfig {
                    if_id,
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::api::config::get_interface_config_from_runtime_in(
                    runtime,
                    NetIfId(if_id),
                ),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaceConfigs {
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::api::config::list_interface_configs_from_runtime_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetInterfaceStats {
                    if_id,
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::api::config::interface_stats_snapshot_with_stack_in(
                    runtime,
                    NetIfId(if_id),
                    Some(stack),
                ),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaceStats {
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::api::config::list_interface_stats_with_stack_in(runtime, Some(stack)),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaces { reply },
            ) => finish_command(
                reply,
                crate::net::api::config::list_interfaces_from_runtime_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetNetworkSnapshot {
                    reply,
                },
            ) => finish_command(reply, crate::net::obs::snapshot()),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetNetworkRecentEvents {
                    limit,
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::obs::snapshot()
                    .recent_events
                    .into_iter()
                    .take(limit)
                    .collect(),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallEnable { reply },
            ) => finish_command(reply, crate::net::security::firewall::enable()),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallDisable {
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::security::firewall::disable(),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallStatus { reply },
            ) => finish_command(
                reply,
                crate::net::api::firewall::firewall_status_text(),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallListRules {
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::api::firewall::firewall_list_rules_text(),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallStats { reply },
            ) => finish_command(
                reply,
                crate::net::api::firewall::firewall_stats_text(),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallAddRule {
                    rule,
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::security::firewall::add_rule(rule).map_err(alloc::string::String::from),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallRemoveRule {
                    id,
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::security::firewall::remove_rule(id)
                    .map_err(alloc::string::String::from),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallClearRules {
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::security::firewall::clear_rules().map_err(alloc::string::String::from),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallSetDefaultPolicy {
                    direction,
                    action,
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::security::firewall::set_default_policy(direction, action)
                    .map_err(alloc::string::String::from),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetArpCache { reply },
            ) => {
                let entries: alloc::vec::Vec<_> = stack
                    .arp_cache()
                    .iter()
                    .map(|(ip, mac)| crate::net::api::connections::ArpCacheEntry {
                        ip: *ip.as_bytes(),
                        mac: *mac.as_bytes(),
                        complete: true,
                    })
                    .collect();
                finish_command(reply, entries)
            }
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::ArpInsert {
                ip,
                mac,
            }) => {
                let now = crate::time::get_uptime_ms();
                let ipv4 = crate::net::l3::ipv4::Ipv4Address::new(ip);
                let mac_addr = MacAddress::new(mac);
                stack.arp_cache_insert(ipv4, mac_addr, now);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetUdpEndpoints {
                    reply,
                },
            ) => {
                let mut result = alloc::vec::Vec::new();
                crate::net::l4::socket::for_each_socket(|endpoint| {
                    if !endpoint.is_udp() {
                        return;
                    }
                    let Some(local_addr) =
                        endpoint.with_inner(|inner| inner.local_addr).flatten()
                    else {
                        return;
                    };
                    result.push(crate::net::api::connections::UdpEndpointInfo {
                        local_addr: alloc::format!("*:{}", local_addr.port()),
                        remote_addr: alloc::string::String::from("*:*"),
                    });
                });
                finish_command(reply, result)
            }
            _ => EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition),
        }
    }
}
