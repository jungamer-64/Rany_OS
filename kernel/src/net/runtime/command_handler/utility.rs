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
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::ArpProbe {
                if_id,
                target_ip,
            }) => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                stack.send_arp_probe_on(if_id, ip);
                EventHandleResult::Success
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
                let is_primary =
                    crate::net::runtime::manager::primary_interface_in(runtime) == Some(if_id);
                {
                    if is_primary {
                        // DNSサーバーを更新
                        if !dns_servers.is_empty() {
                            crate::net::services::dns::set_ipv4_servers_in(runtime, &dns_servers);
                        }

                        crate::net::services::mdns::set_local_ip_in(runtime, lease.ip_address);
                    }
                    stack.apply_dhcp_v4_lease_for_interface(
                        &lease,
                        if_id,
                        dns_servers.first().copied(),
                    );
                    log::info!(
                        "[NET] DHCP lease bound: if{} primary={} ip={}",
                        if_id.0,
                        is_primary,
                        lease.ip_address
                    );
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
                stack.apply_ipv6_global_address_on(if_id, ipv6_addr);

                let is_primary =
                    crate::net::runtime::manager::primary_interface_in(runtime) == Some(if_id);

                if is_primary {
                    // DNSサーバーを更新
                    if !dns_servers.is_empty() {
                        crate::net::services::dns::set_ipv6_servers_in(runtime, &dns_servers);
                    }
                }

                log::info!(
                    "[NET] DHCPv6 lease applied: if{} addr={}",
                    if_id.0,
                    ipv6_addr
                );
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetPrimaryInterfaceConfig { reply },
            ) => {
                let result =
                    crate::net::api::config::primary_interface_config_from_runtime_in(runtime);
                finish_command(reply, result)
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetInterfaceConfig { if_id, reply },
            ) => finish_command(
                reply,
                crate::net::api::config::get_interface_config_from_runtime_in(
                    runtime,
                    NetIfId(if_id),
                ),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaceConfigs { reply },
            ) => finish_command(
                reply,
                crate::net::api::config::list_interface_configs_from_runtime_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetInterfaceStats { if_id, reply },
            ) => finish_command(
                reply,
                crate::net::api::config::interface_stats_snapshot_with_stack_in(
                    runtime,
                    NetIfId(if_id),
                    Some(stack),
                ),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaceStats { reply },
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
                crate::net::runtime::command::ControlCommand::GetNetworkSnapshot { reply },
            ) => finish_command(reply, crate::net::obs::snapshot_in(runtime)),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetNetworkRecentEvents {
                    limit,
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::obs::observability_in(runtime)
                    .trace()
                    .recent(limit),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallEnable { reply },
            ) => finish_command(reply, crate::net::security::firewall::enable_in(runtime)),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallDisable { reply },
            ) => finish_command(reply, crate::net::security::firewall::disable_in(runtime)),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallStatus { reply },
            ) => finish_command(
                reply,
                crate::net::api::firewall::firewall_status_text_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallListRules { reply },
            ) => finish_command(
                reply,
                crate::net::api::firewall::firewall_list_rules_text_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallStats { reply },
            ) => finish_command(
                reply,
                crate::net::api::firewall::firewall_stats_text_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallAddRule { rule, reply },
            ) => finish_command(
                reply,
                crate::net::security::firewall::add_rule_in(runtime, rule)
                    .map_err(alloc::string::String::from),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallRemoveRule { id, reply },
            ) => finish_command(
                reply,
                crate::net::security::firewall::remove_rule_in(runtime, id)
                    .map_err(alloc::string::String::from),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallClearRules { reply },
            ) => finish_command(
                reply,
                crate::net::security::firewall::clear_rules_in(runtime)
                    .map_err(alloc::string::String::from),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallSetDefaultPolicy {
                    direction,
                    action,
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::security::firewall::set_default_policy_in(runtime, direction, action)
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
                if_id,
                ip,
                mac,
            }) => {
                let now = crate::time::get_uptime_ms();
                let ipv4 = crate::net::l3::ipv4::Ipv4Address::new(ip);
                let mac_addr = MacAddress::new(mac);
                stack.arp_cache_insert_on(if_id, ipv4, mac_addr, now);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::NeighborResolvedV4 { if_id, ip, mac },
            ) => {
                let now = crate::time::get_uptime_ms();
                let ipv4 = crate::net::l3::ipv4::Ipv4Address::new(ip);
                let mac_addr = crate::net::l2::ethernet::MacAddress::new(mac);
                stack.arp_cache_insert_on(if_id, ipv4, mac_addr, now);
                stack.drain_arp_pending_on(if_id, &ipv4);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::NeighborResolvedV6 { if_id, ip, mac },
            ) => {
                let now = crate::time::get_uptime_ms();
                let ipv6 = crate::net::l3::ipv6::Ipv6Address::new(ip);
                stack.ndp_cache_insert_on(if_id, &ipv6, mac, now);
                stack.drain_ndp_pending_on(if_id, &ipv6);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetUdpEndpoints { reply },
            ) => finish_command(
                reply,
                crate::net::api::connections::udp_endpoint_infos_from_runtime_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::InterfaceTopologyDirty { revision },
            ) => {
                if !stack.needs_interface_topology_revision(revision) {
                    return EventHandleResult::Success;
                }

                if let Some(topology) =
                    crate::net::runtime::manager::try_interface_topology_in(runtime)
                {
                    stack.reconcile_interface_topology(topology);
                }
                EventHandleResult::Success
            }
            _ => EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition),
        }
    }
}
