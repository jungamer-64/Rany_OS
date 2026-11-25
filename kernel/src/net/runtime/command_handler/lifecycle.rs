// ============================================================================
// kernel/src/net/runtime/command_handler/lifecycle.rs - ランタイム / コマンドハンドラ / ライフサイクル処理
// ============================================================================
//! RuntimeCommandHandler ソケット制御/ライフサイクル系メソッド

use crate::net::l4::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::RuntimeCommand;
use crate::net::runtime::command::complete_command;
use crate::net::runtime::command_handler::{EventHandleResult, RuntimeCommandHandler};
use crate::net::runtime::transport::tcp_table_in;

impl RuntimeCommandHandler {
    pub(super) fn handle_lifecycle_event_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        event: RuntimeCommand,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpResolveRequest {
                    if_id,
                    target_ip,
                },
            ) => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                let current_time = stack.current_time();
                if let Some(mac) = stack.arp_resolve_on(if_id, ip, current_time) {
                    crate::net::l2::arp::notify_arp_resolved_in(
                        runtime,
                        if_id,
                        target_ip,
                        *mac.as_bytes(),
                    );
                } else {
                    stack.send_arp_request_on(if_id, ip);
                }
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::NdpResolveRequest {
                    if_id,
                    target_ip,
                },
            ) => {
                let ip = crate::net::l3::ipv6::Ipv6Address::new(target_ip);

                if ip.is_multicast() {
                    crate::net::l3::ndp::notify_ndp_resolved_in(
                        runtime,
                        if_id,
                        target_ip,
                        ip.multicast_mac(),
                    );
                    return EventHandleResult::Success;
                }

                let path = crate::net::runtime::manager::Ipv6Path {
                    if_id,
                    next_hop: ip,
                };
                if let Ok(Some(mac)) = stack.resolve_ipv6_neighbor(path) {
                    crate::net::l3::ndp::notify_ndp_resolved_in(
                        runtime,
                        if_id,
                        target_ip,
                        *mac.as_bytes(),
                    );
                }
                EventHandleResult::Success
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpDial {
                    local,
                    remote,
                    scope,
                    reply,
                },
            ) => {
                let result =
                    self.make_tcp_connection_with_stack(runtime, local, remote, scope, stack);
                complete_command(reply, result);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::MulticastJoin {
                    if_id,
                    group,
                    reply,
                },
            ) => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(group);
                let success = stack.join_multicast_group_on(if_id, ip).is_ok();
                complete_command(reply, success);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::MulticastLeave {
                    if_id,
                    group,
                    reply,
                },
            ) => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(group);
                let success = stack.leave_multicast_group_on(if_id, ip).is_ok();
                complete_command(reply, success);
                EventHandleResult::Success
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpBind {
                    local,
                    scope,
                    backlog,
                    reply,
                },
            ) => {
                let result = self.make_tcp_acceptor_with_stack(runtime, local, scope, backlog);
                complete_command(reply, result);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessLocalTimeouts,
            ) => {
                // NetworkStack内部タイマーの基準時刻を同期する。
                let now = crate::task::current_tick();
                stack.update_time(now);
                stack.process_timeouts();

                // ICMP Echo待ちの期限切れエントリをクリーンアップ
                crate::net::api::icmp::cleanup_icmp_echo_waiters_in(runtime);
                // ARP非同期解決待ちのタイムアウト済みウェイターをクリーンアップ
                crate::net::l2::arp::cleanup_arp_waiters_in(runtime);
                // NDP非同期解決待ちのタイムアウト済みウェイターをクリーンアップ
                crate::net::l3::ndp::cleanup_ndp_waiters_in(runtime);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessGlobalTimeouts,
            ) => {
                if let Err(error) = stack.maintain_ipv6_addresses(crate::task::current_tick()) {
                    log::warn!("[NET] IPv6 topology maintenance failed: {:?}", error);
                }
                // --- RFC Compliance: Process TCP periodic tasks ---
                // 1. TCB table maintenance (RTO, TimeWait, FinWait2, etc.)
                tcp_table_in(runtime).tick(runtime);
                // 2. Delayed ACK flushing (RFC 1122 Section 4.2.3.2)
                crate::net::l4::tcp::tcp_rx::flush_delayed_acks_in(runtime);
                EventHandleResult::Success
            }
            _ => EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition),
        }
    }
}
