// ============================================================================
// kernel/src/net/l4/endpoint/handler/lifecycle.rs
// ============================================================================
//! RuntimeCommandHandler ソケット制御/ライフサイクル系メソッド

use crate::net::l4::tcp::tcb::tcb_table;
use crate::net::l4::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::RuntimeCommand;
use crate::net::runtime::command_handler::{EventHandleResult, RuntimeCommandHandler};

impl RuntimeCommandHandler {
    pub(super) fn handle_lifecycle_event_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        event: RuntimeCommand,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpResolveRequest { target_ip },
            ) => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                let current_time = stack.current_time();
                if let Some(mac) = stack.arp.resolve(ip, current_time) {
                    crate::net::l2::arp::notify_arp_resolved(target_ip, *mac.as_bytes());
                } else {
                    stack.send_arp_request(ip);
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
                    crate::net::l3::ndp::notify_ndp_resolved(if_id, target_ip, ip.multicast_mac());
                    return EventHandleResult::Success;
                }

                let current_time = stack.current_time();
                let if_scope = if_id.map(crate::net::runtime::manager::NetIfId);

                match stack.resolve_ndp_for_send(if_scope, &ip, current_time, |_| {}) {
                    Some(Ok(mac)) => {
                        crate::net::l3::ndp::notify_ndp_resolved(if_id, target_ip, mac);
                    }
                    Some(Err((ns_if_id, our_ll, ns_msg))) => {
                        let sn_mcast = ip.solicited_node();
                        if let Some(ns_if_id) = ns_if_id {
                            stack.send_ipv6_icmpv6_raw_on(ns_if_id, &our_ll, &sn_mcast, ns_msg);
                        } else {
                            stack.send_ipv6_icmpv6_raw(&our_ll, &sn_mcast, ns_msg);
                        }
                    }
                    None => {}
                }
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpResolved { ip, mac },
            ) => {
                crate::net::l2::arp::notify_arp_resolved(ip, mac);
                EventHandleResult::Success
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpDial {
                    local,
                    remote,
                    scope,
                    result_slot,
                    waker,
                },
            ) => {
                let result =
                    self.make_tcp_connection_with_stack(runtime, local, remote, scope, stack);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::MulticastJoin {
                    group,
                    result_slot,
                    waker,
                },
            ) => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(group);
                let success = stack.join_multicast_group(ip).is_ok();
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(success);
                }
                waker.wake();
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::MulticastLeave {
                    group,
                    result_slot,
                    waker,
                },
            ) => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(group);
                let success = stack.leave_multicast_group(ip).is_ok();
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(success);
                }
                waker.wake();
                EventHandleResult::Success
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpBind {
                    local,
                    scope,
                    backlog,
                    result_slot,
                    waker,
                },
            ) => {
                let result = self.make_tcp_acceptor_with_stack(runtime, local, scope, backlog);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessTimeouts,
            ) => {
                // NetworkStack内部タイマーの基準時刻を同期する。
                // IGMP/ARP/NDP等が `NetworkStack::current_time()` を参照するため、
                // timeoutイベントごとに必ず更新しておく。
                let now = crate::task::current_tick();
                stack.update_time(now);

                stack.process_timeouts();

                // --- RFC Compliance: Process TCP periodic tasks ---
                // 1. TCB table maintenance (RTO, TimeWait, FinWait2, etc.)
                tcb_table().tick();
                // 2. Delayed ACK flushing (RFC 1122 Section 4.2.3.2)
                crate::net::l4::tcp::tcp_rx::flush_delayed_acks();

                // ICMP Echo待ちの期限切れエントリをクリーンアップ
                crate::net::api::icmp::cleanup_icmp_echo_waiters();
                // ARP非同期解決待ちのタイムアウト済みウェイターをクリーンアップ
                crate::net::l2::arp::cleanup_arp_waiters();
                // NDP非同期解決待ちのタイムアウト済みウェイターをクリーンアップ
                crate::net::l3::ndp::cleanup_ndp_waiters();
                EventHandleResult::Success
            }
            _ => EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition),
        }
    }
}
