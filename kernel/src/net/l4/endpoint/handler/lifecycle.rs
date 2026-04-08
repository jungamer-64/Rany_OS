// ============================================================================
// kernel/src/net/l4/endpoint/handler/lifecycle.rs
// ============================================================================
//! NetworkEventHandler ソケット制御/ライフサイクル系メソッド

use crate::net::l4::endpoint::event::NetworkEvent;
use crate::net::l4::endpoint::handler::{EventHandleResult, NetworkEventHandler};
use crate::net::l4::endpoint::tcb::tcb_table;
use crate::net::l4::endpoint::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;

impl NetworkEventHandler {
    pub(super) fn handle_lifecycle_event_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        event: NetworkEvent,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            NetworkEvent::ArpResolveRequest { target_ip } => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                let current_time = stack.current_time();
                if let Some(mac) = stack.arp.resolve(ip, current_time) {
                    crate::net::l2::arp::notify_arp_resolved(target_ip, *mac.as_bytes());
                } else {
                    stack.send_arp_request(ip);
                }
                EventHandleResult::Success
            }
            NetworkEvent::NdpResolveRequest { if_id, target_ip } => {
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
                        let ns_msg = crate::net::payload::PacketPayloadView::new(&ns_msg);
                        if let Some(ns_if_id) = ns_if_id {
                            stack.send_ipv6_icmpv6_raw_on(ns_if_id, &our_ll, &sn_mcast, &ns_msg);
                        } else {
                            stack.send_ipv6_icmpv6_raw(&our_ll, &sn_mcast, &ns_msg);
                        }
                    }
                    None => {}
                }
                EventHandleResult::Success
            }
            NetworkEvent::ArpResolved { ip, mac } => {
                crate::net::l2::arp::notify_arp_resolved(ip, mac);
                EventHandleResult::Success
            }
            NetworkEvent::TcpConnectStream {
                local,
                remote,
                scope,
                result_slot,
                waker,
            } => {
                let result = self.make_tcp_stream_with_stack(runtime, local, remote, scope, stack);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::MulticastJoin {
                group,
                result_slot,
                waker,
            } => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(group);
                let success = stack.join_multicast_group(ip).is_ok();
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(success);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::MulticastLeave {
                group,
                result_slot,
                waker,
            } => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(group);
                let success = stack.leave_multicast_group(ip).is_ok();
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(success);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpBindListener {
                local,
                scope,
                backlog,
                result_slot,
                waker,
            } => {
                let result = self.make_tcp_listener_with_stack(runtime, local, scope, backlog);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::ApplyIpv6Address {
                addr,
                result_slot,
                waker,
            } => {
                let ipv6 = crate::net::l3::ipv6::Ipv6Address::new(addr);
                stack.enqueue_apply_ipv6_global_address(ipv6);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(true);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::ProcessTimeouts => {
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
                super::super::tcp_rx::flush_delayed_acks();

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
