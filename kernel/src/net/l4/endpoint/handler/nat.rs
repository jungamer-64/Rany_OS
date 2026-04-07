// ============================================================================
// kernel/src/net/l4/endpoint/handler/nat.rs
// ============================================================================
//! NetworkEventHandler NATイベント系メソッド

use crate::net::l4::endpoint::event::NetworkEvent;
use crate::net::l4::endpoint::handler::{EventHandleResult, NetworkEventHandler};
use crate::net::l4::endpoint::types::EndpointError;
use crate::net::payload::PacketPayloadView;

impl NetworkEventHandler {
    pub(super) fn handle_nat_event_with_stack(
        &self,
        event: NetworkEvent,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            NetworkEvent::NatIcmpTimeExceeded {
                src_ip,
                original_ip_header,
            } => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                stack.send_icmp_time_exceeded(
                    src,
                    crate::net::l3::icmp::TimeExceededCode::TtlExceeded,
                    &original_ip_header,
                );
                EventHandleResult::Success
            }
            NetworkEvent::NatIcmpDestUnreachable {
                src_ip,
                code,
                next_hop_mtu,
                original_packet,
            } => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let now = stack.current_time();
                stack.send_icmp_error(
                    src,
                    crate::net::l3::icmp::DestUnreachCode::from(code),
                    next_hop_mtu,
                    &original_packet,
                    now,
                );
                EventHandleResult::Success
            }
            NetworkEvent::NatForwardUdp {
                if_id,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                payload,
                ttl,
            } => {
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let payload = PacketPayloadView::new(&payload);
                stack.send_udp_raw_payload_scoped_with_src_ttl(
                    crate::net::types::InterfaceScope::Pinned(net_if),
                    src,
                    src_port,
                    dst,
                    dst_port,
                    &payload,
                    ttl,
                );
                EventHandleResult::Success
            }
            NetworkEvent::NatForwardTcp {
                src_ip,
                dst_ip,
                payload,
                ttl,
            } => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let payload = PacketPayloadView::new(&payload);
                stack.send_tcp_payload_with_ttl(src, dst, &payload, ttl);
                EventHandleResult::Success
            }
            _ => EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition),
        }
    }
}
