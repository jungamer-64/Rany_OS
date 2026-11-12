// ============================================================================
// kernel/src/net/runtime/command_handler/raw.rs - ランタイム / コマンドハンドラ / Raw
// ============================================================================
//! RuntimeCommandHandler Raw送信系メソッド

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l3::ipv6::Ipv6Address;
use crate::net::l4::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{
    CommandReplyTicket, RawIpv4Source, RawIpv4Transport, RawIpv6Transport, RawSendCommand,
    RuntimeCommand, TransportCommand, complete_command,
};
use crate::net::runtime::command_handler::{EventHandleResult, RuntimeCommandHandler};
use crate::net::runtime::stack::NetworkStack;

fn finish_raw_send(
    reply: CommandReplyTicket<Result<(), EndpointError>>,
    result: Result<(), EndpointError>,
) -> EventHandleResult {
    let handled = match result {
        Ok(()) => EventHandleResult::Success,
        Err(err) => EventHandleResult::ProtocolError(err),
    };
    complete_command(reply, result);
    handled
}

impl RuntimeCommandHandler {
    fn handle_raw_send_command(
        &self,
        runtime: NetRuntimeHandle,
        stack: &mut NetworkStack,
        command: RawSendCommand,
        reply: CommandReplyTicket<Result<(), EndpointError>>,
    ) -> EventHandleResult {
        let result = match command {
            RawSendCommand::Ipv4 {
                scope,
                dst,
                transport,
            } => {
                let dst = Ipv4Address::new(dst);
                match crate::net::runtime::manager::resolve_ipv4_interface_in(runtime, scope, dst) {
                    Err(_) => Err(EndpointError::NetworkUnreachable),
                    Ok(if_id) => match transport {
                        RawIpv4Transport::Udp {
                            src,
                            ports,
                            ttl,
                            payload,
                        } => {
                            let sent = match src {
                                RawIpv4Source::Auto => stack.send_udp_raw_payload_on_auto_ttl(
                                    if_id, dst, ports, payload, ttl,
                                ),
                                RawIpv4Source::Addr(src_ip) => stack
                                    .send_udp_raw_payload_on_with_src_ttl(
                                        if_id,
                                        Ipv4Address::new(src_ip),
                                        dst,
                                        ports,
                                        payload,
                                        ttl,
                                    ),
                            };
                            if sent {
                                Ok(())
                            } else {
                                Err(EndpointError::NetworkUnreachable)
                            }
                        }
                        RawIpv4Transport::Tcp { src, segment } => {
                            let src = Ipv4Address::new(src);
                            match stack
                                .resolve_ipv4_egress_on(if_id, (!src.is_any()).then_some(src))
                            {
                                Err(_) => Err(EndpointError::NetworkUnreachable),
                                Ok((_, resolved_src)) => {
                                    if stack.send_tcp_payload_on(if_id, resolved_src, dst, segment)
                                    {
                                        Ok(())
                                    } else {
                                        Err(EndpointError::NetworkUnreachable)
                                    }
                                }
                            }
                        }
                    },
                }
            }
            RawSendCommand::Ipv6 {
                scope,
                dst,
                transport,
            } => {
                let dst = Ipv6Address::new(dst);
                match crate::net::runtime::manager::resolve_ipv6_interface_in(runtime, scope, dst) {
                    Err(_) => Err(EndpointError::NetworkUnreachable),
                    Ok(if_id) => match transport {
                        RawIpv6Transport::Udp {
                            src,
                            ports,
                            ttl,
                            payload,
                        } => stack
                            .send_udp_v6_payload_on_with_ttl(
                                if_id,
                                Ipv6Address::new(src),
                                dst,
                                ports,
                                payload,
                                ttl,
                            )
                            .map_err(|_| EndpointError::ResourceExhausted),
                        RawIpv6Transport::Tcp { src, segment } => {
                            let src = Ipv6Address::new(src);
                            match stack.resolve_ipv6_egress_on(
                                if_id,
                                (!src.is_unspecified()).then_some(src),
                                dst,
                            ) {
                                Err(_) => Err(EndpointError::NetworkUnreachable),
                                Ok((_, resolved_src)) => stack
                                    .send_tcp_v6_payload_on(if_id, resolved_src, dst, segment)
                                    .map_err(|_| EndpointError::NetworkUnreachable),
                            }
                        }
                    },
                }
            }
        };
        finish_raw_send(reply, result)
    }

    pub(super) fn handle_raw_event_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        event: RuntimeCommand,
        stack: &mut NetworkStack,
    ) -> EventHandleResult {
        match event {
            RuntimeCommand::Transport(TransportCommand::RawSend { command, reply }) => {
                self.handle_raw_send_command(runtime, stack, command, reply)
            }
            _ => EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition),
        }
    }
}
