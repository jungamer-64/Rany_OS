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
use crate::net::types::NetworkError;

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

fn send_bool_with_tx_completion(
    stack: &mut NetworkStack,
    completion_id: Option<u64>,
    send: impl FnOnce(&mut NetworkStack) -> bool,
) -> bool {
    match completion_id {
        Some(completion_id) => stack.with_pending_tx_completion(completion_id, send),
        None => send(stack),
    }
}

fn send_result_with_tx_completion(
    stack: &mut NetworkStack,
    completion_id: Option<u64>,
    send: impl FnOnce(&mut NetworkStack) -> Result<(), NetworkError>,
) -> bool {
    match completion_id {
        Some(completion_id) => stack
            .with_pending_tx_completion(completion_id, send)
            .is_ok(),
        None => send(stack).is_ok(),
    }
}

fn complete_failed_tx(runtime: NetRuntimeHandle, completion_id: Option<u64>, reason: &'static str) {
    if let Some(completion_id) = completion_id {
        let _ = crate::net::runtime::device::complete_tx_request_in(
            runtime,
            completion_id,
            Err(reason),
        );
    }
}

impl RuntimeCommandHandler {
    fn handle_raw_send_command(
        &self,
        runtime: NetRuntimeHandle,
        stack: &mut NetworkStack,
        command: RawSendCommand,
        reply: CommandReplyTicket<Result<(), EndpointError>>,
    ) -> EventHandleResult {
        match command {
            RawSendCommand::Ipv4 {
                scope,
                dst,
                transport,
                payload,
                completion_id,
            } => match transport {
                RawIpv4Transport::Udp { src, ports, ttl } => {
                    let dst = Ipv4Address::new(dst);
                    let Ok(if_id) = crate::net::runtime::manager::resolve_ipv4_interface_in(
                        runtime, scope, dst,
                    ) else {
                        complete_failed_tx(runtime, completion_id, "raw UDP route unavailable");
                        return finish_raw_send(reply, Err(EndpointError::NetworkUnreachable));
                    };
                    let mut payload = Some(payload);
                    let sent =
                        send_bool_with_tx_completion(stack, completion_id, |stack| match src {
                            RawIpv4Source::Auto => stack.send_udp_raw_payload_on_auto_ttl(
                                if_id,
                                dst,
                                ports,
                                payload.take().expect("raw UDP payload already moved"),
                                ttl,
                            ),
                            RawIpv4Source::Addr(src_ip) => stack
                                .send_udp_raw_payload_on_with_src_ttl(
                                    if_id,
                                    Ipv4Address::new(src_ip),
                                    dst,
                                    ports,
                                    payload.take().expect("raw UDP payload already moved"),
                                    ttl,
                                ),
                        });
                    let result = if sent {
                        Ok(())
                    } else {
                        complete_failed_tx(runtime, completion_id, "raw UDP send failed");
                        Err(EndpointError::NetworkUnreachable)
                    };
                    finish_raw_send(reply, result)
                }
                RawIpv4Transport::Tcp { src } => {
                    let src = Ipv4Address::new(src);
                    let dst = Ipv4Address::new(dst);
                    let Ok(if_id) = crate::net::runtime::manager::resolve_ipv4_interface_in(
                        runtime, scope, dst,
                    ) else {
                        complete_failed_tx(runtime, completion_id, "raw TCP route unavailable");
                        return finish_raw_send(reply, Err(EndpointError::NetworkUnreachable));
                    };
                    let Ok((_, resolved_src)) =
                        stack.resolve_ipv4_egress_on(if_id, (!src.is_any()).then_some(src))
                    else {
                        complete_failed_tx(runtime, completion_id, "raw TCP source unavailable");
                        return finish_raw_send(reply, Err(EndpointError::NetworkUnreachable));
                    };
                    let mut payload = Some(payload);
                    let sent = send_bool_with_tx_completion(stack, completion_id, |stack| {
                        stack.send_tcp_payload_on(
                            if_id,
                            resolved_src,
                            dst,
                            payload.take().expect("raw TCP payload already moved"),
                        )
                    });
                    let result = if sent {
                        Ok(())
                    } else {
                        complete_failed_tx(runtime, completion_id, "raw TCP send failed");
                        Err(EndpointError::NetworkUnreachable)
                    };
                    finish_raw_send(reply, result)
                }
            },
            RawSendCommand::Ipv6 {
                scope,
                dst,
                transport,
                payload,
                completion_id,
            } => match transport {
                RawIpv6Transport::Udp { src, ports, ttl } => {
                    let src = Ipv6Address::new(src);
                    let dst = Ipv6Address::new(dst);
                    let Ok(if_id) = crate::net::runtime::manager::resolve_ipv6_interface_in(
                        runtime, scope, dst,
                    ) else {
                        complete_failed_tx(runtime, completion_id, "raw UDPv6 route unavailable");
                        return finish_raw_send(reply, Err(EndpointError::NetworkUnreachable));
                    };
                    let mut payload = Some(payload);
                    let sent = send_result_with_tx_completion(stack, completion_id, |stack| {
                        stack.send_udp_v6_payload_on_with_ttl(
                            if_id,
                            src,
                            dst,
                            ports,
                            payload.take().expect("raw UDPv6 payload already moved"),
                            ttl,
                        )
                    });
                    let result = if sent {
                        Ok(())
                    } else {
                        complete_failed_tx(runtime, completion_id, "raw UDPv6 send failed");
                        Err(EndpointError::ResourceExhausted)
                    };
                    finish_raw_send(reply, result)
                }
                RawIpv6Transport::Tcp { src } => {
                    let src = Ipv6Address::new(src);
                    let dst = Ipv6Address::new(dst);
                    let Ok(if_id) = crate::net::runtime::manager::resolve_ipv6_interface_in(
                        runtime, scope, dst,
                    ) else {
                        complete_failed_tx(runtime, completion_id, "raw TCPv6 route unavailable");
                        return finish_raw_send(reply, Err(EndpointError::NetworkUnreachable));
                    };
                    let Ok((_, resolved_src)) = stack.resolve_ipv6_egress_on(
                        if_id,
                        (!src.is_unspecified()).then_some(src),
                        dst,
                    ) else {
                        complete_failed_tx(runtime, completion_id, "raw TCPv6 source unavailable");
                        return finish_raw_send(reply, Err(EndpointError::NetworkUnreachable));
                    };
                    let mut payload = Some(payload);
                    let sent = send_result_with_tx_completion(stack, completion_id, |stack| {
                        stack.send_tcp_v6_payload_on(
                            if_id,
                            resolved_src,
                            dst,
                            payload.take().expect("raw TCPv6 payload already moved"),
                        )
                    });
                    let result = if sent {
                        Ok(())
                    } else {
                        complete_failed_tx(runtime, completion_id, "raw TCPv6 send failed");
                        Err(EndpointError::NetworkUnreachable)
                    };
                    finish_raw_send(reply, result)
                }
            },
        }
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
