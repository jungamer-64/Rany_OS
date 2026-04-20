// ============================================================================
// kernel/src/net/l4/endpoint/handler/raw.rs
// ============================================================================
//! RuntimeCommandHandler Raw送信系メソッド

use crate::net::l4::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::RuntimeCommand;
use crate::net::runtime::command_handler::{EventHandleResult, RuntimeCommandHandler};
use kernel_api::service::netdev::{NetTxCompletionPolicy, NetTxMeta};

impl RuntimeCommandHandler {
    pub(super) fn handle_raw_event_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        event: RuntimeCommand,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpSend {
                    src_port,
                    src_ip,
                    dst_ip,
                    dst_port,
                    payload,
                    ttl,
                    completion_id,
                    result_slot,
                    waker,
                },
            ) => {
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let mut payload = Some(payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack.with_pending_tx_meta(meta, |stack| match src_ip {
                        Some(ip) => stack.send_udp_raw_payload_scoped_with_src_ttl(
                            crate::net::types::InterfaceScope::Any,
                            crate::net::l3::ipv4::Ipv4Address::new(ip),
                            src_port,
                            dst,
                            dst_port,
                            payload.take().expect("raw UDP payload already moved"),
                            ttl,
                        ),
                        None => stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Any,
                            src_port,
                            dst,
                            dst_port,
                            payload.take().expect("raw UDP payload already moved"),
                            ttl,
                        ),
                    }),
                    None => match src_ip {
                        Some(ip) => stack.send_udp_raw_payload_scoped_with_src_ttl(
                            crate::net::types::InterfaceScope::Any,
                            crate::net::l3::ipv4::Ipv4Address::new(ip),
                            src_port,
                            dst,
                            dst_port,
                            payload.take().expect("raw UDP payload already moved"),
                            ttl,
                        ),
                        None => stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Any,
                            src_port,
                            dst,
                            dst_port,
                            payload.take().expect("raw UDP payload already moved"),
                            ttl,
                        ),
                    },
                };
                let result = if sent {
                    Ok(())
                } else {
                    if let Some(completion_id) = completion_id {
                        let _ = crate::net::runtime::device::complete_tx_request_in(
                            runtime,
                            completion_id,
                            Err("raw UDP send failed"),
                        );
                    }
                    Err(EndpointError::NetworkUnreachable)
                };
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result.clone());
                }
                waker.wake();
                match result {
                    Ok(()) => EventHandleResult::Success,
                    Err(err) => EventHandleResult::ProtocolError(err),
                }
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpSend {
                    src_ip,
                    dst_ip,
                    payload,
                    completion_id,
                    result_slot,
                    waker,
                },
            ) => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let mut payload = Some(payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack.with_pending_tx_meta(meta, |stack| {
                        stack.send_tcp_payload(
                            src,
                            dst,
                            payload.take().expect("raw TCP payload already moved"),
                        )
                    }),
                    None => stack.send_tcp_payload(
                        src,
                        dst,
                        payload.take().expect("raw TCP payload already moved"),
                    ),
                };
                let result = if sent {
                    Ok(())
                } else {
                    if let Some(completion_id) = completion_id {
                        let _ = crate::net::runtime::device::complete_tx_request_in(
                            runtime,
                            completion_id,
                            Err("raw TCP send failed"),
                        );
                    }
                    Err(EndpointError::ResourceExhausted)
                };
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result.clone());
                }
                waker.wake();
                match result {
                    Ok(()) => EventHandleResult::Success,
                    Err(err) => EventHandleResult::ProtocolError(err),
                }
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpV6Send {
                    src_port,
                    src_ip,
                    dst_ip,
                    dst_port,
                    payload,
                    ttl,
                    completion_id,
                    result_slot,
                    waker,
                },
            ) => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                let mut payload = Some(payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack
                        .with_pending_tx_meta(meta, |stack| {
                            stack.send_udp_v6_payload_scoped_with_ttl(
                                crate::net::types::InterfaceScope::Any,
                                src_port,
                                src,
                                dst,
                                dst_port,
                                payload.take().expect("raw UDPv6 payload already moved"),
                                ttl,
                            )
                        })
                        .is_ok(),
                    None => stack
                        .send_udp_v6_payload_scoped_with_ttl(
                            crate::net::types::InterfaceScope::Any,
                            src_port,
                            src,
                            dst,
                            dst_port,
                            payload.take().expect("raw UDPv6 payload already moved"),
                            ttl,
                        )
                        .is_ok(),
                };
                let result = if sent {
                    Ok(())
                } else {
                    if let Some(completion_id) = completion_id {
                        let _ = crate::net::runtime::device::complete_tx_request_in(
                            runtime,
                            completion_id,
                            Err("raw UDPv6 send failed"),
                        );
                    }
                    Err(EndpointError::ResourceExhausted)
                };
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result.clone());
                }
                waker.wake();
                match result {
                    Ok(()) => EventHandleResult::Success,
                    Err(err) => EventHandleResult::ProtocolError(err),
                }
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpV6Send {
                    src_ip,
                    dst_ip,
                    payload,
                    completion_id,
                    result_slot,
                    waker,
                },
            ) => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                let mut payload = Some(payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack
                        .with_pending_tx_meta(meta, |stack| {
                            stack.send_tcp_v6_payload(
                                src,
                                dst,
                                payload.take().expect("raw TCPv6 payload already moved"),
                            )
                        })
                        .is_ok(),
                    None => stack
                        .send_tcp_v6_payload(
                            src,
                            dst,
                            payload.take().expect("raw TCPv6 payload already moved"),
                        )
                        .is_ok(),
                };
                let result = if sent {
                    Ok(())
                } else {
                    if let Some(completion_id) = completion_id {
                        let _ = crate::net::runtime::device::complete_tx_request_in(
                            runtime,
                            completion_id,
                            Err("raw TCPv6 send failed"),
                        );
                    }
                    Err(EndpointError::ResourceExhausted)
                };
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result.clone());
                }
                waker.wake();
                match result {
                    Ok(()) => EventHandleResult::Success,
                    Err(err) => EventHandleResult::ProtocolError(err),
                }
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpSendOn {
                    if_id,
                    src_port,
                    src_ip,
                    dst_ip,
                    dst_port,
                    payload,
                    ttl,
                    completion_id,
                    result_slot,
                    waker,
                },
            ) => {
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                let mut payload = Some(payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack.with_pending_tx_meta(meta, |stack| match src_ip {
                        Some(src_ip) => stack.send_udp_raw_payload_scoped_with_src_ttl(
                            crate::net::types::InterfaceScope::Pinned(net_if),
                            crate::net::l3::ipv4::Ipv4Address::new(src_ip),
                            src_port,
                            dst,
                            dst_port,
                            payload
                                .take()
                                .expect("scoped raw UDP payload already moved"),
                            ttl,
                        ),
                        None => stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Pinned(net_if),
                            src_port,
                            dst,
                            dst_port,
                            payload
                                .take()
                                .expect("scoped raw UDP payload already moved"),
                            ttl,
                        ),
                    }),
                    None => match src_ip {
                        Some(src_ip) => stack.send_udp_raw_payload_scoped_with_src_ttl(
                            crate::net::types::InterfaceScope::Pinned(net_if),
                            crate::net::l3::ipv4::Ipv4Address::new(src_ip),
                            src_port,
                            dst,
                            dst_port,
                            payload
                                .take()
                                .expect("scoped raw UDP payload already moved"),
                            ttl,
                        ),
                        None => stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Pinned(net_if),
                            src_port,
                            dst,
                            dst_port,
                            payload
                                .take()
                                .expect("scoped raw UDP payload already moved"),
                            ttl,
                        ),
                    },
                };
                let result = if sent {
                    Ok(())
                } else {
                    if let Some(completion_id) = completion_id {
                        let _ = crate::net::runtime::device::complete_tx_request_in(
                            runtime,
                            completion_id,
                            Err("scoped raw UDP send failed"),
                        );
                    }
                    Err(EndpointError::NetworkUnreachable)
                };
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result.clone());
                }
                waker.wake();
                match result {
                    Ok(()) => EventHandleResult::Success,
                    Err(err) => EventHandleResult::ProtocolError(err),
                }
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpSendOn {
                    if_id,
                    src_ip,
                    dst_ip,
                    payload,
                    completion_id,
                    result_slot,
                    waker,
                },
            ) => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                let mut payload = Some(payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack.with_pending_tx_meta(meta, |stack| {
                        stack.send_tcp_payload_on(
                            net_if,
                            src,
                            dst,
                            payload
                                .take()
                                .expect("scoped raw TCP payload already moved"),
                        )
                    }),
                    None => stack.send_tcp_payload_on(
                        net_if,
                        src,
                        dst,
                        payload
                            .take()
                            .expect("scoped raw TCP payload already moved"),
                    ),
                };
                let result = if sent {
                    Ok(())
                } else {
                    if let Some(completion_id) = completion_id {
                        let _ = crate::net::runtime::device::complete_tx_request_in(
                            runtime,
                            completion_id,
                            Err("scoped raw TCP send failed"),
                        );
                    }
                    Err(EndpointError::NetworkUnreachable)
                };
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result.clone());
                }
                waker.wake();
                match result {
                    Ok(()) => EventHandleResult::Success,
                    Err(err) => EventHandleResult::ProtocolError(err),
                }
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpV6SendOn {
                    if_id,
                    src_port,
                    src_ip,
                    dst_ip,
                    dst_port,
                    payload,
                    ttl,
                    completion_id,
                    result_slot,
                    waker,
                },
            ) => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                let mut payload = Some(payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack
                        .with_pending_tx_meta(meta, |stack| {
                            stack.send_udp_v6_payload_scoped_with_ttl(
                                crate::net::types::InterfaceScope::Pinned(net_if),
                                src_port,
                                src,
                                dst,
                                dst_port,
                                payload
                                    .take()
                                    .expect("scoped raw UDPv6 payload already moved"),
                                ttl,
                            )
                        })
                        .is_ok(),
                    None => stack
                        .send_udp_v6_payload_scoped_with_ttl(
                            crate::net::types::InterfaceScope::Pinned(net_if),
                            src_port,
                            src,
                            dst,
                            dst_port,
                            payload
                                .take()
                                .expect("scoped raw UDPv6 payload already moved"),
                            ttl,
                        )
                        .is_ok(),
                };
                let result = if sent {
                    Ok(())
                } else {
                    if let Some(completion_id) = completion_id {
                        let _ = crate::net::runtime::device::complete_tx_request_in(
                            runtime,
                            completion_id,
                            Err("scoped raw UDPv6 send failed"),
                        );
                    }
                    Err(EndpointError::ResourceExhausted)
                };
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result.clone());
                }
                waker.wake();
                match result {
                    Ok(()) => EventHandleResult::Success,
                    Err(err) => EventHandleResult::ProtocolError(err),
                }
            }
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpV6SendOn {
                    if_id,
                    src_ip,
                    dst_ip,
                    payload,
                    completion_id,
                    result_slot,
                    waker,
                },
            ) => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                let mut payload = Some(payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack
                        .with_pending_tx_meta(meta, |stack| {
                            stack.send_tcp_v6_payload_on(
                                net_if,
                                src,
                                dst,
                                payload
                                    .take()
                                    .expect("scoped raw TCPv6 payload already moved"),
                            )
                        })
                        .is_ok(),
                    None => stack
                        .send_tcp_v6_payload_on(
                            net_if,
                            src,
                            dst,
                            payload
                                .take()
                                .expect("scoped raw TCPv6 payload already moved"),
                        )
                        .is_ok(),
                };
                let result = if sent {
                    Ok(())
                } else {
                    if let Some(completion_id) = completion_id {
                        let _ = crate::net::runtime::device::complete_tx_request_in(
                            runtime,
                            completion_id,
                            Err("scoped raw TCPv6 send failed"),
                        );
                    }
                    Err(EndpointError::NetworkUnreachable)
                };
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result.clone());
                }
                waker.wake();
                match result {
                    Ok(()) => EventHandleResult::Success,
                    Err(err) => EventHandleResult::ProtocolError(err),
                }
            }
            _ => EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition),
        }
    }
}
