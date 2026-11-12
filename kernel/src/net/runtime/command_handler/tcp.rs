// ============================================================================
// kernel/src/net/runtime/command_handler/tcp.rs - ランタイム / コマンドハンドラ / TCP
// ============================================================================
//! RuntimeCommandHandler TCP系メソッド

use super::common::{endpoint_error_from_network, endpoint_ipv4_pair, endpoint_is_native_v6_pair};
use super::*;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::socket::TcpSocketState;
use crate::net::l4::tcp::segment::{TcpSegmentBuilder, send_tcp_segment_payload_in};
use crate::net::l4::tcp::tcb::{TcpConnectionState, TcpControlBlock, TcpControlBlockSnapshot};
use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId, SocketResult};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::transport::tcp_table_in;
use kernel_api::resource::net::PacketPayload;

impl RuntimeCommandHandler {
    pub(super) fn handle_tcp_data_ready_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        fd: SocketId,
        _stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        self.handle_data_ready_in(runtime, fd)
    }

    pub(super) fn handle_data_ready_in(
        &self,
        runtime: NetRuntimeHandle,
        fd: SocketId,
    ) -> EventHandleResult {
        let Some(socket) = crate::net::l4::socket::lookup_socket_in(runtime, fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };
        let tcb_table = tcp_table_in(runtime);

        let (local, remote) = match socket.with_inner(|inner| {
            let Some(local) = inner.local_addr else {
                return Err(EndpointError::NotConnected);
            };
            let Some(remote) = inner.remote_addr else {
                return Err(EndpointError::NotConnected);
            };
            Ok((local, remote))
        }) {
            Some(Ok(pair)) => pair,
            Some(Err(err)) => return EventHandleResult::ProtocolError(err),
            None => return EventHandleResult::SocketNotFound(fd),
        };

        // A concurrent writer may append while this command owns the stack
        // guard. Only the bytes observed at entry belong to this batch.
        let mut remaining = socket
            .with_inner(|inner| inner.send_payload_bytes())
            .unwrap_or(0);
        // LOOP_PROOF: mode=bounded; reason=Each nonempty segment consumes remaining bytes from the entry snapshot, while a closed window or failed submission ends the batch.;
        while remaining != 0 {
            let send_params = tcb_table
                .read_by_socket_id(fd, |entry| TcpControlBlockSnapshot::from(entry))
                .and_then(|tcb| {
                    // Data may follow our receive side being closed by the
                    // peer (CLOSE-WAIT) but never our own FIN.
                    if !matches!(
                        tcb.state,
                        TcpConnectionState::Established | TcpConnectionState::CloseWait
                    ) {
                        return None;
                    }

                    let inner_result = socket.with_inner_mut(|inner| {
                        let pending_len = inner.send_payload_bytes().min(remaining);
                        if pending_len == 0 || tcb.should_delay_send(pending_len) {
                            return None;
                        }

                        let effective_wnd = tcb.effective_send_window();
                        if effective_wnd == 0 {
                            return None;
                        }

                        let len = (pending_len as u32)
                            .min(effective_wnd)
                            .min(tcb.max_segment_payload)
                            as usize;
                        if len == 0 {
                            return None;
                        }

                        let send_payload = inner.take_send_segment_window(len)?;
                        Some((tcb, send_payload))
                    });
                    inner_result.flatten()
                });

            let Some((tcb, send_payload)) = send_params else {
                break;
            };

            let if_id = tcb.if_id;
            let seq = tcb.snd_nxt;
            let data_len = send_payload.total_len() as u32;
            remaining -= send_payload.total_len();
            let mut builder = TcpSegmentBuilder::new(local.port(), remote.port())
                .seq(seq)
                .ack(tcb.rcv_nxt)
                .ack_flag()
                .psh()
                .window(tcb.advertised_recv_window());
            if tcb.ts_enabled {
                builder = builder.nop().nop().timestamp(
                    crate::net::l4::tcp::tcp_rx::generate_tcp_timestamp_in(runtime),
                    tcb.ts_ecr,
                );
            }
            let segment = builder
                .payload_packet(send_payload)
                .build_checked_packet(local, remote);
            let segment = match segment {
                Ok(segment) => segment,
                Err(error) => return EventHandleResult::ProtocolError(error),
            };
            crate::net::l4::tcp::retransmit::retransmit_queue_push(
                runtime, if_id, local, remote, seq, data_len, segment,
            );

            if crate::net::l4::tcp::retransmit::retransmit_queue_transmit_ready(
                runtime, if_id, local, remote, seq,
            ) {
                let _ = socket.with_inner_mut(|inner| {
                    inner.send_waker.wake();
                });

                let _ = tcb_table.mark_payload_sent(if_id, local, remote, data_len);
            } else {
                return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
            }
        }

        self.send_fin_after_drain_in(runtime, &socket, local, remote)
    }

    /// Send our FIN once a close was requested and every queued byte has been
    /// handed to the retransmit queue. The FIN occupies the sequence number
    /// after the last data byte, so it is never sent while data is pending.
    fn send_fin_after_drain_in(
        &self,
        runtime: NetRuntimeHandle,
        socket: &crate::net::l4::socket::Socket,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> EventHandleResult {
        let close_ready = socket
            .with_inner(|inner| inner.is_tcp_closing_or_closed() && !inner.has_send_data())
            .unwrap_or(false);
        if !close_ready {
            return EventHandleResult::Success;
        }

        let tcb_table = tcp_table_in(runtime);
        let Some(if_id) =
            tcb_table.read_by_socket_id(socket.socket_id(), |tcb| tcb.route_interface())
        else {
            return EventHandleResult::Success;
        };
        let Some(fin) = tcb_table.begin_close(if_id, local, remote) else {
            // Not ESTABLISHED / CLOSE-WAIT: the FIN was already sent.
            return EventHandleResult::Success;
        };

        let mut builder = TcpSegmentBuilder::new(local.port(), remote.port())
            .seq(fin.seq)
            .ack(fin.ack)
            .ack_flag()
            .fin()
            .window(fin.window);
        if let Some(ts_ecr) = fin.timestamp_echo {
            builder = builder.nop().nop().timestamp(
                crate::net::l4::tcp::tcp_rx::generate_tcp_timestamp_in(runtime),
                ts_ecr,
            );
        }
        let fin_segment = match builder.build_checked_packet(local, remote) {
            Ok(segment) => segment,
            Err(error) => return EventHandleResult::ProtocolError(error),
        };

        // The FIN consumes one sequence number and is retransmitted like data
        // until it is acknowledged.
        crate::net::l4::tcp::retransmit::retransmit_queue_push(
            runtime,
            if_id,
            local,
            remote,
            fin.seq,
            1,
            fin_segment,
        );
        if !crate::net::l4::tcp::retransmit::retransmit_queue_transmit_ready(
            runtime, if_id, local, remote, fin.seq,
        ) {
            return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
        }
        log::info!("TCP: FIN sent {} -> {}", local, remote);
        EventHandleResult::Success
    }

    /// DataReadyイベント処理 (TCP)
    pub(super) fn make_tcp_connection_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        local: EndpointAddr,
        remote: EndpointAddr,
        scope: crate::net::types::InterfaceScope,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> Result<crate::net::l4::tcp::TcpConnection, crate::net::l4::tcp::TcpError> {
        let endpoint = crate::net::l4::socket::Socket::new_registered_tcp_in(
            runtime,
            TcpSocketState::Connecting,
        );

        let configured = endpoint.with_inner_mut(|inner| {
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
            inner.scope = scope;
        });
        if configured.is_none() {
            return Err(crate::net::l4::tcp::TcpError::InvalidState);
        }

        match self.handle_connect_with_stack(runtime, endpoint.socket_id(), local, remote, stack) {
            EventHandleResult::Success => {
                Ok(crate::net::l4::tcp::TcpConnection::from_socket(endpoint))
            }
            // A failed open may already hold a SYN-SENT TCB; aborting it
            // releases the TCB together with the socket.
            EventHandleResult::ProtocolError(err) => {
                crate::net::l4::tcp::termination::abort_connection_handle_in(
                    runtime,
                    endpoint.socket_id(),
                );
                Err(crate::net::l4::tcp::tcp_error_from_endpoint(err))
            }
            _ => {
                crate::net::l4::tcp::termination::abort_connection_handle_in(
                    runtime,
                    endpoint.socket_id(),
                );
                Err(crate::net::l4::tcp::TcpError::InvalidState)
            }
        }
    }

    pub(super) fn make_tcp_acceptor_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        local: EndpointAddr,
        scope: crate::net::types::InterfaceScope,
        backlog: u32,
    ) -> Result<crate::net::l4::tcp::TcpAcceptor, crate::net::l4::tcp::TcpError> {
        let endpoint = crate::net::l4::socket::Socket::new_registered_tcp_in(
            runtime,
            TcpSocketState::Listening,
        );

        let configured = endpoint.with_inner_mut(|inner| {
            inner.local_addr = Some(local);
            inner.scope = scope;
            let Some(tcp) = inner.tcp_mut() else {
                return Err(crate::net::l4::tcp::TcpError::InvalidState);
            };
            tcp.accept_backlog = backlog as usize;
            Ok(())
        });
        if configured
            .unwrap_or(Err(crate::net::l4::tcp::TcpError::InvalidState))
            .is_err()
        {
            return Err(crate::net::l4::tcp::TcpError::InvalidState);
        }

        match self.handle_listen_in(runtime, endpoint.socket_id(), local, backlog) {
            EventHandleResult::Success => {
                Ok(crate::net::l4::tcp::TcpAcceptor::from_socket(endpoint))
            }
            EventHandleResult::ProtocolError(err) => {
                self.unregister_socket_in(runtime, endpoint.socket_id());
                Err(crate::net::l4::tcp::tcp_error_from_endpoint(err))
            }
            _ => {
                self.unregister_socket_in(runtime, endpoint.socket_id());
                Err(crate::net::l4::tcp::TcpError::InvalidState)
            }
        }
    }

    /// Connectイベント処理
    /// TCPハンドシェイクを開始（SYN送信）
    pub(super) fn handle_connect_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        fd: SocketId,
        local: EndpointAddr,
        remote: EndpointAddr,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let Some(socket) = crate::net::l4::socket::lookup_socket_in(runtime, fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let local_port = if local.port() == 0 {
            let Some(port) = crate::net::l4::socket::allocate_tcp_ephemeral_port_in(runtime) else {
                return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
            };
            port
        } else {
            local.port()
        };
        let unresolved_local = local.with_port(local_port);

        let Some((scope, nodelay)) =
            socket.with_inner(|inner| (inner.scope, inner.tcp().map_or(false, |t| t.nodelay)))
        else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let (local_addr, resolved_if) = if let (Some(local_v4), Some(remote_v4)) =
            (unresolved_local.as_ipv4(), remote.as_ipv4())
        {
            let explicit_src = {
                let src = Ipv4Address::new(local_v4);
                if src.is_any() { None } else { Some(src) }
            };
            let remote_ip = Ipv4Address::new(remote_v4);
            let resolved_if = match crate::net::runtime::manager::resolve_ipv4_interface_in(
                runtime, scope, remote_ip,
            ) {
                Ok(if_id) => if_id,
                Err(error) => {
                    return EventHandleResult::ProtocolError(endpoint_error_from_network(error));
                }
            };
            match stack.resolve_ipv4_egress_on(resolved_if, explicit_src) {
                Ok((_, src_ip)) => (EndpointAddr::new(src_ip.octets(), local_port), resolved_if),
                Err(error) => {
                    return EventHandleResult::ProtocolError(endpoint_error_from_network(error));
                }
            }
        } else if unresolved_local.is_ipv6() && remote.is_ipv6() {
            let explicit_src = {
                let src = crate::net::l3::ipv6::Ipv6Address::new(unresolved_local.as_ipv6());
                if src.is_unspecified() {
                    None
                } else {
                    Some(src)
                }
            };
            let remote_v6 = crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6());
            let resolved_if = match crate::net::runtime::manager::resolve_ipv6_interface_in(
                runtime, scope, remote_v6,
            ) {
                Ok(if_id) => if_id,
                Err(error) => {
                    return EventHandleResult::ProtocolError(endpoint_error_from_network(error));
                }
            };
            match stack.resolve_ipv6_egress_on(resolved_if, explicit_src, remote_v6) {
                Ok((_, src_ip)) => (
                    EndpointAddr::new_v6(src_ip.octets(), local_port),
                    resolved_if,
                ),
                Err(error) => {
                    return EventHandleResult::ProtocolError(endpoint_error_from_network(error));
                }
            }
        } else {
            return EventHandleResult::ProtocolError(EndpointError::InvalidArgument);
        };

        let configured = socket.with_inner_mut(|inner| {
            inner.local_addr = Some(local_addr);
            inner.remote_addr = Some(remote);
            inner.scope = crate::net::types::InterfaceScope::Pinned(resolved_if);
            let _ = inner.set_tcp_state(TcpSocketState::Connecting);
        });
        if configured.is_none() {
            return EventHandleResult::SocketNotFound(fd);
        }

        let tcb_table = tcp_table_in(runtime);
        let isn = tcb_table.generate_isn(local_addr, remote);
        let tcb = TcpControlBlock::start_connect(fd, local_addr, remote, isn, nodelay, resolved_if);
        let _ = tcb_table.insert(tcb);

        let syn_segment = TcpSegmentBuilder::new(local_port, remote.port())
            .seq(isn)
            .syn()
            .window(65535)
            .syn_options(
                1460,
                Some(crate::net::l4::tcp::window_scale::DEFAULT_WINDOW_SCALE),
                true,
                Some(crate::net::l4::tcp::tcp_rx::generate_tcp_timestamp_in(
                    runtime,
                )),
            )
            .build_checked_packet(local_addr, remote);

        let syn_segment = match syn_segment {
            Ok(segment) => segment,
            Err(e) => return EventHandleResult::ProtocolError(e),
        };

        if let Err(e) = self.send_tcp_segment(runtime, resolved_if, local_addr, remote, syn_segment)
        {
            log::info!("TCP: Failed to send SYN packet: {:?}", e);
            return EventHandleResult::ProtocolError(match e {
                EndpointError::InvalidArgument => EndpointError::InvalidArgument,
                EndpointError::NetworkUnreachable => EndpointError::NetworkUnreachable,
                _ => EndpointError::Internal,
            });
        }

        let _ = tcb_table.mark_syn_sent(resolved_if, local_addr, remote);

        log::info!("TCP: SYN sent {} -> {} (seq={})", local_addr, remote, isn);
        EventHandleResult::Success
    }

    /// TCPセグメント送信（IPスタック経由）
    fn send_tcp_segment(
        &self,
        runtime: NetRuntimeHandle,
        if_id: crate::net::runtime::manager::NetIfId,
        src: EndpointAddr,
        dst: EndpointAddr,
        segment: PacketPayload,
    ) -> SocketResult<()> {
        if endpoint_ipv4_pair(src, dst).is_none() && !endpoint_is_native_v6_pair(src, dst) {
            return Err(EndpointError::InvalidArgument);
        }
        // Delegate to the packet-backed module-level TCP sender.
        // This centralizes IP family handling and ARP/NDP queuing logic.
        send_tcp_segment_payload_in(runtime, if_id, src, dst, segment, None)
            .map_err(|(cause, _returned)| cause)
    }

    /// Listenイベント処理
    /// サーバーソケットを設定
    pub(super) fn handle_listen_in(
        &self,
        runtime: NetRuntimeHandle,
        fd: SocketId,
        local: EndpointAddr,
        backlog: u32,
    ) -> EventHandleResult {
        let Some(socket) = crate::net::l4::socket::lookup_socket_in(runtime, fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        // ローカルアドレスをソケットに設定
        let listen_result = socket.with_inner_mut(|inner| {
            inner.local_addr = Some(local);
            let Some(tcp) = inner.tcp_mut() else {
                return Err(EndpointError::InvalidArgument);
            };
            tcp.accept_backlog = backlog as usize;
            if let Err(err) = inner.set_tcp_state(TcpSocketState::Listening) {
                return Err(err);
            }
            Ok(())
        });
        match listen_result {
            Some(Ok(())) => {}
            Some(Err(err)) => return EventHandleResult::ProtocolError(err),
            None => return EventHandleResult::SocketNotFound(fd),
        }

        // TCBテーブルにリスナーエントリを作成
        // backlog値を保存（接続要求キューの最大サイズ）
        // 注: 実際の接続要求キューはTCBテーブル側で管理
        let _ = backlog; // 現在のTCB構造体にはbacklogフィールドなし

        log::info!(
            "TCP: Listening on {} (fd={}, backlog={})",
            local,
            fd.raw(),
            backlog
        );

        EventHandleResult::Success
    }

    /// CloseSocket: finish a socket its owner released.
    ///
    /// A TCP connection released by a graceful close keeps its socket while
    /// its TCB lives: from ESTABLISHED / CLOSE-WAIT the queued data and then
    /// the FIN are sent, and once the FIN is out the path that ends the TCB
    /// unregisters the socket. A socket with no TCB (UDP, RAW, or a
    /// connection whose TCB already ended) is unregistered here.
    pub(super) fn handle_close_in(
        &self,
        runtime: NetRuntimeHandle,
        fd: SocketId,
    ) -> EventHandleResult {
        if crate::net::l4::socket::lookup_socket_in(runtime, fd).is_none() {
            return EventHandleResult::SocketNotFound(fd);
        }
        match tcp_table_in(runtime).read_by_socket_id(fd, |tcb| tcb.state()) {
            Some(TcpConnectionState::Established | TcpConnectionState::CloseWait) => {
                self.handle_data_ready_in(runtime, fd)
            }
            Some(_) => EventHandleResult::Success,
            None => {
                self.close_socket_now_in(runtime, fd);
                EventHandleResult::Success
            }
        }
    }
}
