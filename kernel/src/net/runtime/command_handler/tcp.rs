// ============================================================================
// kernel/src/net/runtime/command_handler/tcp.rs - ランタイム / コマンドハンドラ / TCP
// ============================================================================
//! RuntimeCommandHandler TCP系メソッド

use super::common::{
    endpoint_error_from_network, endpoint_ipv4_pair, endpoint_is_native_v6_pair,
    tcp_error_from_endpoint_error,
};
use super::*;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::socket::TcpSocketState;
use crate::net::l4::tcp::segment::{TcpSegmentBuilder, send_tcp_segment_payload_in};
use crate::net::l4::tcp::tcb::{TcpConnectionState, TcpControlBlockEntry, TcpControlBlockSnapshot};
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

        loop {
            let send_params = tcb_table
                .read(local, remote, |entry| TcpControlBlockSnapshot::from(entry))
                .and_then(|tcb| {
                    if tcb.state != TcpConnectionState::Established {
                        return None;
                    }

                    let inner_result = socket.with_inner_mut(|inner| {
                        let pending_len = inner.send_payload_bytes();
                        if pending_len == 0 || tcb.should_delay_send(pending_len) {
                            return None;
                        }

                        let effective_wnd = tcb.effective_send_window();
                        if effective_wnd == 0 {
                            return None;
                        }

                        let len =
                            (pending_len as u32).min(effective_wnd).min(tcb.mss as u32) as usize;
                        if len == 0 {
                            return None;
                        }

                        let send_payload = inner.take_send_payload_prefix(len)?;
                        Some((
                            send_payload,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            tcb.advertised_recv_window(),
                        ))
                    });
                    inner_result.flatten()
                });

            let Some((send_payload, seq, ack, advertised_wnd)) = send_params else {
                break;
            };

            let data_len = send_payload.total_len() as u32;
            let segment = TcpSegmentBuilder::new(local.port(), remote.port())
                .seq(seq)
                .ack(ack)
                .psh()
                .window(advertised_wnd)
                .payload_packet(send_payload)
                .build_checked_packet(local, remote);
            let segment = match segment {
                Ok(segment) => segment,
                Err(error) => return EventHandleResult::ProtocolError(error),
            };
            crate::net::l4::tcp::retransmit::retransmit_queue_push(
                runtime, local, remote, seq, data_len, segment,
            );

            if crate::net::l4::tcp::retransmit::retransmit_queue_transmit_ready(
                runtime, local, remote, seq,
            ) {
                let _ = socket.with_inner_mut(|inner| {
                    inner.send_waker.wake();
                });

                tcb_table.lookup_mut(local, remote, |tcb| {
                    tcb.on_send(data_len);
                    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(data_len);
                });
            } else {
                return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
            }
        }

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
            EventHandleResult::ProtocolError(err) => {
                self.unregister_socket_in(runtime, endpoint.socket_id());
                Err(tcp_error_from_endpoint_error(err))
            }
            _ => {
                self.unregister_socket_in(runtime, endpoint.socket_id());
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
                Err(tcp_error_from_endpoint_error(err))
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
            crate::net::l4::socket::allocate_tcp_ephemeral_port_in(runtime).unwrap_or(49152)
        } else {
            local.port()
        };
        let unresolved_local = local.with_port(local_port);

        let Some((scope, preferred_if, congestion_algo, nodelay, priority)) =
            socket.with_inner(|inner| {
                (
                    inner.scope,
                    inner.last_ingress_if_id,
                    inner.tcp().and_then(|t| t.congestion_algorithm),
                    inner.tcp().map_or(false, |t| t.nodelay),
                    inner.priority,
                )
            })
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
            match stack.resolve_ipv4_egress(
                scope,
                preferred_if,
                explicit_src,
                Ipv4Address::new(remote_v4),
            ) {
                Ok((resolved_if, _, src_ip)) => {
                    (EndpointAddr::new(src_ip.octets(), local_port), resolved_if)
                }
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
            match stack.resolve_ipv6_egress(scope, preferred_if, explicit_src, remote_v6) {
                Ok((resolved_if, _, src_ip)) => (
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
            let _ = inner.set_tcp_state(TcpSocketState::Connecting);
        });
        if configured.is_none() {
            return EventHandleResult::SocketNotFound(fd);
        }

        let tcb_table = tcp_table_in(runtime);
        let isn = tcb_table.generate_isn(local_addr, remote);
        let mut tcb = if let Some(algo) = congestion_algo {
            TcpControlBlockEntry::with_algorithm(fd, local_addr, remote, algo)
        } else {
            TcpControlBlockEntry::new(fd, local_addr, remote)
        };
        tcb.initialize_seq(isn);
        tcb.set_nodelay(nodelay);
        tcb.set_priority(priority);
        tcb.scope = scope;
        tcb.ingress_if_id = Some(resolved_if);
        tcb.state = TcpConnectionState::SynSent;
        let _ = tcb_table.insert(tcb);

        let syn_segment = TcpSegmentBuilder::new(local_port, remote.port())
            .seq(isn)
            .syn()
            .window(65535)
            .syn_options(
                1460,
                Some(7),
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

        if let Err(e) = self.send_tcp_segment(runtime, local_addr, remote, syn_segment) {
            log::info!("TCP: Failed to send SYN packet: {:?}", e);
            return EventHandleResult::ProtocolError(match e {
                EndpointError::InvalidArgument => EndpointError::InvalidArgument,
                EndpointError::NetworkUnreachable => EndpointError::NetworkUnreachable,
                _ => EndpointError::Internal,
            });
        }

        tcb_table.lookup_mut(local_addr, remote, |tcb| {
            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
        });

        log::info!("TCP: SYN sent {} -> {} (seq={})", local_addr, remote, isn);
        EventHandleResult::Success
    }

    pub(super) fn handle_connect_in(
        &self,
        runtime: NetRuntimeHandle,
        fd: SocketId,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> EventHandleResult {
        let Some(socket) = crate::net::l4::socket::lookup_socket_in(runtime, fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };
        let tcb_table = tcp_table_in(runtime);

        // ローカルポートが未割り当ての場合はエフェメラルポートを割り当て
        let local_port = if local.port() == 0 {
            crate::net::l4::socket::allocate_tcp_ephemeral_port_in(runtime).unwrap_or(49152)
        } else {
            local.port()
        };
        let local_addr = local.with_port(local_port);

        // ソケットのローカルアドレスを更新し、設定を取得
        let Some((scope, preferred_if, congestion_algo, nodelay, priority)) = socket
            .with_inner_mut(|inner| {
                inner.local_addr = Some(local_addr);
                inner.remote_addr = Some(remote);
                let _ = inner.set_tcp_state(TcpSocketState::Connecting);
                (
                    inner.scope,
                    inner.last_ingress_if_id,
                    inner.tcp().and_then(|t| t.congestion_algorithm),
                    inner.tcp().map_or(false, |t| t.nodelay),
                    inner.priority,
                )
            })
        else {
            return EventHandleResult::SocketNotFound(fd);
        };

        // TCB（TCP Control Block）を作成
        let isn = tcb_table.generate_isn(local_addr, remote);
        let mut tcb = if let Some(algo) = congestion_algo {
            TcpControlBlockEntry::with_algorithm(fd, local_addr, remote, algo)
        } else {
            TcpControlBlockEntry::new(fd, local_addr, remote)
        };
        tcb.initialize_seq(isn);
        tcb.set_nodelay(nodelay);
        tcb.set_priority(priority); // 設定を反映
        tcb.scope = scope;
        tcb.ingress_if_id = preferred_if;
        tcb.state = TcpConnectionState::SynSent;
        let _ = tcb_table.insert(tcb);

        // SYNパケット構築 (TCPオプション付き)
        // MSS=1460 (標準的なイーサネットMTU)
        // Window Scale=7 (最大8MBウィンドウ)
        let syn_segment = TcpSegmentBuilder::new(local_port, remote.port())
            .seq(isn)
            .syn()
            .window(65535)
            .syn_options(
                1460,
                Some(7),
                true,
                Some(crate::net::l4::tcp::tcp_rx::generate_tcp_timestamp_in(
                    runtime,
                )),
            ) // MSS + Window Scale + SACK Permitted + TS
            .build_checked_packet(local_addr, remote);

        let syn_segment = match syn_segment {
            Ok(segment) => segment,
            Err(e) => return EventHandleResult::ProtocolError(e),
        };

        // パケット送信（IPスタック経由）
        if let Err(e) = self.send_tcp_segment(runtime, local_addr, remote, syn_segment) {
            log::info!("TCP: Failed to send SYN packet: {:?}", e);
            return EventHandleResult::ProtocolError(match e {
                EndpointError::InvalidArgument => EndpointError::InvalidArgument,
                _ => EndpointError::Internal,
            });
        }

        // TCB更新: SYNは1シーケンス番号を消費する
        tcb_table.lookup_mut(local_addr, remote, |tcb| {
            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
        });

        log::info!("TCP: SYN sent {} -> {} (seq={})", local_addr, remote, isn);

        // 注: SYN-ACK受信後にWakerを起こす（受信処理側で行う）
        // ここではまだ接続は完了していない

        EventHandleResult::Success
    }

    /// TCPセグメント送信（IPスタック経由）
    fn send_tcp_segment(
        &self,
        runtime: NetRuntimeHandle,
        src: EndpointAddr,
        dst: EndpointAddr,
        segment: PacketPayload,
    ) -> SocketResult<()> {
        if endpoint_ipv4_pair(src, dst).is_none() && !endpoint_is_native_v6_pair(src, dst) {
            return Err(EndpointError::InvalidArgument);
        }
        // Delegate to the packet-backed module-level TCP sender.
        // This centralizes IP family handling and ARP/NDP queuing logic.
        if send_tcp_segment_payload_in(runtime, src, dst, segment) {
            Ok(())
        } else {
            Err(EndpointError::ResourceExhausted)
        }
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
        let mut tcb = TcpControlBlockEntry::new(
            fd,
            local,
            EndpointAddr::new([0, 0, 0, 0], 0), // リモートは未定
        );
        tcb.state = TcpConnectionState::Listen;
        // backlog値を保存（接続要求キューの最大サイズ）
        // 注: 実際の接続要求キューはTCBテーブル側で管理
        let _ = backlog; // 現在のTCB構造体にはbacklogフィールドなし
        let _ = tcp_table_in(runtime).insert(tcb);

        log::info!(
            "TCP: Listening on {} (fd={}, backlog={})",
            local,
            fd.raw(),
            backlog
        );

        EventHandleResult::Success
    }

    /// Closeイベント処理
    /// 接続を終了
    pub(super) fn handle_close_in(
        &self,
        runtime: NetRuntimeHandle,
        fd: SocketId,
    ) -> EventHandleResult {
        let Some(socket) = crate::net::l4::socket::lookup_socket_in(runtime, fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };
        let tcb_table = tcp_table_in(runtime);

        let Some((local, remote)) =
            socket.with_inner(|inner| (inner.local_addr, inner.remote_addr))
        else {
            return EventHandleResult::SocketNotFound(fd);
        };
        let local = match local {
            Some(addr) => addr,
            None => {
                log::info!("TCP: Close failed - no local address");
                return EventHandleResult::ProtocolError(EndpointError::Internal);
            }
        };
        let remote = match remote {
            Some(addr) => addr,
            None => {
                // リモートアドレスがない場合（Listenソケットなど）は即時クローズ
                tcb_table.remove_by_socket_id(fd);
                self.close_socket_now_in(runtime, fd);
                return EventHandleResult::Success;
            }
        };

        // TCBエントリの状態を取得
        let state = tcb_table
            .read(local, remote, |tcb| tcb.state)
            .unwrap_or(TcpConnectionState::Closed);

        match state {
            TcpConnectionState::Established => {
                // FINパケットを送信
                let seq = tcb_table
                    .lookup_mut(local, remote, |tcb| {
                        let seq = tcb.snd_nxt;
                        tcb.state = TcpConnectionState::FinWait1;
                        // TCB更新: FINは1シーケンス番号を消費する
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                        seq
                    })
                    .unwrap_or(0);

                let fin_segment = TcpSegmentBuilder::new(local.port(), remote.port())
                    .seq(seq)
                    .fin()
                    .ack(0) // ACKは最新の受信シーケンス番号
                    .window(65535)
                    .build_checked_packet(local, remote);

                let fin_segment = match fin_segment {
                    Ok(segment) => segment,
                    Err(e) => return EventHandleResult::ProtocolError(e),
                };

                if let Err(e) = self.send_tcp_segment(runtime, local, remote, fin_segment) {
                    log::info!("TCP: Failed to send FIN: {:?}", e);
                    return EventHandleResult::ProtocolError(match e {
                        EndpointError::InvalidArgument => EndpointError::InvalidArgument,
                        _ => EndpointError::Internal,
                    });
                }

                log::info!("TCP: FIN sent for fd={}", fd.raw());
            }
            TcpConnectionState::CloseWait => {
                // 相手からFINを受信済み、自分からFINを送信
                let seq = tcb_table
                    .lookup_mut(local, remote, |tcb| {
                        let seq = tcb.snd_nxt;
                        tcb.state = TcpConnectionState::LastAck;
                        // TCB更新: FINは1シーケンス番号を消費する
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                        seq
                    })
                    .unwrap_or(0);

                let fin_segment = TcpSegmentBuilder::new(local.port(), remote.port())
                    .seq(seq)
                    .fin()
                    .ack(0)
                    .window(65535)
                    .build_checked_packet(local, remote);

                let fin_segment = match fin_segment {
                    Ok(segment) => segment,
                    Err(e) => return EventHandleResult::ProtocolError(e),
                };

                if let Err(e) = self.send_tcp_segment(runtime, local, remote, fin_segment) {
                    log::info!("TCP: Failed to send FIN (LastAck): {:?}", e);
                }
            }
            TcpConnectionState::Listen | TcpConnectionState::SynSent => {
                // まだ接続が確立していない場合は即座にクローズ
                tcb_table.remove(local, remote);
                self.close_socket_now_in(runtime, fd);
            }
            _ => {
                // 他の状態では何もしない（既にクローズ処理中など）
            }
        }

        EventHandleResult::Success
    }
}
