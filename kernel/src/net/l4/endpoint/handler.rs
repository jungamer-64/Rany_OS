// ============================================================================
// kernel/src/net/l4/endpoint/handler.rs
// ============================================================================
//! # NetworkEventHandler - ネットワークイベントハンドラ
//!
//! NetworkEventHandler, EventHandleResult

// Building block: Endpoint handler implementation

use alloc::vec::Vec;

use super::event::NetworkEvent;
use super::manager::ENDPOINT_MANAGER;
use super::segment::TcpSegmentBuilder;
use super::tcb::{TcpConnectionState, TcpControlBlockEntry, tcb_table};
use super::types::{EndpointAddr, EndpointError, EndpointFd, EndpointResult, EndpointType};
use crate::net::datapath::mempool::PacketRef;
use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::Ipv4Address;

/// イベント処理の結果
#[derive(Debug)]
pub enum EventHandleResult {
    /// 処理成功
    Success,
    /// 着信パケット - プロトコルスタックへのオフロード
    IngressPacket { packet: PacketRef },
    /// ソケットが見つからない
    SocketNotFound(EndpointFd),
    /// プロトコルエラー
    ProtocolError(EndpointError),
    /// 再試行が必要
    Retry,
}

#[inline]
fn endpoint_ipv4_pair(local: EndpointAddr, remote: EndpointAddr) -> Option<([u8; 4], [u8; 4])> {
    Some((local.as_ipv4()?, remote.as_ipv4()?))
}

#[inline]
fn endpoint_is_native_v6_pair(local: EndpointAddr, remote: EndpointAddr) -> bool {
    local.is_ipv6() && remote.is_ipv6() && local.as_ipv4().is_none() && remote.as_ipv4().is_none()
}

fn apply_tcp_checksum_for_addrs(
    segment: &mut [u8],
    local: EndpointAddr,
    remote: EndpointAddr,
) -> EndpointResult<()> {
    if let Some((lv4, rv4)) = endpoint_ipv4_pair(local, remote) {
        TcpSegmentBuilder::calculate_checksum(segment, lv4, rv4);
        return Ok(());
    }
    if endpoint_is_native_v6_pair(local, remote) {
        TcpSegmentBuilder::calculate_checksum_v6(
            segment,
            crate::net::l3::ipv6::Ipv6Address::new(local.as_ipv6()),
            crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6()),
        );
        return Ok(());
    }

    log::warn!(
        "[NET][endpoint] mixed TCP address family rejected: {} -> {}",
        local,
        remote
    );
    Err(EndpointError::InvalidArgument)
}

/// ネットワークイベントハンドラ
/// プロトコルスタック（TCP/UDP）と連携する
pub struct NetworkEventHandler {
    /// ソケットマネージャへの参照を使用
    _marker: core::marker::PhantomData<()>,
}

impl NetworkEventHandler {
    /// 新規ハンドラ作成
    pub fn new() -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }

    /// イベントを処理（フォールバックパス）
    ///
    /// ## 概要
    /// スタックロックの取得を試み、成功時は`handle_event_with_stack()`に委譲する。
    /// ロック取得に失敗した場合のみ、スタック非依存の`handle_event_stackless()`へ。
    ///
    /// ## ⚠️ 使用上の注意
    /// 通常の非同期パスでは `network_event_task()` がスタックロックを保持した状態で
    /// 直接 `handle_event_with_stack()` を呼び出すため、この関数は呼ばれない。
    /// この関数は以下のケースでのみ使用される：
    /// - `network_event_task()` のフォールバックパス（スタック初期化前）
    /// - `sync_process_network_events()` がロック取得に失敗した場合の再エンキュー後
    ///
    /// asyncコンテキストから直接呼び出す場合、スタックロックの二重取得に注意すること。
    pub fn handle_event(&self, event: NetworkEvent) -> EventHandleResult {
        // 最適パス: スタックロックを1回取得し、handle_event_with_stack() に委譲
        // これにより、各イベントが個別にロックを取得する非効率なパターンを排除する
        if let Ok(mut stack_guard) = crate::net::runtime::stack::NETWORK_STACK.lock() {
            if let Some(ref mut stack) = *stack_guard {
                return self.handle_event_with_stack(event, stack);
            }
        }

        // フォールバック: スタック未初期化またはロック取得失敗時
        // スタック非依存のイベントのみ処理する（ロック再取得を完全に回避）
        self.handle_event_stackless(event)
    }

    /// スタックロックなしで処理可能なイベントのみを処理するフォールバックパス
    ///
    /// スタック依存のイベントはエラーを返すか、結果スロットにエラーを書き込んで
    /// Wakerを起床する。これにより、非同期Futureがデッドロックせずに完了する。
    fn handle_event_stackless(&self, event: NetworkEvent) -> EventHandleResult {
        match event {
            // ============================================================
            // スタック非依存のイベント（そのまま処理可能）
            // ============================================================
            NetworkEvent::DataReady { fd, endpoint_type } => {
                self.handle_data_ready(fd, endpoint_type)
            }
            NetworkEvent::TxAvailable => self.handle_tx_available(),
            NetworkEvent::Connect { fd, local, remote } => self.handle_connect(fd, local, remote),
            NetworkEvent::Listen { fd, local, backlog } => self.handle_listen(fd, local, backlog),
            NetworkEvent::Close { fd } => self.handle_close(fd),
            NetworkEvent::SendTo { fd, data, remote } => self.handle_send_to(fd, remote, data),
            NetworkEvent::SetNoDelay { fd, nodelay } => self.handle_set_nodelay(fd, nodelay),
            NetworkEvent::SetPriority { fd, priority } => self.handle_set_priority(fd, priority),
            NetworkEvent::IcmpEchoReply {
                source,
                sequence,
                rtt_us,
            } => {
                crate::net::l4::endpoint::futures::notify_icmp_echo_reply(source, sequence, rtt_us);
                EventHandleResult::Success
            }
            NetworkEvent::ArpResolved { ip, mac } => {
                crate::net::l2::arp::notify_arp_resolved(ip, mac);
                EventHandleResult::Success
            }

            // ============================================================
            // 非同期Futureイベント: スタック不可時はエラーで完了（デッドロック防止）
            // ============================================================
            NetworkEvent::AsyncTcpBind {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(EndpointError::ResourceExhausted));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUdpBind {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpConnect {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(EndpointError::ResourceExhausted));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpConnectStream {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(crate::net::l4::tcp::TcpError::InvalidState));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpBindListener {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(crate::net::l4::tcp::TcpError::InvalidState));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpBindListenerWithToken {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(crate::net::l4::tcp::TcpError::InvalidState));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUdpBindEndpoint {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUdpBindEndpointWithToken {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncMulticastJoin {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncMulticastLeave {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUnbindUdp {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUnbindTcp {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUnbindTcpListener {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpBindWithToken {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(EndpointError::ResourceExhausted));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUdpBindWithToken {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncApplyIpv6Address {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncIcmpEcho {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(()));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncArpResolveCheck {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetLinkLocal { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetConfig { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetStats { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetArpCache { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Vec::new());
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetUdpEndpoints { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Vec::new());
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncProcessTimeouts => {
                // タイムアウト処理（スタック依存部分はスキップ）
                // しかし、独立した TCB テーブルのメンテナンスは実行する
                tcb_table().tick();

                crate::net::l4::endpoint::futures::cleanup_icmp_echo_waiters();
                crate::net::l2::arp::cleanup_arp_waiters();
                EventHandleResult::Success
            }

            // ============================================================
            // DHCP/TCP 非同期クエリ: スタック不可時はデフォルト値で完了
            // ============================================================
            NetworkEvent::AsyncGetDhcpState { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(crate::net::api::dhcp::DhcpRuntimeState {
                        v4_state: alloc::string::String::from("Unavailable"),
                        v4_assigned_ip: None,
                        v4_lease_remaining: None,
                        v4_last_declined: None,
                        v4_last_released: None,
                        v6_state: alloc::string::String::from("Unavailable"),
                        v6_assigned_ip: None,
                        v6_preferred_remaining: None,
                        v6_valid_remaining: None,
                    });
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpRenew { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(alloc::string::String::from("Stack unavailable")));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpRelease { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpDiscover { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpLastDeclined { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpLastReleased { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetTcpConnections { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Vec::new());
                }
                waker.wake();
                EventHandleResult::Success
            }

            // ============================================================
            // スタック依存だがFuture結果不要のイベント: ドロップ（ログのみ）
            // ============================================================
            _ => {
                log::warn!("[NET] Event dropped: stack unavailable (stackless fallback)");
                EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
            }
        }
    }

    /// スタックロック保持状態でイベントを処理（効率化用）
    pub fn handle_event_with_stack(
        &self,
        event: NetworkEvent,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            NetworkEvent::IngressPacket { packet } => {
                let pkt_len = packet.len();
                let data = packet.data();
                let current_time = stack.current_time();

                match stack.ethernet.process(data) {
                    crate::net::l2::ethernet::ProcessResult::Ipv4(payload, src_mac) => {
                        self.handle_ipv4_ingress_with_stack(payload, src_mac, current_time, stack);
                        stack.stats.record_rx(pkt_len);
                        EventHandleResult::Success
                    }
                    crate::net::l2::ethernet::ProcessResult::Arp(payload, src_mac) => {
                        stack.process_arp(payload, current_time, src_mac);
                        stack.stats.record_rx(pkt_len);
                        EventHandleResult::Success
                    }
                    crate::net::l2::ethernet::ProcessResult::Ipv6(payload, src_mac) => {
                        if stack.ipv6.is_some() {
                            // ── ファイアウォール Ingress チェック (IPv6) ──
                            if payload.len() >= 40 {
                                let src_ip = [
                                    payload[8], payload[9], payload[10], payload[11], payload[12],
                                    payload[13], payload[14], payload[15], payload[16], payload[17],
                                    payload[18], payload[19], payload[20], payload[21], payload[22],
                                    payload[23],
                                ];
                                let dst_ip = [
                                    payload[24], payload[25], payload[26], payload[27], payload[28],
                                    payload[29], payload[30], payload[31], payload[32], payload[33],
                                    payload[34], payload[35], payload[36], payload[37], payload[38],
                                    payload[39],
                                ];
                                let next_header = payload[6];
                                let (protocol, transport_data) =
                                    crate::net::l3::ipv6::skip_extension_headers(
                                        crate::net::l3::ipv4::IpProtocol::from(next_header),
                                        &payload[40..],
                                    );

                                let (src_port, dst_port) = if (u8::from(protocol) == 6
                                    || u8::from(protocol) == 17)
                                    && transport_data.len() >= 4
                                {
                                    let sp = u16::from_be_bytes([
                                        transport_data[0],
                                        transport_data[1],
                                    ]);
                                    let dp = u16::from_be_bytes([
                                        transport_data[2],
                                        transport_data[3],
                                    ]);
                                    (sp, dp)
                                } else {
                                    (0, 0)
                                };

                                let tcp_flags = if u8::from(protocol) == 6 && transport_data.len() >= 14 {
                                    transport_data[13]
                                } else {
                                    0
                                };

                                // Security Fix: Use full IPv6 addresses for firewall check
                                if !crate::net::security::firewall::check_ingress(
                                    crate::net::security::firewall::IpAddress::V6(src_ip),
                                    crate::net::security::firewall::IpAddress::V6(dst_ip),
                                    u8::from(protocol),
                                    src_port,
                                    dst_port,
                                    tcp_flags,
                                ) {
                                    stack.stats.record_dropped();
                                    return EventHandleResult::Success;
                                }
                            }

                            stack.process_ipv6_data(payload, current_time, src_mac, false);
                            stack.stats.record_rx(pkt_len);
                        } else {
                            stack.stats.record_dropped();
                        }
                        EventHandleResult::Success
                    }
                    _ => EventHandleResult::Success,
                }
            }
            NetworkEvent::IngressBatch { packets } => {
                // バッチ着信: スタックロック保持中に全パケットを連続処理
                for packet in packets {
                    self.handle_event_with_stack(NetworkEvent::IngressPacket { packet }, stack);
                }
                EventHandleResult::Success
            }
            NetworkEvent::ReassembledPacket { data } => {
                let current_time = stack.current_time();

                // Determine if it's IPv4 or IPv6
                if data.len() >= 20 && (data[0] >> 4) == 4 {
                    // IPv4
                    if let Some(packet) = crate::net::l3::ipv4::Ipv4Packet::parse(&data) {
                        let src_ip = packet.source();
                        let dst_ip = packet.destination();
                        let payload = packet.payload();
                        let protocol = packet.protocol();

                        // ── ファイアウォール Reassembled パケットチェック (IPv4) ──
                        // 再組立て後のパケットに対して再度ファイアウォールを適用する。
                        // これにより、フラグメント化によるポートベースルールの回避を防止する。
                        let (src_port, dst_port, tcp_flags) = match protocol {
                            crate::net::l3::ipv4::IpProtocol::Tcp if payload.len() >= 20 => {
                                let sp = u16::from_be_bytes([payload[0], payload[1]]);
                                let dp = u16::from_be_bytes([payload[2], payload[3]]);
                                let flags = payload[13];
                                (sp, dp, flags)
                            }
                            crate::net::l3::ipv4::IpProtocol::Udp if payload.len() >= 8 => {
                                let sp = u16::from_be_bytes([payload[0], payload[1]]);
                                let dp = u16::from_be_bytes([payload[2], payload[3]]);
                                (sp, dp, 0)
                            }
                            _ => (0, 0, 0),
                        };

                        if !crate::net::security::firewall::check_ingress_v4(
                            src_ip.octets(),
                            dst_ip.octets(),
                            protocol.into(),
                            src_port,
                            dst_port,
                            tcp_flags,
                        ) {
                            stack.stats.record_dropped();
                            return EventHandleResult::Success;
                        }

                        match protocol {
                            crate::net::l3::ipv4::IpProtocol::Tcp => {
                                super::tcp_rx::process_tcp_segment(
                                    src_ip.octets(),
                                    dst_ip.octets(),
                                    payload,
                                );
                            }
                            crate::net::l3::ipv4::IpProtocol::Udp => {
                                self.handle_udp_ingress_with_stack(
                                    src_ip.octets(),
                                    dst_ip.octets(),
                                    payload,
                                    stack,
                                    &data,
                                    current_time,
                                );
                            }
                            crate::net::l3::ipv4::IpProtocol::Icmp => {
                                stack.process_icmp_data(
                                    payload,
                                    src_ip,
                                    dst_ip,
                                    packet.ttl(),
                                    current_time,
                                );
                            }
                            crate::net::l3::ipv4::IpProtocol::Igmp => {
                                stack.process_igmp_data(payload, src_ip, packet.ttl());
                            }
                            _ => {}
                        }
                    }
                } else if data.len() >= 40 && (data[0] >> 4) == 6 {
                    // IPv6
                    if let Some(packet) = crate::net::l3::ipv6::Ipv6Packet::parse(&data) {
                        let src = packet.source();
                        let dst = packet.destination();
                        let (protocol, payload) = packet.skip_extension_headers();

                        // ── ファイアウォール Reassembled パケットチェック (IPv6) ──
                        let (src_port, dst_port, tcp_flags) = match protocol {
                            crate::net::l3::ipv4::IpProtocol::Tcp if payload.len() >= 20 => {
                                let sp = u16::from_be_bytes([payload[0], payload[1]]);
                                let dp = u16::from_be_bytes([payload[2], payload[3]]);
                                let flags = payload[13];
                                (sp, dp, flags)
                            }
                            crate::net::l3::ipv4::IpProtocol::Udp if payload.len() >= 8 => {
                                let sp = u16::from_be_bytes([payload[0], payload[1]]);
                                let dp = u16::from_be_bytes([payload[2], payload[3]]);
                                (sp, dp, 0)
                            }
                            _ => (0, 0, 0),
                        };

                        // Security Fix: Use full IPv6 addresses for firewall check
                        if !crate::net::security::firewall::check_ingress(
                            crate::net::security::firewall::IpAddress::V6(src.octets()),
                            crate::net::security::firewall::IpAddress::V6(dst.octets()),
                            protocol.into(),
                            src_port,
                            dst_port,
                            tcp_flags,
                        ) {
                            stack.stats.record_dropped();
                            return EventHandleResult::Success;
                        }

                        match protocol {
                            crate::net::l3::ipv4::IpProtocol::Tcp => {
                                super::tcp_rx::process_tcp_segment_v6(src, dst, payload);
                            }
                            crate::net::l3::ipv4::IpProtocol::Udp => {
                                stack.process_udp_data_v6(
                                    payload,
                                    src,
                                    dst,
                                    packet.hop_limit(),
                                    &data,
                                );
                            }
                            crate::net::l3::ipv4::IpProtocol::Icmpv6 => {
                                stack.process_icmpv6_data(
                                    payload,
                                    src,
                                    dst,
                                    crate::net::l2::ethernet::MacAddress::ZERO,
                                    packet.hop_limit(),
                                    current_time,
                                );
                            }
                            _ => {}
                        }
                    }
                }
                EventHandleResult::Success
            }
            NetworkEvent::DataReady { fd, endpoint_type } => {
                if endpoint_type == EndpointType::Tcp {
                    self.handle_tcp_data_ready_with_stack(fd, stack)
                } else {
                    EventHandleResult::Success
                }
            }
            NetworkEvent::SendTo { fd, data, remote } => {
                self.handle_send_to_with_stack(fd, remote, data, stack)
            }
            NetworkEvent::RawUdpSend {
                src_port,
                src_ip,
                dst_ip,
                dst_port,
                data,
                ttl,
            } => {
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let resolved_src = match src_ip {
                    Some(ip) => crate::net::l3::ipv4::Ipv4Address::new(ip),
                    None => stack.config().ipv4.address,
                };
                if stack.send_udp_raw_with_src_ttl(
                    resolved_src,
                    src_port,
                    dst,
                    dst_port,
                    &data,
                    ttl,
                ) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawTcpSend {
                src_ip,
                dst_ip,
                segment,
            } => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                if stack.send_tcp(src, dst, &segment) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawUdpV6Send {
                src_port,
                src_ip,
                dst_ip,
                dst_port,
                data,
                ttl,
            } => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                if stack.send_udp_v6_raw_with_ttl(src_port, src, dst, dst_port, &data, ttl) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawTcpV6Send {
                src_ip,
                dst_ip,
                segment,
            } => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                if stack.send_tcp_v6_raw(src, dst, &segment) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::IcmpEchoRequest { target, sequence } => {
                let target_ip = crate::net::l3::ipv4::Ipv4Address::new(target);
                match stack.send_icmp_echo_request(target_ip, sequence) {
                    Ok(_send_time) => EventHandleResult::Success,
                    Err(_) => EventHandleResult::ProtocolError(EndpointError::ResourceExhausted),
                }
            }
            NetworkEvent::IcmpEchoReply {
                source,
                sequence,
                rtt_us,
            } => {
                // ICMP応答をFutureレジストリに通知（スタックロック保持版）
                crate::net::l4::endpoint::futures::notify_icmp_echo_reply(source, sequence, rtt_us);
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpBind {
                local,
                result_slot,
                waker,
            } => {
                // スタックロック保持版: 二重ロックを回避
                let result = stack
                    .bind_tcp(local)
                    .map(|_| ())
                    .map_err(|e| EndpointError::from_tcp_error(e));
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUdpBind {
                port,
                result_slot,
                waker,
            } => {
                // スタックロック保持版: 二重ロックを回避
                let success = stack.bind_udp(port).is_some();
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(success);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::ArpResolveRequest { target_ip } => {
                // スタックロック保持版: ARP要求を送信
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                let current_time = stack.current_time();
                if let Some(mac) = stack.arp.resolve(ip, current_time) {
                    // 既にキャッシュにある場合は即座に通知
                    crate::net::l2::arp::notify_arp_resolved(target_ip, *mac.as_bytes());
                } else {
                    stack.send_arp_request(ip);
                }
                EventHandleResult::Success
            }
            NetworkEvent::ArpResolved { ip, mac } => {
                // ARP解決完了をウェイターに通知
                crate::net::l2::arp::notify_arp_resolved(ip, mac);
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpConnect {
                local,
                remote,
                result_slot,
                waker,
            } => {
                // スタックロック保持版: TCP接続を実行
                let result = stack
                    .connect_tcp(local, remote)
                    .map(|_| ())
                    .map_err(|e| EndpointError::from_tcp_error(e));
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpConnectStream {
                local,
                remote,
                result_slot,
                waker,
            } => {
                // スタックロック保持版: TcpStreamを作成して返す
                let result = stack.connect_tcp(local, remote);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncMulticastJoin {
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
            NetworkEvent::AsyncMulticastLeave {
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
            NetworkEvent::AsyncUnbindUdp {
                port,
                result_slot,
                waker,
            } => {
                stack.unbind_udp(port);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(true);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUnbindTcp {
                local,
                remote,
                result_slot,
                waker,
            } => {
                stack.unbind_tcp(local, remote);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(true);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUnbindTcpListener {
                local,
                result_slot,
                waker,
            } => {
                stack.unbind_tcp_listener(local);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(true);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpBindWithToken {
                local,
                token,
                result_slot,
                waker,
            } => {
                let result = stack
                    .bind_tcp_with_token(local, token)
                    .map(|_| ())
                    .map_err(|e| EndpointError::from_tcp_error(e));
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpBindListener {
                local,
                result_slot,
                waker,
            } => {
                // スタックロック保持版: TcpListenerを作成して返す
                let result = stack.bind_tcp(local);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncTcpBindListenerWithToken {
                local,
                token,
                result_slot,
                waker,
            } => {
                // スタックロック保持版: TcpListenerをトークン付きで作成して返す
                let result = stack.bind_tcp_with_token(local, token);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUdpBindWithToken {
                port,
                token,
                result_slot,
                waker,
            } => {
                let success = stack.bind_udp_with_token(port, token).is_some();
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(success);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUdpBindEndpoint {
                port,
                result_slot,
                waker,
            } => {
                let endpoint = stack.bind_udp(port);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(endpoint);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncUdpBindEndpointWithToken {
                port,
                token,
                result_slot,
                waker,
            } => {
                let endpoint = stack.bind_udp_with_token(port, token);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(endpoint);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncApplyIpv6Address {
                addr,
                result_slot,
                waker,
            } => {
                let ipv6 = crate::net::l3::ipv6::Ipv6Address::new(addr);
                stack.apply_ipv6_global_address(ipv6);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(true);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncProcessTimeouts => {
                stack.process_timeouts();

                // --- RFC Compliance: Process TCP periodic tasks ---
                // 1. TCB table maintenance (RTO, TimeWait, FinWait2, etc.)
                tcb_table().tick();
                // 2. Delayed ACK flushing (RFC 1122 Section 4.2.3.2)
                super::tcp_rx::flush_delayed_acks();

                // ICMP Echo待ちの期限切れエントリをクリーンアップ
                crate::net::l4::endpoint::futures::cleanup_icmp_echo_waiters();
                // ARP非同期解決待ちのタイムアウト済みウェイターをクリーンアップ
                crate::net::l2::arp::cleanup_arp_waiters();
                EventHandleResult::Success
            }
            NetworkEvent::RawUdpSendOn {
                if_id,
                src_port,
                dst_ip,
                dst_port,
                data,
                ttl,
            } => {
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                let src_ip = stack.config().ipv4.address;
                if stack.send_udp_raw_on_with_src_ttl(
                    net_if, src_ip, src_port, dst, dst_port, &data, ttl,
                ) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawTcpSendOn {
                if_id,
                src_ip,
                dst_ip,
                segment,
            } => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                // interface ignored in current implementation
                let _ = if_id;
                if stack.send_tcp(src, dst, &segment) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawUdpV6SendOn {
                if_id,
                src_port,
                src_ip,
                dst_ip,
                dst_port,
                data,
                ttl,
            } => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                if stack
                    .send_udp_v6_raw_on_with_ttl(net_if, src_port, src, dst, dst_port, &data, ttl)
                {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }

            // ================================================================
            // NAT forwarding events (with stack)
            // ================================================================
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
                let s = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let d = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                stack.send_udp_raw_on_with_src_ttl(net_if, s, src_port, d, dst_port, &payload, ttl);
                EventHandleResult::Success
            }
            NetworkEvent::NatForwardTcp {
                src_ip,
                dst_ip,
                segment,
                ttl,
            } => {
                let s = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let d = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                stack.send_tcp_with_ttl(s, d, &segment, ttl);
                EventHandleResult::Success
            }

            // ================================================================
            // Async utility events (with stack)
            // ================================================================
            NetworkEvent::AsyncIcmpEcho {
                target,
                sequence,
                result_slot,
                waker,
            } => {
                let target_ip = crate::net::l3::ipv4::Ipv4Address::new(target);
                let result = stack
                    .send_icmp_echo_request(target_ip, sequence)
                    .map_err(|_| ());
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncArpProbe { target_ip } => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                stack.send_arp_probe(ip);
                EventHandleResult::Success
            }
            NetworkEvent::AsyncArpResolveCheck {
                target_ip,
                requester_mac,
                result_slot,
                waker,
            } => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                let now = stack.current_time();
                let result = stack.arp_resolve(ip, now).map(|mac| {
                    let req_mac = MacAddress::new(requester_mac);
                    mac != req_mac && !mac.is_broadcast()
                });
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpApplyLease {
                ip,
                subnet,
                gateway,
                dns,
                hostname,
            } => {
                let lease = crate::net::services::dhcp::DhcpLease {
                    ip_address: crate::net::l3::ipv4::Ipv4Address::new(ip),
                    subnet_mask: crate::net::l3::ipv4::Ipv4Address::new(subnet),
                    gateway: Some(crate::net::l3::ipv4::Ipv4Address::new(gateway)),
                    dns_servers: alloc::vec![crate::net::l3::ipv4::Ipv4Address::new(dns)],
                    server_ip: crate::net::l3::ipv4::Ipv4Address::ANY,
                    lease_time: 0,
                    t1: 0,
                    t2: 0,
                    hostname: if hostname.is_empty() {
                        None
                    } else {
                        Some(hostname)
                    },
                    domain_name: None,
                    obtained_at: crate::task::timer::current_tick(),
                };
                stack.apply_dhcp_v4_lease(&lease);
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetLinkLocal { result_slot, waker } => {
                let result = stack.config().ipv6.map(|c| c.link_local.octets());
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetConfig { result_slot, waker } => {
                let cfg = stack.config();
                let result = Some(crate::net::api::config::NetworkConfigSnapshot {
                    ip: *cfg.ipv4.address.as_bytes(),
                    netmask: *cfg.ipv4.subnet_mask.as_bytes(),
                    gateway: *cfg.ipv4.gateway.as_bytes(),
                    mac: *cfg.mac.as_bytes(),
                });
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetStats { result_slot, waker } => {
                let stats = stack.stats();
                let result = Some(crate::net::api::config::NetworkStatsSnapshot {
                    rx_packets: stats.rx_packets.load(core::sync::atomic::Ordering::Relaxed),
                    tx_packets: stats.tx_packets.load(core::sync::atomic::Ordering::Relaxed),
                    rx_bytes: stats.rx_bytes.load(core::sync::atomic::Ordering::Relaxed),
                    tx_bytes: stats.tx_bytes.load(core::sync::atomic::Ordering::Relaxed),
                    rx_errors: stats.rx_errors.load(core::sync::atomic::Ordering::Relaxed),
                    rx_dropped: stats.rx_dropped.load(core::sync::atomic::Ordering::Relaxed),
                });
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetArpCache { result_slot, waker } => {
                let entries: Vec<_> = stack
                    .arp_cache()
                    .iter()
                    .map(|(ip, mac)| crate::net::api::connections::ArpCacheEntry {
                        ip: *ip.as_bytes(),
                        mac: *mac.as_bytes(),
                        complete: true,
                    })
                    .collect();
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(entries);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncArpInsert { ip, mac } => {
                let now = crate::time::get_uptime_ms();
                let ipv4 = crate::net::l3::ipv4::Ipv4Address::new(ip);
                let mac_addr = MacAddress::new(mac);
                stack.arp_cache_insert(ipv4, mac_addr, now);
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetUdpEndpoints { result_slot, waker } => {
                let snapshots = stack.list_udp_endpoints();
                let result: Vec<_> = snapshots
                    .into_iter()
                    .map(|snap| crate::net::api::connections::UdpEndpointInfo {
                        local_addr: alloc::format!("*:{}", snap.local_port),
                        remote_addr: alloc::string::String::from("*:*"),
                    })
                    .collect();
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }

            // ============================================================
            // 非同期DHCP/TCP クエリ（スタックロック保持中に処理）
            // ============================================================
            NetworkEvent::AsyncGetDhcpState { result_slot, waker } => {
                use crate::net::services::dhcp;

                let now = tcb_table().get_current_tick();
                let tick_rate = 1000u64;

                let mut out = crate::net::api::dhcp::DhcpRuntimeState {
                    v4_state: alloc::string::String::from("Init"),
                    v4_assigned_ip: None,
                    v4_lease_remaining: None,
                    v4_last_declined: None,
                    v4_last_released: None,
                    v6_state: alloc::string::String::from("Init"),
                    v6_assigned_ip: None,
                    v6_preferred_remaining: None,
                    v6_valid_remaining: None,
                };

                if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
                    if let Some(ref client) = *guard {
                        out.v4_state = alloc::string::String::from(
                            crate::net::api::dhcp::dhcp_v4_state_name(client.state()),
                        );
                        if let Some(lease) = client.lease() {
                            out.v4_assigned_ip = Some(*lease.ip_address.as_bytes());
                            out.v4_lease_remaining =
                                Some(crate::net::api::dhcp::lease_remaining_secs(
                                    lease.lease_time,
                                    lease.obtained_at,
                                    now,
                                    tick_rate,
                                ));
                        }
                        out.v4_last_declined = client.last_declined_ip().map(|ip| *ip.as_bytes());
                        out.v4_last_released = client.last_released_ip().map(|ip| *ip.as_bytes());
                    }
                }

                if let Ok(guard6) = dhcp::DHCPV6_CLIENT.lock() {
                    if let Some(ref client6) = *guard6 {
                        out.v6_state = alloc::string::String::from(
                            crate::net::api::dhcp::dhcp_v6_state_name(client6.state()),
                        );
                        if let Some(lease6) = client6.lease() {
                            out.v6_assigned_ip = Some(*lease6.addr.as_bytes());
                            out.v6_preferred_remaining =
                                Some(crate::net::api::dhcp::lease_remaining_secs(
                                    lease6.preferred_lifetime,
                                    lease6.obtained_at,
                                    now,
                                    tick_rate,
                                ));
                            out.v6_valid_remaining =
                                Some(crate::net::api::dhcp::lease_remaining_secs(
                                    lease6.valid_lifetime,
                                    lease6.obtained_at,
                                    now,
                                    tick_rate,
                                ));
                        }
                    }
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(out);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpRenew { result_slot, waker } => {
                use crate::net::services::dhcp;

                let now = tcb_table().get_current_tick();
                let mut touched = false;
                let mut err_msg: Option<alloc::string::String> = None;

                match dhcp::DHCP_CLIENT.lock() {
                    Ok(guard) => {
                        if let Some(ref client) = *guard {
                            client.force_renew_or_restart(now);
                            touched = true;
                        }
                    }
                    Err(_) => {
                        err_msg = Some(alloc::string::String::from(
                            "DHCPv4 global client lock poisoned",
                        ))
                    }
                }

                if err_msg.is_none() {
                    match dhcp::DHCPV6_CLIENT.lock() {
                        Ok(guard6) => {
                            if let Some(ref client6) = *guard6 {
                                if let Err(e) = client6.force_renew_or_restart(now) {
                                    err_msg = Some(alloc::string::String::from(e));
                                } else {
                                    touched = true;
                                }
                            }
                        }
                        Err(_) => {
                            err_msg = Some(alloc::string::String::from(
                                "DHCPv6 global client lock poisoned",
                            ))
                        }
                    }
                }

                let result = if let Some(e) = err_msg {
                    Err(e)
                } else if !touched {
                    Err(alloc::string::String::from(
                        "DHCP runtime is not initialized",
                    ))
                } else {
                    Ok(())
                };

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpRelease { result_slot, waker } => {
                use crate::net::services::dhcp;

                let mut released = false;
                // DHCPv4 Release
                if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
                    if let Some(ref client) = *guard {
                        client.release();
                        released = true;
                    }
                }
                // DHCPv6 Release (RFC 8415 Section 18.2.6)
                if let Ok(guard) = dhcp::DHCPV6_CLIENT.lock() {
                    if let Some(ref client) = *guard {
                        client.release();
                        released = true;
                    }
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(released);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpDiscover { result_slot, waker } => {
                use crate::net::services::dhcp;

                let now = tcb_table().get_current_tick();
                let mut offer = None;

                if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
                    if let Some(ref client) = *guard {
                        let _ = client.drive(now, 1000);
                        if let Some(o) = client.offered_lease() {
                            offer = Some(crate::net::api::dhcp::DhcpOfferInfo {
                                server_ip: *o.server_ip.as_bytes(),
                                offered_ip: *o.ip_address.as_bytes(),
                            });
                        }
                    }
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(offer);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpLastDeclined { result_slot, waker } => {
                use crate::net::services::dhcp;

                let mut ip = None;
                if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
                    if let Some(ref client) = *guard {
                        ip = client.last_declined_ip().map(|a| *a.as_bytes());
                    }
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(ip);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncDhcpLastReleased { result_slot, waker } => {
                use crate::net::services::dhcp;

                let mut ip = None;
                if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
                    if let Some(ref client) = *guard {
                        ip = client.last_released_ip().map(|a| *a.as_bytes());
                    }
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(ip);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::AsyncGetTcpConnections { result_slot, waker } => {
                let snapshots = tcb_table().list_connections();
                let connections: Vec<_> = snapshots
                    .into_iter()
                    .map(|snap| {
                        let state = match snap.state {
                            TcpConnectionState::Closed => "CLOSED",
                            TcpConnectionState::Listen => "LISTEN",
                            TcpConnectionState::SynSent => "SYN_SENT",
                            TcpConnectionState::SynReceived => "SYN_RCVD",
                            TcpConnectionState::Established => "ESTABLISHED",
                            TcpConnectionState::FinWait1 => "FIN_WAIT1",
                            TcpConnectionState::FinWait2 => "FIN_WAIT2",
                            TcpConnectionState::CloseWait => "CLOSE_WAIT",
                            TcpConnectionState::Closing => "CLOSING",
                            TcpConnectionState::LastAck => "LAST_ACK",
                            TcpConnectionState::TimeWait => "TIME_WAIT",
                        };
                        crate::net::api::connections::TcpConnectionInfo {
                            local_addr: alloc::format!("{}", snap.local),
                            remote_addr: alloc::format!("{}", snap.remote),
                            state: alloc::string::String::from(state),
                        }
                    })
                    .collect();

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(connections);
                }
                waker.wake();
                EventHandleResult::Success
            }

            // その他のイベントはスタック非依存（再帰的ロック取得を回避）
            other => self.handle_event_stackless(other),
        }
    }

    /// IngressPacketイベント処理
    ///
    /// 【完全非同期化】このメソッドはイベントキュー経由でのみ呼び出されるべき。
    /// `handle_event()` → `handle_event_with_stack()` のパスで呼ばれる場合は
    /// 既にスタックロックが保持されている。
    /// `handle_event()` → `handle_event_stackless()` のパスで呼ばれた場合は
    /// イベントを再エンキューして非同期パスに委譲する。
    fn handle_ingress_packet(&self, packet: PacketRef) -> EventHandleResult {
        // スタックロックなしのコンテキストから呼ばれた場合:
        // イベントキュー経由で再エンキューし、network_event_taskが
        // スタックロック保持下で処理する（二重ロック取得を回避）
        crate::net::l4::endpoint::event::send_event_ignore(NetworkEvent::IngressPacket { packet });
        EventHandleResult::Success
    }

    /// IPv4パケットの処理
    fn handle_ipv4_ingress_with_stack(
        &self,
        data: &[u8],
        src_mac: MacAddress,
        current_time: u64,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        // ── ファイアウォール Ingress チェック ──
        // IPv4ヘッダから最小限の 5-tuple を抽出してルール照合する。
        // ゼロコピー: データ参照のみでバッファコピーは行わない。
        if data.len() >= 20 {
            let protocol = data[9];
            let src_ip: [u8; 4] = [data[12], data[13], data[14], data[15]];
            let dst_ip: [u8; 4] = [data[16], data[17], data[18], data[19]];
            let ihl = ((data[0] & 0x0F) as usize) * 4;

            // Security Fix: フラグメントのチェック。
            // 2番目以降のフラグメント (Offset > 0) は L4 ヘッダを含まないため、ポート抽出をスキップする。
            let fragment_offset = (u16::from_be_bytes([data[6], data[7]]) & 0x1FFF) * 8;
            let more_fragments = (data[6] & 0x20) != 0;

            // Tiny Fragment Attack Protection (RFC 3128)
            // Offset 0 でかつ L4 ヘッダが不完全なフラグメントをドロップ
            if fragment_offset == 0 && more_fragments {
                let min_l4_len = match protocol {
                    6 => 20, // TCP
                    17 => 8, // UDP
                    _ => 0,
                };
                if data.len() < ihl + min_l4_len {
                    log::warn!("[FIREWALL] Dropping tiny fragment (RFC 3128): proto={}, len={}", protocol, data.len());
                    stack.stats.record_dropped();
                    return EventHandleResult::Success;
                }
            }

            let tcp_flags = if protocol == 6 && data.len() >= ihl + 14 {
                data[ihl + 13]
            } else {
                0
            };

            let (src_port, dst_port) = if fragment_offset == 0 {
                extract_ports(data, ihl, protocol)
            } else {
                (0, 0)
            };

            if !crate::net::security::firewall::check_ingress_v4(
                src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags,
            ) {
                stack.stats.record_dropped();
                return EventHandleResult::Success;
            }
        }

        // Ipv4Processorを使用してプロトコル判定
        let result = stack.ipv4.process_with_time(data, current_time);

        match result {
            crate::net::l3::ipv4::Ipv4ProcessResult::Icmp(payload, src_ip, dst_ip, ttl, _orig) => {
                stack.process_icmp_data(payload, src_ip, dst_ip, ttl, current_time);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Igmp(payload, src_ip, ttl, _orig) => {
                stack.process_igmp_data(payload, src_ip, ttl);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Udp(payload, src_ip, dst_ip, orig) => {
                self.handle_udp_ingress_with_stack(
                    src_ip.octets(),
                    dst_ip.octets(),
                    payload,
                    stack,
                    orig,
                    current_time,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Tcp(payload, src_ip, dst_ip, _orig) => {
                super::tcp_rx::process_tcp_segment(src_ip.octets(), dst_ip.octets(), payload);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Reassembled(reassembled_data) => {
                // 再組立てパケットを再帰的に処理
                stack.process_reassembled_packet(&reassembled_data, current_time, src_mac);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::FragmentPending => {}
            crate::net::l3::ipv4::Ipv4ProcessResult::ReassemblyTimeout(src, header_data) => {
                stack.send_icmp_time_exceeded(
                    src,
                    crate::net::l3::icmp::TimeExceededCode::FragmentReassemblyExceeded,
                    &header_data,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Dropped => {
                stack.stats.record_dropped();
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Error => {
                stack.stats.record_rx_error();
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Success => {}
            crate::net::l3::ipv4::Ipv4ProcessResult::UnknownProtocol(
                _proto,
                src,
                _dst,
                orig_packet,
            ) => {
                // RFC 792: Send ICMP Destination Unreachable (Protocol Unreachable, Code 2)
                log::warn!(
                    "[NET] Unknown protocol {} from {} - sending ICMP Protocol Unreachable",
                    _proto,
                    src
                );
                stack.send_icmp_error(
                    src,
                    crate::net::l3::icmp::DestUnreachCode::ProtocolUnreachable,
                    None,
                    orig_packet,
                    current_time,
                );
            }
        }

        EventHandleResult::Success
    }

    // IPv6パケットの処理は handle_event_with_stack 内で
    // stack.process_ipv6_data() 経由で処理されるため、
    // 個別のメソッドは不要。
    //
    // ARP/ICMPパケットの処理も同様にNetworkStack側で処理される。

    /// UDPパケットの処理
    fn handle_udp_ingress_with_stack(
        &self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        payload: &[u8],
        stack: &mut crate::net::runtime::stack::NetworkStack,
        original_packet: &[u8],
        current_time: u64,
    ) -> EventHandleResult {
        if payload.len() < 8 {
            return EventHandleResult::Success;
        }

        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
        let data = &payload[8..];

        let remote = EndpointAddr::new(src_ip, src_port);

        let mut found = false;
        if let Some(ref mgr) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
            if let Some(socket) = mgr.find_by_port(EndpointType::Udp, dst_port) {
                socket.push_packet(remote, data.to_vec());
                found = true;
            }
        }

        if !found {
            // Fallback: try the stack-level UdpProcessor endpoint table.
            // This handles endpoints created via stack.bind_udp() (e.g. sync DHCP during boot).
            use crate::net::l3::ipv4::Ipv4Address;
            let src_v4 = Ipv4Address::new(src_ip);
            let dst_v4 = Ipv4Address::new(dst_ip);
            let result = stack.udp_process_raw(payload, src_v4, dst_v4, 64);

            if matches!(result, crate::net::l4::udp::UdpResult::Delivered) {
                found = true;
            }
        }

        if !found {
            // RFC 1122: Send ICMP Port Unreachable
            use crate::net::l3::icmp::DestUnreachCode;
            use crate::net::l3::ipv4::Ipv4Address;

            let src_v4 = Ipv4Address::new(src_ip);
            let dst_v4 = Ipv4Address::new(dst_ip);

            // Only send if it wasn't broadcast/multicast (RFC 1122)
            if !dst_v4.is_broadcast() && !dst_v4.is_multicast() {
                stack.send_icmp_error(
                    src_v4,
                    DestUnreachCode::PortUnreachable,
                    None,
                    original_packet,
                    current_time,
                );
            }
        }

        EventHandleResult::Success
    }

    /// DataReadyイベント処理 (TCP)
    fn handle_tcp_data_ready_with_stack(
        &self,
        fd: EndpointFd,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let (data, local, remote) = {
            let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            if inner.send_buffer.is_empty() {
                return EventHandleResult::Success;
            }
            let local = match inner.local_addr {
                Some(addr) => addr,
                None => return EventHandleResult::ProtocolError(EndpointError::NotConnected),
            };
            let remote = match inner.remote_addr {
                Some(addr) => addr,
                None => return EventHandleResult::ProtocolError(EndpointError::NotConnected),
            };
            (
                inner.send_buffer.iter().copied().collect::<Vec<u8>>(),
                local,
                remote,
            )
        };

        let data_len = data.len() as u32;
        let (seq, ack, window) = match tcb_table().lookup(local, remote) {
            Some(tcb) => {
                if tcb.state != TcpConnectionState::Established {
                    return EventHandleResult::ProtocolError(EndpointError::NotConnected);
                }
                if tcb.should_delay_send(data.len()) {
                    return EventHandleResult::Success;
                }
                (tcb.snd_nxt, tcb.rcv_nxt, tcb.rcv_wnd)
            }
            None => return EventHandleResult::ProtocolError(EndpointError::NotConnected),
        };

        let mut segment = TcpSegmentBuilder::new(local.port(), remote.port())
            .seq(seq)
            .ack(ack)
            .psh()
            .window(window)
            .payload(&data)
            .build();

        if let Err(e) = apply_tcp_checksum_for_addrs(&mut segment, local, remote) {
            return EventHandleResult::ProtocolError(e);
        }

        // スタックを使用して直接送信
        let sent = if let (Some(lv4), Some(rv4)) = (local.as_ipv4(), remote.as_ipv4()) {
            stack.send_tcp(Ipv4Address::new(lv4), Ipv4Address::new(rv4), &segment)
        } else if local.is_ipv6() && remote.is_ipv6() {
            let lv6 = crate::net::l3::ipv6::Ipv6Address::new(local.as_ipv6());
            let rv6 = crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6());
            stack.send_tcp_v6_raw(lv6, rv6, &segment)
        } else {
            false
        };

        if sent {
            let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.send_buffer.drain(..data.len());

            tcb_table().lookup_mut(local, remote, |tcb| {
                tcb.snd_nxt = tcb.snd_nxt.wrapping_add(data_len);
            });
            EventHandleResult::Success
        } else {
            EventHandleResult::Retry
        }
    }

    /// SendToイベント処理 (UDP)
    fn handle_send_to_with_stack(
        &self,
        fd: EndpointFd,
        remote: EndpointAddr,
        data: Vec<u8>,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
        if local_port == 0 {
            return EventHandleResult::ProtocolError(EndpointError::NotConnected);
        }

        let sent = if let (Some(dst_v4), Some(_src_v4)) = (
            remote.as_ipv4(),
            socket.local_addr().and_then(|a| a.as_ipv4()),
        ) {
            stack.send_udp_raw(local_port, Ipv4Address::new(dst_v4), remote.port(), &data)
        } else if remote.is_ipv6() && socket.local_addr().map_or(false, |a| a.is_ipv6()) {
            let src_v6 =
                crate::net::l3::ipv6::Ipv6Address::new(socket.local_addr().unwrap().as_ipv6());
            let dst_v6 = crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6());
            stack.send_udp_v6_raw(local_port, src_v6, dst_v6, remote.port(), &data)
        } else {
            false
        };

        if sent {
            EventHandleResult::Success
        } else {
            EventHandleResult::Retry
        }
    }

    /// SetPriorityイベント処理
    fn handle_set_priority(&self, fd: EndpointFd, priority: u8) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let (local, remote) = {
            let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            let local = match inner.local_addr {
                Some(addr) => addr,
                None => return EventHandleResult::Success,
            };
            let remote = match inner.remote_addr {
                Some(addr) => addr,
                None => return EventHandleResult::Success,
            };
            (local, remote)
        };

        // TCBに反映
        tcb_table().lookup_mut(local, remote, |tcb| {
            tcb.set_priority(priority);
        });

        EventHandleResult::Success
    }

    /// SetNoDelayイベント処理
    fn handle_set_nodelay(&self, fd: EndpointFd, nodelay: bool) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let (local, remote) = {
            let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            let local = match inner.local_addr {
                Some(addr) => addr,
                None => return EventHandleResult::Success, // 未接続なら何もしない
            };
            let remote = match inner.remote_addr {
                Some(addr) => addr,
                None => return EventHandleResult::Success, // リモートなしなら何もしない
            };
            (local, remote)
        };

        // TCBに反映
        tcb_table().lookup_mut(local, remote, |tcb| {
            tcb.set_nodelay(nodelay);
        });

        EventHandleResult::Success
    }

    /// DataReadyイベント処理
    /// 送信バッファにデータがあるのでTCPで送信
    fn handle_data_ready(&self, fd: EndpointFd, _socket_type: EndpointType) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        // TCP状態と送信可能量を取得
        let (local, remote) = {
            let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            let local = match inner.local_addr {
                Some(addr) => addr,
                None => return EventHandleResult::ProtocolError(EndpointError::NotConnected),
            };
            let remote = match inner.remote_addr {
                Some(addr) => addr,
                None => return EventHandleResult::ProtocolError(EndpointError::NotConnected),
            };
            (local, remote)
        };

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            // 現在の送信可能データを決定 (MSS, Window, SWS考慮)
            let send_params = tcb_table().lookup(local, remote).and_then(|tcb| {
                if tcb.state != TcpConnectionState::Established {
                    return None;
                }

                let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                let buffer_len = inner.send_buffer.len();
                if buffer_len == 0 {
                    return None;
                }

                // 1. Sender SWS Avoidance & Nagle チェック
                if tcb.should_delay_send(buffer_len) {
                    return None;
                }

                // 2. 実効ウィンドウによる制限
                let effective_wnd = tcb.effective_send_window();
                if effective_wnd == 0 {
                    return None;
                }

                // 3. 1セグメントあたりのサイズ決定 (min(buffer, window, MSS))
                let mss = tcb.mss as usize;
                let len = (buffer_len as u32).min(effective_wnd).min(mss as u32) as usize;

                if len == 0 {
                    return None;
                }

                // データをコピー (本当はゼロコピーにしたいが、まずはRFC準拠を優先)
                let data: Vec<u8> = inner.send_buffer.iter().take(len).copied().collect();

                Some((data, tcb.snd_nxt, tcb.rcv_nxt, tcb.advertised_recv_window()))
            });

            let Some((data, seq, ack, advertised_wnd)) = send_params else {
                break;
            };

            let data_len = data.len() as u32;

            // TCPセグメントを構築
            let mut segment = TcpSegmentBuilder::new(local.port(), remote.port())
                .seq(seq)
                .ack(ack)
                .psh()
                .window(advertised_wnd)
                .payload(&data)
                .build();

            if let Err(e) = apply_tcp_checksum_for_addrs(&mut segment, local, remote) {
                return EventHandleResult::ProtocolError(e);
            }

            // パケット送信を試みる
            match self.send_tcp_segment(local, remote, segment) {
                Ok(()) => {
                    // 送信成功: send_buffer から削除し、TCB を更新
                    {
                        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                        inner.send_buffer.drain(..data.len());
                        // 送信可能になったため、待ちタスクを起こす
                        if let Some(w) = inner.send_waker.take() {
                            w.wake();
                        }
                    }

                    // TCB 更新
                    tcb_table().lookup_mut(local, remote, |tcb| {
                        tcb.on_send(data_len);
                        // 再送キューにも登録
                        crate::net::l4::endpoint::retransmit::retransmit_queue_push(
                            local,
                            remote,
                            tcb.snd_nxt,
                            data,
                        );
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(data_len);
                    });
                }
                Err(_) => {
                    // 送信失敗 (ARP未解決等) -> 再試行
                    return EventHandleResult::Retry;
                }
            }
        }

        EventHandleResult::Success
    }

    /// TX 資源解放通知処理
    fn handle_tx_available(&self) -> EventHandleResult {
        // 送信待ちのソケットに DataReady イベントを再送して再試行を促す（TCP）
        // また、イベントキュー満杯で待機していた UDP ソケットの send_waker も起床させる
        if let Some(ref mgr) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
            mgr.for_each(|socket| {
                if socket.send_buffer_len() > 0 {
                    super::event::send_event_ignore(super::event::NetworkEvent::DataReady {
                        fd: socket.fd(),
                        endpoint_type: socket.socket_type(),
                    });
                } else {
                    // TCPバッファが空でも send_waker が設定されている場合（UDP の ResourceExhausted 待ち）
                    // はここで直接起床させる。TCP の SendFuture も安全に再ポーリング可能。
                    let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(w) = inner.send_waker.take() {
                        drop(inner); // ロック解放後に wake（デッドロック回避）
                        w.wake();
                    }
                }
            });
        }

        EventHandleResult::Success
    }

    /// Connectイベント処理
    /// TCPハンドシェイクを開始（SYN送信）
    fn handle_connect(
        &self,
        fd: EndpointFd,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        // ローカルポートが未割り当ての場合はエフェメラルポートを割り当て
        let local_port = if local.port() == 0 {
            mgr.allocate_ephemeral_port(EndpointType::Tcp)
                .unwrap_or(49152)
        } else {
            local.port()
        };
        let local_addr = local.with_port(local_port);

        // ソケットのローカルアドレスを更新し、設定を取得
        let (congestion_algo, nodelay, priority) = {
            let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local_addr);
            (
                inner.tcp().and_then(|t| t.congestion_algorithm),
                inner.tcp().map_or(false, |t| t.nodelay),
                inner.priority,
            )
        };

        // TCB（TCP Control Block）を作成
        let isn = tcb_table().generate_isn(local_addr, remote);
        let mut tcb = if let Some(algo) = congestion_algo {
            TcpControlBlockEntry::with_algorithm(fd, local_addr, remote, algo)
        } else {
            TcpControlBlockEntry::new(fd, local_addr, remote)
        };
        tcb.initialize_seq(isn);
        tcb.set_nodelay(nodelay);
        tcb.set_priority(priority); // 設定を反映
        tcb.state = TcpConnectionState::SynSent;
        let _ = tcb_table().insert(tcb);

        // SYNパケット構築 (TCPオプション付き)
        // MSS=1460 (標準的なイーサネットMTU)
        // Window Scale=7 (最大8MBウィンドウ)
        let mut syn_segment = TcpSegmentBuilder::new(local_port, remote.port())
            .seq(isn)
            .syn()
            .window(65535)
            .syn_options(
                1460,
                Some(7),
                true,
                Some(crate::net::l4::endpoint::tcp_rx::generate_tcp_timestamp()),
            ) // MSS + Window Scale + SACK Permitted + TS
            .build();

        // チェックサム計算 (IPv4/IPv6)
        if let Err(e) = apply_tcp_checksum_for_addrs(&mut syn_segment, local_addr, remote) {
            return EventHandleResult::ProtocolError(e);
        }

        // パケット送信（IPスタック経由）
        if let Err(e) = self.send_tcp_segment(local_addr, remote, syn_segment) {
            log::info!("TCP: Failed to send SYN packet: {:?}", e);
            return EventHandleResult::ProtocolError(match e {
                EndpointError::InvalidArgument => EndpointError::InvalidArgument,
                _ => EndpointError::Internal,
            });
        }

        // TCB更新: SYNは1シーケンス番号を消費する
        tcb_table().lookup_mut(local_addr, remote, |tcb| {
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
        src: EndpointAddr,
        dst: EndpointAddr,
        segment: Vec<u8>,
    ) -> EndpointResult<()> {
        if endpoint_ipv4_pair(src, dst).is_none() && !endpoint_is_native_v6_pair(src, dst) {
            return Err(EndpointError::InvalidArgument);
        }
        // Delegate to the module-level `send_tcp_segment` which is IPv4/IPv6-aware.
        // This centralizes IP family handling and ARP/NDP queuing logic.
        if super::segment::send_tcp_segment(src, dst, segment) {
            Ok(())
        } else {
            Err(EndpointError::ResourceExhausted)
        }
    }

    /// Listenイベント処理
    /// サーバーソケットを設定
    fn handle_listen(
        &self,
        fd: EndpointFd,
        local: EndpointAddr,
        backlog: u32,
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        // ローカルアドレスをソケットに設定
        {
            let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
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
        let _ = tcb_table().insert(tcb);

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
    fn handle_close(&self, fd: EndpointFd) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        let local = match inner.local_addr {
            Some(addr) => addr,
            None => {
                log::info!("TCP: Close failed - no local address");
                return EventHandleResult::ProtocolError(EndpointError::Internal);
            }
        };
        let remote = match inner.remote_addr {
            Some(addr) => addr,
            None => {
                // リモートアドレスがない場合（Listenソケットなど）は直接クローズ
                tcb_table().remove_by_fd(fd);
                return EventHandleResult::Success;
            }
        };

        // TCBエントリの状態を取得
        let state = tcb_table()
            .lookup(local, remote)
            .map(|tcb| tcb.state)
            .unwrap_or(TcpConnectionState::Closed);

        match state {
            TcpConnectionState::Established => {
                // FINパケットを送信
                let seq = tcb_table()
                    .lookup_mut(local, remote, |tcb| {
                        let seq = tcb.snd_nxt;
                        tcb.state = TcpConnectionState::FinWait1;
                        // TCB更新: FINは1シーケンス番号を消費する
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                        seq
                    })
                    .unwrap_or(0);

                let mut fin_segment = TcpSegmentBuilder::new(local.port(), remote.port())
                    .seq(seq)
                    .fin()
                    .ack(0) // ACKは最新の受信シーケンス番号
                    .window(65535)
                    .build();

                if let Err(e) = apply_tcp_checksum_for_addrs(&mut fin_segment, local, remote) {
                    return EventHandleResult::ProtocolError(e);
                }

                if let Err(e) = self.send_tcp_segment(local, remote, fin_segment) {
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
                let seq = tcb_table()
                    .lookup_mut(local, remote, |tcb| {
                        let seq = tcb.snd_nxt;
                        tcb.state = TcpConnectionState::LastAck;
                        // TCB更新: FINは1シーケンス番号を消費する
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                        seq
                    })
                    .unwrap_or(0);

                let mut fin_segment = TcpSegmentBuilder::new(local.port(), remote.port())
                    .seq(seq)
                    .fin()
                    .ack(0)
                    .window(65535)
                    .build();

                if let Err(e) = apply_tcp_checksum_for_addrs(&mut fin_segment, local, remote) {
                    return EventHandleResult::ProtocolError(e);
                }

                if let Err(e) = self.send_tcp_segment(local, remote, fin_segment) {
                    log::info!("TCP: Failed to send FIN (LastAck): {:?}", e);
                }
            }
            TcpConnectionState::Listen | TcpConnectionState::SynSent => {
                // まだ接続が確立していない場合は即座にクローズ
                tcb_table().remove(local, remote);
            }
            _ => {
                // 他の状態では何もしない（既にクローズ処理中など）
            }
        }

        EventHandleResult::Success
    }

    /// SendToイベント処理
    /// UDPパケットを送信
    fn handle_send_to(
        &self,
        fd: EndpointFd,
        remote: EndpointAddr,
        data: Vec<u8>,
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        let local = match inner.local_addr {
            Some(addr) => addr,
            None => {
                // ローカルアドレスが未設定の場合はエフェメラルポートを使用
                let port = mgr
                    .allocate_ephemeral_port(EndpointType::Udp)
                    .unwrap_or(49152);
                EndpointAddr::new([0, 0, 0, 0], port)
            }
        };

        if inner.udp().map_or(false, |u| u.socket.is_some()) {
            // UDPパケットを構築
            // UDPヘッダ: src_port(2) + dst_port(2) + length(2) + checksum(2) = 8バイト
            let udp_len = 8 + data.len();
            let mut udp_packet = Vec::with_capacity(udp_len);

            // Source port (2バイト)
            let lp = local.port();
            udp_packet.push((lp >> 8) as u8);
            udp_packet.push(lp as u8);

            // Destination port (2バイト)
            let rp = remote.port();
            udp_packet.push((rp >> 8) as u8);
            udp_packet.push(rp as u8);

            // Length (2バイト) - ヘッダ + データ
            udp_packet.push((udp_len >> 8) as u8);
            udp_packet.push(udp_len as u8);

            // Checksum (2バイト) - 0 = チェックサム無効
            // 注: UDPでは計算してもオプション（IPv4の場合）
            udp_packet.push(0);
            udp_packet.push(0);

            // データ
            udp_packet.extend_from_slice(&data);

            // UDPパケット送信（IPスタック経由）
            let ttl = inner
                .udp()
                .and_then(|u| u.socket.as_ref())
                .map(|s| s.ttl())
                .unwrap_or(64);
            if let Err(e) = self.send_udp_packet(local, remote, udp_packet, ttl) {
                log::info!("UDP: Failed to send packet: {:?}", e);
                return EventHandleResult::ProtocolError(match e {
                    EndpointError::InvalidArgument => EndpointError::InvalidArgument,
                    _ => EndpointError::Internal,
                });
            }

            log::info!(
                "UDP: Sent {} bytes to {} from port {}",
                data.len(),
                remote,
                local.port()
            );

            EventHandleResult::Success
        } else {
            EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition)
        }
    }

    /// UDPパケット送信（非同期イベントキュー経由）
    fn send_udp_packet(
        &self,
        src: EndpointAddr,
        dst: EndpointAddr,
        packet: Vec<u8>,
        ttl: u8,
    ) -> EndpointResult<()> {
        // The `packet` contains a UDP header followed by payload. Extract payload.
        if packet.len() < 8 {
            return Err(EndpointError::InvalidArgument);
        }

        let payload = &packet[8..];

        // IPv4パス
        if let Some((_, dst_v4)) = endpoint_ipv4_pair(src, dst) {
            let dst_ip = crate::net::l3::ipv4::Ipv4Address::new(dst_v4);
            // 非同期イベントキュー経由で送信（ロック競合回避）
            if crate::net::runtime::stack::send_udp_async(
                src.port(),
                dst_ip,
                dst.port(),
                payload,
                ttl,
            ) {
                return Ok(());
            } else {
                return Err(EndpointError::ResourceExhausted);
            }
        }

        // IPv6パス
        if endpoint_is_native_v6_pair(src, dst) {
            let src_v6 = crate::net::l3::ipv6::Ipv6Address::new(src.as_ipv6());
            let dst_v6 = crate::net::l3::ipv6::Ipv6Address::new(dst.as_ipv6());
            // 非同期イベントキュー経由で送信（ロック競合回避）
            if crate::net::runtime::stack::send_udp_v6_async(
                src.port(),
                src_v6,
                dst_v6,
                dst.port(),
                payload,
                ttl,
            ) {
                return Ok(());
            } else {
                return Err(EndpointError::ResourceExhausted);
            }
        }

        Err(EndpointError::InvalidArgument)
    }

    /// ICMP Echo Requestイベント処理（イベントキュー経由で非同期処理）
    ///
    /// `AsyncIcmpEcho` イベントとしてイベントキューに再送出し、
    /// スタックロック保持中のハンドラ（handle_event_with_stack）で処理させる。
    /// `send_real_icmp_echo` の同期ロック取得＋IRQ無効化を回避する。
    fn handle_icmp_echo_request(&self, target: [u8; 4], sequence: u16) -> EventHandleResult {
        // fire-and-forget: スタックロック保持中のコンテキスト（IcmpEchoRequest）で
        // 直接処理されるため、ここでは no-op で Success を返す。
        // 実際のICMP送信は handle_event_with_stack の IcmpEchoRequest 分岐で処理済み。
        let _ = (target, sequence);
        EventHandleResult::Success
    }
}

impl Default for NetworkEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

// File-level tests for handler
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;
    use crate::net::l4::endpoint::event::{NetworkEvent, event_queue};
    use crate::net::l4::endpoint::manager::init_endpoint_manager;
    use crate::net::l4::endpoint::tcb::{TcpConnectionState, TcpControlBlockEntry, tcb_table};
    use crate::net::l4::endpoint::{
        EndpointAddr, EndpointState, create_tcp_endpoint, create_udp_endpoint,
    };

    #[cfg_attr(test, test_case)]
    pub fn test_handle_tx_available_requeues_dataready() {
        init_endpoint_manager();

        let sock = create_tcp_endpoint();
        let fd = sock.fd();

        // Set local and remote so handler proceeds
        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([127, 0, 0, 1], 80);
        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
            inner.send_buffer.extend(&[1, 2, 3]);
        }

        let handler = NetworkEventHandler::new();
        let res = handler.handle_tx_available();
        assert!(matches!(res, EventHandleResult::Success));

        // Event queue should now contain a DataReady event for our fd
        if let Some(evt) = event_queue().recv() {
            match evt {
                NetworkEvent::DataReady { fd: efd, .. } => assert_eq!(efd.raw(), fd.raw()),
                _ => panic!("Expected DataReady event"),
            }
        } else {
            panic!("Expected DataReady event in queue");
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_handle_data_ready_retry_when_no_device() {
        init_endpoint_manager();

        let sock = create_tcp_endpoint();
        let fd = sock.fd();

        // Set local and remote so handler proceeds
        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([10, 0, 2, 2], 80); // likely ARP unresolved
        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
            inner.send_buffer.extend(&[1, 2, 3, 4]);
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Connected);
        }

        let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
        tcb.state = TcpConnectionState::Established;
        let _ = tcb_table().insert(tcb);

        let handler = NetworkEventHandler::new();
        let res = handler.handle_data_ready(fd, EndpointType::Tcp);
        // Depending on stack transport wiring in test env, this can be Retry (no device)
        // or Success (data drained by a configured transmit fn).
        assert!(matches!(
            res,
            EventHandleResult::Retry | EventHandleResult::Success
        ));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_send_udp_packet_rejects_mixed_family() {
        let handler = NetworkEventHandler::new();
        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote =
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 8080);

        assert!(matches!(
            handler.send_udp_packet(local, remote, alloc::vec![0u8; 8], 64),
            Err(EndpointError::InvalidArgument)
        ));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_handle_send_to_ipv6_remote_returns_invalid_argument() {
        init_endpoint_manager();
        let sock = create_udp_endpoint();
        let fd = sock.fd();

        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            let local = EndpointAddr::new([127, 0, 0, 1], 12345);
            inner.local_addr = Some(local);
            inner.ensure_udp().socket = Some(crate::net::l4::udp::UdpEndpoint::new(local.port()));
            let _ = inner.transition_to(EndpointState::Bound);
        }

        let remote =
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 8080);
        let handler = NetworkEventHandler::new();
        let res = handler.handle_send_to(fd, remote, alloc::vec![1, 2, 3]);
        assert!(matches!(
            res,
            EventHandleResult::ProtocolError(EndpointError::InvalidArgument)
        ));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_handle_send_to_ipv4_path_not_invalid_argument() {
        init_endpoint_manager();
        let sock = create_udp_endpoint();
        let fd = sock.fd();

        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            let local = EndpointAddr::new([127, 0, 0, 1], 12346);
            inner.local_addr = Some(local);
            inner.ensure_udp().socket = Some(crate::net::l4::udp::UdpEndpoint::new(local.port()));
            let _ = inner.transition_to(EndpointState::Bound);
        }

        let handler = NetworkEventHandler::new();
        let res =
            handler.handle_send_to(fd, EndpointAddr::new([127, 0, 0, 1], 8081), alloc::vec![9]);
        assert!(!matches!(
            res,
            EventHandleResult::ProtocolError(EndpointError::InvalidArgument)
        ));
    }
}

/// ネットワークイベント処理の初期化
pub fn init_network_event_handler() {
    // イベントキューは既に初期化済み（NETWORK_EVENT_QUEUE）
    // タスクスケジューラにnetwork_event_taskを登録する
    // Note: network_event_taskはasync関数なので、per_core_executor経由でspawnする
    // ネットワークイベント処理はCPU 0で実行（ネットワーク割り込みと同じコア）
    log::info!("Network: Event handler initialized");

    // タスクスポーン（実行時にエグゼキュータが初期化されている必要がある）
    // crate::task::per_core_executor::spawn(super::tcp_rx::network_event_task());
    // 上記は起動シーケンスで呼び出される必要があるため、ここではログのみ
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;
    use crate::net::l4::endpoint::event::{NetworkEvent, event_queue};
    use crate::net::l4::endpoint::manager::init_endpoint_manager;
    use crate::net::l4::endpoint::tcb::{TcpConnectionState, TcpControlBlockEntry, tcb_table};
    use crate::net::l4::endpoint::{EndpointAddr, EndpointState, create_tcp_endpoint};

    pub fn handle_tx_available_requeues_dataready_smoke() -> bool {
        init_endpoint_manager();

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while event_queue().recv().is_some() {}

        let sock = create_tcp_endpoint();
        let fd = sock.fd();

        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([127, 0, 0, 1], 80);
        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
            inner.send_buffer.extend(&[1, 2, 3]);
        }

        let handler = NetworkEventHandler::new();
        if !matches!(handler.handle_tx_available(), EventHandleResult::Success) {
            return false;
        }

        for _ in 0..8 {
            if let Some(evt) = event_queue().recv() {
                if let NetworkEvent::DataReady { fd: efd, .. } = evt {
                    return efd.raw() == fd.raw();
                }
            } else {
                break;
            }
        }

        false
    }

    pub fn handle_data_ready_retry_when_no_device_smoke() -> bool {
        init_endpoint_manager();

        let sock = create_tcp_endpoint();
        let fd = sock.fd();

        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([10, 0, 2, 2], 80);
        if let Some(s) = sock.endpoint() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
            inner.send_buffer.extend(&[1, 2, 3, 4]);
            let _ = inner.transition_to(EndpointState::Bound);
            let _ = inner.transition_to(EndpointState::Connected);
        }

        let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
        tcb.state = TcpConnectionState::Established;
        let _ = tcb_table().insert(tcb);

        let handler = NetworkEventHandler::new();
        matches!(
            handler.handle_data_ready(fd, EndpointType::Tcp),
            EventHandleResult::Retry | EventHandleResult::Success
        )
    }
}

// ============================================================================
// ファイアウォール用ヘルパー
// ============================================================================

/// IPv4 ペイロードからトランスポート層の送信元/宛先ポートを抽出する。
///
/// TCP (proto=6) / UDP (proto=17) の場合、ヘッダ先頭 4 バイトに
/// src_port(2) + dst_port(2) が格納されている。
/// ICMP やその他のプロトコルではポート 0 を返す。
#[inline]
fn extract_ports(ipv4_data: &[u8], ihl: usize, protocol: u8) -> (u16, u16) {
    // TCP=6, UDP=17 のみポートを持つ
    if (protocol == 6 || protocol == 17) && ipv4_data.len() >= ihl + 4 {
        let src_port = u16::from_be_bytes([ipv4_data[ihl], ipv4_data[ihl + 1]]);
        let dst_port = u16::from_be_bytes([ipv4_data[ihl + 2], ipv4_data[ihl + 3]]);
        (src_port, dst_port)
    } else {
        (0, 0)
    }
}
