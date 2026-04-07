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
use super::tcb::{TcpConnectionState, tcb_table};
use super::types::{EndpointAddr, EndpointError, EndpointFd, EndpointType};
use crate::net::datapath::mempool::PacketRef;
use crate::net::l2::ethernet::MacAddress;
use crate::net::payload::PacketPayloadView;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::{NetRuntimeHandle, default_runtime};
use kernel_api::resource::net::PacketPayload;
use kernel_api::service::netdev::{NetTxCompletionPolicy, NetTxMeta};

mod common;
mod control;
mod ingress;
mod tcp;
mod udp;

pub use self::common::EventHandleResult;

use self::common::{
    deliver_raw_payload_if_registered, finish_command, resolve_ingress_if_id_in,
    stackless_dhcp_state_unavailable, subslice_offset,
};

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
    /// - テスト/異常系でイベント処理を直接呼び出した場合
    ///
    /// asyncコンテキストから直接呼び出す場合、スタックロックの二重取得に注意すること。
    pub fn handle_event(&self, event: NetworkEvent) -> EventHandleResult {
        self.handle_event_in(default_runtime(), event)
    }

    pub fn handle_event_in(
        &self,
        runtime: NetRuntimeHandle,
        event: NetworkEvent,
    ) -> EventHandleResult {
        // 最適パス: スタックロックを1回取得し、handle_event_with_stack() に委譲
        // これにより、各イベントが個別にロックを取得する非効率なパターンを排除する
        if let Ok(mut stack_guard) = runtime.context().stack.lock() {
            if let Some(ref mut stack) = *stack_guard {
                return self.handle_event_with_stack_in(runtime, event, stack);
            }
        }

        // フォールバック: スタック未初期化またはロック取得失敗時
        // スタック非依存のイベントのみ処理する（ロック再取得を完全に回避）
        self.handle_event_stackless_in(runtime, event)
    }

    /// スタックロックなしで処理可能なイベントのみを処理するフォールバックパス
    ///
    /// スタック依存のイベントはエラーを返すか、結果スロットにエラーを書き込んで
    /// Wakerを起床する。これにより、非同期Futureがデッドロックせずに完了する。
    fn handle_event_stackless(&self, event: NetworkEvent) -> EventHandleResult {
        self.handle_event_stackless_in(default_runtime(), event)
    }

    fn handle_event_stackless_in(
        &self,
        runtime: NetRuntimeHandle,
        event: NetworkEvent,
    ) -> EventHandleResult {
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
            NetworkEvent::SendTo {
                fd,
                payload,
                remote,
            } => self.handle_send_to(fd, remote, payload),
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
            NetworkEvent::TcpBind {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(EndpointError::ResourceExhausted));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UdpBind {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpConnect {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(EndpointError::ResourceExhausted));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpConnectStream {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(crate::net::l4::tcp::TcpError::InvalidState));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpBindListener {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(crate::net::l4::tcp::TcpError::InvalidState));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpBindListenerWithToken {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(crate::net::l4::tcp::TcpError::InvalidState));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UdpBindEndpoint {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UdpBindEndpointWithToken {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::MulticastJoin {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::MulticastLeave {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UnbindUdp {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UnbindTcp {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UnbindTcpListener {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpBindWithToken {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(EndpointError::ResourceExhausted));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UdpBindWithToken {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::ApplyIpv6Address {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::IcmpEcho {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(()));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::ArpResolveCheck {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::GetLinkLocal { result_slot, waker } => {
                finish_command(result_slot, waker, None)
            }
            NetworkEvent::GetPrimaryInterfaceConfig { result_slot, waker } => {
                finish_command(result_slot, waker, None)
            }
            NetworkEvent::GetInterfaceConfig {
                result_slot, waker, ..
            } => finish_command(result_slot, waker, None),
            NetworkEvent::ListInterfaceConfigs { result_slot, waker } => {
                finish_command(result_slot, waker, Vec::new())
            }
            NetworkEvent::GetInterfaceStats {
                result_slot, waker, ..
            } => finish_command(result_slot, waker, None),
            NetworkEvent::ListInterfaceStats { result_slot, waker } => {
                finish_command(result_slot, waker, Vec::new())
            }
            NetworkEvent::ListInterfaces { result_slot, waker } => {
                finish_command(result_slot, waker, Vec::new())
            }
            NetworkEvent::GetNetworkSnapshot { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::obs::NetSnapshot {
                    rx_packets: 0,
                    tx_packets: 0,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    drops: 0,
                    errors: 0,
                    interfaces: Vec::new(),
                    recent_events: Vec::new(),
                },
            ),
            NetworkEvent::GetNetworkRecentEvents {
                result_slot, waker, ..
            } => finish_command(result_slot, waker, Vec::new()),
            NetworkEvent::FirewallEnable { result_slot, waker } => {
                finish_command(result_slot, waker, Err("Stack unavailable"))
            }
            NetworkEvent::FirewallDisable { result_slot, waker } => {
                finish_command(result_slot, waker, Err("Stack unavailable"))
            }
            NetworkEvent::FirewallStatus { result_slot, waker } => finish_command(
                result_slot,
                waker,
                alloc::string::String::from("Stack unavailable"),
            ),
            NetworkEvent::FirewallListRules { result_slot, waker } => finish_command(
                result_slot,
                waker,
                alloc::string::String::from("Stack unavailable"),
            ),
            NetworkEvent::FirewallStats { result_slot, waker } => finish_command(
                result_slot,
                waker,
                alloc::string::String::from("Stack unavailable"),
            ),
            NetworkEvent::FirewallAddRule {
                result_slot, waker, ..
            } => finish_command(
                result_slot,
                waker,
                Err(alloc::string::String::from("Stack unavailable")),
            ),
            NetworkEvent::FirewallRemoveRule {
                result_slot, waker, ..
            } => finish_command(
                result_slot,
                waker,
                Err(alloc::string::String::from("Stack unavailable")),
            ),
            NetworkEvent::FirewallClearRules { result_slot, waker } => finish_command(
                result_slot,
                waker,
                Err(alloc::string::String::from("Stack unavailable")),
            ),
            NetworkEvent::FirewallSetDefaultPolicy {
                result_slot, waker, ..
            } => finish_command(
                result_slot,
                waker,
                Err(alloc::string::String::from("Stack unavailable")),
            ),
            NetworkEvent::GetArpCache { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Vec::new());
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::GetUdpEndpoints { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Vec::new());
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::ProcessTimeouts => {
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
            NetworkEvent::GetDhcpState {
                result_slot, waker, ..
            } => finish_command(result_slot, waker, stackless_dhcp_state_unavailable()),
            NetworkEvent::ListDhcpStates { result_slot, waker } => {
                finish_command(result_slot, waker, Vec::new())
            }
            NetworkEvent::DhcpRenew { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(alloc::string::String::from("Stack unavailable")));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpRelease { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(false);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpDiscover { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpLastDeclined { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpLastReleased { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(None);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::GetTcpConnections { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Vec::new());
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::RawUdpSend {
                completion_id,
                result_slot,
                waker,
                ..
            }
            | NetworkEvent::RawTcpSend {
                completion_id,
                result_slot,
                waker,
                ..
            }
            | NetworkEvent::RawUdpV6Send {
                completion_id,
                result_slot,
                waker,
                ..
            }
            | NetworkEvent::RawTcpV6Send {
                completion_id,
                result_slot,
                waker,
                ..
            }
            | NetworkEvent::RawUdpSendOn {
                completion_id,
                result_slot,
                waker,
                ..
            }
            | NetworkEvent::RawTcpSendOn {
                completion_id,
                result_slot,
                waker,
                ..
            }
            | NetworkEvent::RawUdpV6SendOn {
                completion_id,
                result_slot,
                waker,
                ..
            }
            | NetworkEvent::RawTcpV6SendOn {
                completion_id,
                result_slot,
                waker,
                ..
            } => {
                if let Some(completion_id) = completion_id {
                    let _ = crate::net::runtime::device::complete_tx_request_in(
                        runtime,
                        completion_id,
                        Err("network stack unavailable"),
                    );
                }
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(EndpointError::ResourceExhausted));
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
        self.handle_event_with_stack_in(default_runtime(), event, stack)
    }

    pub fn handle_event_with_stack_in(
        &self,
        runtime: NetRuntimeHandle,
        event: NetworkEvent,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            NetworkEvent::IngressPacket { if_id, packet } => {
                let pkt_len = packet.len();
                let data = packet.data();
                let current_time = stack.current_time();

                match stack.ethernet.process(data) {
                    crate::net::l2::ethernet::ProcessResult::Ipv4(payload, src_mac) => {
                        let ip_packet = subslice_offset(data, payload).map(|offset| {
                            let mut ip_packet = packet.clone();
                            ip_packet.advance(offset);
                            ip_packet.set_len(payload.len());
                            ip_packet
                        });
                        self.handle_ipv4_ingress_with_stack(
                            runtime,
                            if_id,
                            payload,
                            ip_packet,
                            src_mac,
                            current_time,
                            stack,
                        );
                        stack.stats.record_rx(pkt_len);
                        EventHandleResult::Success
                    }
                    crate::net::l2::ethernet::ProcessResult::Arp(payload, src_mac) => {
                        stack.process_arp(if_id, payload, current_time, src_mac);
                        stack.stats.record_rx(pkt_len);
                        EventHandleResult::Success
                    }
                    crate::net::l2::ethernet::ProcessResult::Ipv6(payload, src_mac) => {
                        if stack.ipv6.is_some() {
                            let ip_packet = subslice_offset(data, payload).map(|offset| {
                                let mut ip_packet = packet.clone();
                                ip_packet.advance(offset);
                                ip_packet.set_len(payload.len());
                                ip_packet
                            });
                            // ── ファイアウォール Ingress チェック (IPv6) ──
                            if payload.len() >= 40 {
                                let src_ip = [
                                    payload[8],
                                    payload[9],
                                    payload[10],
                                    payload[11],
                                    payload[12],
                                    payload[13],
                                    payload[14],
                                    payload[15],
                                    payload[16],
                                    payload[17],
                                    payload[18],
                                    payload[19],
                                    payload[20],
                                    payload[21],
                                    payload[22],
                                    payload[23],
                                ];
                                let dst_ip = [
                                    payload[24],
                                    payload[25],
                                    payload[26],
                                    payload[27],
                                    payload[28],
                                    payload[29],
                                    payload[30],
                                    payload[31],
                                    payload[32],
                                    payload[33],
                                    payload[34],
                                    payload[35],
                                    payload[36],
                                    payload[37],
                                    payload[38],
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
                                    let sp =
                                        u16::from_be_bytes([transport_data[0], transport_data[1]]);
                                    let dp =
                                        u16::from_be_bytes([transport_data[2], transport_data[3]]);
                                    (sp, dp)
                                } else if u8::from(protocol) == 58 && transport_data.len() >= 2 {
                                    // ICMPv6: src_port = type, dst_port = code
                                    (transport_data[0] as u16, transport_data[1] as u16)
                                } else {
                                    (0, 0)
                                };

                                let tcp_flags =
                                    if u8::from(protocol) == 6 && transport_data.len() >= 14 {
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

                            stack.process_ipv6_data(
                                if_id,
                                payload,
                                current_time,
                                src_mac,
                                false,
                                ip_packet,
                            );
                            stack.stats.record_rx(pkt_len);
                        } else {
                            stack.stats.record_dropped();
                        }
                        EventHandleResult::Success
                    }
                    _ => EventHandleResult::Success,
                }
            }
            NetworkEvent::IngressBatch { if_id, packets } => {
                // バッチ着信: スタックロック保持中に全パケットを連続処理
                for packet in packets {
                    self.handle_event_with_stack_in(
                        runtime,
                        NetworkEvent::IngressPacket { if_id, packet },
                        stack,
                    );
                }
                EventHandleResult::Success
            }
            NetworkEvent::ReassembledPacket { if_id, payload } => {
                let current_time = stack.current_time();
                let ingress_if_id = resolve_ingress_if_id_in(runtime, if_id);
                let view = PacketPayloadView::new(&payload);

                // Determine if it's IPv4 or IPv6
                if view.total_len() >= 20 && view.first_byte().map(|byte| byte >> 4) == Some(4) {
                    // IPv4
                    if let Some(header_packet) = view.first_segment() {
                        let header = header_packet.data();
                        if header.len() < 20 {
                            return EventHandleResult::Success;
                        }
                        let header_len = ((header[0] & 0x0f) as usize) * 4;
                        if header_len < 20
                            || header.len() < header_len
                            || view.total_len() < header_len
                        {
                            return EventHandleResult::Success;
                        }
                        let src_ip = crate::net::l3::ipv4::Ipv4Address::new([
                            header[12], header[13], header[14], header[15],
                        ]);
                        let dst_ip = crate::net::l3::ipv4::Ipv4Address::new([
                            header[16], header[17], header[18], header[19],
                        ]);
                        let protocol = crate::net::l3::ipv4::IpProtocol::from(header[9]);
                        let transport_len = view.total_len().saturating_sub(header_len);
                        let prefix_len = transport_len.min(20);
                        let prefix = view.read_vec(header_len, prefix_len);
                        let ttl = header[8];

                        let (src_port, dst_port, tcp_flags) = match protocol {
                            crate::net::l3::ipv4::IpProtocol::Tcp if prefix.len() >= 20 => (
                                u16::from_be_bytes([prefix[0], prefix[1]]),
                                u16::from_be_bytes([prefix[2], prefix[3]]),
                                prefix[13],
                            ),
                            crate::net::l3::ipv4::IpProtocol::Udp if prefix.len() >= 8 => (
                                u16::from_be_bytes([prefix[0], prefix[1]]),
                                u16::from_be_bytes([prefix[2], prefix[3]]),
                                0,
                            ),
                            crate::net::l3::ipv4::IpProtocol::Icmp if prefix.len() >= 2 => {
                                (prefix[0] as u16, prefix[1] as u16, 0)
                            }
                            crate::net::l3::ipv4::IpProtocol::Icmpv6 if prefix.len() >= 2 => {
                                (prefix[0] as u16, prefix[1] as u16, 0)
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

                        if deliver_raw_payload_if_registered(ingress_if_id, payload.clone()) {
                            return EventHandleResult::Success;
                        }

                        let transport_payload = payload.slice(header_len, transport_len);
                        match protocol {
                            crate::net::l3::ipv4::IpProtocol::Tcp => {
                                if let Some(transport_payload) = transport_payload {
                                    super::tcp_rx::process_tcp_segment_payload_on(
                                        if_id,
                                        src_ip.octets(),
                                        dst_ip.octets(),
                                        &transport_payload,
                                    );
                                }
                            }
                            crate::net::l3::ipv4::IpProtocol::Udp => {
                                if let Some(transport_payload) = transport_payload {
                                    stack.process_udp_payload(
                                        if_id,
                                        transport_payload,
                                        src_ip,
                                        dst_ip,
                                        ttl,
                                        &payload,
                                        current_time,
                                    );
                                }
                            }
                            crate::net::l3::ipv4::IpProtocol::Icmp => {
                                if let Some(transport_payload) = transport_payload {
                                    stack.process_icmp_payload(
                                        &transport_payload,
                                        src_ip,
                                        dst_ip,
                                        ttl,
                                        current_time,
                                    );
                                }
                            }
                            crate::net::l3::ipv4::IpProtocol::Igmp => {
                                if let Some(transport_payload) = transport_payload {
                                    stack.process_igmp_payload(&transport_payload, src_ip, ttl);
                                }
                            }
                            _ => {}
                        }
                    }
                } else if view.total_len() >= 40
                    && view.first_byte().map(|byte| byte >> 4) == Some(6)
                {
                    // IPv6
                    if let Some(header_packet) = view.first_segment() {
                        let header = header_packet.data();
                        if header.len() < 40 {
                            return EventHandleResult::Success;
                        }
                        let src = crate::net::l3::ipv6::Ipv6Address::new([
                            header[8], header[9], header[10], header[11], header[12], header[13],
                            header[14], header[15], header[16], header[17], header[18], header[19],
                            header[20], header[21], header[22], header[23],
                        ]);
                        let dst = crate::net::l3::ipv6::Ipv6Address::new([
                            header[24], header[25], header[26], header[27], header[28], header[29],
                            header[30], header[31], header[32], header[33], header[34], header[35],
                            header[36], header[37], header[38], header[39],
                        ]);
                        let (protocol, _) = crate::net::l3::ipv6::skip_extension_headers(
                            crate::net::l3::ipv4::IpProtocol::from(header[6]),
                            &header[40..],
                        );
                        let payload_offset = header.len();
                        let transport_len = view.total_len().saturating_sub(payload_offset);
                        let prefix_len = transport_len.min(20);
                        let prefix = view.read_vec(payload_offset, prefix_len);
                        let hop_limit = header[7];

                        let (src_port, dst_port, tcp_flags) = match protocol {
                            crate::net::l3::ipv4::IpProtocol::Tcp if prefix.len() >= 20 => (
                                u16::from_be_bytes([prefix[0], prefix[1]]),
                                u16::from_be_bytes([prefix[2], prefix[3]]),
                                prefix[13],
                            ),
                            crate::net::l3::ipv4::IpProtocol::Udp if prefix.len() >= 8 => (
                                u16::from_be_bytes([prefix[0], prefix[1]]),
                                u16::from_be_bytes([prefix[2], prefix[3]]),
                                0,
                            ),
                            crate::net::l3::ipv4::IpProtocol::Icmp if prefix.len() >= 2 => {
                                (prefix[0] as u16, prefix[1] as u16, 0)
                            }
                            crate::net::l3::ipv4::IpProtocol::Icmpv6 if prefix.len() >= 2 => {
                                (prefix[0] as u16, prefix[1] as u16, 0)
                            }
                            _ => (0, 0, 0),
                        };

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

                        if deliver_raw_payload_if_registered(ingress_if_id, payload.clone()) {
                            return EventHandleResult::Success;
                        }

                        let transport_payload = payload.slice(payload_offset, transport_len);
                        match protocol {
                            crate::net::l3::ipv4::IpProtocol::Tcp => {
                                if let Some(transport_payload) = transport_payload {
                                    super::tcp_rx::process_tcp_segment_v6_payload_on(
                                        if_id,
                                        src,
                                        dst,
                                        &transport_payload,
                                    );
                                }
                            }
                            crate::net::l3::ipv4::IpProtocol::Udp => {
                                if let Some(transport_payload) = transport_payload {
                                    stack.process_udp_payload_v6(
                                        if_id,
                                        transport_payload,
                                        src,
                                        dst,
                                        hop_limit,
                                        &payload,
                                    );
                                }
                            }
                            crate::net::l3::ipv4::IpProtocol::Icmpv6 => {
                                if let Some(transport_payload) = transport_payload {
                                    stack.process_icmpv6_data(
                                        if_id,
                                        transport_payload,
                                        src,
                                        dst,
                                        crate::net::l2::ethernet::MacAddress::ZERO,
                                        hop_limit,
                                        current_time,
                                    );
                                }
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
            NetworkEvent::Connect { fd, local, remote } => {
                self.handle_connect_with_stack(fd, local, remote, stack)
            }
            NetworkEvent::SendTo {
                fd,
                payload,
                remote,
            } => self.handle_send_to_with_stack(fd, remote, payload, stack),
            NetworkEvent::RawUdpSend {
                src_port,
                src_ip,
                dst_ip,
                dst_port,
                payload,
                ttl,
                completion_id,
                result_slot,
                waker,
            } => {
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let payload = PacketPayloadView::new(&payload);
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
                            &payload,
                            ttl,
                        ),
                        None => stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Any,
                            src_port,
                            dst,
                            dst_port,
                            &payload,
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
                            &payload,
                            ttl,
                        ),
                        None => stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Any,
                            src_port,
                            dst,
                            dst_port,
                            &payload,
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
            NetworkEvent::RawTcpSend {
                src_ip,
                dst_ip,
                payload,
                completion_id,
                result_slot,
                waker,
            } => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let payload = PacketPayloadView::new(&payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack.with_pending_tx_meta(meta, |stack| {
                        stack.send_tcp_payload(src, dst, &payload)
                    }),
                    None => stack.send_tcp_payload(src, dst, &payload),
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
            NetworkEvent::RawUdpV6Send {
                src_port,
                src_ip,
                dst_ip,
                dst_port,
                payload,
                ttl,
                completion_id,
                result_slot,
                waker,
            } => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                let payload = PacketPayloadView::new(&payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack.with_pending_tx_meta(meta, |stack| {
                        stack.send_udp_v6_payload_scoped_with_ttl(
                            crate::net::types::InterfaceScope::Any,
                            src_port,
                            src,
                            dst,
                            dst_port,
                            &payload,
                            ttl,
                        )
                    }),
                    None => stack.send_udp_v6_payload_scoped_with_ttl(
                        crate::net::types::InterfaceScope::Any,
                        src_port,
                        src,
                        dst,
                        dst_port,
                        &payload,
                        ttl,
                    ),
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
            NetworkEvent::RawTcpV6Send {
                src_ip,
                dst_ip,
                payload,
                completion_id,
                result_slot,
                waker,
            } => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                let payload = PacketPayloadView::new(&payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack.with_pending_tx_meta(meta, |stack| {
                        stack.send_tcp_v6_payload(src, dst, &payload)
                    }),
                    None => stack.send_tcp_v6_payload(src, dst, &payload),
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
            NetworkEvent::TcpBind {
                result_slot, waker, ..
            } => {
                let result = Err(EndpointError::InvalidStateTransition);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UdpBind {
                port,
                scope,
                result_slot,
                waker,
            } => {
                // スタックロック保持版: 二重ロックを回避
                let success = stack.bind_udp_scoped(scope, port).is_some();
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
            NetworkEvent::TcpConnect {
                result_slot, waker, ..
            } => {
                let result = Err(EndpointError::InvalidStateTransition);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpConnectStream {
                local,
                remote,
                result_slot,
                waker,
            } => {
                let result = self.make_tcp_stream_with_stack(runtime, local, remote, stack);
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
            NetworkEvent::UnbindUdp {
                port,
                scope,
                result_slot,
                waker,
            } => {
                stack.unbind_udp_scoped(scope, port);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(true);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UnbindTcp {
                local,
                remote,
                result_slot,
                waker,
            } => {
                if let Some(entry) = tcb_table().remove(local, remote) {
                    self.close_endpoint_for_unbind(entry.fd);
                }
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(true);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UnbindTcpListener {
                fd,
                result_slot,
                waker,
            } => {
                let _ = tcb_table().remove_by_fd(fd);
                self.close_endpoint_for_unbind(fd);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(true);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpBindWithToken {
                result_slot, waker, ..
            } => {
                let result = Err(EndpointError::InvalidStateTransition);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpBindListener {
                local,
                result_slot,
                waker,
            } => {
                let result = self.make_tcp_listener_with_stack(
                    runtime,
                    local,
                    super::inner::EndpointInner::DEFAULT_BACKLOG as u32,
                );
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpBindListenerWithToken {
                local,
                token,
                result_slot,
                waker,
            } => {
                let _ = token;
                let result = self.make_tcp_listener_with_stack(
                    runtime,
                    local,
                    super::inner::EndpointInner::DEFAULT_BACKLOG as u32,
                );
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(result);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UdpBindWithToken {
                port,
                scope,
                token,
                result_slot,
                waker,
            } => {
                let success = stack
                    .bind_udp_with_token_scoped(scope, port, token)
                    .is_some();
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(success);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UdpBindEndpoint {
                port,
                scope,
                result_slot,
                waker,
            } => {
                let endpoint = stack.bind_udp_scoped(scope, port);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(endpoint);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::UdpBindEndpointWithToken {
                port,
                scope,
                token,
                result_slot,
                waker,
            } => {
                let endpoint = stack.bind_udp_with_token_scoped(scope, port, token);
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(endpoint);
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
                src_ip,
                dst_ip,
                dst_port,
                payload,
                ttl,
                completion_id,
                result_slot,
                waker,
            } => {
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                let payload = PacketPayloadView::new(&payload);
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
                            &payload,
                            ttl,
                        ),
                        None => stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Pinned(net_if),
                            src_port,
                            dst,
                            dst_port,
                            &payload,
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
                            &payload,
                            ttl,
                        ),
                        None => stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Pinned(net_if),
                            src_port,
                            dst,
                            dst_port,
                            &payload,
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
            NetworkEvent::RawTcpSendOn {
                if_id,
                src_ip,
                dst_ip,
                payload,
                completion_id,
                result_slot,
                waker,
            } => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                let payload = PacketPayloadView::new(&payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack.with_pending_tx_meta(meta, |stack| {
                        stack.send_tcp_payload_on(net_if, src, dst, &payload)
                    }),
                    None => stack.send_tcp_payload_on(net_if, src, dst, &payload),
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
            NetworkEvent::RawUdpV6SendOn {
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
            } => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                let payload = PacketPayloadView::new(&payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack.with_pending_tx_meta(meta, |stack| {
                        stack.send_udp_v6_payload_scoped_with_ttl(
                            crate::net::types::InterfaceScope::Pinned(net_if),
                            src_port,
                            src,
                            dst,
                            dst_port,
                            &payload,
                            ttl,
                        )
                    }),
                    None => stack.send_udp_v6_payload_scoped_with_ttl(
                        crate::net::types::InterfaceScope::Pinned(net_if),
                        src_port,
                        src,
                        dst,
                        dst_port,
                        &payload,
                        ttl,
                    ),
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
            NetworkEvent::RawTcpV6SendOn {
                if_id,
                src_ip,
                dst_ip,
                payload,
                completion_id,
                result_slot,
                waker,
            } => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                let net_if = crate::net::runtime::manager::NetIfId(if_id);
                let payload = PacketPayloadView::new(&payload);
                let tx_meta = completion_id.map(|completion_id| NetTxMeta {
                    completion_id: Some(completion_id),
                    completion_policy: NetTxCompletionPolicy::DeviceCompletion,
                    ..NetTxMeta::default()
                });
                let sent = match tx_meta {
                    Some(meta) => stack.with_pending_tx_meta(meta, |stack| {
                        stack.send_tcp_v6_payload_on(net_if, src, dst, &payload)
                    }),
                    None => stack.send_tcp_v6_payload_on(net_if, src, dst, &payload),
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
                let payload = PacketPayloadView::new(&payload);
                stack.send_udp_raw_payload_scoped_with_src_ttl(
                    crate::net::types::InterfaceScope::Pinned(net_if),
                    s,
                    src_port,
                    d,
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
                let s = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let d = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                let payload = PacketPayloadView::new(&payload);
                stack.send_tcp_payload_with_ttl(s, d, &payload, ttl);
                EventHandleResult::Success
            }

            // ================================================================
            // Async utility events (with stack)
            // ================================================================
            NetworkEvent::IcmpEcho {
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
            NetworkEvent::ArpProbe { target_ip } => {
                let ip = crate::net::l3::ipv4::Ipv4Address::new(target_ip);
                stack.send_arp_probe(ip);
                EventHandleResult::Success
            }
            NetworkEvent::ArpResolveCheck {
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
            NetworkEvent::DhcpApplyLease {
                if_id,
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
                    obtained_at: crate::task::current_tick(),
                };
                let target_if = if_id.map(crate::net::runtime::manager::NetIfId);
                let selected_primary = target_if
                    .map(|if_id| {
                        crate::net::runtime::device::claim_bound_primary_interface_with_stack_state_in(
                            runtime,
                            if_id, stack,
                        )
                    })
                    .unwrap_or(false);
                if let Some(if_id) = target_if {
                    let is_primary = selected_primary
                        || crate::net::runtime::device::primary_if_in(runtime) == Some(if_id);
                    if is_primary {
                        crate::net::services::dhcp::mark_primary_interface(if_id);
                    }
                    stack.apply_dhcp_v4_lease_for_interface(&lease, if_id, is_primary);
                    log::info!(
                        "[NET] DHCP lease bound: if{} primary={} ip={}",
                        if_id.0,
                        is_primary,
                        lease.ip_address
                    );
                } else {
                    stack.apply_dhcp_v4_lease(&lease);
                }
                EventHandleResult::Success
            }
            NetworkEvent::GetLinkLocal { result_slot, waker } => {
                let result = stack.config().ipv6.map(|c| c.link_local.octets());
                finish_command(result_slot, waker, result)
            }
            NetworkEvent::GetPrimaryInterfaceConfig { result_slot, waker } => {
                let result =
                    crate::net::api::config::primary_interface_config_from_runtime_in(runtime);
                finish_command(result_slot, waker, result)
            }
            NetworkEvent::GetInterfaceConfig {
                if_id,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::get_interface_config_from_runtime_in(
                    runtime,
                    NetIfId(if_id),
                ),
            ),
            NetworkEvent::ListInterfaceConfigs { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::list_interface_configs_from_runtime_in(runtime),
            ),
            NetworkEvent::GetInterfaceStats {
                if_id,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::interface_stats_snapshot_with_stack_in(
                    runtime,
                    NetIfId(if_id),
                    Some(stack),
                ),
            ),
            NetworkEvent::ListInterfaceStats { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::list_interface_stats_with_stack_in(runtime, Some(stack)),
            ),
            NetworkEvent::ListInterfaces { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::list_interfaces_from_runtime_in(runtime),
            ),
            NetworkEvent::GetNetworkSnapshot { result_slot, waker } => {
                finish_command(result_slot, waker, crate::net::obs::snapshot())
            }
            NetworkEvent::GetNetworkRecentEvents {
                limit,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::obs::snapshot()
                    .recent_events
                    .into_iter()
                    .take(limit)
                    .collect(),
            ),
            NetworkEvent::FirewallEnable { result_slot, waker } => {
                finish_command(result_slot, waker, crate::net::security::firewall::enable())
            }
            NetworkEvent::FirewallDisable { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::security::firewall::disable(),
            ),
            NetworkEvent::FirewallStatus { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_status_text(),
            ),
            NetworkEvent::FirewallListRules { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_list_rules_text(),
            ),
            NetworkEvent::FirewallStats { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_stats_text(),
            ),
            NetworkEvent::FirewallAddRule {
                rule,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::security::firewall::add_rule(rule).map_err(alloc::string::String::from),
            ),
            NetworkEvent::FirewallRemoveRule {
                id,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::security::firewall::remove_rule(id)
                    .map_err(alloc::string::String::from),
            ),
            NetworkEvent::FirewallClearRules { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::security::firewall::clear_rules().map_err(alloc::string::String::from),
            ),
            NetworkEvent::FirewallSetDefaultPolicy {
                direction,
                action,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                crate::net::security::firewall::set_default_policy(direction, action)
                    .map_err(alloc::string::String::from),
            ),
            NetworkEvent::GetArpCache { result_slot, waker } => {
                let entries: Vec<_> = stack
                    .arp_cache()
                    .iter()
                    .map(|(ip, mac)| crate::net::api::connections::ArpCacheEntry {
                        ip: *ip.as_bytes(),
                        mac: *mac.as_bytes(),
                        complete: true,
                    })
                    .collect();
                finish_command(result_slot, waker, entries)
            }
            NetworkEvent::ArpInsert { ip, mac } => {
                let now = crate::time::get_uptime_ms();
                let ipv4 = crate::net::l3::ipv4::Ipv4Address::new(ip);
                let mac_addr = MacAddress::new(mac);
                stack.arp_cache_insert(ipv4, mac_addr, now);
                EventHandleResult::Success
            }
            NetworkEvent::GetUdpEndpoints { result_slot, waker } => {
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
            NetworkEvent::GetDhcpState {
                if_id,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                if let Some(if_id) = if_id {
                    crate::net::api::dhcp::get_dhcp_state_snapshot_in(runtime, NetIfId(if_id))
                } else {
                    crate::net::api::dhcp::dhcp_state_snapshot_in(runtime)
                },
            ),
            NetworkEvent::ListDhcpStates { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::dhcp::list_dhcp_states_snapshot_in(runtime),
            ),
            NetworkEvent::DhcpRenew { result_slot, waker } => {
                use crate::net::services::dhcp;

                let now = tcb_table().get_current_tick();
                let mut touched = false;
                let mut err_msg: Option<alloc::string::String> = None;

                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    client.force_renew_or_restart(now);
                    touched = true;
                }

                if err_msg.is_none() {
                    match dhcp::primary_v6_client_lock_in(runtime).lock() {
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
            NetworkEvent::DhcpRelease { result_slot, waker } => {
                use crate::net::services::dhcp;

                let mut released = false;
                // DHCPv4 Release
                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    client.release();
                    released = true;
                }
                // DHCPv6 Release (RFC 8415 Section 18.2.6)
                if let Ok(guard) = dhcp::primary_v6_client_lock_in(runtime).lock() {
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
            NetworkEvent::DhcpDiscover { result_slot, waker } => {
                use crate::net::services::dhcp;

                let now = tcb_table().get_current_tick();
                let mut offer = None;

                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    let _ = client.drive(now, 1000);
                    if let Some(o) = client.offered_lease() {
                        offer = Some(crate::net::api::dhcp::DhcpOfferInfo {
                            server_ip: *o.server_ip.as_bytes(),
                            offered_ip: *o.ip_address.as_bytes(),
                        });
                    }
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(offer);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpLastDeclined { result_slot, waker } => {
                use crate::net::services::dhcp;

                let mut ip = None;
                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    ip = client.last_declined_ip().map(|a| *a.as_bytes());
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(ip);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::DhcpLastReleased { result_slot, waker } => {
                use crate::net::services::dhcp;

                let mut ip = None;
                if let Some(client) = dhcp::primary_v4_client_in(runtime) {
                    ip = client.last_released_ip().map(|a| *a.as_bytes());
                }

                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(ip);
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::GetTcpConnections { result_slot, waker } => {
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

    // IPv6パケットの処理は handle_event_with_stack 内で
    // stack.process_ipv6_data() 経由で処理されるため、
    // 個別のメソッドは不要。
    //
    // ARP/ICMPパケットの処理も同様にNetworkStack側で処理される。
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
        EndpointAddr, EndpointError, EndpointState, create_raw_endpoint, create_tcp_endpoint,
        create_udp_endpoint,
    };

    fn test_payload(data: &[u8]) -> PacketPayload {
        crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
    }

    fn test_packet(data: &[u8]) -> crate::net::datapath::mempool::PacketRef {
        crate::net::payload::packet_from_bytes(data).expect("allocate packet-backed test packet")
    }

    fn build_ipv4_udp_frame(
        src_mac: crate::net::l2::ethernet::MacAddress,
        dst_mac: crate::net::l2::ethernet::MacAddress,
        src_ip: crate::net::l3::ipv4::Ipv4Address,
        dst_ip: crate::net::l3::ipv4::Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
        let mut frame = alloc::vec![0u8; 256];
        let mut eth =
            crate::net::l2::ethernet::EthernetFrameMut::new(&mut frame).expect("ethernet frame");
        eth.set_destination(dst_mac)
            .set_source(src_mac)
            .set_ether_type(crate::net::l2::ethernet::EtherType::Ipv4);

        let mut ip =
            crate::net::l3::ipv4::Ipv4PacketMut::new(eth.payload_mut()).expect("ipv4 packet");
        ip.init_header()
            .set_source(src_ip)
            .set_destination(dst_ip)
            .set_ttl(64)
            .set_protocol(crate::net::l3::ipv4::IpProtocol::Udp);

        let udp_len = crate::net::l4::udp::UdpProcessor::build_packet(
            ip.payload_mut(),
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            payload,
        )
        .expect("udp packet");
        ip.finalize(udp_len);

        let total_ip_len = crate::net::l3::ipv4::Ipv4Header::MIN_SIZE + udp_len;
        eth.set_payload_len(total_ip_len);

        let frame_bytes = eth.as_bytes().to_vec();
        let ip_offset = crate::net::l2::ethernet::EthernetHeader::SIZE;
        let ip_bytes = frame_bytes[ip_offset..ip_offset + total_ip_len].to_vec();
        (frame_bytes, ip_bytes)
    }

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
            let _ = inner.send_payload(test_payload(&[1, 2, 3]));
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
            let _ = inner.send_payload(test_payload(&[1, 2, 3, 4]));
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
            handler.send_udp_payload(local, remote, test_payload(&[0u8; 8]), 64,),
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
        let res = handler.handle_send_to(fd, remote, test_payload(&[1, 2, 3]));
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
        let res = handler.handle_send_to(
            fd,
            EndpointAddr::new([127, 0, 0, 1], 8081),
            test_payload(&[9]),
        );
        assert!(!matches!(
            res,
            EventHandleResult::ProtocolError(EndpointError::InvalidArgument)
        ));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_raw_endpoint_intercepts_udp_before_socket_demux() {
        init_endpoint_manager();
        crate::net::runtime::stack::init_default();

        let udp = create_udp_endpoint();
        if let Some(endpoint) = udp.endpoint() {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            let local = EndpointAddr::new([127, 0, 0, 1], 8088);
            inner.local_addr = Some(local);
            inner.ensure_udp().socket = Some(crate::net::l4::udp::UdpEndpoint::new(local.port()));
            let _ = inner.transition_to(EndpointState::Bound);
        }

        let raw = create_raw_endpoint();
        if let Some(endpoint) = raw.endpoint() {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.scope = crate::net::types::InterfaceScope::Any;
            inner.ensure_raw();
            let _ = inner.transition_to(EndpointState::Bound);
        }

        let manager =
            crate::net::l4::endpoint::manager::endpoint_manager().expect("endpoint manager lock");
        let guard = manager.read().unwrap_or_else(|e| e.into_inner());
        let manager = guard.as_ref().expect("endpoint manager");
        assert!(
            manager
                .register_raw_scope(crate::net::types::InterfaceScope::Any, raw.fd())
                .is_ok()
        );
        drop(guard);

        let ingress_if = NetIfId(9);
        let (frame, ip_bytes) = build_ipv4_udp_frame(
            crate::net::l2::ethernet::MacAddress::from_octets(0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc),
            crate::net::l2::ethernet::MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01),
            crate::net::l3::ipv4::Ipv4Address::new([10, 0, 0, 2]),
            crate::net::l3::ipv4::Ipv4Address::new([127, 0, 0, 1]),
            54000,
            8088,
            b"raw-first",
        );

        let handler = NetworkEventHandler::new();
        let res = handler.handle_event(NetworkEvent::IngressPacket {
            if_id: Some(ingress_if),
            packet: test_packet(&frame),
        });
        assert!(matches!(res, EventHandleResult::Success));

        let (payload, if_id) = raw
            .endpoint()
            .expect("raw endpoint")
            .try_recv_raw_payload()
            .expect("raw payload");
        assert_eq!(if_id, ingress_if);
        let mut actual = alloc::vec![0u8; payload.total_len()];
        let copied =
            crate::net::payload::PacketPayloadView::new(&payload).copy_all_into(&mut actual);
        actual.truncate(copied);
        assert_eq!(actual, ip_bytes);

        let mut buf = [0u8; 32];
        assert!(matches!(
            udp.endpoint()
                .expect("udp endpoint")
                .try_recv_from(&mut buf),
            Err(EndpointError::Timeout)
        ));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_unbind_tcp_listener_closes_exact_fd_only() {
        init_endpoint_manager();

        let local = EndpointAddr::new([127, 0, 0, 1], 18080);
        let listener = create_tcp_endpoint();
        let fd = listener.fd();
        let handler = NetworkEventHandler::new();

        assert!(matches!(
            handler.handle_listen(fd, local, 16),
            EventHandleResult::Success
        ));

        let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
        let waker = alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new());
        assert!(matches!(
            handler.handle_event(NetworkEvent::UnbindTcpListener {
                fd,
                result_slot,
                waker,
            }),
            EventHandleResult::Success
        ));

        let endpoint = listener.endpoint().expect("listener endpoint");
        let inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(inner.state, EndpointState::Closed);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_unbind_tcp_listener_does_not_close_rebound_listener() {
        init_endpoint_manager();

        let local = EndpointAddr::new([127, 0, 0, 1], 18081);
        let stale = create_tcp_endpoint();
        let stale_fd = stale.fd();
        if let Some(endpoint) = stale.endpoint() {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            let _ = inner.transition_to(EndpointState::Closed);
        }

        let rebound = create_tcp_endpoint();
        let rebound_fd = rebound.fd();
        let handler = NetworkEventHandler::new();

        assert!(matches!(
            handler.handle_listen(rebound_fd, local, 16),
            EventHandleResult::Success
        ));

        let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
        let waker = alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new());
        assert!(matches!(
            handler.handle_event(NetworkEvent::UnbindTcpListener {
                fd: stale_fd,
                result_slot,
                waker,
            }),
            EventHandleResult::Success
        ));

        let endpoint = rebound.endpoint().expect("rebound endpoint");
        let inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(inner.state, EndpointState::Listening);
        assert_eq!(inner.local_addr, Some(local));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_make_tcp_listener_with_stack_returns_listening_listener() {
        init_endpoint_manager();

        let handler = NetworkEventHandler::new();
        let local = EndpointAddr::new([127, 0, 0, 1], 18082);
        let listener = handler
            .make_tcp_listener_with_stack(crate::net::runtime::default_runtime(), local, 16)
            .expect("listener should bind");

        let endpoint = listener.endpoint();
        assert_eq!(endpoint.state(), EndpointState::Listening);
        assert_eq!(endpoint.local_addr(), Some(local));
        assert!(matches!(
            endpoint.try_next_incoming(),
            Err(EndpointError::Timeout)
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

    fn test_payload(data: &[u8]) -> PacketPayload {
        crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
    }

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
            let _ = inner.send_payload(test_payload(&[1, 2, 3]));
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
            let _ = inner.send_payload(test_payload(&[1, 2, 3, 4]));
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
