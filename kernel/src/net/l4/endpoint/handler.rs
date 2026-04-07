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
use super::tcb::{tcb_table, TcpConnectionState};
use super::types::{EndpointAddr, EndpointError, EndpointFd, EndpointType};
use crate::net::datapath::mempool::PacketRef;
use crate::net::l2::ethernet::MacAddress;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::{default_runtime, NetRuntimeHandle};
use kernel_api::resource::net::PacketPayload;

mod common;
mod control;
mod ingress;
mod nat;
mod raw;
mod tcp;
mod udp;
mod utility;

pub use self::common::EventHandleResult;

use self::common::{finish_command, stackless_dhcp_state_unavailable, subslice_offset};

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
                self.handle_ingress_batch_with_stack(runtime, if_id, packets, stack)
            }
            NetworkEvent::ReassembledPacket { if_id, payload } => {
                self.handle_reassembled_packet_with_stack(runtime, if_id, payload, stack)
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
            raw_event @ NetworkEvent::RawUdpSend { .. } => {
                self.handle_raw_event_with_stack(runtime, raw_event, stack)
            }
            raw_event @ NetworkEvent::RawTcpSend { .. } => {
                self.handle_raw_event_with_stack(runtime, raw_event, stack)
            }
            raw_event @ NetworkEvent::RawUdpV6Send { .. } => {
                self.handle_raw_event_with_stack(runtime, raw_event, stack)
            }
            raw_event @ NetworkEvent::RawTcpV6Send { .. } => {
                self.handle_raw_event_with_stack(runtime, raw_event, stack)
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
            raw_event @ NetworkEvent::RawUdpSendOn { .. } => {
                self.handle_raw_event_with_stack(runtime, raw_event, stack)
            }
            raw_event @ NetworkEvent::RawTcpSendOn { .. } => {
                self.handle_raw_event_with_stack(runtime, raw_event, stack)
            }
            raw_event @ NetworkEvent::RawUdpV6SendOn { .. } => {
                self.handle_raw_event_with_stack(runtime, raw_event, stack)
            }
            raw_event @ NetworkEvent::RawTcpV6SendOn { .. } => {
                self.handle_raw_event_with_stack(runtime, raw_event, stack)
            }

            // ================================================================
            // NAT forwarding events (with stack)
            // ================================================================
            nat_event @ NetworkEvent::NatIcmpTimeExceeded { .. } => {
                self.handle_nat_event_with_stack(nat_event, stack)
            }
            nat_event @ NetworkEvent::NatIcmpDestUnreachable { .. } => {
                self.handle_nat_event_with_stack(nat_event, stack)
            }
            nat_event @ NetworkEvent::NatForwardUdp { .. } => {
                self.handle_nat_event_with_stack(nat_event, stack)
            }
            nat_event @ NetworkEvent::NatForwardTcp { .. } => {
                self.handle_nat_event_with_stack(nat_event, stack)
            }

            // ================================================================
            // Async utility events (with stack)
            // ================================================================
            utility_event @ NetworkEvent::IcmpEcho { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::ArpProbe { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::ArpResolveCheck { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::DhcpApplyLease { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::GetLinkLocal { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::GetPrimaryInterfaceConfig { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::GetInterfaceConfig { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::ListInterfaceConfigs { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::GetInterfaceStats { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::ListInterfaceStats { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::ListInterfaces { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::GetNetworkSnapshot { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::GetNetworkRecentEvents { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::FirewallEnable { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::FirewallDisable { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::FirewallStatus { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::FirewallListRules { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::FirewallStats { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::FirewallAddRule { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::FirewallRemoveRule { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::FirewallClearRules { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::FirewallSetDefaultPolicy { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::GetArpCache { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::ArpInsert { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
            }
            utility_event @ NetworkEvent::GetUdpEndpoints { .. } => {
                self.handle_utility_event_with_stack(runtime, utility_event, stack)
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
    use crate::net::l4::endpoint::event::{event_queue, NetworkEvent};
    use crate::net::l4::endpoint::manager::init_endpoint_manager;
    use crate::net::l4::endpoint::tcb::{tcb_table, TcpConnectionState, TcpControlBlockEntry};
    use crate::net::l4::endpoint::{
        create_raw_endpoint, create_tcp_endpoint, create_udp_endpoint, EndpointAddr, EndpointError,
        EndpointState,
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
        assert!(manager
            .register_raw_scope(crate::net::types::InterfaceScope::Any, raw.fd())
            .is_ok());
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
    use crate::net::l4::endpoint::event::{event_queue, NetworkEvent};
    use crate::net::l4::endpoint::manager::init_endpoint_manager;
    use crate::net::l4::endpoint::tcb::{tcb_table, TcpConnectionState, TcpControlBlockEntry};
    use crate::net::l4::endpoint::{create_tcp_endpoint, EndpointAddr, EndpointState};

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
