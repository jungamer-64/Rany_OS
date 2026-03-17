// ============================================================================
// kernel/src/net/l4/endpoint/handler.rs
// ============================================================================
//! # NetworkEventHandler - ネットワークイベントハンドラ
//!
//! NetworkEventHandler, EventHandleResult

// Building block: Endpoint handler implementation

use alloc::vec::Vec;

use super::event::NetworkEvent;
use super::manager::{ENDPOINT_MANAGER, EndpointFamily};
use super::segment::{TcpSegmentBuilder, send_tcp_segment_payload};
use super::tcb::{TcpConnectionState, TcpControlBlockEntry, tcb_table};
use super::types::{
    EndpointAddr, EndpointError, EndpointFd, EndpointResult, EndpointState, EndpointType,
};
use crate::net::datapath::mempool::PacketRef;
use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::payload::PacketPayloadView;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::{NetRuntimeHandle, default_runtime};
use kernel_api::resource::net::PacketPayload;
use kernel_api::service::netdev::{NetTxCompletionPolicy, NetTxMeta};

/// イベント処理の結果
#[derive(Debug)]
pub enum EventHandleResult {
    /// 処理成功
    Success,
    /// 着信パケット - プロトコルスタックへのオフロード
    IngressPacket {
        if_id: Option<NetIfId>,
        packet: PacketRef,
    },
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

#[inline]
fn resolve_ingress_if_id(if_id: Option<NetIfId>) -> NetIfId {
    resolve_ingress_if_id_in(default_runtime(), if_id)
}

#[inline]
fn resolve_ingress_if_id_in(runtime: NetRuntimeHandle, if_id: Option<NetIfId>) -> NetIfId {
    if let Some(if_id) = if_id {
        return if_id;
    }
    crate::net::runtime::device::primary_if_in(runtime)
        .or_else(|| {
            crate::net::runtime::manager::list_interfaces_in(runtime)
                .ok()
                .and_then(|ifaces| ifaces.first().map(|iface| iface.if_id))
        })
        .unwrap_or_default()
}

#[inline]
fn subslice_offset(container: &[u8], subslice: &[u8]) -> Option<usize> {
    let base = container.as_ptr() as usize;
    let sub = subslice.as_ptr() as usize;
    let end = base.checked_add(container.len())?;
    let sub_end = sub.checked_add(subslice.len())?;
    (sub >= base && sub_end <= end).then_some(sub - base)
}

#[inline]
fn deliver_raw_payload_if_registered(if_id: NetIfId, payload: PacketPayload) -> bool {
    crate::net::l4::endpoint::manager::deliver_raw_payload(if_id, payload)
}

#[inline]
fn endpoint_error_from_network(error: crate::net::types::NetworkError) -> EndpointError {
    match error {
        crate::net::types::NetworkError::InvalidAddress => EndpointError::InvalidArgument,
        crate::net::types::NetworkError::NetworkUnreachable => EndpointError::NetworkUnreachable,
        _ => EndpointError::Internal,
    }
}

#[inline]
fn tcp_error_from_endpoint_error(error: EndpointError) -> crate::net::l4::tcp::TcpError {
    match error {
        EndpointError::NotConnected => crate::net::l4::tcp::TcpError::ConnectionClosed,
        EndpointError::ConnectionRefused => crate::net::l4::tcp::TcpError::ConnectionRefused,
        EndpointError::Timeout => crate::net::l4::tcp::TcpError::Timeout,
        EndpointError::AddressInUse | EndpointError::PortInUse => {
            crate::net::l4::tcp::TcpError::AddressInUse
        }
        EndpointError::BufferFull => crate::net::l4::tcp::TcpError::BufferFull,
        EndpointError::NetworkUnreachable => crate::net::l4::tcp::TcpError::NetworkUnreachable,
        EndpointError::PermissionDenied => crate::net::l4::tcp::TcpError::PermissionDenied,
        _ => crate::net::l4::tcp::TcpError::InvalidState,
    }
}

#[inline]
fn finish_command<T>(
    result_slot: alloc::sync::Arc<crate::sync::PoisonLock<Option<T>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    value: T,
) -> EventHandleResult {
    if let Ok(mut slot) = result_slot.lock() {
        *slot = Some(value);
    }
    waker.wake();
    EventHandleResult::Success
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
            NetworkEvent::GetPrimaryInterfaceConfig { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::primary_interface_config_snapshot_sync_in(runtime),
            ),
            NetworkEvent::GetAggregateNetworkStats { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::aggregate_network_stats_snapshot_sync_in(runtime),
            ),
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
                crate::net::api::config::get_interface_stats_without_stack_in(
                    runtime,
                    NetIfId(if_id),
                ),
            ),
            NetworkEvent::ListInterfaceStats { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::config::list_interface_stats_with_stack_in(runtime, None),
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
            NetworkEvent::FirewallEnable { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_enable_sync(),
            ),
            NetworkEvent::FirewallDisable { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_disable_sync(),
            ),
            NetworkEvent::FirewallStatus { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_status_sync(),
            ),
            NetworkEvent::FirewallListRules { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_list_rules_sync(),
            ),
            NetworkEvent::FirewallStats { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_stats_sync(),
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
                if_id,
                result_slot,
                waker,
            } => finish_command(
                result_slot,
                waker,
                if let Some(if_id) = if_id {
                    crate::net::api::dhcp::get_dhcp_state_sync_in(runtime, NetIfId(if_id))
                } else {
                    crate::net::api::dhcp::dhcp_state_sync_in(runtime)
                },
            ),
            NetworkEvent::ListDhcpStates { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::dhcp::list_dhcp_states_sync_in(runtime),
            ),
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
                let result = crate::net::api::config::primary_interface_id_in(runtime)
                    .and_then(|if_id| {
                        crate::net::api::config::get_interface_config_from_runtime_in(
                            runtime, if_id,
                        )
                    })
                    .map(|cfg| crate::net::api::config::NetworkConfigSnapshot {
                        ip: cfg.ip,
                        netmask: cfg.netmask,
                        gateway: cfg.gateway,
                        mac: cfg.mac,
                    });
                finish_command(result_slot, waker, result)
            }
            NetworkEvent::GetAggregateNetworkStats { result_slot, waker } => {
                let stats = crate::net::api::config::list_interface_stats_with_stack_in(
                    runtime,
                    Some(stack),
                );
                finish_command(
                    result_slot,
                    waker,
                    crate::net::api::config::aggregate_network_stats_from_list(&stats),
                )
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
            NetworkEvent::FirewallEnable { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_enable_sync(),
            ),
            NetworkEvent::FirewallDisable { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_disable_sync(),
            ),
            NetworkEvent::FirewallStatus { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_status_sync(),
            ),
            NetworkEvent::FirewallListRules { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_list_rules_sync(),
            ),
            NetworkEvent::FirewallStats { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::firewall::firewall_stats_sync(),
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
                    crate::net::api::dhcp::get_dhcp_state_sync_in(runtime, NetIfId(if_id))
                } else {
                    crate::net::api::dhcp::dhcp_state_sync_in(runtime)
                },
            ),
            NetworkEvent::ListDhcpStates { result_slot, waker } => finish_command(
                result_slot,
                waker,
                crate::net::api::dhcp::list_dhcp_states_sync_in(runtime),
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

    /// IngressPacketイベント処理
    ///
    /// 【完全非同期化】このメソッドはイベントキュー経由でのみ呼び出されるべき。
    /// `handle_event()` → `handle_event_with_stack()` のパスで呼ばれる場合は
    /// 既にスタックロックが保持されている。
    /// `handle_event()` → `handle_event_stackless()` のパスで呼ばれた場合は
    /// イベントを再エンキューして非同期パスに委譲する。
    fn handle_ingress_packet(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        packet: PacketRef,
    ) -> EventHandleResult {
        // スタックロックなしのコンテキストから呼ばれた場合:
        // イベントキュー経由で再エンキューし、network_event_taskが
        // スタックロック保持下で処理する（二重ロック取得を回避）
        crate::net::l4::endpoint::event::enqueue_event_ignore_in(
            runtime,
            NetworkEvent::IngressPacket { if_id, packet },
        );
        EventHandleResult::Success
    }

    /// IPv4パケットの処理
    fn handle_ipv4_ingress_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        data: &[u8],
        ip_packet: Option<PacketRef>,
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
                    log::warn!(
                        "[FIREWALL] Dropping tiny fragment (RFC 3128): proto={}, len={}",
                        protocol,
                        data.len()
                    );
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
        let ingress_if_id = resolve_ingress_if_id_in(runtime, if_id);
        let result = stack
            .ipv4
            .process_with_time_and_packet(data, ip_packet.clone(), current_time);

        match result {
            crate::net::l3::ipv4::Ipv4ProcessResult::Icmp(payload, src_ip, dst_ip, ttl, _orig) => {
                if let Some(packet) = ip_packet.clone() {
                    if deliver_raw_payload_if_registered(
                        ingress_if_id,
                        PacketPayload::single(packet),
                    ) {
                        return EventHandleResult::Success;
                    }
                }
                let Some(payload) = ip_packet.as_ref().and_then(|ip_packet| {
                    crate::net::payload::payload_from_subslice(ip_packet, data, payload)
                }) else {
                    return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                };
                stack.process_icmp_payload(&payload, src_ip, dst_ip, ttl, current_time);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Igmp(payload, src_ip, ttl, _orig) => {
                if let Some(packet) = ip_packet.clone() {
                    if deliver_raw_payload_if_registered(
                        ingress_if_id,
                        PacketPayload::single(packet),
                    ) {
                        return EventHandleResult::Success;
                    }
                }
                let Some(payload) = ip_packet.as_ref().and_then(|ip_packet| {
                    crate::net::payload::payload_from_subslice(ip_packet, data, payload)
                }) else {
                    return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                };
                stack.process_igmp_payload(&payload, src_ip, ttl);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Udp(payload, src_ip, dst_ip, orig) => {
                if let Some(packet) = ip_packet.clone() {
                    if deliver_raw_payload_if_registered(
                        ingress_if_id,
                        PacketPayload::single(packet),
                    ) {
                        return EventHandleResult::Success;
                    }
                }
                let udp_segment_payload = ip_packet.as_ref().and_then(|ip_packet| {
                    crate::net::payload::payload_from_subslice(ip_packet, data, payload)
                });
                self.handle_udp_ingress_with_stack(
                    runtime,
                    if_id,
                    src_ip.octets(),
                    dst_ip.octets(),
                    payload,
                    udp_segment_payload,
                    data.get(8).copied().unwrap_or(64),
                    stack,
                    orig,
                    current_time,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Tcp(payload, src_ip, dst_ip, _orig) => {
                if let Some(packet) = ip_packet.clone() {
                    if deliver_raw_payload_if_registered(
                        ingress_if_id,
                        PacketPayload::single(packet),
                    ) {
                        return EventHandleResult::Success;
                    }
                }
                let Some(tcp_segment_payload) = ip_packet.as_ref().and_then(|ip_packet| {
                    crate::net::payload::payload_from_subslice(ip_packet, data, payload)
                }) else {
                    return EventHandleResult::Success;
                };
                super::tcp_rx::process_tcp_segment_payload_on(
                    if_id,
                    src_ip.octets(),
                    dst_ip.octets(),
                    &tcp_segment_payload,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Reassembled(payload) => {
                // 再組立てパケットを再帰的に処理
                let _ = src_mac;
                self.handle_event_with_stack(
                    NetworkEvent::ReassembledPacket { if_id, payload },
                    stack,
                );
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
                if let Some(packet) = ip_packet {
                    if deliver_raw_payload_if_registered(
                        ingress_if_id,
                        PacketPayload::single(packet),
                    ) {
                        return EventHandleResult::Success;
                    }
                }
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
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        payload: &[u8],
        udp_segment_payload: Option<PacketPayload>,
        ttl: u8,
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
        let ingress_if_id = resolve_ingress_if_id_in(runtime, if_id);
        let Some(udp_segment_payload) = udp_segment_payload else {
            return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
        };

        let mut found = false;
        if let Some(ref mgr) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
            if let Some(socket) = mgr.find_by_port(
                EndpointType::Udp,
                EndpointFamily::Ipv4,
                dst_port,
                Some(ingress_if_id),
            ) {
                if let Some(payload) = udp_segment_payload.slice(8, data.len()) {
                    socket.push_packet_payload(ingress_if_id, remote, payload);
                } else {
                    log::warn!(
                        "[NET] UDP ingress payload allocation failed for {}:{} -> {}:{}",
                        EndpointAddr::new(src_ip, src_port),
                        src_port,
                        EndpointAddr::new(dst_ip, dst_port),
                        dst_port,
                    );
                    return EventHandleResult::Success;
                }
                found = true;
            }
        }

        if !found {
            // Fallback: try the stack-level UdpProcessor endpoint table.
            // This handles endpoints created via stack.bind_udp() (e.g. sync DHCP during boot).
            use crate::net::l3::ipv4::Ipv4Address;
            let src_v4 = Ipv4Address::new(src_ip);
            let dst_v4 = Ipv4Address::new(dst_ip);
            let result = stack.udp_process_raw_payload(udp_segment_payload, src_v4, dst_v4, ttl);

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
        let _ = stack;
        self.handle_data_ready(fd, EndpointType::Tcp)
    }

    /// SendToイベント処理 (UDP)
    fn handle_send_to_with_stack(
        &self,
        fd: EndpointFd,
        remote: EndpointAddr,
        payload: PacketPayload,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let (local_addr, scope) = {
            let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            let scope = match inner.scope {
                crate::net::types::InterfaceScope::Pinned(if_id) => {
                    crate::net::types::InterfaceScope::Pinned(if_id)
                }
                crate::net::types::InterfaceScope::Any => inner
                    .last_ingress_if_id
                    .map(crate::net::types::InterfaceScope::Pinned)
                    .unwrap_or(crate::net::types::InterfaceScope::Any),
            };
            (inner.local_addr, scope)
        };

        let local_port = local_addr.map(|a| a.port()).unwrap_or(0);
        if local_port == 0 {
            return EventHandleResult::ProtocolError(EndpointError::NotConnected);
        }

        let sent = if let Some(dst_v4) = remote.as_ipv4() {
            let dst_ip = Ipv4Address::new(dst_v4);
            let explicit_src = local_addr
                .and_then(|addr| addr.as_ipv4())
                .map(Ipv4Address::new)
                .filter(|ip| !ip.is_any());
            let payload_view = PacketPayloadView::new(&payload);

            match stack.resolve_ipv4_egress(scope, None, explicit_src, dst_ip) {
                Ok((Some(if_id), _, _)) => {
                    let pinned = crate::net::types::InterfaceScope::Pinned(if_id);
                    if let Some(src_ip) = explicit_src {
                        stack.send_udp_raw_payload_scoped_with_src_ttl(
                            pinned,
                            src_ip,
                            local_port,
                            dst_ip,
                            remote.port(),
                            &payload_view,
                            64,
                        )
                    } else {
                        stack.send_udp_raw_payload_scoped_auto_ttl(
                            pinned,
                            local_port,
                            dst_ip,
                            remote.port(),
                            &payload_view,
                            64,
                        )
                    }
                }
                Ok((None, _, _)) => {
                    if let Some(src_ip) = explicit_src {
                        stack.send_udp_raw_payload_scoped_with_src_ttl(
                            crate::net::types::InterfaceScope::Any,
                            src_ip,
                            local_port,
                            dst_ip,
                            remote.port(),
                            &payload_view,
                            64,
                        )
                    } else {
                        stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Any,
                            local_port,
                            dst_ip,
                            remote.port(),
                            &payload_view,
                            64,
                        )
                    }
                }
                Err(error) => {
                    return EventHandleResult::ProtocolError(endpoint_error_from_network(error));
                }
            }
        } else if remote.is_ipv6() && local_addr.map_or(false, |a| a.is_ipv6()) {
            let src_v6 = local_addr
                .map(|addr| crate::net::l3::ipv6::Ipv6Address::new(addr.as_ipv6()))
                .unwrap_or(crate::net::l3::ipv6::Ipv6Address::UNSPECIFIED);
            let dst_v6 = crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6());
            let payload_view = PacketPayloadView::new(&payload);

            match stack.resolve_ipv6_egress(scope, None, Some(src_v6), dst_v6) {
                Ok((Some(if_id), _, _)) => stack.send_udp_v6_payload_scoped_with_ttl(
                    crate::net::types::InterfaceScope::Pinned(if_id),
                    local_port,
                    src_v6,
                    dst_v6,
                    remote.port(),
                    &payload_view,
                    64,
                ),
                Ok((None, _, _)) => stack.send_udp_v6_payload_scoped_with_ttl(
                    crate::net::types::InterfaceScope::Any,
                    local_port,
                    src_v6,
                    dst_v6,
                    remote.port(),
                    &payload_view,
                    64,
                ),
                Err(error) => {
                    return EventHandleResult::ProtocolError(endpoint_error_from_network(error));
                }
            }
        } else {
            false
        };

        if sent {
            EventHandleResult::Success
        } else {
            EventHandleResult::ProtocolError(EndpointError::NetworkUnreachable)
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
                let pending_len = inner.send_payload_bytes();
                if pending_len == 0 {
                    return None;
                }

                // 1. Sender SWS Avoidance & Nagle チェック
                if tcb.should_delay_send(pending_len) {
                    return None;
                }

                // 2. 実効ウィンドウによる制限
                let effective_wnd = tcb.effective_send_window();
                if effective_wnd == 0 {
                    return None;
                }

                // 3. 1セグメントあたりのサイズ決定 (min(buffer, window, MSS))
                let mss = tcb.mss as usize;
                let len = (pending_len as u32).min(effective_wnd).min(mss as u32) as usize;

                if len == 0 {
                    return None;
                }

                let payload = inner.peek_send_payload_prefix(len)?;
                Some((
                    payload,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    tcb.advertised_recv_window(),
                ))
            });

            let Some((payload, seq, ack, advertised_wnd)) = send_params else {
                break;
            };

            let data_len = payload.total_len() as u32;

            // TCPセグメントを構築
            let segment = match TcpSegmentBuilder::new(local.port(), remote.port())
                .seq(seq)
                .ack(ack)
                .psh()
                .window(advertised_wnd)
                .payload_packet(payload.clone())
                .build_checked_packet(local, remote)
            {
                Ok(segment) => segment,
                Err(e) => return EventHandleResult::ProtocolError(e),
            };
            let segment_payload = PacketPayload::single(segment);
            let retransmit_segment = segment_payload.clone();

            // パケット送信を試みる
            match self.send_tcp_segment(local, remote, segment_payload) {
                Ok(()) => {
                    // 送信成功: endpointキューから削除し、TCB を更新
                    {
                        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                        inner.consume_send_payload(data_len as usize);
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
                            retransmit_segment.clone(),
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
                let pending = {
                    let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                    inner.has_send_data()
                };
                if pending {
                    super::event::enqueue_event_ignore_in(
                        socket.runtime(),
                        super::event::NetworkEvent::DataReady {
                            fd: socket.fd(),
                            endpoint_type: socket.socket_type(),
                        },
                    );
                } else {
                    // TCPバッファが空でも send_waker が設定されている場合（UDP の ResourceExhausted 待ち）
                    // はここで直接起床させる。TCP の write/poll_write 境界も安全に再ポーリング可能。
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

    fn unregister_endpoint(&self, fd: EndpointFd) {
        if let Some(ref mgr) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
            let _ = mgr.unregister(fd);
        }
    }

    fn make_tcp_stream_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        local: EndpointAddr,
        remote: EndpointAddr,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> Result<crate::net::l4::tcp::TcpStream, crate::net::l4::tcp::TcpError> {
        let owned = crate::net::l4::endpoint::create_tcp_endpoint_in(runtime);
        let endpoint = owned
            .into_inner()
            .ok_or(crate::net::l4::tcp::TcpError::InvalidState)?;

        {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
            inner.ensure_tcp();
            let _ = inner.transition_to(EndpointState::Connecting);
        }

        match self.handle_connect_with_stack(endpoint.fd(), local, remote, stack) {
            EventHandleResult::Success => {
                Ok(crate::net::l4::tcp::TcpStream::from_endpoint(endpoint))
            }
            EventHandleResult::ProtocolError(err) => {
                self.unregister_endpoint(endpoint.fd());
                Err(tcp_error_from_endpoint_error(err))
            }
            _ => {
                self.unregister_endpoint(endpoint.fd());
                Err(crate::net::l4::tcp::TcpError::InvalidState)
            }
        }
    }

    fn make_tcp_listener_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        local: EndpointAddr,
        backlog: u32,
    ) -> Result<crate::net::l4::tcp::TcpListener, crate::net::l4::tcp::TcpError> {
        let owned = crate::net::l4::endpoint::create_tcp_endpoint_in(runtime);
        let endpoint = owned
            .into_inner()
            .ok_or(crate::net::l4::tcp::TcpError::InvalidState)?;

        {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.ensure_tcp().accept_backlog = backlog as usize;
            inner
                .transition_to(EndpointState::Bound)
                .map_err(tcp_error_from_endpoint_error)?;
        }

        match self.handle_listen(endpoint.fd(), local, backlog) {
            EventHandleResult::Success => {
                Ok(crate::net::l4::tcp::TcpListener::from_endpoint(endpoint))
            }
            EventHandleResult::ProtocolError(err) => {
                self.unregister_endpoint(endpoint.fd());
                Err(tcp_error_from_endpoint_error(err))
            }
            _ => {
                self.unregister_endpoint(endpoint.fd());
                Err(crate::net::l4::tcp::TcpError::InvalidState)
            }
        }
    }

    fn close_endpoint_for_unbind(&self, fd: EndpointFd) {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return;
        };
        let Some(socket) = mgr.get(fd) else {
            return;
        };

        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.clear_protocol();
        inner.clear_tcp_payload_queues();
        if let Some(waker) = inner.recv_waker.take() {
            waker.wake();
        }
        if let Some(waker) = inner.send_waker.take() {
            waker.wake();
        }
        if let Some(waker) = inner.connect_waker.take() {
            waker.wake();
        }
        if let Some(waker) = inner.accept_waker.take() {
            waker.wake();
        }
        let _ = inner.transition_to(EndpointState::Closed);
    }

    /// Connectイベント処理
    /// TCPハンドシェイクを開始（SYN送信）
    fn handle_connect_with_stack(
        &self,
        fd: EndpointFd,
        local: EndpointAddr,
        remote: EndpointAddr,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let local_port = if local.port() == 0 {
            mgr.allocate_ephemeral_port(EndpointType::Tcp)
                .unwrap_or(49152)
        } else {
            local.port()
        };
        let unresolved_local = local.with_port(local_port);

        let (scope, preferred_if, congestion_algo, nodelay, priority) = {
            let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            (
                inner.scope,
                inner.last_ingress_if_id,
                inner.tcp().and_then(|t| t.congestion_algorithm),
                inner.tcp().map_or(false, |t| t.nodelay),
                inner.priority,
            )
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

        {
            let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local_addr);
            inner.remote_addr = Some(remote);
            if inner.state.can_connect() {
                let _ = inner.transition_to(EndpointState::Connecting);
            }
        }

        let isn = tcb_table().generate_isn(local_addr, remote);
        let mut tcb = if let Some(algo) = congestion_algo {
            TcpControlBlockEntry::with_algorithm(fd, local_addr, remote, algo)
        } else {
            TcpControlBlockEntry::new(fd, local_addr, remote)
        };
        tcb.initialize_seq(isn);
        tcb.set_nodelay(nodelay);
        tcb.set_priority(priority);
        tcb.scope = scope;
        tcb.ingress_if_id = resolved_if.or(preferred_if);
        tcb.state = TcpConnectionState::SynSent;
        let _ = tcb_table().insert(tcb);

        let syn_segment = TcpSegmentBuilder::new(local_port, remote.port())
            .seq(isn)
            .syn()
            .window(65535)
            .syn_options(
                1460,
                Some(7),
                true,
                Some(crate::net::l4::endpoint::tcp_rx::generate_tcp_timestamp()),
            )
            .build_checked_packet(local_addr, remote);

        let syn_segment = match syn_segment {
            Ok(segment) => segment,
            Err(e) => return EventHandleResult::ProtocolError(e),
        };

        if let Err(e) =
            self.send_tcp_segment(local_addr, remote, PacketPayload::single(syn_segment))
        {
            log::info!("TCP: Failed to send SYN packet: {:?}", e);
            return EventHandleResult::ProtocolError(match e {
                EndpointError::InvalidArgument => EndpointError::InvalidArgument,
                EndpointError::NetworkUnreachable => EndpointError::NetworkUnreachable,
                _ => EndpointError::Internal,
            });
        }

        tcb_table().lookup_mut(local_addr, remote, |tcb| {
            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
        });

        log::info!("TCP: SYN sent {} -> {} (seq={})", local_addr, remote, isn);
        EventHandleResult::Success
    }

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
        let (scope, preferred_if, congestion_algo, nodelay, priority) = {
            let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local_addr);
            inner.remote_addr = Some(remote);
            if inner.state.can_connect() {
                let _ = inner.transition_to(EndpointState::Connecting);
            }
            (
                inner.scope,
                inner.last_ingress_if_id,
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
        tcb.scope = scope;
        tcb.ingress_if_id = preferred_if;
        tcb.state = TcpConnectionState::SynSent;
        let _ = tcb_table().insert(tcb);

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
                Some(crate::net::l4::endpoint::tcp_rx::generate_tcp_timestamp()),
            ) // MSS + Window Scale + SACK Permitted + TS
            .build_checked_packet(local_addr, remote);

        let syn_segment = match syn_segment {
            Ok(segment) => segment,
            Err(e) => return EventHandleResult::ProtocolError(e),
        };

        // パケット送信（IPスタック経由）
        if let Err(e) =
            self.send_tcp_segment(local_addr, remote, PacketPayload::single(syn_segment))
        {
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
        segment: PacketPayload,
    ) -> EndpointResult<()> {
        if endpoint_ipv4_pair(src, dst).is_none() && !endpoint_is_native_v6_pair(src, dst) {
            return Err(EndpointError::InvalidArgument);
        }
        // Delegate to the packet-backed module-level TCP sender.
        // This centralizes IP family handling and ARP/NDP queuing logic.
        if send_tcp_segment_payload(src, dst, segment) {
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
            inner.ensure_tcp().accept_backlog = backlog as usize;
            if inner.state.can_listen() {
                if let Err(err) = inner.transition_to(EndpointState::Listening) {
                    return EventHandleResult::ProtocolError(err);
                }
            } else if inner.state != EndpointState::Listening {
                return EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition);
            }
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

                if let Err(e) =
                    self.send_tcp_segment(local, remote, PacketPayload::single(fin_segment))
                {
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

                if let Err(e) =
                    self.send_tcp_segment(local, remote, PacketPayload::single(fin_segment))
                {
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
        payload: PacketPayload,
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
            let ttl = inner
                .udp()
                .and_then(|u| u.socket.as_ref())
                .map(|s| s.ttl())
                .unwrap_or(64);
            let payload_len = payload.total_len();
            if let Err(e) = self.send_udp_payload(local, remote, payload, ttl) {
                log::info!("UDP: Failed to send packet: {:?}", e);
                return EventHandleResult::ProtocolError(match e {
                    EndpointError::InvalidArgument => EndpointError::InvalidArgument,
                    _ => EndpointError::Internal,
                });
            }

            log::info!(
                "UDP: Sent {} bytes to {} from port {}",
                payload_len,
                remote,
                local.port()
            );

            EventHandleResult::Success
        } else {
            EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition)
        }
    }

    /// UDPパケット送信（非同期イベントキュー経由）
    fn send_udp_payload(
        &self,
        src: EndpointAddr,
        dst: EndpointAddr,
        payload: PacketPayload,
        ttl: u8,
    ) -> EndpointResult<()> {
        let runtime = default_runtime();
        let (result_slot, waker) = crate::net::runtime::stack::new_detached_command_channel();

        // IPv4パス
        if let Some((src_v4, dst_v4)) = endpoint_ipv4_pair(src, dst) {
            let src_ip = crate::net::l3::ipv4::Ipv4Address::new(src_v4);
            let dst_ip = crate::net::l3::ipv4::Ipv4Address::new(dst_v4);
            super::event::enqueue_event_ignore_in(
                runtime,
                NetworkEvent::RawUdpSend {
                    src_port: src.port(),
                    src_ip: (!src_ip.is_any()).then_some(src_ip.octets()),
                    dst_ip: dst_ip.octets(),
                    dst_port: dst.port(),
                    payload,
                    ttl,
                    completion_id: None,
                    result_slot,
                    waker,
                },
            );
            return Ok(());
        }

        // IPv6パス
        if endpoint_is_native_v6_pair(src, dst) {
            let src_v6 = crate::net::l3::ipv6::Ipv6Address::new(src.as_ipv6());
            let dst_v6 = crate::net::l3::ipv6::Ipv6Address::new(dst.as_ipv6());
            super::event::enqueue_event_ignore_in(
                runtime,
                NetworkEvent::RawUdpV6Send {
                    src_port: src.port(),
                    src_ip: src_v6.octets(),
                    dst_ip: dst_v6.octets(),
                    dst_port: dst.port(),
                    payload,
                    ttl,
                    completion_id: None,
                    result_slot,
                    waker,
                },
            );
            return Ok(());
        }

        Err(EndpointError::InvalidArgument)
    }

    /// ICMP Echo Requestイベント処理（イベントキュー経由で非同期処理）
    ///
    /// `IcmpEcho` イベントとしてイベントキューに再送出し、
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
            .recv_raw_payload_sync()
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
                .recv_from_sync(&mut buf),
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
            endpoint.next_incoming_sync(),
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
    } else if protocol == 1 && ipv4_data.len() >= ihl + 2 {
        // ICMP: src_port = type, dst_port = code
        (ipv4_data[ihl] as u16, ipv4_data[ihl + 1] as u16)
    } else {
        (0, 0)
    }
}
