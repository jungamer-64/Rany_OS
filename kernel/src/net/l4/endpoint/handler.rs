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
use super::tcb::tcb_table;
use super::types::{EndpointAddr, EndpointError, EndpointFd, EndpointType};
use crate::net::datapath::mempool::PacketRef;
use crate::net::l2::ethernet::MacAddress;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use kernel_api::resource::net::PacketPayload;

mod common;
mod control;
mod ingress;
mod lifecycle;
mod nat;
mod query;
mod raw;
mod tcp;
mod udp;
mod utility;

pub use self::common::EventHandleResult;

use self::common::{finish_command, stackless_dhcp_state_unavailable};

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

    pub fn handle_event_in(
        &self,
        runtime: NetRuntimeHandle,
        event: NetworkEvent,
    ) -> EventHandleResult {
        // 最適パス: スタックロックを1回取得し、handle_event_with_stack_in() に委譲
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
            NetworkEvent::Close { fd } => self.handle_close(fd),
            NetworkEvent::SendTo { .. } => {
                EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
            }
            NetworkEvent::SetNoDelay { fd, nodelay } => self.handle_set_nodelay(fd, nodelay),
            NetworkEvent::SetPriority { fd, priority } => self.handle_set_priority(fd, priority),
            NetworkEvent::IcmpEchoReply {
                source,
                sequence,
                rtt_us,
            } => {
                crate::net::api::icmp::notify_icmp_echo_reply(source, sequence, rtt_us);
                EventHandleResult::Success
            }
            NetworkEvent::ArpResolved { ip, mac } => {
                crate::net::l2::arp::notify_arp_resolved(ip, mac);
                EventHandleResult::Success
            }

            // ============================================================
            // 非同期Futureイベント: スタック不可時はエラーで完了（デッドロック防止）
            // ============================================================
            NetworkEvent::TcpDialConnection {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(crate::net::l4::tcp::TcpError::InvalidState));
                }
                waker.wake();
                EventHandleResult::Success
            }
            NetworkEvent::TcpBindAcceptor {
                result_slot, waker, ..
            } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(crate::net::l4::tcp::TcpError::InvalidState));
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

                crate::net::api::icmp::cleanup_icmp_echo_waiters();
                crate::net::l2::arp::cleanup_arp_waiters();
                crate::net::l3::ndp::cleanup_ndp_waiters();
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
            NetworkEvent::DhcpInform { result_slot, waker } => {
                if let Ok(mut slot) = result_slot.lock() {
                    *slot = Some(Err(alloc::string::String::from("Stack unavailable")));
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

    pub fn handle_event_with_stack_in(
        &self,
        runtime: NetRuntimeHandle,
        event: NetworkEvent,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            NetworkEvent::IngressPacket { if_id, packet } => {
                self.handle_ingress_packet_with_stack(runtime, if_id, packet, stack)
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
                crate::net::api::icmp::notify_icmp_echo_reply(source, sequence, rtt_us);
                EventHandleResult::Success
            }
            lifecycle_event @ NetworkEvent::ArpResolveRequest { .. }
            | lifecycle_event @ NetworkEvent::NdpResolveRequest { .. }
            | lifecycle_event @ NetworkEvent::ArpResolved { .. }
            | lifecycle_event @ NetworkEvent::TcpDialConnection { .. }
            | lifecycle_event @ NetworkEvent::MulticastJoin { .. }
            | lifecycle_event @ NetworkEvent::MulticastLeave { .. }
            | lifecycle_event @ NetworkEvent::TcpBindAcceptor { .. }
            | lifecycle_event @ NetworkEvent::ProcessTimeouts => {
                self.handle_lifecycle_event_with_stack(runtime, lifecycle_event, stack)
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
            utility_event @ NetworkEvent::DhcpV6ApplyLease { .. } => {
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
            query_event @ NetworkEvent::GetDhcpState { .. } => {
                self.handle_query_event_with_stack(runtime, query_event)
            }
            query_event @ NetworkEvent::ListDhcpStates { .. } => {
                self.handle_query_event_with_stack(runtime, query_event)
            }
            query_event @ NetworkEvent::DhcpRenew { .. } => {
                self.handle_query_event_with_stack(runtime, query_event)
            }
            query_event @ NetworkEvent::DhcpRelease { .. } => {
                self.handle_query_event_with_stack(runtime, query_event)
            }
            query_event @ NetworkEvent::DhcpDiscover { .. } => {
                self.handle_query_event_with_stack(runtime, query_event)
            }
            query_event @ NetworkEvent::DhcpInform { .. } => {
                self.handle_query_event_with_stack(runtime, query_event)
            }
            query_event @ NetworkEvent::DhcpLastDeclined { .. } => {
                self.handle_query_event_with_stack(runtime, query_event)
            }
            query_event @ NetworkEvent::DhcpLastReleased { .. } => {
                self.handle_query_event_with_stack(runtime, query_event)
            }
            query_event @ NetworkEvent::GetTcpConnections { .. } => {
                self.handle_query_event_with_stack(runtime, query_event)
            }

            // その他のイベントはスタック非依存（再帰的ロック取得を回避）
            other => self.handle_event_stackless_in(runtime, other),
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
