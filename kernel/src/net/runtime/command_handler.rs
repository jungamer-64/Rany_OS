// ============================================================================
// kernel/src/net/runtime/command_handler.rs - RuntimeCommandHandler - ネットワークイベントハンドラ
// ============================================================================
//! # RuntimeCommandHandler - ネットワークイベントハンドラ
//!
//! RuntimeCommandHandler, EventHandleResult

// Building block: Socket handler implementation

use alloc::vec::Vec;

use crate::net::datapath::mempool::PacketRef;
use crate::net::l2::ethernet::MacAddress;
use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::RuntimeCommand;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::tcp_table_in;
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
pub struct RuntimeCommandHandler {
    /// ソケットマネージャへの参照を使用
    _marker: core::marker::PhantomData<()>,
}

impl RuntimeCommandHandler {
    /// 新規ハンドラ作成
    pub fn new() -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }

    pub fn handle_event_in(
        &self,
        runtime: NetRuntimeHandle,
        event: RuntimeCommand,
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
        event: RuntimeCommand,
    ) -> EventHandleResult {
        match event {
            // ============================================================
            // スタック非依存のイベント（そのまま処理可能）
            // ============================================================
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpDataReady { socket_id },
            ) => self.handle_data_ready(socket_id),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TxAvailable,
            ) => self.handle_tx_available(),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::CloseSocket { socket_id },
            ) => self.handle_close(socket_id),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::UdpSendTo { .. },
            ) => EventHandleResult::ProtocolError(EndpointError::ResourceExhausted),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::SetTcpNoDelay {
                    socket_id,
                    nodelay,
                },
            ) => self.handle_set_nodelay(socket_id, nodelay),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::SetSocketPriority {
                    socket_id,
                    priority,
                },
            ) => self.handle_set_priority(socket_id, priority),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::IcmpEchoReply {
                    source,
                    sequence,
                    rtt_us,
                },
            ) => {
                crate::net::api::icmp::notify_icmp_echo_reply(source, sequence, rtt_us);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpResolved { ip, mac },
            ) => {
                crate::net::l2::arp::notify_arp_resolved_in(runtime, ip, mac);
                EventHandleResult::Success
            }

            // ============================================================
            // 非同期Futureイベント: スタック不可時はエラーで完了（デッドロック防止）
            // ============================================================
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpDial { reply, .. },
            ) => finish_command(reply, Err(crate::net::l4::tcp::TcpError::InvalidState)),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpBind { reply, .. },
            ) => finish_command(reply, Err(crate::net::l4::tcp::TcpError::InvalidState)),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::MulticastJoin { reply, .. },
            ) => finish_command(reply, false),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::MulticastLeave { reply, .. },
            ) => finish_command(reply, false),
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::IcmpEcho {
                reply,
                ..
            }) => finish_command(reply, Err(())),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpResolveCheck { reply, .. },
            ) => finish_command(reply, None),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetLinkLocal { reply },
            ) => finish_command(reply, None),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetPrimaryInterfaceConfig { reply },
            ) => finish_command(reply, None),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetInterfaceConfig { reply, .. },
            ) => finish_command(reply, None),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaceConfigs { reply },
            ) => finish_command(reply, Vec::new()),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetInterfaceStats { reply, .. },
            ) => finish_command(reply, None),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaceStats { reply },
            ) => finish_command(reply, Vec::new()),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaces { reply },
            ) => finish_command(reply, Vec::new()),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetNetworkSnapshot { reply },
            ) => finish_command(
                reply,
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
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetNetworkRecentEvents {
                    reply, ..
                },
            ) => finish_command(reply, Vec::new()),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallEnable { reply },
            ) => finish_command(reply, Err("Stack unavailable")),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallDisable { reply },
            ) => finish_command(reply, Err("Stack unavailable")),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallStatus { reply },
            ) => finish_command(reply, alloc::string::String::from("Stack unavailable")),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallListRules { reply },
            ) => finish_command(reply, alloc::string::String::from("Stack unavailable")),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallStats { reply },
            ) => finish_command(reply, alloc::string::String::from("Stack unavailable")),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallAddRule { reply, .. },
            ) => finish_command(reply, Err(alloc::string::String::from("Stack unavailable"))),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallRemoveRule { reply, .. },
            ) => finish_command(reply, Err(alloc::string::String::from("Stack unavailable"))),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallClearRules { reply },
            ) => finish_command(reply, Err(alloc::string::String::from("Stack unavailable"))),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallSetDefaultPolicy {
                    reply,
                    ..
                },
            ) => finish_command(reply, Err(alloc::string::String::from("Stack unavailable"))),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetArpCache { reply },
            ) => finish_command(reply, Vec::new()),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetUdpEndpoints { reply },
            ) => finish_command(reply, Vec::new()),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessTimeouts,
            ) => {
                // タイムアウト処理（スタック依存部分はスキップ）
                // しかし、runtime-owned TCB テーブルのメンテナンスは実行する
                tcp_table_in(runtime).tick(runtime);

                crate::net::api::icmp::cleanup_icmp_echo_waiters();
                crate::net::l2::arp::cleanup_arp_waiters_in(runtime);
                crate::net::l3::ndp::cleanup_ndp_waiters_in(runtime);
                EventHandleResult::Success
            }

            // ============================================================
            // DHCP/TCP 非同期クエリ: スタック不可時はデフォルト値で完了
            // ============================================================
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetDhcpState { reply, .. },
            ) => finish_command(reply, stackless_dhcp_state_unavailable()),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListDhcpStates { reply },
            ) => finish_command(reply, Vec::new()),
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpRenew {
                reply,
            }) => finish_command(reply, Err(alloc::string::String::from("Stack unavailable"))),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpRelease { reply },
            ) => finish_command(reply, false),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpDiscover { reply },
            ) => finish_command(reply, None),
            RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpInform {
                reply,
            }) => finish_command(reply, Err(alloc::string::String::from("Stack unavailable"))),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpLastDeclined { reply },
            ) => finish_command(reply, None),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpLastReleased { reply },
            ) => finish_command(reply, None),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetTcpConnections { reply },
            ) => finish_command(reply, Vec::new()),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpSend {
                    completion_id,
                    reply,
                    ..
                },
            )
            | RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpSend {
                    completion_id,
                    reply,
                    ..
                },
            )
            | RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpV6Send {
                    completion_id,
                    reply,
                    ..
                },
            )
            | RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpV6Send {
                    completion_id,
                    reply,
                    ..
                },
            )
            | RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpSendOn {
                    completion_id,
                    reply,
                    ..
                },
            )
            | RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpSendOn {
                    completion_id,
                    reply,
                    ..
                },
            )
            | RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpV6SendOn {
                    completion_id,
                    reply,
                    ..
                },
            )
            | RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpV6SendOn {
                    completion_id,
                    reply,
                    ..
                },
            ) => {
                if let Some(completion_id) = completion_id {
                    let _ = crate::net::runtime::device::complete_tx_request_in(
                        runtime,
                        completion_id,
                        Err("network stack unavailable"),
                    );
                }
                crate::net::runtime::command::complete_command(
                    reply,
                    Err(EndpointError::ResourceExhausted),
                );
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
        event: RuntimeCommand,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        match event {
            RuntimeCommand::Ingress(crate::net::runtime::command::IngressCommand::Packet {
                if_id,
                packet,
            }) => self.handle_ingress_packet_with_stack(runtime, if_id, packet, stack),
            RuntimeCommand::Ingress(crate::net::runtime::command::IngressCommand::Batch {
                if_id,
                packets,
            }) => self.handle_ingress_batch_with_stack(runtime, if_id, packets, stack),
            RuntimeCommand::Ingress(
                crate::net::runtime::command::IngressCommand::Reassembled { if_id, payload },
            ) => self.handle_reassembled_packet_with_stack(runtime, if_id, payload, stack),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpDataReady { socket_id },
            ) => self.handle_tcp_data_ready_with_stack(socket_id, stack),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::UdpSendTo {
                    socket_id,
                    payload,
                    remote,
                },
            ) => self.handle_send_to_with_stack(socket_id, remote, payload, stack),
            raw_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpSend { .. },
            ) => self.handle_raw_event_with_stack(runtime, raw_event, stack),
            raw_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpSend { .. },
            ) => self.handle_raw_event_with_stack(runtime, raw_event, stack),
            raw_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpV6Send { .. },
            ) => self.handle_raw_event_with_stack(runtime, raw_event, stack),
            raw_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpV6Send { .. },
            ) => self.handle_raw_event_with_stack(runtime, raw_event, stack),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::IcmpEchoRequest { target, sequence },
            ) => {
                let target_ip = crate::net::l3::ipv4::Ipv4Address::new(target);
                match stack.send_icmp_echo_request(target_ip, sequence) {
                    Ok(_send_time) => EventHandleResult::Success,
                    Err(_) => EventHandleResult::ProtocolError(EndpointError::ResourceExhausted),
                }
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::IcmpEchoReply {
                    source,
                    sequence,
                    rtt_us,
                },
            ) => {
                // ICMP応答をFutureレジストリに通知（スタックロック保持版）
                crate::net::api::icmp::notify_icmp_echo_reply(source, sequence, rtt_us);
                EventHandleResult::Success
            }
            lifecycle_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpResolveRequest { .. },
            )
            | lifecycle_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::NdpResolveRequest { .. },
            )
            | lifecycle_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpResolved { .. },
            )
            | lifecycle_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpDial { .. },
            )
            | lifecycle_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::MulticastJoin { .. },
            )
            | lifecycle_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::MulticastLeave { .. },
            )
            | lifecycle_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpBind { .. },
            )
            | lifecycle_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessTimeouts,
            ) => self.handle_lifecycle_event_with_stack(runtime, lifecycle_event, stack),
            raw_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpSendOn { .. },
            ) => self.handle_raw_event_with_stack(runtime, raw_event, stack),
            raw_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpSendOn { .. },
            ) => self.handle_raw_event_with_stack(runtime, raw_event, stack),
            raw_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawUdpV6SendOn { .. },
            ) => self.handle_raw_event_with_stack(runtime, raw_event, stack),
            raw_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawTcpV6SendOn { .. },
            ) => self.handle_raw_event_with_stack(runtime, raw_event, stack),

            // ================================================================
            // NAT forwarding events (with stack)
            // ================================================================
            nat_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::NatForwardUdp { .. },
            ) => self.handle_nat_event_with_stack(nat_event, stack),
            nat_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::NatForwardTcp { .. },
            ) => self.handle_nat_event_with_stack(nat_event, stack),

            // ================================================================
            // Async utility events (with stack)
            // ================================================================
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::IcmpEcho { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpProbe { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpResolveCheck { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpApplyLease { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpV6ApplyLease { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetLinkLocal { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetPrimaryInterfaceConfig { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetInterfaceConfig { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaceConfigs { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetInterfaceStats { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaceStats { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaces { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetNetworkSnapshot { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetNetworkRecentEvents { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallEnable { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallDisable { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallStatus { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallListRules { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallStats { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallAddRule { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallRemoveRule { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallClearRules { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::FirewallSetDefaultPolicy { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetArpCache { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpInsert { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetUdpEndpoints { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),

            // ============================================================
            // 非同期DHCP/TCP クエリ（スタックロック保持中に処理）
            // ============================================================
            query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetDhcpState { .. },
            ) => self.handle_query_event_with_stack(runtime, query_event),
            query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListDhcpStates { .. },
            ) => self.handle_query_event_with_stack(runtime, query_event),
            query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpRenew { .. },
            ) => self.handle_query_event_with_stack(runtime, query_event),
            query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpRelease { .. },
            ) => self.handle_query_event_with_stack(runtime, query_event),
            query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpDiscover { .. },
            ) => self.handle_query_event_with_stack(runtime, query_event),
            query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpInform { .. },
            ) => self.handle_query_event_with_stack(runtime, query_event),
            query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpLastDeclined { .. },
            ) => self.handle_query_event_with_stack(runtime, query_event),
            query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpLastReleased { .. },
            ) => self.handle_query_event_with_stack(runtime, query_event),
            query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetTcpConnections { .. },
            ) => self.handle_query_event_with_stack(runtime, query_event),

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

impl Default for RuntimeCommandHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// ネットワークイベント処理の初期化
pub fn init_network_event_handler() {
    // イベントキューは既に初期化済み（NETWORK_EVENT_QUEUE）
    // タスクスケジューラにruntime_command_taskを登録する
    // runtime_command_taskはasync関数なので、per_core_executor経由でspawnする
    // ネットワークイベント処理はCPU 0で実行（ネットワーク割り込みと同じコア）
    log::info!("Network: Event handler initialized");

    // タスクスポーン（実行時にエグゼキュータが初期化されている必要がある）
    // crate::task::per_core_executor::spawn(super::tcp_rx::runtime_command_task());
    // 上記は起動シーケンスで呼び出される必要があるため、ここではログのみ
}
