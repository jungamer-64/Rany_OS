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
mod query;
mod raw;
mod tcp;
mod udp;
mod utility;

pub use self::common::EventHandleResult;

use self::common::finish_command;

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
        if let Ok(mut stack_guard) = crate::net::runtime::stack::stack_in(runtime).lock() {
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
            ) => self.handle_data_ready_in(runtime, socket_id),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::CloseSocket { socket_id },
            ) => self.handle_close_in(runtime, socket_id),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::UdpSendTo { .. },
            ) => EventHandleResult::ProtocolError(EndpointError::ResourceExhausted),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::IcmpEchoReply {
                    source,
                    sequence,
                    rtt_us,
                },
            ) => {
                crate::net::api::icmp::notify_icmp_echo_reply_in(runtime, source, sequence, rtt_us);
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
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetPrimaryInterfaceConfig { reply },
            ) => finish_command(
                reply,
                crate::net::api::config::primary_interface_config_from_runtime_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetInterfaceConfig { if_id, reply },
            ) => finish_command(
                reply,
                crate::net::api::config::get_interface_config_from_runtime_in(
                    runtime,
                    NetIfId(if_id),
                ),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaceConfigs { reply },
            ) => finish_command(
                reply,
                crate::net::api::config::list_interface_configs_from_runtime_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetInterfaceStats { if_id, reply },
            ) => finish_command(
                reply,
                crate::net::api::config::get_interface_stats_without_stack_in(
                    runtime,
                    NetIfId(if_id),
                ),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaceStats { reply },
            ) => finish_command(
                reply,
                crate::net::api::config::list_interface_stats_with_stack_in(runtime, None),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListInterfaces { reply },
            ) => finish_command(
                reply,
                crate::net::api::config::list_interfaces_from_runtime_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetNetworkSnapshot { reply },
            ) => finish_command(reply, crate::net::obs::snapshot_in(runtime)),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetNetworkRecentEvents {
                    limit,
                    reply,
                },
            ) => finish_command(
                reply,
                crate::net::obs::observability_in(runtime)
                    .trace()
                    .recent(limit),
            ),
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
            ) => finish_command(
                reply,
                crate::net::api::connections::udp_endpoint_infos_from_runtime_in(runtime),
            ),
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessLocalTimeouts,
            ) => {
                crate::net::api::icmp::cleanup_icmp_echo_waiters_in(runtime);
                crate::net::l2::arp::cleanup_arp_waiters_in(runtime);
                crate::net::l3::ndp::cleanup_ndp_waiters_in(runtime);
                EventHandleResult::Success
            }
            RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessGlobalTimeouts,
            ) => {
                // タイムアウト処理（スタック依存部分はスキップ）
                // しかし、runtime-owned TCB テーブルのメンテナンスは実行する
                tcp_table_in(runtime).tick(runtime);
                EventHandleResult::Success
            }

            // ============================================================
            // DHCP/TCP 非同期クエリ: runtime-owned state だけで回答できるものは
            // stack lock に依存せず通常クエリ経路を使う。
            // ============================================================
            query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetDhcpState { .. },
            )
            | query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ListDhcpStates { .. },
            )
            | query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpRenew { .. },
            )
            | query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpRelease { .. },
            )
            | query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpDiscover { .. },
            )
            | query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpInform { .. },
            )
            | query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpLastDeclined { .. },
            )
            | query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpLastReleased { .. },
            )
            | query_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::GetTcpConnections { .. },
            ) => self.handle_query_event_with_stack(runtime, query_event),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawSend { command, reply },
            ) => {
                if let Some(completion_id) = command.completion_id() {
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
            RuntimeCommand::Ingress(
                crate::net::runtime::command::IngressCommand::Reassembled { if_id, payload },
            ) => self.handle_reassembled_packet_with_stack(runtime, if_id, payload, stack),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpDataReady { socket_id },
            ) => self.handle_tcp_data_ready_with_stack(runtime, socket_id, stack),
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::UdpSendTo {
                    socket_id,
                    payload,
                    remote,
                },
            ) => self.handle_send_to_with_stack(runtime, socket_id, remote, payload, stack),
            raw_event @ RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::RawSend { .. },
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
                crate::net::api::icmp::notify_icmp_echo_reply_in(runtime, source, sequence, rtt_us);
                EventHandleResult::Success
            }
            lifecycle_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpResolveRequest { .. },
            )
            | lifecycle_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::NdpResolveRequest { .. },
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
                crate::net::runtime::command::ControlCommand::ProcessLocalTimeouts,
            ) => self.handle_lifecycle_event_with_stack(runtime, lifecycle_event, stack),
            // ================================================================
            // Async utility events (with stack)
            // ================================================================
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ArpProbe { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpApplyLease { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::DhcpV6ApplyLease { .. },
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
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::InterfaceTopologyDirty { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::NeighborResolvedV4 { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            utility_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::NeighborResolvedV6 { .. },
            ) => self.handle_utility_event_with_stack(runtime, utility_event, stack),
            lifecycle_event @ RuntimeCommand::Control(
                crate::net::runtime::command::ControlCommand::ProcessGlobalTimeouts,
            ) => self.handle_lifecycle_event_with_stack(runtime, lifecycle_event, stack),

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

pub(crate) fn drive_tcp_data_ready_in(
    runtime: NetRuntimeHandle,
    socket_id: SocketId,
) -> EventHandleResult {
    RuntimeCommandHandler::new().handle_event_in(
        runtime,
        RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::TcpDataReady { socket_id },
        ),
    )
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
