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
            | lifecycle_event @ NetworkEvent::TcpConnectStream { .. }
            | lifecycle_event @ NetworkEvent::MulticastJoin { .. }
            | lifecycle_event @ NetworkEvent::MulticastLeave { .. }
            | lifecycle_event @ NetworkEvent::TcpBindListener { .. }
            | lifecycle_event @ NetworkEvent::ApplyIpv6Address { .. }
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

// File-level tests for handler
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;
    use crate::net::l4::endpoint::event::{NetworkEvent, event_queue};
    use crate::net::l4::endpoint::manager::init_endpoint_manager;
    use crate::net::l4::endpoint::tcb::{TcpConnectionState, TcpControlBlockEntry, tcb_table};
    use crate::net::l4::endpoint::{
        Endpoint, EndpointAddr, EndpointError, EndpointState, EndpointType,
    };
    use crate::net::l4::test_support::new_test_endpoint;

    fn test_payload(data: &[u8]) -> PacketPayload {
        crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
    }

    fn test_packet(data: &[u8]) -> crate::net::datapath::mempool::PacketRef {
        crate::net::payload::packet_from_bytes(data).expect("allocate packet-backed test packet")
    }

    fn new_tcp_socket() -> Endpoint {
        new_test_endpoint(EndpointType::Tcp)
    }

    fn new_udp_socket() -> Endpoint {
        new_test_endpoint(EndpointType::Udp)
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

        let sock = new_tcp_socket();
        let fd = sock.fd();

        // Set local and remote so handler proceeds
        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([127, 0, 0, 1], 80);
        let mut inner = sock.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
        let _ = inner.send_payload(test_payload(&[1, 2, 3]));
        drop(inner);

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

        let sock = new_tcp_socket();
        let fd = sock.fd();

        // Set local and remote so handler proceeds
        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([10, 0, 2, 2], 80); // likely ARP unresolved
        let mut inner = sock.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
        let _ = inner.send_payload(test_payload(&[1, 2, 3, 4]));
        let _ = inner.transition_to(EndpointState::Bound);
        let _ = inner.transition_to(EndpointState::Connected);
        drop(inner);

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
    pub fn test_stackless_send_to_requires_stack() {
        init_endpoint_manager();

        let sock = new_udp_socket();
        let fd = sock.fd();
        let handler = NetworkEventHandler::new();
        let res = handler.handle_event_in(
            crate::net::runtime::default_runtime(),
            NetworkEvent::SendTo {
                fd,
                payload: test_payload(&[9]),
                remote: EndpointAddr::new([127, 0, 0, 1], 8081),
            },
        );

        assert!(matches!(
            res,
            EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
        ));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_raw_endpoint_intercepts_udp_before_socket_demux() {
        init_endpoint_manager();
        crate::net::runtime::stack::init_default();

        let udp = new_udp_socket();
        let mut inner = udp.inner().lock().unwrap_or_else(|e| e.into_inner());
        let local = EndpointAddr::new([127, 0, 0, 1], 8088);
        inner.local_addr = Some(local);
        inner.ensure_udp();
        let _ = inner.transition_to(EndpointState::Bound);
        drop(inner);

        let raw = new_test_endpoint(EndpointType::Raw);
        let mut inner = raw.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.scope = crate::net::types::InterfaceScope::Any;
        inner.ensure_raw();
        let _ = inner.transition_to(EndpointState::Bound);
        drop(inner);

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
        let res = handler.handle_event_in(
            crate::net::runtime::default_runtime(),
            NetworkEvent::IngressPacket {
                if_id: Some(ingress_if),
                packet: test_packet(&frame),
            },
        );
        assert!(matches!(res, EventHandleResult::Success));

        let (payload, if_id) = raw.try_recv_raw_payload().expect("raw payload");
        assert_eq!(if_id, ingress_if);
        let mut actual = alloc::vec![0u8; payload.total_len()];
        let copied =
            crate::net::payload::PacketPayloadView::new(&payload).copy_all_into(&mut actual);
        actual.truncate(copied);
        assert_eq!(actual, ip_bytes);

        assert!(matches!(
            udp.try_recv_udp_payload(),
            Err(EndpointError::Timeout)
        ));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_close_listener_closes_exact_fd_only() {
        init_endpoint_manager();

        let local = EndpointAddr::new([127, 0, 0, 1], 18080);
        let listener = new_tcp_socket();
        let fd = listener.fd();
        let handler = NetworkEventHandler::new();

        assert!(matches!(
            handler.handle_listen(fd, local, 16),
            EventHandleResult::Success
        ));

        assert!(matches!(
            handler.handle_event_in(
                crate::net::runtime::default_runtime(),
                NetworkEvent::Close { fd },
            ),
            EventHandleResult::Success
        ));

        let inner = listener.inner().lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(inner.state, EndpointState::Closed);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_close_listener_does_not_close_rebound_listener() {
        init_endpoint_manager();

        let local = EndpointAddr::new([127, 0, 0, 1], 18081);
        let stale = new_tcp_socket();
        let stale_fd = stale.fd();
        let mut inner = stale.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        let _ = inner.transition_to(EndpointState::Closed);
        drop(inner);

        let rebound = new_tcp_socket();
        let rebound_fd = rebound.fd();
        let handler = NetworkEventHandler::new();

        assert!(matches!(
            handler.handle_listen(rebound_fd, local, 16),
            EventHandleResult::Success
        ));

        assert!(matches!(
            handler.handle_event_in(
                crate::net::runtime::default_runtime(),
                NetworkEvent::Close { fd: stale_fd },
            ),
            EventHandleResult::Success
        ));

        let inner = rebound.inner().lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(inner.state, EndpointState::Listening);
        assert_eq!(inner.local_addr, Some(local));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_make_tcp_listener_with_stack_returns_listening_listener() {
        init_endpoint_manager();

        let handler = NetworkEventHandler::new();
        let local = EndpointAddr::new([127, 0, 0, 1], 18082);
        let listener = handler
            .make_tcp_listener_with_stack(
                crate::net::runtime::default_runtime(),
                local,
                crate::net::types::InterfaceScope::Any,
                16,
            )
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
    use crate::net::l4::endpoint::{Endpoint, EndpointAddr, EndpointState, EndpointType};
    use crate::net::l4::test_support::new_test_endpoint;

    fn new_tcp_socket() -> Endpoint {
        new_test_endpoint(EndpointType::Tcp)
    }

    fn test_payload(data: &[u8]) -> PacketPayload {
        crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
    }

    pub fn handle_tx_available_requeues_dataready_smoke() -> bool {
        init_endpoint_manager();

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while event_queue().recv().is_some() {}

        let sock = new_tcp_socket();
        let fd = sock.fd();

        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([127, 0, 0, 1], 80);
        let mut inner = sock.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
        let _ = inner.send_payload(test_payload(&[1, 2, 3]));
        drop(inner);

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

        let sock = new_tcp_socket();
        let fd = sock.fd();

        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new([10, 0, 2, 2], 80);
        let mut inner = sock.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
        let _ = inner.send_payload(test_payload(&[1, 2, 3, 4]));
        let _ = inner.transition_to(EndpointState::Bound);
        let _ = inner.transition_to(EndpointState::Connected);
        drop(inner);

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
