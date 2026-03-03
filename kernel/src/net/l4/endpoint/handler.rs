// ============================================================================
// kernel/src/net/endpoint/handler.rs
// ============================================================================
//! # NetworkEventHandler - ネットワークイベントハンドラ
//!
//! NetworkEventHandler, EventHandleResult

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
    local.is_ipv6()
        && remote.is_ipv6()
        && local.as_ipv4().is_none()
        && remote.as_ipv4().is_none()
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

    /// イベントを処理
    pub fn handle_event(&self, event: NetworkEvent) -> EventHandleResult {
        match event {
            NetworkEvent::IngressPacket { packet } => self.handle_ingress_packet(packet),
            NetworkEvent::IngressBatch { packets } => {
                // バッチ着信: スタックロックを1回取得して全パケットを処理
                if let Ok(mut stack_guard) = crate::net::runtime::stack::NETWORK_STACK.lock() {
                    if let Some(ref mut stack) = *stack_guard {
                        for packet in packets {
                            self.handle_event_with_stack(
                                NetworkEvent::IngressPacket { packet },
                                stack,
                            );
                        }
                    }
                }
                EventHandleResult::Success
            }
            NetworkEvent::ReassembledPacket { data } => {
                if let Ok(mut stack_guard) = crate::net::runtime::stack::NETWORK_STACK.lock() {
                    if let Some(ref mut stack) = *stack_guard {
                        let current_time = stack.current_time();
                        stack.process_reassembled_packet(&data, current_time, crate::net::l2::ethernet::MacAddress::ZERO);
                    }
                }
                EventHandleResult::Success
            }
            NetworkEvent::DataReady { fd, endpoint_type } => self.handle_data_ready(fd, endpoint_type),
            NetworkEvent::TxAvailable => self.handle_tx_available(),
            NetworkEvent::Connect { fd, local, remote } => self.handle_connect(fd, local, remote),
            NetworkEvent::Listen { fd, local, backlog } => self.handle_listen(fd, local, backlog),
            NetworkEvent::Close { fd } => self.handle_close(fd),
            NetworkEvent::SendTo { fd, data, remote } => self.handle_send_to(fd, remote, data),
            NetworkEvent::SetNoDelay { fd, nodelay } => self.handle_set_nodelay(fd, nodelay),
            NetworkEvent::SetPriority { fd, priority } => self.handle_set_priority(fd, priority),
            NetworkEvent::RawUdpSend { src_port, dst_ip, dst_port, data } => {
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                if crate::net::runtime::stack::send_udp(src_port, dst, dst_port, &data) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawTcpSend { src_ip, dst_ip, segment } => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                if crate::net::runtime::stack::send_tcp(src, dst, &segment) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawUdpV6Send { src_port, src_ip, dst_ip, dst_port, data } => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                if crate::net::runtime::stack::send_udp_v6(src_port, src, dst, dst_port, &data) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawTcpV6Send { src_ip, dst_ip, segment } => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                if crate::net::runtime::stack::send_tcp_v6(src, dst, &segment) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::IcmpEchoRequest { target, sequence } => {
                self.handle_icmp_echo_request(target, sequence)
            }
            NetworkEvent::IcmpEchoReply { source, sequence, rtt_us } => {
                // ICMP応答をFutureレジストリに通知
                crate::net::l4::endpoint::futures::notify_icmp_echo_reply(source, sequence, rtt_us);
                EventHandleResult::Success
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
                    self.handle_event_with_stack(
                        NetworkEvent::IngressPacket { packet },
                        stack,
                    );
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
                        
                        match packet.protocol() {
                            crate::net::l3::ipv4::IpProtocol::Tcp => {
                                super::tcp_rx::process_tcp_segment(src_ip.octets(), dst_ip.octets(), payload);
                            }
                            crate::net::l3::ipv4::IpProtocol::Udp => {
                                self.handle_udp_ingress_with_stack(src_ip.octets(), dst_ip.octets(), payload, stack, &data, current_time);
                            }
                            crate::net::l3::ipv4::IpProtocol::Icmp => {
                                stack.process_icmp_data(payload, src_ip, dst_ip, packet.ttl(), current_time);
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
                        let payload = packet.payload();
                        
                        // Note: For IPv6, we'd ideally have process_tcp_data_v6 in endpoint too.
                        // For now, delegate back to stack for IPv6 as it's less fragmented (pun intended)
                        // but this is where we'd unify IPv6 as well.
                        use crate::net::l3::ipv4::IpProtocol;
                        match packet.next_header() {
                            IpProtocol::Tcp => {
                                // super::tcp_rx::process_tcp_segment_v6(src, dst, payload); // TODO
                                stack.process_tcp_data_v6(payload, src, dst, current_time);
                            }
                            IpProtocol::Udp => {
                                stack.process_udp_data_v6(payload, src, dst, packet.hop_limit());
                            }
                            IpProtocol::Icmpv6 => {
                                stack.process_icmpv6_data(payload, src, dst, crate::net::l2::ethernet::MacAddress::ZERO, packet.hop_limit(), current_time);
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
            NetworkEvent::RawUdpSend { src_port, dst_ip, dst_port, data } => {
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                if stack.send_udp_raw(src_port, dst, dst_port, &data) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawTcpSend { src_ip, dst_ip, segment } => {
                let src = crate::net::l3::ipv4::Ipv4Address::new(src_ip);
                let dst = crate::net::l3::ipv4::Ipv4Address::new(dst_ip);
                if stack.send_tcp(src, dst, &segment) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawUdpV6Send { src_port, src_ip, dst_ip, dst_port, data } => {
                let src = crate::net::l3::ipv6::Ipv6Address::new(src_ip);
                let dst = crate::net::l3::ipv6::Ipv6Address::new(dst_ip);
                if stack.send_udp_v6_raw(src_port, src, dst, dst_port, &data) {
                    EventHandleResult::Success
                } else {
                    EventHandleResult::ProtocolError(EndpointError::ResourceExhausted)
                }
            }
            NetworkEvent::RawTcpV6Send { src_ip, dst_ip, segment } => {
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
            NetworkEvent::IcmpEchoReply { source, sequence, rtt_us } => {
                // ICMP応答をFutureレジストリに通知（スタックロック保持版）
                crate::net::l4::endpoint::futures::notify_icmp_echo_reply(source, sequence, rtt_us);
                EventHandleResult::Success
            }
            // その他のイベントはスタック非依存または個別ロックで対応
            other => self.handle_event(other),
        }
    }

    /// IngressPacketイベント処理
    fn handle_ingress_packet(&self, packet: PacketRef) -> EventHandleResult {
        // Ethernetヘッダ解析
        if let Ok(mut stack_guard) = crate::net::runtime::stack::NETWORK_STACK.lock() {
            if let Some(ref mut stack) = *stack_guard {
                return self.handle_event_with_stack(NetworkEvent::IngressPacket { packet }, stack);
            }
        }
        EventHandleResult::Success
    }

    /// IPv4パケットの処理
    fn handle_ipv4_ingress_with_stack(
        &self, 
        data: &[u8], 
        src_mac: MacAddress, 
        current_time: u64, 
        stack: &mut crate::net::runtime::stack::NetworkStack
    ) -> EventHandleResult {
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
                self.handle_udp_ingress_with_stack(src_ip.octets(), dst_ip.octets(), payload, stack, orig, current_time);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Tcp(payload, src_ip, dst_ip, _orig) => {
                super::tcp_rx::process_tcp_segment(src_ip.octets(), dst_ip.octets(), payload);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Reassembled(reassembled_data) => {
                // 再組立てパケットを再帰的に処理
                stack.process_reassembled_packet(&reassembled_data, current_time, src_mac);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::FragmentPending => {}
            crate::net::l3::ipv4::Ipv4ProcessResult::Dropped => {
                stack.stats.record_dropped();
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Error => {
                stack.stats.record_rx_error();
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Success => {}
        }

        EventHandleResult::Success
    }

    /// IPv6パケットの処理 (Stub)
    fn handle_ipv6_ingress(
        &self, 
        _data: &[u8], 
        _packet: PacketRef
    ) -> EventHandleResult {
        EventHandleResult::Success
    }

    /// ARPパケットの処理 (NetworkStack側で処理するため未使用)
    fn handle_arp_ingress(&self, _data: &[u8], _src_mac: MacAddress) -> EventHandleResult {
        EventHandleResult::Success
    }

    /// ICMPパケットの処理 (NetworkStack側で処理するため未使用)
    fn handle_icmp_ingress(&self, _data: &[u8], _src_ip: Ipv4Address, _dst_ip: Ipv4Address, _ttl: u8) -> EventHandleResult {
        EventHandleResult::Success
    }

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
        if let Some(ref mgr) = *ENDPOINT_MANAGER.read() {
            if let Some(socket) = mgr.find_by_port(EndpointType::Udp, dst_port) {
                socket.push_packet(remote, data.to_vec());
                found = true;
            }
        }

        if !found {
            // RFC 1122: Send ICMP Port Unreachable
            use crate::net::l3::ipv4::Ipv4Address;
            use crate::net::l3::icmp::DestUnreachCode;
            
            let src_v4 = Ipv4Address::new(src_ip);
            let dst_v4 = Ipv4Address::new(dst_ip);
            
            // Only send if it wasn't broadcast/multicast (RFC 1122)
            if !dst_v4.is_broadcast() && !dst_v4.is_multicast() {
                stack.send_icmp_error(src_v4, DestUnreachCode::PortUnreachable, original_packet, current_time);
            }
        }

        EventHandleResult::Success
    }

    /// DataReadyイベント処理 (TCP)
    fn handle_tcp_data_ready_with_stack(
        &self, 
        fd: EndpointFd, 
        stack: &mut crate::net::runtime::stack::NetworkStack
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read();
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
        stack: &mut crate::net::runtime::stack::NetworkStack
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read();
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

        let sent = if let (Some(dst_v4), Some(_src_v4)) = (remote.as_ipv4(), socket.local_addr().and_then(|a| a.as_ipv4())) {
            stack.send_udp_raw(local_port, Ipv4Address::new(dst_v4), remote.port(), &data)
        } else if remote.is_ipv6() && socket.local_addr().map_or(false, |a| a.is_ipv6()) {
            let src_v6 = crate::net::l3::ipv6::Ipv6Address::new(socket.local_addr().unwrap().as_ipv6());
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
        let manager = ENDPOINT_MANAGER.read();
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
        let manager = ENDPOINT_MANAGER.read();
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
        let manager = ENDPOINT_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        // 送信バッファからデータを取得（drainは送信成功後に行う）
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

        // TCBから seq/ack/window を取得（送信成功後に snd_nxt を更新）
        let data_len = data.len() as u32;
        let (seq, ack, window) = match tcb_table().lookup(local, remote) {
            Some(tcb) => {
                if tcb.state != TcpConnectionState::Established {
                    return EventHandleResult::ProtocolError(EndpointError::NotConnected);
                }

                // Nagle's algorithm (RFC 896): Delay sending if data is small and there is outstanding data
                if tcb.should_delay_send(data.len()) {
                    log::debug!("TCP: Nagle algorithm delaying send for fd={}", fd.raw());
                    return EventHandleResult::Success; // Delay until ACK received or more data added
                }

                (tcb.snd_nxt, tcb.rcv_nxt, tcb.rcv_wnd)
            }
            None => return EventHandleResult::ProtocolError(EndpointError::NotConnected),
        };

        // TCPセグメントを構築
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

        // パケット送信を試みる
        match self.send_tcp_segment(local, remote, segment) {
            Ok(()) => {
                // 送信成功: send_buffer から対応分を削除し、TCB を更新
                {
                    let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                    let drain_len = data.len();
                    inner.send_buffer.drain(..drain_len);
                    // 送信可能になったため、待ちタスクを起こす
                    if let Some(w) = inner.send_waker.take() {
                        w.wake();
                    }
                }

                // TCB 更新（seq を予約）
                tcb_table().lookup_mut(local, remote, |tcb| {
                    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(data_len);
                });

                log::info!(
                    "TCP: Sent {} bytes (seq={}, ack={}) fd={}",
                    data.len(),
                    seq,
                    ack,
                    fd.raw()
                );

                EventHandleResult::Success
            }
            Err(EndpointError::ResourceExhausted) => {
                // デバイスまたは ARP 等で送信できない -> 再試行
                EventHandleResult::Retry
            }
            Err(EndpointError::InvalidArgument) => {
                log::info!("TCP: Failed to send data: InvalidArgument (family mismatch)");
                EventHandleResult::ProtocolError(EndpointError::InvalidArgument)
            }
            Err(e) => {
                log::info!("TCP: Failed to send data: {:?}", e);
                EventHandleResult::ProtocolError(EndpointError::Internal)
            }
        }
    }

    /// TX 資源解放通知処理
    fn handle_tx_available(&self) -> EventHandleResult {
        // 送信待ちのソケットに DataReady イベントを再送して再試行を促す
        if let Some(ref mgr) = *ENDPOINT_MANAGER.read() {
            mgr.for_each(|socket| {
                if socket.send_buffer_len() > 0 {
                    super::event::send_event_ignore(super::event::NetworkEvent::DataReady {
                        fd: socket.fd(),
                        endpoint_type: socket.socket_type(),
                    });
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
        let manager = ENDPOINT_MANAGER.read();
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
            (inner.tcp().and_then(|t| t.congestion_algorithm), inner.tcp().map_or(false, |t| t.nodelay), inner.priority)
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
            .syn_options(1460, 7) // MSS + Window Scale + SACK Permitted
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

        log::info!(
            "TCP: SYN sent {} -> {} (seq={})",
            local_addr,
            remote,
            isn
        );

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
    fn handle_listen(&self, fd: EndpointFd, local: EndpointAddr, backlog: u32) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read();
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
        let manager = ENDPOINT_MANAGER.read();
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
    fn handle_send_to(&self, fd: EndpointFd, remote: EndpointAddr, data: Vec<u8>) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read();
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
            if let Err(e) = self.send_udp_packet(local, remote, udp_packet) {
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
    ) -> EndpointResult<()> {
        // The `packet` contains a UDP header followed by payload. Extract payload.
        if packet.len() < 8 {
            return Err(EndpointError::InvalidArgument);
        }

        let payload = &packet[8..];
        let (_, dst_v4) = endpoint_ipv4_pair(src, dst).ok_or(EndpointError::InvalidArgument)?;
        let dst_ip = crate::net::l3::ipv4::Ipv4Address::new(dst_v4);

        // 非同期イベントキュー経由で送信（ロック競合回避）
        if crate::net::runtime::stack::send_udp_async(src.port(), dst_ip, dst.port(), payload) {
            Ok(())
        } else {
            Err(EndpointError::ResourceExhausted)
        }
    }

    /// ICMP Echo Requestイベント処理（スタックロックを取得して送信）
    fn handle_icmp_echo_request(&self, target: [u8; 4], sequence: u16) -> EventHandleResult {
        match crate::net::runtime::bridge::send_real_icmp_echo(target, sequence) {
            Ok(_ts) => EventHandleResult::Success,
            Err(_e) => EventHandleResult::ProtocolError(EndpointError::ResourceExhausted),
        }
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
    use crate::net::l4::endpoint::event::{event_queue, NetworkEvent};
    use crate::net::l4::endpoint::manager::init_endpoint_manager;
    use crate::net::l4::endpoint::{create_tcp_endpoint, create_udp_endpoint, EndpointAddr, EndpointState};
    use crate::net::l4::endpoint::tcb::{tcb_table, TcpConnectionState, TcpControlBlockEntry};

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
        assert!(matches!(res, EventHandleResult::Retry | EventHandleResult::Success));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_send_udp_packet_rejects_mixed_family() {
        let handler = NetworkEventHandler::new();
        let local = EndpointAddr::new([127, 0, 0, 1], 12345);
        let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 8080);

        assert!(matches!(
            handler.send_udp_packet(local, remote, alloc::vec![0u8; 8]),
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

        let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 8080);
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
        let res = handler.handle_send_to(fd, EndpointAddr::new([127, 0, 0, 1], 8081), alloc::vec![9]);
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
    use crate::net::l4::endpoint::event::{event_queue, NetworkEvent};
    use crate::net::l4::endpoint::manager::init_endpoint_manager;
    use crate::net::l4::endpoint::{create_tcp_endpoint, EndpointAddr, EndpointState};
    use crate::net::l4::endpoint::tcb::{tcb_table, TcpConnectionState, TcpControlBlockEntry};

    pub fn handle_tx_available_requeues_dataready_smoke() -> bool {
        init_endpoint_manager();

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
