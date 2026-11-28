// ============================================================================
// kernel/src/net/runtime/stack/core_impl/receive.rs - ランタイム / スタック / コア実装 / 受信処理
// ============================================================================

// =============================================================================
// Receive Path — IPv4/IPv6 incoming packet processing
//
// Split from core_impl/mod.rs for clarity. Contains all methods that process
// incoming packets: process_ipv4, process_ipv6_data, process_icmpv6_data,
// process_ndp_message, process_igmp_payload, etc.
// =============================================================================

use super::*;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::transport::tcp_table_in;

impl NetworkStack {
    pub fn process_icmp_payload(
        &mut self,
        runtime: NetRuntimeHandle,
        ingress_if_id: NetIfId,
        payload: kernel_api::resource::net::PacketPayload,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        _ttl: u8,
        current_time: u64,
    ) {
        let Some(ingress_config) = self.interface_config(ingress_if_id) else {
            return;
        };
        if dst_ip.is_broadcast()
            || dst_ip.is_multicast()
            || dst_ip == ingress_config.ipv4.broadcast_address()
        {
            return;
        }

        let result = {
            let Some(state) = self.interfaces.get_mut(&ingress_if_id) else {
                return;
            };
            state
                .icmp
                .process_payload(&payload, src_ip, dst_ip, current_time)
        };

        match result {
            IcmpResult::SendEchoReply {
                src_ip,
                identifier,
                sequence,
                data_offset,
                data_len,
            } => {
                if !ingress_config.icmp_echo_enabled {
                    return;
                }
                let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                    &payload,
                    data_offset,
                    data_len,
                ) else {
                    self.record_rx_error_on(ingress_if_id);
                    return;
                };
                let Some(echo_data) = bounds
                    .take_from(payload)
                    .and_then(|window| window.into_payload().ok())
                else {
                    self.record_rx_error_on(ingress_if_id);
                    return;
                };
                self.send_icmp_echo_reply_payload(
                    ingress_if_id,
                    src_ip,
                    identifier,
                    sequence,
                    echo_data,
                    current_time,
                );
            }
            IcmpResult::EchoReplyReceived { sequence } => {
                let rtt_us = 0;
                crate::net::api::icmp::notify_icmp_echo_reply_in(
                    runtime,
                    *src_ip.as_bytes(),
                    sequence,
                    rtt_us,
                );
                let _ = crate::net::runtime::command::try_enqueue_command_in(
                    self.runtime,
                    crate::net::runtime::command::RuntimeCommand::Control(
                        crate::net::runtime::command::ControlCommand::IcmpEchoReply {
                            source: *src_ip.as_bytes(),
                            sequence,
                            rtt_us,
                        },
                    ),
                );
            }
            IcmpResult::Error { icmp_type, code } => {
                self.handle_icmp_error_payload(
                    runtime,
                    ingress_if_id,
                    &payload,
                    icmp_type,
                    code,
                    current_time,
                );
            }
            IcmpResult::Redirect {
                code,
                gateway,
                destination,
            } => {
                self.handle_icmp_redirect(ingress_if_id, code, gateway, destination, src_ip);
            }
            IcmpResult::SendTimestampReply {
                src_ip,
                identifier,
                sequence,
                originate_ts,
                receive_ts,
                transmit_ts,
            } => {
                self.send_icmp_timestamp_reply(
                    ingress_if_id,
                    src_ip,
                    identifier,
                    sequence,
                    originate_ts,
                    receive_ts,
                    transmit_ts,
                    current_time,
                );
            }
            IcmpResult::Invalid => self.record_rx_error_on(ingress_if_id),
            IcmpResult::Ignored => {}
        }
    }

    /// Process IPv6 packet data
    pub fn process_ipv6_data(
        &mut self,
        runtime: NetRuntimeHandle,
        if_id: super::NetIfId,
        current_time: u64,
        src_mac: MacAddress,
        packet_ref: PacketRef,
        headers: crate::net::l3::ipv6::Ipv6HeaderChain,
    ) {
        let ingress_if_id = if_id;
        let result = {
            if let Some(state) = self.interfaces.get_mut(&ingress_if_id) {
                if let Some(ref mut ipv6) = state.ipv6 {
                    ipv6.process_owned_packet(packet_ref, headers, current_time)
                } else {
                    return;
                }
            } else {
                return;
            }
        };

        match result {
            Ipv6ProcessResult::Icmpv6(packet, src, dst, hop_limit) => {
                let Ok(icmpv6_payload) = packet.into_payload() else {
                    self.record_rx_error_on(ingress_if_id);
                    return;
                };
                self.process_icmpv6_data(
                    runtime,
                    ingress_if_id,
                    icmpv6_payload,
                    src,
                    dst,
                    src_mac,
                    hop_limit,
                    current_time,
                );
            }
            Ipv6ProcessResult::Tcp(packet, src, dst, _hop_limit) => {
                let Ok(tcp_segment_payload) = packet.into_payload() else {
                    self.record_rx_error_on(ingress_if_id);
                    return;
                };
                crate::net::l4::tcp::tcp_rx::process_tcp_segment_v6_payload_on(
                    runtime,
                    ingress_if_id,
                    src,
                    dst,
                    tcp_segment_payload,
                );
            }
            Ipv6ProcessResult::Udp(packet, src, dst, hop_limit) => {
                self.process_udp_payload_v6(ingress_if_id, packet, src, dst, hop_limit);
            }
            Ipv6ProcessResult::Reassembled(payload) => {
                // Reassembled IPv6 payload is offloaded to endpoint async path.
                let _ = crate::net::runtime::command::try_enqueue_command_in(
                    self.runtime,
                    crate::net::runtime::command::RuntimeCommand::Ingress(
                        crate::net::runtime::command::IngressCommand::Reassembled {
                            if_id: ingress_if_id,
                            payload,
                        },
                    ),
                );
            }
            Ipv6ProcessResult::FragmentPending => {
                // Waiting for additional fragments.
            }
            Ipv6ProcessResult::ReassemblyError(err, src, _dst, quoted_packet) => match err {
                crate::net::l3::ipv6::Ipv6ReassemblyError::Overlap => {
                    // RFC 8200 / RFC 5722: overlapping fragments are silently dropped.
                    log::warn!(
                        "IPv6: Fragment overlap from {} - discarding (RFC 8200)",
                        src
                    );
                }
                crate::net::l3::ipv6::Ipv6ReassemblyError::ResourceLimit => {
                    log::warn!(
                        "IPv6: Fragment budget exceeded by datagram from {} - discarding",
                        src
                    );
                }
                crate::net::l3::ipv6::Ipv6ReassemblyError::InvalidSize
                | crate::net::l3::ipv6::Ipv6ReassemblyError::PacketTooLarge => {
                    // RFC 8200: Parameter Problem, pointer to Payload Length field.
                    self.send_icmpv6_parameter_problem_payload(
                        ingress_if_id,
                        src,
                        0,
                        4,
                        quoted_packet,
                    );
                }
                crate::net::l3::ipv6::Ipv6ReassemblyError::IncompleteHeaderChain => {
                    // RFC 7112: pointer targets first byte of Fragment Header.
                    let fragment_header_pointer =
                        (quoted_packet.total_len() as u32).saturating_sub(8);
                    self.send_icmpv6_parameter_problem_payload(
                        ingress_if_id,
                        src,
                        0,
                        fragment_header_pointer,
                        quoted_packet,
                    );
                }
            },
            Ipv6ProcessResult::UnknownNextHeader(_proto, pointer, src, _dst, orig_packet) => {
                // RFC 4443 Section 3.4: Parameter Problem (Code 1).
                self.send_icmpv6_parameter_problem_payload(
                    ingress_if_id,
                    src,
                    1,
                    pointer,
                    orig_packet,
                );
            }
            Ipv6ProcessResult::ParameterProblem(code, pointer, src, _dst, orig_packet) => {
                // RFC 4443 Section 3.4: Parameter Problem with specific code (e.g. Code 2 for Unrecognized Option).
                self.send_icmpv6_parameter_problem_payload(
                    ingress_if_id,
                    src,
                    code,
                    pointer,
                    orig_packet,
                );
            }
            Ipv6ProcessResult::HopLimitExceeded(src, _dst, orig_packet) => {
                // RFC 4443 Section 3.3: Time Exceeded (Code 0).
                self.send_icmpv6_time_exceeded_on(ingress_if_id, src, 0, orig_packet);
            }
            Ipv6ProcessResult::Dropped => self.record_dropped_on(ingress_if_id),
            Ipv6ProcessResult::Error => self.record_rx_error_on(ingress_if_id),
        }
    }

    // =========================================================================
    // IPv6 Processing
    // =========================================================================

    /// Process ICMPv6 data
    pub(crate) fn process_icmpv6_data(
        &mut self,
        runtime: NetRuntimeHandle,
        if_id: super::NetIfId,
        payload: kernel_api::resource::net::PacketPayload,
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: MacAddress,
        hop_limit: u8,
        current_time: u64,
    ) {
        let ingress_if_id = if_id;
        let Some(state) = self.interfaces.get(&ingress_if_id) else {
            return;
        };
        let Some(ref icmpv6) = state.icmpv6 else {
            return;
        };
        let result = icmpv6.process_payload(payload, src, dst, src_mac, hop_limit, current_time);

        match result {
            Icmpv6Result::SendEchoReply {
                dst: reply_dst,
                identifier,
                sequence,
                data: echo_data,
            } => {
                // SECURITY: RFC 4443 に従い multicast Echo Request へ応答しない。
                if dst.is_multicast() {
                    return;
                }

                // Choose source address: if the original request was to our global address,
                // use that as source for the reply.
                let mut reply_src = None;
                if let Some(config) = self
                    .interface_config_or_runtime(ingress_if_id)
                    .and_then(|cfg| cfg.ipv6)
                {
                    if config.addresses.assigned().any(|address| address == dst) {
                        reply_src = Some(dst);
                    }
                    if reply_src.is_none() {
                        reply_src = config.addresses.link_local();
                    }
                }

                if let Some(src_addr) = reply_src {
                    self.send_icmpv6_echo_reply_with_src_on(
                        ingress_if_id,
                        src_addr,
                        reply_dst,
                        identifier,
                        sequence,
                        echo_data,
                    );
                }
            }
            Icmpv6Result::EchoReplyReceived {
                identifier,
                sequence,
            } => {
                log::info!(
                    "ICMPv6: Echo Reply received id={} seq={}",
                    identifier,
                    sequence
                );
            }
            Icmpv6Result::NdpMessage {
                msg_type,
                data: ndp_data,
                src: ndp_src,
                dst: ndp_dst,
                src_mac: ndp_src_mac,
                hop_limit,
            } => {
                self.process_ndp_message(
                    runtime,
                    ingress_if_id,
                    msg_type,
                    ndp_data,
                    ndp_src,
                    ndp_dst,
                    ndp_src_mac,
                    hop_limit,
                    current_time,
                );
            }
            Icmpv6Result::PacketTooBig {
                quoted_src,
                dst,
                mtu,
                quoted_packet,
            } => {
                let local = self
                    .interface_config_or_runtime(ingress_if_id)
                    .and_then(|config| config.ipv6)
                    .is_some_and(|config| {
                        config.addresses.assigned().any(|addr| addr == quoted_src)
                    });
                if !local
                    || !matches_ipv6_pmtu_quote(
                        runtime,
                        ingress_if_id,
                        quoted_src,
                        dst,
                        mtu,
                        &quoted_packet,
                    )
                {
                    return;
                }
                let now = self.current_time();
                if let Some(state) = self.interfaces.get_mut(&ingress_if_id) {
                    state.ipv6_pmtu_cache.update(dst, mtu, now);
                }
            }

            Icmpv6Result::DestinationUnreachable {
                code,
                quoted_src,
                quoted_dst,
                quoted_packet,
            } => {
                log::warn!(
                    "ICMPv6: Destination Unreachable (code={}) src={} dst={}",
                    code,
                    quoted_src,
                    quoted_dst
                );
                self.handle_icmpv6_error_transport_notification(
                    runtime,
                    ingress_if_id,
                    quoted_src,
                    quoted_dst,
                    Icmpv6Type::DestinationUnreachable,
                    code,
                    &quoted_packet,
                );
            }
            Icmpv6Result::TimeExceeded {
                code,
                quoted_src,
                quoted_dst,
                quoted_packet,
            } => {
                log::warn!(
                    "ICMPv6: Time Exceeded (code={}) src={} dst={}",
                    code,
                    quoted_src,
                    quoted_dst
                );
                self.handle_icmpv6_error_transport_notification(
                    runtime,
                    ingress_if_id,
                    quoted_src,
                    quoted_dst,
                    Icmpv6Type::TimeExceeded,
                    code,
                    &quoted_packet,
                );
            }
            Icmpv6Result::ParameterProblem {
                code,
                pointer,
                quoted_src,
                quoted_dst,
                quoted_packet,
            } => {
                log::warn!(
                    "ICMPv6: Parameter Problem (code={}, pointer={}) src={} dst={}",
                    code,
                    pointer,
                    quoted_src,
                    quoted_dst
                );
                self.handle_icmpv6_error_transport_notification(
                    runtime,
                    ingress_if_id,
                    quoted_src,
                    quoted_dst,
                    Icmpv6Type::ParameterProblem,
                    code,
                    &quoted_packet,
                );
            }
            Icmpv6Result::Dropped | Icmpv6Result::Error => {}
        }
    }

    /// ND may report a duplicate while an address is still unavailable to IP.
    fn process_tentative_neighbor_message(
        &mut self,
        if_id: NetIfId,
        kind: Icmpv6Type,
        payload: &PacketPayload,
        src: Ipv6Address,
        dst: Ipv6Address,
    ) -> bool {
        use crate::net::runtime::manager::{self, DadEvent};

        if !matches!(
            kind,
            Icmpv6Type::NeighborSolicitation | Icmpv6Type::NeighborAdvertisement
        ) {
            return false;
        }
        let view = PacketPayloadView::new(payload);
        let Some(target) = view.read_array::<16>(8).map(Ipv6Address::new) else {
            return false;
        };
        if !self
            .interface_config(if_id)
            .and_then(|config| config.ipv6)
            .is_some_and(|ipv6| {
                ipv6.addresses
                    .entries
                    .iter()
                    .flatten()
                    .any(|entry| entry.address == target && !entry.assigned())
            })
        {
            return false;
        }
        if view.read_array::<1>(1) != Some([0]) || target.is_multicast() {
            return true;
        }

        let solicitation = kind == Icmpv6Type::NeighborSolicitation;
        if solicitation {
            if !src.is_unspecified() || dst != target.solicited_node() {
                return true;
            }
        } else if src.is_unspecified()
            || (dst.is_multicast()
                && view
                    .read_array::<1>(4)
                    .is_some_and(|[flags]| flags & 0x40 != 0))
        {
            return true;
        }

        let mut nonce = None;
        let mut offset = 24;
        // LOOP_PROOF: mode=bounded; reason=Each valid ND option advances by at least eight bytes within the payload.;
        while offset < view.total_len() {
            let Some([option, units]) = view.read_array::<2>(offset) else {
                return true;
            };
            let len = usize::from(units) * 8;
            if len == 0 || len > view.total_len() - offset || (solicitation && option == 1) {
                return true;
            }
            if solicitation && option == 14 && units == 1 {
                nonce = view.read_array::<6>(offset + 2);
            }
            offset += len;
        }

        if manager::update_ipv6_dad_in(
            self.runtime,
            if_id,
            target,
            DadEvent::Conflict {
                received_nonce: nonce,
            },
        )
        .is_ok_and(|changed| changed)
        {
            self.refresh_interface_topology();
        }
        true
    }

    /// Process NDP message
    pub(crate) fn process_ndp_message(
        &mut self,
        runtime: NetRuntimeHandle,
        if_id: super::NetIfId,
        msg_type: crate::net::l3::icmpv6::Icmpv6Type,
        payload: kernel_api::resource::net::PacketPayload,
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: MacAddress,
        hop_limit: u8,
        current_time: u64,
    ) {
        // SECURITY: RFC 4861 Section 6.1.1 に従い、IP Hop Limit は 255 でなければならない。
        // This ensures the packet was not forwarded by a router.
        if hop_limit != 255 {
            log::warn!("NDP: Dropping packet with invalid hop limit {}", hop_limit);
            return;
        }

        if self.process_tentative_neighbor_message(if_id, msg_type, &payload, src, dst) {
            return;
        }
        let ingress_if_id = if_id;
        let result = {
            let Some(state) = self.interfaces.get_mut(&ingress_if_id) else {
                return;
            };
            let Some(ref mut ndp) = state.ndp else {
                return;
            };
            ndp.process_payload(
                msg_type,
                &payload,
                src,
                dst,
                *src_mac.as_bytes(),
                current_time,
            )
        };

        match result {
            NdpResult::SendNeighborAdvertisement {
                dst: na_dst,
                target,
                our_mac,
                solicited,
            } => {
                // Get our link-local address
                let our_addr = self
                    .interface_config_or_runtime(ingress_if_id)
                    .and_then(|cfg| cfg.ipv6)
                    .and_then(|cfg| cfg.addresses.link_local());
                if let Some(our_addr) = our_addr {
                    let Some(na_msg) =
                        NdpProcessor::build_na(&our_addr, &na_dst, &target, &our_mac, solicited)
                    else {
                        self.record_dropped_on(ingress_if_id);
                        return;
                    };
                    self.send_ipv6_icmpv6_on(ingress_if_id, &our_addr, &na_dst, na_msg);
                    log::info!("NDP: Sent NA for {} to {}", target, na_dst);
                }
            }
            NdpResult::SendNeighborAdvertisementMulticast { target, our_mac } => {
                // Get our link-local address
                let our_addr = self
                    .interface_config_or_runtime(ingress_if_id)
                    .and_then(|cfg| cfg.ipv6)
                    .and_then(|cfg| cfg.addresses.link_local());
                if let Some(our_addr) = our_addr {
                    let mcast_dst = Ipv6Address::ALL_NODES_LINK_LOCAL;
                    let Some(na_msg) = NdpProcessor::build_na(
                        &our_addr, &mcast_dst, &target, &our_mac,
                        false, // solicited = false for multicast defense
                    ) else {
                        self.record_dropped_on(ingress_if_id);
                        return;
                    };
                    self.send_ipv6_icmpv6_on(ingress_if_id, &our_addr, &mcast_dst, na_msg);
                    log::info!(
                        "NDP: Sent Multicast NA for {} to defend address (DAD)",
                        target
                    );
                }
            }
            NdpResult::NeighborUpdated { ip, mac } => {
                log::info!(
                    "NDP: Neighbor {} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ip,
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                );

                // NDP解決完了をウェイターレジストリへ通知（非同期NdpResolveFuture向け）
                crate::net::l3::ndp::notify_ndp_resolved_in(
                    runtime,
                    ingress_if_id,
                    ip.octets(),
                    mac,
                );

                // Drain any pending packets for this now-resolved neighbor (local core)
                self.drain_ndp_pending_on(ingress_if_id, &ip);

                // Broadcast NeighborResolvedV6 to all Per-Core queues for cross-core NDP cache update + pending drain
                let ip_bytes = ip.octets();
                let mac_bytes = mac;
                crate::net::runtime::command::broadcast_command_in(runtime, move || {
                    crate::net::runtime::command::RuntimeCommand::Control(
                        crate::net::runtime::command::ControlCommand::NeighborResolvedV6 {
                            if_id: ingress_if_id,
                            ip: ip_bytes,
                            mac: mac_bytes,
                        },
                    )
                });
            }
            NdpResult::RouterAdvertisement {
                router,
                router_lifetime_secs,
                prefixes,
            } => {
                match crate::net::runtime::manager::learn_ipv6_ra_in(
                    self.runtime,
                    if_id,
                    router,
                    router_lifetime_secs,
                    &prefixes,
                    current_time,
                ) {
                    Ok(()) => self.refresh_interface_topology(),
                    Err(error) => {
                        log::warn!(
                            "[NET] IPv6 router advertisement on if{} rejected: {:?}",
                            if_id.0,
                            error
                        );
                        return;
                    }
                }
            }
            NdpResult::Redirect {
                target,
                destination,
            } => {
                // SECURITY: check 0: Redirect handling が global に有効か確認する。
                let redirects_enabled = self
                    .interface_config(if_id)
                    .is_some_and(|config| config.icmpv6_redirect_enabled);
                if !redirects_enabled {
                    log::warn!(
                        "NDP: Ignoring Redirect for {} to target router {} (Security: disabled by default)",
                        destination,
                        target
                    );
                } else {
                    log::info!(
                        "NDP: Applying Redirect for {} to target router {}",
                        destination,
                        target
                    );
                    // Update IPv6 Path MTU or routing table with redirect info
                    // Currently we don't have a separate IPv6 redirect cache like IPv4,
                    // but we could theoretically update the neighbor cache (already done in process_redirect).
                }
            }
            NdpResult::None | NdpResult::Error => {}
        }
    }

    pub fn process_igmp_payload(
        &mut self,
        if_id: NetIfId,
        payload: &kernel_api::resource::net::PacketPayload,
        src_ip: Ipv4Address,
        ttl: u8,
    ) {
        if ttl != 1 {
            log::warn!("IGMP: Dropping packet with invalid TTL {}", ttl);
            return;
        }

        let Some(config) = self.interface_config(if_id) else {
            return;
        };
        let local_ip = config.ipv4.address;
        let subnet_mask = config.ipv4.subnet_mask;
        if local_ip.apply_mask(subnet_mask) != src_ip.apply_mask(subnet_mask) {
            log::warn!("IGMP: Dropping packet from different subnet {}", src_ip);
            return;
        }

        let current_time = self.current_time();
        let result = {
            let Some(state) = self.interfaces.get_mut(&if_id) else {
                return;
            };
            state.igmp.update_time(current_time);
            state.igmp.process_payload(payload, src_ip)
        };

        match result {
            IgmpResult::GeneralQueryReceived { max_resp_time: _ } => {}
            IgmpResult::GroupQueryReceived {
                group: _,
                max_resp_time: _,
            } => {}
            IgmpResult::ReportReceived { group: _ } => {}
            IgmpResult::Ignored => {}
            IgmpResult::InvalidPacket | IgmpResult::InvalidChecksum => {
                if let Some(stats) = self.interface_stats(if_id) {
                    stats.record_rx_error();
                }
            }
            IgmpResult::UnknownType(_) => {
                if let Some(stats) = self.interface_stats(if_id) {
                    stats.record_dropped();
                }
            }
        }

        self.send_pending_igmp_reports();
    }
}

/// PTB quotes can end before the original datagram ends, but must include
/// enough of a supported transport to associate the report with local traffic.
fn matches_ipv6_pmtu_quote(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    src: Ipv6Address,
    dst: Ipv6Address,
    mtu: u32,
    packet: &PacketPayload,
) -> bool {
    use crate::net::l4::EndpointAddr;

    let view = PacketPayloadView::new(packet);
    let Some([version, _, _, _, len_hi, len_lo]) = view.read_array::<6>(0) else {
        return false;
    };
    let original_len = u32::from(u16::from_be_bytes([len_hi, len_lo])) + 40;
    if version >> 4 != 6 || mtu < 1280 || mtu >= original_len {
        return false;
    }
    let Some((protocol, transport)) = crate::net::payload::ipv6_transport_payload(packet) else {
        return false;
    };
    // Do not interpret bytes past the end of the original IP payload as transport.
    let offset = view.total_len() - transport.total_len();
    if offset + 8 > original_len as usize {
        return false;
    }
    let Some([sh, sl, dh, dl, a, b, c, d]) = transport.read_array::<8>(0) else {
        return false;
    };
    let local_port = u16::from_be_bytes([sh, sl]);
    let remote_port = u16::from_be_bytes([dh, dl]);
    match protocol {
        IpProtocol::Tcp => tcp_table_in(runtime).validate_icmp_sequence(
            if_id,
            EndpointAddr::new_v6(src.octets(), local_port),
            EndpointAddr::new_v6(dst.octets(), remote_port),
            u32::from_be_bytes([a, b, c, d]),
        ),
        IpProtocol::Udp => {
            let udp_len = usize::from(u16::from_be_bytes([a, b]));
            udp_len >= 8
                && offset + udp_len == original_len as usize
                && [c, d] != [0, 0]
                && remote_port != 0
                && crate::net::l4::socket::find_udp_by_port_in(runtime, local_port, if_id).is_some()
        }
        _ => false,
    }
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod tests {
    use super::*;
    use crate::net::l4::test_support::packet_fixture_with_data;
    use crate::net::l4::udp::UdpEndpoint;
    use crate::net::types::InterfaceScope;

    #[test]
    fn ipv6_pmtu_requires_transport_evidence_on_the_ingress_interface() {
        let runtime = crate::net::runtime::create_runtime().expect("isolated runtime");
        let if_id = NetIfId(1);
        let local = Ipv6Address::from_eui64(&[2, 0, 0, 0, 0, 1]);
        let remote = Ipv6Address::from_eui64(&[2, 0, 0, 0, 0, 2]);
        let _endpoint = UdpEndpoint::bind_in(runtime, InterfaceScope::Pinned(if_id), 12345, None)
            .expect("UDP endpoint");

        let mut quote = [0u8; 48];
        quote[0] = 0x60;
        quote[4..6].copy_from_slice(&1460u16.to_be_bytes());
        quote[6] = u8::from(IpProtocol::Udp);
        quote[8..24].copy_from_slice(local.as_bytes());
        quote[24..40].copy_from_slice(remote.as_bytes());
        quote[40..42].copy_from_slice(&12345u16.to_be_bytes());
        quote[42..44].copy_from_slice(&53u16.to_be_bytes());
        quote[44..46].copy_from_slice(&1460u16.to_be_bytes());
        quote[46..48].copy_from_slice(&1u16.to_be_bytes());

        let matches = |interface, mtu, bytes: &[u8]| {
            let packet = PacketPayload::try_single(packet_fixture_with_data(bytes)).expect("quote");
            matches_ipv6_pmtu_quote(runtime, interface, local, remote, mtu, &packet)
        };
        assert!(matches(if_id, 1280, &quote));
        assert!(!matches(NetIfId(2), 1280, &quote));
        assert!(!matches(if_id, 1279, &quote));
        assert!(!matches(if_id, 1500, &quote));
        assert!(!matches(if_id, 1280, &quote[..44]));
        quote[6] = u8::from(IpProtocol::Tcp);
        assert!(!matches(if_id, 1280, &quote[..47]));
        assert!(!matches(if_id, 1280, &quote));
        quote[6] = u8::from(IpProtocol::Icmpv6);
        assert!(!matches(if_id, 1280, &quote));
        quote[6] = 0; // Extension header with no complete transport in the quote.
        assert!(!matches(if_id, 1280, &quote[..41]));
    }
}
