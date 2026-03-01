use super::*;
use super::NetIfId;


mod global_instance;
pub use global_instance::*;
mod igmp_multicast;
impl NetworkStack {
    /// Create a new network stack with configuration
    ///
    /// # パフォーマンス注意
    /// Ipv4Config が Clone を実装しているが、内部データが Copy なら
    /// clone() はゼロコストでインライン化される
    pub fn new(config: NetworkConfig) -> Self {
        let mac = config.mac;
        let ip = config.ipv4.address;

        // Note: ipv4.clone() は Ipv4Config が小さい構造体のため
        // アセンブリでは memcpy やレジスタコピーに展開される
        let (ipv6_proc, icmpv6_proc, ndp_proc) = if let Some(ref ipv6_config) = config.ipv6 {
            let mac_bytes = mac.as_bytes();
            (
                Some(Ipv6Processor::new(*ipv6_config)),
                Some(Icmpv6Processor::new(config.icmp_echo_enabled)),
                Some(NdpProcessor::new(ipv6_config.link_local, *mac_bytes)),
            )
        } else {
            (None, None, None)
        };

        NetworkStack {
            ethernet: EthernetProcessor::new(mac),
            ipv4: Ipv4Processor::new(config.ipv4.clone()),
            ipv6: ipv6_proc,
            arp: ArpProcessor::new(mac, ip),
            icmp: IcmpProcessor::new(ip),
            icmpv6: icmpv6_proc,
            igmp: IgmpProcessor::new(ip),
            ndp: ndp_proc,
            udp: UdpProcessor::new(),
            tcp: TcpProcessor::new(),
            tx_pool: PacketPool::new(64, MAX_PACKET_SIZE),
            config: config,
            stats: NetworkStats::default(),
            transmit_fn: None,
            current_time: AtomicU64::new(0),
            redirect_cache: RedirectCache::new(),
            ndp_pending_queue: NdpPendingQueue::new(),
            ipv6_fragment_reassembler: Ipv6FragmentReassembler::new(
                Ipv6FragmentReassembler::DEFAULT_MAX_BUFFERS,
            ),
            ipv6_pmtu_cache: Ipv6PmtuCache::new(Ipv6PmtuCache::DEFAULT_MAX_ENTRIES),
        }
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(NetworkConfig::default())
    }

    /// Set transmit callback
    pub fn set_transmit_fn(&mut self, f: TransmitFn) {
        self.transmit_fn = Some(f);
    }

    /// Update current time (call periodically)
    pub fn update_time(&self, ticks: u64) {
        self.current_time.store(ticks, Ordering::Release);
    }

    /// Get current time
    pub fn current_time(&self) -> u64 {
        self.current_time.load(Ordering::Acquire)
    }

    /// Get configuration (full clone - use sparingly)
    pub fn config(&self) -> NetworkConfig {
        self.config.clone()
    }

    /// ICMP echo が有効かチェック
    #[inline]
    pub fn icmp_echo_enabled(&self) -> bool {
        self.config.icmp_echo_enabled
    }

    /// MAC アドレスを取得
    #[inline]
    pub fn mac_address(&self) -> MacAddress {
        self.config.mac
    }

    /// IPv4 アドレスを取得
    #[inline]
    pub fn ipv4_address(&self) -> Ipv4Address {
        self.config.ipv4.address
    }

    /// Update configuration
    pub fn set_config(&mut self, config: NetworkConfig) {
        // Update all processors
        self.ethernet.set_local_mac(config.mac);
        self.ipv4.set_config(config.ipv4.clone());
        self.arp.set_local(config.mac, config.ipv4.address);

        self.config = config;
    }

    /// Get statistics
    pub fn stats(&self) -> &NetworkStats {
        &self.stats
    }

    /// Process an incoming packet (main entry point)
    pub fn receive(&mut self, packet: PacketRef) {
        let current_time = self.current_time();
        let pkt_len = packet.len();

        // Process Ethernet frame (zero-copy via PacketRef view)
        let result = self.ethernet.process(packet.data());

        match result {
            ProcessResult::Ipv4(payload, src_mac) => {
                // Safety: Ensure payload is within packet bounds before offset calculation
                let pkt_data = packet.data();
                if payload.as_ptr() < pkt_data.as_ptr() || 
                   payload.as_ptr() as usize + payload.len() > pkt_data.as_ptr() as usize + pkt_data.len() {
                    self.stats.record_rx_error();
                    return;
                }
                let offset = unsafe { payload.as_ptr().offset_from(pkt_data.as_ptr()) } as usize;
                let mut ip_packet = packet.clone_ref();
                ip_packet.advance(offset);
                self.process_ipv4(payload, current_time, ip_packet, src_mac);
                self.stats.record_rx(pkt_len);
            }
            ProcessResult::Arp(payload, src_mac) => {
                self.process_arp(payload, current_time, src_mac);
                self.stats.record_rx(pkt_len);
            }
            ProcessResult::Ipv6(payload, src_mac) => {
                if self.ipv6.is_some() {
                    self.process_ipv6_data(payload, current_time, src_mac, false);
                    self.stats.record_rx(pkt_len);
                } else {
                    self.stats.record_dropped();
                }
            }
            ProcessResult::VlanTagged { vlan_id, pcp: _, dei: _, inner_type, payload, src_mac } => {
                // VLAN-tagged frame - process based on inner type
                // For now, we process the inner payload directly
                // In a full implementation, we would check VLAN membership
                let pkt_data = packet.data();
                if payload.as_ptr() < pkt_data.as_ptr() || 
                   payload.as_ptr() as usize + payload.len() > pkt_data.as_ptr() as usize + pkt_data.len() {
                    self.stats.record_rx_error();
                    return;
                }
                let offset = unsafe { payload.as_ptr().offset_from(pkt_data.as_ptr()) } as usize;
                let mut inner_packet = packet.clone_ref();
                inner_packet.advance(offset);

                match inner_type {
                    EtherType::Ipv4 => {
                        self.process_ipv4(payload, current_time, inner_packet, src_mac);
                        self.stats.record_rx(pkt_len);
                    }
                    EtherType::Arp => {
                        self.process_arp(payload, current_time, src_mac);
                        self.stats.record_rx(pkt_len);
                    }
                    EtherType::Ipv6 => {
                        if self.ipv6.is_some() {
                            self.process_ipv6_data(payload, current_time, src_mac, false);
                            self.stats.record_rx(pkt_len);
                        } else {
                            self.stats.record_dropped();
                        }
                    }
                    _ => {
                        // Unsupported inner protocol
                        self.stats.record_dropped();
                    }
                }

                // Log VLAN info if needed
                let _ = vlan_id; // VLAN ID can be used for filtering/routing
            }
            ProcessResult::Dropped => {
                self.stats.record_dropped();
            }
            ProcessResult::Error => {
                self.stats.record_rx_error();
            }
        }
    }


    /// Process a batch of incoming packets
    pub fn receive_batch(&mut self, batch: PacketBatch) {
        // Since we are already holding the lock (caller must lock),
        // we can process packets in a loop efficiently.
        for packet in batch {
            // Processing logic is identical to single packet receive
            // receive() takes ownership of PacketRef
            self.receive(packet);
        }
    }

    /// Process IPv4 packet
    pub(super) fn process_ipv4(&mut self, data: &[u8], current_time: u64, packet: PacketRef, _src_mac: MacAddress) {
        let result = self.ipv4.process_with_time(data, current_time);

        match result {
            Ipv4ProcessResult::Icmp(payload, src_ip, dst_ip, ttl) => {
                if payload.as_ptr() < data.as_ptr() || 
                   payload.as_ptr() as usize + payload.len() > data.as_ptr() as usize + data.len() {
                    self.stats.record_rx_error();
                    return;
                }
                let offset = unsafe { payload.as_ptr().offset_from(data.as_ptr()) } as usize;
                let mut p = packet;
                p.advance(offset);
                self.process_icmp(payload, src_ip, dst_ip, ttl, current_time, p);
            }
            Ipv4ProcessResult::Igmp(payload, src_ip, ttl) => {
                self.process_igmp_data(payload, src_ip, ttl);
            }
            Ipv4ProcessResult::Udp(payload, src_ip, dst_ip) => {
                if payload.as_ptr() < data.as_ptr() || 
                   payload.as_ptr() as usize + payload.len() > data.as_ptr() as usize + data.len() {
                    self.stats.record_rx_error();
                    return;
                }
                let offset = unsafe { payload.as_ptr().offset_from(data.as_ptr()) } as usize;
                let mut p = packet;
                p.advance(offset);
                self.process_udp(payload, src_ip, dst_ip, p);
            }
            Ipv4ProcessResult::Tcp(payload, src_ip, dst_ip) => {
                if payload.as_ptr() < data.as_ptr() || 
                   payload.as_ptr() as usize + payload.len() > data.as_ptr() as usize + data.len() {
                    self.stats.record_rx_error();
                    return;
                }
                let offset = unsafe { payload.as_ptr().offset_from(data.as_ptr()) } as usize;
                let mut p = packet;
                p.advance(offset);
                self.process_tcp(payload, src_ip, dst_ip, p, current_time);
            }
            Ipv4ProcessResult::Reassembled(reassembled_data) => {
                // Process reassembled packet recursively
                // The reassembled data is a complete IP packet
                self.process_reassembled_packet(&reassembled_data, current_time, _src_mac);
            }
            Ipv4ProcessResult::FragmentPending => {
                // Fragment received, waiting for more fragments
                // Nothing to do here
            }
            Ipv4ProcessResult::Dropped => {
                self.stats.record_dropped();
            }
            Ipv4ProcessResult::Error => {
                self.stats.record_rx_error();
            }
            Ipv4ProcessResult::Success => {}
        }
    }

    /// Process a reassembled IP packet
    pub(super) fn process_reassembled_packet(&mut self, data: &[u8], current_time: u64, _src_mac: MacAddress) {
        // Parse the reassembled packet
        if let Some(packet) = Ipv4Packet::parse(data) {
            let src = packet.source();
            let dst = packet.destination();
            let payload = packet.payload();

            match packet.protocol() {
                IpProtocol::Icmp => {
                    // Process ICMP directly without PacketRef
                    self.process_icmp_data(payload, src, dst, packet.ttl(), current_time);
                }
                IpProtocol::Igmp => {
                    // Process IGMP for multicast group management
                    self.process_igmp_data(payload, src, packet.ttl());
                }
                IpProtocol::Udp => {
                    // Process UDP directly without PacketRef
                    self.process_udp_data(payload, src, dst);
                }
                IpProtocol::Tcp => {
                    // Process TCP directly without PacketRef
                    self.process_tcp_data(payload, src, dst, current_time);
                }
                _ => {
                    self.stats.record_dropped();
                }
            }
        }
    }

    /// Process ICMP data (for reassembled packets)
    pub(super) fn process_icmp_data(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        _ttl: u8,
        current_time: u64,
    ) {
        if !self.icmp_echo_enabled() {
            return;
        }

        // Security: Do not respond to broadcast/multicast ICMP Echo Requests (Smurf attack prevention)
        if dst_ip.is_broadcast()
            || dst_ip.is_multicast()
            || dst_ip == self.ipv4.config().broadcast_address()
        {
            return;
        }

        let result = self.icmp.process(data, src_ip, dst_ip, current_time);

        match result {
            IcmpResult::SendEchoReply {
                src_ip,
                identifier,
                sequence,
                data_offset,
                data_len,
            } => {
                let echo_data = if data_offset + data_len <= data.len() {
                    &data[data_offset..data_offset + data_len]
                } else {
                    &[]
                };
                self.send_icmp_echo_reply(src_ip, identifier, sequence, echo_data, current_time);
            }
            IcmpResult::EchoReplyReceived { identifier, sequence } => {
                let _ = (identifier, sequence);
            }
            IcmpResult::Error { icmp_type, code } => {
                // Handle ICMP errors for PMTUD (RFC 1191)
                self.handle_icmp_error(data, icmp_type, code, current_time);
            }
            IcmpResult::Redirect { code, gateway, destination } => {
                // Handle ICMP Redirect for route optimization (RFC 792)
                self.handle_icmp_redirect(code, gateway, destination, src_ip);
            }
            _ => {}
        }
    }

    // =========================================================================
    // IPv6 Processing
    // =========================================================================

    /// Process IPv6 packet data
    pub(super) fn process_ipv6_data(&mut self, data: &[u8], current_time: u64, src_mac: MacAddress, reassembled: bool) {
        let ipv6 = match self.ipv6 {
            Some(ref ipv6) => ipv6,
            None => return,
        };

        // Security: Minimum length and version check (RFC 8200)
        if data.len() < 40 || (data[0] >> 4) != 6 {
            self.stats.record_header_error();
            return;
        }

        // Check for fragment header before normal processing
        use crate::net::l3::ipv6::{skip_extension_headers_fraginfo, ExtHeaderResult};
        match skip_extension_headers_fraginfo(data) {
            ExtHeaderResult::Fragment {
                unfragmentable,
                frag_header,
                frag_payload,
            } => {
                // Security (RFC 8200): A packet must not contain more than one Fragment header.
                // If this packet was already reassembled, it must not contain another Fragment header.
                if reassembled {
                    log::warn!("[NET-IPV6] Dropping packet with nested Fragment header");
                    self.stats.record_dropped();
                    return;
                }

                // Extract dst from fixed header at offset 24
                let dst = crate::net::l3::ipv6::Ipv6Address::new([
                    data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
                    data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
                ]);

                // Security: Check if the packet is for us before adding to reassembly buffer (DoS prevention)
                if !ipv6.is_for_us(&dst) {
                    self.stats.record_dropped();
                    return;
                }

                // Extract src from fixed header at offset 8
                let src = crate::net::l3::ipv6::Ipv6Address::new([
                    data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
                    data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
                ]);

                let (reassembled_pkt, expired) = self.ipv6_fragment_reassembler.process_fragment(
                    src,
                    dst,
                    unfragmentable,
                    &frag_header,
                    frag_payload,
                    current_time,
                );

                // Handle expired fragments by sending ICMPv6 Time Exceeded
                for (exp_src, exp_dst, unfrag) in expired {
                    // RFC 8200: Send Fragment Reassembly Time Exceeded
                    // code 1 = fragment reassembly time exceeded
                    
                    // Security: Rate limit ICMPv6 error messages (RFC 4443)
                    if let Some(ref icmpv6) = self.icmpv6 {
                        if !icmpv6.check_tx_rate_limit(current_time) {
                            continue;
                        }
                    }

                    let time_exceeded = crate::net::l3::icmpv6::Icmpv6EchoBuilder::build_time_exceeded(
                        &exp_dst, &exp_src, 1, &unfrag
                    );
                    self.send_ipv6_icmpv6(&exp_dst, &exp_src, &time_exceeded);
                }

                if let Some(reassembled_data) = reassembled_pkt {
                    // Recursively process the reassembled (non-fragmented) packet
                    // Set reassembled=true to prevent further fragmentation processing
                    self.process_ipv6_data(&reassembled_data, current_time, src_mac, true);
                }
                return;
            }
            ExtHeaderResult::NoFragment(_, _) => {
                // Fall through to normal processing
            }
        }

        let result = ipv6.process(data);

        match result {
            Ipv6ProcessResult::Icmpv6(payload, src, dst, hop_limit) => {
                self.process_icmpv6_data(payload, src, dst, src_mac, hop_limit, current_time);
            }
            Ipv6ProcessResult::Tcp(payload, src, dst) => {
                self.process_tcp_data_v6(payload, src, dst, current_time);
            }
            Ipv6ProcessResult::Udp(payload, src, dst) => {
                self.process_udp_data_v6(payload, src, dst);
            }
            Ipv6ProcessResult::Dropped => {
                self.stats.record_dropped();
            }
            Ipv6ProcessResult::Error => {
                self.stats.record_rx_error();
            }
        }
    }

    /// Process ICMPv6 data
    pub(super) fn process_icmpv6_data(
        &mut self,
        data: &[u8],
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: MacAddress,
        hop_limit: u8,
        current_time: u64,
    ) {
        // Security: Do not respond to multicast Echo Requests (Smurf attack prevention)
        if dst.is_multicast() {
            return;
        }

        let icmpv6 = match self.icmpv6 {
            Some(ref icmpv6) => icmpv6,
            None => return,
        };

        let result = icmpv6.process(data, src, dst, src_mac, hop_limit, current_time);

        match result {
            Icmpv6Result::SendEchoReply {
                dst: reply_dst,
                identifier,
                sequence,
                data: echo_data,
            } => {
                // Choose source address: if the original request was to our global address, 
                // use that as source for the reply.
                let mut reply_src = None;
                if let Some(ref ipv6) = self.ipv6 {
                    let config = ipv6.config();
                    if let Some(global) = config.global {
                        if dst == global {
                            reply_src = Some(global);
                        }
                    }
                    if reply_src.is_none() {
                        reply_src = Some(config.link_local);
                    }
                }

                if let Some(src_addr) = reply_src {
                    self.send_icmpv6_echo_reply_with_src(src_addr, reply_dst, identifier, sequence, &echo_data);
                }
            }
            Icmpv6Result::EchoReplyReceived {
                src: _,
                identifier,
                sequence,
            } => {
                log::info!("ICMPv6: Echo Reply received id={} seq={}", identifier, sequence);
            }
            Icmpv6Result::NdpMessage {
                msg_type,
                data: ndp_data,
                src: ndp_src,
                dst: ndp_dst,
                src_mac: ndp_src_mac,
                hop_limit,
            } => {
                self.process_ndp_message(msg_type, &ndp_data, ndp_src, ndp_dst, ndp_src_mac, hop_limit, current_time);
            }
            Icmpv6Result::PacketTooBig { quoted_src, dst, mtu, quoted_packet } => {
                // Security check (RFC 8201 / RFC 5927): Verify that the ICMPv6 message quotes 
                // a packet that we actually sent and corresponds to an active connection.
                let mut is_our_packet = false;
                if let Some(ref ipv6) = self.ipv6 {
                    let config = ipv6.config();
                    if quoted_src == config.link_local {
                        is_our_packet = true;
                    } else if let Some(global) = config.global {
                        if quoted_src == global {
                            is_our_packet = true;
                        }
                    }
                }

                if is_our_packet {
                    // Further validation: check transport layer (ports/sequence numbers)
                    // Quoted packet starts with an IPv6 header (40 bytes)
                    if quoted_packet.len() >= 40 {
                        let next_header = quoted_packet[6];
                        let payload = &quoted_packet[40..];

                        // Skip extension headers to find the upper-layer header
                        use crate::net::l3::ipv6::skip_extension_headers;
                        let (final_proto, transport_data) = skip_extension_headers(IpProtocol::from(next_header), payload);

                        match final_proto {
                            IpProtocol::Tcp => {
                                if transport_data.len() >= 8 {
                                    let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                                    let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);
                                    let seq_num = u32::from_be_bytes([transport_data[4], transport_data[5], transport_data[6], transport_data[7]]);

                                    use crate::net::l4::tcp::SocketAddr as TcpSocketAddr;
                                    let local_addr = TcpSocketAddr::new_v6(quoted_src, src_port);
                                    let remote_addr = TcpSocketAddr::new_v6(dst, dst_port);

                                    if !self.tcp.validate_icmp_sequence(local_addr, remote_addr, seq_num) {
                                        log::warn!("[NET] ICMPv6: PMTU error for {} rejected due to invalid TCP seq", dst);
                                        return;
                                    }
                                }
                            }
                            IpProtocol::Udp => {
                                if transport_data.len() >= 4 {
                                    let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                                    if !self.udp.has_socket(src_port) {
                                        log::warn!("[NET] ICMPv6: PMTU error for {} rejected (no UDP socket on port {})", dst, src_port);
                                        return;
                                    }
                                }
                            }
                            _ => {
                                // For other protocols, we've already checked the IP addresses
                            }
                        }
                    }

                    log::info!("ICMPv6: Packet Too Big for {}, MTU={}", dst, mtu);
                    // Update IPv6 Path MTU cache (RFC 8201)
                    let current_time = self.current_time();
                    self.ipv6_pmtu_cache.update(dst, mtu, current_time);
                } else {
                    log::warn!(
                        "ICMPv6: Packet Too Big for {} rejected (quoted src {} is not local)",
                        dst, quoted_src
                    );
                }
            }

            Icmpv6Result::Dropped | Icmpv6Result::Error => {}
        }
    }

    /// Process NDP message
    pub(super) fn process_ndp_message(
        &mut self,
        msg_type: crate::net::l3::icmpv6::Icmpv6Type,
        data: &[u8],
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: MacAddress,
        hop_limit: u8,
        current_time: u64,
    ) {
        // Security (RFC 4861 Section 6.1.1): The IP Hop Limit field MUST have a value of 255.
        // This ensures the packet was not forwarded by a router.
        if hop_limit != 255 {
            log::warn!("NDP: Dropping packet with invalid hop limit {}", hop_limit);
            return;
        }

        let ndp = match self.ndp {
            Some(ref mut ndp) => ndp,
            None => return,
        };

        let result = ndp.process(msg_type, data, src, dst, *src_mac.as_bytes(), current_time);

        match result {
            NdpResult::SendNeighborAdvertisement {
                dst: na_dst,
                target,
                our_mac,
                solicited,
            } => {
                // Get our link-local address
                if let Some(ref ipv6) = self.ipv6 {
                    let our_addr = ipv6.config().link_local;
                    let na_msg = NdpProcessor::build_na(
                        &our_addr,
                        &na_dst,
                        &target,
                        &our_mac,
                        solicited,
                    );
                    self.send_ipv6_icmpv6(&our_addr, &na_dst, &na_msg);
                    log::info!("NDP: Sent NA for {} to {}", target, na_dst);
                }
            }
            NdpResult::NeighborUpdated { ip, mac } => {
                log::info!(
                    "NDP: Neighbor {} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
                // Drain any pending packets for this now-resolved neighbor
                self.drain_ndp_pending(&ip);
            }
            NdpResult::RouterAdvertisement {
                router,
                router_mac: _,
                prefixes,
            } => {
                log::info!("NDP: Router Advertisement from {}, {} prefixes", router, prefixes.len());
                // SLAAC (RFC 4862): Apply prefix information
                for prefix_opt in &prefixes {
                    if let crate::net::l3::ndp::NdpOption::PrefixInfo {
                        prefix_len,
                        on_link: _,
                        autonomous,
                        valid_lifetime,
                        preferred_lifetime: _,
                        prefix,
                    } = prefix_opt
                    {
                        // Only process /64 autonomous prefixes with non-zero lifetime
                        if *autonomous && *prefix_len == 64 && *valid_lifetime > 0 {
                            if let Some(ref mut ipv6) = self.ipv6 {
                                let mac_bytes = self.config.mac.as_bytes();
                                let global_addr =
                                    Ipv6Address::from_prefix_eui64(prefix, mac_bytes);
                                // Only set if we don't already have this address
                                if ipv6.config().global != Some(global_addr) {
                                    ipv6.set_global_address(global_addr);
                                    log::info!(
                                        "SLAAC: Configured global address {} from prefix {}",
                                        global_addr, prefix
                                    );
                                }
                            }
                            if let Some(ref mut ndp) = self.ndp {
                                let mac_bytes = self.config.mac.as_bytes();
                                let global_addr =
                                    Ipv6Address::from_prefix_eui64(prefix, mac_bytes);
                                ndp.add_global_address(global_addr);
                            }
                        }
                    } else if let crate::net::l3::ndp::NdpOption::RecursiveDnsServer {
                        lifetime,
                        servers,
                    } = prefix_opt
                    {
                        if *lifetime > 0 {
                            for server in servers {
                                crate::net::services::dns::add_ipv6_server(*server);
                                log::info!("NDP: Added DNS server {} from RDNSS option", server);
                            }
                        }
                    }
                }
                // Set router as default gateway
                if let Some(ref mut ipv6) = self.ipv6 {
                    if ipv6.config().gateway.is_none() {
                        ipv6.config_mut().gateway = Some(router);
                        log::info!("SLAAC: Set default gateway to {}", router);
                    }
                }
            }
            NdpResult::None | NdpResult::Error => {}
        }
    }

    /// Send ICMPv6 Echo Reply with explicit source address
    pub(super) fn send_icmpv6_echo_reply_with_src(
        &mut self,
        src: Ipv6Address,
        dst: Ipv6Address,
        identifier: u16,
        sequence: u16,
        echo_data: &[u8],
    ) {
        // Build ICMPv6 Echo Reply message (with checksum)
        let icmpv6_msg = Icmpv6EchoBuilder::build_echo_reply(
            &src, &dst, identifier, sequence, echo_data,
        );

        self.send_ipv6_icmpv6(&src, &dst, &icmpv6_msg);

        log::info!(
            "ICMPv6: Echo Reply sent from {} to {} id={} seq={}",
            src, dst, identifier, sequence
        );
    }

    /// Send an IPv6 packet containing ICMPv6 payload
    pub(super) fn send_ipv6_icmpv6(&mut self, src: &Ipv6Address, dst: &Ipv6Address, icmpv6_data: &[u8]) {
        let config = self.config;
        let current_time = self.current_time.load(Ordering::Relaxed);

        // Resolve destination MAC
        let dst_mac = if dst.is_multicast() {
            dst.multicast_mac()
        } else {
            // Use NDP to resolve
            match self.ndp {
                Some(ref mut ndp) => {
                    match ndp.resolve(dst) {
                        Some(mac) => mac,
                        None => {
                            // Queue packet for later delivery
                            self.ndp_pending_queue.enqueue(*src, *dst, icmpv6_data, current_time);

                            // Start NDP resolution (send NS)
                            let ns_msg = ndp.start_resolution(dst, current_time);
                            // Send NS via solicited-node multicast
                            let sn_mcast = dst.solicited_node();
                            log::debug!(
                                "IPv6: NDP resolution started for {}, packet queued ({} pending)",
                                dst,
                                self.ndp_pending_queue.packets.len()
                            );

                            // We need to send the NS message — use the link-local address as src
                            let our_ll = ndp.our_link_local;
                            // Send NS via the regular send path (multicast MAC is resolved directly)
                            self.send_ipv6_icmpv6_raw(&our_ll, &sn_mcast, &ns_msg);
                            return;
                        }
                    }
                }
                None => return,
            }
        };

        let dst_mac = MacAddress::new(dst_mac);

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();

            // Build IPv6 packet
            if let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) {
                ip_packet.init_header();
                ip_packet.set_source(src);
                ip_packet.set_destination(dst);
                ip_packet.set_next_header(IpProtocol::Icmpv6);
                ip_packet.set_hop_limit(255); // NDP/ICMPv6 uses 255

                // Copy ICMPv6 payload
                let payload = ip_packet.payload_mut();
                if icmpv6_data.len() <= payload.len() {
                    payload[..icmpv6_data.len()].copy_from_slice(icmpv6_data);
                    ip_packet.finalize(icmpv6_data.len());

                    let total_len = IPV6_HEADER_SIZE + icmpv6_data.len();
                    frame.set_payload_len(total_len);

                    self.transmit(frame.as_bytes());
                }
            }
        }
    }

    /// Send an IPv6/ICMPv6 packet without NDP resolution (for multicast destinations)
    ///
    /// NDP NS送信など、NDP解決自体の送信パスで再帰を避けるために使用。
    /// 宛先はマルチキャストアドレスのみ想定。
    fn send_ipv6_icmpv6_raw(&mut self, src: &Ipv6Address, dst: &Ipv6Address, icmpv6_data: &[u8]) {
        let config = self.config;

        // Multicast MAC resolution (no NDP needed)
        let dst_mac = MacAddress::new(dst.multicast_mac());

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();

            if let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) {
                ip_packet.init_header();
                ip_packet.set_source(src);
                ip_packet.set_destination(dst);
                ip_packet.set_next_header(IpProtocol::Icmpv6);
                ip_packet.set_hop_limit(255);

                let payload = ip_packet.payload_mut();
                if icmpv6_data.len() <= payload.len() {
                    payload[..icmpv6_data.len()].copy_from_slice(icmpv6_data);
                    ip_packet.finalize(icmpv6_data.len());

                    let total_len = IPV6_HEADER_SIZE + icmpv6_data.len();
                    frame.set_payload_len(total_len);

                    self.transmit(frame.as_bytes());
                }
            }
        }
    }

    /// Send a UDP/IPv6 datagram (with NDP resolution)
    pub fn send_udp_v6_raw(&mut self, src_port: u16, src_ip: Ipv6Address, dst: Ipv6Address, dst_port: u16, data: &[u8]) -> bool {
        let config = self.config;
        let current_time = self.current_time.load(Ordering::Relaxed);

        // Resolve destination MAC address (multicast -> multicast MAC, otherwise via NDP)
        let dst_mac = if dst.is_multicast() {
            MacAddress::new(dst.multicast_mac())
        } else {
            match self.ndp {
                Some(ref mut ndp) => match ndp.resolve(&dst) {
                    Some(mac) => MacAddress::new(mac),
                    None => {
                        // Queue packet for later and trigger NDP resolution
                        // We'll enqueue in ndp_pending_queue similar to ICMPv6 send path
                        // Build minimal IPv6+UDP packet for queuing (reuse payload area)
                        // For queuing, store as icmpv6_data-like structure: src/dst/payload
                        // Use same pending queue as ICMPv6 (it stores raw icmpv6_data), so place UDP data there
                        self.ndp_pending_queue.enqueue(src_ip, dst, data, current_time);

                        // Start NDP resolution
                        let ns_msg = ndp.start_resolution(&dst, current_time);
                        let sn_mcast = dst.solicited_node();
                        let our_ll = ndp.our_link_local;
                        self.send_ipv6_icmpv6_raw(&our_ll, &sn_mcast, &ns_msg);
                        return false;
                    }
                },
                None => return false,
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();
            if let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) {
                ip_packet.init_header();
                ip_packet.set_source(&src_ip);
                ip_packet.set_destination(&dst);
                ip_packet.set_next_header(IpProtocol::Udp);
                ip_packet.set_hop_limit(64);

                // Build UDP header + payload into IPv6 payload area
                let payload_buf = ip_packet.payload_mut();
                if payload_buf.len() < 8 + data.len() {
                    return false;
                }

                // UDP header
                payload_buf[0..2].copy_from_slice(&src_port.to_be_bytes());
                payload_buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
                let udp_len = (8 + data.len()) as u16;
                payload_buf[4..6].copy_from_slice(&udp_len.to_be_bytes());
                payload_buf[6..8].copy_from_slice(&0u16.to_be_bytes()); // checksum=0 for calc

                // payload
                payload_buf[8..8 + data.len()].copy_from_slice(data);

                // Compute UDP checksum (IPv6 pseudo-header)
                let pseudo = crate::net::l3::ipv6::ipv6_pseudo_header_checksum(&src_ip, &dst, IpProtocol::Udp, udp_len as u32);
                let checksum = crate::net::l3::ipv4::data_checksum(&payload_buf[..udp_len as usize], pseudo);
                let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
                payload_buf[6..8].copy_from_slice(&final_checksum.to_be_bytes());

                ip_packet.finalize(udp_len as usize);
                let total_len = IPV6_HEADER_SIZE + udp_len as usize;
                frame.set_payload_len(total_len);

                return self.transmit(frame.as_bytes());
            }
        }

        false
    }

    /// Transmit a UDP datagram on a given interface (portions of the stack still
    /// assume a single global configuration, so the interface ID is currently
    /// ignored).  This shim exists to exercise the new transmit callback
    /// signature from higher layers.
    pub fn send_udp_raw_on(
        &mut self,
        _if_id: super::NetIfId,
        src_port: u16,
        dst: Ipv4Address,
        dst_port: u16,
        data: &[u8],
    ) -> bool {
        // FUTURE: consult per-interface configuration before sending
        self.send_udp_raw(src_port, dst, dst_port, data)
    }

    /// UDP transmit helper with explicit source IPv4 and TTL.
    /// Interface selection is currently ignored (transitional multi-NIC shim).
    pub fn send_udp_raw_on_with_src_ttl(
        &mut self,
        _if_id: super::NetIfId,
        src_ip: Ipv4Address,
        src_port: u16,
        dst: Ipv4Address,
        dst_port: u16,
        data: &[u8],
        ttl: u8,
    ) -> bool {
        self.send_udp_raw_with_src_ttl(src_ip, src_port, dst, dst_port, data, ttl)
    }

    /// Transmit an IPv6 UDP datagram on a specific interface (ignored for now)
    pub fn send_udp_v6_raw_on(
        &mut self,
        _if_id: super::NetIfId,
        src_port: u16,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        dst_port: u16,
        data: &[u8],
    ) -> bool {
        self.send_udp_v6_raw(src_port, src_ip, dst_ip, dst_port, data)
    }

    /// Send a TCP segment over IPv6 (with NDP resolution)
    pub fn send_tcp_v6_raw(&mut self, src_ip: Ipv6Address, dst: Ipv6Address, tcp_segment: &[u8]) -> bool {
        let config = self.config;
        let current_time = self.current_time.load(Ordering::Relaxed);

        // Resolve destination MAC (multicast -> multicast MAC, otherwise via NDP)
        let dst_mac = if dst.is_multicast() {
            MacAddress::new(dst.multicast_mac())
        } else {
            match self.ndp {
                Some(ref mut ndp) => match ndp.resolve(&dst) {
                    Some(mac) => MacAddress::new(mac),
                    None => {
                        // Queue packet for later and trigger NDP resolution
                        self.ndp_pending_queue.enqueue(src_ip, dst, tcp_segment, current_time);

                        let ns_msg = ndp.start_resolution(&dst, current_time);
                        let sn_mcast = dst.solicited_node();
                        let our_ll = ndp.our_link_local;
                        self.send_ipv6_icmpv6_raw(&our_ll, &sn_mcast, &ns_msg);
                        return false;
                    }
                },
                None => return false,
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();
            if let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) {
                ip_packet.init_header();
                ip_packet.set_source(&src_ip);
                ip_packet.set_destination(&dst);
                ip_packet.set_next_header(IpProtocol::Tcp);
                ip_packet.set_hop_limit(64);

                let payload_buf = ip_packet.payload_mut();
                if payload_buf.len() < tcp_segment.len() {
                    return false;
                }

                payload_buf[..tcp_segment.len()].copy_from_slice(tcp_segment);
                ip_packet.finalize(tcp_segment.len());

                let total_len = IPV6_HEADER_SIZE + tcp_segment.len();
                frame.set_payload_len(total_len);

                return self.transmit(frame.as_bytes());
            }
        }

        false
    }

    /// Drain pending packets for a resolved neighbor
    ///
    /// NDP Neighbor Advertisementを受信してキャッシュが更新された際に呼び出す。
    /// 指定アドレス宛の保留パケットを全て送信する。
    fn drain_ndp_pending(&mut self, resolved_ip: &Ipv6Address) {
        let pending = self.ndp_pending_queue.drain_for(resolved_ip);
        if pending.is_empty() {
            return;
        }

        log::debug!(
            "NDP: Draining {} pending packets for {}",
            pending.len(),
            resolved_ip
        );

        for pkt in pending {
            self.send_ipv6_icmpv6(&pkt.src, &pkt.dst, &pkt.icmpv6_data);
        }
    }

    /// Apply a DHCPv6-obtained global IPv6 address to the stack
    pub fn apply_ipv6_global_address(&mut self, addr: crate::net::l3::ipv6::Ipv6Address) {
        if let Some(ref mut ipv6_proc) = self.ipv6 {
            ipv6_proc.set_global_address(addr);
        }
        if let Some(ref mut ndp_proc) = self.ndp {
            ndp_proc.add_global_address(addr);
        }
    }

    /// Expire timed-out NDP pending packets
    pub fn expire_ndp_pending(&mut self) {
        let current_time = self.current_time.load(Ordering::Relaxed);
        self.ndp_pending_queue.expire(current_time);
    }

    /// Process IGMP data for multicast group management
    pub(super) fn process_igmp_data(&mut self, data: &[u8], src_ip: Ipv4Address, ttl: u8) {
        // Security (RFC 2236 Section 2): all IGMP messages MUST be sent with a IP TTL of 1.
        if ttl != 1 {
            log::warn!("IGMP: Dropping packet with invalid TTL {}", ttl);
            return;
        }

        // Security: Verify source is on the same subnet
        let local_ip = self.config.ipv4.address;
        let subnet_mask = self.config.ipv4.subnet_mask;
        if local_ip.apply_mask(subnet_mask) != src_ip.apply_mask(subnet_mask) {
            log::warn!("IGMP: Dropping packet from different subnet {}", src_ip);
            return;
        }

        let current_time = self.current_time();
        self.igmp.update_time(current_time);
        
        let result = self.igmp.process(data, src_ip);
        
        match result {
            IgmpResult::GeneralQueryReceived { max_resp_time: _ } => {
                // Timers are set internally, reports will be sent on timer expiry
            }
            IgmpResult::GroupQueryReceived { group: _, max_resp_time: _ } => {
                // Timer set for specific group
            }
            IgmpResult::ReportReceived { group: _ } => {
                // Report suppression handled internally
            }
            IgmpResult::Ignored => {}
            IgmpResult::InvalidPacket | IgmpResult::InvalidChecksum => {
                self.stats.record_rx_error();
            }
            IgmpResult::UnknownType(_) => {
                self.stats.record_dropped();
            }
        }
        
        // Process and send any pending IGMP reports
        self.send_pending_igmp_reports();
    }
    
    /// Send pending IGMP reports
    pub(super) fn send_pending_igmp_reports(&mut self) {
        let pending = self.igmp.take_pending_reports();
        let current_time = self.current_time();
        
        for (group_addr, is_leave) in pending {
            if is_leave {
                self.send_igmp_leave(group_addr, current_time);
            } else {
                self.send_igmp_report(group_addr, current_time);
            }
        }
    }
    
    /// Send an IGMP Membership Report
    pub(super) fn send_igmp_report(&mut self, group_addr: Ipv4Address, _current_time: u64) {
        let mut buffer = [0u8; MAX_PACKET_SIZE];
        let config = self.config.clone();
        
        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            // Destination is the multicast MAC address for the group
            let dst_mac = multicast_ip_to_mac(group_addr);
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);
            
            let payload = frame.payload_mut();
            
            // Build IPv4 header
            // IGMPv2 reports are sent to the group address
            if let Some(mut ip_pkt) = Ipv4PacketMut::new(payload) {
                ip_pkt
                    .set_version(4)
                    .set_ihl(5)
                    .set_dscp(0xc0) // Internetwork Control
                    .set_ttl(1) // IGMP messages use TTL=1
                    .set_protocol(IpProtocol::Igmp)
                    .set_source(config.ipv4.address)
                    .set_destination(group_addr);

                // Build IGMP message into IPv4 payload.
                let ip_payload = ip_pkt.payload_mut();
                if ip_payload.len() >= 8 {
                    if let Some(len) = crate::net::l2::igmp::IgmpProcessor::build_report(group_addr, ip_payload) {
                        let total_len = (20 + len) as u16;
                        ip_pkt.set_total_length(total_len).update_checksum();

                        let frame_len = 14 + total_len as usize;
                        if let Some(tx_fn) = self.transmit_fn {
                            if tx_fn(None, &buffer[..frame_len]) {
                                self.stats.record_tx(frame_len);
                            }
                        }
                    }
                }
            }
        }
    }
}
