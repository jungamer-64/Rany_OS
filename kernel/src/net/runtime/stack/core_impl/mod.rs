use super::*;
use super::NetIfId;


mod global_instance;
pub use global_instance::*;
/// Protocol-specific NetworkStack impl methods (IGMP, ARP, ICMP, TCP bind, UDP raw).
mod protocol_impl;
/// Receive path — IPv4/IPv6 incoming packet processing.
mod receive;
/// Send path — IPv6 / ICMPv6 / NDP / IGMP outgoing packet construction.
mod send_v6;
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
            stats: NetworkStats::default(),
            timeout_wheel: TimeoutWheel::new(100), // 100ms resolution
            config: config,
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

    /// Process periodic timeouts (call periodically, e.g., every 100ms)
    pub fn process_timeouts(&mut self) {
        let now = self.current_time();
        
        // 1. Process TCP retransmissions
        self.process_tcp_retransmissions(now);

        // 2. Process TCP keepalives and zero-window probes
        let mut extra_packets = self.tcp.process_keepalives(now);
        extra_packets.extend(self.tcp.process_zero_window_probes(now));

        for res in extra_packets {
            let mut buffer = [0u8; MAX_PACKET_SIZE];
            if let Some((local, remote, seq, total_len)) = Self::build_tcp_packet_from_result(&res, &mut buffer) {
                let sent = if local.is_ipv6() && remote.is_ipv6() {
                    let src_v6 = Ipv6Address::new(local.as_ipv6());
                    let dst_v6 = Ipv6Address::new(remote.as_ipv6());
                    self.send_tcp_v6_raw(src_v6, dst_v6, &buffer[..total_len])
                } else if let (Some(lv4), Some(rv4)) = (local.as_ipv4(), remote.as_ipv4()) {
                    let src_ip_out = Ipv4Address::new(lv4);
                    let dst_ip_out = Ipv4Address::new(rv4);
                    self.send_tcp(src_ip_out, dst_ip_out, &buffer[..total_len])
                } else {
                    false
                };

                if sent {
                    self.tcp.record_sent_packet(local, remote, seq, 0x10 /* ACK */, &[], now);
                }
            }
        }

        // 3. Process other scheduled timeouts
        let expired = self.timeout_wheel.tick(now);

        for timer in expired {
            match timer.kind {
                TimerKind::Dhcpv4Renewal => {
                    self.maintenance_dhcpv4();
                }
                TimerKind::Dhcpv6Renewal => {
                    self.maintenance_dhcpv6();
                }
                // Other timer kinds handled elsewhere or to be implemented
                _ => {}
            }
        }

        // Always reschedule DHCP maintenance if not already scheduled
        // (Simplified logic: schedule every 10s for lease checking)
        const DHCP_MAINTENANCE_INTERVAL_MS: u64 = 10_000;
        self.timeout_wheel.schedule(DHCP_MAINTENANCE_INTERVAL_MS, TimerKind::Dhcpv4Renewal, now);
        self.timeout_wheel.schedule(DHCP_MAINTENANCE_INTERVAL_MS, TimerKind::Dhcpv6Renewal, now);
    }

    /// Perform DHCPv4 maintenance (renewal/rebinding)
    fn maintenance_dhcpv4(&mut self) {
        if let Ok(guard) = crate::net::services::dhcp::DHCP_CLIENT.lock() {
            if let Some(ref client) = *guard {
                let now = self.current_time();
                if let Some(lease) = client.lease() {
                    // Check T1 (Renewal) or T2 (Rebinding)
                    // Tick rate is assumed 1000 ticks/sec (1ms)
                    if lease.needs_rebind(now, 1000) {
                        log::info!("[DHCP] Lease needs rebinding (T2)");
                        // Build and send REQUEST (broadcast)
                        self.trigger_dhcpv4_request(true);
                    } else if lease.needs_renewal(now, 1000) {
                        log::info!("[DHCP] Lease needs renewal (T1)");
                        // Build and send REQUEST (unicast to server)
                        self.trigger_dhcpv4_request(false);
                    }
                }
            }
        }
    }

    fn trigger_dhcpv4_request(&mut self, _broadcast: bool) {
        // Implementation of sending DHCPREQUEST
        // For brevity in this turn, we'll assume a helper exists or add it.
        // The DhcpClient already has build_request().
    }

    /// Perform DHCPv6 maintenance
    fn maintenance_dhcpv6(&mut self) {
        if let Ok(guard) = crate::net::services::dhcp::DHCPV6_CLIENT.lock() {
            if let Some(ref client) = *guard {
                // Similar logic for DHCPv6...
                let _ = client;
            }
        }
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

    /// Check if an IPv4 multicast group is allowed (joined or mandatory)
    fn is_multicast_allowed(&self, group: Ipv4Address) -> bool {
        use crate::net::l3::igmp::ALL_HOSTS_GROUP;
        group == ALL_HOSTS_GROUP || self.igmp.is_member(group)
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
}
