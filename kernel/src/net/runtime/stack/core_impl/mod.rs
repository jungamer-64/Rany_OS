use super::NetIfId;
use super::*;

mod global_instance;
pub use global_instance::*;
/// Protocol-specific NetworkStack impl methods (IGMP, ARP, ICMP, TCP bind, UDP raw).
mod protocol_impl;
/// Receive path — IPv4/IPv6 incoming packet processing.
mod receive;
/// Send path — IPv6 / ICMPv6 / NDP / IGMP outgoing packet construction.
mod send_v6;
impl NetworkStack {
    pub(crate) fn interface_config_or_runtime(&self, if_id: NetIfId) -> Option<NetworkConfig> {
        self.interface_config(if_id).or_else(|| {
            crate::net::runtime::manager::get_interface(if_id)
                .ok()
                .flatten()
                .and_then(|iface| iface.config)
        })
    }

    fn legacy_single_interface_runtime(&self) -> Option<(Option<NetIfId>, NetworkConfig)> {
        if self.interfaces.is_empty() {
            Some((None, self.config()))
        } else {
            None
        }
    }

    fn select_ipv4_source(
        &self,
        config: NetworkConfig,
        explicit_src: Option<Ipv4Address>,
    ) -> Result<Ipv4Address, crate::net::types::NetworkError> {
        match explicit_src {
            Some(src_ip) if !src_ip.is_any() => {
                if config.ipv4.address == src_ip {
                    Ok(src_ip)
                } else {
                    Err(crate::net::types::NetworkError::InvalidAddress)
                }
            }
            Some(src_ip) => Ok(src_ip),
            None => {
                if config.ipv4.address.is_any() {
                    Err(crate::net::types::NetworkError::NetworkUnreachable)
                } else {
                    Ok(config.ipv4.address)
                }
            }
        }
    }

    fn select_ipv6_source(
        &self,
        config: NetworkConfig,
        explicit_src: Option<Ipv6Address>,
        dst_ip: Ipv6Address,
    ) -> Result<Ipv6Address, crate::net::types::NetworkError> {
        let Some(ipv6_cfg) = config.ipv6 else {
            return Err(crate::net::types::NetworkError::NetworkUnreachable);
        };

        match explicit_src {
            Some(src_ip) if !src_ip.is_unspecified() => {
                if ipv6_cfg.global == Some(src_ip) || ipv6_cfg.link_local == src_ip {
                    Ok(src_ip)
                } else {
                    Err(crate::net::types::NetworkError::InvalidAddress)
                }
            }
            _ => {
                let candidate = if dst_ip.is_link_local() {
                    ipv6_cfg.link_local
                } else {
                    ipv6_cfg.global.unwrap_or(ipv6_cfg.link_local)
                };
                if candidate.is_unspecified() {
                    Err(crate::net::types::NetworkError::NetworkUnreachable)
                } else {
                    Ok(candidate)
                }
            }
        }
    }

    pub(crate) fn resolve_ipv4_egress(
        &self,
        scope: crate::net::types::InterfaceScope,
        preferred_if: Option<NetIfId>,
        explicit_src: Option<Ipv4Address>,
        dst_ip: Ipv4Address,
    ) -> Result<(Option<NetIfId>, NetworkConfig, Ipv4Address), crate::net::types::NetworkError> {
        let resolved = scope
            .as_if_id()
            .or(preferred_if)
            .map(|if_id| {
                self.interface_config_or_runtime(if_id)
                    .map(|cfg| (Some(if_id), cfg))
                    .ok_or(crate::net::types::NetworkError::NetworkUnreachable)
            })
            .transpose()?
            .or_else(|| {
                crate::net::runtime::manager::lookup_ipv4_route(dst_ip)
                    .ok()
                    .flatten()
                    .and_then(|route| {
                        self.interface_config_or_runtime(route.if_id)
                            .map(|cfg| (Some(route.if_id), cfg))
                    })
            })
            .or_else(|| self.legacy_single_interface_runtime())
            .ok_or(crate::net::types::NetworkError::NetworkUnreachable)?;

        let src_ip = self.select_ipv4_source(resolved.1, explicit_src)?;
        Ok((resolved.0, resolved.1, src_ip))
    }

    pub(crate) fn resolve_ipv6_egress(
        &self,
        scope: crate::net::types::InterfaceScope,
        preferred_if: Option<NetIfId>,
        explicit_src: Option<Ipv6Address>,
        dst_ip: Ipv6Address,
    ) -> Result<(Option<NetIfId>, NetworkConfig, Ipv6Address), crate::net::types::NetworkError> {
        let resolved = scope
            .as_if_id()
            .or(preferred_if)
            .map(|if_id| {
                self.interface_config_or_runtime(if_id)
                    .map(|cfg| (Some(if_id), cfg))
                    .ok_or(crate::net::types::NetworkError::NetworkUnreachable)
            })
            .transpose()?
            .or_else(|| {
                crate::net::runtime::manager::lookup_ipv6_route(dst_ip)
                    .ok()
                    .flatten()
                    .and_then(|route| {
                        self.interface_config_or_runtime(route.if_id)
                            .map(|cfg| (Some(route.if_id), cfg))
                    })
            })
            .or_else(|| self.legacy_single_interface_runtime())
            .ok_or(crate::net::types::NetworkError::NetworkUnreachable)?;

        let src_ip = self.select_ipv6_source(resolved.1, explicit_src, dst_ip)?;
        Ok((resolved.0, resolved.1, src_ip))
    }

    pub(crate) fn resolve_ingress_if(&self, if_id: Option<NetIfId>) -> NetIfId {
        if let Some(if_id) = if_id {
            return if_id;
        }
        self.primary_interface
            .or_else(|| {
                crate::net::runtime::manager::list_interfaces()
                    .ok()
                    .and_then(|ifaces| ifaces.first().map(|iface| iface.if_id))
            })
            .unwrap_or_default()
    }

    /// Create a new network stack with configuration
    ///
    /// # パフォーマンス注意
    /// Ipv4Config が Clone を実装しているが、内部データが Copy なら
    /// clone() はゼロコストでインライン化される
    pub fn new(config: NetworkConfig) -> Self {
        let mac = config.mac;
        let ip = config.ipv4.address;
        let dad_link_local = config.ipv6.as_ref().map(|cfg| cfg.link_local);

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

        let mut stack = NetworkStack {
            interfaces: BTreeMap::new(),
            primary_interface: None,
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
            config,
            transmit_fn: None,
            current_time: AtomicU64::new(0),
            redirect_cache: RedirectCache::new(),
            ndp_pending_queue: NdpPendingQueue::new(),
            ipv6_fragment_reassembler: Ipv6FragmentReassembler::new(
                Ipv6FragmentReassembler::DEFAULT_MAX_BUFFERS,
            ),
            ipv6_pmtu_cache: Ipv6PmtuCache::new(Ipv6PmtuCache::DEFAULT_MAX_ENTRIES),
        };

        // RFC 4862: Initiate DAD for link-local address upon interface startup
        if let Some(ll) = dad_link_local {
            stack.initiate_ipv6_dad(ll);
        }

        stack
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(NetworkConfig::default())
    }

    /// Set transmit callback
    pub fn set_transmit_fn(&mut self, f: TransmitFn) {
        self.transmit_fn = Some(f);
    }

    /// Register or refresh per-interface state.
    pub fn register_interface_state(&mut self, if_id: NetIfId, config: NetworkConfig) {
        match self.interfaces.get_mut(&if_id) {
            Some(state) => state.set_config(config),
            None => {
                self.interfaces.insert(if_id, InterfaceStackState::new(config));
            }
        }
        if self.primary_interface.is_none() {
            self.primary_interface = Some(if_id);
        }
    }

    /// Remove per-interface state.
    pub fn unregister_interface_state(&mut self, if_id: NetIfId) {
        self.interfaces.remove(&if_id);
        if self.primary_interface == Some(if_id) {
            self.primary_interface = self.interfaces.keys().next().copied();
        }
    }

    /// Select the preferred interface used by legacy internal helpers.
    pub fn set_primary_interface_state(&mut self, if_id: Option<NetIfId>) {
        self.primary_interface = if_id;
    }

    pub fn interface_config(&self, if_id: NetIfId) -> Option<NetworkConfig> {
        self.interfaces.get(&if_id).map(|state| state.config)
    }

    pub fn list_interface_configs(&self) -> Vec<(NetIfId, NetworkConfig)> {
        self.interfaces
            .iter()
            .map(|(if_id, state)| (*if_id, state.config))
            .collect()
    }

    pub fn interface_stats(&self, if_id: NetIfId) -> Option<&NetworkStats> {
        self.interfaces.get(&if_id).map(|state| &state.stats)
    }

    pub fn transmit_on(&self, if_id: Option<NetIfId>, data: &[u8]) -> bool {
        if let Some(f) = self.transmit_fn {
            if f(if_id, data) {
                self.stats.record_tx(data.len());
                if let Some(if_id) = if_id {
                    if let Some(stats) = self.interface_stats(if_id) {
                        stats.record_tx(data.len());
                    }
                }
                return true;
            }

            self.stats.record_tx_error();
            if let Some(if_id) = if_id {
                if let Some(stats) = self.interface_stats(if_id) {
                    stats.record_tx_error();
                }
            }
            return false;
        }

        false
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
            if let Some((local, remote, seq, total_len)) =
                Self::build_tcp_packet_from_result(&res, &mut buffer)
            {
                let sent = self.send_tcp_packet_for_flow(local, remote, &buffer[..total_len]);

                if sent {
                    self.tcp
                        .record_sent_packet(local, remote, seq, 0x10 /* ACK */, &[], now);
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
        self.timeout_wheel
            .schedule(DHCP_MAINTENANCE_INTERVAL_MS, TimerKind::Dhcpv4Renewal, now);
        self.timeout_wheel
            .schedule(DHCP_MAINTENANCE_INTERVAL_MS, TimerKind::Dhcpv6Renewal, now);
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

    fn trigger_dhcpv4_request(&mut self, broadcast: bool) {
        let mut buffer = [0u8; 576];
        let now = self.current_time();

        let client_opt = crate::net::services::dhcp::DHCP_CLIENT.lock();
        if let Ok(guard) = client_opt {
            if let Some(ref client) = *guard {
                if let Ok(len) = client.build_request(&mut buffer, now) {
                    let dst_ip = if broadcast {
                        Ipv4Address::BROADCAST
                    } else if let Some(lease) = client.lease() {
                        lease.server_ip
                    } else {
                        Ipv4Address::BROADCAST
                    };

                    // DHCP uses source port 68, destination port 67
                    // Note: We use 0.0.0.0 as source IP if not bound yet,
                    // or current IP for renewal as per RFC 2131.
                    let src_ip = if broadcast {
                        Ipv4Address::ANY
                    } else {
                        self.config.ipv4.address
                    };

                    self.send_udp_raw_with_src_ttl(src_ip, 68, dst_ip, 67, &buffer[..len], 64);
                }
            }
        }
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
        let old_ip = self.config.ipv4.address;
        let new_ip = config.ipv4.address;

        // Update all processors
        self.ethernet.set_local_mac(config.mac);
        self.ipv4.set_config(config.ipv4.clone());
        self.arp.set_local(config.mac, config.ipv4.address);

        self.config = config;

        if let Some(primary_if_id) = self.primary_interface {
            if let Some(state) = self.interfaces.get_mut(&primary_if_id) {
                state.set_config(config);
            }
        }

        // RFC 2131 Section 4.4.1: Send Gratuitous ARP when IP address is assigned or changed.
        // This updates the ARP cache of other hosts on the network.
        if new_ip != Ipv4Address::ANY && new_ip != old_ip {
            self.send_arp_request(new_ip);
        }
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
        self.initiate_ipv6_dad(addr);
    }

    /// Initiate DAD for an IPv6 address
    pub fn initiate_ipv6_dad(&mut self, addr: Ipv6Address) {
        if let Some(ref mut ndp) = self.ndp {
            let res = ndp.initiate_dad(&addr);
            if let NdpResult::SendNeighborSolicitation { src, dst, target } = res {
                let msg = NdpProcessor::build_ns(&src, &dst, &target, self.config.mac.as_bytes());
                self.send_ipv6_icmpv6(&src, &dst, &msg);
            }
        }
    }

    /// Expire timed-out NDP pending packets
    pub fn expire_ndp_pending(&mut self) {
        let current_time = self.current_time.load(Ordering::Relaxed);
        self.ndp_pending_queue.expire(current_time);
    }
}
