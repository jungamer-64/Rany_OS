use super::NetIfId;
use super::*;
use crate::net::payload::PacketPayloadView;
use alloc::vec;
use kernel_api::resource::net::PacketPayload;

mod global_instance;
pub(crate) use global_instance::*;
/// Protocol-specific NetworkStack impl methods (IGMP, ARP, ICMP, TCP bind, UDP raw).
mod protocol_impl;
/// Receive path — IPv4/IPv6 incoming packet processing.
mod receive;
/// Send path — IPv6 / ICMPv6 / NDP / IGMP outgoing packet construction.
mod send_v6;
impl NetworkStack {
    pub(crate) fn interface_config_or_runtime(&self, if_id: NetIfId) -> Option<NetworkConfig> {
        self.interface_config(if_id).or_else(|| {
            crate::net::runtime::manager::get_interface_in(
                crate::net::runtime::default_runtime(),
                if_id,
            )
            .ok()
            .flatten()
            .and_then(|iface| iface.config)
        })
    }

    fn bootstrap_runtime_config(&self) -> Option<(Option<NetIfId>, NetworkConfig)> {
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
    ) -> Result<(Option<NetIfId>, NetworkConfig, Ipv4Address), crate::net::types::NetworkError>
    {
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
                crate::net::runtime::manager::lookup_ipv4_route_in(
                    crate::net::runtime::default_runtime(),
                    dst_ip,
                )
                .ok()
                .flatten()
                .and_then(|route| {
                    self.interface_config_or_runtime(route.if_id)
                        .map(|cfg| (Some(route.if_id), cfg))
                })
            })
            .or_else(|| self.bootstrap_runtime_config())
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
    ) -> Result<(Option<NetIfId>, NetworkConfig, Ipv6Address), crate::net::types::NetworkError>
    {
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
                crate::net::runtime::manager::lookup_ipv6_route_in(
                    crate::net::runtime::default_runtime(),
                    dst_ip,
                )
                .ok()
                .flatten()
                .and_then(|route| {
                    self.interface_config_or_runtime(route.if_id)
                        .map(|cfg| (Some(route.if_id), cfg))
                })
            })
            .or_else(|| self.bootstrap_runtime_config())
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
                crate::net::runtime::manager::list_interfaces_in(
                    crate::net::runtime::default_runtime(),
                )
                .ok()
                .and_then(|ifaces| ifaces.first().map(|iface| iface.if_id))
            })
            .unwrap_or_default()
    }

    pub fn send_raw_ip_payload_scoped(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        payload: PacketPayload,
    ) -> Result<(), crate::net::types::NetworkError> {
        let view = PacketPayloadView::new(&payload);
        let Some(version) = view.first_byte().map(|byte| byte >> 4) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };

        match version {
            4 => self.send_raw_ipv4_payload_scoped(scope, &view),
            6 => self.send_raw_ipv6_payload_scoped(scope, &view),
            _ => Err(crate::net::types::NetworkError::InvalidAddress),
        }
    }

    fn send_raw_ipv4_payload_scoped(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        payload: &PacketPayloadView<'_>,
    ) -> Result<(), crate::net::types::NetworkError> {
        let mut fixed = [0u8; 60];
        if payload.copy_range(0, &mut fixed[..20]) < 20 {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        if (fixed[0] >> 4) != 4 {
            return Err(crate::net::types::NetworkError::InvalidAddress);
        }

        let ihl = ((fixed[0] & 0x0f) as usize) * 4;
        if !(20..=60).contains(&ihl) {
            return Err(crate::net::types::NetworkError::InvalidAddress);
        }

        let mut header = vec![0u8; ihl];
        if payload.copy_range(0, &mut header) < ihl {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        let total_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if total_len < ihl || total_len != payload.total_len() {
            return Err(crate::net::types::NetworkError::InvalidAddress);
        }

        let observed_checksum = u16::from_be_bytes([header[10], header[11]]);
        let expected_checksum = crate::net::l3::ipv4::calculate_ip_checksum(&header);
        if observed_checksum != expected_checksum {
            return Err(crate::net::types::NetworkError::InvalidAddress);
        }

        let src_ip = crate::net::l3::ipv4::Ipv4Address::new([
            header[12], header[13], header[14], header[15],
        ]);
        let dst_ip = crate::net::l3::ipv4::Ipv4Address::new([
            header[16], header[17], header[18], header[19],
        ]);
        let protocol = header[9];
        let (src_port, dst_port, tcp_flags) = if total_len >= ihl + 4 {
            match protocol {
                6 if total_len >= ihl + 14 => {
                    let ports = payload.read_vec(ihl, 14);
                    if ports.len() < 14 {
                        (0, 0, 0)
                    } else {
                        (
                            u16::from_be_bytes([ports[0], ports[1]]),
                            u16::from_be_bytes([ports[2], ports[3]]),
                            ports[13],
                        )
                    }
                }
                17 if total_len >= ihl + 4 => {
                    let ports = payload.read_vec(ihl, 4);
                    if ports.len() < 4 {
                        (0, 0, 0)
                    } else {
                        (
                            u16::from_be_bytes([ports[0], ports[1]]),
                            u16::from_be_bytes([ports[2], ports[3]]),
                            0,
                        )
                    }
                }
                _ => (0, 0, 0),
            }
        } else {
            (0, 0, 0)
        };

        if !crate::net::security::firewall::check_egress(
            src_ip.octets(),
            dst_ip.octets(),
            protocol,
            src_port,
            dst_port,
            tcp_flags,
        ) {
            self.stats.record_dropped();
            return Err(crate::net::types::NetworkError::PermissionDenied);
        }

        let (if_id, config, _) = self.resolve_ipv4_egress(scope, None, Some(src_ip), dst_ip)?;
        let dst_mac = if dst_ip.is_loopback() {
            config.mac
        } else {
            self.resolve_mac(if_id, dst_ip, &config, self.current_time())
                .ok_or(crate::net::types::NetworkError::NetworkUnreachable)?
        };

        let mut packet = self
            .alloc_ethernet_frame_packet(EthernetHeader::SIZE + total_len)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        frame
            .set_destination(dst_mac)
            .set_source(config.mac)
            .set_ether_type(EtherType::Ipv4);
        let frame_payload = frame.payload_mut();
        if frame_payload.len() < total_len {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }
        if payload.copy_range(0, &mut frame_payload[..total_len]) != total_len {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }
        frame.set_payload_len(total_len);
        let frame_len = frame.as_bytes().len();
        drop(frame);
        packet.set_len(frame_len);
        if self.transmit_packet_on(if_id, packet) {
            Ok(())
        } else {
            Err(crate::net::types::NetworkError::TransmitFailed)
        }
    }

    fn send_raw_ipv6_payload_scoped(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        payload: &PacketPayloadView<'_>,
    ) -> Result<(), crate::net::types::NetworkError> {
        let mut header = [0u8; 40];
        if payload.copy_range(0, &mut header) < 40 {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        if (header[0] >> 4) != 6 {
            return Err(crate::net::types::NetworkError::InvalidAddress);
        }

        let total_len = IPV6_HEADER_SIZE + u16::from_be_bytes([header[4], header[5]]) as usize;
        if total_len != payload.total_len() {
            return Err(crate::net::types::NetworkError::InvalidAddress);
        }

        let src_ip = crate::net::l3::ipv6::Ipv6Address::new([
            header[8], header[9], header[10], header[11], header[12], header[13], header[14],
            header[15], header[16], header[17], header[18], header[19], header[20], header[21],
            header[22], header[23],
        ]);
        let dst_ip = crate::net::l3::ipv6::Ipv6Address::new([
            header[24], header[25], header[26], header[27], header[28], header[29], header[30],
            header[31], header[32], header[33], header[34], header[35], header[36], header[37],
            header[38], header[39],
        ]);
        let next_header = header[6];

        let (if_id, config, _) = self.resolve_ipv6_egress(scope, None, Some(src_ip), dst_ip)?;
        let dst_mac = if dst_ip.is_multicast() {
            MacAddress::new(dst_ip.multicast_mac())
        } else {
            match self.resolve_ndp_for_send(
                if_id,
                &dst_ip,
                self.current_time.load(Ordering::Relaxed),
                |_| {},
            ) {
                Some(Ok(mac)) => MacAddress::new(mac),
                Some(Err((ns_if_id, our_ll, ns_msg))) => {
                    let solicited = dst_ip.solicited_node();
                    let ns_msg = crate::net::payload::PacketPayloadView::new(&ns_msg);
                    if let Some(ns_if_id) = ns_if_id {
                        self.send_ipv6_icmpv6_raw_on(ns_if_id, &our_ll, &solicited, &ns_msg);
                    } else {
                        self.send_ipv6_icmpv6_raw(&our_ll, &solicited, &ns_msg);
                    }
                    return Err(crate::net::types::NetworkError::ArpResolutionPending);
                }
                None => return Err(crate::net::types::NetworkError::NetworkUnreachable),
            }
        };

        let (src_port, dst_port, tcp_flags) = if total_len >= IPV6_HEADER_SIZE + 4 {
            match next_header {
                6 if total_len >= IPV6_HEADER_SIZE + 14 => {
                    let ports = payload.read_vec(IPV6_HEADER_SIZE, 14);
                    if ports.len() < 14 {
                        (0, 0, 0)
                    } else {
                        (
                            u16::from_be_bytes([ports[0], ports[1]]),
                            u16::from_be_bytes([ports[2], ports[3]]),
                            ports[13],
                        )
                    }
                }
                17 => {
                    let ports = payload.read_vec(IPV6_HEADER_SIZE, 4);
                    if ports.len() < 4 {
                        (0, 0, 0)
                    } else {
                        (
                            u16::from_be_bytes([ports[0], ports[1]]),
                            u16::from_be_bytes([ports[2], ports[3]]),
                            0,
                        )
                    }
                }
                58 => {
                    let icmp = payload.read_vec(IPV6_HEADER_SIZE, 2);
                    if icmp.len() < 2 {
                        (0, 0, 0)
                    } else {
                        (icmp[0] as u16, icmp[1] as u16, 0)
                    }
                }
                _ => (0, 0, 0),
            }
        } else {
            (0, 0, 0)
        };

        if !crate::net::security::firewall::check_egress(
            crate::net::security::firewall::IpAddress::V6(src_ip.octets()),
            crate::net::security::firewall::IpAddress::V6(dst_ip.octets()),
            next_header,
            src_port,
            dst_port,
            tcp_flags,
        ) {
            self.stats.record_dropped();
            return Err(crate::net::types::NetworkError::PermissionDenied);
        }

        let mut packet = self
            .alloc_ethernet_frame_packet(EthernetHeader::SIZE + total_len)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        frame
            .set_destination(dst_mac)
            .set_source(config.mac)
            .set_ether_type(EtherType::Ipv6);
        let frame_payload = frame.payload_mut();
        if frame_payload.len() < total_len {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }
        if payload.copy_range(0, &mut frame_payload[..total_len]) != total_len {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }
        frame.set_payload_len(total_len);
        let frame_len = frame.as_bytes().len();
        drop(frame);
        packet.set_len(frame_len);
        if self.transmit_packet_on(if_id, packet) {
            Ok(())
        } else {
            Err(crate::net::types::NetworkError::TransmitFailed)
        }
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
            tx_pool: PacketPool::new(64, MAX_PACKET_SIZE),
            stats: NetworkStats::default(),
            timeout_wheel: TimeoutWheel::new(100), // 100ms resolution
            config,
            transmit_fn: None,
            transmit_awaits_device_completion: false,
            pending_tx_meta: None,
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
        self.set_transmit_fn_with_completion(f, false);
    }

    pub fn set_transmit_fn_with_completion(
        &mut self,
        f: TransmitFn,
        waits_for_device_completion: bool,
    ) {
        self.transmit_fn = Some(f);
        self.transmit_awaits_device_completion = waits_for_device_completion;
    }

    /// Register or refresh per-interface state.
    pub fn register_interface_state(&mut self, if_id: NetIfId, config: NetworkConfig) {
        match self.interfaces.get_mut(&if_id) {
            Some(state) => state.set_config(config),
            None => {
                self.interfaces
                    .insert(if_id, InterfaceStackState::new(config));
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

    /// Select the preferred interface used for scope-less runtime resolution.
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

    pub fn with_pending_tx_meta<R>(
        &mut self,
        meta: kernel_api::service::netdev::NetTxMeta,
        f: impl FnOnce(&mut Self) -> R,
    ) -> R {
        let previous = self.pending_tx_meta.replace(meta);
        let result = f(self);
        self.pending_tx_meta = previous;
        result
    }

    pub fn transmit_packet_on(&self, if_id: Option<NetIfId>, packet: PacketRef) -> bool {
        if let Some(f) = self.transmit_fn {
            let meta = self.pending_tx_meta.unwrap_or_default();
            let packet_len = packet.len();
            if f(if_id, packet, meta) {
                if !self.transmit_awaits_device_completion
                    && meta.completion_policy
                        == kernel_api::service::netdev::NetTxCompletionPolicy::DeviceCompletion
                {
                    if let Some(completion_id) = meta.completion_id {
                        let _ = crate::net::runtime::device::complete_tx_request_in(
                            crate::net::runtime::default_runtime(),
                            completion_id,
                            Ok(()),
                        );
                    }
                }
                self.stats.record_tx(packet_len);
                if let Some(if_id) = if_id {
                    if let Some(stats) = self.interface_stats(if_id) {
                        stats.record_tx(packet_len);
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

    fn alloc_ethernet_frame_packet(&self, frame_len: usize) -> Option<PacketRef> {
        crate::net::payload::alloc_packet_with_headroom(frame_len.max(60), 0)
    }

    fn effective_ipv4_pmtu(&mut self, dst_ip: Ipv4Address, current_time: u64) -> usize {
        self.ipv4
            .get_pmtu(dst_ip, current_time)
            .max(crate::net::l3::ipv4::PmtuEntry::MIN_MTU)
            .min(crate::net::runtime::stack::MTU as u16) as usize
    }

    fn send_ipv4_l4_payload_with_pmtu(
        &mut self,
        if_id: Option<NetIfId>,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        protocol: IpProtocol,
        ttl: u8,
        payload: &PacketPayloadView<'_>,
        path_mtu: usize,
    ) -> Result<(), crate::net::types::NetworkError> {
        const IPV4_HEADER_LEN: usize = crate::net::l3::ipv4::Ipv4Header::MIN_SIZE;
        const MAX_IPV4_PAYLOAD_LEN: usize = (u16::MAX as usize) - IPV4_HEADER_LEN;
        let payload_len = payload.total_len();

        if payload_len > MAX_IPV4_PAYLOAD_LEN {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        let Some(unfragmented_payload_limit) = path_mtu.checked_sub(IPV4_HEADER_LEN) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        let identification = self.ipv4.next_id(dst_ip);

        if payload_len <= unfragmented_payload_limit {
            let mut packet = self
                .alloc_ethernet_frame_packet(EthernetHeader::SIZE + IPV4_HEADER_LEN + payload_len)
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) else {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            };
            frame
                .set_destination(dst_mac)
                .set_source(src_mac)
                .set_ether_type(EtherType::Ipv4);

            let eth_payload = frame.payload_mut();
            let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) else {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            };
            ip_packet
                .init_header()
                .set_source(src_ip)
                .set_destination(dst_ip)
                .set_protocol(protocol)
                .set_identification(identification)
                .set_ttl(ttl);

            let payload_buf = ip_packet.payload_mut();
            if payload_buf.len() < payload_len {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            }
            if payload.copy_range(0, &mut payload_buf[..payload_len]) != payload_len {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            }
            ip_packet.finalize(payload_len);

            let total_len = ip_packet.total_len();
            frame.set_payload_len(total_len);
            let frame_len = frame.as_bytes().len();
            drop(frame);
            packet.set_len(frame_len);

            if self.transmit_packet_on(if_id, packet) {
                return Ok(());
            }
            return Err(crate::net::types::NetworkError::TransmitFailed);
        }

        let non_last_fragment_len = unfragmented_payload_limit & !0x7;
        if non_last_fragment_len == 0 {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        let mut offset = 0usize;
        while offset < payload_len {
            let remaining = payload_len - offset;
            let fragment_data_len = if remaining > unfragmented_payload_limit {
                non_last_fragment_len.min(remaining)
            } else {
                remaining
            };
            if fragment_data_len == 0 {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            }
            let more_fragments = offset + fragment_data_len < payload_len;
            if more_fragments && (fragment_data_len % 8 != 0) {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            }

            let mut packet = self
                .alloc_ethernet_frame_packet(
                    EthernetHeader::SIZE + IPV4_HEADER_LEN + fragment_data_len,
                )
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) else {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            };
            frame
                .set_destination(dst_mac)
                .set_source(src_mac)
                .set_ether_type(EtherType::Ipv4);

            let eth_payload = frame.payload_mut();
            let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) else {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            };
            ip_packet
                .init_header()
                .set_source(src_ip)
                .set_destination(dst_ip)
                .set_protocol(protocol)
                .set_identification(identification)
                .set_ttl(ttl);
            let fragment_offset_units = u16::try_from(offset / 8)
                .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;
            let Some(header) = ip_packet.header_mut() else {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            };
            header.set_fragmentation(false, more_fragments, fragment_offset_units);

            let payload_buf = ip_packet.payload_mut();
            if payload_buf.len() < fragment_data_len {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            }
            if payload.copy_range(offset, &mut payload_buf[..fragment_data_len])
                != fragment_data_len
            {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            }
            ip_packet.finalize(fragment_data_len);

            let total_len = ip_packet.total_len();
            frame.set_payload_len(total_len);
            let frame_len = frame.as_bytes().len();
            drop(frame);
            packet.set_len(frame_len);

            if !self.transmit_packet_on(if_id, packet) {
                return Err(crate::net::types::NetworkError::TransmitFailed);
            }

            offset += fragment_data_len;
        }

        Ok(())
    }

    fn send_tcp_raw_scoped_with_ttl_payload(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: &PacketPayloadView<'_>,
        ttl: u8,
    ) -> bool {
        let Some(header) = tcp_segment.read_array::<14>(0) else {
            return false;
        };
        let src_port = u16::from_be_bytes([header[0], header[1]]);
        let dst_port = u16::from_be_bytes([header[2], header[3]]);
        let tcp_flags = header[13];

        if !crate::net::security::firewall::check_egress(
            src_ip.octets(),
            dst_ip.octets(),
            6,
            src_port,
            dst_port,
            tcp_flags,
        ) {
            self.stats.record_dropped();
            return false;
        }

        let Ok((if_id, config, resolved_src)) =
            self.resolve_ipv4_egress(scope, None, Some(src_ip), dst_ip)
        else {
            self.stats.record_dropped();
            return false;
        };

        let current_time = self.current_time();
        let dst_mac = if dst_ip.is_loopback() {
            config.mac
        } else {
            match self.resolve_mac(if_id, dst_ip, &config, current_time) {
                Some(mac) => mac,
                None => return false,
            }
        };

        let path_mtu = self.effective_ipv4_pmtu(dst_ip, current_time);
        self.send_ipv4_l4_payload_with_pmtu(
            if_id,
            config.mac,
            dst_mac,
            resolved_src,
            dst_ip,
            IpProtocol::Tcp,
            ttl,
            tcp_segment,
            path_mtu,
        )
        .is_ok()
    }

    pub fn send_tcp_payload(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: &PacketPayloadView<'_>,
    ) -> bool {
        self.send_tcp_raw_scoped_with_ttl_payload(
            crate::net::types::InterfaceScope::Any,
            src_ip,
            dst_ip,
            tcp_segment,
            64,
        )
    }

    pub fn send_tcp_payload_on(
        &mut self,
        if_id: NetIfId,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: &PacketPayloadView<'_>,
    ) -> bool {
        self.send_tcp_raw_scoped_with_ttl_payload(
            crate::net::types::InterfaceScope::Pinned(if_id),
            src_ip,
            dst_ip,
            tcp_segment,
            64,
        )
    }

    pub fn send_tcp_payload_with_ttl(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: &PacketPayloadView<'_>,
        ttl: u8,
    ) -> bool {
        self.send_tcp_raw_scoped_with_ttl_payload(
            crate::net::types::InterfaceScope::Any,
            src_ip,
            dst_ip,
            tcp_segment,
            ttl,
        )
    }

    pub fn join_multicast_group(
        &mut self,
        group: Ipv4Address,
    ) -> Result<(), crate::net::l3::igmp::IgmpError> {
        self.igmp.join_group(group)
    }

    pub fn leave_multicast_group(
        &mut self,
        group: Ipv4Address,
    ) -> Result<(), crate::net::l3::igmp::IgmpError> {
        self.igmp.leave_group(group)
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

        // IGMPタイマー進行とpending送信を周期処理に接続する。
        // これにより受信イベントが無い期間でもMembership Report/Leaveを排出できる。
        self.igmp.update_time(now);
        self.send_pending_igmp_reports();

        // Endpoint-owned TCP timers/retransmits are driven from the endpoint event
        // task via `tcb_table().tick()`. The integrated stack keeps only generic
        // timeout-wheel work here.
        let expired = self.timeout_wheel.tick(now);

        for timer in expired {
            match timer.kind {
                // Other timer kinds handled elsewhere or to be implemented
                _ => {}
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
        self.igmp.set_local_ip(new_ip);

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
    pub fn enqueue_apply_ipv6_global_address(&mut self, addr: crate::net::l3::ipv6::Ipv6Address) {
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
                if let Some(msg) =
                    NdpProcessor::build_ns(&src, &dst, &target, self.config.mac.as_bytes())
                {
                    let msg = crate::net::payload::PacketPayloadView::new(&msg);
                    self.send_ipv6_icmpv6(&src, &dst, &msg);
                }
            }
        }
    }

    /// Expire timed-out NDP pending packets
    pub fn expire_ndp_pending(&mut self) {
        let current_time = self.current_time.load(Ordering::Relaxed);
        self.ndp_pending_queue.expire(current_time);
    }
}
