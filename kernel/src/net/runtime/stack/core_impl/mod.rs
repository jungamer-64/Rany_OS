// ============================================================================
// kernel/src/net/runtime/stack/core_impl/mod.rs - ランタイム / スタック / コア実装 モジュール
// ============================================================================

use super::NetIfId;
use super::*;
use crate::net::payload::PacketPayloadView;
use crate::net::runtime::device::{TxAdmissionError, TxBody, TxFrame};
use kernel_api::resource::net::{PacketByteCount, PacketPayload, PacketRef, RetainedPayloadFront};

fn set_packet_visible_len(
    packet: &mut PacketRef,
    len: usize,
) -> Result<(), crate::net::types::NetworkError> {
    let len = PacketByteCount::new(len).ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
    packet
        .try_resize(len.get())
        .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)
}

/// Ethernet and IPv4 header fields shared by every frame of one datagram.
struct Ipv4FrameHeader {
    src_mac: MacAddress,
    dst_mac: MacAddress,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    protocol: IpProtocol,
    ttl: u8,
    identification: u16,
}

impl Ipv4FrameHeader {
    const LEN: usize = EthernetHeader::SIZE + crate::net::l3::ipv4::Ipv4Header::MIN_SIZE;
    const BYTE_LEN: PacketByteCount = match PacketByteCount::new(Self::LEN) {
        Some(len) => len,
        None => panic!("Ethernet and IPv4 headers are non-empty"),
    };

    /// Write the Ethernet and IPv4 headers of a frame carrying
    /// `payload_len` IP payload bytes into `buffer` of exactly `LEN` bytes.
    fn write(
        &self,
        buffer: &mut [u8],
        payload_len: usize,
        more_fragments: bool,
        fragment_offset_units: u16,
    ) -> Result<(), crate::net::types::NetworkError> {
        const IPV4_HEADER_LEN: usize = crate::net::l3::ipv4::Ipv4Header::MIN_SIZE;
        let total_len = IPV4_HEADER_LEN
            .checked_add(payload_len)
            .and_then(|len| u16::try_from(len).ok())
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        if buffer.len() != Self::LEN {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }
        let Some(mut frame) = EthernetFrameMut::new(buffer) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        frame
            .set_destination(self.dst_mac)
            .set_source(self.src_mac)
            .set_ether_type(EtherType::Ipv4);
        let Some(mut ip_packet) = Ipv4PacketMut::new(frame.payload_mut()) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        ip_packet
            .init_header()
            .set_source(self.src_ip)
            .set_destination(self.dst_ip)
            .set_protocol(self.protocol)
            .set_identification(self.identification)
            .set_ttl(self.ttl);
        let Some(header) = ip_packet.header_mut() else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        header.set_total_length(total_len);
        header.set_fragmentation(
            !more_fragments && fragment_offset_units == 0,
            more_fragments,
            fragment_offset_units,
        );
        header.set_checksum(0);
        ip_packet.update_checksum();
        Ok(())
    }
}

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
        self.interface_config(if_id)
    }

    fn default_interface_id(&self) -> Option<NetIfId> {
        self.reconciled_primary
            .filter(|if_id| self.interfaces.contains_key(if_id))
    }

    pub(crate) fn interface_state_for_ingress(
        &self,
        if_id: NetIfId,
    ) -> Option<(NetIfId, &InterfaceStackState)> {
        self.interfaces.get(&if_id).map(|state| (if_id, state))
    }

    pub(crate) fn interface_state_for_ingress_mut(
        &mut self,
        if_id: NetIfId,
    ) -> Option<(NetIfId, &mut InterfaceStackState)> {
        self.interfaces.get_mut(&if_id).map(|state| (if_id, state))
    }

    pub(crate) fn primary_interface_state(&self) -> Option<(NetIfId, &InterfaceStackState)> {
        self.default_interface_id()
            .and_then(|if_id| self.interfaces.get(&if_id).map(|state| (if_id, state)))
    }

    pub(crate) fn primary_interface_config(&self) -> Option<NetworkConfig> {
        self.primary_interface_state()
            .map(|(_, state)| state.config())
    }

    pub(crate) fn primary_interface_state_mut(
        &mut self,
    ) -> Option<(NetIfId, &mut InterfaceStackState)> {
        let if_id = self.default_interface_id()?;
        self.interfaces.get_mut(&if_id).map(|state| (if_id, state))
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

    pub(crate) fn resolve_ipv4_egress_on(
        &self,
        if_id: NetIfId,
        explicit_src: Option<Ipv4Address>,
    ) -> Result<(NetworkConfig, Ipv4Address), crate::net::types::NetworkError> {
        if !crate::net::runtime::manager::is_interface_operational_in(self.runtime, if_id) {
            return Err(crate::net::types::NetworkError::NetworkUnreachable);
        }
        let config = self
            .interface_config_or_runtime(if_id)
            .ok_or(crate::net::types::NetworkError::NetworkUnreachable)?;

        let src_ip = self.select_ipv4_source(config, explicit_src)?;
        Ok((config, src_ip))
    }

    pub(crate) fn resolve_ipv6_egress_on(
        &self,
        if_id: NetIfId,
        explicit_src: Option<Ipv6Address>,
        dst_ip: Ipv6Address,
    ) -> Result<(NetworkConfig, Ipv6Address), crate::net::types::NetworkError> {
        if !crate::net::runtime::manager::is_interface_operational_in(self.runtime, if_id) {
            return Err(crate::net::types::NetworkError::NetworkUnreachable);
        }
        let config = self
            .interface_config_or_runtime(if_id)
            .ok_or(crate::net::types::NetworkError::NetworkUnreachable)?;

        let src_ip = self.select_ipv6_source(config, explicit_src, dst_ip)?;
        Ok((config, src_ip))
    }

    pub fn send_raw_ip_payload_on(
        &mut self,
        if_id: NetIfId,
        payload: PacketPayload,
    ) -> Result<(), crate::net::types::NetworkPayloadError> {
        let view = PacketPayloadView::new(&payload);
        let Some(version) = view.first_byte().map(|byte| byte >> 4) else {
            return Err(crate::net::types::NetworkPayloadError::new(
                crate::net::types::NetworkError::BufferTooSmall,
                payload,
            ));
        };

        match version {
            4 => self.send_raw_ipv4_payload_on(if_id, payload),
            6 => self.send_raw_ipv6_payload_on(if_id, payload),
            _ => Err(crate::net::types::NetworkPayloadError::new(
                crate::net::types::NetworkError::InvalidAddress,
                payload,
            )),
        }
    }

    fn send_raw_ipv4_payload_on(
        &mut self,
        if_id: NetIfId,
        payload: PacketPayload,
    ) -> Result<(), crate::net::types::NetworkPayloadError> {
        let payload_view = PacketPayloadView::new(&payload);
        let parsed = (|| {
            let fixed = payload_view
                .read_array::<20>(0)
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            if (fixed[0] >> 4) != 4 {
                return Err(crate::net::types::NetworkError::InvalidAddress);
            }
            let ihl = ((fixed[0] & 0x0f) as usize) * 4;
            if !(20..=60).contains(&ihl) {
                return Err(crate::net::types::NetworkError::InvalidAddress);
            }
            let header_storage = payload_view
                .read_fixed_bytes::<60>(0, ihl)
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            let header = header_storage.as_slice();
            let total_len = u16::from_be_bytes([header[2], header[3]]) as usize;
            if total_len < ihl || total_len != payload_view.total_len() {
                return Err(crate::net::types::NetworkError::InvalidAddress);
            }
            if !crate::net::l3::ipv4::Ipv4Header::header_checksum_is_valid(&header[..ihl]) {
                return Err(crate::net::types::NetworkError::InvalidAddress);
            }
            let src_ip = crate::net::l3::ipv4::Ipv4Address::new([
                header[12], header[13], header[14], header[15],
            ]);
            let dst_ip = crate::net::l3::ipv4::Ipv4Address::new([
                header[16], header[17], header[18], header[19],
            ]);
            let protocol = header[9];
            let (src_port, dst_port, tcp_flags) = match protocol {
                6 if total_len >= ihl + 14 => {
                    let ports = payload_view
                        .read_array::<14>(ihl)
                        .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
                    (
                        u16::from_be_bytes([ports[0], ports[1]]),
                        u16::from_be_bytes([ports[2], ports[3]]),
                        ports[13],
                    )
                }
                17 if total_len >= ihl + 4 => {
                    let ports = payload_view
                        .read_array::<4>(ihl)
                        .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
                    (
                        u16::from_be_bytes([ports[0], ports[1]]),
                        u16::from_be_bytes([ports[2], ports[3]]),
                        0,
                    )
                }
                _ => (0, 0, 0),
            };
            Ok((
                src_ip, dst_ip, protocol, header[8], src_port, dst_port, tcp_flags,
            ))
        })();
        let (src_ip, dst_ip, protocol, ttl, src_port, dst_port, tcp_flags) = match parsed {
            Ok(parsed) => parsed,
            Err(cause) => {
                return Err(crate::net::types::NetworkPayloadError::new(cause, payload));
            }
        };

        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            src_ip.octets(),
            dst_ip.octets(),
            protocol,
            src_port,
            dst_port,
            tcp_flags,
        ) {
            self.record_dropped_on(if_id);
            return Err(crate::net::types::NetworkPayloadError::new(
                crate::net::types::NetworkError::PermissionDenied,
                payload,
            ));
        }

        let (config, _) = match self.resolve_ipv4_egress_on(if_id, Some(src_ip)) {
            Ok(egress) => egress,
            Err(cause) => {
                return Err(crate::net::types::NetworkPayloadError::new(cause, payload));
            }
        };
        let current_time = self.current_time();
        let mut pending_payload = Some(payload);
        let dst_mac = if dst_ip.is_loopback() {
            config.mac
        } else {
            match self.resolve_arp_for_send(if_id, dst_ip, current_time, |pending| {
                pending.enqueue_raw(
                    src_ip,
                    dst_ip,
                    IpProtocol::from(protocol),
                    ttl,
                    pending_payload
                        .take()
                        .expect("pending raw IPv4 payload must exist"),
                    current_time,
                );
            }) {
                Some(mac) => mac,
                None => {
                    return match pending_payload.take() {
                        Some(payload) => Err(crate::net::types::NetworkPayloadError::new(
                            crate::net::types::NetworkError::ArpResolutionPending,
                            payload,
                        )),
                        None => Ok(()),
                    };
                }
            }
        };

        let raw_payload = pending_payload
            .take()
            .expect("resolved raw IPv4 payload must exist");
        let packet = match self.build_ethernet_header_packet(config.mac, dst_mac, EtherType::Ipv4) {
            Ok(packet) => packet,
            Err(cause) => {
                return Err(crate::net::types::NetworkPayloadError::new(
                    cause,
                    raw_payload,
                ));
            }
        };
        match self.transmit_frame_on(
            if_id,
            TxFrame::with_header(packet, TxBody::Owned(raw_payload)),
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                let cause = match error.cause() {
                    crate::net::runtime::device::TxAdmissionCause::TooManySegments => {
                        crate::net::types::NetworkError::BufferTooSmall
                    }
                    _ => crate::net::types::NetworkError::TransmitFailed,
                };
                let (_header, body) = error.into_frame().into_parts();
                match body {
                    TxBody::Owned(payload) => {
                        Err(crate::net::types::NetworkPayloadError::new(cause, payload))
                    }
                    TxBody::Retained(_) => {
                        unreachable!("an owned raw payload is never frozen by a rejected admission")
                    }
                }
            }
        }
    }

    fn send_raw_ipv6_payload_on(
        &mut self,
        if_id: NetIfId,
        payload: PacketPayload,
    ) -> Result<(), crate::net::types::NetworkPayloadError> {
        let payload_view = PacketPayloadView::new(&payload);
        let Some(header) = payload_view.read_array::<40>(0) else {
            return Err(crate::net::types::NetworkPayloadError::new(
                crate::net::types::NetworkError::BufferTooSmall,
                payload,
            ));
        };
        if (header[0] >> 4) != 6 {
            return Err(crate::net::types::NetworkPayloadError::new(
                crate::net::types::NetworkError::InvalidAddress,
                payload,
            ));
        }

        let total_len = IPV6_HEADER_SIZE + u16::from_be_bytes([header[4], header[5]]) as usize;
        if total_len != payload_view.total_len() {
            return Err(crate::net::types::NetworkPayloadError::new(
                crate::net::types::NetworkError::InvalidAddress,
                payload,
            ));
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

        let (config, _) = match self.resolve_ipv6_egress_on(if_id, Some(src_ip), dst_ip) {
            Ok(egress) => egress,
            Err(cause) => {
                return Err(crate::net::types::NetworkPayloadError::new(cause, payload));
            }
        };
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
                    self.send_ipv6_icmpv6_raw_on(ns_if_id, &our_ll, &solicited, ns_msg);
                    return Err(crate::net::types::NetworkPayloadError::new(
                        crate::net::types::NetworkError::ArpResolutionPending,
                        payload,
                    ));
                }
                None => {
                    return Err(crate::net::types::NetworkPayloadError::new(
                        crate::net::types::NetworkError::NetworkUnreachable,
                        payload,
                    ));
                }
            }
        };

        let transport_offset = IPV6_HEADER_SIZE;
        let (src_port, dst_port, tcp_flags) = match next_header {
            6 if total_len >= transport_offset + 14 => {
                let ports = payload_view
                    .read_array::<14>(transport_offset)
                    .expect("validated IPv6 TCP header remains readable");
                (
                    u16::from_be_bytes([ports[0], ports[1]]),
                    u16::from_be_bytes([ports[2], ports[3]]),
                    ports[13],
                )
            }
            17 if total_len >= transport_offset + 4 => {
                let ports = payload_view
                    .read_array::<4>(transport_offset)
                    .expect("validated IPv6 UDP header remains readable");
                (
                    u16::from_be_bytes([ports[0], ports[1]]),
                    u16::from_be_bytes([ports[2], ports[3]]),
                    0,
                )
            }
            _ => (0, 0, 0),
        };

        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            crate::net::security::firewall::IpAddress::V6(src_ip.octets()),
            crate::net::security::firewall::IpAddress::V6(dst_ip.octets()),
            next_header,
            src_port,
            dst_port,
            tcp_flags,
        ) {
            self.record_dropped_on(if_id);
            return Err(crate::net::types::NetworkPayloadError::new(
                crate::net::types::NetworkError::PermissionDenied,
                payload,
            ));
        }

        let packet = match self.build_ethernet_header_packet(config.mac, dst_mac, EtherType::Ipv6) {
            Ok(packet) => packet,
            Err(cause) => {
                return Err(crate::net::types::NetworkPayloadError::new(cause, payload));
            }
        };
        match self.transmit_frame_on(if_id, TxFrame::with_header(packet, TxBody::Owned(payload))) {
            Ok(()) => Ok(()),
            Err(error) => {
                let cause = match error.cause() {
                    crate::net::runtime::device::TxAdmissionCause::TooManySegments => {
                        crate::net::types::NetworkError::BufferTooSmall
                    }
                    _ => crate::net::types::NetworkError::TransmitFailed,
                };
                let (_header, body) = error.into_frame().into_parts();
                match body {
                    TxBody::Owned(payload) => {
                        Err(crate::net::types::NetworkPayloadError::new(cause, payload))
                    }
                    TxBody::Retained(_) => {
                        unreachable!("an owned raw payload is never frozen by a rejected admission")
                    }
                }
            }
        }
    }

    /// Create a new network stack with configuration
    ///
    /// # パフォーマンス注意
    /// NetworkConfig is copied as scalar configuration at the stack boundary.
    pub fn new_in(runtime: NetRuntimeHandle) -> Self {
        NetworkStack {
            runtime,
            interfaces: BTreeMap::new(),
            applied_topology_revision:
                crate::net::runtime::manager::InterfaceTopologyRevision::INITIAL,
            reconciled_primary: None,
            timeout_wheel: TimeoutWheel::new(100), // 100ms resolution
            transmit_fn: crate::net::runtime::bridge::transmit_from_stack_in,
            current_time: AtomicU64::new(0),
        }
    }

    /// Register or refresh per-interface state.
    pub fn register_interface_state(&mut self, if_id: NetIfId, config: NetworkConfig) {
        match self.interfaces.get_mut(&if_id) {
            Some(state) if state.config != config => {
                state.set_config(config);
            }
            Some(_) => {}
            None => {
                let state = InterfaceStackState::new(config);
                self.interfaces.insert(if_id, state);
            }
        }
    }

    pub(crate) fn needs_interface_topology_revision(
        &self,
        revision: crate::net::runtime::manager::InterfaceTopologyRevision,
    ) -> bool {
        self.applied_topology_revision != revision
    }

    pub(crate) fn reconcile_interface_topology(
        &mut self,
        topology: crate::net::runtime::manager::InterfaceTopologySnapshot,
    ) {
        let revision = topology.revision();
        let primary = topology.primary();
        self.interfaces.retain(|if_id, _| topology.contains(*if_id));

        for entry in topology.into_entries() {
            self.register_interface_state(entry.if_id, entry.config);
        }
        self.reconciled_primary = primary;
        self.applied_topology_revision = revision;
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

    fn record_rx_error_on(&self, if_id: NetIfId) {
        if let Some(stats) = self.interface_stats(if_id) {
            stats.record_rx_error();
        }
    }

    /// A CPU stack can lag topology publication during startup or removal.
    /// Rejection remains valid without a local counter for the selected interface.
    fn record_dropped_on(&self, if_id: NetIfId) {
        if let Some(stats) = self.interface_stats(if_id) {
            stats.record_dropped();
        }
    }

    /// Hand `frame` to the device boundary of `if_id`.
    ///
    /// # Errors
    /// Returns the unchanged frame with the reason the device did not admit it.
    pub(crate) fn transmit_frame_on(
        &self,
        if_id: NetIfId,
        frame: TxFrame,
    ) -> Result<(), TxAdmissionError> {
        let frame_len = frame.total_len();
        match (self.transmit_fn)(
            self.runtime,
            if_id,
            frame,
            kernel_api::service::netdev::NetTxMeta::default(),
        ) {
            Ok(()) => {
                self.record_tx_success_on(if_id, frame_len);
                Ok(())
            }
            Err(error) => {
                self.record_tx_error_on(if_id);
                Err(error)
            }
        }
    }

    fn record_tx_success_on(&self, if_id: NetIfId, packet_len: usize) {
        if let Some(stats) = self.interface_stats(if_id) {
            stats.record_tx(packet_len);
        }
    }

    fn record_tx_error_on(&self, if_id: NetIfId) {
        if let Some(stats) = self.interface_stats(if_id) {
            stats.record_tx_error();
        }
    }

    /// Allocate a packet for a complete generated frame, at least the minimum
    /// Ethernet frame length long so short frames are padded with zeros.
    fn alloc_ethernet_frame_packet(&self, frame_len: usize) -> Option<PacketRef> {
        crate::net::payload::alloc_packet_with_headroom_in(self.runtime, frame_len.max(60), 0)
    }

    /// Allocate a generated-header packet of exactly `header_len` bytes. Its
    /// tailroom lets the device boundary move a small leading body segment in.
    pub(crate) fn alloc_header_packet(&self, header_len: usize) -> Option<PacketRef> {
        crate::net::payload::alloc_packet_with_headroom_in(self.runtime, header_len, 0)
    }

    fn build_ethernet_header_packet(
        &self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        ether_type: EtherType,
    ) -> Result<PacketRef, crate::net::types::NetworkError> {
        let mut packet = self
            .alloc_header_packet(EthernetHeader::SIZE)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        frame
            .set_destination(dst_mac)
            .set_source(src_mac)
            .set_ether_type(ether_type);
        Ok(packet)
    }

    fn effective_ipv4_pmtu(
        &mut self,
        if_id: NetIfId,
        dst_ip: Ipv4Address,
        current_time: u64,
    ) -> usize {
        self.interfaces
            .get_mut(&if_id)
            .map(|state| {
                state
                    .ipv4
                    .get_pmtu(dst_ip, current_time)
                    .max(crate::net::l3::ipv4::PmtuEntry::MIN_MTU)
                    .min(crate::net::runtime::stack::MTU as u16) as usize
            })
            .unwrap_or(crate::net::runtime::stack::MTU)
    }

    /// Send `body` in one IPv4 datagram, or in fragments when it exceeds the
    /// path MTU. An owned body takes its headers in place when its headroom
    /// allows; otherwise each frame carries its own generated header packet
    /// followed by a retained window of the body.
    fn send_ipv4_l4_payload_with_pmtu(
        &mut self,
        if_id: NetIfId,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        protocol: IpProtocol,
        ttl: u8,
        body: TxBody,
        path_mtu: usize,
    ) -> Result<(), crate::net::types::NetworkError> {
        const IPV4_HEADER_LEN: usize = crate::net::l3::ipv4::Ipv4Header::MIN_SIZE;
        const MAX_IPV4_PAYLOAD_LEN: usize = (u16::MAX as usize) - IPV4_HEADER_LEN;
        let payload_len = body.total_len();

        if payload_len > MAX_IPV4_PAYLOAD_LEN {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        let Some(unfragmented_payload_limit) = path_mtu.checked_sub(IPV4_HEADER_LEN) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        let Some(state) = self.interfaces.get_mut(&if_id) else {
            return Err(crate::net::types::NetworkError::NetworkUnreachable);
        };
        let identification = state.ipv4.next_id(dst_ip);
        let header = Ipv4FrameHeader {
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            protocol,
            ttl,
            identification,
        };

        if payload_len <= unfragmented_payload_limit {
            let frame = match body {
                TxBody::Owned(mut payload) => {
                    match payload.try_prepend_in_place(Ipv4FrameHeader::BYTE_LEN) {
                        Ok(buffer) => {
                            header.write(buffer, payload_len, false, 0)?;
                            TxFrame::whole(payload)
                        }
                        Err(_) => {
                            let packet =
                                self.build_ipv4_header_packet(&header, payload_len, false, 0)?;
                            TxFrame::with_header(packet, TxBody::Owned(payload))
                        }
                    }
                }
                retained @ TxBody::Retained(_) => {
                    let packet = self.build_ipv4_header_packet(&header, payload_len, false, 0)?;
                    TxFrame::with_header(packet, retained)
                }
            };
            return self
                .transmit_frame_on(if_id, frame)
                .map_err(|_| crate::net::types::NetworkError::TransmitFailed);
        }

        let non_last_fragment_len = unfragmented_payload_limit & !0x7;
        if non_last_fragment_len == 0 {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        let mut remaining_body = Some(body.into_retained());
        let mut offset = 0usize;
        // LOOP_PROOF: mode=condition; reason=Each iteration consumes the remaining body and keeps only a strictly shorter remainder, ending when the last fragment takes it whole.;
        while let Some(retained) = remaining_body.take() {
            let remaining = payload_len - offset;
            let more_fragments = remaining > unfragmented_payload_limit;
            let fragment_data_len = if more_fragments {
                non_last_fragment_len
            } else {
                remaining
            };
            let fragment_offset_units = u16::try_from(offset / 8)
                .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;
            let fragment_body = if more_fragments {
                let fragment_len = PacketByteCount::new(fragment_data_len)
                    .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
                match retained.try_take_front(fragment_len) {
                    Ok(RetainedPayloadFront::Prefix { front, remainder }) => {
                        remaining_body = Some(remainder);
                        front
                    }
                    Ok(RetainedPayloadFront::Whole(front)) => front,
                    Err(_) => return Err(crate::net::types::NetworkError::ResourceExhausted),
                }
            } else {
                retained
            };
            let packet = self.build_ipv4_header_packet(
                &header,
                fragment_data_len,
                more_fragments,
                fragment_offset_units,
            )?;
            // A rejected fragment ends the datagram; fragments already admitted
            // are discarded by the receiver's reassembly timeout.
            self.transmit_frame_on(
                if_id,
                TxFrame::with_header(packet, TxBody::Retained(fragment_body)),
            )
            .map_err(|_| crate::net::types::NetworkError::TransmitFailed)?;
            offset += fragment_data_len;
        }
        Ok(())
    }

    fn build_ipv4_header_packet(
        &self,
        header: &Ipv4FrameHeader,
        payload_len: usize,
        more_fragments: bool,
        fragment_offset_units: u16,
    ) -> Result<PacketRef, crate::net::types::NetworkError> {
        let mut packet = self
            .alloc_header_packet(Ipv4FrameHeader::LEN)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        header.write(
            packet.data_mut(),
            payload_len,
            more_fragments,
            fragment_offset_units,
        )?;
        Ok(packet)
    }

    fn send_tcp_raw_on_with_ttl_payload(
        &mut self,
        if_id: NetIfId,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: TxBody,
        ttl: u8,
    ) -> bool {
        let tcp_segment_view = PacketPayloadView::new(tcp_segment.payload());
        let Some(header) = tcp_segment_view.read_array::<14>(0) else {
            return false;
        };
        let src_port = u16::from_be_bytes([header[0], header[1]]);
        let dst_port = u16::from_be_bytes([header[2], header[3]]);
        let tcp_flags = header[13];

        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            src_ip.octets(),
            dst_ip.octets(),
            6,
            src_port,
            dst_port,
            tcp_flags,
        ) {
            self.record_dropped_on(if_id);
            return false;
        }

        let Ok((config, resolved_src)) = self.resolve_ipv4_egress_on(if_id, Some(src_ip)) else {
            self.record_dropped_on(if_id);
            return false;
        };

        let current_time = self.current_time();
        let mut pending_segment = Some(tcp_segment);
        let dst_mac = if dst_ip.is_loopback() {
            config.mac
        } else {
            match self.resolve_arp_for_send(if_id, dst_ip, current_time, |pending| {
                pending.enqueue_tcp(
                    resolved_src,
                    dst_ip,
                    ttl,
                    pending_segment
                        .take()
                        .expect("pending TCP segment must exist"),
                    current_time,
                );
            }) {
                Some(mac) => mac,
                None => return false,
            }
        };

        let path_mtu = self.effective_ipv4_pmtu(if_id, dst_ip, current_time);
        let tcp_segment = pending_segment
            .take()
            .expect("resolved TCP segment must exist");
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

    pub(crate) fn send_tcp_payload_on(
        &mut self,
        if_id: NetIfId,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: TxBody,
    ) -> bool {
        self.send_tcp_raw_on_with_ttl_payload(if_id, src_ip, dst_ip, tcp_segment, 64)
    }

    pub(crate) fn send_tcp_payload_on_with_ttl(
        &mut self,
        if_id: NetIfId,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: TxBody,
        ttl: u8,
    ) -> bool {
        self.send_tcp_raw_on_with_ttl_payload(if_id, src_ip, dst_ip, tcp_segment, ttl)
    }

    pub fn join_multicast_group_on(
        &mut self,
        if_id: NetIfId,
        group: Ipv4Address,
    ) -> Result<(), crate::net::l3::igmp::IgmpError> {
        let Some(state) = self.interfaces.get_mut(&if_id) else {
            return Err(crate::net::l3::igmp::IgmpError::InvalidGroupAddress);
        };
        state.igmp.join_group(group)
    }

    pub fn leave_multicast_group_on(
        &mut self,
        if_id: NetIfId,
        group: Ipv4Address,
    ) -> Result<(), crate::net::l3::igmp::IgmpError> {
        let Some(state) = self.interfaces.get_mut(&if_id) else {
            return Err(crate::net::l3::igmp::IgmpError::InvalidGroupAddress);
        };
        state.igmp.leave_group(group)
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
        for state in self.interfaces.values_mut() {
            state.igmp.update_time(now);
        }

        let revision =
            crate::net::runtime::manager::current_interface_topology_revision_in(self.runtime);
        if self.needs_interface_topology_revision(revision) {
            let _ = crate::net::runtime::command::try_enqueue_command_in(
                self.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(
                    crate::net::runtime::command::ControlCommand::InterfaceTopologyDirty {
                        revision,
                    },
                ),
            );
        }
        self.send_pending_igmp_reports();

        // Expire timed-out pending packets
        self.expire_arp_pending();
        self.expire_ndp_pending();
        self.expire_fragment_reassembly(now);

        // Runtime-owned TCP timers/retransmits are driven from the endpoint event
        // task via the transport state's TCB table. The integrated stack keeps only generic
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
        self.primary_interface_state()
            .map(|(_, state)| state.config)
            .expect("network stack config requested without registered interface state")
    }

    /// ICMP echo が有効かチェック
    #[inline]
    pub fn icmp_echo_enabled(&self) -> bool {
        self.primary_interface_state()
            .is_some_and(|(_, state)| state.config.icmp_echo_enabled)
    }

    /// MAC アドレスを取得
    #[inline]
    pub fn mac_address(&self) -> MacAddress {
        self.primary_interface_state()
            .map(|(_, state)| state.config.mac)
            .expect("network stack MAC requested without registered interface state")
    }

    /// IPv4 アドレスを取得
    #[inline]
    pub fn ipv4_address(&self) -> Ipv4Address {
        self.primary_interface_state()
            .map(|(_, state)| state.config.ipv4.address)
            .expect("network stack IPv4 address requested without registered interface state")
    }

    /// Update configuration
    pub fn set_config(&mut self, config: NetworkConfig) {
        let Some((primary_if_id, state)) = self.primary_interface_state_mut() else {
            return;
        };
        let old_ip = state.config.ipv4.address;
        let new_ip = config.ipv4.address;

        state.set_config(config);

        // RFC 2131 Section 4.4.1: Send Gratuitous ARP when IP address is assigned or changed.
        // This updates the ARP cache of other hosts on the network.
        if new_ip != Ipv4Address::ANY && new_ip != old_ip {
            self.send_arp_request_on(primary_if_id, new_ip);
        }
    }

    /// Apply a DHCPv6-obtained global IPv6 address to the stack
    pub fn apply_ipv6_global_address_on(
        &mut self,
        if_id: NetIfId,
        addr: crate::net::l3::ipv6::Ipv6Address,
    ) {
        let Some(state) = self.interfaces.get_mut(&if_id) else {
            return;
        };
        if let Some(ref mut ipv6_proc) = state.ipv6 {
            ipv6_proc.set_global_address(addr);
        }
        if let Some(ref mut ndp_proc) = state.ndp {
            ndp_proc.add_global_address(addr);
        }
        self.initiate_ipv6_dad_on(if_id, addr);
    }

    /// Initiate DAD for an IPv6 address
    pub fn initiate_ipv6_dad_on(&mut self, if_id: NetIfId, addr: Ipv6Address) {
        let dad = {
            let Some(state) = self.interfaces.get_mut(&if_id) else {
                return;
            };
            let Some(ref mut ndp) = state.ndp else {
                return;
            };
            match ndp.initiate_dad(&addr) {
                NdpResult::SendNeighborSolicitation { src, dst, target } => {
                    NdpProcessor::build_ns(&src, &dst, &target, state.config.mac.as_bytes())
                        .map(|msg| (if_id, src, dst, msg))
                }
                _ => None,
            }
        };
        if let Some((if_id, src, dst, msg)) = dad {
            self.send_ipv6_icmpv6_raw_on(if_id, &src, &dst, msg);
        }
    }

    /// Expire timed-out NDP pending packets
    pub fn expire_ndp_pending(&mut self) {
        let current_time = self.current_time.load(Ordering::Relaxed);
        for state in self.interfaces.values_mut() {
            state.ndp_pending_queue.expire(current_time);
        }
    }

    /// Run the IPv4 and IPv6 reassembly timers on every interface. Datagrams
    /// are reclaimed here even when no further fragment arrives, and each one
    /// whose first fragment was received is reported to its source with a
    /// Time Exceeded (fragment reassembly) message.
    fn expire_fragment_reassembly(&mut self, now: u64) {
        let mut expired_v4 = Vec::new();
        let mut expired_v6 = Vec::new();
        for (if_id, state) in self.interfaces.iter_mut() {
            let (v4, v6) = state.expire_fragment_reassembly(now);
            expired_v4.extend(v4.into_iter().map(|datagram| (*if_id, datagram)));
            expired_v6.extend(v6.into_iter().map(|datagram| (*if_id, datagram)));
        }
        for (if_id, datagram) in expired_v4 {
            self.send_icmp_time_exceeded_payload(
                if_id,
                datagram.source,
                crate::net::l3::icmp::TimeExceededCode::FragmentReassemblyExceeded,
                datagram.quoted,
            );
        }
        for (if_id, datagram) in expired_v6 {
            self.send_icmpv6_time_exceeded_on(if_id, datagram.source, 1, datagram.quoted);
        }
    }

    /// Expire timed-out ARP pending packets
    pub fn expire_arp_pending(&mut self) {
        let current_time = self.current_time.load(Ordering::Relaxed);
        for state in self.interfaces.values_mut() {
            state.arp_pending_queue.expire(current_time);
        }
    }
}

#[cfg(feature = "qemu-test-export")]
pub(crate) mod qemu_tests;
