// ============================================================================
// kernel/src/net/runtime/stack/core_impl/mod.rs - ランタイム / スタック / コア実装 モジュール
// ============================================================================

use super::NetIfId;
use super::*;
use crate::net::payload::PacketPayloadView;
use crate::net::runtime::device::{OwnedTxPayloadWindow, TxFragmentWindow};
use kernel_api::resource::net::{PacketByteCount, PacketPayload, PacketRef};
use kernel_api::service::netdev::NetTxSegment;

mod global_instance;
pub(crate) use global_instance::*;
/// Protocol-specific NetworkStack impl methods (IGMP, ARP, ICMP, TCP bind, UDP raw).
mod protocol_impl;
/// Receive path — IPv4/IPv6 incoming packet processing.
mod receive;
/// Send path — IPv6 / ICMPv6 / NDP / IGMP outgoing packet construction.
mod send_v6;

struct FragmentTxPacket {
    header: PacketRef,
    descriptors: Vec<NetTxSegment>,
    frame_len: usize,
}

impl NetworkStack {
    pub(crate) fn interface_config_or_runtime(&self, if_id: NetIfId) -> Option<NetworkConfig> {
        self.interface_config(if_id)
    }

    fn default_interface_id(&self) -> Option<NetIfId> {
        self.primary_interface
            .filter(|if_id| self.interfaces.contains_key(if_id))
            .or_else(|| self.interfaces.keys().next().copied())
    }

    pub(crate) fn interface_state_for_ingress(
        &self,
        if_id: Option<NetIfId>,
    ) -> Option<(NetIfId, &InterfaceStackState)> {
        match if_id {
            Some(if_id) => self.interfaces.get(&if_id).map(|state| (if_id, state)),
            None => self
                .default_interface_id()
                .and_then(|if_id| self.interfaces.get(&if_id).map(|state| (if_id, state))),
        }
    }

    pub(crate) fn interface_state_for_ingress_mut(
        &mut self,
        if_id: Option<NetIfId>,
    ) -> Option<(NetIfId, &mut InterfaceStackState)> {
        let selected_if_id = match if_id {
            Some(if_id) if self.interfaces.contains_key(&if_id) => if_id,
            Some(_) => return None,
            None => self.default_interface_id()?,
        };
        self.interfaces
            .get_mut(&selected_if_id)
            .map(|state| (selected_if_id, state))
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

    pub(crate) fn resolve_ipv4_egress(
        &self,
        scope: crate::net::types::InterfaceScope,
        preferred_if: Option<NetIfId>,
        explicit_src: Option<Ipv4Address>,
        dst_ip: Ipv4Address,
    ) -> Result<(NetIfId, NetworkConfig, Ipv4Address), crate::net::types::NetworkError> {
        let resolved = scope
            .as_if_id()
            .or(preferred_if)
            .map(|if_id| {
                self.interface_config_or_runtime(if_id)
                    .map(|cfg| (if_id, cfg))
                    .ok_or(crate::net::types::NetworkError::NetworkUnreachable)
            })
            .transpose()?
            .or_else(|| {
                crate::net::runtime::manager::lookup_ipv4_route_in(self.runtime, dst_ip)
                    .ok()
                    .flatten()
                    .and_then(|route| {
                        self.interface_config_or_runtime(route.if_id)
                            .map(|cfg| (route.if_id, cfg))
                    })
            })
            .or_else(|| {
                self.default_interface_id()
                    .and_then(|if_id| self.interface_config(if_id).map(|cfg| (if_id, cfg)))
            })
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
    ) -> Result<(NetIfId, NetworkConfig, Ipv6Address), crate::net::types::NetworkError> {
        let resolved = scope
            .as_if_id()
            .or(preferred_if)
            .map(|if_id| {
                self.interface_config_or_runtime(if_id)
                    .map(|cfg| (if_id, cfg))
                    .ok_or(crate::net::types::NetworkError::NetworkUnreachable)
            })
            .transpose()?
            .or_else(|| {
                crate::net::runtime::manager::lookup_ipv6_route_in(self.runtime, dst_ip)
                    .ok()
                    .flatten()
                    .and_then(|route| {
                        self.interface_config_or_runtime(route.if_id)
                            .map(|cfg| (route.if_id, cfg))
                    })
            })
            .or_else(|| {
                self.default_interface_id()
                    .and_then(|if_id| self.interface_config(if_id).map(|cfg| (if_id, cfg)))
            })
            .ok_or(crate::net::types::NetworkError::NetworkUnreachable)?;

        let src_ip = self.select_ipv6_source(resolved.1, explicit_src, dst_ip)?;
        Ok((resolved.0, resolved.1, src_ip))
    }

    pub(crate) fn resolve_ingress_if(&self, if_id: Option<NetIfId>) -> Option<NetIfId> {
        if let Some(if_id) = if_id {
            return self.interfaces.contains_key(&if_id).then_some(if_id);
        }
        self.primary_interface
            .filter(|if_id| self.interfaces.contains_key(if_id))
            .or_else(|| {
                crate::net::runtime::manager::list_interfaces_in(self.runtime)
                    .ok()
                    .and_then(|ifaces| {
                        ifaces
                            .iter()
                            .map(|iface| iface.if_id)
                            .find(|if_id| self.interfaces.contains_key(if_id))
                    })
            })
            .or_else(|| self.interfaces.keys().next().copied())
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
            4 => self.send_raw_ipv4_payload_scoped(scope, payload),
            6 => self.send_raw_ipv6_payload_scoped(scope, payload),
            _ => Err(crate::net::types::NetworkError::InvalidAddress),
        }
    }

    fn send_raw_ipv4_payload_scoped(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        payload: PacketPayload,
    ) -> Result<(), crate::net::types::NetworkError> {
        let payload_view = PacketPayloadView::new(&payload);
        let Some(fixed) = payload_view.read_array::<20>(0) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        if (fixed[0] >> 4) != 4 {
            return Err(crate::net::types::NetworkError::InvalidAddress);
        }

        let ihl = ((fixed[0] & 0x0f) as usize) * 4;
        if !(20..=60).contains(&ihl) {
            return Err(crate::net::types::NetworkError::InvalidAddress);
        }

        let Some(header_storage) = payload_view.read_fixed_bytes::<60>(0, ihl) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        let header = header_storage.as_slice();

        let total_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if total_len < ihl || total_len != payload_view.total_len() {
            return Err(crate::net::types::NetworkError::InvalidAddress);
        }

        if u16::from_be_bytes([header[10], header[11]])
            != crate::net::l3::ipv4::calculate_ip_checksum(&header[..ihl])
        {
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

        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            src_ip.octets(),
            dst_ip.octets(),
            protocol,
            src_port,
            dst_port,
            tcp_flags,
        ) {
            self.stats().record_dropped();
            return Err(crate::net::types::NetworkError::PermissionDenied);
        }

        let (if_id, config, _) = self.resolve_ipv4_egress(scope, None, Some(src_ip), dst_ip)?;
        let current_time = self.current_time();
        let mut pending_payload = Some(payload);
        let dst_mac = if dst_ip.is_loopback() {
            config.mac
        } else {
            match self.resolve_arp_for_send(Some(if_id), dst_ip, current_time, |pending| {
                pending.enqueue_raw(
                    src_ip,
                    dst_ip,
                    IpProtocol::from(protocol),
                    header[8],
                    pending_payload
                        .take()
                        .expect("pending raw IPv4 payload must exist"),
                    current_time,
                );
            }) {
                Some(mac) => mac,
                None => return Err(crate::net::types::NetworkError::ArpResolutionPending),
            }
        };

        let packet = self.build_ethernet_header_packet(config.mac, dst_mac, EtherType::Ipv4)?;
        let mut frame_payload = kernel_api::resource::net::PacketPayload::single(packet);
        crate::net::payload::append_payload(
            &mut frame_payload,
            pending_payload
                .take()
                .expect("resolved raw IPv4 payload must exist"),
        );
        if self.transmit_packet_on(Some(if_id), frame_payload) {
            Ok(())
        } else {
            Err(crate::net::types::NetworkError::TransmitFailed)
        }
    }

    fn send_raw_ipv6_payload_scoped(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        payload: PacketPayload,
    ) -> Result<(), crate::net::types::NetworkError> {
        let payload_view = PacketPayloadView::new(&payload);
        let Some(header) = payload_view.read_array::<40>(0) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        if (header[0] >> 4) != 6 {
            return Err(crate::net::types::NetworkError::InvalidAddress);
        }

        let total_len = IPV6_HEADER_SIZE + u16::from_be_bytes([header[4], header[5]]) as usize;
        if total_len != payload_view.total_len() {
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
                Some(if_id),
                &dst_ip,
                self.current_time.load(Ordering::Relaxed),
                |_| {},
            ) {
                Some(Ok(mac)) => MacAddress::new(mac),
                Some(Err((ns_if_id, our_ll, ns_msg))) => {
                    let solicited = dst_ip.solicited_node();
                    if let Some(ns_if_id) = ns_if_id {
                        self.send_ipv6_icmpv6_raw_on(ns_if_id, &our_ll, &solicited, ns_msg);
                    } else {
                        self.send_ipv6_icmpv6_raw(&our_ll, &solicited, ns_msg);
                    }
                    return Err(crate::net::types::NetworkError::ArpResolutionPending);
                }
                None => return Err(crate::net::types::NetworkError::NetworkUnreachable),
            }
        };

        let transport_offset = IPV6_HEADER_SIZE;
        let (src_port, dst_port, tcp_flags) = match next_header {
            6 if total_len >= transport_offset + 14 => {
                let ports = payload_view
                    .read_array::<14>(transport_offset)
                    .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
                (
                    u16::from_be_bytes([ports[0], ports[1]]),
                    u16::from_be_bytes([ports[2], ports[3]]),
                    ports[13],
                )
            }
            17 if total_len >= transport_offset + 4 => {
                let ports = payload_view
                    .read_array::<4>(transport_offset)
                    .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
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
            self.stats().record_dropped();
            return Err(crate::net::types::NetworkError::PermissionDenied);
        }

        let packet = self.build_ethernet_header_packet(config.mac, dst_mac, EtherType::Ipv6)?;
        let mut frame_payload = kernel_api::resource::net::PacketPayload::single(packet);
        crate::net::payload::append_payload(&mut frame_payload, payload);
        if self.transmit_packet_on(Some(if_id), frame_payload) {
            Ok(())
        } else {
            Err(crate::net::types::NetworkError::TransmitFailed)
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
            primary_interface: None,
            timeout_wheel: TimeoutWheel::new(100), // 100ms resolution
            transmit_fn: None,
            transmit_awaits_device_completion: false,
            pending_tx_meta: None,
            current_time: AtomicU64::new(0),
        }
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

    pub fn transmit_packet_on(
        &self,
        if_id: Option<NetIfId>,
        payload: kernel_api::resource::net::PacketPayload,
    ) -> bool {
        if let Some(f) = self.transmit_fn {
            let meta = self.pending_tx_meta.unwrap_or_default();
            let packet_len = kernel_api::resource::net::PacketPayload::total_len(&payload);
            if f(self.runtime, if_id, payload, meta) {
                if !self.transmit_awaits_device_completion {
                    if let Some(completion_id) =
                        meta.device_completion_ticket().map(|ticket| ticket.get())
                    {
                        let _ = crate::net::runtime::device::complete_tx_request_in(
                            self.runtime,
                            completion_id,
                            Ok(()),
                        );
                    }
                }
                self.record_tx_success_on(if_id, packet_len);
                return true;
            }

            self.record_tx_error_on(if_id);
            return false;
        }

        false
    }

    fn record_tx_success_on(&self, if_id: Option<NetIfId>, packet_len: usize) {
        let stats = if_id
            .and_then(|if_id| self.interface_stats(if_id))
            .or_else(|| {
                self.primary_interface_state()
                    .map(|(_, state)| &state.stats)
            });
        if let Some(stats) = stats {
            stats.record_tx(packet_len);
        }
    }

    fn record_tx_error_on(&self, if_id: Option<NetIfId>) {
        let stats = if_id
            .and_then(|if_id| self.interface_stats(if_id))
            .or_else(|| {
                self.primary_interface_state()
                    .map(|(_, state)| &state.stats)
            });
        if let Some(stats) = stats {
            stats.record_tx_error();
        }
    }

    fn alloc_ethernet_frame_packet(&self, frame_len: usize) -> Option<PacketRef> {
        crate::net::payload::alloc_packet_with_headroom(frame_len.max(60), 0)
    }

    fn tx_segment_for_packet(
        packet: &PacketRef,
    ) -> Result<NetTxSegment, crate::net::types::NetworkError> {
        if packet.is_empty() {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }
        let len = PacketByteCount::new(packet.len())
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        NetTxSegment::from_dma(packet.data().as_ptr(), packet.device_address(), len)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)
    }

    fn build_fragment_tx_descriptors(
        header: &PacketRef,
        payload_window: OwnedTxPayloadWindow<'_>,
    ) -> Result<Vec<NetTxSegment>, crate::net::types::NetworkError> {
        let mut descriptors = Vec::new();
        descriptors.push(Self::tx_segment_for_packet(header)?);
        let payload_descriptors = payload_window
            .to_segments()
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        descriptors.extend(payload_descriptors);
        Ok(descriptors)
    }

    fn transmit_fragment_packets_on(
        &self,
        if_id: Option<NetIfId>,
        owners: Vec<PacketRef>,
        fragments: Vec<FragmentTxPacket>,
    ) -> Result<(), crate::net::types::NetworkError> {
        if fragments.is_empty() {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        let runtime = self.runtime;
        let meta = self.pending_tx_meta.unwrap_or_default();
        let frame_len = fragments
            .iter()
            .try_fold(0usize, |acc, fragment| acc.checked_add(fragment.frame_len))
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        let group_id = crate::net::runtime::device::register_tx_owner_group_in(
            runtime,
            owners,
            fragments.len(),
            meta.device_completion_ticket().map(|ticket| ticket.get()),
        )
        .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;

        let mut request_meta = meta;
        request_meta.completion = kernel_api::service::netdev::TxCompletionMode::QueueAcceptance;
        let mut requests: Vec<crate::net::runtime::device::TxRequest> = Vec::new();
        for fragment in fragments {
            let mut header_keepalive = Vec::new();
            header_keepalive.push(fragment.header);
            let Some(request) = crate::net::runtime::device::register_grouped_tx_lease_in(
                runtime,
                header_keepalive,
                group_id,
                fragment.descriptors,
                request_meta,
            ) else {
                for request in requests {
                    let _ = crate::net::runtime::device::complete_tx_lease_in(
                        runtime,
                        request.lease_id,
                        Err("fragment TX request registration failed"),
                    );
                }
                crate::net::runtime::device::unregister_tx_owner_group_in(runtime, group_id);
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            };
            requests.push(request);
        }

        let mut pending = requests.into_iter();
        while let Some(request) = pending.next() {
            if crate::net::runtime::device::transmit_registered_tx_request_in(
                runtime, if_id, request,
            ) {
                continue;
            }
            for request in pending {
                let _ = crate::net::runtime::device::complete_tx_lease_in(
                    runtime,
                    request.lease_id,
                    Err("fragment TX request cancelled"),
                );
            }
            self.record_tx_error_on(if_id);
            return Err(crate::net::types::NetworkError::TransmitFailed);
        }

        self.record_tx_success_on(if_id, frame_len);
        Ok(())
    }

    fn build_ethernet_header_packet(
        &self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        ether_type: EtherType,
    ) -> Result<PacketRef, crate::net::types::NetworkError> {
        let mut packet = self
            .alloc_ethernet_frame_packet(EthernetHeader::SIZE)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        frame
            .set_destination(dst_mac)
            .set_source(src_mac)
            .set_ether_type(ether_type);
        frame.set_payload_len(0);
        let frame_len = frame.as_bytes().len();
        drop(frame);
        if !packet.set_len(frame_len) {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }
        Ok(packet)
    }

    fn build_ipv4_ethernet_header_packet(
        &self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        protocol: IpProtocol,
        ttl: u8,
        identification: u16,
        payload_len: usize,
        more_fragments: bool,
        fragment_offset_units: u16,
    ) -> Result<PacketRef, crate::net::types::NetworkError> {
        const IPV4_HEADER_LEN: usize = crate::net::l3::ipv4::Ipv4Header::MIN_SIZE;
        let total_len = IPV4_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        let total_len_u16 = u16::try_from(total_len)
            .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;

        let mut packet = self
            .alloc_ethernet_frame_packet(EthernetHeader::SIZE + IPV4_HEADER_LEN)
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
        let Some(header) = ip_packet.header_mut() else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        header.set_total_length(total_len_u16);
        header.set_fragmentation(
            !more_fragments && fragment_offset_units == 0,
            more_fragments,
            fragment_offset_units,
        );
        header.set_checksum(0);
        ip_packet.update_checksum();

        frame.set_payload_len(IPV4_HEADER_LEN);
        let frame_len = frame.as_bytes().len();
        drop(frame);
        if !packet.set_len(frame_len) {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }
        Ok(packet)
    }

    fn effective_ipv4_pmtu(&mut self, dst_ip: Ipv4Address, current_time: u64) -> usize {
        self.primary_interface_state_mut()
            .map(|(_, state)| {
                state
                    .ipv4
                    .get_pmtu(dst_ip, current_time)
                    .max(crate::net::l3::ipv4::PmtuEntry::MIN_MTU)
                    .min(crate::net::runtime::stack::MTU as u16) as usize
            })
            .unwrap_or(crate::net::runtime::stack::MTU)
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
        payload: PacketPayload,
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
        let Some((_, state)) = self.primary_interface_state_mut() else {
            return Err(crate::net::types::NetworkError::NetworkUnreachable);
        };
        let identification = state.ipv4.next_id(dst_ip);

        if payload_len <= unfragmented_payload_limit {
            let packet = self.build_ipv4_ethernet_header_packet(
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                protocol,
                ttl,
                identification,
                payload_len,
                false,
                0,
            )?;
            let mut frame_payload = kernel_api::resource::net::PacketPayload::single(packet);
            crate::net::payload::append_payload(&mut frame_payload, payload);

            if self.transmit_packet_on(if_id, frame_payload) {
                return Ok(());
            }
            return Err(crate::net::types::NetworkError::TransmitFailed);
        }

        let non_last_fragment_len = unfragmented_payload_limit & !0x7;
        if non_last_fragment_len == 0 {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        let owners = payload.into_segments();
        let mut fragments = Vec::new();
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
            let fragment_offset_units = u16::try_from(offset / 8)
                .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;
            let packet = self.build_ipv4_ethernet_header_packet(
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                protocol,
                ttl,
                identification,
                fragment_data_len,
                more_fragments,
                fragment_offset_units,
            )?;
            let payload_window = TxFragmentWindow::new(&owners, offset, fragment_data_len)
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            let descriptors = Self::build_fragment_tx_descriptors(
                &packet,
                OwnedTxPayloadWindow::new(&owners, payload_window),
            )?;
            let frame_len = packet
                .len()
                .checked_add(fragment_data_len)
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            fragments.push(FragmentTxPacket {
                header: packet,
                descriptors,
                frame_len,
            });

            offset += fragment_data_len;
        }

        self.transmit_fragment_packets_on(if_id, owners, fragments)
    }

    fn send_tcp_raw_scoped_with_ttl_payload(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: PacketPayload,
        ttl: u8,
    ) -> bool {
        let tcp_segment_view = PacketPayloadView::new(&tcp_segment);
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
            self.stats().record_dropped();
            return false;
        }

        let Ok((if_id, config, resolved_src)) =
            self.resolve_ipv4_egress(scope, None, Some(src_ip), dst_ip)
        else {
            self.stats().record_dropped();
            return false;
        };

        let current_time = self.current_time();
        let mut pending_segment = Some(tcp_segment);
        let dst_mac = if dst_ip.is_loopback() {
            config.mac
        } else {
            match self.resolve_arp_for_send(Some(if_id), dst_ip, current_time, |pending| {
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

        let path_mtu = self.effective_ipv4_pmtu(dst_ip, current_time);
        let tcp_segment = pending_segment
            .take()
            .expect("resolved TCP segment must exist");
        self.send_ipv4_l4_payload_with_pmtu(
            Some(if_id),
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
        tcp_segment: PacketPayload,
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
        tcp_segment: PacketPayload,
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
        tcp_segment: PacketPayload,
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
        let Some((_, state)) = self.primary_interface_state_mut() else {
            return Err(crate::net::l3::igmp::IgmpError::InvalidGroupAddress);
        };
        state.igmp.join_group(group)
    }

    pub fn leave_multicast_group(
        &mut self,
        group: Ipv4Address,
    ) -> Result<(), crate::net::l3::igmp::IgmpError> {
        let Some((_, state)) = self.primary_interface_state_mut() else {
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
        self.send_pending_igmp_reports();

        // Expire timed-out pending packets
        self.expire_arp_pending();
        self.expire_ndp_pending();

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

    /// Get statistics
    pub fn stats(&self) -> &NetworkStats {
        self.primary_interface_state()
            .map(|(_, state)| &state.stats)
            .expect("network stack stats requested without registered interface state")
    }

    /// Apply a DHCPv6-obtained global IPv6 address to the stack
    pub fn enqueue_apply_ipv6_global_address(&mut self, addr: crate::net::l3::ipv6::Ipv6Address) {
        let Some((_, state)) = self.primary_interface_state_mut() else {
            return;
        };
        if let Some(ref mut ipv6_proc) = state.ipv6 {
            ipv6_proc.set_global_address(addr);
        }
        if let Some(ref mut ndp_proc) = state.ndp {
            ndp_proc.add_global_address(addr);
        }
        self.initiate_ipv6_dad(addr);
    }

    /// Initiate DAD for an IPv6 address
    pub fn initiate_ipv6_dad(&mut self, addr: Ipv6Address) {
        let dad = {
            let Some((if_id, state)) = self.primary_interface_state_mut() else {
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

    /// Expire timed-out ARP pending packets
    pub fn expire_arp_pending(&mut self) {
        let current_time = self.current_time.load(Ordering::Relaxed);
        for state in self.interfaces.values_mut() {
            state.arp_pending_queue.expire(current_time);
        }
    }
}
