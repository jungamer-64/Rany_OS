// ============================================================================
// kernel/src/net/runtime/stack/core_impl/protocol_impl/arp.rs - ランタイム / スタック / コア実装 / プロトコル実装 / ARP
// ============================================================================
//! ARP packet processing, ARP reply/request/probe sending, and ARP cache access.

use super::*;
use crate::net::runtime::NetRuntimeHandle;

impl NetworkStack {
    /// Process ARP packet
    pub fn process_arp(
        &mut self,
        runtime: NetRuntimeHandle,
        if_id: super::NetIfId,
        data: &[u8],
        current_time: u64,
        src_mac: MacAddress,
    ) {
        let result = {
            let Some(state) = self.interfaces.get_mut(&if_id) else {
                return;
            };
            state.arp.process(data, current_time, src_mac)
        };

        match result {
            ArpResult::SendReply {
                target_mac,
                target_ip,
            } => {
                self.send_arp_reply_on(if_id, target_mac, target_ip);
            }
            ArpResult::CacheUpdated {
                resolved_ip,
                resolved_mac,
            } => {
                crate::net::l2::arp::notify_arp_resolved_in(
                    runtime,
                    *resolved_ip.as_bytes(),
                    *resolved_mac.as_bytes(),
                );
                self.drain_arp_pending_on(if_id, &resolved_ip);
                let ip_bytes = *resolved_ip.as_bytes();
                let mac_bytes = *resolved_mac.as_bytes();
                crate::net::runtime::command::broadcast_command_in(runtime, move || {
                    crate::net::runtime::command::RuntimeCommand::Control(
                        crate::net::runtime::command::ControlCommand::NeighborResolvedV4 {
                            if_id,
                            ip: ip_bytes,
                            mac: mac_bytes,
                        },
                    )
                });
            }
            ArpResult::SendGratuitous => {
                self.send_gratuitous_arp_on(if_id);
            }
            ArpResult::Ignored | ArpResult::Invalid => {}
        }
    }

    pub(crate) fn send_gratuitous_arp_on(&mut self, if_id: super::NetIfId) {
        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };
        let Some(state) = self.interfaces.get(&if_id) else {
            return;
        };
        let config = state.config;

        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(config.mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = state.arp.build_gratuitous(payload) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();
                let frame_len = frame.as_bytes().len();
                drop(frame);
                if set_packet_visible_len(&mut packet, frame_len).is_ok() {
                    self.transmit_packet_on(
                        Some(if_id),
                        kernel_api::resource::net::PacketPayload::single(packet),
                    );
                }
            }
        }
    }

    pub(crate) fn send_arp_reply_on(
        &mut self,
        if_id: super::NetIfId,
        target_mac: MacAddress,
        target_ip: Ipv4Address,
    ) {
        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };
        let Some(state) = self.interfaces.get(&if_id) else {
            return;
        };
        let config = state.config;

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(target_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = state.arp.build_reply(payload, target_mac, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();
                let frame_len = frame.as_bytes().len();
                drop(frame);
                if set_packet_visible_len(&mut packet, frame_len).is_ok() {
                    self.transmit_packet_on(
                        Some(if_id),
                        kernel_api::resource::net::PacketPayload::single(packet),
                    );
                }
            }
        }
    }

    /// Send an ARP request
    pub fn send_arp_request(&mut self, target_ip: Ipv4Address) {
        let Some((if_id, _)) = self.primary_interface_state() else {
            return;
        };
        self.send_arp_request_on(if_id, target_ip);
    }

    /// Send an ARP request via a specific interface.
    pub fn send_arp_request_on(&mut self, if_id: super::NetIfId, target_ip: Ipv4Address) {
        self.send_arp_request_on_registered_interface(if_id, target_ip, self.current_time())
            .unwrap_or(());
    }

    fn send_arp_request_on_registered_interface(
        &mut self,
        if_id: super::NetIfId,
        target_ip: Ipv4Address,
        current_time: u64,
    ) -> Option<()> {
        if self.interfaces.get(&if_id).is_none() {
            return None;
        }

        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return Some(()),
        };

        let Some(packet_len) =
            self.prepare_arp_request_on_interface(if_id, target_ip, current_time, &mut packet)
        else {
            return Some(());
        };

        if set_packet_visible_len(&mut packet, packet_len).is_ok()
            && self.transmit_packet_on(
                Some(if_id),
                kernel_api::resource::net::PacketPayload::single(packet),
            )
        {
            self.mark_arp_request_sent_on_interface(if_id, target_ip, current_time);
        }
        Some(())
    }

    /// Build an ARP request frame into `packet` for a pinned interface.
    ///
    /// Returns the final frame length when packet construction succeeds.
    fn prepare_arp_request_on_interface(
        &mut self,
        if_id: super::NetIfId,
        target_ip: Ipv4Address,
        current_time: u64,
        packet: &mut PacketRef,
    ) -> Option<usize> {
        let state = self.interfaces.get_mut(&if_id)?;
        if state.arp.cache().is_pending(target_ip, current_time) {
            return None;
        }

        let mut frame = EthernetFrameMut::new(packet.data_mut())?;
        frame
            .set_destination(MacAddress::BROADCAST)
            .set_source(state.config.mac)
            .set_ether_type(EtherType::Arp);

        let len = state.arp.build_request(frame.payload_mut(), target_ip)?;
        frame.set_payload_len(len);
        frame.pad_to_minimum();
        Some(frame.as_bytes().len())
    }

    /// Mark an ARP request as sent for interface-scoped pending tracking.
    fn mark_arp_request_sent_on_interface(
        &mut self,
        if_id: super::NetIfId,
        target_ip: Ipv4Address,
        current_time: u64,
    ) {
        if let Some(state) = self.interfaces.get_mut(&if_id) {
            state.arp.request_sent(target_ip, current_time);
        }
    }

    /// Send an ARP probe (RFC 5227 / RFC 2131 Section 2.2)
    ///
    /// Probes are sent with sender_ip = 0.0.0.0 to detect address conflicts
    /// without polluting other hosts' ARP caches with unverified information.
    pub fn send_arp_probe(&mut self, target_ip: Ipv4Address) {
        let Some((if_id, _)) = self.primary_interface_state() else {
            return;
        };
        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };
        let current_time = self.current_time();
        let Some(state) = self.interfaces.get(&if_id) else {
            return;
        };

        // Build Ethernet frame (broadcast)
        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(state.config.mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = state.arp.build_probe(payload, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();
                let frame_len = frame.as_bytes().len();
                drop(frame);
                if set_packet_visible_len(&mut packet, frame_len).is_ok()
                    && self.transmit_packet_on(
                        Some(if_id),
                        kernel_api::resource::net::PacketPayload::single(packet),
                    )
                {
                    if let Some(state) = self.interfaces.get_mut(&if_id) {
                        state.arp.request_sent(target_ip, current_time);
                    }
                    log::info!("[NET-ARP] ARP probe sent for {}", target_ip);
                }
            }
        }
    }

    /// Resolve an IP address to a MAC from the ARP cache (public wrapper)
    pub fn arp_resolve(&self, ip: Ipv4Address, current_time: u64) -> Option<MacAddress> {
        self.interfaces
            .values()
            .find_map(|state| state.arp.resolve(ip, current_time))
    }

    /// Insert an entry into a specific interface's ARP cache.
    pub fn arp_cache_insert_on(
        &mut self,
        if_id: super::NetIfId,
        ip: Ipv4Address,
        mac: MacAddress,
        current_time: u64,
    ) {
        if let Some(state) = self.interfaces.get_mut(&if_id) {
            state.arp.cache().insert(ip, mac, current_time);
        }
    }

    /// Get ARP cache entries (for debugging)
    pub fn arp_cache(&self) -> Vec<(Ipv4Address, MacAddress)> {
        let mut entries = Vec::new();
        for state in self.interfaces.values() {
            entries.extend(
                state
                    .arp
                    .cache()
                    .all_entries()
                    .into_iter()
                    .filter(|e| e.state == crate::net::l2::arp::ArpEntryState::Resolved)
                    .map(|e| (e.ip, e.mac)),
            );
        }
        entries
    }

    /// Drain pending IPv4 packets for a resolved IP
    fn drain_arp_pending_queue(
        &mut self,
        if_id: super::NetIfId,
        resolved_ip: &Ipv4Address,
        pending: Vec<crate::net::runtime::stack::PendingIpv4Packet>,
    ) {
        if pending.is_empty() {
            return;
        }

        log::debug!(
            "ARP: Draining {} pending packets for {} on {:?}",
            pending.len(),
            resolved_ip,
            if_id
        );

        for pkt in pending {
            match pkt.payload {
                crate::net::runtime::stack::PendingIpv4Payload::Udp {
                    src_port,
                    dst_port,
                    ttl,
                    data,
                } => {
                    if let Some(config) = self.interface_config_or_runtime(if_id) {
                        let _ = self.send_udp_raw_with_config_and_if_ttl_payload(
                            Some(if_id),
                            &config,
                            pkt.src,
                            src_port,
                            pkt.dst,
                            dst_port,
                            data,
                            ttl,
                        );
                    }
                }
                crate::net::runtime::stack::PendingIpv4Payload::Tcp { ttl, segment } => {
                    let scope = crate::net::types::InterfaceScope::Pinned(if_id);
                    let _ = self.send_tcp_raw_scoped_with_ttl_payload(
                        scope, pkt.src, pkt.dst, segment, ttl,
                    );
                }
                crate::net::runtime::stack::PendingIpv4Payload::Raw {
                    protocol,
                    ttl,
                    payload,
                } => {
                    let Some(src_mac) = self.interface_config_or_runtime(if_id).map(|c| c.mac)
                    else {
                        continue;
                    };
                    let _ = self.send_ipv4_l4_payload_with_pmtu(
                        Some(if_id),
                        src_mac,
                        MacAddress::ZERO, // Will be resolved by send_ipv4_l4_payload_with_pmtu
                        pkt.src,
                        pkt.dst,
                        protocol,
                        ttl,
                        payload,
                        1500, // Default MTU
                    );
                }
            }
        }
    }

    pub(crate) fn drain_arp_pending(&mut self, resolved_ip: &Ipv4Address) {
        let mut drained = Vec::new();
        for (if_id, state) in self.interfaces.iter_mut() {
            let pending = state.arp_pending_queue.drain_for(resolved_ip);
            if !pending.is_empty() {
                drained.push((*if_id, pending));
            }
        }
        for (if_id, pending) in drained {
            self.drain_arp_pending_queue(if_id, resolved_ip, pending);
        }
    }

    pub(crate) fn drain_arp_pending_on(
        &mut self,
        if_id: super::NetIfId,
        resolved_ip: &Ipv4Address,
    ) {
        let pending = if let Some(state) = self.interfaces.get_mut(&if_id) {
            state.arp_pending_queue.drain_for(resolved_ip)
        } else {
            Vec::new()
        };

        self.drain_arp_pending_queue(if_id, resolved_ip, pending);
    }
}
