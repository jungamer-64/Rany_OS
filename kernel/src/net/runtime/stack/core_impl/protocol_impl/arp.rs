// ============================================================================
// ARP-related NetworkStack impl methods
// ============================================================================
//! ARP packet processing, ARP reply/request/probe sending, and ARP cache access.

use super::*;

impl NetworkStack {
    /// Process ARP packet
    pub fn process_arp(
        &mut self,
        if_id: Option<super::NetIfId>,
        data: &[u8],
        current_time: u64,
        src_mac: MacAddress,
    ) {
        if let Some(if_id) = if_id {
            if self.interfaces.get(&if_id).is_some() {
                let result = {
                    let state = self.interfaces.get_mut(&if_id).unwrap();
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
                        crate::net::l2::arp::notify_arp_resolved(
                            *resolved_ip.as_bytes(),
                            *resolved_mac.as_bytes(),
                        );
                    }
                    ArpResult::SendGratuitous => {
                        self.send_gratuitous_arp_on(if_id);
                    }
                    ArpResult::Ignored | ArpResult::Invalid => {}
                }
                return;
            }
        }

        let result = self.arp.process(data, current_time, src_mac);

        match result {
            ArpResult::SendReply {
                target_mac,
                target_ip,
            } => {
                self.send_arp_reply(target_mac, target_ip);
            }
            ArpResult::CacheUpdated {
                resolved_ip,
                resolved_mac,
            } => {
                // ARP解決完了をウェイターレジストリに通知（非同期ArpResolveFuture向け）
                crate::net::l2::arp::notify_arp_resolved(
                    *resolved_ip.as_bytes(),
                    *resolved_mac.as_bytes(),
                );
            }
            ArpResult::SendGratuitous => {
                self.send_gratuitous_arp();
            }
            ArpResult::Ignored | ArpResult::Invalid => {}
        }
    }

    /// Send a gratuitous ARP to defend our address (RFC 5227)
    pub(crate) fn send_gratuitous_arp(&mut self) {
        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };
        let mac = self.mac_address();

        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_gratuitous(payload) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();
                let frame_len = frame.as_bytes().len();
                drop(frame);
                packet.set_len(frame_len);
                self.transmit_packet(packet);
            }
        }
    }

    pub(crate) fn send_gratuitous_arp_on(&mut self, if_id: super::NetIfId) {
        let Some(config) = self.interface_config_or_runtime(if_id) else {
            self.send_gratuitous_arp();
            return;
        };
        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };

        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(config.mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(state) = self.interfaces.get(&if_id) {
                if let Some(len) = state.arp.build_gratuitous(payload) {
                    frame.set_payload_len(len);
                    frame.pad_to_minimum();
                    let frame_len = frame.as_bytes().len();
                    drop(frame);
                    packet.set_len(frame_len);
                    self.transmit_packet_on(Some(if_id), packet);
                }
            }
        }
    }

    /// Send an ARP reply
    pub(crate) fn send_arp_reply(&mut self, target_mac: MacAddress, target_ip: Ipv4Address) {
        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };
        let mac = self.mac_address();

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(target_mac)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_reply(payload, target_mac, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();
                let frame_len = frame.as_bytes().len();
                drop(frame);
                packet.set_len(frame_len);
                self.transmit_packet(packet);
            }
        }
    }

    pub(crate) fn send_arp_reply_on(
        &mut self,
        if_id: super::NetIfId,
        target_mac: MacAddress,
        target_ip: Ipv4Address,
    ) {
        let Some(config) = self.interface_config_or_runtime(if_id) else {
            self.send_arp_reply(target_mac, target_ip);
            return;
        };
        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };

        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(target_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(state) = self.interfaces.get(&if_id) {
                if let Some(len) = state.arp.build_reply(payload, target_mac, target_ip) {
                    frame.set_payload_len(len);
                    frame.pad_to_minimum();
                    let frame_len = frame.as_bytes().len();
                    drop(frame);
                    packet.set_len(frame_len);
                    self.transmit_packet_on(Some(if_id), packet);
                }
            }
        }
    }

    /// Send an ARP request
    pub fn send_arp_request(&mut self, target_ip: Ipv4Address) {
        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };
        let mac = self.mac_address();
        let current_time = self.current_time();

        // Check if we already have a pending request
        if self.arp.cache().is_pending(target_ip, current_time) {
            return;
        }

        // Build Ethernet frame (broadcast)
        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_request(payload, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();
                let frame_len = frame.as_bytes().len();
                drop(frame);
                packet.set_len(frame_len);
                if self.transmit_packet(packet) {
                    // Mark request as sent only when TX succeeded.
                    self.arp.request_sent(target_ip, current_time);
                    log::info!(
                        "[NET-ARP] ARP request sent for {}.{}.{}.{}",
                        target_ip.as_bytes()[0],
                        target_ip.as_bytes()[1],
                        target_ip.as_bytes()[2],
                        target_ip.as_bytes()[3]
                    );
                } else {
                    log::warn!(
                        "[NET-ARP] ARP request transmit failed for {}.{}.{}.{}",
                        target_ip.as_bytes()[0],
                        target_ip.as_bytes()[1],
                        target_ip.as_bytes()[2],
                        target_ip.as_bytes()[3]
                    );
                }
            }
        }
    }

    /// Send an ARP request via a specific interface.
    pub fn send_arp_request_on(&mut self, if_id: super::NetIfId, target_ip: Ipv4Address) {
        self
            .send_arp_request_on_registered_interface(if_id, target_ip, self.current_time())
            .unwrap_or_else(|| self.send_arp_request(target_ip));
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

        packet.set_len(packet_len);
        if self.transmit_packet_on(Some(if_id), packet) {
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
        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };
        let mac = self.mac_address();
        let current_time = self.current_time();

        // Build Ethernet frame (broadcast)
        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_probe(payload, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();
                let frame_len = frame.as_bytes().len();
                drop(frame);
                packet.set_len(frame_len);
                if self.transmit_packet(packet) {
                    self.arp.request_sent(target_ip, current_time);
                    log::info!("[NET-ARP] ARP probe sent for {}", target_ip);
                }
            }
        }
    }

    /// Resolve an IP address to a MAC from the ARP cache (public wrapper)
    pub fn arp_resolve(&self, ip: Ipv4Address, current_time: u64) -> Option<MacAddress> {
        self.arp.resolve(ip, current_time)
    }

    /// Insert an entry into the ARP cache (public wrapper for tests/diagnostics)
    pub fn arp_cache_insert(&mut self, ip: Ipv4Address, mac: MacAddress, current_time: u64) {
        self.arp.cache().insert(ip, mac, current_time);
    }

    /// Get ARP cache entries (for debugging)
    pub fn arp_cache(&self) -> Vec<(Ipv4Address, MacAddress)> {
        self.arp
            .cache()
            .all_entries()
            .iter()
            .filter(|e| e.state == crate::net::l2::arp::ArpEntryState::Resolved)
            .map(|e| (e.ip, e.mac))
            .collect()
    }
}
