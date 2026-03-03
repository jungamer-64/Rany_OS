// ============================================================================
// ARP-related NetworkStack impl methods
// ============================================================================
//! ARP packet processing, ARP reply/request/probe sending, and ARP cache access.

use super::*;

impl NetworkStack {
    /// Process ARP packet
    pub fn process_arp(&mut self, data: &[u8], current_time: u64, src_mac: MacAddress) {
        let result = self.arp.process(data, current_time, src_mac);

        match result {
            ArpResult::SendReply {
                target_mac,
                target_ip,
            } => {
                self.send_arp_reply(target_mac, target_ip);
            }
            ArpResult::CacheUpdated { resolved_ip, resolved_mac } => {
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
        let mut buffer = [0u8; 64];
        let mac = self.mac_address();

        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_gratuitous(payload) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();
                self.transmit(frame.as_bytes());
            }
        }
    }

    /// Send an ARP reply
    pub(crate) fn send_arp_reply(&mut self, target_mac: MacAddress, target_ip: Ipv4Address) {
        let mut buffer = [0u8; 64];
        let mac = self.mac_address();

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(target_mac)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_reply(payload, target_mac, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();

                self.transmit(frame.as_bytes());
            }
        }
    }

    /// Send an ARP request
    pub fn send_arp_request(&mut self, target_ip: Ipv4Address) {
        let mut buffer = [0u8; 64];
        let mac = self.mac_address();
        let current_time = self.current_time();

        // Check if we already have a pending request
        if self.arp.cache().is_pending(target_ip, current_time) {
            return;
        }

        // Build Ethernet frame (broadcast)
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_request(payload, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();

                if self.transmit(frame.as_bytes()) {
                    // Mark request as sent only when TX succeeded.
                    self.arp.request_sent(target_ip, current_time);
                    log::info!("[NET-ARP] ARP request sent for {}.{}.{}.{}",
                        target_ip.as_bytes()[0], target_ip.as_bytes()[1], target_ip.as_bytes()[2], target_ip.as_bytes()[3]);
                } else {
                    log::warn!("[NET-ARP] ARP request transmit failed for {}.{}.{}.{}",
                        target_ip.as_bytes()[0], target_ip.as_bytes()[1], target_ip.as_bytes()[2], target_ip.as_bytes()[3]);
                }
            }
        }
    }

    /// Send an ARP probe (RFC 5227 / RFC 2131 Section 2.2)
    /// 
    /// Probes are sent with sender_ip = 0.0.0.0 to detect address conflicts
    /// without polluting other hosts' ARP caches with unverified information.
    pub fn send_arp_probe(&mut self, target_ip: Ipv4Address) {
        let mut buffer = [0u8; 64];
        let mac = self.mac_address();
        let current_time = self.current_time();

        // Build Ethernet frame (broadcast)
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_probe(payload, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();

                if self.transmit(frame.as_bytes()) {
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
