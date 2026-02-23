use super::*;


impl ArpProcessor {
    /// Create a new ARP processor
    pub fn new(local_mac: MacAddress, local_ip: Ipv4Address) -> Self {
        ArpProcessor {
            local_mac,
            local_ip,
            cache: ArpCache::new(),
        }
    }

    /// Get the ARP cache
    pub fn cache(&self) -> &ArpCache {
        &self.cache
    }

    /// Set local addresses
    pub fn set_local(&mut self, mac: MacAddress, ip: Ipv4Address) {
        self.local_mac = mac;
        self.local_ip = ip;
    }

    /// Process an incoming ARP packet
    pub fn process(&self, data: &[u8], current_time: u64) -> ArpResult {
        if data.len() < ArpPacket::SIZE {
            return ArpResult::Invalid;
        }

        // SAFETY: We checked the length. Use centralized helper for bounds/alignment check.
        let packet =
            crate::util::get_ref::<ArpPacket>(data, 0).expect("ARP packet slice out of bounds");

        if !packet.is_valid() {
            return ArpResult::Invalid;
        }

        let sender_mac = packet.sender_mac();
        let sender_ip = packet.sender_ip();
        let target_ip = packet.target_ip();

        // Update cache with sender info (opportunistic update)
        if !sender_ip.is_any() && !sender_mac.is_broadcast() {
            self.cache.insert(sender_ip, sender_mac, current_time);
        }

        match packet.operation() {
            ArpOperation::Request => {
                // Is this request for us?
                if target_ip == self.local_ip {
                    ArpResult::SendReply {
                        target_mac: sender_mac,
                        target_ip: sender_ip,
                    }
                } else {
                    ArpResult::Ignored
                }
            }
            ArpOperation::Reply => {
                // We already updated the cache above
                ArpResult::CacheUpdated
            }
            _ => ArpResult::Ignored,
        }
    }

    /// Build an ARP request packet
    pub fn build_request(&self, buffer: &mut [u8], target_ip: Ipv4Address) -> Option<usize> {
        if buffer.len() < ArpPacket::SIZE {
            return None;
        }

        // SAFETY: Buffer is large enough
        let packet = crate::util::get_mut_ref::<ArpPacket>(buffer, 0)
            .expect("ARP packet slice out of bounds");

        packet.init_request(self.local_mac, self.local_ip, target_ip);
        Some(ArpPacket::SIZE)
    }

    /// Build an ARP reply packet
    pub fn build_reply(
        &self,
        buffer: &mut [u8],
        target_mac: MacAddress,
        target_ip: Ipv4Address,
    ) -> Option<usize> {
        if buffer.len() < ArpPacket::SIZE {
            return None;
        }

        // SAFETY: Buffer is large enough
        let packet = crate::util::get_mut_ref::<ArpPacket>(buffer, 0)
            .expect("ARP packet slice out of bounds");

        packet.init_reply(self.local_mac, self.local_ip, target_mac, target_ip);
        Some(ArpPacket::SIZE)
    }

    /// Build a Gratuitous ARP packet (RFC 5227)
    ///
    /// Gratuitous ARP is an ARP request where sender IP = target IP.
    /// Used to announce address changes and update caches on the network.
    pub fn build_gratuitous(&self, buffer: &mut [u8]) -> Option<usize> {
        if buffer.len() < ArpPacket::SIZE {
            return None;
        }

        let packet = crate::util::get_mut_ref::<ArpPacket>(buffer, 0)
            .expect("ARP packet slice out of bounds");

        // Gratuitous: request where sender_ip == target_ip, target_mac = broadcast
        packet.init_request(self.local_mac, self.local_ip, self.local_ip);
        Some(ArpPacket::SIZE)
    }

    /// Build an ARP probe packet (RFC 5227)
    ///
    /// ARP probe is used for Duplicate Address Detection (DAD).
    /// sender_ip = 0.0.0.0, target_ip = address being probed.
    pub fn build_probe(&self, buffer: &mut [u8], probe_ip: Ipv4Address) -> Option<usize> {
        if buffer.len() < ArpPacket::SIZE {
            return None;
        }

        let packet = crate::util::get_mut_ref::<ArpPacket>(buffer, 0)
            .expect("ARP packet slice out of bounds");

        // Probe: sender_ip = 0.0.0.0 to avoid polluting caches
        packet.init_request(self.local_mac, Ipv4Address::ANY, probe_ip);
        Some(ArpPacket::SIZE)
    }

    /// Resolve an IP address to MAC (from cache)
    pub fn resolve(&self, ip: Ipv4Address, current_time: u64) -> Option<MacAddress> {
        // Broadcast IP -> broadcast MAC
        if ip.is_broadcast() {
            return Some(MacAddress::BROADCAST);
        }

        self.cache.lookup(ip, current_time)
    }

    /// Check if we need to send an ARP request
    pub fn needs_request(&self, ip: Ipv4Address, current_time: u64) -> bool {
        self.cache.lookup(ip, current_time).is_none() && !self.cache.is_pending(ip, current_time)
    }

    /// Mark that we're waiting for a reply
    pub fn request_sent(&self, ip: Ipv4Address, current_time: u64) {
        self.cache.mark_incomplete(ip, current_time);
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
#[path = "tests.rs"]
pub mod tests;

