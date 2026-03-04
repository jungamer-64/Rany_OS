// ============================================================================
// kernel/src/net/l2/arp/processor_impl.rs
// ============================================================================
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
    pub fn process(&self, data: &[u8], current_time: u64, src_mac: MacAddress) -> ArpResult {
        if data.len() < ArpPacket::SIZE {
            return ArpResult::Invalid;
        }

        // SAFETY: We checked the length.  Instead of holding a reference to a
        // packed struct (which may generate unaligned loads), copy the header to
        // an owned value via `read_unaligned`.  That way we avoid any hardware
        // alignment faults on platforms like ARM.
        let packet_ref =
            crate::util::get_ref::<ArpPacket>(data, 0).expect("ARP packet slice out of bounds");
        let packet: ArpPacket = unsafe { core::ptr::read_unaligned(packet_ref) };

        if !packet.is_valid() {
            return ArpResult::Invalid;
        }

        let sender_mac = packet.sender_mac();

        // Security: Verify that the sender MAC address in the ARP packet matches
        // the source MAC address in the Ethernet header. If they don't match,
        // it's a strong indicator of ARP spoofing/poisoning.
        if sender_mac != src_mac {
            log::warn!(
                "[NET-ARP] Possible spoofing detected: ARP sender MAC {} does not match Ethernet source MAC {}",
                sender_mac,
                src_mac
            );
            return ArpResult::Invalid;
        }

        let sender_ip = packet.sender_ip();
        let target_ip = packet.target_ip();

        // Security: Reject ARP packets where sender_ip claims to be our own IP.
        // This prevents IP address conflict / gratuitous ARP spoofing attacks where
        // an attacker advertises our IP with their MAC address.
        if sender_ip == self.local_ip && sender_mac != self.local_mac {
            log::warn!(
                "[NET-ARP] Possible IP conflict/spoofing: sender claims our IP {} with MAC {} (our MAC: {})",
                sender_ip,
                sender_mac,
                self.local_mac
            );
            return ArpResult::Invalid;
        }

        // Decide whether we're allowed to update the cache. (RFC 826 logic)
        // RFC 826: "If the pair <protocol type, sender protocol address> is already in 
        // my translation table, update that sender's entry... and then check the opcode."
        let mut should_update = false;
        if !sender_ip.is_any() && !sender_mac.is_broadcast() {
            // Rule 1: Always update if entry already exists (standard compliance)
            if self.cache.has_entry(sender_ip) {
                // Security: Log if MAC changed (indicator of spoofing or migration)
                if let Some(existing_mac) = self.cache.lookup(sender_ip, current_time) {
                    if existing_mac != sender_mac {
                        log::info!("[NET-ARP] MAC changed for {}: {} -> {} (updating per RFC 826)", 
                            sender_ip, existing_mac, sender_mac);
                    }
                }
                should_update = true;
            } 
            // Rule 2: Create new entry if it's a request for US or a reply we are waiting for.
            else if packet.operation() == ArpOperation::Request && target_ip == self.local_ip {
                should_update = true;
            } else if packet.operation() == ArpOperation::Reply {
                if self.cache.is_pending(sender_ip, current_time) {
                    should_update = true;
                } else {
                    log::warn!("[NET-ARP] Dropping unsolicited ARP reply from {} ({})", sender_ip, sender_mac);
                }
            }
        }

        if should_update {
            self.cache.insert(sender_ip, sender_mac, current_time);
        }

        match packet.operation() {
            ArpOperation::Request => {
                // RFC 5227: Check for ARP probe (sender_ip is unspecified)
                if sender_ip.is_any() {
                    if target_ip == self.local_ip {
                        log::info!("[NET-ARP] Received ARP probe for our IP {} - sending gratuitous ARP to defend (RFC 5227)", target_ip);
                        return ArpResult::SendGratuitous;
                    }
                    return ArpResult::Ignored;
                }

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
                if should_update {
                    ArpResult::CacheUpdated {
                        resolved_ip: sender_ip,
                        resolved_mac: sender_mac,
                    }
                } else {
                    ArpResult::Ignored
                }
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


