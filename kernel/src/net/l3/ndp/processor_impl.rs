// ============================================================================
// kernel/src/net/l3/ndp/processor_impl.rs - NDP helper functions retained for IPv6 multicast
// ============================================================================

use super::*;
use crate::net::l2::ethernet::MacAddress;
use crate::net::payload::{PacketPayloadView, alloc_packet_with_headroom};
use kernel_api::resource::net::PacketPayload;

impl NdpProcessor {
    /// Create a new NDP processor
    pub(crate) fn new(
        our_mac: [u8; 6],
        addresses: crate::net::l3::ipv6::address_state::Ipv6AddressSet,
    ) -> Self {
        Self {
            cache: NeighborCache::new(),
            addresses,
            our_mac,
            stats: NdpStats::default(),
        }
    }

    pub(crate) fn set_addresses(
        &mut self,
        addresses: crate::net::l3::ipv6::address_state::Ipv6AddressSet,
    ) {
        self.addresses = addresses;
    }

    pub(crate) fn link_local(&self) -> Option<Ipv6Address> {
        self.addresses.link_local()
    }

    pub fn is_our_address(&self, addr: &Ipv6Address) -> bool {
        self.addresses.assigned().any(|address| address == *addr)
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    /// Get neighbor cache reference
    #[inline]
    pub fn cache(&self) -> &NeighborCache {
        &self.cache
    }

    /// Get mutable neighbor cache
    #[inline]
    pub fn cache_mut(&mut self) -> &mut NeighborCache {
        &mut self.cache
    }

    /// Build a Neighbor Solicitation message
    ///
    /// Returns the ICMPv6 payload (caller wraps in IPv6)
    pub fn build_ns(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        target: &Ipv6Address,
        src_mac: &[u8; 6],
    ) -> Option<PacketPayload> {
        Self::build_ns_with_option(src, dst, target, 1, src_mac)
    }

    pub(crate) fn build_dad_ns(target: Ipv6Address, nonce: &[u8; 6]) -> Option<PacketPayload> {
        // RFC 7527 uses the SEND Nonce option for DAD loopback detection.
        Self::build_ns_with_option(
            &Ipv6Address::UNSPECIFIED,
            &target.solicited_node(),
            &target,
            14,
            nonce,
        )
    }

    fn build_ns_with_option(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        target: &Ipv6Address,
        option: u8,
        data: &[u8; 6],
    ) -> Option<PacketPayload> {
        // ICMPv6 header, target, and one eight-byte option.
        let total_len = 32;
        let mut packet = alloc_packet_with_headroom(total_len, 0)?;
        let msg = &mut packet.data_mut()[..total_len];

        msg[0] = u8::from(Icmpv6Type::NeighborSolicitation);
        msg[1] = 0; // code
        // Checksum placeholder: bytes 2-3
        // Reserved: bytes 4-7 (already 0)
        // Target address: bytes 8-23
        msg[8..24].copy_from_slice(target.as_bytes());

        msg[24] = option;
        msg[25] = 1;
        msg[26..32].copy_from_slice(data);

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(&msg, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        msg[2] = cksum_bytes[0];
        msg[3] = cksum_bytes[1];

        PacketPayload::try_single(packet).ok()
    }

    /// Build a Neighbor Advertisement message
    ///
    /// Returns the ICMPv6 payload
    pub fn build_na(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        target: &Ipv6Address,
        our_mac: &[u8; 6],
        solicited: bool,
    ) -> Option<PacketPayload> {
        // NA: type(1) + code(1) + checksum(2) + flags(4) + target(16) + TLLA option(8) = 32
        let total_len = 32;
        let mut packet = alloc_packet_with_headroom(total_len, 0)?;
        let msg = &mut packet.data_mut()[..total_len];

        msg[0] = u8::from(Icmpv6Type::NeighborAdvertisement);
        msg[1] = 0; // code
        // Checksum placeholder: bytes 2-3

        // Flags: R=0, S=solicited, O=1 (override)
        let mut flags: u8 = 0x20; // Override
        if solicited {
            flags |= 0x40; // Solicited
        }
        msg[4] = flags;
        // bytes 5-7: rest of flags field (0)

        // Target address: bytes 8-23
        msg[8..24].copy_from_slice(target.as_bytes());

        // Target Link-Layer Address option
        msg[24] = 2; // type = Target Link-Layer Address
        msg[25] = 1; // length = 1 (in 8-byte units)
        msg[26..32].copy_from_slice(our_mac);

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(&msg, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        msg[2] = cksum_bytes[0];
        msg[3] = cksum_bytes[1];

        PacketPayload::try_single(packet).ok()
    }

    pub(crate) fn resolve_for_send(
        &mut self,
        ip: Ipv6Address,
        now: u64,
    ) -> Result<NeighborResolution, crate::net::types::NetworkError> {
        use crate::net::types::NetworkError;
        if ip.is_multicast() {
            return Ok(NeighborResolution::Resolved(ip.multicast_mac()));
        }
        if let Some(mac) = self.cache.mac_for_send(&ip, now) {
            return Ok(NeighborResolution::Resolved(mac));
        }
        let source = self.link_local().ok_or(NetworkError::NetworkUnreachable)?;
        if self.cache.lookup(&ip).is_some() {
            return Ok(NeighborResolution::Pending);
        }

        let probe = self
            .prepare_probe(source, Solicitation::Resolve(ip))
            .ok_or(NetworkError::ResourceExhausted)?;
        let mut entry = NeighborEntry::new_incomplete(ip, now);
        entry.probes_sent = 1;
        self.cache.insert(entry);
        Ok(NeighborResolution::Probe(probe))
    }

    fn prepare_probe(
        &self,
        source: Ipv6Address,
        solicitation: Solicitation,
    ) -> Option<NeighborProbe> {
        let (target, destination, mac) = match solicitation {
            Solicitation::Resolve(target) => {
                let destination = target.solicited_node();
                (target, destination, destination.multicast_mac())
            }
            Solicitation::Verify { target, mac } => (target, target, mac),
        };
        let payload = Self::build_ns(&source, &destination, &target, &self.our_mac)?;
        self.stats.ns_sent.fetch_add(1, Ordering::Relaxed);
        Some(NeighborProbe {
            source,
            destination,
            mac,
            payload,
        })
    }

    pub(crate) fn tick(&mut self, now: u64) -> Vec<NeighborProbe> {
        self.cache.expire_reachable(now);
        self.cache.expire_old(now);
        let Some(source) = self.link_local() else {
            return Vec::new();
        };
        self.cache
            .process_nud_timers(now)
            .into_iter()
            .filter_map(|solicitation| self.prepare_probe(source, solicitation))
            .collect()
    }
}

// =====================================================
// Helper: Multicast MAC conversion
// =====================================================

// =====================================================
// Tests
// =====================================================
