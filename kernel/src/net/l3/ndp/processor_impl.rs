// ============================================================================
// kernel/src/net/l3/ndp/processor_impl.rs - NDP helper functions retained for IPv6 multicast
// ============================================================================

use super::*;
use crate::net::l2::ethernet::MacAddress;
use crate::net::payload::{PacketPayloadView, alloc_packet_with_headroom};
use kernel_api::resource::net::PacketPayload;

impl NdpProcessor {
    /// Create a new NDP processor
    pub fn new(our_link_local: Ipv6Address, our_mac: [u8; 6]) -> Self {
        Self {
            cache: NeighborCache::new(),
            our_link_local,
            global_addresses: Vec::new(),
            our_mac,
            stats: NdpStats::default(),
        }
    }

    /// Add a global address that this node responds to for NDP
    pub fn add_global_address(&mut self, addr: Ipv6Address) {
        if !self.global_addresses.contains(&addr) {
            self.global_addresses.push(addr);
        }
    }

    /// Remove a global address
    pub fn remove_global_address(&mut self, addr: &Ipv6Address) {
        self.global_addresses.retain(|a| a != addr);
    }

    /// Check if the given address is one of our addresses (link-local or global)
    pub fn is_our_address(&self, addr: &Ipv6Address) -> bool {
        *addr == self.our_link_local || self.global_addresses.contains(addr)
    }

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

    /// Get stats
    #[inline]
    pub fn stats(&self) -> &NdpStats {
        &self.stats
    }

    /// Process an NDP message (already validated as ICMPv6 NDP type)
    ///
    /// `data` includes the full ICMPv6 message (type, code, checksum, ...)
    /// `src_mac` is the source MAC address from the Ethernet header
    pub fn process(
        &mut self,
        msg_type: Icmpv6Type,
        data: &[u8],
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: [u8; 6],
        current_time: u64,
    ) -> NdpResult {
        match msg_type {
            Icmpv6Type::NeighborSolicitation => {
                self.process_ns(data, src, dst, src_mac, current_time)
            }
            Icmpv6Type::NeighborAdvertisement => {
                self.process_na(data, src, dst, src_mac, current_time)
            }
            Icmpv6Type::RouterAdvertisement => self.process_ra(data, src, dst, current_time),
            Icmpv6Type::Redirect => self.process_redirect(data, src, dst, current_time),
            Icmpv6Type::RouterSolicitation => {
                // We don't process RS (we're not a router)
                NdpResult::None
            }
            _ => NdpResult::None,
        }
    }

    pub fn process_payload(
        &mut self,
        msg_type: Icmpv6Type,
        payload: &PacketPayload,
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: [u8; 6],
        current_time: u64,
    ) -> NdpResult {
        match msg_type {
            Icmpv6Type::NeighborSolicitation => {
                self.process_ns_payload(payload, src, dst, src_mac, current_time)
            }
            Icmpv6Type::NeighborAdvertisement => {
                self.process_na_payload(payload, src, dst, src_mac, current_time)
            }
            Icmpv6Type::RouterAdvertisement => {
                self.process_ra_payload(payload, src, dst, current_time)
            }
            Icmpv6Type::Redirect => self.process_redirect_payload(payload, src, dst, current_time),
            Icmpv6Type::RouterSolicitation => NdpResult::None,
            _ => NdpResult::None,
        }
    }

    /// Process Neighbor Solicitation
    ///
    /// NS format: type(1) + code(1) + checksum(2) + reserved(4) + target(16) [+ options]
    pub(super) fn process_ns(
        &mut self,
        data: &[u8],
        src: Ipv6Address,
        _dst: Ipv6Address,
        src_mac: [u8; 6],
        current_time: u64,
    ) -> NdpResult {
        if data.len() < NS_MIN_SIZE {
            return NdpResult::Error;
        }

        self.stats.ns_received.fetch_add(1, Ordering::Relaxed);

        // Extract target address (bytes 8-23)
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&data[8..24]);
        let target = Ipv6Address::new(target_bytes);

        // Check if this NS is for us (link-local or any global address)
        if !self.is_our_address(&target) {
            return NdpResult::None;
        }

        // Parse options to get source link-layer address
        let options = if data.len() > NS_MIN_SIZE {
            parse_ndp_options(&data[NS_MIN_SIZE..])
        } else {
            Vec::new()
        };

        // Learn sender's MAC from Source Link-Layer Address option
        for opt in &options {
            if let NdpOption::LinkLayerAddress {
                option_type: NdpOptionType::SourceLinkLayerAddress,
                mac,
            } = opt
            {
                // SECURITY: Source Link-Layer Address option の一致を検証する。
                // the source MAC address in the Ethernet header.
                if *mac != src_mac {
                    log::warn!(
                        "[NET-NDP] Possible NS spoofing: SLLA {} does not match Ethernet source MAC {}",
                        MacAddress::from_octets(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
                        MacAddress::from_octets(
                            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]
                        )
                    );
                    return NdpResult::Error;
                }

                if !src.is_unspecified() {
                    self.cache.update_stale(&src, *mac, current_time);
                }
            }
        }

        // Respond with Neighbor Advertisement
        if src.is_unspecified() {
            // RFC 4862 Section 5.4.3: Defense against DAD probe.
            // MUST send to all-nodes multicast address.
            log::info!(
                "[NET-NDP] Received DAD probe for our address {} - defending (RFC 4862)",
                target
            );
            NdpResult::SendNeighborAdvertisementMulticast {
                target,
                our_mac: self.our_mac,
            }
        } else {
            NdpResult::SendNeighborAdvertisement {
                dst: src,
                target,
                our_mac: self.our_mac,
                solicited: true, // If it's not unspecified, it's a regular NS (usually)
            }
        }
    }

    pub(super) fn process_ns_payload(
        &mut self,
        payload: &PacketPayload,
        src: Ipv6Address,
        _dst: Ipv6Address,
        src_mac: [u8; 6],
        current_time: u64,
    ) -> NdpResult {
        let view = PacketPayloadView::new(payload);
        if view.total_len() < NS_MIN_SIZE {
            return NdpResult::Error;
        }

        self.stats.ns_received.fetch_add(1, Ordering::Relaxed);

        let Some(target_bytes) = view.read_array::<16>(8) else {
            return NdpResult::Error;
        };
        let target = Ipv6Address::new(target_bytes);

        if !self.is_our_address(&target) {
            return NdpResult::None;
        }

        let options = if view.total_len() > NS_MIN_SIZE {
            parse_ndp_options_view(&view, NS_MIN_SIZE)
        } else {
            Vec::new()
        };

        for opt in &options {
            if let NdpOption::LinkLayerAddress {
                option_type: NdpOptionType::SourceLinkLayerAddress,
                mac,
            } = opt
            {
                if *mac != src_mac {
                    log::warn!(
                        "[NET-NDP] Possible NS spoofing: SLLA {} does not match Ethernet source MAC {}",
                        MacAddress::from_octets(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
                        MacAddress::from_octets(
                            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]
                        )
                    );
                    return NdpResult::Error;
                }

                if !src.is_unspecified() {
                    self.cache.update_stale(&src, *mac, current_time);
                }
            }
        }

        if src.is_unspecified() {
            log::info!(
                "[NET-NDP] Received DAD probe for our address {} - defending (RFC 4862)",
                target
            );
            NdpResult::SendNeighborAdvertisementMulticast {
                target,
                our_mac: self.our_mac,
            }
        } else {
            NdpResult::SendNeighborAdvertisement {
                dst: src,
                target,
                our_mac: self.our_mac,
                solicited: true,
            }
        }
    }

    /// Process Neighbor Advertisement
    ///
    /// NA format: type(1) + code(1) + checksum(2) + flags(4) + target(16) [+ options]
    pub(super) fn process_na(
        &mut self,
        data: &[u8],
        _src: Ipv6Address,
        _dst: Ipv6Address,
        src_mac: [u8; 6],
        current_time: u64,
    ) -> NdpResult {
        if data.len() < NA_MIN_SIZE {
            return NdpResult::Error;
        }

        self.stats.na_received.fetch_add(1, Ordering::Relaxed);

        // Flags: R(1) + S(1) + O(1) + reserved(29) — byte 4
        let flags = data[4];
        let _router = (flags & 0x80) != 0;
        let solicited = (flags & 0x40) != 0;
        let override_flag = (flags & 0x20) != 0;

        // Target address (bytes 8-23)
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&data[8..24]);
        let target = Ipv6Address::new(target_bytes);

        // SECURITY: RFC 4861 Section 7.1.2 に従い、target address は multicast address であってはならない。
        if target.is_multicast() {
            log::warn!(
                "[NET-NDP] Dropping NA with multicast target address {}",
                target
            );
            return NdpResult::Error;
        }

        // Parse options for Target Link-Layer Address
        let options = if data.len() > NA_MIN_SIZE {
            parse_ndp_options(&data[NA_MIN_SIZE..])
        } else {
            Vec::new()
        };

        let mut learned_mac = None;
        for opt in &options {
            if let NdpOption::LinkLayerAddress {
                option_type: NdpOptionType::TargetLinkLayerAddress,
                mac,
            } = opt
            {
                // SECURITY: Target Link-Layer Address option の一致を検証する。
                // the source MAC address in the Ethernet header.
                if *mac != src_mac {
                    log::warn!(
                        "[NET-NDP] Possible NA spoofing: TLLA {} does not match Ethernet source MAC {}",
                        MacAddress::from_octets(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
                        MacAddress::from_octets(
                            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]
                        )
                    );
                    return NdpResult::Error;
                }
                learned_mac = Some(*mac);
            }
        }

        // Update neighbor cache
        if let Some(mac) = learned_mac {
            // RFC 4861 Section 7.2.5:
            // If the Target Address is already in the Neighbor Cache:
            //   1. If the Solicited flag is set, the state becomes REACHABLE.
            //   2. If the Solicited flag is zero and the Override flag is set, state becomes STALE.
            //   3. If neither (1) nor (2), do not update.
            // If the Target Address is NOT in the Neighbor Cache, only create if solicited.
            if let Some(entry) = self.cache.lookup_mut(&target) {
                if solicited {
                    entry.mac = mac;
                    entry.state = NeighborState::Reachable;
                    entry.timestamp = current_time;
                    entry.probes_sent = 0;
                } else if override_flag {
                    if entry.mac != mac {
                        entry.mac = mac;
                        entry.state = NeighborState::Stale;
                        entry.timestamp = current_time;
                    }
                }
            } else {
                // RFC 4861 Section 7.2.5: If the Target Address is NOT in the Neighbor Cache,
                // advertisements for the target SHOULD be silently discarded.
                return NdpResult::None;
            }

            return NdpResult::NeighborUpdated { ip: target, mac };
        }

        NdpResult::None
    }

    pub(super) fn process_na_payload(
        &mut self,
        payload: &PacketPayload,
        _src: Ipv6Address,
        _dst: Ipv6Address,
        src_mac: [u8; 6],
        current_time: u64,
    ) -> NdpResult {
        let view = PacketPayloadView::new(payload);
        if view.total_len() < NA_MIN_SIZE {
            return NdpResult::Error;
        }

        self.stats.na_received.fetch_add(1, Ordering::Relaxed);

        let Some(flags) = view.read_array::<1>(4).map(|bytes| bytes[0]) else {
            return NdpResult::Error;
        };
        let solicited = (flags & 0x40) != 0;
        let override_flag = (flags & 0x20) != 0;

        let Some(target_bytes) = view.read_array::<16>(8) else {
            return NdpResult::Error;
        };
        let target = Ipv6Address::new(target_bytes);

        if target.is_multicast() {
            log::warn!(
                "[NET-NDP] Dropping NA with multicast target address {}",
                target
            );
            return NdpResult::Error;
        }

        let options = if view.total_len() > NA_MIN_SIZE {
            parse_ndp_options_view(&view, NA_MIN_SIZE)
        } else {
            Vec::new()
        };

        let mut learned_mac = None;
        for opt in &options {
            if let NdpOption::LinkLayerAddress {
                option_type: NdpOptionType::TargetLinkLayerAddress,
                mac,
            } = opt
            {
                if *mac != src_mac {
                    log::warn!(
                        "[NET-NDP] Possible NA spoofing: TLLA {} does not match Ethernet source MAC {}",
                        MacAddress::from_octets(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
                        MacAddress::from_octets(
                            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]
                        )
                    );
                    return NdpResult::Error;
                }
                learned_mac = Some(*mac);
            }
        }

        if let Some(mac) = learned_mac {
            if let Some(entry) = self.cache.lookup_mut(&target) {
                if solicited {
                    entry.mac = mac;
                    entry.state = NeighborState::Reachable;
                    entry.timestamp = current_time;
                    entry.probes_sent = 0;
                } else if override_flag && entry.mac != mac {
                    entry.mac = mac;
                    entry.state = NeighborState::Stale;
                    entry.timestamp = current_time;
                }
            } else {
                return NdpResult::None;
            }

            return NdpResult::NeighborUpdated { ip: target, mac };
        }

        NdpResult::None
    }

    /// Process Router Advertisement
    ///
    /// RA provides prefix info, gateway, and hop limit
    pub(super) fn process_ra(
        &mut self,
        data: &[u8],
        src: Ipv6Address,
        _dst: Ipv6Address,
        current_time: u64,
    ) -> NdpResult {
        // SECURITY: RFC 4861 Section 6.1.2 に従い、source address は link-local address でなければならない。
        if !src.is_link_local() {
            log::warn!("NDP: Dropping RA from non-link-local address {}", src);
            return NdpResult::Error;
        }

        if data.len() < 16 {
            // RA minimum: type(1) + code(1) + checksum(2) + cur_hop_limit(1) +
            // flags(1) + router_lifetime(2) + reachable_time(4) + retrans_timer(4) = 16
            return NdpResult::Error;
        }

        self.stats.ra_received.fetch_add(1, Ordering::Relaxed);

        // Parse options
        let options = if data.len() > 16 {
            parse_ndp_options(&data[16..])
        } else {
            Vec::new()
        };

        // Extract router's MAC from Source Link-Layer Address option
        let mut router_mac = None;
        let mut prefix_options = Vec::new();
        for opt in options {
            match &opt {
                NdpOption::LinkLayerAddress {
                    option_type: NdpOptionType::SourceLinkLayerAddress,
                    mac,
                } => {
                    router_mac = Some(*mac);
                    // Update neighbor cache with router's MAC (RFC 4861: should be STALE)
                    self.cache.update_stale(&src, *mac, current_time);
                }
                NdpOption::PrefixInfo { .. }
                | NdpOption::Mtu(_)
                | NdpOption::RecursiveDnsServer { .. } => {
                    prefix_options.push(opt);
                }
                _ => {}
            }
        }

        NdpResult::RouterAdvertisement {
            router: src,
            router_mac,
            prefixes: prefix_options,
        }
    }

    pub(super) fn process_ra_payload(
        &mut self,
        payload: &PacketPayload,
        src: Ipv6Address,
        _dst: Ipv6Address,
        current_time: u64,
    ) -> NdpResult {
        if !src.is_link_local() {
            log::warn!("NDP: Dropping RA from non-link-local address {}", src);
            return NdpResult::Error;
        }

        let view = PacketPayloadView::new(payload);
        if view.total_len() < 16 {
            return NdpResult::Error;
        }

        self.stats.ra_received.fetch_add(1, Ordering::Relaxed);

        let options = if view.total_len() > 16 {
            parse_ndp_options_view(&view, 16)
        } else {
            Vec::new()
        };

        let mut router_mac = None;
        let mut prefix_options = Vec::new();
        for opt in options {
            match &opt {
                NdpOption::LinkLayerAddress {
                    option_type: NdpOptionType::SourceLinkLayerAddress,
                    mac,
                } => {
                    router_mac = Some(*mac);
                    self.cache.update_stale(&src, *mac, current_time);
                }
                NdpOption::PrefixInfo { .. }
                | NdpOption::Mtu(_)
                | NdpOption::RecursiveDnsServer { .. } => {
                    prefix_options.push(opt);
                }
                _ => {}
            }
        }

        NdpResult::RouterAdvertisement {
            router: src,
            router_mac,
            prefixes: prefix_options,
        }
    }

    /// Process Redirect message (RFC 4861 Section 8)
    ///
    /// Redirect format: type(1) + code(1) + checksum(2) + reserved(4) + target(16) + destination(16) [+ options]
    pub(super) fn process_redirect(
        &mut self,
        data: &[u8],
        src: Ipv6Address,
        _dst: Ipv6Address,
        current_time: u64,
    ) -> NdpResult {
        // SECURITY: RFC 4861 Section 8.1 に従って検証する。
        // 1. Source address MUST be a link-local address.
        if !src.is_link_local() {
            log::warn!("NDP: Dropping Redirect from non-link-local address {}", src);
            return NdpResult::Error;
        }

        // 2. The ICMP Hop Limit MUST be 255 (already checked in receive.rs via process_ndp_message).

        if data.len() < 40 {
            // type(1) + code(1) + checksum(2) + reserved(4) + target(16) + destination(16) = 40
            return NdpResult::Error;
        }

        // Extract target (bytes 8-23) and destination (bytes 24-39)
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&data[8..24]);
        let target = Ipv6Address::new(target_bytes);

        let mut dest_bytes = [0u8; 16];
        dest_bytes.copy_from_slice(&data[24..40]);
        let destination = Ipv6Address::new(dest_bytes);

        // SECURITY: RFC 4861 Section 8.1 に従って検証する。
        // 3. The ICMP Code MUST be 0.
        if data[1] != 0 {
            return NdpResult::Error;
        }

        // 4. Destination address MUST NOT be a multicast address.
        if destination.is_multicast() {
            log::warn!(
                "NDP: Dropping Redirect with multicast destination {}",
                destination
            );
            return NdpResult::Error;
        }

        // 5. The Target Address MUST be either a link-local address (when the redirect
        //    is to a router) or the same as the Destination Address (when the
        //    redirect is to the destination itself).
        if !target.is_link_local() && target != destination {
            log::warn!(
                "NDP: Dropping Redirect with invalid target {} for destination {}",
                target,
                destination
            );
            return NdpResult::Error;
        }

        // Parse options for Target Link-Layer Address
        let options = if data.len() > 40 {
            parse_ndp_options(&data[40..])
        } else {
            Vec::new()
        };

        for opt in options {
            if let NdpOption::LinkLayerAddress {
                option_type: NdpOptionType::TargetLinkLayerAddress,
                mac,
            } = opt
            {
                // Update neighbor cache with target's MAC
                self.cache.update_reachable(&target, mac, current_time);
            }
        }

        NdpResult::Redirect {
            target,
            destination,
        }
    }

    pub(super) fn process_redirect_payload(
        &mut self,
        payload: &PacketPayload,
        src: Ipv6Address,
        _dst: Ipv6Address,
        current_time: u64,
    ) -> NdpResult {
        if !src.is_link_local() {
            log::warn!("NDP: Dropping Redirect from non-link-local address {}", src);
            return NdpResult::Error;
        }

        let view = PacketPayloadView::new(payload);
        if view.total_len() < 40 {
            return NdpResult::Error;
        }

        let Some(target_bytes) = view.read_array::<16>(8) else {
            return NdpResult::Error;
        };
        let target = Ipv6Address::new(target_bytes);

        let Some(dest_bytes) = view.read_array::<16>(24) else {
            return NdpResult::Error;
        };
        let destination = Ipv6Address::new(dest_bytes);

        let Some(code) = view.read_array::<1>(1).map(|bytes| bytes[0]) else {
            return NdpResult::Error;
        };
        if code != 0 {
            return NdpResult::Error;
        }

        if destination.is_multicast() {
            log::warn!(
                "NDP: Dropping Redirect with multicast destination {}",
                destination
            );
            return NdpResult::Error;
        }

        if !target.is_link_local() && target != destination {
            log::warn!(
                "NDP: Dropping Redirect with invalid target {} for destination {}",
                target,
                destination
            );
            return NdpResult::Error;
        }

        let options = if view.total_len() > 40 {
            parse_ndp_options_view(&view, 40)
        } else {
            Vec::new()
        };

        for opt in options {
            if let NdpOption::LinkLayerAddress {
                option_type: NdpOptionType::TargetLinkLayerAddress,
                mac,
            } = opt
            {
                self.cache.update_reachable(&target, mac, current_time);
            }
        }

        NdpResult::Redirect {
            target,
            destination,
        }
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
        // NS: type(1) + code(1) + checksum(2) + reserved(4) + target(16) + SLLA option(8) = 32
        let total_len = 32;
        let mut packet = alloc_packet_with_headroom(total_len, 0)?;
        let msg = &mut packet.data_mut()[..total_len];

        msg[0] = u8::from(Icmpv6Type::NeighborSolicitation);
        msg[1] = 0; // code
        // Checksum placeholder: bytes 2-3
        // Reserved: bytes 4-7 (already 0)
        // Target address: bytes 8-23
        msg[8..24].copy_from_slice(target.as_bytes());

        // Source Link-Layer Address option
        msg[24] = 1; // type = Source Link-Layer Address
        msg[25] = 1; // length = 1 (in 8-byte units)
        msg[26..32].copy_from_slice(src_mac);

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(&msg, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        msg[2] = cksum_bytes[0];
        msg[3] = cksum_bytes[1];

        Some(PacketPayload::single(packet))
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

        Some(PacketPayload::single(packet))
    }

    /// Build a Router Solicitation message
    ///
    /// Sent to ff02::2 (all-routers) to solicit Router Advertisements
    pub fn build_rs(src: &Ipv6Address, src_mac: &[u8; 6]) -> Option<PacketPayload> {
        let dst = Ipv6Address::ALL_ROUTERS_LINK_LOCAL;
        // RS: type(1) + code(1) + checksum(2) + reserved(4) + SLLA option(8) = 16
        let total_len = 16;
        let mut packet = alloc_packet_with_headroom(total_len, 0)?;
        let msg = &mut packet.data_mut()[..total_len];

        msg[0] = u8::from(Icmpv6Type::RouterSolicitation);
        msg[1] = 0; // code
        // bytes 2-3: checksum placeholder
        // bytes 4-7: reserved

        // Source Link-Layer Address option
        msg[8] = 1; // type = Source Link-Layer Address
        msg[9] = 1; // length = 1 (in 8-byte units)
        msg[10..16].copy_from_slice(src_mac);

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(src, &dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(&msg, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        msg[2] = cksum_bytes[0];
        msg[3] = cksum_bytes[1];

        Some(PacketPayload::single(packet))
    }

    /// Resolve an IPv6 address to MAC address
    ///
    /// Returns Some(mac) if entry is in Reachable/Stale/Delay/Probe state,
    /// None if Incomplete or not in cache.
    pub fn resolve(&self, ip: &Ipv6Address) -> Option<[u8; 6]> {
        // Multicast addresses map directly to MAC
        if ip.is_multicast() {
            return Some(ip.multicast_mac());
        }

        // Lookup in neighbor cache
        self.cache.lookup(ip).and_then(|entry| {
            if entry.has_mac() {
                Some(entry.mac)
            } else {
                None
            }
        })
    }

    /// Start resolution for a neighbor (create Incomplete entry)
    ///
    /// Returns the NS message to send (caller sends it)
    pub fn start_resolution(
        &mut self,
        target: &Ipv6Address,
        current_time: u64,
    ) -> Option<PacketPayload> {
        // Create incomplete entry
        self.cache
            .insert(NeighborEntry::new_incomplete(*target, current_time));
        self.stats.ns_sent.fetch_add(1, Ordering::Relaxed);

        // Build NS targeting the solicited-node multicast address
        let sn_mcast = target.solicited_node();
        Self::build_ns(&self.our_link_local, &sn_mcast, target, &self.our_mac)
    }

    /// Initiate Duplicate Address Detection (DAD) for a new address (RFC 4862)
    pub fn initiate_dad(&self, target: &Ipv6Address) -> NdpResult {
        log::info!("[NET-NDP] Initiating DAD for address {} (RFC 4862)", target);
        let mcast_dst = target.solicited_node();
        NdpResult::SendNeighborSolicitation {
            src: Ipv6Address::UNSPECIFIED,
            dst: mcast_dst,
            target: *target,
        }
    }

    /// Run periodic maintenance (expire entries + NUD timer processing)
    ///
    /// Returns a list of NS probe messages to send (for NUD Probe/Incomplete states)
    pub fn tick(&mut self, current_time: u64) -> Vec<PacketPayload> {
        self.cache.expire_reachable(current_time);
        self.cache.expire_old(current_time);

        // Process NUD state machine timers (Delay→Probe, Probe retries)
        let probe_targets = self.cache.process_nud_timers(current_time);
        let mut ns_messages = Vec::new();

        for target in probe_targets {
            // Build unicast NS for Probe, or solicited-node multicast NS for Incomplete
            let entry_state = self.cache.lookup(&target).map(|e| e.state);
            let ns = match entry_state {
                Some(NeighborState::Probe) => {
                    // Unicast NS to target's last known address
                    Self::build_ns(&self.our_link_local, &target, &target, &self.our_mac)
                }
                _ => {
                    // Multicast NS to solicited-node address
                    let sn_mcast = target.solicited_node();
                    Self::build_ns(&self.our_link_local, &sn_mcast, &target, &self.our_mac)
                }
            };
            if let Some(ns) = ns {
                self.stats.ns_sent.fetch_add(1, Ordering::Relaxed);
                ns_messages.push(ns);
            }
        }

        ns_messages
    }
}

// =====================================================
// Helper: Multicast MAC conversion
// =====================================================

/// Convert IPv6 multicast address to Ethernet multicast MAC
///
/// 33:33:xx:xx:xx:xx (last 4 bytes of IPv6 multicast address)
#[inline]
pub fn ipv6_multicast_to_mac(addr: &Ipv6Address) -> [u8; 6] {
    addr.multicast_mac()
}

// =====================================================
// Tests
// =====================================================
