use super::*;

// --- Address tests ---

#[cfg_attr(test, test_case)]
pub fn test_unspecified() {
    let addr = Ipv6Address::UNSPECIFIED;
    assert!(addr.is_unspecified());
    assert!(!addr.is_loopback());
    assert!(!addr.is_multicast());
    assert!(!addr.is_unicast_link_local());
}

#[cfg_attr(test, test_case)]
pub fn test_loopback() {
    let addr = Ipv6Address::LOOPBACK;
    assert!(!addr.is_unspecified());
    assert!(addr.is_loopback());
    assert!(!addr.is_multicast());
}

#[cfg_attr(test, test_case)]
pub fn test_multicast() {
    let addr = Ipv6Address::ALL_NODES_LINK_LOCAL;
    assert!(addr.is_multicast());
    assert!(addr.is_link_local());
    assert!(!addr.is_unicast_link_local());
}

#[cfg_attr(test, test_case)]
pub fn test_link_local() {
    // fe80::1
    let addr = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert!(addr.is_unicast_link_local());
    assert!(addr.is_link_local());
    assert!(!addr.is_multicast());
    assert!(!addr.is_global());
}

#[cfg_attr(test, test_case)]
pub fn test_global() {
    // 2001:db8::1 (documentation global unicast prefix)
    let addr = Ipv6Address::new([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    assert!(!addr.is_unspecified());
    assert!(!addr.is_loopback());
    assert!(!addr.is_multicast());
    assert!(!addr.is_link_local());
    assert!(addr.is_global());
}

#[cfg_attr(test, test_case)]
pub fn test_header_chain_completeness_rfc7112() {
    // TCP header (20 bytes) - only 10 bytes provided
    let tcp_truncated = [0u8; 10];
    assert!(!is_header_chain_complete(6, &tcp_truncated), "Should reject truncated TCP header (RFC 7112)");

    // TCP header - 20 bytes provided
    let tcp_full = [0u8; 20];
    assert!(is_header_chain_complete(6, &tcp_full), "Should accept complete TCP header");

    // UDP header (8 bytes) - only 4 bytes provided
    let udp_truncated = [0u8; 4];
    assert!(!is_header_chain_complete(17, &udp_truncated), "Should reject truncated UDP header (RFC 7112)");

    // UDP header - 8 bytes provided
    let udp_full = [0u8; 8];
    assert!(is_header_chain_complete(17, &udp_full), "Should accept complete UDP header");

    // AH header (length in 4-byte units)
    // Next Header (1), Payload Len (4 -> 24 bytes), Reserved (2), SPI (4), Seq (4), ICV (12)
    let mut ah_truncated = [0u8; 16];
    ah_truncated[1] = 4; // 24 bytes expected
    assert!(!is_header_chain_complete(51, &ah_truncated), "Should reject truncated AH header");

    // ESP header - always considered complete for chain walk (RFC 7112)
    assert!(is_header_chain_complete(50, &[]), "ESP should terminate chain regardless of length");
}

#[cfg_attr(test, test_case)]
pub fn test_eui64() {
    // MAC: 52:54:00:12:34:56
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let addr = Ipv6Address::from_eui64(&mac);

    assert!(addr.is_unicast_link_local());
    // fe80::5054:00ff:fe12:3456
    // 7th bit flipped: 0x52 ^ 0x02 = 0x50
    assert_eq!(addr.as_bytes()[0], 0xfe);
    assert_eq!(addr.as_bytes()[1], 0x80);
    assert_eq!(addr.as_bytes()[8], 0x50); // 0x52 ^ 0x02
    assert_eq!(addr.as_bytes()[9], 0x54);
    assert_eq!(addr.as_bytes()[10], 0x00);
    assert_eq!(addr.as_bytes()[11], 0xff);
    assert_eq!(addr.as_bytes()[12], 0xfe);
    assert_eq!(addr.as_bytes()[13], 0x12);
    assert_eq!(addr.as_bytes()[14], 0x34);
    assert_eq!(addr.as_bytes()[15], 0x56);
}

#[cfg_attr(test, test_case)]
pub fn test_solicited_node() {
    // fe80::5054:00ff:fe12:3456 → ff02::1:ff12:3456
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let addr = Ipv6Address::from_eui64(&mac);
    let sn = addr.solicited_node();

    assert!(sn.is_multicast());
    assert!(sn.is_solicited_node_multicast());
    assert_eq!(sn.as_bytes()[12], 0xff);
    assert_eq!(sn.as_bytes()[13], 0x12); // last 3 bytes of unicast
    assert_eq!(sn.as_bytes()[14], 0x34);
    assert_eq!(sn.as_bytes()[15], 0x56);
}

#[cfg_attr(test, test_case)]
pub fn test_multicast_mac() {
    // ff02::1:ff12:3456 → 33:33:ff:12:34:56
    let addr = Ipv6Address::new([
        0xff, 0x02, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0x01, 0xff, 0x12, 0x34, 0x56,
    ]);
    let mac = addr.multicast_mac();
    assert_eq!(mac, [0x33, 0x33, 0xff, 0x12, 0x34, 0x56]);
}

// --- Header / Packet tests ---

#[cfg_attr(test, test_case)]
pub fn test_header_size() {
    assert_eq!(core::mem::size_of::<Ipv6Header>(), IPV6_HEADER_SIZE);
}

#[cfg_attr(test, test_case)]
pub fn test_packet_parse_valid() {
    // Construct a minimal valid IPv6 packet (ICMPv6 Echo Request)
    let mut buf = [0u8; 48]; // 40 header + 8 payload
    buf[0] = 0x60; // version = 6
    buf[4] = 0; buf[5] = 8; // payload length = 8
    buf[6] = 58; // next header = ICMPv6 (58)
    buf[7] = 64; // hop limit = 64

    let packet = Ipv6Packet::parse(&buf).unwrap();
    assert_eq!(packet.header().version(), 6);
    assert_eq!(packet.header().payload_length(), 8);
    assert_eq!(packet.next_header(), IpProtocol::Icmpv6);
    assert_eq!(packet.hop_limit(), 64);
    assert_eq!(packet.payload().len(), 8);
}

#[cfg_attr(test, test_case)]
pub fn test_packet_parse_wrong_version() {
    let mut buf = [0u8; 48];
    buf[0] = 0x40; // version = 4 (IPv4)
    assert!(Ipv6Packet::parse(&buf).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_packet_parse_too_short() {
    let buf = [0x60u8; 20]; // too short for IPv6 header
    assert!(Ipv6Packet::parse(&buf).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_packet_mut_build() {
    let mut buf = [0u8; 60]; // 40 header + 20 payload
    let mut pkt = Ipv6PacketMut::new(&mut buf).unwrap();
    pkt.init_header();

    let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let dst = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    pkt.set_source(&src);
    pkt.set_destination(&dst);
    pkt.set_next_header(IpProtocol::Icmpv6);
    pkt.set_hop_limit(255);
    pkt.finalize(20);

    let header = pkt.header().expect("initialized IPv6 packet must have a header");
    assert_eq!(header.version(), 6);
    assert_eq!(header.source(), src);
    assert_eq!(header.destination(), dst);
    assert_eq!(header.next_header(), IpProtocol::Icmpv6);
    assert_eq!(header.hop_limit(), 255);
    assert_eq!(header.payload_length(), 20);
}

#[cfg_attr(test, test_case)]
pub fn test_ipv6_packet_mut_finalize_clamp() {
    let mut buffer = [0u8; 50]; // 40 bytes header + 10 bytes payload
    let mut packet = Ipv6PacketMut::new(&mut buffer).unwrap();
    packet.init_header();

    // Try to finalize with a payload larger than buffer
    packet.finalize(100);

    // Check that it was clamped
    let bytes = packet.as_bytes();
    assert_eq!(bytes.len(), 50);

    // Check header payload length
    if let Some(h) = packet.header() {
        assert_eq!(h.payload_length(), 10);
    }
}

#[cfg_attr(test, test_case)]
pub fn test_ipv6_packet_mut_manual_overflow_protection() {
    let mut buffer = [0u8; 50];
    let mut packet = Ipv6PacketMut::new(&mut buffer).unwrap();
    packet.init_header();

    // Manually set a large payload length
    if let Some(h) = packet.header_mut() {
        h.set_payload_length(100);
    }

    // as_bytes() should not panic
    let bytes = packet.as_bytes();
    assert_eq!(bytes.len(), 50);
}

// --- Extension header tests ---

#[cfg_attr(test, test_case)]
pub fn test_skip_no_extension_headers() {
    // Payload that starts directly with upper-layer data
    let data = [1, 2, 3, 4, 5, 6, 7, 8];
    let (proto, remaining) = skip_extension_headers(IpProtocol::Tcp, &data);
    assert_eq!(proto, IpProtocol::Tcp);
    assert_eq!(remaining.len(), 8);
}

#[cfg_attr(test, test_case)]
pub fn test_skip_hop_by_hop() {
    // Hop-by-Hop Options header: next=ICMPv6(58), len=0 → 8 bytes total
    let mut data = [0u8; 16];
    data[0] = 58; // next header = ICMPv6
    data[1] = 0;  // length = 0 → (0+1)*8 = 8 bytes
    // data[2..8] = padding/options
    data[8] = 0x80; // fake ICMPv6 echo request

    let (proto, remaining) = skip_extension_headers(
        IpProtocol::Unknown(0), // Hop-by-Hop = 0
        &data,
    );
    assert_eq!(proto, IpProtocol::Icmpv6);
    assert_eq!(remaining.len(), 8);
    assert_eq!(remaining[0], 0x80);
}

#[cfg_attr(test, test_case)]
pub fn test_skip_fragment_header() {
    // Fragment header: next=TCP(6), always 8 bytes
    let mut data = [0u8; 16];
    data[0] = 6; // next header = TCP
    data[1] = 0; // reserved
    // data[2..4] = fragment offset + M flag
    // data[4..8] = identification

    let (proto, remaining) = skip_extension_headers(
        IpProtocol::Unknown(44), // Fragment = 44
        &data,
    );
    assert_eq!(proto, IpProtocol::Tcp);
    assert_eq!(remaining.len(), 8);
}

// --- Pseudo-header checksum test ---

#[cfg_attr(test, test_case)]
pub fn test_pseudo_header_checksum() {
    let src = Ipv6Address::LOOPBACK;
    let dst = Ipv6Address::LOOPBACK;
    let sum = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, 8);

    // Both addresses = ::1, so sum contributions from addresses:
    // src: 7 words of 0 + 1 word of 1 = 1
    // dst: same = 1
    // length = 8 → 0 + 8 = 8
    // next_header = 58
    // total = 1 + 1 + 8 + 58 = 68
    assert_eq!(sum, 68);
}

// --- Display test ---

#[cfg_attr(test, test_case)]
pub fn test_display_loopback() {
    let addr = Ipv6Address::LOOPBACK;
    let s = alloc::format!("{}", addr);
    assert_eq!(s, "::1");
}

#[cfg_attr(test, test_case)]
pub fn test_display_link_local() {
    // fe80::1
    let addr = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let s = alloc::format!("{}", addr);
    assert_eq!(s, "fe80::1");
}

#[cfg_attr(test, test_case)]
pub fn test_display_all_nodes() {
    let addr = Ipv6Address::ALL_NODES_LINK_LOCAL;
    let s = alloc::format!("{}", addr);
    assert_eq!(s, "ff02::1");
}

#[cfg_attr(test, test_case)]
pub fn test_display_full() {
    // 2001:db8:1:2:3:4:5:6 (no zero run >= 2)
    let addr = Ipv6Address::new([
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06,
    ]);
    let s = alloc::format!("{}", addr);
    assert_eq!(s, "2001:db8:1:2:3:4:5:6");
}

#[cfg_attr(test, test_case)]
pub fn test_from_u64_pair() {
    let addr = Ipv6Address::from_u64_pair(
        0xfe80_0000_0000_0000,
        0x0000_0000_0000_0001,
    );
    assert!(addr.is_unicast_link_local());
    assert_eq!(addr.as_bytes()[15], 1);
}

#[cfg_attr(test, test_case)]
pub fn test_pmtu_cache_evict_oldest_uses_lru() {
    let mut cache = Ipv6PmtuCache::new(2);
    let dst_a = Ipv6Address::new([0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let dst_b = Ipv6Address::new([0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst_c = Ipv6Address::new([0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

    cache.update(dst_a, 1400, 10);
    cache.update(dst_b, 1390, 20);
    cache.update(dst_c, 1380, 30);

    assert_eq!(cache.len(), 2);
    assert!(!cache.entries.contains_key(&dst_a));
    assert!(cache.entries.contains_key(&dst_b));
    assert!(cache.entries.contains_key(&dst_c));
    assert_eq!(cache.lru.len(), cache.entries.len());
}

#[cfg_attr(test, test_case)]
pub fn test_pmtu_cache_update_moves_lru_timestamp() {
    let mut cache = Ipv6PmtuCache::new(2);
    let dst_a = Ipv6Address::new([0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa]);
    let dst_b = Ipv6Address::new([0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb]);
    let dst_c = Ipv6Address::new([0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc]);

    cache.update(dst_a, 1450, 10);
    cache.update(dst_b, 1440, 20);
    cache.update(dst_a, 1300, 30); // reduction refreshes LRU timestamp
    cache.update(dst_c, 1430, 40);

    assert_eq!(cache.len(), 2);
    assert!(cache.entries.contains_key(&dst_a));
    assert!(!cache.entries.contains_key(&dst_b));
    assert!(cache.entries.contains_key(&dst_c));
    assert!(cache.lru.contains(&(30, dst_a)));
    assert!(!cache.lru.iter().any(|(_, key)| *key == dst_b));
}

#[cfg_attr(test, test_case)]
pub fn test_pmtu_cache_evict_expired_cleans_entries_and_lru() {
    let mut cache = Ipv6PmtuCache::new(4);
    let dst_a = Ipv6Address::new([0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a]);
    let dst_b = Ipv6Address::new([0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1b]);

    cache.update(dst_a, 1400, 0);
    cache.update(dst_b, 1390, Ipv6PmtuEntry::TIMEOUT_MS);
    cache.evict_expired(Ipv6PmtuEntry::TIMEOUT_MS + 1);

    assert_eq!(cache.len(), 1);
    assert_eq!(cache.lru.len(), 1);
    assert!(!cache.entries.contains_key(&dst_a));
    assert!(cache.entries.contains_key(&dst_b));
    assert_eq!(
        cache.get(&dst_a, Ipv6PmtuEntry::TIMEOUT_MS + 1),
        Ipv6PmtuEntry::DEFAULT_MTU
    );
    assert_eq!(cache.get(&dst_b, Ipv6PmtuEntry::TIMEOUT_MS + 1), 1390);
}

// --- Fragmentation tests ---

#[cfg_attr(test, test_case)]
pub fn test_ipv6_fragment_header_parse() {
    let mut data = [0u8; 8];
    data[0] = 6; // next header = TCP
    data[2] = 0x00; data[3] = 0x09; // offset = 1, M = 1
    data[4] = 0x11; data[5] = 0x22; data[6] = 0x33; data[7] = 0x44; // ID

    let frag = Ipv6FragmentHeader::parse(&data).expect("parse failed");
    assert_eq!(frag.next_header, 6);
    assert_eq!(frag.fragment_offset, 1);
    assert_eq!(frag.more_fragments, true);
    assert_eq!(frag.identification, 0x11223344);
    assert_eq!(frag.offset_bytes(), 8);
}

#[cfg_attr(test, test_case)]
pub fn test_ipv6_fragment_reassembly_success() {
    let mut reassembler = Ipv6FragmentReassembler::new(4);
    let src = Ipv6Address::LOOPBACK;
    let dst = Ipv6Address::LOOPBACK;
    let id = 0x12345678;
    let now = 1000;

    // Unfragmentable part (IPv6 header, next=44)
    let mut unfrag = [0u8; 40];
    unfrag[0] = 0x60;
    unfrag[6] = 44; // Fragment header
    src.as_bytes().iter().enumerate().for_each(|(i, &b)| unfrag[8+i] = b);
    dst.as_bytes().iter().enumerate().for_each(|(i, &b)| unfrag[24+i] = b);

    // Fragment 1: offset=0, M=1, next=58 (ICMPv6)
    let frag1_hdr = Ipv6FragmentHeader {
        next_header: 58,
        fragment_offset: 0,
        more_fragments: true,
        identification: id,
    };
    let payload1 = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // 8 bytes

    let (res1, _) = reassembler.process_fragment(src, dst, &unfrag, &frag1_hdr, &payload1, now);
    assert!(res1.is_none());
    assert_eq!(reassembler.active_buffers(), 1);

    // Fragment 2: offset=1 (8 bytes), M=0
    let frag2_hdr = Ipv6FragmentHeader {
        next_header: 58,
        fragment_offset: 1,
        more_fragments: false,
        identification: id,
    };
    let payload2 = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];

    let (res2, _) = reassembler.process_fragment(src, dst, &unfrag, &frag2_hdr, &payload2, now);
    let packet = res2.expect("reassembly failed");
    assert_eq!(reassembler.active_buffers(), 0);

    // Check reassembled packet
    assert_eq!(packet.len(), 40 + 16);
    assert_eq!(packet[6], 58); // Patched Next Header (ICMPv6)
    assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 16); // Patched Payload Length
    assert_eq!(&packet[40..48], &payload1);
    assert_eq!(&packet[48..56], &payload2);
}

#[cfg_attr(test, test_case)]
pub fn test_ipv6_fragment_overlap_rejection() {
    let mut reassembler = Ipv6FragmentReassembler::new(4);
    let src = Ipv6Address::LOOPBACK;
    let dst = Ipv6Address::LOOPBACK;
    let id = 0x999;

    let unfrag = [0u8; 40];
    let frag1 = Ipv6FragmentHeader { next_header: 6, fragment_offset: 0, more_fragments: true, identification: id };
    let frag2 = Ipv6FragmentHeader { next_header: 6, fragment_offset: 1, more_fragments: false, identification: id };
    
    reassembler.process_fragment(src, dst, &unfrag, &frag1, &[0xaa; 16], 0);
    
    // Overlapping fragment (starts at offset 8, but offset 0-16 already filled)
    let (res, _) = reassembler.process_fragment(src, dst, &unfrag, &frag2, &[0xbb; 8], 0);
    assert!(res.is_none());
    assert_eq!(reassembler.stats().dropped_invalid, 1);
    assert_eq!(reassembler.active_buffers(), 0); // Entire datagram discarded on overlap
}

#[cfg_attr(test, test_case)]
pub fn test_ipv6_fragment_tiny_attack_rejection() {
    let mut reassembler = Ipv6FragmentReassembler::new(4);
    let src = Ipv6Address::LOOPBACK;
    let dst = Ipv6Address::LOOPBACK;
    
    // First fragment with only 4 bytes of payload (ICMPv6 header is 8 bytes)
    // This violates RFC 7112 (entire header chain must be in first fragment)
    let unfrag = [0u8; 40];
    let frag = Ipv6FragmentHeader { next_header: 58, fragment_offset: 0, more_fragments: true, identification: 0x123 };
    
    let (res, _) = reassembler.process_fragment(src, dst, &unfrag, &frag, &[0x00; 4], 0);
    assert!(res.is_none());
    assert_eq!(reassembler.stats().dropped_invalid, 1);
}
