use super::*;

// --- Address tests ---

#[test_case]
fn test_unspecified() {
    let addr = Ipv6Address::UNSPECIFIED;
    assert!(addr.is_unspecified());
    assert!(!addr.is_loopback());
    assert!(!addr.is_multicast());
    assert!(!addr.is_unicast_link_local());
}

#[test_case]
fn test_loopback() {
    let addr = Ipv6Address::LOOPBACK;
    assert!(!addr.is_unspecified());
    assert!(addr.is_loopback());
    assert!(!addr.is_multicast());
}

#[test_case]
fn test_multicast() {
    let addr = Ipv6Address::ALL_NODES_LINK_LOCAL;
    assert!(addr.is_multicast());
    assert!(addr.is_link_local());
    assert!(!addr.is_unicast_link_local());
}

#[test_case]
fn test_link_local() {
    // fe80::1
    let addr = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert!(addr.is_unicast_link_local());
    assert!(addr.is_link_local());
    assert!(!addr.is_multicast());
    assert!(!addr.is_global());
}

#[test_case]
fn test_global() {
    // 2001:db8::1
    let addr = Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert!(addr.is_global());
    assert!(!addr.is_unicast_link_local());
    assert!(!addr.is_multicast());
    assert!(!addr.is_loopback());
}

#[test_case]
fn test_eui64() {
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

#[test_case]
fn test_solicited_node() {
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

#[test_case]
fn test_multicast_mac() {
    // ff02::1:ff12:3456 → 33:33:ff:12:34:56
    let addr = Ipv6Address::new([
        0xff, 0x02, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0x01, 0xff, 0x12, 0x34, 0x56,
    ]);
    let mac = addr.multicast_mac();
    assert_eq!(mac, [0x33, 0x33, 0xff, 0x12, 0x34, 0x56]);
}

// --- Header / Packet tests ---

#[test_case]
fn test_header_size() {
    assert_eq!(core::mem::size_of::<Ipv6Header>(), IPV6_HEADER_SIZE);
}

#[test_case]
fn test_packet_parse_valid() {
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

#[test_case]
fn test_packet_parse_wrong_version() {
    let mut buf = [0u8; 48];
    buf[0] = 0x40; // version = 4 (IPv4)
    assert!(Ipv6Packet::parse(&buf).is_none());
}

#[test_case]
fn test_packet_parse_too_short() {
    let buf = [0x60u8; 20]; // too short for IPv6 header
    assert!(Ipv6Packet::parse(&buf).is_none());
}

#[test_case]
fn test_packet_mut_build() {
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

    assert_eq!(pkt.header().version(), 6);
    assert_eq!(pkt.header().source(), src);
    assert_eq!(pkt.header().destination(), dst);
    assert_eq!(pkt.header().next_header(), IpProtocol::Icmpv6);
    assert_eq!(pkt.header().hop_limit(), 255);
    assert_eq!(pkt.header().payload_length(), 20);
}

// --- Extension header tests ---

#[test_case]
fn test_skip_no_extension_headers() {
    // Payload that starts directly with upper-layer data
    let data = [1, 2, 3, 4, 5, 6, 7, 8];
    let (proto, remaining) = skip_extension_headers(IpProtocol::Tcp, &data);
    assert_eq!(proto, IpProtocol::Tcp);
    assert_eq!(remaining.len(), 8);
}

#[test_case]
fn test_skip_hop_by_hop() {
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

#[test_case]
fn test_skip_fragment_header() {
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

#[test_case]
fn test_pseudo_header_checksum() {
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

#[test_case]
fn test_display_loopback() {
    let addr = Ipv6Address::LOOPBACK;
    let s = alloc::format!("{}", addr);
    assert_eq!(s, "::1");
}

#[test_case]
fn test_display_link_local() {
    // fe80::1
    let addr = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let s = alloc::format!("{}", addr);
    assert_eq!(s, "fe80::1");
}

#[test_case]
fn test_display_all_nodes() {
    let addr = Ipv6Address::ALL_NODES_LINK_LOCAL;
    let s = alloc::format!("{}", addr);
    assert_eq!(s, "ff02::1");
}

#[test_case]
fn test_display_full() {
    // 2001:db8:1:2:3:4:5:6 (no zero run >= 2)
    let addr = Ipv6Address::new([
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06,
    ]);
    let s = alloc::format!("{}", addr);
    assert_eq!(s, "2001:db8:1:2:3:4:5:6");
}

#[test_case]
fn test_from_u64_pair() {
    let addr = Ipv6Address::from_u64_pair(
        0xfe80_0000_0000_0000,
        0x0000_0000_0000_0001,
    );
    assert!(addr.is_unicast_link_local());
    assert_eq!(addr.as_bytes()[15], 1);
}
