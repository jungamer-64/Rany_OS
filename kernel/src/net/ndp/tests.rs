use super::*;

#[test_case]
fn test_neighbor_cache_basic() {
    let mut cache = NeighborCache::new();
    let ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    assert!(cache.is_empty());

    cache.insert(NeighborEntry::new_reachable(ip, mac, 1000));
    assert_eq!(cache.len(), 1);

    let entry = cache.lookup(&ip).unwrap();
    assert_eq!(entry.mac, mac);
    assert_eq!(entry.state, NeighborState::Reachable);

    cache.remove(&ip);
    assert!(cache.is_empty());
}

#[test_case]
fn test_neighbor_cache_update() {
    let mut cache = NeighborCache::new();
    let ip = Ipv6Address::LOOPBACK;

    // Insert incomplete
    cache.insert(NeighborEntry::new_incomplete(ip, 100));
    assert!(!cache.lookup(&ip).unwrap().has_mac());

    // Update to reachable
    let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    cache.update_reachable(&ip, mac, 200);
    let entry = cache.lookup(&ip).unwrap();
    assert!(entry.has_mac());
    assert_eq!(entry.mac, mac);
    assert_eq!(entry.state, NeighborState::Reachable);
}

#[test_case]
fn test_neighbor_cache_expiry() {
    let mut cache = NeighborCache::new();
    let ip = Ipv6Address::LOOPBACK;
    let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    cache.insert(NeighborEntry::new_reachable(ip, mac, 0));
    assert_eq!(cache.lookup(&ip).unwrap().state, NeighborState::Reachable);

    // Expire after reachable timeout
    cache.expire_reachable(REACHABLE_TIME_MS + 1);
    assert_eq!(cache.lookup(&ip).unwrap().state, NeighborState::Stale);

    // Expire after stale timeout
    cache.expire_old(STALE_TIMEOUT_MS + REACHABLE_TIME_MS + 2);
    assert!(cache.is_empty());
}

#[test_case]
fn test_parse_slla_option() {
    // Source Link-Layer Address: type=1, len=1 (8 bytes), mac=52:54:00:12:34:56
    let data = [1, 1, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let options = parse_ndp_options(&data);
    assert_eq!(options.len(), 1);
    match &options[0] {
        NdpOption::LinkLayerAddress { option_type, mac } => {
            assert_eq!(*option_type, NdpOptionType::SourceLinkLayerAddress);
            assert_eq!(*mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        }
        _ => panic!("Expected LinkLayerAddress"),
    }
}

#[test_case]
fn test_parse_prefix_info_option() {
    // Prefix Information: type=3, len=4 (32 bytes)
    let mut data = [0u8; 32];
    data[0] = 3;  // type
    data[1] = 4;  // length (4 * 8 = 32 bytes)
    data[2] = 64; // prefix length
    data[3] = 0xC0; // flags: on-link + autonomous
    data[4] = 0; data[5] = 0; data[6] = 0x0E; data[7] = 0x10; // valid lifetime = 3600
    data[8] = 0; data[9] = 0; data[10] = 0x07; data[11] = 0x08; // preferred lifetime = 1800
    // bytes 12-15: reserved
    // prefix: 2001:db8:: at bytes 16-31
    data[16] = 0x20; data[17] = 0x01;
    data[18] = 0x0d; data[19] = 0xb8;

    let options = parse_ndp_options(&data);
    assert_eq!(options.len(), 1);
    match &options[0] {
        NdpOption::PrefixInfo { prefix_len, on_link, autonomous, valid_lifetime, preferred_lifetime, prefix } => {
            assert_eq!(*prefix_len, 64);
            assert!(*on_link);
            assert!(*autonomous);
            assert_eq!(*valid_lifetime, 3600);
            assert_eq!(*preferred_lifetime, 1800);
            assert_eq!(prefix.as_bytes()[0], 0x20);
            assert_eq!(prefix.as_bytes()[1], 0x01);
        }
        _ => panic!("Expected PrefixInfo"),
    }
}

#[test_case]
fn test_build_ns() {
    let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56]);
    let target = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst = target.solicited_node();
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    let msg = NdpProcessor::build_ns(&src, &dst, &target, &mac);
    assert_eq!(msg.len(), 32);
    assert_eq!(msg[0], u8::from(Icmpv6Type::NeighborSolicitation));
    // Target at bytes 8-23
    assert_eq!(&msg[8..24], target.as_bytes());
    // SLLA option at bytes 24-31
    assert_eq!(msg[24], 1); // type
    assert_eq!(msg[25], 1); // length
    assert_eq!(&msg[26..32], &mac);

    // Verify checksum
    let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
    let cksum = data_checksum(&msg, pseudo);
    assert_eq!(cksum, 0);
}

#[test_case]
fn test_build_na() {
    let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let dst = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let target = src;
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    let msg = NdpProcessor::build_na(&src, &dst, &target, &mac, true);
    assert_eq!(msg.len(), 32);
    assert_eq!(msg[0], u8::from(Icmpv6Type::NeighborAdvertisement));
    // Flags: Solicited + Override = 0x60
    assert_eq!(msg[4] & 0x60, 0x60);
    // Target at bytes 8-23
    assert_eq!(&msg[8..24], target.as_bytes());

    // Verify checksum
    let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
    let cksum = data_checksum(&msg, pseudo);
    assert_eq!(cksum, 0);
}

#[test_case]
fn test_build_rs() {
    let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    let msg = NdpProcessor::build_rs(&src, &mac);
    assert_eq!(msg.len(), 16);
    assert_eq!(msg[0], u8::from(Icmpv6Type::RouterSolicitation));

    // Verify checksum
    let dst = Ipv6Address::ALL_ROUTERS_LINK_LOCAL;
    let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
    let cksum = data_checksum(&msg, pseudo);
    assert_eq!(cksum, 0);
}

#[test_case]
fn test_multicast_mac() {
    let addr = Ipv6Address::ALL_NODES_LINK_LOCAL;
    let mac = ipv6_multicast_to_mac(&addr);
    assert_eq!(mac, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
}

#[test_case]
fn test_resolve_multicast() {
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let proc = NdpProcessor::new(Ipv6Address::LOOPBACK, mac);

    let mcast = Ipv6Address::ALL_NODES_LINK_LOCAL;
    let resolved = proc.resolve(&mcast).unwrap();
    assert_eq!(resolved, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
}

#[test_case]
fn test_ns_processing() {
    let our_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let our_ip = Ipv6Address::from_eui64(&our_mac);
    let mut proc = NdpProcessor::new(our_ip, our_mac);

    let sender_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let sender_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst = our_ip.solicited_node();

    // Build an NS targeting our address
    let ns = NdpProcessor::build_ns(&sender_ip, &dst, &our_ip, &sender_mac);

    let result = proc.process(
        Icmpv6Type::NeighborSolicitation,
        &ns,
        sender_ip,
        dst,
        1000,
    );

    match result {
        NdpResult::SendNeighborAdvertisement { dst, target, our_mac: na_mac, solicited } => {
            assert_eq!(dst, sender_ip);
            assert_eq!(target, our_ip);
            assert_eq!(na_mac, our_mac);
            assert!(solicited);
        }
        _ => panic!("Expected SendNeighborAdvertisement"),
    }

    // Sender should be learned in our cache
    let entry = proc.cache().lookup(&sender_ip).unwrap();
    assert_eq!(entry.mac, sender_mac);
    assert_eq!(entry.state, NeighborState::Reachable);
}
