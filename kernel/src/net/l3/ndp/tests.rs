// ============================================================================
// kernel/src/net/l3/ndp/tests.rs - L3 / NDP / テスト
// ============================================================================

use super::*;

fn payload_bytes(payload: &kernel_api::resource::net::PacketPayload) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; payload.total_len()];
    let view = crate::net::payload::PacketPayloadView::new(payload);
    let mut copied = 0usize;
    view.for_each_chunk(|chunk| {
        if copied == out.len() {
            return;
        }
        let take = chunk.len().min(out.len() - copied);
        out[copied..copied + take].copy_from_slice(&chunk[..take]);
        copied += take;
    });
    out.truncate(copied);
    out
}

#[cfg_attr(test, test_case)]
pub fn test_neighbor_cache_basic() {
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

#[cfg_attr(test, test_case)]
pub fn test_neighbor_cache_update() {
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

#[cfg_attr(test, test_case)]
pub fn test_neighbor_cache_expiry() {
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

#[cfg_attr(test, test_case)]
pub fn test_parse_slla_option() {
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

#[cfg_attr(test, test_case)]
pub fn test_parse_prefix_info_option() {
    // Prefix Information: type=3, len=4 (32 bytes)
    let mut data = [0u8; 32];
    data[0] = 3; // type
    data[1] = 4; // length (4 * 8 = 32 bytes)
    data[2] = 64; // prefix length
    data[3] = 0xC0; // flags: on-link + autonomous
    data[4] = 0;
    data[5] = 0;
    data[6] = 0x0E;
    data[7] = 0x10; // valid lifetime = 3600
    data[8] = 0;
    data[9] = 0;
    data[10] = 0x07;
    data[11] = 0x08; // preferred lifetime = 1800
    // bytes 12-15: reserved
    // prefix: 2001:db8:: at bytes 16-31
    data[16] = 0x20;
    data[17] = 0x01;
    data[18] = 0x0d;
    data[19] = 0xb8;

    let options = parse_ndp_options(&data);
    assert_eq!(options.len(), 1);
    match &options[0] {
        NdpOption::PrefixInfo {
            prefix_len,
            on_link,
            autonomous,
            valid_lifetime,
            preferred_lifetime,
            prefix,
        } => {
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

#[cfg_attr(test, test_case)]
pub fn test_build_ns() {
    let src = Ipv6Address::new([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56,
    ]);
    let target = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst = target.solicited_node();
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    let msg = NdpProcessor::build_ns(&src, &dst, &target, &mac).expect("ns");
    let msg = payload_bytes(&msg);
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

#[cfg_attr(test, test_case)]
pub fn test_build_na() {
    let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let dst = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let target = src;
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    let msg = NdpProcessor::build_na(&src, &dst, &target, &mac, true).expect("na");
    let msg = payload_bytes(&msg);
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

#[cfg_attr(test, test_case)]
pub fn test_build_rs() {
    let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    let msg = NdpProcessor::build_rs(&src, &mac).expect("rs");
    let msg = payload_bytes(&msg);
    assert_eq!(msg.len(), 16);
    assert_eq!(msg[0], u8::from(Icmpv6Type::RouterSolicitation));

    // Verify checksum
    let dst = Ipv6Address::ALL_ROUTERS_LINK_LOCAL;
    let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
    let cksum = data_checksum(&msg, pseudo);
    assert_eq!(cksum, 0);
}

#[cfg_attr(test, test_case)]
pub fn test_multicast_mac() {
    let addr = Ipv6Address::ALL_NODES_LINK_LOCAL;
    let mac = addr.multicast_mac();
    assert_eq!(mac, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
}

#[cfg_attr(test, test_case)]
pub fn test_resolve_multicast() {
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let processor = NdpProcessor::new(Ipv6Address::LOOPBACK, mac);

    let mcast = Ipv6Address::ALL_NODES_LINK_LOCAL;
    let resolved = processor.resolve(&mcast).unwrap();
    assert_eq!(resolved, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
}

#[cfg_attr(test, test_case)]
pub fn test_ns_processing() {
    let our_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let our_ip = Ipv6Address::from_eui64(&our_mac);
    let mut processor = NdpProcessor::new(our_ip, our_mac);

    let sender_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let sender_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst = our_ip.solicited_node();

    // Build an NS targeting our address
    let ns = NdpProcessor::build_ns(&sender_ip, &dst, &our_ip, &sender_mac).expect("ns");
    let ns = payload_bytes(&ns);

    let result = processor.process(
        Icmpv6Type::NeighborSolicitation,
        &ns,
        sender_ip,
        dst,
        sender_mac,
        1000,
    );

    match result {
        NdpResult::SendNeighborAdvertisement {
            dst,
            target,
            our_mac: na_mac,
            solicited,
        } => {
            assert_eq!(dst, sender_ip);
            assert_eq!(target, our_ip);
            assert_eq!(na_mac, our_mac);
            assert!(solicited);
        }
        _ => panic!("Expected SendNeighborAdvertisement"),
    }

    // Sender should be learned in our cache as STALE (RFC 4861)
    let entry = processor.cache().lookup(&sender_ip).unwrap();
    assert_eq!(entry.mac, sender_mac);
    assert_eq!(entry.state, NeighborState::Stale);
}

#[cfg_attr(test, test_case)]
pub fn test_ndp_spoofing_detection() {
    let our_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let our_ip = Ipv6Address::from_eui64(&our_mac);
    let mut processor = NdpProcessor::new(our_ip, our_mac);

    let sender_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst = our_ip.solicited_node();

    // Attacker sends NS with SLLA option containing their MAC,
    // but the actual Ethernet source MAC is different (spoofed).
    let slla_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let actual_eth_mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    let ns = NdpProcessor::build_ns(&sender_ip, &dst, &our_ip, &slla_mac).expect("ns");
    let ns = payload_bytes(&ns);

    let result = processor.process(
        Icmpv6Type::NeighborSolicitation,
        &ns,
        sender_ip,
        dst,
        actual_eth_mac,
        1000,
    );

    // Should return Error due to spoofing detection
    assert!(matches!(result, NdpResult::Error));

    // Cache should NOT be updated
    assert!(processor.cache().lookup(&sender_ip).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_na_multicast_target_rejection() {
    let our_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let our_ip = Ipv6Address::from_eui64(&our_mac);
    let mut processor = NdpProcessor::new(our_ip, our_mac);

    let sender_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let sender_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    // Build an NA with a MULTICAST target address (invalid per RFC 4861)
    let mcast_target = Ipv6Address::ALL_NODES_LINK_LOCAL;
    let na =
        NdpProcessor::build_na(&sender_ip, &our_ip, &mcast_target, &sender_mac, true).expect("na");
    let na = payload_bytes(&na);

    let result = processor.process(
        Icmpv6Type::NeighborAdvertisement,
        &na,
        sender_ip,
        our_ip,
        sender_mac,
        1000,
    );

    // Should return Error
    assert!(matches!(result, NdpResult::Error));

    // Cache should NOT be updated with multicast address
    assert!(processor.cache().lookup(&mcast_target).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_na_discard_unknown_target() {
    let our_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let our_ip = Ipv6Address::from_eui64(&our_mac);
    let mut processor = NdpProcessor::new(our_ip, our_mac);

    let sender_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let sender_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let target_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

    // Build an NA for a target NOT in our cache
    let na =
        NdpProcessor::build_na(&sender_ip, &our_ip, &target_ip, &sender_mac, true).expect("na");
    let na = payload_bytes(&na);

    let result = processor.process(
        Icmpv6Type::NeighborAdvertisement,
        &na,
        sender_ip,
        our_ip,
        sender_mac,
        1000,
    );

    // Should return None because it was discarded
    assert!(matches!(result, NdpResult::None));

    // Cache should NOT have the target
    assert!(processor.cache().lookup(&target_ip).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_ra_processing() {
    let our_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let our_ip = Ipv6Address::from_eui64(&our_mac);
    let mut processor = NdpProcessor::new(our_ip, our_mac);

    let router_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let router_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    // Build a simple RA with SLLA option
    let mut ra = alloc::vec![0u8; 16];
    ra[0] = u8::from(Icmpv6Type::RouterAdvertisement);
    ra[4] = 64; // Hop limit
    // bytes 8-23 are router info... for RA processing it's just raw bytes

    // Add SLLA option
    ra.push(1); // type=SourceLinkLayerAddress
    ra.push(1); // len=1
    ra.extend_from_slice(&router_mac);

    let result = processor.process(
        Icmpv6Type::RouterAdvertisement,
        &ra,
        router_ip,
        our_ip,
        router_mac,
        1000,
    );

    match result {
        NdpResult::RouterAdvertisement {
            router,
            router_mac: learned_mac,
            ..
        } => {
            assert_eq!(router, router_ip);
            assert_eq!(learned_mac, Some(router_mac));
        }
        _ => panic!("Expected RouterAdvertisement result"),
    }

    // Router should be in cache as STALE
    let entry = processor
        .cache()
        .lookup(&router_ip)
        .expect("Router should be in cache");
    assert_eq!(entry.mac, router_mac);
    assert_eq!(entry.state, NeighborState::Stale);
}
