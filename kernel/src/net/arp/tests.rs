use super::*;

#[cfg_attr(test, test_case)]
pub fn test_arp_cache() {
    let cache = ArpCache::new();
    let ip = Ipv4Address::from_octets(192, 168, 1, 1);
    let mac = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

    // Initially empty
    assert!(cache.lookup(ip, 0).is_none());

    // Insert and lookup
    cache.insert(ip, mac, 100);
    assert_eq!(cache.lookup(ip, 100), Some(mac));

    // Expired entry
    assert!(cache.lookup(ip, ARP_CACHE_TIMEOUT + 200).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_arp_packet() {
    let mut buffer = [0u8; ArpPacket::SIZE];
    let packet = crate::util::get_mut_ref::<ArpPacket>(&mut buffer, 0)
        .expect("Arp packet mutable slice out of bounds");

    let sender_mac = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    let sender_ip = Ipv4Address::from_octets(192, 168, 1, 1);
    let target_ip = Ipv4Address::from_octets(192, 168, 1, 2);

    packet.init_request(sender_mac, sender_ip, target_ip);

    assert!(packet.is_valid());
    assert_eq!(packet.operation(), ArpOperation::Request);
    assert_eq!(packet.sender_mac(), sender_mac);
    assert_eq!(packet.sender_ip(), sender_ip);
    assert_eq!(packet.target_ip(), target_ip);
}
