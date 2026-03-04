use crate::net::l3::ipv6;

#[test]
fn repro_pmtu_evict() {
    let mut cache = ipv6::Ipv6PmtuCache::new(1);
    let dst = ipv6::Ipv6Address::new([0x20, 1, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
    cache.update(dst, 1400, 0);
    cache.evict_expired(ipv6::Ipv6PmtuEntry::TIMEOUT_MS + 1);
}
