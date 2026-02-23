use super::*;

#[cfg_attr(test, test_case)]
pub fn test_network_stack_creation() {
    let stack = NetworkStack::new_default();
    let config = stack.config();

    assert_eq!(
        config.mac,
        MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    );
    assert!(config.icmp_echo_enabled);
}

#[cfg_attr(test, test_case)]
pub fn test_network_stack_poisoned_runtime_apis_fail() {
    use crate::sync::set_panicking;

    // Initialize and then poison the global stack lock
    init_default();

    set_panicking(true);
    if let Ok(_g) = NETWORK_STACK.lock() {
        // Dropping _g while panicking marks the lock poisoned
    }
    set_panicking(false);

    // Runtime APIs should fail conservatively when the global lock is poisoned
    assert!(!send_udp(1234, Ipv4Address::LOOPBACK, 80, &[0x1, 0x2]));
    assert!(!send_tcp(Ipv4Address::LOOPBACK, Ipv4Address::LOOPBACK, &[]));
    assert!(bind_udp(1234).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_send_udp_fallback_zero_copy() {
    // Initialize stack and set transmit function to always succeed
    init_default();
    if let Ok(mut guard) = stack().lock() {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(|_if_id: Option<super::NetIfId>, _data: &[u8]| {
                assert!(_if_id.is_none());
                true
            });
        }
    }

    let dst = Ipv4Address::new([255, 255, 255, 255]); // Broadcast -> immediate MAC
    assert!(send_udp(1234, dst, 80, &[1, 2, 3]));
}

#[cfg_attr(test, test_case)]
pub fn test_send_icmp_fallback_zero_copy() {
    // Initialize stack and set transmit function
    init_default();
    if let Ok(mut guard) = stack().lock() {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(|_if_id: Option<super::NetIfId>, _data: &[u8]| {
                assert!(_if_id.is_none());
                true
            });
            // Pre-populate ARP cache so ping will proceed
            let target = Ipv4Address::new([8, 8, 8, 8]);
            s.arp.cache().insert(
                target,
                MacAddress::from_octets(0x52, 0x54, 0x00, 0x12, 0x34, 0x56),
                s.current_time(),
            );
        }
    }

    let res = crate::net::send_icmp_echo([8, 8, 8, 8], 1);
    assert!(res.is_ok());
}

#[cfg_attr(test, test_case)]
pub fn test_redirect_cache_basic() {
    let mut cache = RedirectCache::new();
    let dst = Ipv4Address::new([10, 0, 0, 100]);
    let gateway = Ipv4Address::new([192, 168, 1, 2]);
    
    // Initially empty
    assert!(cache.get(dst).is_none());
    
    // Insert and retrieve
    cache.insert(dst, gateway);
    assert_eq!(cache.get(dst), Some(gateway));
    
    // Update existing entry
    let new_gateway = Ipv4Address::new([192, 168, 1, 3]);
    cache.insert(dst, new_gateway);
    assert_eq!(cache.get(dst), Some(new_gateway));
}

#[cfg_attr(test, test_case)]
pub fn test_redirect_cache_expiry() {
    let mut cache = RedirectCache::new();
    let dst = Ipv4Address::new([10, 0, 0, 100]);
    let gateway = Ipv4Address::new([192, 168, 1, 2]);
    
    // Insert at time 0
    cache.set_time(0);
    cache.insert(dst, gateway);
    
    // Still valid at TTL - 1
    cache.set_time(REDIRECT_CACHE_TTL - 1);
    assert_eq!(cache.get(dst), Some(gateway));
    
    // Expired after TTL
    cache.set_time(REDIRECT_CACHE_TTL + 1);
    assert!(cache.get(dst).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_transmit_fn_interface_parameter() {
    // verify that the stack passes the optional interface ID through the
    // transmit callback.  by default we expect `None` to be delivered.
    init_default();
    let seen: core::cell::Cell<Option<NetIfId>> = core::cell::Cell::new(None);
    if let Ok(mut guard) = stack().lock() {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(|if_id, _data| {
                seen.set(if_id);
                true
            });
        }
    }
    // perform a simple send which triggers the callback
    let _ = send_udp(1234, Ipv4Address::LOOPBACK, 80, &[0u8]);
    assert!(seen.get().is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_send_on_helpers_exist() {
    init_default();
    // no panic means functions compile and can be called
    let _ = send_udp_on(NetIfId(0), 1234, Ipv4Address::LOOPBACK, 80, &[0u8]);
    let _ = send_udp_v6_on(
        NetIfId(0),
        1234,
        crate::net::ipv6::Ipv6Address::LOOPBACK,
        crate::net::ipv6::Ipv6Address::LOOPBACK,
        80,
        &[0u8],
    );
    let _ = send_tcp_on(NetIfId(0), Ipv4Address::LOOPBACK, Ipv4Address::LOOPBACK, &[]);
}

#[cfg_attr(test, test_case)]
pub fn test_redirect_cache_cleanup() {
    let mut cache = RedirectCache::new();
    let dst1 = Ipv4Address::new([10, 0, 0, 1]);
    let dst2 = Ipv4Address::new([10, 0, 0, 2]);
    let gateway = Ipv4Address::new([192, 168, 1, 2]);
    
    cache.set_time(0);
    cache.insert(dst1, gateway);
    
    cache.set_time(REDIRECT_CACHE_TTL / 2);
    cache.insert(dst2, gateway);
    
    // First entry expires, second still valid
    cache.set_time(REDIRECT_CACHE_TTL + 1);
    cache.cleanup();
    
    // dst1 should be removed, dst2 still valid
    assert!(cache.get(dst1).is_none());
    // dst2 is still within TTL from its insertion time
    cache.set_time(REDIRECT_CACHE_TTL / 2 + REDIRECT_CACHE_TTL - 1);
    assert_eq!(cache.get(dst2), Some(gateway));
}

#[cfg_attr(test, test_case)]
pub fn test_redirect_cache_eviction() {
    let mut cache = RedirectCache::new();
    let gateway = Ipv4Address::new([192, 168, 1, 2]);
    
    // Fill cache completely
    for i in 0..REDIRECT_CACHE_SIZE {
        cache.set_time(i as u64 * 100);
        let dst = Ipv4Address::new([10, 0, 0, i as u8]);
        cache.insert(dst, gateway);
    }
    
    // Adding one more should evict the oldest (dst 10.0.0.0)
    cache.set_time(REDIRECT_CACHE_SIZE as u64 * 100);
    let new_dst = Ipv4Address::new([10, 0, 1, 0]);
    cache.insert(new_dst, gateway);
    
    // New entry should be present
    assert_eq!(cache.get(new_dst), Some(gateway));
    
    // Oldest entry (10.0.0.0) should be evicted
    assert!(cache.get(Ipv4Address::new([10, 0, 0, 0])).is_none());
}
