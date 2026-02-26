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
pub fn test_dhcp_v4_ack_updates_stack_config_via_udp_hook() {
    init_default();

    let client_mac = MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    crate::net::dhcp::init(client_mac);

    let xid = {
        let mut discover = [0u8; crate::net::dhcp::DHCP_MAX_MESSAGE_SIZE];
        let guard = match crate::net::dhcp::DHCP_CLIENT.lock() {
            Ok(g) => g,
            Err(_) => panic!("dhcp lock"),
        };
        let client = guard.as_ref().expect("dhcp client");
        let _ = client
            .build_discover(&mut discover, 10)
            .expect("build discover");
        u32::from_be_bytes([discover[4], discover[5], discover[6], discover[7]])
    };

    let offered_ip = Ipv4Address::new([10, 0, 2, 99]);
    let server_ip = Ipv4Address::new([10, 0, 2, 2]);
    let subnet = Ipv4Address::new([255, 255, 255, 0]);
    let dns = Ipv4Address::new([1, 1, 1, 1]);

    let mut dhcp_ack = [0u8; 512];
    dhcp_ack[0] = crate::net::DhcpOperation::Reply as u8;
    dhcp_ack[1] = 1;
    dhcp_ack[2] = 6;
    dhcp_ack[4..8].copy_from_slice(&xid.to_be_bytes());
    dhcp_ack[16..20].copy_from_slice(offered_ip.as_bytes()); // yiaddr
    dhcp_ack[20..24].copy_from_slice(server_ip.as_bytes()); // siaddr
    dhcp_ack[28..34].copy_from_slice(client_mac.as_bytes());

    let mut off = crate::net::DhcpHeader::SIZE;
    dhcp_ack[off..off + 4].copy_from_slice(&crate::net::DHCP_MAGIC_COOKIE);
    off += 4;

    dhcp_ack[off] = crate::net::dhcp::DhcpOption::MessageType as u8;
    dhcp_ack[off + 1] = 1;
    dhcp_ack[off + 2] = crate::net::DhcpMessageType::Ack as u8;
    off += 3;

    dhcp_ack[off] = crate::net::dhcp::DhcpOption::ServerIdentifier as u8;
    dhcp_ack[off + 1] = 4;
    dhcp_ack[off + 2..off + 6].copy_from_slice(server_ip.as_bytes());
    off += 6;

    dhcp_ack[off] = crate::net::dhcp::DhcpOption::SubnetMask as u8;
    dhcp_ack[off + 1] = 4;
    dhcp_ack[off + 2..off + 6].copy_from_slice(subnet.as_bytes());
    off += 6;

    dhcp_ack[off] = crate::net::dhcp::DhcpOption::Router as u8;
    dhcp_ack[off + 1] = 4;
    dhcp_ack[off + 2..off + 6].copy_from_slice(server_ip.as_bytes());
    off += 6;

    dhcp_ack[off] = crate::net::dhcp::DhcpOption::DnsServer as u8;
    dhcp_ack[off + 1] = 4;
    dhcp_ack[off + 2..off + 6].copy_from_slice(dns.as_bytes());
    off += 6;

    dhcp_ack[off] = crate::net::dhcp::DhcpOption::LeaseTime as u8;
    dhcp_ack[off + 1] = 4;
    dhcp_ack[off + 2..off + 6].copy_from_slice(&3600u32.to_be_bytes());
    off += 6;

    dhcp_ack[off] = crate::net::dhcp::DhcpOption::End as u8;
    off += 1;

    let src_ip = server_ip;
    let dst_ip = Ipv4Address::new([255, 255, 255, 255]);

    let mut frame = [0u8; MAX_PACKET_SIZE];
    let mut eth = EthernetFrameMut::new(&mut frame).expect("ethernet frame");
    eth.set_destination(client_mac)
        .set_source(MacAddress::from_octets(0x52, 0x54, 0x00, 0x12, 0x34, 0x56))
        .set_ether_type(EtherType::Ipv4);

    let payload = eth.payload_mut();
    let mut ip = Ipv4PacketMut::new(payload).expect("ipv4 packet");
    ip.set_version(4)
        .set_ihl(5)
        .set_ttl(64)
        .set_protocol(IpProtocol::Udp)
        .set_source(src_ip)
        .set_destination(dst_ip);

    let udp_len = UdpProcessor::build_packet(
        ip.payload_mut(),
        src_ip,
        crate::net::DHCP_SERVER_PORT,
        dst_ip,
        crate::net::DHCP_CLIENT_PORT,
        &dhcp_ack[..off],
    )
    .expect("udp packet");
    ip.finalize(udp_len);
    eth.set_payload_len(crate::net::Ipv4Header::MIN_SIZE + udp_len);

    receive(eth.as_bytes());

    let guard = match stack().lock() {
        Ok(g) => g,
        Err(_) => panic!("stack lock"),
    };
    let stack_guard = guard.as_ref().expect("stack initialized");
    let cfg = stack_guard.config();
    assert_eq!(cfg.ipv4.address, offered_ip);
    assert_eq!(cfg.ipv4.subnet_mask, subnet);
    assert_eq!(cfg.ipv4.gateway, server_ip);
    assert_eq!(cfg.ipv4.dns, Some(dns));
}

#[cfg_attr(test, test_case)]
pub fn test_dhcp_runtime_public_apis_smoke() {
    init_default();

    assert!(crate::net::init_dhcp_runtime().is_ok());

    let st = crate::net::dhcp_state();
    assert!(!st.v4_state.is_empty());
    assert!(!st.v6_state.is_empty());

    assert!(crate::net::dhcp_renew().is_ok());

    // The new public entrypoints should at least compile and return sane defaults.
    // At the moment no offer exists, so discover should return None.
    assert!(crate::net::dhcp_discover().is_none());

    // Sending a request with bogus addresses should not panic; result may be false.
    let _ = crate::net::dhcp_request([0, 0, 0, 0], [0, 0, 0, 0]);

    // Release should be a no-op as well
    crate::net::dhcp_release();

    // last declined / released are initially None
    assert!(crate::net::dhcp_last_declined().is_none());
    assert!(crate::net::dhcp_last_released().is_none());

    // create a fake client lease to exercise release API
    if let Ok(guard) = crate::net::dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            // manually populate lease and then release via helper
            let lease = crate::net::dhcp::DhcpLease {
                ip_address: crate::net::Ipv4Address::new([10, 1, 2, 3]),
                subnet_mask: crate::net::Ipv4Address::new([255, 255, 255, 0]),
                gateway: None,
                dns_servers: alloc::vec![],
                server_ip: crate::net::Ipv4Address::new([10, 1, 2, 1]),
                lease_time: 3600,
                t1: 1800,
                t2: 3150,
                obtained_at: 0,
                hostname: None,
                domain_name: None,
            };
            client.set_lease_for_test(lease.clone());
        }
    }
    crate::net::dhcp_release();
    assert_eq!(crate::net::dhcp_last_released(), Some([10,1,2,3]));

    // simulate a conflict/decline
    let test_ip = [192, 168, 123, 45];
    let server_ip = [192, 168, 123, 1];
    if let Ok(guard) = crate::net::dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            let _ = client.send_decline(crate::net::Ipv4Address::new(test_ip), Some(crate::net::Ipv4Address::new(server_ip)));
        }
    }
    assert_eq!(crate::net::dhcp_last_declined(), Some(test_ip));

    // verify dhcp_state snapshot reflects the same
    let snap = crate::net::dhcp_state();
    assert_eq!(snap.v4_last_declined, Some(test_ip));
    assert_eq!(snap.v4_last_released, Some([10,1,2,3]));
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
    use core::sync::atomic::{AtomicU16, AtomicU8, Ordering};

    static SEEN_KIND: AtomicU8 = AtomicU8::new(0);
    static SEEN_IF_ID: AtomicU16 = AtomicU16::new(0);

    fn record_if_id(if_id: Option<NetIfId>, _data: &[u8]) -> bool {
        match if_id {
            Some(id) => {
                SEEN_IF_ID.store(id.0, Ordering::Relaxed);
                SEEN_KIND.store(2, Ordering::Relaxed);
            }
            None => {
                SEEN_KIND.store(1, Ordering::Relaxed);
            }
        }
        true
    }

    init_default();
    SEEN_KIND.store(0, Ordering::Relaxed);
    if let Ok(mut guard) = stack().lock() {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(record_if_id);
        }
    }
    // perform a simple send which triggers the callback
    let _ = send_udp(1234, Ipv4Address::LOOPBACK, 80, &[0u8]);
    assert_eq!(SEEN_KIND.load(Ordering::Relaxed), 1);
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

#[cfg_attr(test, test_case)]
pub fn test_redirect_cache_reuses_expired_slot_before_oldest() {
    let mut cache = RedirectCache::new();
    let gateway = Ipv4Address::new([192, 168, 1, 2]);

    for i in 0..REDIRECT_CACHE_SIZE {
        cache.set_time(1000 + i as u64);
        cache.insert(Ipv4Address::new([10, 0, 0, i as u8]), gateway);
    }

    // Refresh one entry so it stays live while the others age out.
    let refreshed = Ipv4Address::new([10, 0, 0, 0]);
    cache.set_time(1000 + REDIRECT_CACHE_TTL + 5);
    cache.insert(refreshed, gateway);

    let replaced_expired = Ipv4Address::new([10, 0, 0, 1]);
    let new_dst = Ipv4Address::new([10, 0, 1, 99]);
    cache.set_time(1000 + REDIRECT_CACHE_TTL + 10);
    cache.insert(new_dst, gateway);

    assert_eq!(cache.get(new_dst), Some(gateway));
    assert_eq!(cache.get(refreshed), Some(gateway));
    assert!(cache.get(replaced_expired).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_ndp_pending_queue_drain_for_preserves_order() {
    let mut queue = NdpPendingQueue::new();
    let src = Ipv6Address::LOOPBACK;
    let dst_a = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let dst_b = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst_c = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

    queue.enqueue(src, dst_a, b"a1", 1);
    queue.enqueue(src, dst_b, b"b1", 2);
    queue.enqueue(src, dst_a, b"a2", 3);
    queue.enqueue(src, dst_c, b"c1", 4);

    let drained_a = queue.drain_for(&dst_a);
    assert_eq!(drained_a.len(), 2);
    assert_eq!(drained_a[0].icmpv6_data.as_slice(), b"a1");
    assert_eq!(drained_a[1].icmpv6_data.as_slice(), b"a2");

    assert_eq!(queue.packets.len(), 2);

    let drained_b = queue.drain_for(&dst_b);
    assert_eq!(drained_b.len(), 1);
    assert_eq!(drained_b[0].icmpv6_data.as_slice(), b"b1");

    let drained_c = queue.drain_for(&dst_c);
    assert_eq!(drained_c.len(), 1);
    assert_eq!(drained_c[0].icmpv6_data.as_slice(), b"c1");
    assert!(queue.packets.is_empty());
}
