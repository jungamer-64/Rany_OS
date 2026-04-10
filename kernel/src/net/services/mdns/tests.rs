use super::*;

#[cfg_attr(test, test_case)]
pub fn test_constants() {
    assert_eq!(MDNS_PORT, 5353);
    assert_eq!(MDNS_MULTICAST_GROUP, Ipv4Address::new([224, 0, 0, 251]));
    assert_eq!(MDNS_DEFAULT_TTL, 120);
}

#[cfg_attr(test, test_case)]
pub fn test_multicast_mac() {
    let mac = multicast_mac();
    assert_eq!(mac, [0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB]);
}

#[cfg_attr(test, test_case)]
pub fn test_mdns_service_new() {
    let service = MdnsService::new_in(
        crate::net::runtime::default_runtime(),
        String::from("myhost"),
        Ipv4Address::new([192, 168, 1, 100]),
    );
    assert_eq!(service.hostname(), "myhost");
    assert_eq!(service.fqdn(), "myhost.local");
    assert_eq!(service.local_ip(), Ipv4Address::new([192, 168, 1, 100]));
    assert_eq!(service.cache_len(), 0);
}

#[cfg_attr(test, test_case)]
pub fn test_encode_decode_dns_name() {
    let mut buffer = [0u8; 256];
    let name = "myhost.local";

    let end = encode_dns_name(&mut buffer, 0, name).expect("encode should succeed");

    // Expected: [6, 'm', 'y', 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0]
    assert_eq!(buffer[0], 6); // "myhost" length
    assert_eq!(&buffer[1..7], b"myhost");
    assert_eq!(buffer[7], 5); // "local" length
    assert_eq!(&buffer[8..13], b"local");
    assert_eq!(buffer[13], 0); // null terminator
    assert_eq!(end, 14);

    // Decode it back
    let (decoded, offset) = decode_dns_name(&buffer, 0).expect("decode should succeed");
    assert_eq!(decoded, "myhost.local");
    assert_eq!(offset, 14);
}

#[cfg_attr(test, test_case)]
pub fn test_build_query() {
    let mut buffer = [0u8; 256];
    let _len =
        MdnsService::build_query(&mut buffer, "test.local").expect("build_query should succeed");

    // Check header
    assert_eq!(u16::from_be_bytes([buffer[0], buffer[1]]), 0); // ID = 0
    assert_eq!(u16::from_be_bytes([buffer[2], buffer[3]]), 0x0000); // flags: query
    assert_eq!(u16::from_be_bytes([buffer[4], buffer[5]]), 1); // QDCOUNT = 1
    assert_eq!(u16::from_be_bytes([buffer[6], buffer[7]]), 0); // ANCOUNT = 0
}

#[cfg_attr(test, test_case)]
pub fn test_build_response() {
    let mut buffer = [0u8; 256];
    let ip = Ipv4Address::new([192, 168, 1, 42]);
    let len = MdnsService::build_response(&mut buffer, "test.local", ip, 120)
        .expect("build_response should succeed");

    // Check header
    assert_eq!(u16::from_be_bytes([buffer[0], buffer[1]]), 0); // ID = 0
    assert_eq!(u16::from_be_bytes([buffer[2], buffer[3]]), 0x8400); // flags: response + AA
    assert_eq!(u16::from_be_bytes([buffer[4], buffer[5]]), 0); // QDCOUNT = 0
    assert_eq!(u16::from_be_bytes([buffer[6], buffer[7]]), 1); // ANCOUNT = 1

    // Verify the IP address is in the packet
    // The RDATA should contain 192.168.1.42
    let rdata_start = len - 4;
    assert_eq!(buffer[rdata_start], 192);
    assert_eq!(buffer[rdata_start + 1], 168);
    assert_eq!(buffer[rdata_start + 2], 1);
    assert_eq!(buffer[rdata_start + 3], 42);
}

#[cfg_attr(test, test_case)]
pub fn test_process_query_for_our_hostname() {
    let mut service = MdnsService::new_in(
        crate::net::runtime::default_runtime(),
        String::from("myhost"),
        Ipv4Address::new([10, 0, 0, 5]),
    );

    // Build a query for "myhost.local"
    let mut query_buf = [0u8; 256];
    let query_len = MdnsService::build_query(&mut query_buf, "myhost.local").expect("build_query");

    let result = service.process_packet(
        &query_buf[..query_len],
        Ipv4Address::new([10, 0, 0, 1]),
        255,
        100,
    );

    match result {
        MdnsResult::SendResponse { name, ip, ttl } => {
            assert_eq!(name.to_owned_string(), "myhost.local");
            assert_eq!(ip, Ipv4Address::new([10, 0, 0, 5]));
            assert_eq!(ttl, MDNS_DEFAULT_TTL);
        }
        _ => panic!("Expected SendResponse"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_process_query_for_other_hostname() {
    let mut service = MdnsService::new_in(
        crate::net::runtime::default_runtime(),
        String::from("myhost"),
        Ipv4Address::new([10, 0, 0, 5]),
    );

    // Build a query for a different host
    let mut query_buf = [0u8; 256];
    let query_len =
        MdnsService::build_query(&mut query_buf, "otherhost.local").expect("build_query");

    let result = service.process_packet(
        &query_buf[..query_len],
        Ipv4Address::new([10, 0, 0, 1]),
        255,
        100,
    );

    match result {
        MdnsResult::Ignored => {} // expected
        _ => panic!("Expected Ignored"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_process_response_updates_cache() {
    let mut service = MdnsService::new_in(
        crate::net::runtime::default_runtime(),
        String::from("myhost"),
        Ipv4Address::new([10, 0, 0, 5]),
    );

    // Build a response for "other.local" -> 10.0.0.42
    let mut resp_buf = [0u8; 256];
    let resp_len = MdnsService::build_response(
        &mut resp_buf,
        "other.local",
        Ipv4Address::new([10, 0, 0, 42]),
        120,
    )
    .expect("build_response");

    let result = service.process_packet(
        &resp_buf[..resp_len],
        Ipv4Address::new([10, 0, 0, 42]),
        255,
        1000,
    );

    match result {
        MdnsResult::Resolved { name, ip } => {
            assert_eq!(name.to_owned_string(), "other.local");
            assert_eq!(ip, Ipv4Address::new([10, 0, 0, 42]));
        }
        _ => panic!("Expected Resolved"),
    }

    // Verify cache was updated
    let resolved = service.resolve("other.local", 1000);
    assert_eq!(resolved, Some(Ipv4Address::new([10, 0, 0, 42])));

    // Verify cache expires
    let resolved_expired = service.resolve("other.local", 1200);
    assert_eq!(resolved_expired, None);
}

#[cfg_attr(test, test_case)]
pub fn test_cleanup_expired() {
    let mut service = MdnsService::new_in(
        crate::net::runtime::default_runtime(),
        String::from("myhost"),
        Ipv4Address::new([10, 0, 0, 5]),
    );

    // Manually insert a cache entry that will expire
    service.cache.insert(
        crate::net::services::dns::DnsNameOwned::from_ascii_name("expired.local")
            .expect("dns name"),
        MdnsCacheEntry {
            ip: Ipv4Address::new([10, 0, 0, 99]),
            expiry_time: 100,
        },
    );
    service.cache.insert(
        crate::net::services::dns::DnsNameOwned::from_ascii_name("valid.local").expect("dns name"),
        MdnsCacheEntry {
            ip: Ipv4Address::new([10, 0, 0, 88]),
            expiry_time: 500,
        },
    );

    assert_eq!(service.cache_len(), 2);

    // Cleanup at time 200 should remove the expired entry
    service.cleanup_expired(200);

    assert_eq!(service.cache_len(), 1);
    assert!(service.resolve("expired.local", 200).is_none());
    assert_eq!(
        service.resolve("valid.local", 200),
        Some(Ipv4Address::new([10, 0, 0, 88]))
    );
}

#[cfg_attr(test, test_case)]
pub fn test_invalid_packet_too_short() {
    let mut service = MdnsService::new_in(
        crate::net::runtime::default_runtime(),
        String::from("myhost"),
        Ipv4Address::new([10, 0, 0, 5]),
    );

    // Packet shorter than DNS header
    let short_data = [0u8; 6];
    let result = service.process_packet(&short_data, Ipv4Address::new([10, 0, 0, 1]), 0, 0);

    match result {
        MdnsResult::InvalidPacket => {} // expected
        _ => panic!("Expected InvalidPacket"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_names_equal_case_insensitive() {
    assert!(names_equal("MyHost.Local", "myhost.local"));
    assert!(names_equal("HOST.LOCAL", "host.local"));
    assert!(!names_equal("host1.local", "host2.local"));
}

#[cfg_attr(test, test_case)]
pub fn test_dns_name_compression() {
    // Craft a packet with compression pointer
    // Name at offset 0: [4, 't', 'e', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0]
    // Compressed name pointing back to offset 0: [0xC0, 0x00]
    let mut data = [0u8; 64];
    data[0] = 4;
    data[1] = b't';
    data[2] = b'e';
    data[3] = b's';
    data[4] = b't';
    data[5] = 5;
    data[6] = b'l';
    data[7] = b'o';
    data[8] = b'c';
    data[9] = b'a';
    data[10] = b'l';
    data[11] = 0;

    // Compressed pointer at offset 14 pointing to offset 0
    data[14] = 0xC0;
    data[15] = 0x00;

    // Decode original name
    let (name1, off1) = decode_dns_name(&data, 0).expect("decode original");
    assert_eq!(name1, "test.local");
    assert_eq!(off1, 12);

    // Decode compressed name
    let (name2, off2) = decode_dns_name(&data, 14).expect("decode compressed");
    assert_eq!(name2, "test.local");
    assert_eq!(off2, 16); // past the 2-byte pointer
}

#[cfg_attr(test, test_case)]
pub fn test_encode_dns_name_label_too_long() {
    let mut buffer = [0u8; 256];
    // Create a label longer than 63 chars
    let long_label = "a".repeat(64);
    let long_name = alloc::format!("{}.local", long_label);

    let result = encode_dns_name(&mut buffer, 0, &long_name);
    assert!(result.is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_roundtrip_query_response() {
    let mut server = MdnsService::new_in(
        crate::net::runtime::default_runtime(),
        String::from("server"),
        Ipv4Address::new([192, 168, 1, 10]),
    );
    let mut client = MdnsService::new_in(
        crate::net::runtime::default_runtime(),
        String::from("client"),
        Ipv4Address::new([192, 168, 1, 20]),
    );

    // Client builds a query for server.local
    let mut query_buf = [0u8; 512];
    let query_len = MdnsService::build_query(&mut query_buf, "server.local").expect("build_query");

    // Server processes the query
    let result = server.process_packet(
        &query_buf[..query_len],
        Ipv4Address::new([192, 168, 1, 20]),
        255,
        1000,
    );

    // Server should want to send a response
    match result {
        MdnsResult::SendResponse { name, ip, ttl } => {
            // Server builds the response
            let mut resp_buf = [0u8; 512];
            let resp_len =
                MdnsService::build_response(&mut resp_buf, &name.to_owned_string(), ip, ttl)
                    .expect("build_response");

            // Client processes the response
            let client_result = client.process_packet(
                &resp_buf[..resp_len],
                Ipv4Address::new([192, 168, 1, 10]),
                255,
                1000,
            );

            match client_result {
                MdnsResult::Resolved { name, ip } => {
                    assert_eq!(name.to_owned_string(), "server.local");
                    assert_eq!(ip, Ipv4Address::new([192, 168, 1, 10]));
                }
                _ => panic!("Expected Resolved"),
            }

            // Client should now have the entry cached
            let cached = client
                .resolve("server.local", 1000)
                .expect("should be cached");
            assert_eq!(cached, Ipv4Address::new([192, 168, 1, 10]));
        }
        _ => panic!("Expected SendResponse"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_mdns_reject_invalid_ttl() {
    let mut service = MdnsService::new_in(
        crate::net::runtime::default_runtime(),
        String::from("myhost"),
        Ipv4Address::new([10, 0, 0, 5]),
    );
    let mut query_buf = [0u8; 256];
    let query_len = MdnsService::build_query(&mut query_buf, "myhost.local").expect("build_query");

    // TTL 64 should be ignored
    let result = service.process_packet(
        &query_buf[..query_len],
        Ipv4Address::new([10, 0, 0, 1]),
        64,
        100,
    );
    assert!(matches!(result, MdnsResult::Ignored));

    // TTL 255 should be accepted
    let result = service.process_packet(
        &query_buf[..query_len],
        Ipv4Address::new([10, 0, 0, 1]),
        255,
        100,
    );
    assert!(matches!(result, MdnsResult::SendResponse { .. }));
}
