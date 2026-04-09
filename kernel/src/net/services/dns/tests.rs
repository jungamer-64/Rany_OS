use super::*;
use crate::sync::set_panicking;
use alloc::vec;

#[cfg_attr(test, test_case)]
pub fn test_primary_server_poisoned_returns_none() {
    eprintln!("[TEST] Running test_primary_server_poisoned_returns_none...");
    let client = DnsClient::new(100);
    {
        let mut s = client.ipv4_servers.lock().unwrap();
        s.push(Ipv4Address::from_octets(1, 2, 3, 4));
    }

    set_panicking(true);
    {
        let _guard = client.ipv4_servers.lock().unwrap();
    }
    set_panicking(false);

    assert_eq!(client.primary_ipv4_server(), None);
}

#[cfg_attr(test, test_case)]
pub fn test_build_query_with_edns0() {
    let client = DnsClient::new(100);
    let name = "example.com";

    let payload = client.build_query_payload(name, DnsQueryType::A).unwrap();
    let view = crate::net::payload::PacketPayloadView::new(&payload);
    let len = view.total_len();
    let mut buffer = vec![0u8; len];
    assert_eq!(view.copy_all_into(&mut buffer), len);

    // Header check
    let header = crate::util::get_ref::<DnsHeader>(&buffer, 0).unwrap();
    assert_eq!(header.question_count(), 1);
    assert_eq!(u16::from_be_bytes(header.arcount), 1); // EDNS0 OPT

    // Question ends at DnsHeader::SIZE + 13 + 4 = 12 + 13 + 4 = 29
    // OPT RR starts at 29
    let opt_offset = 12 + 13 + 4;
    assert_eq!(buffer[opt_offset], 0); // Root name
    let opt_type = u16::from_be_bytes([buffer[opt_offset + 1], buffer[opt_offset + 2]]);
    assert_eq!(opt_type, DnsQueryType::OPT as u16);

    let udp_payload_size = u16::from_be_bytes([buffer[opt_offset + 3], buffer[opt_offset + 4]]);
    assert_eq!(udp_payload_size, 4096);

    assert_eq!(len, opt_offset + 11);
}

#[cfg_attr(test, test_case)]
pub fn test_dns_header_truncated_flag() {
    // Create a header with TC bit set (bit 9 of flags)
    let mut data = [0u8; 12];
    // Flags with TC=1: 0x8200 (response + truncated)
    data[2] = 0x82;
    data[3] = 0x00;

    let header = crate::util::get_ref::<DnsHeader>(&data, 0).unwrap();
    assert!(header.is_truncated());
    assert!(header.is_response());
}

#[cfg_attr(test, test_case)]
pub fn test_dns_header_not_truncated() {
    let mut data = [0u8; 12];
    // Flags: standard response without TC
    data[2] = 0x80;
    data[3] = 0x00;

    let header = crate::util::get_ref::<DnsHeader>(&data, 0).unwrap();
    assert!(!header.is_truncated());
}

#[cfg_attr(test, test_case)]
pub fn test_build_tcp_query() {
    let client = DnsClient::new(100);
    let payload = client
        .build_tcp_query_payload("example.com", DnsQueryType::A)
        .unwrap();
    let view = crate::net::payload::PacketPayloadView::new(&payload);
    let len = view.total_len();
    let mut buffer = vec![0u8; len];
    assert_eq!(view.copy_all_into(&mut buffer), len);

    // Length prefix should be first 2 bytes
    let msg_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
    assert_eq!(len, 2 + msg_len);

    // DNS header starts at byte 2
    let header = crate::util::get_ref::<DnsHeader>(&buffer[2..], 0).unwrap();
    assert!(!header.is_response()); // Query, not response
}

#[cfg_attr(test, test_case)]
pub fn test_needs_tcp_fallback_truncated() {
    let client = DnsClient::new(100);

    // Create truncated response
    let mut data = [0u8; 100];
    data[2] = 0x82; // TC bit set
    data[3] = 0x00;

    assert!(client.needs_tcp_fallback(&data));
}

#[cfg_attr(test, test_case)]
pub fn test_needs_tcp_fallback_512_bytes() {
    let client = DnsClient::new(100);

    // Create response at UDP limit
    let mut data = [0u8; 512];
    data[2] = 0x80; // Normal response
    data[3] = 0x00;

    assert!(client.needs_tcp_fallback(&data));
}

#[cfg_attr(test, test_case)]
pub fn test_needs_tcp_fallback_normal() {
    let client = DnsClient::new(100);

    // Create normal response below limit
    let mut data = [0u8; 100];
    data[2] = 0x80;
    data[3] = 0x00;

    assert!(!client.needs_tcp_fallback(&data));
}

#[cfg_attr(test, test_case)]
pub fn test_tcp_message_length() {
    assert_eq!(DnsClient::tcp_message_length(&[0x00, 0x20]), 32);
    assert_eq!(DnsClient::tcp_message_length(&[0x01, 0x00]), 256);
    assert_eq!(DnsClient::tcp_message_length(&[0xFF, 0xFF]), 65535);
}

#[cfg_attr(test, test_case)]
pub fn test_parse_aaaa_record() {
    use crate::net::l3::ipv6::Ipv6Address;
    let client = DnsClient::new(100);

    // Fake DNS response with AAAA record
    // Header (12 bytes) + Question (example.com + 4) + Answer (AAAA record)
    let mut data = vec![0u8; 12 + 13 + 4 + 2 + 10 + 16];

    // Header: 1 question, 1 answer, no error
    data[0..2].copy_from_slice(&0x1234u16.to_be_bytes()); // ID
    data[2] = 0x81;
    data[3] = 0x80; // Standard response
    data[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    data[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT

    // Question: example.com (7 + 3 + 0)
    let q_offset = 12;
    data[q_offset] = 7;
    data[q_offset + 1..q_offset + 8].copy_from_slice(b"example");
    data[q_offset + 8] = 3;
    data[q_offset + 9..q_offset + 12].copy_from_slice(b"com");
    data[q_offset + 12] = 0;
    data[q_offset + 13..q_offset + 15].copy_from_slice(&(DnsQueryType::AAAA as u16).to_be_bytes());
    data[q_offset + 15..q_offset + 17].copy_from_slice(&1u16.to_be_bytes()); // IN

    // Answer: Name pointer (0xc00c) + Type (AAAA=28) + Class (1) + TTL (3600) + Len (16) + IPv6 addr
    let a_offset = q_offset + 17;
    data[a_offset..a_offset + 2].copy_from_slice(&0xc00cu16.to_be_bytes());
    data[a_offset + 2..a_offset + 4].copy_from_slice(&(DnsQueryType::AAAA as u16).to_be_bytes());
    data[a_offset + 4..a_offset + 6].copy_from_slice(&1u16.to_be_bytes());
    data[a_offset + 6..a_offset + 10].copy_from_slice(&3600u32.to_be_bytes());
    data[a_offset + 10..a_offset + 12].copy_from_slice(&16u16.to_be_bytes());

    let ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    data[a_offset + 12..a_offset + 28].copy_from_slice(&ipv6_addr);

    // We need to register the ID first because parse_response checks for pending IDs
    if let Ok(mut pending) = client.pending_ids.lock() {
        pending.insert(0x1234, 0);
    }

    let payload = crate::net::payload::payload_from_bytes(&data).expect("dns test packet");
    let records = client
        .parse_response_payload(&payload, 1000, "example.com", DnsQueryType::AAAA)
        .expect("dns payload parse result")
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].name, "example.com");
    assert_eq!(records[0].rtype, DnsQueryType::AAAA);

    if let DnsRecordData::AAAA(addr) = &records[0].data {
        assert_eq!(addr.as_bytes(), &ipv6_addr);
    } else {
        panic!("Expected AAAA record data");
    }
}
