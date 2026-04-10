use super::*;
use crate::sync::set_panicking;
use alloc::vec;
use alloc::vec::Vec;

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn dns_name_view(name: &str) -> DnsNameView {
    let mut labels = Vec::new();
    for label in name.split('.') {
        let payload = crate::net::payload::payload_from_bytes(label.as_bytes())
            .expect("dns label payload must be created");
        let span = PayloadSpan::from_range(&payload, 0, label.len())
            .expect("dns label span must be created");
        labels.push(span);
    }
    DnsNameView::from_labels(labels)
}

fn dns_txt_view(text: &str) -> DnsTxtView {
    let payload = crate::net::payload::payload_from_bytes(text.as_bytes())
        .expect("dns txt payload must be created");
    let span =
        PayloadSpan::from_range(&payload, 0, text.len()).expect("dns txt span must be created");
    DnsTxtView::from_spans(vec![span])
}

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
pub fn test_build_tcp_query_payload() {
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
    let response = client
        .parse_response_payload(&payload, 1000, "example.com", DnsQueryType::AAAA)
        .expect("dns payload parse result")
        .unwrap();
    assert_eq!(response.records.len(), 1);
    assert_eq!(response.records[0].name.to_owned_string(), "example.com");
    assert_eq!(
        response.records[0].rtype,
        DnsRecordType::Known(DnsQueryType::AAAA)
    );

    if let DnsRecordData::AAAA(addr) = &response.records[0].data {
        assert_eq!(addr.as_bytes(), &ipv6_addr);
    } else {
        panic!("Expected AAAA record data");
    }
}

#[cfg_attr(test, test_case)]
pub fn test_parse_response_rejects_unexpected_transaction_id() {
    let client = DnsClient::new(100);
    let mut data = vec![0u8; 12];
    data[0..2].copy_from_slice(&0x2222u16.to_be_bytes());
    data[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    data[4..6].copy_from_slice(&1u16.to_be_bytes());

    let qname = encode_dns_name("example.com");
    data.extend_from_slice(&qname);
    data.extend_from_slice(&(DnsQueryType::A as u16).to_be_bytes().as_slice());
    data.extend_from_slice(&1u16.to_be_bytes());

    let payload = crate::net::payload::payload_from_bytes(&data).expect("dns test packet");
    let parsed = client
        .parse_response_payload(&payload, 1000, "example.com", DnsQueryType::A)
        .expect("must not require tcp fallback");
    assert!(matches!(parsed, Err(DnsResponseCode::FormatError)));
}

#[cfg_attr(test, test_case)]
pub fn test_parse_response_rejects_question_mismatch() {
    let client = DnsClient::new(100);
    if let Ok(mut pending) = client.pending_ids.lock() {
        pending.insert(0x1234, 1000);
    }

    let mut data = vec![0u8; 12];
    data[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    data[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    data[4..6].copy_from_slice(&1u16.to_be_bytes());

    let qname = encode_dns_name("evil.com");
    data.extend_from_slice(&qname);
    data.extend_from_slice(&(DnsQueryType::A as u16).to_be_bytes().as_slice());
    data.extend_from_slice(&1u16.to_be_bytes());

    let payload = crate::net::payload::payload_from_bytes(&data).expect("dns test packet");
    let parsed = client
        .parse_response_payload(&payload, 1000, "example.com", DnsQueryType::A)
        .expect("must not require tcp fallback");
    assert!(matches!(parsed, Err(DnsResponseCode::FormatError)));
}

#[cfg_attr(test, test_case)]
pub fn test_cache_entry_ttl_boundary() {
    let entry = DnsCacheEntry {
        response: kernel_api::resource::net::PacketPayload::default(),
        records: Vec::new(),
        cached_at: 1_000,
        min_ttl: 2,
        negative: false,
        rcode: None,
    };

    assert!(!entry.is_expired(2_999, 1_000));
    assert!(entry.is_expired(3_000, 1_000));
}

#[cfg_attr(test, test_case)]
pub fn test_cname_chain_extracts_final_a() {
    let client = DnsClient::new(100);
    let ip = Ipv4Address::from_octets(203, 0, 113, 10);

    let records = vec![
        DnsRecordMeta {
            name: dns_name_view("example.com"),
            rtype: DnsRecordType::Known(DnsQueryType::CNAME),
            rclass: DnsQueryClass::IN,
            ttl: 60,
            data: DnsRecordData::Name(dns_name_view("alias.example.com")),
        },
        DnsRecordMeta {
            name: dns_name_view("alias.example.com"),
            rtype: DnsRecordType::Known(DnsQueryType::A),
            rclass: DnsQueryClass::IN,
            ttl: 60,
            data: DnsRecordData::A(ip),
        },
    ];

    assert_eq!(
        client.resolve_ipv4_from_records(&records, "example.com"),
        Some(ip)
    );
}

#[cfg_attr(test, test_case)]
pub fn test_cname_chain_extracts_final_aaaa() {
    let client = DnsClient::new(100);
    let ip = Ipv6Address::new([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
    ]);

    let records = vec![
        DnsRecordMeta {
            name: dns_name_view("example.com"),
            rtype: DnsRecordType::Known(DnsQueryType::CNAME),
            rclass: DnsQueryClass::IN,
            ttl: 60,
            data: DnsRecordData::Name(dns_name_view("alias6.example.com")),
        },
        DnsRecordMeta {
            name: dns_name_view("alias6.example.com"),
            rtype: DnsRecordType::Known(DnsQueryType::AAAA),
            rclass: DnsQueryClass::IN,
            ttl: 60,
            data: DnsRecordData::AAAA(ip),
        },
    ];

    assert_eq!(
        client.resolve_ipv6_from_records(&records, "example.com"),
        Some(ip)
    );
}

#[cfg_attr(test, test_case)]
pub fn test_parse_response_preserves_unknown_rtype() {
    let client = DnsClient::new(100);
    let mut data = vec![0u8; 12];
    data[0..2].copy_from_slice(&0x4321u16.to_be_bytes()); // ID
    data[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // standard response
    data[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    data[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT

    let qname = encode_dns_name("example.com");
    data.extend_from_slice(&qname);
    data.extend_from_slice(&(DnsQueryType::A as u16).to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes()); // IN

    // Answer: name pointer + unknown type + IN + TTL + RDLENGTH + data
    data.extend_from_slice(&0xc00cu16.to_be_bytes());
    data.extend_from_slice(&65000u16.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&120u32.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes());
    data.push(0xAB);

    if let Ok(mut pending) = client.pending_ids.lock() {
        pending.insert(0x4321, 0);
    }

    let payload = crate::net::payload::payload_from_bytes(&data).expect("dns test packet");
    let response = client
        .parse_response_payload(&payload, 1000, "example.com", DnsQueryType::A)
        .expect("dns payload parse result")
        .expect("dns parse ok");

    assert_eq!(response.records.len(), 1);
    assert_eq!(response.records[0].rtype, DnsRecordType::Unknown(65000));
    assert!(matches!(response.records[0].data, DnsRecordData::Raw(_)));
}

#[cfg_attr(test, test_case)]
pub fn test_build_prioritized_server_list_ipv4_then_ipv6() {
    let v4_1 = Ipv4Address::from_octets(1, 1, 1, 1);
    let v4_2 = Ipv4Address::from_octets(8, 8, 8, 8);
    let v6_1 = Ipv6Address::new([0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let v6_2 = Ipv6Address::new([0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let prioritized = DnsClient::build_prioritized_server_list(&[v4_1, v4_2], &[v6_1, v6_2]);
    assert_eq!(
        prioritized,
        vec![
            DnsServerAddr::V4(v4_1),
            DnsServerAddr::V4(v4_2),
            DnsServerAddr::V6(v6_1),
            DnsServerAddr::V6(v6_2),
        ]
    );
}

#[cfg_attr(test, test_case)]
pub fn test_ptr_ipv4_query_name() {
    let ip = Ipv4Address::from_octets(1, 2, 3, 4);
    assert_eq!(
        DnsClient::ptr_ipv4_query_name(ip).as_str(),
        "4.3.2.1.in-addr.arpa"
    );
}

#[cfg_attr(test, test_case)]
pub fn test_ptr_ipv6_query_name() {
    let ip = Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        DnsClient::ptr_ipv6_query_name(ip).as_str(),
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    );
}

#[cfg_attr(test, test_case)]
pub fn test_resolve_txt_from_records_filters_name() {
    let client = DnsClient::new(100);
    let records = vec![
        DnsRecordMeta {
            name: dns_name_view("example.com"),
            rtype: DnsRecordType::Known(DnsQueryType::TXT),
            rclass: DnsQueryClass::IN,
            ttl: 60,
            data: DnsRecordData::TXT(dns_txt_view("v=spf1 -all")),
        },
        DnsRecordMeta {
            name: dns_name_view("other.example.com"),
            rtype: DnsRecordType::Known(DnsQueryType::TXT),
            rclass: DnsQueryClass::IN,
            ttl: 60,
            data: DnsRecordData::TXT(dns_txt_view("not-target")),
        },
    ];

    let txt = client.resolve_txt_from_records(&records, "example.com");
    assert_eq!(txt.len(), 1);
    assert_eq!(txt[0].to_owned_string(), "v=spf1 -all");
}

#[cfg_attr(test, test_case)]
pub fn test_resolve_mx_from_records_returns_structs() {
    let client = DnsClient::new(100);
    let records = vec![DnsRecordMeta {
        name: dns_name_view("example.com"),
        rtype: DnsRecordType::Known(DnsQueryType::MX),
        rclass: DnsQueryClass::IN,
        ttl: 120,
        data: DnsRecordData::MX(10, dns_name_view("mail.example.com")),
    }];

    let mx = client.resolve_mx_from_records(&records, "example.com");
    assert_eq!(mx.len(), 1);
    assert_eq!(mx[0].preference, 10);
    assert_eq!(mx[0].exchange.to_owned_string(), "mail.example.com");
}

#[cfg_attr(test, test_case)]
pub fn test_resolve_srv_from_records_returns_structs() {
    let client = DnsClient::new(100);
    let records = vec![DnsRecordMeta {
        name: dns_name_view("_sip._tcp.example.com"),
        rtype: DnsRecordType::Known(DnsQueryType::SRV),
        rclass: DnsQueryClass::IN,
        ttl: 120,
        data: DnsRecordData::SRV {
            priority: 10,
            weight: 5,
            port: 5060,
            target: dns_name_view("sip1.example.com"),
        },
    }];

    let srv = client.resolve_srv_from_records(&records, "_sip._tcp.example.com");
    assert_eq!(srv.len(), 1);
    assert_eq!(srv[0].priority, 10);
    assert_eq!(srv[0].weight, 5);
    assert_eq!(srv[0].port, 5060);
    assert_eq!(srv[0].target.to_owned_string(), "sip1.example.com");
}

#[cfg_attr(test, test_case)]
pub fn test_resolve_ptr_from_records_follows_cname_chain() {
    let client = DnsClient::new(100);
    let query = "4.3.2.1.in-addr.arpa";
    let alias = "ptr-alias.example.com";
    let host = "host.example.com";

    let records = vec![
        DnsRecordMeta {
            name: dns_name_view(query),
            rtype: DnsRecordType::Known(DnsQueryType::CNAME),
            rclass: DnsQueryClass::IN,
            ttl: 60,
            data: DnsRecordData::Name(dns_name_view(alias)),
        },
        DnsRecordMeta {
            name: dns_name_view(alias),
            rtype: DnsRecordType::Known(DnsQueryType::PTR),
            rclass: DnsQueryClass::IN,
            ttl: 60,
            data: DnsRecordData::Name(dns_name_view(host)),
        },
    ];

    let resolved = client
        .resolve_ptr_from_records(&records, query)
        .expect("ptr should resolve");
    assert_eq!(resolved.to_owned_string(), host);
}

#[cfg_attr(test, test_case)]
pub fn test_resolve_ptr_ipv6_from_records_follows_cname_chain() {
    let client = DnsClient::new(100);
    let ip = Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let query = DnsClient::ptr_ipv6_query_name(ip);
    let alias = "ptr6-alias.example.com";
    let host = "host6.example.com";

    let records = vec![
        DnsRecordMeta {
            name: dns_name_view(query.as_str()),
            rtype: DnsRecordType::Known(DnsQueryType::CNAME),
            rclass: DnsQueryClass::IN,
            ttl: 60,
            data: DnsRecordData::Name(dns_name_view(alias)),
        },
        DnsRecordMeta {
            name: dns_name_view(alias),
            rtype: DnsRecordType::Known(DnsQueryType::PTR),
            rclass: DnsQueryClass::IN,
            ttl: 60,
            data: DnsRecordData::Name(dns_name_view(host)),
        },
    ];

    let resolved = client
        .resolve_ptr_from_records(&records, query.as_str())
        .expect("ptr6 should resolve");
    assert_eq!(resolved.to_owned_string(), host);
}
