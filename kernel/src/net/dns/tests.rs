use super::*;
use crate::sync::set_panicking;

#[cfg_attr(test, test_case)]
pub fn test_primary_server_poisoned_returns_none() {
    let client = DnsClient::new(100);
    {
        let mut s = client.servers.lock().unwrap();
        s.push(Ipv4Address::from_octets(1, 2, 3, 4));
    }
    set_panicking(true);
    assert_eq!(client.primary_server(), None);
    set_panicking(false);
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
    let mut buffer = [0u8; 256];
    
    let len = client.build_tcp_query(&mut buffer, "example.com", DnsQueryType::A).unwrap();
    
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
