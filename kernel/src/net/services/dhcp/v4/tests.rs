use super::*;
use crate::sync::set_panicking;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

fn dhcp_options_contain(opts_with_cookie: &[u8], target: DhcpOption) -> bool {
    let mut i = if opts_with_cookie.starts_with(&DHCP_MAGIC_COOKIE) {
        4
    } else {
        0
    };
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while i < opts_with_cookie.len() {
        let code = opts_with_cookie[i];
        if code == DhcpOption::End as u8 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        if i + 1 >= opts_with_cookie.len() {
            break;
        }
        let len = opts_with_cookie[i + 1] as usize;
        if code == target as u8 {
            return true;
        }
        i = i.saturating_add(2 + len);
    }
    false
}

#[cfg_attr(test, test_case)]
pub fn test_check_timeout_poisoned_state_reset_skips() {
    let client = DhcpClient::new(crate::net::l2::ethernet::MacAddress::ZERO);
    {
        let mut s = client.state.lock().unwrap();
        *s = DhcpState::Selecting;
    }
    client.state_time.store(0, Ordering::SeqCst);
    client
        .retry_count
        .store(DhcpClient::MAX_RETRIES - 1, Ordering::SeqCst);

    set_panicking(true);
    // Should not panic even if state lock is poisoned
    let _ = crate::task::block_on(client.check_timeout(10, 1));
    set_panicking(false);
}

#[cfg_attr(test, test_case)]
pub fn test_dhcp_header_encode_into_serializes_network_order_bytes() {
    let header = DhcpHeader {
        op: DhcpOperation::Request as u8,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: 0x1122_3344u32.to_be_bytes(),
        secs: 0x5566u16.to_be_bytes(),
        flags: 0x7788u16.to_be_bytes(),
        ciaddr: [1, 2, 3, 4],
        yiaddr: [5, 6, 7, 8],
        siaddr: [9, 10, 11, 12],
        giaddr: [13, 14, 15, 16],
        chaddr: [0xAA; 16],
        sname: [0xBB; 64],
        file: [0xCC; 128],
    };

    let mut buf = vec![0u8; DhcpHeader::SIZE];
    header
        .encode_into(&mut buf)
        .expect("encode_into should succeed");

    assert_eq!(buf.len(), DhcpHeader::SIZE);
    assert_eq!(&buf[0..4], &[DhcpOperation::Request as u8, 1, 6, 0]);
    assert_eq!(&buf[4..8], &0x1122_3344u32.to_be_bytes());
    assert_eq!(&buf[8..10], &0x5566u16.to_be_bytes());
    assert_eq!(&buf[10..12], &0x7788u16.to_be_bytes());
    assert_eq!(&buf[12..16], &[1, 2, 3, 4]);
    assert_eq!(&buf[28..44], &[0xAA; 16]);
    assert_eq!(&buf[44..108], &[0xBB; 64]);
    assert_eq!(&buf[108..236], &[0xCC; 128]);
}

#[cfg_attr(test, test_case)]
pub fn test_build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip() {
    let client = DhcpClient::new(crate::net::l2::ethernet::MacAddress::ZERO);

    let lease = DhcpLease {
        ip_address: Ipv4Address::new([192, 168, 0, 42]),
        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
        gateway: Some(Ipv4Address::new([192, 168, 0, 1])),
        dns_servers: Vec::new(),
        server_ip: Ipv4Address::new([192, 168, 0, 1]),
        lease_time: 3600,
        t1: 1800,
        t2: 3150,
        obtained_at: 0,
        hostname: None,
        domain_name: None,
    };

    {
        let mut l = client.lease.lock().unwrap();
        *l = Some(lease.clone());
    }
    {
        let mut s = client.state.lock().unwrap();
        *s = DhcpState::Renewing;
    }

    let mut buf = vec![0u8; 512];
    let len = client
        .build_request(&mut buf, 123)
        .expect("build_request failed");

    // ciaddr should be set to the current IP
    assert_eq!(&buf[12..16], lease.ip_address.as_bytes());

    // Options area should NOT include Server Identifier or Requested IP for renewal
    let opts = &buf[DhcpHeader::SIZE..len];
    assert!(!dhcp_options_contain(opts, DhcpOption::ServerIdentifier));
    assert!(!dhcp_options_contain(opts, DhcpOption::RequestedIp));
}

#[cfg_attr(test, test_case)]
pub fn test_build_request_requesting_includes_serverid_and_requestedip() {
    let client = DhcpClient::new(crate::net::l2::ethernet::MacAddress::ZERO);

    let offered = DhcpLease {
        ip_address: Ipv4Address::new([10, 0, 0, 5]),
        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
        gateway: Some(Ipv4Address::new([10, 0, 0, 1])),
        dns_servers: Vec::new(),
        server_ip: Ipv4Address::new([10, 0, 0, 1]),
        lease_time: 3600,
        t1: 1800,
        t2: 3150,
        obtained_at: 0,
        hostname: None,
        domain_name: None,
    };

    {
        let mut o = client.offered_lease.lock().unwrap();
        *o = Some(offered.clone());
    }
    {
        let mut s = client.state.lock().unwrap();
        *s = DhcpState::Requesting;
    }

    let mut buf = vec![0u8; 512];
    let len = client
        .build_request(&mut buf, 42)
        .expect("build_request failed");
    let opts = &buf[DhcpHeader::SIZE..len];
    assert!(dhcp_options_contain(opts, DhcpOption::ServerIdentifier));
    assert!(dhcp_options_contain(opts, DhcpOption::RequestedIp));
}

#[cfg_attr(test, test_case)]
pub fn test_build_discover_reuse_xid_on_retransmit() {
    let client = DhcpClient::new(crate::net::l2::ethernet::MacAddress::ZERO);

    // Pre-set XID and state to Selecting (retransmit scenario)
    client.xid.store(0x1234_5678, Ordering::SeqCst);
    {
        let mut s = client.state.lock().unwrap();
        *s = DhcpState::Selecting;
    }

    let mut buf1 = vec![0u8; 512];
    let _ = client
        .build_discover(&mut buf1, 10)
        .expect("build_discover failed");
    let xid1 = u32::from_be_bytes(buf1[4..8].try_into().unwrap());
    assert_eq!(xid1, 0x1234_5678);

    let mut buf2 = vec![0u8; 512];
    let _ = client
        .build_discover(&mut buf2, 20)
        .expect("build_discover failed");
    let xid2 = u32::from_be_bytes(buf2[4..8].try_into().unwrap());
    assert_eq!(xid2, 0x1234_5678);
}

#[cfg_attr(test, test_case)]
pub fn test_build_discover_state_lock_poison_returns_err() {
    let client = DhcpClient::new(crate::net::l2::ethernet::MacAddress::ZERO);

    // Poison the state lock by dropping a guard while marked as panicking
    {
        let g = client.state.lock().unwrap();
        set_panicking(true);
        drop(g); // dropping while panicking should poison
        set_panicking(false);
    }

    let mut buf = vec![0u8; 512];
    assert!(client.build_discover(&mut buf, 100).is_err());
}

#[cfg_attr(test, test_case)]
pub fn test_process_response_chaddr_mismatch() {
    use crate::net::l2::ethernet::MacAddress;

    let client = DhcpClient::new(MacAddress::new([1, 2, 3, 4, 5, 6]));
    client.xid.store(0x1234_5678, Ordering::SeqCst);

    let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
    buf[0] = DhcpOperation::Reply as u8;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    buf[16..20].copy_from_slice(&[10, 0, 0, 5]); // yiaddr
    buf[20..24].copy_from_slice(&[192, 168, 0, 1]); // siaddr
    // CHADDR does not match client MAC
    buf[28..34].copy_from_slice(&[7, 7, 7, 7, 7, 7]);

    let mut offset = DhcpHeader::SIZE;
    buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    offset += 4;

    buf[offset] = DhcpOption::MessageType as u8;
    buf[offset + 1] = 1;
    buf[offset + 2] = DhcpMessageType::Offer as u8;
    offset += 3;

    buf[offset] = DhcpOption::ServerIdentifier as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&[192, 168, 0, 1]);
    offset += 6;
    buf[offset] = DhcpOption::End as u8;

    assert!(client.process_response(&buf, 100).is_err());
}

#[cfg_attr(test, test_case)]
pub fn test_process_response_offer_missing_serverid_returns_err() {
    use crate::net::l2::ethernet::MacAddress;

    let client = DhcpClient::new(MacAddress::new([1, 2, 3, 4, 5, 6]));
    client.xid.store(0x2222_3333, Ordering::SeqCst);

    let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
    buf[0] = DhcpOperation::Reply as u8;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&0x2222_3333u32.to_be_bytes());
    buf[16..20].copy_from_slice(&[10, 0, 0, 5]); // yiaddr
    buf[28..34].copy_from_slice(client.mac_address.as_bytes());

    let mut offset = DhcpHeader::SIZE;
    buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    offset += 4;

    buf[offset] = DhcpOption::MessageType as u8;
    buf[offset + 1] = 1;
    buf[offset + 2] = DhcpMessageType::Offer as u8;
    offset += 3;

    // No Server Identifier option
    buf[offset] = DhcpOption::End as u8;

    assert!(client.process_response(&buf, 200).is_err());
}

#[cfg_attr(test, test_case)]
pub fn test_process_response_siaddr_serverid_mismatch() {
    use crate::net::l2::ethernet::MacAddress;

    let client = DhcpClient::new(MacAddress::new([1, 2, 3, 4, 5, 6]));
    client.xid.store(0x4444_5555, Ordering::SeqCst);

    let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
    buf[0] = DhcpOperation::Reply as u8;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&0x4444_5555u32.to_be_bytes());
    buf[16..20].copy_from_slice(&[10, 0, 0, 5]); // yiaddr
    buf[20..24].copy_from_slice(&[192, 168, 0, 5]); // siaddr
    buf[28..34].copy_from_slice(client.mac_address.as_bytes());

    let mut offset = DhcpHeader::SIZE;
    buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    offset += 4;

    buf[offset] = DhcpOption::MessageType as u8;
    buf[offset + 1] = 1;
    buf[offset + 2] = DhcpMessageType::Offer as u8;
    offset += 3;

    // Server Identifier different from siaddr
    buf[offset] = DhcpOption::ServerIdentifier as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&[192, 168, 0, 1]);
    offset += 6;
    buf[offset] = DhcpOption::End as u8;

    assert!(client.process_response(&buf, 300).is_err());
}

#[cfg_attr(test, test_case)]
pub fn test_process_response_ack_requesting_mismatch() {
    use crate::net::l2::ethernet::MacAddress;

    let client = DhcpClient::new(MacAddress::new([8, 8, 8, 8, 8, 8]));
    client.xid.store(0x6666_7777, Ordering::SeqCst);

    // Offered lease does not match incoming ACK server identifier
    let offered = DhcpLease {
        ip_address: Ipv4Address::new([10, 0, 0, 5]),
        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
        gateway: Some(Ipv4Address::new([10, 0, 0, 1])),
        dns_servers: Vec::new(),
        server_ip: Ipv4Address::new([10, 0, 0, 1]),
        lease_time: 3600,
        t1: 1800,
        t2: 3150,
        obtained_at: 0,
        hostname: None,
        domain_name: None,
    };

    {
        let mut o = client.offered_lease.lock().unwrap();
        *o = Some(offered.clone());
    }
    {
        let mut s = client.state.lock().unwrap();
        *s = DhcpState::Requesting;
    }

    let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
    buf[0] = DhcpOperation::Reply as u8;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&0x6666_7777u32.to_be_bytes());
    buf[16..20].copy_from_slice(&[10, 0, 0, 5]); // yiaddr matches offered
    buf[28..34].copy_from_slice(client.mac_address.as_bytes());

    let mut offset = DhcpHeader::SIZE;
    buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    offset += 4;

    buf[offset] = DhcpOption::MessageType as u8;
    buf[offset + 1] = 1;
    buf[offset + 2] = DhcpMessageType::Ack as u8; // ACK comes from different server
    offset += 3;

    // Server Identifier that does NOT match offered.server_ip
    buf[offset] = DhcpOption::ServerIdentifier as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&[10, 0, 0, 2]);
    offset += 6;
    buf[offset] = DhcpOption::End as u8;

    assert!(client.process_response(&buf, 400).is_err());
}

#[cfg_attr(test, test_case)]
pub fn test_process_response_ack_renewal_success() {
    use crate::net::l2::ethernet::MacAddress;

    let client = DhcpClient::new(MacAddress::new([9, 9, 9, 9, 9, 9]));
    client.xid.store(0x9999_aaaa, Ordering::SeqCst);

    let lease = DhcpLease {
        ip_address: Ipv4Address::new([192, 168, 0, 42]),
        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
        gateway: Some(Ipv4Address::new([192, 168, 0, 1])),
        dns_servers: Vec::new(),
        server_ip: Ipv4Address::new([192, 168, 0, 1]),
        lease_time: 3600,
        t1: 1800,
        t2: 3150,
        obtained_at: 0,
        hostname: None,
        domain_name: None,
    };

    {
        let mut l = client.lease.lock().unwrap();
        *l = Some(lease.clone());
    }
    {
        let mut s = client.state.lock().unwrap();
        *s = DhcpState::Renewing;
    }

    // Build ACK matching current lease
    let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
    buf[0] = DhcpOperation::Reply as u8;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&0x9999_aaaau32.to_be_bytes());
    buf[16..20].copy_from_slice(lease.ip_address.as_bytes()); // yiaddr
    buf[28..34].copy_from_slice(client.mac_address.as_bytes());

    let mut offset = DhcpHeader::SIZE;
    buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    offset += 4;

    buf[offset] = DhcpOption::MessageType as u8;
    buf[offset + 1] = 1;
    buf[offset + 2] = DhcpMessageType::Ack as u8;
    offset += 3;

    buf[offset] = DhcpOption::ServerIdentifier as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(lease.server_ip.as_bytes());
    offset += 6;
    buf[offset] = DhcpOption::End as u8;

    let res = client
        .process_response(&buf, 500)
        .expect("ACK should be accepted");
    match res {
        DhcpResponseResult::Ack(l) => {
            assert_eq!(l.ip_address, lease.ip_address);
        }
        _ => panic!("expected Ack"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_build_decline_and_build_release_contents() {
    use crate::net::l2::ethernet::MacAddress;

    let client = DhcpClient::new(MacAddress::new([1, 2, 3, 4, 5, 6]));
    client.xid.store(0xabab_cdef, Ordering::SeqCst);

    // build_decline
    let mut dbuf = [0u8; 512];
    let declined_ip = Ipv4Address::new([10, 0, 0, 99]);
    let server_ip = Some(Ipv4Address::new([10, 0, 0, 1]));
    let len = client
        .build_decline(&mut dbuf, declined_ip, server_ip, 0)
        .expect("build_decline failed");
    let opts = &dbuf[DhcpHeader::SIZE..len];
    // check MessageType Decline present
    assert!(
        opts.windows(3)
            .any(|w| w[0] == DhcpOption::MessageType as u8
                && w[1] == 1
                && w[2] == DhcpMessageType::Decline as u8)
    );
    // check Requested IP option present
    assert!(
        opts.windows(6)
            .any(|w| w[0] == DhcpOption::RequestedIp as u8
                && w[1] == 4
                && &w[2..6] == declined_ip.as_bytes())
    );
    // check Server Identifier present
    assert!(
        opts.windows(6)
            .any(|w| w[0] == DhcpOption::ServerIdentifier as u8
                && w[1] == 4
                && &w[2..6] == server_ip.unwrap().as_bytes())
    );

    // build_release
    let lease = DhcpLease {
        ip_address: Ipv4Address::new([172, 16, 0, 5]),
        subnet_mask: Ipv4Address::new([255, 255, 0, 0]),
        gateway: None,
        dns_servers: Vec::new(),
        server_ip: Ipv4Address::new([10, 0, 0, 1]),
        lease_time: 1200,
        t1: 600,
        t2: 900,
        obtained_at: 0,
        hostname: None,
        domain_name: None,
    };
    {
        let mut l = client.lease.lock().unwrap();
        *l = Some(lease.clone());
    }

    let mut rbuf = [0u8; 512];
    let rlen = client
        .build_release(&mut rbuf, 0)
        .expect("build_release failed");
    // ciaddr should be set
    assert_eq!(&rbuf[12..16], lease.ip_address.as_bytes());
    let ropts = &rbuf[DhcpHeader::SIZE..rlen];
    assert!(
        ropts
            .windows(3)
            .any(|w| w[0] == DhcpOption::MessageType as u8
                && w[1] == 1
                && w[2] == DhcpMessageType::Release as u8)
    );
    assert!(
        ropts
            .windows(6)
            .any(|w| w[0] == DhcpOption::ServerIdentifier as u8
                && w[1] == 4
                && &w[2..6] == lease.server_ip.as_bytes())
    );
}

#[cfg_attr(test, test_case)]
pub fn test_release_clears_lease_and_sets_last_released() {
    use crate::net::l2::ethernet::MacAddress;

    let client = DhcpClient::new(MacAddress::new([5, 5, 5, 5, 5, 5]));
    let lease = DhcpLease {
        ip_address: Ipv4Address::new([192, 168, 10, 10]),
        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
        gateway: None,
        dns_servers: Vec::new(),
        server_ip: Ipv4Address::new([10, 0, 0, 1]),
        lease_time: 3600,
        t1: 1800,
        t2: 3150,
        obtained_at: 0,
        hostname: None,
        domain_name: None,
    };
    {
        let mut l = client.lease.lock().unwrap();
        *l = Some(lease.clone());
    }
    {
        let mut s = client.state.lock().unwrap();
        *s = DhcpState::Bound;
    }

    // Call release (best-effort send) - should clear lease and set last_released
    client.release();
    assert!(client.lease.lock().unwrap().is_none());
    assert_eq!(client.last_released_ip(), Some(lease.ip_address));
}

#[cfg_attr(test, test_case)]
pub fn test_parse_t1_t2_and_timeout_transitions() {
    let client = DhcpClient::new(crate::net::l2::ethernet::MacAddress::ZERO);
    client.xid.store(0x1111_2222, Ordering::SeqCst);

    let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
    buf[0] = DhcpOperation::Reply as u8;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&0x1111_2222u32.to_be_bytes());
    buf[16..20].copy_from_slice(&[10, 0, 0, 8]); // yiaddr
    buf[28..34].copy_from_slice(client.mac_address.as_bytes());

    let mut offset = DhcpHeader::SIZE;
    buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    offset += 4;

    // Message Type: ACK
    buf[offset] = DhcpOption::MessageType as u8;
    buf[offset + 1] = 1;
    buf[offset + 2] = DhcpMessageType::Ack as u8;
    offset += 3;

    // Server Identifier
    buf[offset] = DhcpOption::ServerIdentifier as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&[10, 0, 0, 1]);
    offset += 6;

    // Lease Time
    buf[offset] = DhcpOption::LeaseTime as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&100u32.to_be_bytes());
    offset += 6;

    // Renewal (T1)
    buf[offset] = 58u8; // RenewalTime
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&30u32.to_be_bytes());
    offset += 6;

    // Rebinding (T2)
    buf[offset] = 59u8; // RebindingTime
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&60u32.to_be_bytes());
    offset += 6;
    buf[offset] = DhcpOption::End as u8;

    let res = client
        .process_response(&buf, 0)
        .expect("ACK should be accepted");
    match res {
        DhcpResponseResult::Ack(lease) => {
            assert_eq!(lease.lease_time, 100);
            assert_eq!(lease.t1, 30);
            assert_eq!(lease.t2, 60);

            // Verify T1 transition to Renewing
            {
                let mut s = client.state.lock().unwrap();
                *s = DhcpState::Bound;
            }
            client.lease.lock().unwrap().as_mut().unwrap().obtained_at = 0;
            // current_tick passes T1
            assert!(crate::task::block_on(client.check_timeout(31, 1)));
            assert_eq!(client.state(), DhcpState::Renewing);

            // advance past T2 -> Rebinding
            assert!(crate::task::block_on(client.check_timeout(61, 1)));
            assert_eq!(client.state(), DhcpState::Rebinding);
        }
        _ => panic!("expected Ack"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_build_lease_defaults_large_timers_without_overflow() {
    let header = DhcpHeader {
        op: DhcpOperation::Reply as u8,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: 0u32.to_be_bytes(),
        secs: 0u16.to_be_bytes(),
        flags: 0u16.to_be_bytes(),
        ciaddr: [0; 4],
        yiaddr: [10, 0, 0, 42],
        siaddr: [10, 0, 0, 1],
        giaddr: [0; 4],
        chaddr: [0; 16],
        sname: [0; 64],
        file: [0; 128],
    };
    let opts = ParsedOptions {
        message_type: Some(DhcpMessageType::Ack),
        subnet_mask: None,
        router: None,
        dns_servers: Vec::new(),
        lease_time: u32::MAX,
        renewal_time: None,
        rebinding_time: None,
        server_id: None,
        hostname: None,
        domain_name: None,
    };

    let lease = DhcpClient::build_lease(&header, opts, 123);

    assert_eq!(lease.lease_time, u32::MAX);
    assert_eq!(lease.t1, u32::MAX / 2);
    assert_eq!(lease.t2, ((u32::MAX as u64 * 7) / 8) as u32);
    assert_eq!(lease.ip_address, Ipv4Address::new([10, 0, 0, 42]));
    assert_eq!(lease.server_ip, Ipv4Address::new([10, 0, 0, 1]));
}

#[cfg_attr(test, test_case)]
pub fn test_offer_probe_and_decline_flow() {
    use crate::net::l2::ethernet::MacAddress;
    use crate::net::runtime::stack;

    // Initialize global stack for ARP facilities (best-effort)
    stack::init_in(
        crate::net::runtime::default_runtime(),
        stack::NetworkConfig::default(),
    );

    let client = DhcpClient::new(MacAddress::new([7, 7, 7, 7, 7, 7]));
    client.xid.store(0x3333_4444, Ordering::SeqCst);

    // Build an OFFER packet
    let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
    buf[0] = DhcpOperation::Reply as u8;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&0x3333_4444u32.to_be_bytes());
    buf[16..20].copy_from_slice(&[10, 0, 0, 9]); // yiaddr
    buf[28..34].copy_from_slice(client.mac_address.as_bytes());

    let mut offset = DhcpHeader::SIZE;
    buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    offset += 4;

    buf[offset] = DhcpOption::MessageType as u8;
    buf[offset + 1] = 1;
    buf[offset + 2] = DhcpMessageType::Offer as u8;
    offset += 3;

    // Server Identifier
    buf[offset] = DhcpOption::ServerIdentifier as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&[10, 0, 0, 1]);
    offset += 6;
    buf[offset] = DhcpOption::End as u8;

    // Process offer (should send ARP probe and set probe timestamp)
    let _ = client
        .process_response(&buf, 100)
        .expect("Offer should be processed");
    assert!(client.offered_lease.lock().unwrap().is_some());
    assert!(client.offered_probe_at.load(Ordering::SeqCst) != 0);

    // Simulate ARP reply from another host for the offered IP
    if let Ok(mut s) = stack::stack_in(crate::net::runtime::default_runtime()).lock() {
        if let Some(ref mut st) = s.as_mut() {
            st.arp_cache_insert(
                Ipv4Address::new([10, 0, 0, 9]),
                MacAddress::from_octets(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
                200,
            );
        }
    }

    // Advance time beyond PROBE_WAIT_SECS
    let _ = crate::task::block_on(client.check_timeout(200, 1));
    // Offer should have been cleared due to conflict
    assert!(client.offered_lease.lock().unwrap().is_none());
    // Decline should have been recorded
    assert_eq!(
        client.last_declined_ip(),
        Some(Ipv4Address::new([10, 0, 0, 9]))
    );
}

#[cfg_attr(test, test_case)]
pub fn test_drive_init_sends_discover_and_enters_selecting() {
    let client = DhcpClient::new(crate::net::l2::ethernet::MacAddress::ZERO);
    assert_eq!(client.state(), DhcpState::Init);
    crate::task::block_on(client.drive(123, 1)).expect("drive failed");
    assert_eq!(client.state(), DhcpState::Selecting);
}

#[cfg_attr(test, test_case)]
pub fn test_force_renew_or_restart_paths() {
    let client = DhcpClient::new(crate::net::l2::ethernet::MacAddress::ZERO);
    let lease = DhcpLease {
        ip_address: Ipv4Address::new([192, 168, 1, 10]),
        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
        gateway: Some(Ipv4Address::new([192, 168, 1, 1])),
        dns_servers: Vec::new(),
        server_ip: Ipv4Address::new([192, 168, 1, 1]),
        lease_time: 3600,
        t1: 1800,
        t2: 3150,
        obtained_at: 0,
        hostname: None,
        domain_name: None,
    };

    {
        let mut l = client.lease.lock().unwrap();
        *l = Some(lease);
    }
    {
        let mut s = client.state.lock().unwrap();
        *s = DhcpState::Bound;
    }
    client.force_renew_or_restart(100);
    assert_eq!(client.state(), DhcpState::Renewing);
    assert!(client.lease().is_some());

    {
        let mut s = client.state.lock().unwrap();
        *s = DhcpState::Requesting;
    }
    {
        let mut o = client.offered_lease.lock().unwrap();
        *o = Some(DhcpLease {
            ip_address: Ipv4Address::new([10, 0, 0, 5]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Some(Ipv4Address::new([10, 0, 0, 1])),
            dns_servers: Vec::new(),
            server_ip: Ipv4Address::new([10, 0, 0, 1]),
            lease_time: 1200,
            t1: 600,
            t2: 900,
            obtained_at: 0,
            hostname: None,
            domain_name: None,
        });
    }
    client.force_renew_or_restart(200);
    assert_eq!(client.state(), DhcpState::Init);
    assert!(client.lease().is_none());
    assert!(client.offered_lease.lock().unwrap().is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_build_inform_sets_ciaddr_and_message_type() {
    use crate::net::l2::ethernet::MacAddress;

    let client = DhcpClient::new(MacAddress::new([1, 1, 1, 1, 1, 1]));
    let lease = DhcpLease {
        ip_address: Ipv4Address::new([192, 168, 1, 77]),
        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
        gateway: Some(Ipv4Address::new([192, 168, 1, 1])),
        dns_servers: vec![Ipv4Address::new([1, 1, 1, 1])],
        server_ip: Ipv4Address::new([192, 168, 1, 1]),
        lease_time: 3600,
        t1: 1800,
        t2: 3150,
        obtained_at: 0,
        hostname: None,
        domain_name: None,
    };

    {
        let mut l = client.lease.lock().unwrap();
        *l = Some(lease.clone());
    }

    let mut buf = vec![0u8; DHCP_MAX_MESSAGE_SIZE];
    let len = client
        .build_inform(&mut buf, 123)
        .expect("build_inform failed");

    assert_eq!(&buf[12..16], lease.ip_address.as_bytes());

    let opts = &buf[DhcpHeader::SIZE..len];
    assert!(
        opts.windows(3)
            .any(|w| w[0] == DhcpOption::MessageType as u8
                && w[1] == 1
                && w[2] == DhcpMessageType::Inform as u8)
    );
    assert!(!dhcp_options_contain(opts, DhcpOption::RequestedIp));
}

#[cfg_attr(test, test_case)]
pub fn test_process_response_ack_informing_accepts_zero_yiaddr() {
    use crate::net::l2::ethernet::MacAddress;

    let client = DhcpClient::new(MacAddress::new([2, 2, 2, 2, 2, 2]));
    client.xid.store(0x4242_3535, Ordering::SeqCst);

    let lease = DhcpLease {
        ip_address: Ipv4Address::new([10, 0, 0, 42]),
        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
        gateway: Some(Ipv4Address::new([10, 0, 0, 1])),
        dns_servers: vec![Ipv4Address::new([8, 8, 8, 8])],
        server_ip: Ipv4Address::new([10, 0, 0, 1]),
        lease_time: 7200,
        t1: 3600,
        t2: 6300,
        obtained_at: 10,
        hostname: None,
        domain_name: None,
    };

    {
        let mut l = client.lease.lock().unwrap();
        *l = Some(lease.clone());
    }
    {
        let mut s = client.state.lock().unwrap();
        *s = DhcpState::Informing;
    }

    let mut buf = vec![0u8; DhcpHeader::SIZE + 64];
    buf[0] = DhcpOperation::Reply as u8;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&0x4242_3535u32.to_be_bytes());
    // INFORM ACK では yiaddr が 0 の場合がある
    buf[16..20].copy_from_slice(&[0, 0, 0, 0]);
    buf[28..34].copy_from_slice(client.mac_address.as_bytes());

    let mut offset = DhcpHeader::SIZE;
    buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    offset += 4;

    // Message Type: ACK
    buf[offset] = DhcpOption::MessageType as u8;
    buf[offset + 1] = 1;
    buf[offset + 2] = DhcpMessageType::Ack as u8;
    offset += 3;

    // Server Identifier
    buf[offset] = DhcpOption::ServerIdentifier as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(lease.server_ip.as_bytes());
    offset += 6;

    // DNS update in INFORM ACK
    buf[offset] = DhcpOption::DnsServer as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&[1, 1, 1, 1]);
    offset += 6;

    buf[offset] = DhcpOption::End as u8;

    let res = client
        .process_response(&buf, 999)
        .expect("INFORM ACK should be accepted");
    match res {
        DhcpResponseResult::Ack(updated) => {
            assert_eq!(updated.ip_address, lease.ip_address);
            assert_eq!(updated.lease_time, lease.lease_time);
            assert_eq!(updated.t1, lease.t1);
            assert_eq!(updated.t2, lease.t2);
            assert_eq!(updated.server_ip, lease.server_ip);
            assert_eq!(updated.dns_servers, vec![Ipv4Address::new([1, 1, 1, 1])]);
        }
        _ => panic!("expected Ack"),
    }

    assert_eq!(client.state(), DhcpState::Bound);
}

#[cfg_attr(test, test_case)]
pub fn test_inform_requires_active_lease() {
    use crate::net::l2::ethernet::MacAddress;

    let client = DhcpClient::new(MacAddress::new([3, 3, 3, 3, 3, 3]));
    assert!(client.inform(100).is_err());
    assert_eq!(client.state(), DhcpState::Init);
}
