use super::*;

#[cfg_attr(test, test_case)]
pub fn test_ipv4_address() {
    eprintln!("[TEST] Running test_ipv4_address...");
    let addr = Ipv4Address::from_octets(192, 168, 1, 1);
    assert!(addr.is_private());
    assert!(!addr.is_loopback());

    assert!(Ipv4Address::LOOPBACK.is_loopback());
    assert!(Ipv4Address::BROADCAST.is_broadcast());
}

#[cfg_attr(test, test_case)]
pub fn test_subnet() {
    let addr1 = Ipv4Address::from_octets(192, 168, 1, 1);
    let addr2 = Ipv4Address::from_octets(192, 168, 1, 100);
    let mask = Ipv4Address::from_octets(255, 255, 255, 0);

    assert!(addr1.same_subnet(&addr2, mask));
}

#[cfg_attr(test, test_case)]
pub fn test_fragment_key() {
    let header = Ipv4Header {
        version_ihl: 0x45,
        dscp_ecn: 0,
        total_length: [0, 40],
        identification: [0x12, 0x34],
        flags_fragment: [0x20, 0x00], // More Fragments
        ttl: 64,
        protocol: 6, // TCP
        checksum: [0, 0],
        src_addr: [192, 168, 1, 1],
        dst_addr: [192, 168, 1, 2],
    };

    let key = FragmentKey::from_header(&header);
    assert_eq!(key.id, 0x1234);
    assert_eq!(key.src, Ipv4Address::from_octets(192, 168, 1, 1));
    assert_eq!(key.dst, Ipv4Address::from_octets(192, 168, 1, 2));
    assert_eq!(key.protocol, 6);
}

#[cfg_attr(test, test_case)]
pub fn test_fragment_buffer_basic() {
    let buffer = FragmentBuffer::new(0);
    assert!(!buffer.is_complete());
    assert!(!buffer.is_expired(1000));
    assert!(buffer.is_expired(FragmentBuffer::TIMEOUT_MS + 1000));
}

#[cfg_attr(test, test_case)]
pub fn test_fragment_reassembly_simple() {
    let mut reassembler = FragmentReassembler::new(16);

    // First fragment (offset 0, more fragments)
    let header1 = Ipv4Header {
        version_ihl: 0x45,
        dscp_ecn: 0,
        total_length: [0, 28], // 20 + 8 bytes payload
        identification: [0x00, 0x01],
        flags_fragment: [0x20, 0x00], // MF=1, offset=0
        ttl: 64,
        protocol: 17, // UDP
        checksum: [0, 0],
        src_addr: [10, 0, 0, 1],
        dst_addr: [10, 0, 0, 2],
    };
    let payload1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let h1_data = crate::util::struct_as_bytes(&header1);

    let result = reassembler.process_fragment(&header1, h1_data, &payload1, None, 0);
    assert!(result.0.is_none()); // Not complete yet

    // Second fragment (offset 8, last fragment)
    let header2 = Ipv4Header {
        version_ihl: 0x45,
        dscp_ecn: 0,
        total_length: [0, 28],
        identification: [0x00, 0x01],
        flags_fragment: [0x00, 0x01], // MF=0, offset=8/8=1
        ttl: 64,
        protocol: 17,
        checksum: [0, 0],
        src_addr: [10, 0, 0, 1],
        dst_addr: [10, 0, 0, 2],
    };
    let payload2 = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let h2_data = crate::util::struct_as_bytes(&header2);

    let result = reassembler.process_fragment(&header2, h2_data, &payload2, None, 0);
    assert!(result.0.is_some()); // Complete!

    let reassembled = result.0.unwrap();
    let bytes = crate::net::payload::PacketPayloadView::new(&reassembled)
        .read_vec(0, reassembled.total_len());
    assert!(bytes.len() >= 36); // 20 header + 16 payload
}

#[cfg_attr(test, test_case)]
pub fn test_fragment_reassembly_returns_payload_chain() {
    let mut reassembler = FragmentReassembler::new(16);

    let header1 = Ipv4Header {
        version_ihl: 0x45,
        dscp_ecn: 0,
        total_length: [0, 28],
        identification: [0x00, 0x77],
        flags_fragment: [0x20, 0x00],
        ttl: 64,
        protocol: 17,
        checksum: [0, 0],
        src_addr: [10, 1, 0, 1],
        dst_addr: [10, 1, 0, 2],
    };
    let payload1 = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
    let h1_data = crate::util::struct_as_bytes(&header1);
    let packet1 = kernel_api::resource::net::PacketRef::from_vec(payload1.to_vec());
    let result = reassembler.process_fragment(&header1, h1_data, &payload1, Some(packet1), 0);
    assert!(result.0.is_none());

    let header2 = Ipv4Header {
        version_ihl: 0x45,
        dscp_ecn: 0,
        total_length: [0, 28],
        identification: [0x00, 0x77],
        flags_fragment: [0x00, 0x01],
        ttl: 64,
        protocol: 17,
        checksum: [0, 0],
        src_addr: [10, 1, 0, 1],
        dst_addr: [10, 1, 0, 2],
    };
    let payload2 = [0x05, 0x06, 0x07, 0x08, 0xaa, 0xbb, 0xcc, 0xdd];
    let h2_data = crate::util::struct_as_bytes(&header2);
    let packet2 = kernel_api::resource::net::PacketRef::from_vec(payload2.to_vec());
    let result = reassembler.process_fragment(&header2, h2_data, &payload2, Some(packet2), 0);
    let payload = result.0.expect("reassembly should complete");

    match &payload {
        kernel_api::resource::net::PacketPayload::Chain(chain) => {
            assert_eq!(chain.segments().len(), 3);
            assert_eq!(chain.segments()[0].len(), Ipv4Header::MIN_SIZE);
            assert_eq!(chain.segments()[1].data(), &payload1);
            assert_eq!(chain.segments()[2].data(), &payload2);
        }
        other => panic!(
            "expected payload chain, got {:?}",
            core::mem::discriminant(other)
        ),
    }

    let bytes =
        crate::net::payload::PacketPayloadView::new(&payload).read_vec(0, payload.total_len());
    assert_eq!(
        bytes.len(),
        Ipv4Header::MIN_SIZE + payload1.len() + payload2.len()
    );
    assert_eq!(
        &bytes[Ipv4Header::MIN_SIZE..Ipv4Header::MIN_SIZE + payload1.len()],
        &payload1
    );
    assert_eq!(&bytes[Ipv4Header::MIN_SIZE + payload1.len()..], &payload2);
}

#[cfg_attr(test, test_case)]
pub fn test_pmtu_cache_basic() {
    let mut cache = PmtuCache::new(256);
    let dst = Ipv4Address::from_octets(192, 168, 1, 100);
    let current_time = 0u64;

    // Initial lookup returns default MTU (cache miss)
    assert_eq!(cache.get(dst, current_time), PmtuEntry::DEFAULT_MTU);

    // Update PMTU
    cache.update(dst, 1400, current_time);

    // Now lookup should return the updated value
    assert_eq!(cache.get(dst, current_time), 1400);

    // After timeout, entry expires and returns default MTU
    let after_timeout = current_time + PmtuEntry::TIMEOUT_MS + 1;
    assert_eq!(cache.get(dst, after_timeout), PmtuEntry::DEFAULT_MTU);
}

#[cfg_attr(test, test_case)]
pub fn test_pmtu_cache_update_smaller() {
    let mut cache = PmtuCache::new(256);
    let dst = Ipv4Address::from_octets(10, 0, 0, 1);
    let current_time = 0u64;

    // Set initial PMTU
    cache.update(dst, 1400, current_time);
    assert_eq!(cache.get(dst, current_time), 1400);

    // Smaller PMTU should replace
    cache.update(dst, 1200, current_time + 100);
    assert_eq!(cache.get(dst, current_time + 100), 1200);
}

#[cfg_attr(test, test_case)]
pub fn test_pmtu_cache_minimum() {
    let mut cache = PmtuCache::new(256);
    let dst = Ipv4Address::from_octets(8, 8, 8, 8);

    // Very small MTU should be clamped to minimum
    cache.update(dst, 100, 0);
    assert_eq!(cache.get(dst, 0), PmtuEntry::MIN_MTU);
}

// Additional tests for fragmentation edge cases

#[cfg_attr(test, test_case)]
pub fn test_fragment_overflow_rejected() {
    let mut buffer = FragmentBuffer::new(0);
    let header = Ipv4Header {
        version_ihl: 0x45,
        dscp_ecn: 0,
        total_length: [0, 0],
        identification: [0, 0],
        flags_fragment: [0x20, 0x00], // MF=1, offset=0
        ttl: 64,
        protocol: 17,
        checksum: [0, 0],
        src_addr: [10, 0, 0, 1],
        dst_addr: [10, 0, 0, 2],
    };
    // construct payload length that causes overflow
    let payload = vec![0u8; (FragmentBuffer::MAX_DATAGRAM_SIZE + 1) as usize];
    // fragment_offset bytes = 0
    assert!(
        !buffer.add_fragment(&header, &payload, None, 0),
        "overflow should be rejected"
    );
}

#[cfg_attr(test, test_case)]
pub fn test_fragment_overlap_detection() {
    let mut reassembler = FragmentReassembler::new(4);

    let hdr1 = Ipv4Header {
        version_ihl: 0x45,
        dscp_ecn: 0,
        total_length: [0, 40],
        identification: [0, 1],
        flags_fragment: [0x20, 0x00], // MF=1, offset=0
        ttl: 64,
        protocol: 6,
        checksum: [0, 0],
        src_addr: [1, 1, 1, 1],
        dst_addr: [2, 2, 2, 2],
    };
    let p1 = [0u8; 8];
    let h1_data = crate::util::struct_as_bytes(&hdr1);
    let result = reassembler.process_fragment(&hdr1, h1_data, &p1, None, 0);
    assert!(result.0.is_none());

    // second fragment overlaps first (offset 0)
    let hdr2 = Ipv4Header {
        flags_fragment: [0x00, 0x00],
        ..hdr1
    };
    // offset field still 0 (means overlap)
    let p2 = [0u8; 8];
    let h2_data = crate::util::struct_as_bytes(&hdr2);
    let result2 = reassembler.process_fragment(&hdr2, h2_data, &p2, None, 0);
    // reassembler should drop buffer and return None
    assert!(result2.0.is_none());
    // buffer map should be empty now
    assert_eq!(reassembler.active_buffers(), 0);
}

#[cfg_attr(test, test_case)]
pub fn test_fragment_hole_exhaustion() {
    let mut buffer = FragmentBuffer::new(0);
    // artificially create many non-adjacent fragments to grow holes
    for i in 0..(FragmentBuffer::MAX_HOLES + 5) {
        let offset = (i as u16) * 8 + 1000;
        let mut hdr = Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: [0, 20],
            identification: [0, 2],
            flags_fragment: [0x20, 0x00],
            ttl: 64,
            protocol: 6,
            checksum: [0, 0],
            src_addr: [3, 3, 3, 3],
            dst_addr: [4, 4, 4, 4],
        };
        // manually set fragment offset field (bytes 6-7)
        let off_val = offset / 8;
        hdr.flags_fragment = [
            (hdr.flags_fragment[0] & 0xE0) | ((off_val >> 8) as u8),
            off_val as u8,
        ];
        let payload = [0u8; 8];
        let accepted = buffer.add_fragment(&hdr, &payload, None, 0);
        if i as usize > FragmentBuffer::MAX_HOLES {
            assert!(!accepted, "should start rejecting after hole limit");
            break;
        }
    }
}

#[cfg_attr(test, test_case)]
pub fn test_fragment_with_options_vulnerability_fixed() {
    let mut reassembler = FragmentReassembler::new(16);

    // First fragment with IHL=6 (24 bytes).
    let header1 = Ipv4Header {
        version_ihl: 0x46, // IHL=6 (24 bytes)
        dscp_ecn: 0,
        total_length: [0, 32], // 24 header + 8 bytes payload
        identification: [0x00, 0x01],
        flags_fragment: [0x20, 0x00], // MF=1, offset=0
        ttl: 64,
        protocol: 17, // UDP
        checksum: [0, 0],
        src_addr: [10, 0, 0, 1],
        dst_addr: [10, 0, 0, 2],
    };
    // Full 24-byte header data
    let mut h1_full = Vec::new();
    h1_full.extend_from_slice(crate::util::struct_as_bytes(&header1));
    h1_full.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]); // 4 bytes of options

    let payload1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let result = reassembler.process_fragment(&header1, &h1_full, &payload1, None, 0);
    assert!(result.0.is_none());

    // Second fragment (offset 8, last fragment)
    let header2 = Ipv4Header {
        version_ihl: 0x46,
        dscp_ecn: 0,
        total_length: [0, 32],
        identification: [0x00, 0x01],
        flags_fragment: [0x00, 0x01], // MF=0, offset=8/8=1
        ttl: 64,
        protocol: 17,
        checksum: [0, 0],
        src_addr: [10, 0, 0, 1],
        dst_addr: [10, 0, 0, 2],
    };
    let payload2 = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let h2_data = crate::util::struct_as_bytes(&header2);

    let result = reassembler.process_fragment(&header2, h2_data, &payload2, None, 0);
    assert!(result.0.is_some());

    let reassembled = result.0.unwrap();

    // Parse the reassembled packet
    let reassembled_bytes = crate::net::payload::PacketPayloadView::new(&reassembled)
        .read_vec(0, reassembled.total_len());
    if let Some(packet) = Ipv4Packet::parse(&reassembled_bytes) {
        assert_eq!(packet.header().ihl(), 6);
        assert_eq!(packet.header().header_len(), 24);

        let payload = packet.payload();
        assert_eq!(payload.len(), 16, "Payload length should be 16");
        assert_eq!(payload[0], 0x01, "First byte of payload should be 0x01");
        assert_eq!(payload[15], 0x10, "Last byte of payload should be 0x10");
    } else {
        panic!("Reassembled packet could not be parsed");
    }
}

#[cfg_attr(test, test_case)]
pub fn test_ipv4_id_generation_unpredictability() {
    let mut processor = Ipv4Processor::new(Ipv4Config {
        address: Ipv4Address::new([10, 0, 0, 1]),
        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
        gateway: Ipv4Address::ANY,
        dns: None,
    });

    let dst1 = Ipv4Address::new([192, 168, 1, 1]);
    let dst2 = Ipv4Address::new([192, 168, 1, 2]);

    let id1_a = processor.next_id(dst1);
    let id1_b = processor.next_id(dst1);
    let id2_a = processor.next_id(dst2);

    // Verify IDs are different
    assert_ne!(id1_a, id1_b);
    assert_ne!(id1_a, id2_a);

    // In our new secure implementation, the difference between consecutive IDs
    // for the same destination should not be a constant small increment (like 1 or 2).
    // It's technically possible but very unlikely to be 1 or 2 due to the hash.
    let diff = id1_b.wrapping_sub(id1_a);
    // Since we're using a hash, any diff is possible, but it shouldn't be
    // consistently small across many calls.
    // This is a weak test but it confirms the code runs and produces non-obvious output.
    assert!(diff > 2 || diff == 0); // Very basic check
}
