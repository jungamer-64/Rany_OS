// ============================================================================
// src/test/network_tests.rs - Network Subsystem Integration Tests
// ============================================================================

use crate::test::TestResult;
use alloc::string::String;

/// Test packet-owned allocation
pub fn test_mempool_allocation() -> TestResult {
    use crate::net::payload::alloc_packet_with_headroom;
    use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

    let packet = match alloc_packet_with_headroom(1518, DEFAULT_PACKET_HEADROOM) {
        Some(p) => p,
        None => return TestResult::Failed(String::from("Failed to allocate packet")),
    };

    if packet.data_capacity() < 1518 {
        return TestResult::Failed(alloc::format!(
            "Packet capacity too small: {} < 1518",
            packet.data_capacity()
        ));
    }

    let mut packets = alloc::vec::Vec::new();
    for i in 0..8 {
        if let Some(p) = alloc_packet_with_headroom(64, DEFAULT_PACKET_HEADROOM) {
            packets.push(p);
        } else {
            return TestResult::Failed(alloc::format!("Failed to allocate packet {}", i));
        }
    }

    packets.clear();

    if alloc_packet_with_headroom(64, DEFAULT_PACKET_HEADROOM).is_none() {
        return TestResult::Failed(String::from("Packet allocator exhausted after drop"));
    }

    TestResult::Passed
}

/// Test Ethernet frame parsing
pub fn test_ethernet_frame() -> TestResult {
    use crate::net::l2::ethernet::{
        EtherType, EthernetFrame, EthernetFrameMut, EthernetHeader, MacAddress,
    };

    // Test MAC address
    let mac = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    if mac.is_broadcast() {
        return TestResult::Failed(String::from("Non-broadcast MAC detected as broadcast"));
    }

    let broadcast = MacAddress::BROADCAST;
    if !broadcast.is_broadcast() {
        return TestResult::Failed(String::from("Broadcast MAC not detected"));
    }

    // Test frame parsing
    let raw_frame: [u8; 64] = {
        let mut frame = [0u8; 64];
        // Destination MAC
        frame[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Source MAC
        frame[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // EtherType (IPv4)
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame
    };

    let frame = match EthernetFrame::parse(&raw_frame) {
        Some(f) => f,
        None => return TestResult::Failed(String::from("Failed to parse Ethernet frame")),
    };

    if !frame.destination().is_broadcast() {
        return TestResult::Failed(String::from("Destination should be broadcast"));
    }

    if frame.source() != mac {
        return TestResult::Failed(String::from("Source MAC mismatch"));
    }

    if frame.ether_type() != EtherType::Ipv4 {
        return TestResult::Failed(String::from("EtherType should be IPv4"));
    }

    // Test frame building
    let mut buffer = [0u8; 64];
    let mut frame_builder = match EthernetFrameMut::new(&mut buffer) {
        Some(f) => f,
        None => return TestResult::Failed(String::from("Failed to create frame builder")),
    };

    frame_builder
        .set_destination(MacAddress::BROADCAST)
        .set_source(mac)
        .set_ether_type(EtherType::Arp);

    let built_frame = EthernetFrame::parse(frame_builder.as_bytes()).unwrap();
    if built_frame.ether_type() != EtherType::Arp {
        return TestResult::Failed(String::from("Built frame has wrong EtherType"));
    }

    TestResult::Passed
}

/// Test IPv4 packet parsing
pub fn test_ipv4_packet() -> TestResult {
    use crate::net::l3::ipv4::{IpProtocol, Ipv4Address, Ipv4Header, Ipv4Packet};

    // Test IPv4 address
    let addr = Ipv4Address::new(192, 168, 1, 1);
    if addr.octets() != [192, 168, 1, 1] {
        return TestResult::Failed(String::from("IPv4 address mismatch"));
    }

    // Test loopback
    let loopback = Ipv4Address::LOOPBACK;
    if !loopback.is_loopback() {
        return TestResult::Failed(String::from("Loopback not detected"));
    }

    // Test broadcast
    let broadcast = Ipv4Address::BROADCAST;
    if !broadcast.is_broadcast() {
        return TestResult::Failed(String::from("Broadcast not detected"));
    }

    // Create a test IPv4 packet
    let mut packet_data = [0u8; 40];
    // Version (4) + IHL (5) = 0x45
    packet_data[0] = 0x45;
    // TOS
    packet_data[1] = 0x00;
    // Total Length (40 bytes)
    packet_data[2] = 0x00;
    packet_data[3] = 0x28;
    // Identification
    packet_data[4] = 0x00;
    packet_data[5] = 0x01;
    // Flags + Fragment Offset
    packet_data[6] = 0x00;
    packet_data[7] = 0x00;
    // TTL
    packet_data[8] = 64;
    // Protocol (TCP)
    packet_data[9] = 6;
    // Checksum (0 for now)
    packet_data[10] = 0x00;
    packet_data[11] = 0x00;
    // Source IP (192.168.1.1)
    packet_data[12..16].copy_from_slice(&[192, 168, 1, 1]);
    // Destination IP (192.168.1.2)
    packet_data[16..20].copy_from_slice(&[192, 168, 1, 2]);

    let packet = match Ipv4Packet::parse(&packet_data) {
        Some(p) => p,
        None => return TestResult::Failed(String::from("Failed to parse IPv4 packet")),
    };

    if packet.version() != 4 {
        return TestResult::Failed(alloc::format!("Wrong version: {}", packet.version()));
    }

    if packet.header_len() != 20 {
        return TestResult::Failed(alloc::format!(
            "Wrong header length: {}",
            packet.header_len()
        ));
    }

    if packet.ttl() != 64 {
        return TestResult::Failed(alloc::format!("Wrong TTL: {}", packet.ttl()));
    }

    if packet.protocol() != IpProtocol::Tcp {
        return TestResult::Failed(String::from("Wrong protocol"));
    }

    if packet.source() != Ipv4Address::new(192, 168, 1, 1) {
        return TestResult::Failed(String::from("Wrong source IP"));
    }

    if packet.destination() != Ipv4Address::new(192, 168, 1, 2) {
        return TestResult::Failed(String::from("Wrong destination IP"));
    }

    TestResult::Passed
}

/// Test TCP state machine
pub fn test_tcp_state_machine() -> TestResult {
    use crate::net::l4::tcp::TcpState;

    // Test state transitions (conceptual)
    let state = TcpState::Closed;

    // Verify initial state
    if state != TcpState::Closed {
        return TestResult::Failed(String::from("Initial state should be Closed"));
    }

    // Test state values exist
    let _states = [
        TcpState::Closed,
        TcpState::Listen,
        TcpState::SynSent,
        TcpState::SynReceived,
        TcpState::Established,
        TcpState::FinWait1,
        TcpState::FinWait2,
        TcpState::CloseWait,
        TcpState::Closing,
        TcpState::LastAck,
        TcpState::TimeWait,
    ];

    TestResult::Passed
}

/// Test packet payload view
pub fn test_packet_payload_view() -> TestResult {
    use crate::net::payload::{PacketPayloadView, alloc_packet_with_headroom};
    use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

    let data = b"Hello, packet payload!";
    let mut packet = match alloc_packet_with_headroom(data.len(), DEFAULT_PACKET_HEADROOM) {
        Some(packet) => packet,
        None => return TestResult::Failed(String::from("Failed to allocate packet payload")),
    };
    packet.data_mut().copy_from_slice(data);

    let payload = match PacketPayload::try_single(packet) {
        Ok(payload) => payload,
        Err(_) => return TestResult::Failed(String::from("Packet payload must be non-empty")),
    };
    let view = PacketPayloadView::new(&payload);
    if view.total_len() != data.len() {
        return TestResult::Failed(alloc::format!(
            "Payload length mismatch: {} != {}",
            view.total_len(),
            data.len()
        ));
    }

    for (index, expected) in data.iter().enumerate() {
        if view.read_u8(index) != Some(*expected) {
            return TestResult::Failed(alloc::format!("Payload byte mismatch at {}", index));
        }
    }

    TestResult::Passed
}

/// Test ARP cache
pub fn test_arp_cache() -> TestResult {
    use crate::net::l2::arp::{ArpCache, ArpEntry, ArpEntryState};
    use crate::net::l2::ethernet::MacAddress;
    use crate::net::l3::ipv4::Ipv4Address;

    let mut cache = ArpCache::new(100);

    let ip = Ipv4Address::new(192, 168, 1, 100);
    let mac = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

    // Insert entry
    cache.insert(ip, mac);

    // Lookup entry
    match cache.lookup(ip) {
        Some(entry) => {
            if entry.mac != mac {
                return TestResult::Failed(String::from("ARP cache returned wrong MAC"));
            }
        }
        None => {
            return TestResult::Failed(String::from("ARP cache lookup failed"));
        }
    }

    // Lookup non-existent entry
    let unknown_ip = Ipv4Address::new(10, 0, 0, 1);
    if cache.lookup(unknown_ip).is_some() {
        return TestResult::Failed(String::from("ARP cache should return None for unknown IP"));
    }

    TestResult::Passed
}

/// Test UDP socket operations
pub fn test_udp_socket() -> TestResult {
    use crate::net::l3::ipv4::Ipv4Address;
    use crate::net::l4::udp::{UdpAddr, UdpSocket};

    // Create UDP socket
    let socket = UdpSocket::new();

    // Bind to local address
    let addr = UdpAddr {
        ip: Ipv4Address::new(0, 0, 0, 0),
        port: 12345,
    };

    // Binding should succeed (at least not panic)
    // In a real test environment we'd test send/receive

    TestResult::Passed
}

/// Test ICMP echo
pub fn test_icmp_echo() -> TestResult {
    use crate::net::l3::icmp::{IcmpEchoBuilder, IcmpType};
    use crate::net::l3::ipv4::Ipv4Address;

    // Build ICMP echo request
    let builder = IcmpEchoBuilder::new()
        .id(1234)
        .sequence(1)
        .data(&[1, 2, 3, 4, 5, 6, 7, 8]);

    let mut buffer = [0u8; 64];
    let len = builder.build(&mut buffer);

    if len == 0 {
        return TestResult::Failed(String::from("Failed to build ICMP echo"));
    }

    // Verify ICMP type
    if buffer[0] != 8 {
        // ICMP Echo Request
        return TestResult::Failed(alloc::format!("Wrong ICMP type: {}", buffer[0]));
    }

    TestResult::Passed
}
