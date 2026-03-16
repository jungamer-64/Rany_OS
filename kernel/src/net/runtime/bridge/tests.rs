use super::*;
use crate::net::datapath::mempool;
use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::{IpProtocol, Ipv4Address, Ipv4Config, Ipv4PacketMut};
use crate::net::l4::endpoint::tcb::{TcpConnectionState, TcpControlBlockEntry, tcb_table};
use crate::net::l4::endpoint::{
    EndpointAddr as TcpEndpointAddr, EndpointState, create_tcp_endpoint, init_endpoint_manager,
};
use crate::net::runtime::manager;
use crate::net::runtime::stack::{self, NetworkConfig};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

struct BridgeStateGuard {
    prev_if_stats: BTreeMap<NetIfId, StackGlueInterfaceStats>,
    prev_primary_if: Option<NetIfId>,
    prev_nat_entries: Vec<NatEntry>,
    prev_forward_events: Vec<(NetIfId, Ipv4Address)>,
    prev_manager: Option<crate::net::runtime::manager::NetworkManager>,
}

impl BridgeStateGuard {
    fn new() -> Self {
        let runtime = crate::net::runtime::default_runtime();
        let state = runtime_state_for(runtime);
        let prev_if_stats =
            core::mem::take(&mut *state.if_stats.write().unwrap_or_else(|e| e.into_inner()));
        let prev_primary_if = {
            let mut g = state.primary_if.write().unwrap_or_else(|e| e.into_inner());
            let v = *g;
            *g = None;
            v
        };
        let prev_nat_entries = nat_test_snapshot();
        nat_test_clear();
        let prev_forward_events = core::mem::take(
            &mut *state
                .forward_events
                .write()
                .unwrap_or_else(|e| e.into_inner()),
        );
        let prev_manager = {
            let mut guard = crate::net::runtime::manager::network_manager()
                .lock_for_init("[TEST][NET BRIDGE] manager snapshot");
            core::mem::take(&mut *guard)
        };
        Self {
            prev_if_stats,
            prev_primary_if,
            prev_nat_entries,
            prev_forward_events,
            prev_manager,
        }
    }
}

impl Drop for BridgeStateGuard {
    fn drop(&mut self) {
        let runtime = crate::net::runtime::default_runtime();
        let state = runtime_state_for(runtime);
        *state.if_stats.write().unwrap_or_else(|e| e.into_inner()) =
            core::mem::take(&mut self.prev_if_stats);
        *state.primary_if.write().unwrap_or_else(|e| e.into_inner()) = self.prev_primary_if.take();
        nat_test_restore(&self.prev_nat_entries);
        *state
            .forward_events
            .write()
            .unwrap_or_else(|e| e.into_inner()) = core::mem::take(&mut self.prev_forward_events);
        let mut guard = crate::net::runtime::manager::network_manager()
            .lock_for_init("[TEST][NET BRIDGE] manager restore");
        *guard = self.prev_manager.take();
    }
}

// ---------------------------------------------------------------------
// QEMU deterministic helpers (heap-aware fallback)
// ---------------------------------------------------------------------

#[cfg(feature = "qemu-test-export")]
fn qemu_prepare_zero_copy_env() -> BridgeStateGuard {
    let guard = BridgeStateGuard::new();
    stack::stack().clear_poison();
    guard
}

#[cfg(feature = "qemu-test-export")]
fn qemu_insert_established_tcp_endpoint(
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
) -> Option<crate::net::l4::endpoint::OwnedEndpoint> {
    init_endpoint_manager();
    let sock = create_tcp_endpoint();
    if let Some(endpoint) = sock.endpoint() {
        let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
        let _ = inner.transition_to(EndpointState::Bound);
        let _ = inner.transition_to(EndpointState::Connected);
    } else {
        return None;
    }

    let _ = tcb_table().remove(local, remote);
    let mut tcb = TcpControlBlockEntry::new(sock.fd(), local, remote);
    tcb.state = TcpConnectionState::Established;
    tcb.rcv_nxt = 1;
    tcb_table().insert(tcb).ok()?;
    Some(sock)
}

#[cfg(feature = "qemu-test-export")]
fn qemu_zero_copy_prereq_postcheck(
    sock: &crate::net::l4::endpoint::OwnedEndpoint,
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
) -> bool {
    check_batch_timeout(100_000, 1);
    let endpoint_ready = sock.endpoint().map_or(false, |endpoint| {
        let inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.state == EndpointState::Connected && inner.recv_buffer.is_empty()
    });
    let tcb_ready = matches!(
        tcb_table().get(local, remote),
        Some(entry) if entry.state == TcpConnectionState::Established && entry.rcv_nxt == 1
    );
    endpoint_ready && tcb_ready
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_packet_path_available() -> bool {
    let _ = mempool::init_net_mempool(1);
    mempool::alloc_packet().is_some()
}

#[cfg(feature = "qemu-test-export")]
fn qemu_zero_copy_prereq_ipv4_heapless_smoke() -> bool {
    let _bridge_guard = qemu_prepare_zero_copy_env();

    let mut config = NetworkConfig::default();
    config.ipv4.address = Ipv4Address::new([127, 0, 0, 1]);
    stack::init(config);

    let local = TcpEndpointAddr::new([127, 0, 0, 1], 1000);
    let remote = TcpEndpointAddr::new([127, 0, 0, 1], 2000);
    let sock = match qemu_insert_established_tcp_endpoint(local, remote) {
        Some(sock) => sock,
        None => return false,
    };

    qemu_zero_copy_prereq_postcheck(&sock, local, remote)
}

#[cfg(feature = "qemu-test-export")]
fn qemu_zero_copy_prereq_ipv6_heapless_smoke() -> bool {
    let _bridge_guard = qemu_prepare_zero_copy_env();

    let mut config = NetworkConfig::default();
    config.ipv6 = Some(crate::net::l3::ipv6::Ipv6Config::from_mac(&[
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    ]));
    stack::init(config);

    let local = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 1000);
    let remote =
        TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 2000);
    let sock = match qemu_insert_established_tcp_endpoint(local, remote) {
        Some(sock) => sock,
        None => return false,
    };

    qemu_zero_copy_prereq_postcheck(&sock, local, remote)
}

// Heapless fallback for routing/NAT parity when packet-path allocation is unavailable.

#[cfg(feature = "qemu-test-export")]
fn qemu_routing_nat_heapless_smoke() -> bool {
    let _guard = BridgeStateGuard::new();
    manager::init_network_manager();

    let if1 = match manager::register_interface("qemu-if-a") {
        Ok(id) => id,
        Err(_) => return false,
    };
    let if2 = match manager::register_interface("qemu-if-b") {
        Ok(id) => id,
        Err(_) => return false,
    };

    let cfg1 = NetworkConfig {
        mac: MacAddress::from_octets(0, 1, 2, 3, 4, 5),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 0, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ipv6: None,
        icmp_echo_enabled: true,
        ..NetworkConfig::default()
    };
    let cfg2 = NetworkConfig {
        mac: MacAddress::from_octets(0, 1, 2, 3, 4, 6),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 1, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ipv6: None,
        icmp_echo_enabled: true,
        ..NetworkConfig::default()
    };
    if manager::set_interface_config(if1, cfg1).is_err()
        || manager::set_interface_config(if2, cfg2).is_err()
    {
        return false;
    }

    let route = manager::Ipv4Route {
        destination: Ipv4Address::new([10, 0, 1, 0]),
        prefix_len: 24,
        gateway: None,
        if_id: if2,
        metric: 1,
        flags: manager::RouteFlags::connected(),
        admin_enabled: true,
        managed_by_interface: false,
    };
    if manager::add_ipv4_route(route).is_err() {
        return false;
    }

    let route_ok = matches!(
        manager::lookup_ipv4_route(Ipv4Address::new([10, 0, 1, 5])),
        Ok(Some(r)) if r.if_id == if2
    );
    if !route_ok {
        return false;
    }

    true
}

// Public QEMU smoke entry points used by net peripheral required suite.

#[cfg(feature = "qemu-test-export")]
pub fn qemu_zero_copy_via_bridge_smoke() -> bool {
    qemu_zero_copy_prereq_ipv4_heapless_smoke()
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_routing_and_nat_smoke() -> bool {
    qemu_routing_nat_heapless_smoke()
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_zero_copy_via_bridge_v6_smoke() -> bool {
    qemu_zero_copy_prereq_ipv6_heapless_smoke()
}

#[cfg_attr(test, test_case)]
pub fn test_zero_copy_via_bridge() {
    let _guard = BridgeStateGuard::new();
    stack::stack().clear_poison();
    init_endpoint_manager();

    // Initialize mempool and stack
    let _ = mempool::init_net_mempool(4);

    // Configure stack to use 127.0.0.1 for tests
    let mut config = NetworkConfig::default();
    config.ipv4.address = Ipv4Address::new([127, 0, 0, 1]);
    stack::init(config);

    // Prepare a TCB and register it in the global stack
    let local = TcpEndpointAddr::new([127, 0, 0, 1], 1000);
    let remote = TcpEndpointAddr::new([127, 0, 0, 1], 2000);
    let sock = qemu_insert_established_tcp_endpoint(local, remote)
        .expect("established TCP endpoint should be inserted");

    // Build packet: virtio header + ethernet + IPv4 + TCP + payload
    let header_size = crate::io::virtio::net::VirtioNetHeader::SIZE;
    let payload = b"hello";
    let tcp_len = 20 + payload.len();
    let ip_total_len = 20 + tcp_len; // IP header + TCP + payload
    let eth_total_len = 14 + ip_total_len; // Ethernet frame length

    // Allocate packet buffer
    let mut packet = mempool::alloc_packet().expect("alloc packet");
    let buf = packet.data_mut();

    // Ensure buffer large enough
    let needed = header_size + eth_total_len;
    assert!(buf.len() >= needed, "Packet buffer too small for test");

    // Virtio header (zero)
    for i in 0..header_size {
        buf[i] = 0;
    }

    // Ethernet header
    let eth_off = header_size;
    buf[eth_off..eth_off + 6].copy_from_slice(&[0xff; 6]); // dst
    buf[eth_off + 6..eth_off + 12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
    buf[eth_off + 12..eth_off + 14].copy_from_slice(&[0x08, 0x00]); // EtherType = IPv4

    // IPv4 header
    let ip_off = eth_off + 14;
    {
        let mut ipv4_mut = Ipv4PacketMut::new(&mut buf[ip_off..ip_off + 20]).expect("ipv4 mut");
        ipv4_mut
            .init_header()
            .set_source(Ipv4Address::new([127, 0, 0, 1]))
            .set_destination(Ipv4Address::new([127, 0, 0, 1]))
            .set_protocol(IpProtocol::Tcp)
            .set_identification(1);
    }
    // Write TCP header and payload into IP payload
    let tcp_off = ip_off + 20;
    // Src port 2000, dst port 1000
    buf[tcp_off..tcp_off + 2].copy_from_slice(&2000u16.to_be_bytes());
    buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&1000u16.to_be_bytes());
    // Seq = 1
    buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&1u32.to_be_bytes());
    // Ack = 0
    buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&0u32.to_be_bytes());
    // Data offset = 5 (20 bytes), flags = 0
    let data_off_flags = ((5u16 << 12) | 0u16).to_be_bytes();
    buf[tcp_off + 12..tcp_off + 14].copy_from_slice(&data_off_flags);
    // Window
    buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&65535u16.to_be_bytes());
    // Payload
    buf[tcp_off + 20..tcp_off + 20 + payload.len()].copy_from_slice(payload);

    // Finalize IP header (set total length and checksum)
    Ipv4PacketMut::new(&mut buf[ip_off..ip_off + 20])
        .expect("ipv4 mut")
        .finalize(tcp_len);

    // Set packet length (virtio header + ethernet frame)
    packet.set_len(header_size + eth_total_len);

    // Call bridge zero-copy entry
    process_received_packet_zero_copy(packet, header_size, eth_total_len);

    // Force a batch timeout to flush the packet into the stack
    check_batch_timeout(100_000, 1);

    let mut buf = [0u8; 32];
    let len = sock.recv_sync(&mut buf).expect("tcp endpoint should receive payload");
    assert_eq!(&buf[..len], payload);
    let _ = tcb_table().remove(local, remote);
}

#[cfg_attr(test, test_case)]
pub fn test_routing_and_nat() {
    // setup environment
    let _guard = BridgeStateGuard::new();
    let _ = mempool::init_net_mempool(4);
    manager::init_network_manager();

    // create two interfaces
    let if1 = manager::register_interface("if1").expect("register if1");
    let if2 = manager::register_interface("if2").expect("register if2");
    // configure addresses
    let cfg1 = NetworkConfig {
        mac: MacAddress::from_octets(0, 1, 2, 3, 4, 5),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 0, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ipv6: None,
        icmp_echo_enabled: true,
        ..NetworkConfig::default()
    };
    let cfg2 = NetworkConfig {
        mac: MacAddress::from_octets(0, 1, 2, 3, 4, 6),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 1, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ipv6: None,
        icmp_echo_enabled: true,
        ..NetworkConfig::default()
    };
    let _ = manager::set_interface_config(if1, cfg1);
    let _ = manager::set_interface_config(if2, cfg2);

    // add route 10.0.1.0/24 via if2
    let route = manager::Ipv4Route {
        destination: Ipv4Address::new([10, 0, 1, 0]),
        prefix_len: 24,
        gateway: None,
        if_id: if2,
        metric: 1,
        flags: manager::RouteFlags::connected(),
        admin_enabled: true,
        managed_by_interface: false,
    };
    let _ = manager::add_ipv4_route(route);

    // craft a UDP packet from 10.0.0.2:1234 to 10.0.1.5:80 arriving on if1
    let header_size = crate::io::virtio::net::VirtioNetHeader::SIZE;
    let mut packet = mempool::alloc_packet().unwrap();
    let buf = packet.data_mut();
    // build ethernet, ip, udp similar to earlier tests
    let eth_off = header_size;
    let ip_off = eth_off + 14;
    // fill with minimal sizes
    buf[0..header_size].fill(0);
    // eth header
    buf[eth_off..eth_off + 6].fill(0xff);
    buf[eth_off + 6..eth_off + 12].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
    buf[eth_off + 12..eth_off + 14].copy_from_slice(&[0x08, 0x00]); // IPv4
    // ip header
    {
        let mut ipm = Ipv4PacketMut::new(&mut buf[ip_off..ip_off + 20]).unwrap();
        ipm.init_header()
            .set_source(Ipv4Address::new([10, 0, 0, 2]))
            .set_destination(Ipv4Address::new([10, 0, 1, 5]))
            .set_protocol(IpProtocol::Udp);
        ipm.set_total_length(28); // 20 ip + 8 udp
        ipm.update_checksum();
    }
    // udp header
    let udp_off = ip_off + 20;
    buf[udp_off..udp_off + 2].copy_from_slice(&1234u16.to_be_bytes());
    buf[udp_off + 2..udp_off + 4].copy_from_slice(&80u16.to_be_bytes());
    buf[udp_off + 4..udp_off + 6].copy_from_slice(&8u16.to_be_bytes());
    buf[udp_off + 6..udp_off + 8].copy_from_slice(&0u16.to_be_bytes());

    let total_len = header_size + 14 + 28;
    packet.set_len(total_len);

    // clear forward events
    #[cfg(any(test, feature = "qemu-test-export"))]
    {
        runtime_state()
            .forward_events
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    process_received_packet_zero_copy_for_interface(if1, packet, header_size, 14 + 28);

    // verify forwarded to if2 and NAT table contains entry
    #[cfg(any(test, feature = "qemu-test-export"))]
    {
        let ev = runtime_state()
            .forward_events
            .read()
            .unwrap_or_else(|e| e.into_inner());
        assert!(
            ev.iter()
                .any(|(id, dst)| *id == if2 && *dst == Ipv4Address::new([10, 0, 1, 5]))
        );
        // check NAT entry exists for internal port 1234
        let entries = nat_test_entries();
        assert!(entries.iter().any(|e| e.protocol == IpProtocol::Udp
            && e.internal_ip == Ipv4Address::new([10, 0, 0, 2])
            && e.internal_port == 1234));
    }
}

#[cfg_attr(test, test_case)]
pub fn test_nat_inbound_roundtrip_is_protocol_scoped() {
    let _guard = BridgeStateGuard::new();
    manager::init_network_manager();

    let wan_if = manager::register_interface("wan0").expect("register wan0");
    let other_wan_if = manager::register_interface("wan1").expect("register wan1");
    let wan_cfg = NetworkConfig {
        mac: MacAddress::from_octets(0, 1, 2, 3, 4, 42),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 1, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ipv6: None,
        icmp_echo_enabled: true,
        ..NetworkConfig::default()
    };
    let _ = manager::set_interface_config(wan_if, wan_cfg);
    let _ = manager::set_interface_config(
        other_wan_if,
        NetworkConfig {
            mac: MacAddress::from_octets(0, 1, 2, 3, 4, 43),
            ipv4: Ipv4Config {
                address: Ipv4Address::new([10, 0, 2, 1]),
                subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                gateway: Ipv4Address::ANY,
                dns: None,
            },
            ipv6: None,
            icmp_echo_enabled: true,
            ..NetworkConfig::default()
        },
    );

    let internal_ip = Ipv4Address::new([10, 0, 0, 2]);
    let internal_port = 1234;
    let remote_ip = Ipv4Address::new([198, 51, 100, 10]);
    let remote_port = 43210;
    let (ext_ip, ext_port) = nat_translate_out(
        IpProtocol::Udp,
        internal_ip,
        internal_port,
        remote_ip,
        remote_port,
        wan_if,
        0,
    )
    .expect("NAT allocation failed");

    assert_eq!(ext_ip, Ipv4Address::new([10, 0, 1, 1]));
    assert!(ext_port >= nat_test_ephemeral_port_start());

    let mut dst_ip = ext_ip;
    let mut dst_port = ext_port;
    assert!(nat_translate_in(
        IpProtocol::Udp,
        remote_ip,
        remote_port,
        &mut dst_ip,
        &mut dst_port,
        0
    ));
    assert_eq!(dst_ip, internal_ip);
    assert_eq!(dst_port, internal_port);

    // Same external port but different protocol must not match.
    let mut dst_ip = ext_ip;
    let mut dst_port = ext_port;
    assert!(!nat_translate_in(
        IpProtocol::Tcp,
        remote_ip,
        remote_port,
        &mut dst_ip,
        &mut dst_port,
        0
    ));
    assert_eq!(dst_ip, ext_ip);
    assert_eq!(dst_port, ext_port);

    // Different local WAN IP (also local) must not match this mapping.
    let mut dst_ip = Ipv4Address::new([10, 0, 2, 1]);
    let mut dst_port = ext_port;
    assert!(!nat_translate_in(
        IpProtocol::Udp,
        remote_ip,
        remote_port,
        &mut dst_ip,
        &mut dst_port,
        0
    ));
    assert_eq!(dst_ip, Ipv4Address::new([10, 0, 2, 1]));
    assert_eq!(dst_port, ext_port);

    // Non-local destination addresses must not be rewritten.
    let mut dst_ip = Ipv4Address::new([203, 0, 113, 9]);
    let mut dst_port = ext_port;
    assert!(!nat_translate_in(
        IpProtocol::Udp,
        remote_ip,
        remote_port,
        &mut dst_ip,
        &mut dst_port,
        0
    ));
    assert_eq!(dst_ip, Ipv4Address::new([203, 0, 113, 9]));
    assert_eq!(dst_port, ext_port);
}

#[cfg_attr(test, test_case)]
pub fn test_nat_gc_expires_idle_entries() {
    let _guard = BridgeStateGuard::new();
    manager::init_network_manager();

    let wan_if = manager::register_interface("wan0").expect("register wan0");
    let _ = manager::set_interface_config(
        wan_if,
        NetworkConfig {
            mac: MacAddress::from_octets(0, 1, 2, 3, 4, 44),
            ipv4: Ipv4Config {
                address: Ipv4Address::new([10, 0, 9, 1]),
                subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                gateway: Ipv4Address::ANY,
                dns: None,
            },
            ipv6: None,
            icmp_echo_enabled: true,
            ..NetworkConfig::default()
        },
    );

    let (_, stale_port) = nat_translate_out(
        IpProtocol::Udp,
        Ipv4Address::new([10, 0, 0, 2]),
        1111,
        Ipv4Address::new([198, 51, 100, 1]),
        50001,
        wan_if,
        0,
    )
    .expect("NAT allocation failed");
    let (_, fresh_port) = nat_translate_out(
        IpProtocol::Udp,
        Ipv4Address::new([10, 0, 0, 3]),
        2222,
        Ipv4Address::new([198, 51, 100, 2]),
        50002,
        wan_if,
        0,
    )
    .expect("NAT allocation failed");

    assert!(nat_test_force_last_used(stale_port, 100));
    assert!(nat_test_force_last_used(fresh_port, 900));

    nat_maybe_gc(0);

    let entries = nat_test_entries();
    assert_eq!(nat_test_entry_count(), 1);
    assert!(
        !entries
            .iter()
            .any(|entry| entry.external_port == stale_port)
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.external_port == fresh_port)
    );
}

#[cfg_attr(test, test_case)]
pub fn test_nat_icmp_echo() {
    let _guard = BridgeStateGuard::new();
    manager::init_network_manager();

    let wan_if = manager::register_interface("wan0").expect("register wan0");
    let _ = manager::set_interface_config(
        wan_if,
        NetworkConfig {
            mac: MacAddress::from_octets(0, 1, 2, 3, 4, 45),
            ipv4: Ipv4Config {
                address: Ipv4Address::new([10, 0, 1, 1]),
                subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                gateway: Ipv4Address::ANY,
                dns: None,
            },
            ipv6: None,
            icmp_echo_enabled: true,
            ..NetworkConfig::default()
        },
    );

    let internal_ip = Ipv4Address::new([10, 0, 0, 2]);
    let remote_ip = Ipv4Address::new([8, 8, 8, 8]);
    let mut icmp_req = [0u8; 8];
    icmp_req[0] = 8; // Echo Request
    icmp_req[4] = 0x12; // Identifier
    icmp_req[5] = 0x34;

    let (ext_ip, ext_port) = nat_translate_out_icmp(internal_ip, remote_ip, &icmp_req, wan_if)
        .expect("NAT allocation failed");
    assert_eq!(ext_ip, Ipv4Address::new([10, 0, 1, 1]));

    // Response
    let mut icmp_reply = [0u8; 8];
    icmp_reply[0] = 0; // Echo Reply
    icmp_reply[4] = (ext_port >> 8) as u8;
    icmp_reply[5] = (ext_port & 0xff) as u8;

    let mut dst_ip = ext_ip;
    let new_dst =
        nat_translate_in_icmp(remote_ip, &mut dst_ip, &mut icmp_reply).expect("NAT lookup failed");
    assert_eq!(new_dst, internal_ip);
    assert_eq!(icmp_reply[4], 0x12);
    assert_eq!(icmp_reply[5], 0x34);
}

#[cfg_attr(test, test_case)]
pub fn test_nat_icmp_error() {
    let _guard = BridgeStateGuard::new();
    manager::init_network_manager();

    let wan_if = manager::register_interface("wan0").expect("register wan0");
    let _ = manager::set_interface_config(
        wan_if,
        NetworkConfig {
            mac: MacAddress::from_octets(0, 1, 2, 3, 4, 46),
            ipv4: Ipv4Config {
                address: Ipv4Address::new([10, 0, 1, 1]),
                subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                gateway: Ipv4Address::ANY,
                dns: None,
            },
            ipv6: None,
            icmp_echo_enabled: true,
            ..NetworkConfig::default()
        },
    );

    let internal_ip = Ipv4Address::new([10, 0, 0, 2]);
    let internal_port = 1234;
    let remote_ip = Ipv4Address::new([93, 184, 216, 34]);
    let remote_port = 80;

    let (_ext_ip, ext_port) = nat_translate_out(
        IpProtocol::Tcp,
        internal_ip,
        internal_port,
        remote_ip,
        remote_port,
        wan_if,
        0,
    )
    .expect("NAT allocation failed");

    // ICMP Error (Time Exceeded) from an intermediate router (1.1.1.1)
    let mut icmp_err = [0u8; 8 + 20 + 8];
    icmp_err[0] = 11; // Time Exceeded
    icmp_err[1] = 0; // Code: TTL exceeded in transit

    // Original IP header
    let inner_ip_off = 8;
    icmp_err[inner_ip_off + 9] = 6; // TCP
    icmp_err[inner_ip_off + 12..inner_ip_off + 16].copy_from_slice(_ext_ip.as_bytes()); // was sent as translated IP
    icmp_err[inner_ip_off + 16..inner_ip_off + 20].copy_from_slice(remote_ip.as_bytes());

    // Original transport (first 8 bytes)
    let inner_tcp_off = inner_ip_off + 20;
    icmp_err[inner_tcp_off..inner_tcp_off + 2].copy_from_slice(&ext_port.to_be_bytes());
    icmp_err[inner_tcp_off + 2..inner_tcp_off + 4].copy_from_slice(&remote_port.to_be_bytes());

    let mut dst_ip = _ext_ip;
    let router_ip = Ipv4Address::new([1, 1, 1, 1]);
    let new_dst = nat_translate_in_icmp(router_ip, &mut dst_ip, &mut icmp_err)
        .expect("NAT lookup failed for ICMP error");

    assert_eq!(new_dst, internal_ip);
    // Inner IP should be rewritten back to internal IP
    assert_eq!(
        Ipv4Address::from_octets(
            icmp_err[inner_ip_off + 12],
            icmp_err[inner_ip_off + 13],
            icmp_err[inner_ip_off + 14],
            icmp_err[inner_ip_off + 15]
        ),
        internal_ip
    );
    // Inner port should be rewritten back to internal port
    assert_eq!(
        u16::from_be_bytes([icmp_err[inner_tcp_off], icmp_err[inner_tcp_off + 1]]),
        internal_port
    );
}

#[cfg_attr(test, test_case)]
pub fn test_zero_copy_via_bridge_v6() {
    let _guard = BridgeStateGuard::new();
    stack::stack().clear_poison();
    init_endpoint_manager();

    // Initialize mempool and stack
    let _ = mempool::init_net_mempool(4);

    // Configure stack with IPv6 enabled for tests
    let mut config = NetworkConfig::default();
    config.ipv6 = Some(crate::net::l3::ipv6::Ipv6Config::from_mac(&[
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    ]));
    stack::init(config);

    // Prepare a TCB and register it in the global stack (IPv6)
    let local = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 1000);
    let remote =
        TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 2000);
    let sock = qemu_insert_established_tcp_endpoint(local, remote)
        .expect("established TCP endpoint should be inserted");

    // Build packet: virtio header + ethernet + IPv6 + TCP + payload
    let header_size = crate::io::virtio::net::VirtioNetHeader::SIZE;
    let payload = b"hello-v6";
    let tcp_len = 20 + payload.len();
    let ipv6_total_len = 40 + tcp_len; // IPv6 header + TCP + payload
    let eth_total_len = 14 + ipv6_total_len; // Ethernet frame length

    // Allocate packet buffer
    let mut packet = mempool::alloc_packet().expect("alloc packet");
    let buf = packet.data_mut();

    // Ensure buffer large enough
    let needed = header_size + eth_total_len;
    assert!(buf.len() >= needed, "Packet buffer too small for test");

    // Virtio header (zero)
    for i in 0..header_size {
        buf[i] = 0;
    }

    // Ethernet header
    let eth_off = header_size;
    buf[eth_off..eth_off + 6].copy_from_slice(&[0xff; 6]); // dst
    buf[eth_off + 6..eth_off + 12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
    buf[eth_off + 12..eth_off + 14].copy_from_slice(&[0x86, 0xdd]); // EtherType = IPv6

    // IPv6 header
    let ip_off = eth_off + 14;
    {
        let mut ipv6_mut = crate::net::l3::ipv6::Ipv6PacketMut::new(&mut buf[ip_off..ip_off + 40])
            .expect("ipv6 mut");
        ipv6_mut.init_header();
        ipv6_mut.set_source(&crate::net::l3::ipv6::Ipv6Address::LOOPBACK);
        ipv6_mut.set_destination(&crate::net::l3::ipv6::Ipv6Address::LOOPBACK);
        ipv6_mut.set_next_header(crate::net::l3::ipv4::IpProtocol::Tcp);
        ipv6_mut.set_payload_length(tcp_len as u16);
    }

    // Write TCP header and payload into IPv6 payload
    let tcp_off = ip_off + 40;
    // Src port 2000, dst port 1000
    buf[tcp_off..tcp_off + 2].copy_from_slice(&2000u16.to_be_bytes());
    buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&1000u16.to_be_bytes());
    // Seq = 1
    buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&1u32.to_be_bytes());
    // Ack = 0
    buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&0u32.to_be_bytes());
    // Data offset = 5 (20 bytes), flags = 0
    let data_off_flags = ((5u16 << 12) | 0u16).to_be_bytes();
    buf[tcp_off + 12..tcp_off + 14].copy_from_slice(&data_off_flags);
    // Window
    buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&65535u16.to_be_bytes());
    // Payload
    buf[tcp_off + 20..tcp_off + 20 + payload.len()].copy_from_slice(payload);

    // Set packet length (virtio header + ethernet frame)
    packet.set_len(header_size + eth_total_len);

    // Call bridge zero-copy entry
    process_received_packet_zero_copy(packet, header_size, eth_total_len);

    // Force a batch timeout to flush the packet into the stack
    check_batch_timeout(100_000, 1);

    let mut buf = [0u8; 32];
    let len = sock.recv_sync(&mut buf).expect("tcp endpoint should receive payload");
    assert_eq!(&buf[..len], payload);
    let _ = tcb_table().remove(local, remote);
}

#[cfg_attr(test, test_case)]
pub fn test_per_interface_bridge_stats_are_separated() {
    let _guard = BridgeStateGuard::new();
    let runtime = crate::net::runtime::default_runtime();
    let if0 = NetIfId(10);
    let if1 = NetIfId(11);

    ensure_stack_glue_if_state_in(runtime, if0, Some(0));
    ensure_stack_glue_if_state_in(runtime, if1, Some(1));
    record_stack_glue_if_rx_in(runtime, if0);
    record_stack_glue_if_rx_in(runtime, if0);
    record_stack_glue_if_tx_in(runtime, if1);

    let s0 = get_stack_glue_stats_for_interface(if0).expect("if0 stats");
    let s1 = get_stack_glue_stats_for_interface(if1).expect("if1 stats");
    assert_eq!(s0.rx_packets, 2);
    assert_eq!(s0.tx_packets, 0);
    assert_eq!(s1.rx_packets, 0);
    assert_eq!(s1.tx_packets, 1);
    assert_eq!(list_stack_glue_stats().len(), 2);
}

#[cfg_attr(test, test_case)]
pub fn test_register_virtio_port_is_idempotent_and_records_mapping() {
    let _guard = BridgeStateGuard::new();

    let if0 = manager::register_virtio_port(0, None).expect("register vnet0");
    let if0_again = manager::register_virtio_port(0, None).expect("register vnet0 again");
    let if1 = manager::register_virtio_port(1, None).expect("register vnet1");

    register_stack_glue_interface(if0, Some(0));
    register_stack_glue_interface(if1, Some(1));

    assert_eq!(if0, if0_again);
    assert_ne!(if0, if1);
    assert_eq!(lookup_if_by_virtio_index(0), Some(if0));
    assert_eq!(lookup_if_by_virtio_index(1), Some(if1));

    let s0 = get_stack_glue_stats_for_interface(if0).expect("if0 stats");
    let s1 = get_stack_glue_stats_for_interface(if1).expect("if1 stats");
    assert_eq!(s0.virtio_index, Some(0));
    assert_eq!(s1.virtio_index, Some(1));
    assert_eq!(list_stack_glue_stats().len(), 2);
}

#[cfg_attr(test, test_case)]
pub fn test_register_virtio_port_prefers_vnet0_as_primary() {
    let _guard = BridgeStateGuard::new();

    let if1 = manager::register_virtio_port(1, None).expect("register vnet1");
    register_stack_glue_interface(if1, Some(1));
    assert_eq!(primary_stack_glue_if(), Some(if1));

    let if0 = manager::register_virtio_port(0, None).expect("register vnet0");
    register_stack_glue_interface(if0, Some(0));
    assert_eq!(primary_stack_glue_if(), Some(if0));

    let if2 = manager::register_virtio_port(2, None).expect("register vnet2");
    register_stack_glue_interface(if2, Some(2));
    assert_eq!(primary_stack_glue_if(), Some(if0));
}

#[cfg_attr(test, test_case)]
pub fn test_transmit_from_stack_interface_argument() {
    // using a dummy interface id should simply delegate to the
    // per-interface send function, which currently fails (no mapping)
    let dummy = NetIfId(7);
    assert!(!transmit_from_stack(
        Some(dummy),
        b"hello",
        kernel_api::service::netdev::NetTxMeta::default(),
    ));
}

#[cfg_attr(test, test_case)]
pub fn test_runtime_scoped_bridge_and_nat_state_do_not_leak() {
    crate::net::runtime::context::reset_runtime_registry_for_tests();

    let runtime_a = crate::net::runtime::default_runtime();
    let runtime_b = crate::net::runtime::create_runtime();
    let if_a;
    let if_b;

    {
        let mut manager = runtime_a
            .context()
            .manager
            .lock_for_init("[TEST][NET BRIDGE] runtime_a manager");
        *manager = Some(manager::NetworkManager::new());
    }
    {
        let mut manager = runtime_b
            .context()
            .manager
            .lock_for_init("[TEST][NET BRIDGE] runtime_b manager");
        *manager = Some(manager::NetworkManager::new());
    }

    {
        let mut manager = runtime_a
            .context()
            .manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let manager = manager.as_mut().expect("runtime_a manager");
        if_a = manager.register_interface("rt-a".into());
        manager
            .set_interface_config(
                if_a,
                NetworkConfig {
                    mac: MacAddress::from_octets(0, 1, 2, 3, 4, 20),
                    ipv4: Ipv4Config {
                        address: Ipv4Address::new([10, 10, 0, 1]),
                        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                        gateway: Ipv4Address::ANY,
                        dns: None,
                    },
                    ipv6: None,
                    icmp_echo_enabled: true,
                    ..NetworkConfig::default()
                },
            )
            .expect("runtime_a config");
    }
    {
        let mut manager = runtime_b
            .context()
            .manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let manager = manager.as_mut().expect("runtime_b manager");
        if_b = manager.register_interface("rt-b".into());
        manager
            .set_interface_config(
                if_b,
                NetworkConfig {
                    mac: MacAddress::from_octets(0, 1, 2, 3, 4, 21),
                    ipv4: Ipv4Config {
                        address: Ipv4Address::new([10, 20, 0, 1]),
                        subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
                        gateway: Ipv4Address::ANY,
                        dns: None,
                    },
                    ipv6: None,
                    icmp_echo_enabled: true,
                    ..NetworkConfig::default()
                },
            )
            .expect("runtime_b config");
    }

    register_stack_glue_interface_in(runtime_a, if_a, Some(0));
    register_stack_glue_interface_in(runtime_b, if_b, Some(1));
    record_stack_glue_if_rx_in(runtime_a, if_a);
    record_stack_glue_if_tx_in(runtime_b, if_b);

    let (_ip_a, port_a) = nat_translate_out_in(
        runtime_a,
        IpProtocol::Udp,
        Ipv4Address::new([10, 10, 0, 2]),
        1000,
        Ipv4Address::new([1, 1, 1, 1]),
        53,
        if_a,
        0,
    )
    .expect("runtime_a nat");
    let (_ip_b, port_b) = nat_translate_out_in(
        runtime_b,
        IpProtocol::Udp,
        Ipv4Address::new([10, 20, 0, 2]),
        2000,
        Ipv4Address::new([8, 8, 8, 8]),
        53,
        if_b,
        0,
    )
    .expect("runtime_b nat");

    assert_ne!(port_a, 0);
    assert_ne!(port_b, 0);

    let stats_a = runtime_state_for(runtime_a)
        .if_stats
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&if_a)
        .copied()
        .expect("runtime_a stats");
    let stats_b = runtime_state_for(runtime_b)
        .if_stats
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&if_b)
        .copied()
        .expect("runtime_b stats");

    assert_eq!(stats_a.rx_packets, 1);
    assert_eq!(stats_a.tx_packets, 0);
    assert_eq!(stats_b.rx_packets, 0);
    assert_eq!(stats_b.tx_packets, 1);
    assert_eq!(
        *runtime_state_for(runtime_a)
            .primary_if
            .read()
            .unwrap_or_else(|e| e.into_inner()),
        Some(if_a)
    );
    assert_eq!(
        *runtime_state_for(runtime_b)
            .primary_if
            .read()
            .unwrap_or_else(|e| e.into_inner()),
        Some(if_b)
    );

    let entries_a = nat_test_entries_in(runtime_a);
    let entries_b = nat_test_entries_in(runtime_b);
    assert_eq!(entries_a.len(), 1);
    assert_eq!(entries_b.len(), 1);
    assert_eq!(entries_a[0].if_id, if_a);
    assert_eq!(entries_b[0].if_id, if_b);
}
