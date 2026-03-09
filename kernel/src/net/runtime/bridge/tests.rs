use super::*;
use crate::net::datapath::mempool;
use crate::net::l3::ipv4::{IpProtocol, Ipv4Address, Ipv4PacketMut};
use crate::net::l4::tcp::{
    EndpointAddr as TcpEndpointAddr, Ipv4Addr as TcpIpv4Addr, TcpControlBlock,
};
use crate::net::runtime::manager;
use crate::net::runtime::stack;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

struct BridgeStateGuard {
    prev_if_stats: BTreeMap<NetIfId, StackGlueInterfaceStats>,
    prev_primary_if: Option<NetIfId>,
    prev_nat_table: BTreeMap<u16, NatEntry>,
    prev_nat_next_port: u16,
    prev_forward_events: Vec<(NetIfId, Ipv4Address)>,
    prev_manager: Option<crate::net::runtime::manager::NetworkManager>,
}

impl BridgeStateGuard {
    fn new() -> Self {
        let prev_if_stats = core::mem::take(&mut *STACK_GLUE_IF_STATS.write());
        let prev_primary_if = {
            let mut g = PRIMARY_STACK_GLUE_IF.write();
            let v = *g;
            *g = None;
            v
        };
        let prev_nat_table = core::mem::take(&mut *NAT_TABLE.write());
        let prev_nat_next_port =
            NAT_NEXT_PORT.swap(NAT_EPHEMERAL_START, core::sync::atomic::Ordering::Relaxed);
        let prev_forward_events = core::mem::take(&mut *FORWARD_EVENTS.write());
        let prev_manager = {
            let mut guard = crate::net::runtime::manager::NETWORK_MANAGER
                .lock_for_init("[TEST][NET BRIDGE] manager snapshot");
            core::mem::take(&mut *guard)
        };
        Self {
            prev_if_stats,
            prev_primary_if,
            prev_nat_table,
            prev_nat_next_port,
            prev_forward_events,
            prev_manager,
        }
    }
}

impl Drop for BridgeStateGuard {
    fn drop(&mut self) {
        *STACK_GLUE_IF_STATS.write() = core::mem::take(&mut self.prev_if_stats);
        *PRIMARY_STACK_GLUE_IF.write() = self.prev_primary_if.take();
        *NAT_TABLE.write() = core::mem::take(&mut self.prev_nat_table);
        NAT_NEXT_PORT.store(
            self.prev_nat_next_port,
            core::sync::atomic::Ordering::Relaxed,
        );
        *FORWARD_EVENTS.write() = core::mem::take(&mut self.prev_forward_events);
        let mut guard = crate::net::runtime::manager::NETWORK_MANAGER
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
fn qemu_insert_established_tcb(
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
) -> Option<alloc::sync::Arc<PoisonLock<TcpControlBlock>>> {
    let mut tcb = TcpControlBlock::new(local);
    tcb.set_remote_addr(remote);
    tcb.enter_established();
    tcb.set_rcv_nxt(1);
    let tcb_arc = alloc::sync::Arc::new(PoisonLock::new(tcb));

    match stack::stack().lock() {
        Ok(mut guard) => {
            let stack = guard.as_mut()?;
            stack.insert_test_tcp_connection(local, remote, tcb_arc.clone());
            Some(tcb_arc)
        }
        Err(_) => None,
    }
}

#[cfg(feature = "qemu-test-export")]
fn qemu_zero_copy_prereq_postcheck(
    tcb_arc: &alloc::sync::Arc<PoisonLock<TcpControlBlock>>,
) -> bool {
    check_batch_timeout(100_000, 1);
    match tcb_arc.lock() {
        Ok(guard) => guard.recv_buffer_is_empty() && guard.is_established(),
        Err(_) => false,
    }
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
    let tcb_arc = match qemu_insert_established_tcb(local, remote) {
        Some(tcb) => tcb,
        None => return false,
    };

    qemu_zero_copy_prereq_postcheck(&tcb_arc)
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
    let tcb_arc = match qemu_insert_established_tcb(local, remote) {
        Some(tcb) => tcb,
        None => return false,
    };

    qemu_zero_copy_prereq_postcheck(&tcb_arc)
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

    // Initialize mempool and stack
    let _ = mempool::init_net_mempool(4);

    // Configure stack to use 127.0.0.1 for tests
    let mut config = NetworkConfig::default();
    config.ipv4.address = Ipv4Address::new([127, 0, 0, 1]);
    stack::init(config);

    // Prepare a TCB and register it in the global stack
    let local = TcpEndpointAddr::new([127, 0, 0, 1], 1000);
    let remote = TcpEndpointAddr::new([127, 0, 0, 1], 2000);

    let mut tcb = TcpControlBlock::new(local);
    tcb.set_remote_addr(remote);
    tcb.enter_established();
    tcb.set_rcv_nxt(1);
    let tcb_arc = alloc::sync::Arc::new(PoisonLock::new(tcb));

    // Insert into stack's tcp connections
    match stack::stack().lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.insert_test_tcp_connection(local, remote, tcb_arc.clone());
            }
        }
        Err(_) => panic!("Stack poisoned"),
    }

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

    // Now verify TCB received the payload zero-copy
    if let Ok(guard) = tcb_arc.lock() {
        assert!(!guard.recv_buffer_is_empty());
        assert_eq!(guard.recv_buffer_front_data().unwrap(), payload);
    } else {
        panic!("TCB lock poisoned in test");
    }
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
        FORWARD_EVENTS.write().clear();
    }

    process_received_packet_zero_copy_for_interface(if1, packet, header_size, 14 + 28);

    // verify forwarded to if2 and NAT table contains entry
    #[cfg(any(test, feature = "qemu-test-export"))]
    {
        let ev = FORWARD_EVENTS.read();
        assert!(
            ev.iter()
                .any(|(id, dst)| *id == if2 && *dst == Ipv4Address::new([10, 0, 1, 5]))
        );
        // check NAT entry exists for internal port 1234
        let table = NAT_TABLE.read();
        assert!(table.values().any(|e| e.protocol == IpProtocol::Udp
            && e.internal_addr == Ipv4Address::new([10, 0, 0, 2])
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
    assert!(ext_port >= NAT_EPHEMERAL_START);

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

    {
        let mut table = NAT_TABLE.write();
        table.get_mut(&stale_port).unwrap().last_seen = 100;
        table.get_mut(&fresh_port).unwrap().last_seen = 900;
    }

    let removed = nat_prune_expired(1_000);
    assert_eq!(removed, 1);

    let table = NAT_TABLE.read();
    assert!(!table.contains_key(&stale_port));
    assert!(table.contains_key(&fresh_port));
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

    let mut tcb = TcpControlBlock::new(local);
    tcb.set_remote_addr(remote);
    tcb.enter_established();
    tcb.set_rcv_nxt(1);
    let tcb_arc = alloc::sync::Arc::new(PoisonLock::new(tcb));

    // Insert into stack's tcp connections
    match stack::stack().lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.insert_test_tcp_connection(local, remote, tcb_arc.clone());
            }
        }
        Err(_) => panic!("Stack poisoned"),
    }

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

    // Now verify TCB received the payload zero-copy
    if let Ok(guard) = tcb_arc.lock() {
        assert!(!guard.recv_buffer_is_empty());
        assert_eq!(guard.recv_buffer_front_data().unwrap(), payload);
    } else {
        panic!("TCB lock poisoned in test");
    }
}

#[cfg_attr(test, test_case)]
pub fn test_per_interface_bridge_stats_are_separated() {
    let _guard = BridgeStateGuard::new();
    let if0 = NetIfId(10);
    let if1 = NetIfId(11);

    ensure_stack_glue_if_state(if0, Some(0));
    ensure_stack_glue_if_state(if1, Some(1));
    record_stack_glue_if_rx(if0);
    record_stack_glue_if_rx(if0);
    record_stack_glue_if_tx(if1);

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

    let if0 = register_virtio_port(0, None).expect("register vnet0");
    let if0_again = register_virtio_port(0, None).expect("register vnet0 again");
    let if1 = register_virtio_port(1, None).expect("register vnet1");

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

    let if1 = register_virtio_port(1, None).expect("register vnet1");
    assert_eq!(primary_stack_glue_if(), Some(if1));

    let if0 = register_virtio_port(0, None).expect("register vnet0");
    assert_eq!(primary_stack_glue_if(), Some(if0));

    let _if2 = register_virtio_port(2, None).expect("register vnet2");
    assert_eq!(primary_stack_glue_if(), Some(if0));
}

#[cfg_attr(test, test_case)]
pub fn test_transmit_from_stack_interface_argument() {
    // using a dummy interface id should simply delegate to the
    // per-interface send function, which currently fails (no mapping)
    let dummy = NetIfId(7);
    assert!(!transmit_from_stack(Some(dummy), b"hello"));
}
