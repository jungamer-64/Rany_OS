use super::*;

fn register_operational_interface(
    runtime: crate::net::runtime::NetRuntimeHandle,
    name: &'static str,
    preference: crate::net::runtime::manager::PrimaryPreference,
    config: NetworkConfig,
) -> NetIfId {
    let if_id = crate::net::runtime::manager::register_interface_in(runtime, name, preference)
        .expect("register interface");
    crate::net::runtime::manager::set_interface_config_in(runtime, if_id, config)
        .expect("configure interface");
    crate::net::runtime::manager::set_interface_link_state_in(
        runtime,
        if_id,
        crate::net::runtime::manager::LinkState::Up,
    )
    .expect("raise interface link");
    if_id
}

fn production_stacks_converge_on_primary_and_remove_stopped_interfaces() {
    let runtime = crate::net::runtime::create_runtime().expect("isolated network runtime");
    crate::net::runtime::manager::init_network_manager_in(runtime);
    let if_a = register_operational_interface(
        runtime,
        "if-a",
        crate::net::runtime::manager::PrimaryPreference::Auto,
        NetworkConfig::default(),
    );
    let mut config_b = NetworkConfig::default();
    config_b.mac = crate::net::l2::ethernet::MacAddress::from_octets(2, 0, 0, 0, 0, 2);
    let if_b = register_operational_interface(
        runtime,
        "if-b",
        crate::net::runtime::manager::PrimaryPreference::Prefer,
        config_b,
    );

    let revision = crate::net::runtime::manager::current_interface_topology_revision_in(runtime);
    let mut stacks = core::array::from_fn::<_, 4, _>(|_| NetworkStack::new_in(runtime));
    assert!(
        stacks
            .iter()
            .all(|stack| stack.needs_interface_topology_revision(revision))
    );

    let manager_guard = runtime.context().manager.lock().expect("lock manager");
    assert!(crate::net::runtime::manager::try_interface_topology_in(runtime).is_none());
    drop(manager_guard);

    for stack in &mut stacks {
        let topology = crate::net::runtime::manager::try_interface_topology_in(runtime)
            .expect("topology snapshot");
        stack.reconcile_interface_topology(topology);
        assert!(!stack.needs_interface_topology_revision(revision));
        assert_eq!(stack.default_interface_id(), Some(if_b));
        assert!(stack.interfaces.contains_key(&if_a));
        assert!(stack.interfaces.contains_key(&if_b));
    }

    crate::net::runtime::manager::set_interface_link_state_in(
        runtime,
        if_b,
        crate::net::runtime::manager::LinkState::Down,
    )
    .expect("drop primary link");
    let failover_revision =
        crate::net::runtime::manager::current_interface_topology_revision_in(runtime);
    assert_eq!(
        crate::net::runtime::manager::primary_interface_in(runtime),
        Some(if_a)
    );

    for stack in &mut stacks {
        let topology = crate::net::runtime::manager::try_interface_topology_in(runtime)
            .expect("failover topology snapshot");
        stack.reconcile_interface_topology(topology);
        assert!(!stack.needs_interface_topology_revision(failover_revision));
        assert_eq!(stack.default_interface_id(), Some(if_a));
        assert!(stack.interfaces.contains_key(&if_a));
        assert!(!stack.interfaces.contains_key(&if_b));
    }
}

fn identical_topology_snapshot_preserves_interface_protocol_state() {
    let runtime = crate::net::runtime::create_runtime().expect("isolated network runtime");
    crate::net::runtime::manager::init_network_manager_in(runtime);
    let mut config = NetworkConfig::default();
    config.ipv6 = Some(crate::net::l3::ipv6::Ipv6Config::default());
    let if_id = register_operational_interface(
        runtime,
        "if-state",
        crate::net::runtime::manager::PrimaryPreference::Auto,
        config,
    );
    let mut stack = NetworkStack::new_in(runtime);
    stack.reconcile_interface_topology(
        crate::net::runtime::manager::try_interface_topology_in(runtime)
            .expect("initial topology snapshot"),
    );

    let neighbor = crate::net::l3::ipv6::Ipv6Address::new([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
    ]);
    stack.ndp_cache_insert_on(if_id, &neighbor, [1, 2, 3, 4, 5, 6], 42);
    assert!(
        stack.interfaces[&if_id]
            .ndp
            .as_ref()
            .expect("NDP processor")
            .cache()
            .lookup(&neighbor)
            .is_some()
    );

    stack.reconcile_interface_topology(
        crate::net::runtime::manager::try_interface_topology_in(runtime)
            .expect("identical topology snapshot"),
    );
    assert!(
        stack.interfaces[&if_id]
            .ndp
            .as_ref()
            .expect("preserved NDP processor")
            .cache()
            .lookup(&neighbor)
            .is_some()
    );
}

fn timeout_retries_after_queue_loss_and_manager_contention() {
    use crate::net::runtime::command::{ControlCommand, RuntimeCommand};

    let runtime = crate::net::runtime::create_runtime().expect("isolated network runtime");
    crate::net::runtime::manager::init_network_manager_in(runtime);
    let if_id = register_operational_interface(
        runtime,
        "if-retry",
        crate::net::runtime::manager::PrimaryPreference::Auto,
        NetworkConfig::default(),
    );
    let mut stack = NetworkStack::new_in(runtime);
    stack.reconcile_interface_topology(
        crate::net::runtime::manager::try_interface_topology_in(runtime)
            .expect("initial topology snapshot"),
    );

    let mut changed = NetworkConfig::default();
    changed.icmp_echo_enabled = false;
    crate::net::runtime::manager::set_interface_config_in(runtime, if_id, changed)
        .expect("change interface configuration");
    let changed_revision =
        crate::net::runtime::manager::current_interface_topology_revision_in(runtime);
    assert!(stack.needs_interface_topology_revision(changed_revision));

    let queue = crate::net::runtime::command::command_resources_for_cpu_in(
        runtime,
        crate::cpu::CurrentCpu::acquire()
            .expect("topology retry CPU")
            .id(),
    )
    .expect("current CPU command resources")
    .command_queue
    .clone();
    // LOOP_PROOF: mode=condition; reason=This isolated fixture has no producers and each recv removes one command from the bounded queue until empty.;
    while queue.recv().is_some() {}
    for _ in 0..crate::net::runtime::command::NETWORK_EVENT_QUEUE_CAPACITY {
        assert!(queue.send(RuntimeCommand::Control(
            ControlCommand::ProcessGlobalTimeouts,
        )));
    }
    stack.process_timeouts();
    assert!(stack.needs_interface_topology_revision(changed_revision));
    // LOOP_PROOF: mode=condition; reason=The fixture has stopped producing commands and recv drains at most the queue capacity before returning None.;
    while queue.recv().is_some() {}

    stack.process_timeouts();
    let dirty = queue.recv().expect("timeout retry command");
    let manager_guard = runtime.context().manager.lock().expect("lock manager");
    assert!(matches!(
        crate::net::runtime::command_handler::RuntimeCommandHandler::new()
            .handle_event_with_stack_in(runtime, dirty, &mut stack),
        crate::net::runtime::command_handler::EventHandleResult::Success
    ));
    assert!(stack.needs_interface_topology_revision(changed_revision));
    drop(manager_guard);

    stack.process_timeouts();
    let dirty = queue.recv().expect("contention retry command");
    assert!(matches!(
        crate::net::runtime::command_handler::RuntimeCommandHandler::new()
            .handle_event_with_stack_in(runtime, dirty, &mut stack),
        crate::net::runtime::command_handler::EventHandleResult::Success
    ));
    assert!(!stack.needs_interface_topology_revision(changed_revision));
    assert_eq!(stack.interface_config(if_id), Some(changed));
}

fn ipv4_pmtu_remains_available_with_echo_disabled() {
    use crate::net::l3::icmp::DestUnreachCode;
    use crate::net::l3::ipv4::{IpProtocol, data_checksum};
    use crate::net::l4::socket::{Socket, bind_udp_dual_stack_in};
    use crate::net::payload::GeneratedPacketWriter;
    use crate::net::types::InterfaceScope;
    use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

    let runtime = crate::net::runtime::create_runtime().expect("isolated ICMP runtime");
    crate::net::runtime::manager::init_network_manager_in(runtime);
    let mut config = NetworkConfig::default();
    config.icmp_echo_enabled = false;
    let local = Ipv4Address::new([192, 0, 2, 2]);
    let remote = Ipv4Address::new([198, 51, 100, 2]);
    let router = Ipv4Address::new([192, 0, 2, 1]);
    config.ipv4.address = local;
    let if_id = register_operational_interface(
        runtime,
        "icmp-pmtu",
        crate::net::runtime::manager::PrimaryPreference::Auto,
        config,
    );
    let mut stack = NetworkStack::new_in(runtime);
    stack.refresh_interface_topology();

    let socket = Socket::new_udp_in(runtime);
    let local_port = 50_000u16;
    bind_udp_dual_stack_in(
        runtime,
        local_port,
        InterfaceScope::Pinned(if_id),
        socket.socket_id(),
    )
    .expect("bind quoted UDP flow");
    let mut message = [0u8; 36];
    message[0] = 3;
    message[1] = DestUnreachCode::FragmentationNeeded as u8;
    message[6..8].copy_from_slice(&1200u16.to_be_bytes());
    message[8] = 0x45;
    message[10..12].copy_from_slice(&1500u16.to_be_bytes());
    message[14] = 0x40;
    message[16] = 64;
    message[17] = IpProtocol::Udp.into();
    message[20..24].copy_from_slice(local.as_bytes());
    message[24..28].copy_from_slice(remote.as_bytes());
    message[28..30].copy_from_slice(&local_port.to_be_bytes());
    let quoted_checksum = data_checksum(&message[8..28], 0);
    message[18..20].copy_from_slice(&quoted_checksum.to_be_bytes());
    let checksum = data_checksum(&message, 0);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());

    let mut writer =
        GeneratedPacketWriter::new(message.len(), DEFAULT_PACKET_HEADROOM).expect("ICMP packet");
    writer.write_generated_bytes(&message).expect("ICMP bytes");
    stack.process_icmp_payload(
        runtime,
        if_id,
        writer.finish().expect("ICMP payload"),
        router,
        local,
        64,
        1,
    );
    assert_eq!(
        stack
            .interfaces
            .get_mut(&if_id)
            .expect("IPv4 interface")
            .ipv4
            .get_pmtu(remote, 1),
        1200
    );
}

fn ipv6_router_advertisement_reaches_route_lookup_and_peer_stacks() {
    use crate::net::l3::ipv6::Ipv6Config;
    use crate::net::payload::GeneratedPacketWriter;
    use crate::net::runtime::manager::{self, PrimaryPreference};
    use crate::net::types::InterfaceScope;
    use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

    let runtime = crate::net::runtime::create_runtime().expect("isolated IPv6 runtime");
    manager::init_network_manager_in(runtime);
    let mut config = NetworkConfig::default();
    config.ipv6 = Some(Ipv6Config::default());
    let if_id = register_operational_interface(runtime, "slaac", PrimaryPreference::Auto, config);
    let mut ingress = NetworkStack::new_in(runtime);
    let mut peer_stack = NetworkStack::new_in(runtime);
    ingress.refresh_interface_topology();
    peer_stack.refresh_interface_topology();

    let router = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let prefix = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let remote = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let mut advertisement = [0; 48];
    advertisement[0] = Icmpv6Type::RouterAdvertisement.into();
    advertisement[6..8].copy_from_slice(&30u16.to_be_bytes());
    advertisement[16..20].copy_from_slice(&[3, 4, 64, 0xc0]);
    advertisement[20..24].copy_from_slice(&120u32.to_be_bytes());
    advertisement[24..28].copy_from_slice(&60u32.to_be_bytes());
    advertisement[32..48].copy_from_slice(prefix.as_bytes());
    let mut writer = GeneratedPacketWriter::new(advertisement.len(), DEFAULT_PACKET_HEADROOM)
        .expect("RA packet");
    writer
        .write_generated_bytes(&advertisement)
        .expect("RA bytes");
    ingress.process_ndp_message(
        runtime,
        if_id,
        Icmpv6Type::RouterAdvertisement,
        writer.finish().expect("RA payload"),
        router,
        Ipv6Address::ALL_NODES_LINK_LOCAL,
        MacAddress::ZERO,
        255,
        1000,
    );

    assert_eq!(
        manager::resolve_ipv6_path_in(runtime, InterfaceScope::Any, remote),
        Ok(manager::Ipv6Path {
            if_id,
            next_hop: router
        }),
    );
    peer_stack.refresh_interface_topology();
    let learned = peer_stack
        .interface_config(if_id)
        .and_then(|config| config.ipv6)
        .expect("peer stack IPv6 topology");
    let address = Ipv6Address::from_prefix_eui64(&prefix, config.mac.as_bytes());
    assert!(learned.addresses.assigned().next().is_none());
    assert!(learned.addresses.for_destination(address.solicited_node()));
    assert!(!learned.addresses.for_destination(address));
}

fn complete_probe(
    _: NetRuntimeHandle,
    _: NetIfId,
    frame: TxFrame,
    meta: kernel_api::service::netdev::NetTxMeta,
) -> Result<(), crate::net::runtime::device::TxAdmissionError> {
    use crate::net::runtime::device::tx::NetPortTx;
    use kernel_api::service::netdev::TxDeviceOutcome;
    let tx = NetPortTx::new(4, 1).expect("fake port TX");
    tx.admit(frame, meta)?;
    let mut scratch = Vec::new();
    let (lease, _) = tx
        .begin_submission(0, &mut scratch)
        .expect("admitted DAD probe");
    tx.finish_submission(lease, true, &mut scratch);
    tx.complete(lease, TxDeviceOutcome::Transmitted)
        .expect("DAD TX completion");
    Ok(())
}

fn ipv6_udp_waits_for_the_gateway_and_preserves_the_ip_destination() {
    use crate::net::l3::ipv6::Ipv6Config;
    use crate::net::l3::ipv6::address_state::AddressLifetimes;
    use crate::net::l4::udp::UdpPorts;
    use crate::net::payload::{GeneratedPacketWriter, PacketPayloadView};
    use crate::net::runtime::device::{TxAdmissionError, TxFrame};
    use crate::net::runtime::manager::{self, PrimaryPreference};
    use crate::net::types::InterfaceScope;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use kernel_api::service::netdev::NetTxMeta;

    const ROUTER: Ipv6Address =
        Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    const ROUTER_MAC: [u8; 6] = [2, 4, 6, 8, 10, 12];
    const SOURCE: Ipv6Address =
        Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);
    const DESTINATION: Ipv6Address =
        Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
    static DATAGRAMS: AtomicUsize = AtomicUsize::new(0);
    static SOLICITATIONS: AtomicUsize = AtomicUsize::new(0);

    fn capture(
        _: NetRuntimeHandle,
        _: NetIfId,
        frame: TxFrame,
        _: NetTxMeta,
    ) -> Result<(), TxAdmissionError> {
        let (header, body) = frame.into_parts();
        let packet = header
            .as_ref()
            .map_or_else(
                || PacketPayloadView::new(body.payload()).read_array::<54>(0),
                |header| {
                    header
                        .data()
                        .get(..54)
                        .and_then(|bytes| bytes.try_into().ok())
                },
            )
            .expect("Ethernet and IPv6 header");
        assert_eq!(&packet[12..14], &[0x86, 0xdd]);
        match packet[20] {
            58 => {
                assert_eq!(&packet[38..54], ROUTER.solicited_node().as_bytes());
                SOLICITATIONS.fetch_add(1, Ordering::Relaxed);
            }
            17 => {
                assert_eq!(&packet[..6], &ROUTER_MAC);
                assert_eq!(&packet[22..38], SOURCE.as_bytes());
                assert_eq!(&packet[38..54], DESTINATION.as_bytes());
                DATAGRAMS.fetch_add(1, Ordering::Relaxed);
            }
            protocol => panic!("unexpected IPv6 protocol {protocol}"),
        }
        Ok(())
    }

    let runtime = crate::net::runtime::create_runtime().expect("isolated IPv6 runtime");
    manager::init_network_manager_in(runtime);
    let mut config = NetworkConfig::default();
    config.ipv6 = Some(Ipv6Config::default());
    let if_id =
        register_operational_interface(runtime, "ipv6-egress", PrimaryPreference::Auto, config);
    manager::set_default_route_v6_in(runtime, if_id, ROUTER, 10).expect("default route");
    manager::stage_dhcp_ipv6_in(
        runtime,
        if_id,
        SOURCE,
        AddressLifetimes::new(0, 60, 60).unwrap(),
        0,
    )
    .expect("stage address");
    let mut stack = NetworkStack::new_in(runtime);
    stack.transmit_fn = complete_probe;
    stack
        .maintain_ipv6_addresses(0)
        .expect("admit the DAD probe");
    let assigned = |stack: &NetworkStack| {
        stack
            .interface_config(if_id)
            .unwrap()
            .ipv6
            .unwrap()
            .addresses
            .source()
    };
    assert_eq!(assigned(&stack), None);
    assert_eq!(manager::assigned_ipv6_link_local_in(runtime, if_id), None);
    let now = crate::task::current_tick();
    stack.maintain_ipv6_addresses(now + 1000).unwrap();
    assert_eq!(assigned(&stack), Some(SOURCE));
    assert!(
        stack
            .interface_config(if_id)
            .unwrap()
            .ipv6
            .unwrap()
            .addresses
            .link_local()
            .is_some()
    );
    stack.transmit_fn = capture;
    stack.update_time(now + 1000);
    SOLICITATIONS.store(0, Ordering::Relaxed);

    let mut writer =
        GeneratedPacketWriter::new(4, kernel_api::resource::net::DEFAULT_PACKET_HEADROOM)
            .expect("UDP payload");
    writer.write_generated_bytes(b"data").unwrap();
    DATAGRAMS.store(0, Ordering::Relaxed);
    assert_eq!(
        stack.send_udp_v6_payload(
            InterfaceScope::Any,
            Ipv6Address::UNSPECIFIED,
            DESTINATION,
            UdpPorts::new(5000, 5001),
            writer.finish().unwrap(),
            64,
        ),
        Ok(()),
    );
    assert_eq!(DATAGRAMS.load(Ordering::Relaxed), 0);
    assert_eq!(SOLICITATIONS.load(Ordering::Relaxed), 1);
    stack.update_time(now + 1999);
    stack.process_timeouts();
    assert_eq!(SOLICITATIONS.load(Ordering::Relaxed), 1);
    stack.update_time(now + 2000);
    stack.process_timeouts();
    assert_eq!(SOLICITATIONS.load(Ordering::Relaxed), 2);
    stack.ndp_cache_insert_on(if_id, &ROUTER, ROUTER_MAC, now + 2000);
    stack.drain_ndp_pending_on(if_id, &ROUTER);
    stack.drain_ndp_pending_on(if_id, &ROUTER);
    assert_eq!(DATAGRAMS.load(Ordering::Relaxed), 1);
    let link_local = Ipv6Address::from_eui64(config.mac.as_bytes());
    assert_eq!(
        manager::assigned_ipv6_link_local_in(runtime, if_id),
        Some(link_local)
    );
    manager::set_interface_link_state_in(runtime, if_id, manager::LinkState::Down).unwrap();
    manager::set_interface_link_state_in(runtime, if_id, manager::LinkState::Up).unwrap();
    assert_eq!(manager::assigned_ipv6_link_local_in(runtime, if_id), None);
}

fn reassembled_ipv6_uses_extension_header_transport_window() {
    use crate::net::l3::ipv6::{Ipv6Config, ipv6_pseudo_header_checksum};
    use crate::net::l4::socket::{Socket, bind_udp_dual_stack_in};
    use crate::net::payload::{GeneratedPacketWriter, PacketPayloadView};
    use crate::net::runtime::command::{IngressCommand, RuntimeCommand};
    use crate::net::runtime::manager::{self, PrimaryPreference};
    use crate::net::security::firewall::{
        FirewallAction, FirewallDirection, FirewallRule, PortMatch, add_rule_in,
        set_default_policy_in,
    };
    use crate::net::types::InterfaceScope;
    use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

    let runtime = crate::net::runtime::create_runtime().expect("isolated IPv6 ingress runtime");
    manager::init_network_manager_in(runtime);
    let mut config = NetworkConfig::default();
    let ipv6 = Ipv6Config::default();
    config.ipv6 = Some(ipv6);
    let if_id =
        register_operational_interface(runtime, "ipv6-ingress", PrimaryPreference::Auto, config);
    let mut stack = NetworkStack::new_in(runtime);
    stack.transmit_fn = complete_probe;
    stack
        .maintain_ipv6_addresses(0)
        .expect("probe link-local address");
    stack
        .maintain_ipv6_addresses(crate::task::current_tick() + 1000)
        .expect("assign link-local address");
    let socket = Socket::new_udp_in(runtime);
    let dst_port = 30_001u16;
    bind_udp_dual_stack_in(
        runtime,
        dst_port,
        InterfaceScope::Pinned(if_id),
        socket.socket_id(),
    )
    .expect("bind IPv6 destination port");
    set_default_policy_in(runtime, FirewallDirection::Ingress, FirewallAction::Deny)
        .expect("require an explicit allow rule");
    add_rule_in(
        runtime,
        FirewallRule::builder()
            .ingress()
            .udp()
            .dst_port(PortMatch::Exact(dst_port))
            .allow()
            .build(),
    )
    .expect("allow destination port");

    let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst = Ipv6Address::from_eui64(config.mac.as_bytes());
    let mut packet = [0; 60];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&20u16.to_be_bytes());
    packet[6] = 60; // Destination Options
    packet[7] = 64;
    packet[8..24].copy_from_slice(src.as_bytes());
    packet[24..40].copy_from_slice(dst.as_bytes());
    packet[40] = 17;
    packet[48..50].copy_from_slice(&30_000u16.to_be_bytes());
    packet[50..52].copy_from_slice(&dst_port.to_be_bytes());
    packet[52..54].copy_from_slice(&12u16.to_be_bytes());
    packet[56..60].copy_from_slice(b"data");
    let sum = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Udp, 12);
    let checksum = crate::net::l3::ipv4::data_checksum(&packet[48..], sum);
    packet[54..56].copy_from_slice(&checksum.to_be_bytes());

    let mut writer = GeneratedPacketWriter::new(packet.len(), DEFAULT_PACKET_HEADROOM)
        .expect("reassembled IPv6 packet");
    writer.write_generated_bytes(&packet).expect("IPv6 bytes");
    let offset =
        kernel_api::resource::net::PacketByteCount::new(41).expect("header segment offset");
    let kernel_api::resource::net::PacketPayloadFront::Prefix { front, remainder } = writer
        .finish()
        .expect("IPv6 payload")
        .try_take_front(offset)
        .expect("split across Destination Options header")
    else {
        panic!("the extension header must cross packet segments");
    };
    let payload = front.try_append(remainder).expect("segmented IPv6 payload");
    let handler = crate::net::runtime::command_handler::RuntimeCommandHandler::new();
    let _ = handler.handle_event_with_stack_in(
        runtime,
        RuntimeCommand::Ingress(IngressCommand::Reassembled { if_id, payload }),
        &mut stack,
    );
    let (received_if, _, _, payload) = socket.try_recv_udp_payload().expect("allowed UDP delivery");
    assert_eq!(received_if, if_id);
    assert_eq!(
        PacketPayloadView::new(&payload).read_array::<4>(0),
        Some(*b"data")
    );
}

pub(crate) fn interface_topology() -> bool {
    production_stacks_converge_on_primary_and_remove_stopped_interfaces();
    identical_topology_snapshot_preserves_interface_protocol_state();
    timeout_retries_after_queue_loss_and_manager_contention();
    ipv4_pmtu_remains_available_with_echo_disabled();
    ipv6_router_advertisement_reaches_route_lookup_and_peer_stacks();
    ipv6_udp_waits_for_the_gateway_and_preserves_the_ip_destination();
    reassembled_ipv6_uses_extension_header_transport_window();
    true
}
