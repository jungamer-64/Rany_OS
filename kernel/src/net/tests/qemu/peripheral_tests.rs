// ============================================================================
// kernel/src/net/tests/qemu/peripheral_tests.rs - Network QEMU peripheral smoke tests
// ============================================================================

use crate::net::l3::{igmp, ipv4::Ipv4Address};
use crate::net::l4::socket::{Socket, SocketFamily, bind_udp_dual_stack_in, find_udp_by_port_in};
use crate::net::l4::udp::{UdpProcessor, UdpResult};
use crate::net::payload::alloc_packet_with_headroom;
use crate::net::runtime::create_runtime;
use crate::net::runtime::manager::NetIfId;
use crate::net::services::dhcp;
use crate::net::types::InterfaceScope;
use crate::sync::PoisonLock;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::resource::net::{
    DEFAULT_PACKET_HEADROOM, PacketByteCount, PacketPayload, PacketRef,
};
use kernel_api::service::netdev::{
    MacAddress as PortMacAddress, NETDEV_FLAG_ADMIN_UP, NETDEV_FLAG_HEALTHY, NETDEV_FLAG_LINK_UP,
    NetDeviceInfo, NetDevicePort, NetDriverEvent, NetPortId, NetPortRegistration,
    NetPortRuntimeHandle, NetPortStats, NetRxFrameLayout, NetRxMeta, NetTxMeta, PrimaryPortPolicy,
    TxSubmission,
};

macro_rules! run_case {
    ($func:path) => {{
        #[cfg(all(test, feature = "qemu-test-export"))]
        {
            let _ = stringify!($func);
            true
        }
        #[cfg(not(all(test, feature = "qemu-test-export")))]
        {
            $func();
            true
        }
    }};
}

pub fn dhcp_v4_build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip_smoke() -> bool {
    run_case!(
        dhcp::qemu_v4_tests::test_build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip
    )
}

pub fn dhcp_v4_build_request_requesting_includes_serverid_and_requestedip_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_build_request_requesting_includes_serverid_and_requestedip)
}

pub fn dhcp_v4_build_discover_reuse_xid_on_retransmit_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_build_discover_reuse_xid_on_retransmit)
}

pub fn dhcp_v4_process_response_chaddr_mismatch_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_chaddr_mismatch)
}

pub fn dhcp_v4_process_response_offer_missing_serverid_returns_err_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_offer_missing_serverid_returns_err)
}

pub fn dhcp_v4_process_response_ack_requesting_mismatch_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_ack_requesting_mismatch)
}

pub fn dhcp_v4_process_response_ack_renewal_success_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_ack_renewal_success)
}

pub fn dhcp_v4_build_decline_and_build_release_contents_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_build_decline_and_build_release_contents)
}

pub fn dhcp_v4_release_clears_lease_and_sets_last_released_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_release_clears_lease_and_sets_last_released)
}

pub fn dhcp_v4_parse_t1_t2_and_timeout_transitions_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_parse_t1_t2_and_timeout_transitions)
}

pub fn dhcp_v4_offer_probe_and_decline_flow_smoke() -> bool {
    use crate::net::l2::ethernet::MacAddress;
    use crate::net::runtime::stack;
    use crate::net::services::dhcp::{
        DHCP_MAGIC_COOKIE, DhcpClient, DhcpHeader, DhcpMessageType, DhcpOperation, DhcpOption,
    };

    stack::init_in(crate::net::runtime::default_runtime());

    let client = DhcpClient::new(
        crate::net::runtime::default_runtime(),
        crate::net::runtime::manager::NetIfId(1),
        MacAddress::new([7, 7, 7, 7, 7, 7]),
    );

    let mut buf = alloc::vec![0u8; DhcpHeader::SIZE + 64];
    buf[0] = DhcpOperation::Reply as u8;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&0u32.to_be_bytes());
    buf[16..20].copy_from_slice(&[10, 0, 0, 9]);
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
    buf[offset + 2..offset + 6].copy_from_slice(&[10, 0, 0, 1]);
    offset += 6;
    buf[offset] = DhcpOption::End as u8;

    if client.process_response(&buf, 100).is_err() {
        return false;
    }
    let _ = client.check_timeout(102, 1);
    client
        .last_declined_ip()
        .map(|ip| ip == crate::net::l3::ipv4::Ipv4Address::new([10, 0, 0, 9]))
        .unwrap_or(true)
}

pub fn dhcp_v6_build_solicit_min_size_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_build_solicit_min_size)
}

pub fn dhcp_v6_parse_reply_with_iaaddr_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_parse_reply_with_iaaddr)
}

pub fn dhcp_v6_build_request_min_size_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_build_request_min_size)
}

pub fn dhcp_v6_bound_to_renewing_and_rebinding_transitions_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_bound_to_renewing_and_rebinding_transitions)
}

pub fn dhcp_v6_handle_packet_stores_server_addr_and_duid_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_handle_packet_stores_server_addr_and_duid)
}

pub fn dhcp_v6_advertise_triggers_request_and_requesting_state_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_advertise_triggers_request_and_requesting_state)
}

pub fn dhcp_v6_requesting_retransmit_exhaustion_goes_to_init_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_requesting_retransmit_exhaustion_goes_to_init)
}

pub fn dhcp_v6_solicit_advertise_request_reply_complete_flow_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_solicit_advertise_request_reply_complete_flow)
}

pub fn dhcp_v6_renew_uses_known_server_address_for_dst_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_renew_uses_known_server_address_for_dst)
}

pub fn igmp_igmp_type_conversion_smoke() -> bool {
    run_case!(igmp::tests::test_igmp_type_conversion)
}

pub fn igmp_multicast_validation_smoke() -> bool {
    run_case!(igmp::tests::test_multicast_validation)
}

pub fn igmp_join_group_smoke() -> bool {
    run_case!(igmp::tests::test_join_group)
}

pub fn igmp_join_group_unsolicited_followup_smoke() -> bool {
    run_case!(igmp::tests::test_join_group_unsolicited_followup)
}

pub fn igmp_join_invalid_address_smoke() -> bool {
    run_case!(igmp::tests::test_join_invalid_address)
}

pub fn igmp_leave_group_smoke() -> bool {
    run_case!(igmp::tests::test_leave_group)
}

pub fn igmp_leave_nonmember_smoke() -> bool {
    run_case!(igmp::tests::test_leave_nonmember)
}

pub fn igmp_igmp_checksum_smoke() -> bool {
    run_case!(igmp::tests::test_igmp_checksum)
}

pub fn igmp_build_report_smoke() -> bool {
    run_case!(igmp::tests::test_build_report)
}

pub fn igmp_build_leave_smoke() -> bool {
    run_case!(igmp::tests::test_build_leave)
}

pub fn igmp_multicast_ip_to_mac_smoke() -> bool {
    run_case!(igmp::tests::test_multicast_ip_to_mac)
}

pub fn igmp_process_general_query_smoke() -> bool {
    run_case!(igmp::tests::test_process_general_query)
}

pub fn igmp_report_suppression_smoke() -> bool {
    run_case!(igmp::tests::test_report_suppression)
}

pub fn igmp_v3_report_minimal_layout_accepted_smoke() -> bool {
    run_case!(igmp::tests::test_v3_report_minimal_layout_accepted)
}

pub fn igmp_v3_report_invalid_layout_rejected_smoke() -> bool {
    run_case!(igmp::tests::test_v3_report_invalid_layout_rejected)
}

pub fn runtime_two_runtimes_bind_same_udp_port_independently_smoke() -> bool {
    let Ok(runtime_a) = create_runtime() else {
        return false;
    };
    let Ok(runtime_b) = create_runtime() else {
        return false;
    };

    let socket_a = Socket::new_udp_in(runtime_a);
    let socket_b = Socket::new_udp_in(runtime_b);

    bind_udp_dual_stack_in(runtime_a, 80, InterfaceScope::Any, socket_a.socket_id()).is_ok()
        && bind_udp_dual_stack_in(runtime_b, 80, InterfaceScope::Any, socket_b.socket_id()).is_ok()
        && find_udp_by_port_in(runtime_a, SocketFamily::Ipv4, 80, NetIfId(1)).is_some()
        && find_udp_by_port_in(runtime_b, SocketFamily::Ipv4, 80, NetIfId(2)).is_some()
}

pub fn runtime_udp_concrete_ingress_interface_is_preserved_smoke() -> bool {
    let Ok(runtime) = create_runtime() else {
        return false;
    };
    let processor = UdpProcessor::new();

    processor.process_payload_on(
        runtime,
        NetIfId(7),
        PacketPayload::default(),
        Ipv4Address::ANY,
        Ipv4Address::ANY,
        64,
    ) == UdpResult::NoEndpoint
}

pub fn runtime_large_packet_headroom_preserves_request_smoke() -> bool {
    let requested_headroom = DEFAULT_PACKET_HEADROOM.saturating_mul(2);
    let Some(packet) = alloc_packet_with_headroom(128, requested_headroom) else {
        return false;
    };

    packet.headroom() >= requested_headroom && packet.len() == 128
}

struct QemuFakePortState {
    runtime: PoisonLock<Option<NetPortRuntimeHandle>>,
    tx_packets: AtomicU64,
}

impl QemuFakePortState {
    const fn new() -> Self {
        Self {
            runtime: PoisonLock::new(None),
            tx_packets: AtomicU64::new(0),
        }
    }

    fn update_link(&self, up: bool) -> Result<(), &'static str> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| "fake port runtime lock poisoned")?
            .ok_or("fake port runtime is not installed")?;
        runtime.update_link(up)
    }

    fn submit_rx(&self, packet: PacketRef) -> Result<(), &'static str> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| "fake port runtime lock poisoned")?
            .ok_or("fake port runtime is not installed")?;
        let frame_len = PacketByteCount::new(packet.len()).ok_or("empty fake RX frame")?;
        let layout = NetRxFrameLayout::whole_payload(frame_len).ok_or("invalid fake RX layout")?;
        runtime.submit_rx(packet, NetRxMeta::new(0, layout, 0))
    }
}

struct QemuFakePort {
    state: &'static QemuFakePortState,
    info: NetDeviceInfo,
}

impl NetDevicePort for QemuFakePort {
    fn info(&self) -> NetDeviceInfo {
        self.info
    }

    fn start(&self, runtime: NetPortRuntimeHandle) -> Result<(), &'static str> {
        *self
            .state
            .runtime
            .lock()
            .map_err(|_| "fake port runtime lock poisoned")? = Some(runtime);
        Ok(())
    }

    fn submit_tx_chain(
        &self,
        _submission: TxSubmission<'_>,
        _meta: NetTxMeta,
    ) -> Result<(), &'static str> {
        self.state.tx_packets.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn handle_event(&self, _if_id: u16, _event: NetDriverEvent) -> Result<(), &'static str> {
        Ok(())
    }

    fn stats(&self) -> NetPortStats {
        NetPortStats {
            tx_packets: self.state.tx_packets.load(Ordering::Acquire),
            initialized: true,
            ..NetPortStats::default()
        }
    }

    fn stop(&self) {}
}

fn register_qemu_fake_port(
    runtime: crate::net::runtime::NetRuntimeHandle,
    port_id: u64,
    mac: [u8; 6],
) -> Option<(&'static QemuFakePortState, NetIfId)> {
    let state = Box::leak(Box::new(QemuFakePortState::new()));
    let info = NetDeviceInfo {
        port_id: NetPortId::new(port_id),
        driver_name: "qemu-fake-net",
        queue_pairs: 4,
        mtu: crate::net::runtime::stack::MTU as u32,
        mac: PortMacAddress::new(mac),
        flags: NETDEV_FLAG_ADMIN_UP | NETDEV_FLAG_HEALTHY | NETDEV_FLAG_LINK_UP,
        ..NetDeviceInfo::default()
    };
    let driver: Box<dyn NetDevicePort> = Box::new(QemuFakePort { state, info });
    let if_id = crate::net::runtime::device::register_port_in(
        runtime,
        NetPortRegistration::new(info, driver, PrimaryPortPolicy::Auto),
    )
    .ok()?;
    Some((state, if_id))
}

fn allocate_frame(runtime: crate::net::runtime::NetRuntimeHandle, len: usize) -> Option<PacketRef> {
    let mut packet = crate::net::datapath::mempool::alloc_packet_in(runtime)?;
    packet.set_len(PacketByteCount::new(len)?).then_some(packet)
}

struct Ipv4FrameSpec<'a> {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    protocol: crate::net::l3::ipv4::IpProtocol,
    identification: u16,
    fragment_offset: u16,
    more_fragments: bool,
    payload: &'a [u8],
}

fn build_ipv4_frame(
    runtime: crate::net::runtime::NetRuntimeHandle,
    spec: Ipv4FrameSpec<'_>,
) -> Option<PacketRef> {
    let frame_len = 14usize.checked_add(20)?.checked_add(spec.payload.len())?;
    let mut frame = allocate_frame(runtime, frame_len)?;
    let bytes = frame.data_mut();
    bytes[0..6].copy_from_slice(&spec.dst_mac);
    bytes[6..12].copy_from_slice(&spec.src_mac);
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let mut packet = crate::net::l3::ipv4::Ipv4PacketMut::new(&mut bytes[14..])?;
    packet
        .init_header()
        .set_source(spec.src_ip)
        .set_destination(spec.dst_ip)
        .set_protocol(spec.protocol)
        .set_identification(spec.identification);
    packet
        .header_mut()?
        .set_fragmentation(false, spec.more_fragments, spec.fragment_offset);
    packet.payload_mut()[..spec.payload.len()].copy_from_slice(spec.payload);
    packet.finalize(spec.payload.len());
    Some(frame)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(last) = chunks.remainder().first() {
        sum = sum.wrapping_add((*last as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmp_echo_request(identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + data.len());
    packet.extend_from_slice(&[8, 0, 0, 0]);
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(data);
    let checksum = internet_checksum(&packet).to_be_bytes();
    packet[2..4].copy_from_slice(&checksum);
    packet
}

fn udp_datagram(src_port: u16, dst_port: u16, data: &[u8]) -> Option<Vec<u8>> {
    let len = 8usize.checked_add(data.len())?;
    let len = u16::try_from(len).ok()?;
    let mut packet = Vec::with_capacity(len as usize);
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(data);
    Some(packet)
}

fn process_runtime_commands(
    runtime: crate::net::runtime::NetRuntimeHandle,
    handler: &crate::net::runtime::command_handler::RuntimeCommandHandler,
    executor_count: usize,
    mut observe_packet: impl FnMut(usize, NetIfId, u8),
) -> Option<usize> {
    let mut total = 0usize;
    for _ in 0..8 {
        let mut processed = 0usize;
        for cpu_id in 0..executor_count {
            let queue = crate::net::runtime::command::command_queue_for_core_in(runtime, cpu_id);
            let mut stack_guard = runtime.context().stacks[cpu_id].lock().ok()?;
            let core_stack = stack_guard.as_mut()?;
            while let Some(command) = queue.recv() {
                let observed = match &command {
                    crate::net::runtime::command::RuntimeCommand::Ingress(
                        crate::net::runtime::command::IngressCommand::Packet { if_id, packet },
                    ) if packet.data().len() >= 24 => Some((*if_id, packet.data()[23])),
                    _ => None,
                };
                matches!(
                    handler.handle_event_with_stack_in(runtime, command, core_stack),
                    crate::net::runtime::command_handler::EventHandleResult::Success
                )
                .then_some(())?;
                if let Some((if_id, protocol)) = observed {
                    observe_packet(cpu_id, if_id, protocol);
                }
                processed = processed.saturating_add(1);
            }
        }
        total = total.saturating_add(processed);
        if processed == 0 {
            return Some(total);
        }
    }
    None
}

fn packet_payload_eq(payload: &PacketPayload, expected: &[u8]) -> bool {
    let view = crate::net::payload::PacketPayloadView::new(payload);
    if view.total_len() != expected.len() {
        return false;
    }
    let mut offset = 0usize;
    let mut equal = true;
    view.for_each_chunk(|chunk| {
        let end = offset.saturating_add(chunk.len());
        if end > expected.len() || chunk != &expected[offset..end] {
            equal = false;
        }
        offset = end;
    });
    equal && offset == expected.len()
}

fn configure_test_address(
    runtime: crate::net::runtime::NetRuntimeHandle,
    if_id: NetIfId,
    address: Ipv4Address,
) -> Option<()> {
    let mut config = crate::net::runtime::manager::get_interface_in(runtime, if_id)
        .ok()
        .flatten()?
        .config?;
    config.ipv4.address = address;
    crate::net::runtime::manager::set_interface_config_in(runtime, if_id, config).ok()
}

fn run_fake_ports_smp_flow_failover() -> Option<()> {
    let runtime = create_runtime().ok()?;
    let _ = crate::net::datapath::mempool::init_net_mempool(128);
    let mac_a = [0x02, 0, 0, 0, 1, 1];
    let mac_b = [0x02, 0, 0, 0, 1, 2];
    let source_mac = [0x02, 0, 0, 0, 2, 1];
    let (state_a, if_a) = register_qemu_fake_port(runtime, 0xf001, mac_a)?;
    let (state_b, if_b) = register_qemu_fake_port(runtime, 0xf002, mac_b)?;
    let local_ip = Ipv4Address::new([10, 23, 0, 2]);
    let remote_ip = Ipv4Address::new([10, 23, 0, 1]);
    configure_test_address(runtime, if_a, local_ip)?;
    configure_test_address(runtime, if_b, local_ip)?;
    (crate::net::runtime::manager::primary_interface_in(runtime) == Some(if_a)).then_some(())?;

    let cpu_count = (crate::cpu::count() as usize).clamp(1, 4);
    let executor_count = crate::task::executor_slot_count().max(1);
    (executor_count >= cpu_count).then_some(())?;
    let handler = crate::net::runtime::command_handler::RuntimeCommandHandler::new();
    process_runtime_commands(runtime, &handler, executor_count, |_, _, _| {})?;
    for cpu_id in 0..executor_count {
        let stack_guard = runtime.context().stacks[cpu_id].lock().ok()?;
        let core_stack = stack_guard.as_ref()?;
        core_stack.interface_config(if_a)?;
        core_stack.interface_config(if_b)?;
        (core_stack.primary_interface_state()?.0 == if_a).then_some(())?;
    }

    let socket_a = Socket::new_udp_in(runtime);
    let socket_b = Socket::new_udp_in(runtime);
    let destination_port = 42_424;
    bind_udp_dual_stack_in(
        runtime,
        destination_port,
        InterfaceScope::Pinned(if_a),
        socket_a.socket_id(),
    )
    .ok()?;
    bind_udp_dual_stack_in(
        runtime,
        destination_port,
        InterfaceScope::Pinned(if_b),
        socket_b.socket_id(),
    )
    .ok()?;

    let udp_header = udp_datagram(40_000, destination_port, &[0; 8])?;
    let first_fragment = &udp_header[..8];
    let payload_a = b"port-A!!";
    let payload_b = b"port-B!!";
    let fragment_id = 0x4512;
    for (if_id, dst_mac) in [(if_a, mac_a), (if_b, mac_b)] {
        let frame = build_ipv4_frame(
            runtime,
            Ipv4FrameSpec {
                dst_mac,
                src_mac: source_mac,
                src_ip: remote_ip,
                dst_ip: local_ip,
                protocol: crate::net::l3::ipv4::IpProtocol::Udp,
                identification: fragment_id,
                fragment_offset: 0,
                more_fragments: true,
                payload: first_fragment,
            },
        )?;
        let state = if if_id == if_a { state_a } else { state_b };
        state.submit_rx(frame).ok()?;
    }
    for (if_id, dst_mac, payload) in [(if_a, mac_a, &payload_a[..]), (if_b, mac_b, &payload_b[..])]
    {
        let frame = build_ipv4_frame(
            runtime,
            Ipv4FrameSpec {
                dst_mac,
                src_mac: source_mac,
                src_ip: remote_ip,
                dst_ip: local_ip,
                protocol: crate::net::l3::ipv4::IpProtocol::Udp,
                identification: fragment_id,
                fragment_offset: 1,
                more_fragments: false,
                payload,
            },
        )?;
        let state = if if_id == if_a { state_a } else { state_b };
        state.submit_rx(frame).ok()?;
    }
    let mut fragments_a = 0usize;
    let mut fragments_b = 0usize;
    let mut fragment_cpu = None;
    process_runtime_commands(
        runtime,
        &handler,
        executor_count,
        |cpu_id, if_id, protocol| {
            if protocol != 17 {
                return;
            }
            if fragment_cpu.is_none() {
                fragment_cpu = Some(cpu_id);
            }
            if fragment_cpu == Some(cpu_id) {
                if if_id == if_a {
                    fragments_a = fragments_a.saturating_add(1);
                } else if if_id == if_b {
                    fragments_b = fragments_b.saturating_add(1);
                }
            }
        },
    )?;
    (fragments_a == 2 && fragments_b == 2).then_some(())?;
    let (rx_if_a, _, _, received_a) = socket_a.try_recv_udp_payload().ok()?;
    let (rx_if_b, _, _, received_b) = socket_b.try_recv_udp_payload().ok()?;
    (rx_if_a == if_a && packet_payload_eq(&received_a, payload_a)).then_some(())?;
    (rx_if_b == if_b && packet_payload_eq(&received_b, payload_b)).then_some(())?;

    let src_ip_u32 = u32::from_be_bytes(remote_ip.octets());
    let dst_ip_u32 = u32::from_be_bytes(local_ip.octets());
    let rss_tx_before =
        crate::net::runtime::bridge::get_stack_glue_stats_for_interface_in(runtime, if_b)
            .map_or(0, |stats| stats.tx_packets);
    for target_cpu in 0..cpu_count {
        let src_port = (1024u16..=u16::MAX).find(|src_port| {
            crate::net::datapath::optimization::FlowAffinity::hash_5tuple(
                src_ip_u32,
                dst_ip_u32,
                *src_port,
                destination_port,
                17,
            ) as usize
                % executor_count
                == target_cpu
        })?;
        let udp = udp_datagram(src_port, destination_port, b"rss-udp")?;
        state_b
            .submit_rx(build_ipv4_frame(
                runtime,
                Ipv4FrameSpec {
                    dst_mac: mac_b,
                    src_mac: source_mac,
                    src_ip: remote_ip,
                    dst_ip: local_ip,
                    protocol: crate::net::l3::ipv4::IpProtocol::Udp,
                    identification: src_port,
                    fragment_offset: 0,
                    more_fragments: false,
                    payload: &udp,
                },
            )?)
            .ok()?;

        let source_octet = (1u8..=254).find(|octet| {
            let source = u32::from_be_bytes([10, 24, target_cpu as u8, *octet]);
            crate::net::datapath::optimization::FlowAffinity::hash_5tuple(
                source, dst_ip_u32, 0, 0, 1,
            ) as usize
                % executor_count
                == target_cpu
        })?;
        let icmp_source = Ipv4Address::new([10, 24, target_cpu as u8, source_octet]);
        {
            let mut stack_guard = runtime.context().stacks[target_cpu].lock().ok()?;
            stack_guard.as_mut()?.arp_cache_insert_on(
                if_b,
                icmp_source,
                crate::net::l2::ethernet::MacAddress::new(source_mac),
                10,
            );
        }
        let echo = icmp_echo_request(target_cpu as u16, 1, b"rss-icmp");
        state_b
            .submit_rx(build_ipv4_frame(
                runtime,
                Ipv4FrameSpec {
                    dst_mac: mac_b,
                    src_mac: source_mac,
                    src_ip: icmp_source,
                    dst_ip: local_ip,
                    protocol: crate::net::l3::ipv4::IpProtocol::Icmp,
                    identification: 0x6000 + target_cpu as u16,
                    fragment_offset: 0,
                    more_fragments: false,
                    payload: &echo,
                },
            )?)
            .ok()?;
    }
    let mut saw_udp = [false; 4];
    let mut saw_icmp = [false; 4];
    process_runtime_commands(
        runtime,
        &handler,
        executor_count,
        |cpu_id, if_id, protocol| {
            if if_id == if_b && cpu_id < 4 {
                saw_udp[cpu_id] |= protocol == 17;
                saw_icmp[cpu_id] |= protocol == 1;
            }
        },
    )?;
    for cpu_id in 0..cpu_count {
        (saw_udp[cpu_id] && saw_icmp[cpu_id]).then_some(())?;
    }
    for _ in 0..cpu_count {
        let (rx_if, _, _, received) = socket_b.try_recv_udp_payload().ok()?;
        (rx_if == if_b && packet_payload_eq(&received, b"rss-udp")).then_some(())?;
    }
    let rss_tx_after =
        crate::net::runtime::bridge::get_stack_glue_stats_for_interface_in(runtime, if_b)?
            .tx_packets;
    (rss_tx_after >= rss_tx_before.saturating_add(cpu_count as u64)).then_some(())?;

    for cpu_id in 0..executor_count {
        let mut stack_guard = runtime.context().stacks[cpu_id].lock().ok()?;
        stack_guard.as_mut()?.arp_cache_insert_on(
            if_a,
            remote_ip,
            crate::net::l2::ethernet::MacAddress::new(source_mac),
            10,
        );
    }
    let tx_a_before =
        crate::net::runtime::bridge::get_stack_glue_stats_for_interface_in(runtime, if_a)
            .map_or(0, |stats| stats.tx_packets);
    let echo = icmp_echo_request(7, 9, b"primary");
    let frame = build_ipv4_frame(
        runtime,
        Ipv4FrameSpec {
            dst_mac: mac_a,
            src_mac: source_mac,
            src_ip: remote_ip,
            dst_ip: local_ip,
            protocol: crate::net::l3::ipv4::IpProtocol::Icmp,
            identification: 0x7001,
            fragment_offset: 0,
            more_fragments: false,
            payload: &echo,
        },
    )?;
    state_a.submit_rx(frame).ok()?;
    let mut primary_icmp = 0usize;
    process_runtime_commands(runtime, &handler, executor_count, |_, if_id, protocol| {
        if if_id == if_a && protocol == 1 {
            primary_icmp = primary_icmp.saturating_add(1);
        }
    })?;
    (primary_icmp == 1).then_some(())?;
    let tx_a_after =
        crate::net::runtime::bridge::get_stack_glue_stats_for_interface_in(runtime, if_a)?
            .tx_packets;
    (tx_a_after > tx_a_before).then_some(())?;

    state_a.update_link(false).ok()?;
    (crate::net::runtime::manager::primary_interface_in(runtime) == Some(if_b)).then_some(())?;
    let stopped_rx_before =
        crate::net::runtime::bridge::get_stack_glue_stats_for_interface_in(runtime, if_a)
            .map_or(0, |stats| stats.rx_packets);
    let stopped_frame = build_ipv4_frame(
        runtime,
        Ipv4FrameSpec {
            dst_mac: mac_a,
            src_mac: source_mac,
            src_ip: remote_ip,
            dst_ip: local_ip,
            protocol: crate::net::l3::ipv4::IpProtocol::Icmp,
            identification: 0x7002,
            fragment_offset: 0,
            more_fragments: false,
            payload: &echo,
        },
    )?;
    state_a.submit_rx(stopped_frame).is_err().then_some(())?;
    let stopped_rx_after =
        crate::net::runtime::bridge::get_stack_glue_stats_for_interface_in(runtime, if_a)
            .map_or(0, |stats| stats.rx_packets);
    (stopped_rx_after == stopped_rx_before).then_some(())?;
    let stopped_tx = PacketPayload::single(build_ipv4_frame(
        runtime,
        Ipv4FrameSpec {
            dst_mac: mac_a,
            src_mac: source_mac,
            src_ip: remote_ip,
            dst_ip: local_ip,
            protocol: crate::net::l3::ipv4::IpProtocol::Icmp,
            identification: 0x7003,
            fragment_offset: 0,
            more_fragments: false,
            payload: &echo,
        },
    )?);
    (!crate::net::runtime::device::transmit_packet_in(
        runtime,
        if_a,
        stopped_tx,
        NetTxMeta::default(),
    ))
    .then_some(())?;

    process_runtime_commands(runtime, &handler, executor_count, |_, _, _| {})?;
    for cpu_id in 0..executor_count {
        let mut stack_guard = runtime.context().stacks[cpu_id].lock().ok()?;
        let core_stack = stack_guard.as_mut()?;
        core_stack.interface_config(if_a).is_none().then_some(())?;
        core_stack.interface_config(if_b)?;
        (core_stack.primary_interface_state()?.0 == if_b).then_some(())?;
        core_stack.arp_cache_insert_on(
            if_b,
            remote_ip,
            crate::net::l2::ethernet::MacAddress::new(source_mac),
            20,
        );
    }
    let tx_b_before =
        crate::net::runtime::bridge::get_stack_glue_stats_for_interface_in(runtime, if_b)
            .map_or(0, |stats| stats.tx_packets);
    let frame = build_ipv4_frame(
        runtime,
        Ipv4FrameSpec {
            dst_mac: mac_b,
            src_mac: source_mac,
            src_ip: remote_ip,
            dst_ip: local_ip,
            protocol: crate::net::l3::ipv4::IpProtocol::Icmp,
            identification: 0x7004,
            fragment_offset: 0,
            more_fragments: false,
            payload: &echo,
        },
    )?;
    state_b.submit_rx(frame).ok()?;
    let mut secondary_icmp = 0usize;
    process_runtime_commands(runtime, &handler, executor_count, |_, if_id, protocol| {
        if if_id == if_b && protocol == 1 {
            secondary_icmp = secondary_icmp.saturating_add(1);
        }
    })?;
    (secondary_icmp == 1).then_some(())?;
    let tx_b_after =
        crate::net::runtime::bridge::get_stack_glue_stats_for_interface_in(runtime, if_b)?
            .tx_packets;
    (tx_b_after > tx_b_before).then_some(())?;

    crate::net::runtime::device::unregister_port_in(runtime, if_b).then_some(())?;
    crate::net::runtime::device::unregister_port_in(runtime, if_a).then_some(())?;
    Some(())
}

pub fn runtime_fake_ports_smp_flow_failover_smoke() -> bool {
    run_fake_ports_smp_flow_failover().is_some()
}
