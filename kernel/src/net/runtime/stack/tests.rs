use super::*;
use crate::net::runtime::manager;
use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::future::Future;
use kernel_api::resource::net::PacketPayload;

static TEST_LAST_TX_IF: PoisonLock<Option<NetIfId>> = PoisonLock::new(None);

fn test_payload(data: &[u8]) -> PacketPayload {
    crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
}

fn payload_bytes(payload: &PacketPayload) -> Vec<u8> {
    let mut out = alloc::vec![0u8; payload.total_len()];
    let copied = crate::net::payload::PacketPayloadView::new(payload).copy_all_into(&mut out);
    out.truncate(copied);
    out
}

fn record_test_tx_if(
    if_id: Option<NetIfId>,
    _packet: crate::net::datapath::mempool::PacketRef,
    _meta: kernel_api::service::netdev::NetTxMeta,
) -> bool {
    let mut guard = TEST_LAST_TX_IF.lock().unwrap_or_else(|e| e.into_inner());
    *guard = if_id;
    true
}

struct ManagerStateGuard {
    prev_manager: Option<crate::net::runtime::manager::NetworkManager>,
}

impl ManagerStateGuard {
    fn new() -> Self {
        let prev_manager = {
            let mut guard = crate::net::runtime::manager::network_manager()
                .lock_for_init("[TEST][STACK] manager snapshot");
            core::mem::take(&mut *guard)
        };
        *TEST_LAST_TX_IF.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Self { prev_manager }
    }
}

impl Drop for ManagerStateGuard {
    fn drop(&mut self) {
        let mut guard = crate::net::runtime::manager::network_manager()
            .lock_for_init("[TEST][STACK] manager restore");
        *guard = self.prev_manager.take();
        *TEST_LAST_TX_IF.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn build_ipv4_raw_udp_packet(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut buffer =
        alloc::vec![0u8; crate::net::l3::ipv4::Ipv4Header::MIN_SIZE + 8 + payload.len()];
    let mut ip = crate::net::l3::ipv4::Ipv4PacketMut::new(&mut buffer).expect("ipv4 packet");
    ip.init_header()
        .set_source(src_ip)
        .set_destination(dst_ip)
        .set_ttl(64)
        .set_protocol(crate::net::l3::ipv4::IpProtocol::Udp);

    let udp_len = crate::net::l4::udp::UdpProcessor::build_packet(
        ip.payload_mut(),
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        payload,
    )
    .expect("udp packet");
    ip.finalize(udp_len);
    buffer.truncate(crate::net::l3::ipv4::Ipv4Header::MIN_SIZE + udp_len);
    buffer
}

fn build_ipv6_raw_udp_packet(
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut buffer = alloc::vec![0u8; crate::net::l3::ipv6::IPV6_HEADER_SIZE + 8 + payload.len()];
    let mut ip = crate::net::l3::ipv6::Ipv6PacketMut::new(&mut buffer).expect("ipv6 packet");
    ip.init_header();
    ip.set_source(&src_ip);
    ip.set_destination(&dst_ip);
    ip.set_hop_limit(64);
    ip.set_next_header(crate::net::l3::ipv4::IpProtocol::Udp);

    let udp_len = {
        let mut udp = crate::net::l4::udp::UdpPacketMut::new(ip.payload_mut()).expect("udp packet");
        udp.set_src_port(src_port)
            .set_dst_port(dst_port)
            .write_payload(payload);
        udp.finalize_v6(src_ip, dst_ip)
    };
    ip.finalize(udp_len);
    buffer.truncate(crate::net::l3::ipv6::IPV6_HEADER_SIZE + udp_len);
    buffer
}

fn install_primary_dhcp_v4_client(
    mac: MacAddress,
) -> alloc::sync::Arc<crate::net::services::dhcp::DhcpClient> {
    manager::init_network_manager();

    let if_id = manager::register_interface("dhcp-test0").expect("register dhcp test interface");
    let mut config = NetworkConfig::default();
    config.mac = mac;
    manager::set_interface_config(if_id, config).expect("set dhcp test config");
    crate::net::services::dhcp::ensure_interface_runtime(if_id, config)
        .expect("init dhcp interface runtime");
    crate::net::services::dhcp::mark_primary_interface(if_id);
    crate::net::services::dhcp::primary_v4_client_in(crate::net::runtime::default_runtime())
        .expect("dhcp client")
}

fn run_with_event_task<F>(future: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    crate::net::l4::endpoint::event::reset_event_system_for_tests();

    let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
    let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let mut executor = crate::task::TestExecutor::new();

    let result_slot_clone = result_slot.clone();
    let completed_clone = completed.clone();
    executor.spawn(crate::task::Task::new(async move {
        let output = future.await;
        let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(output);
        completed_clone.store(true, core::sync::atomic::Ordering::Release);
    }));
    executor.spawn(crate::task::Task::new(async {
        crate::net::l4::endpoint::tcp_rx::network_event_task().await;
    }));

    let mut output = None;
    for _ in 0..100_000 {
        executor.drive_once_for_test();
        if completed.load(core::sync::atomic::Ordering::Acquire) {
            output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
            break;
        }
    }

    crate::net::l4::endpoint::event::reset_event_system_for_tests();
    output.expect("network stack test future timed out")
}

fn run_with_event_task_in<F>(runtime: crate::net::runtime::NetRuntimeHandle, future: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    crate::net::l4::endpoint::event::reset_event_system_for_tests_in(runtime);

    let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
    let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let mut executor = crate::task::TestExecutor::new();

    let result_slot_clone = result_slot.clone();
    let completed_clone = completed.clone();
    executor.spawn(crate::task::Task::new(async move {
        let output = future.await;
        let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(output);
        completed_clone.store(true, core::sync::atomic::Ordering::Release);
    }));
    executor.spawn(crate::task::Task::new(async move {
        crate::net::l4::endpoint::tcp_rx::network_event_task_in(runtime).await;
    }));

    let mut output = None;
    for _ in 0..100_000 {
        executor.drive_once_for_test();
        if completed.load(core::sync::atomic::Ordering::Acquire) {
            output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
            break;
        }
    }

    crate::net::l4::endpoint::event::reset_event_system_for_tests_in(runtime);
    output.expect("network stack test future timed out")
}

#[cfg_attr(test, test_case)]
pub fn test_network_stack_creation() {
    let stack = NetworkStack::new_default();
    let config = stack.config();

    assert_eq!(
        config.mac,
        MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    );
    assert!(config.icmp_echo_enabled);
}

#[cfg_attr(test, test_case)]
pub fn test_network_stack_poisoned_runtime_apis_fail() {
    use crate::sync::set_panicking;

    // Initialize and then poison the global stack lock
    init_default();

    set_panicking(true);
    if let Ok(_g) = stack().lock() {
        // Dropping _g while panicking marks the lock poisoned
    }
    set_panicking(false);

    // Runtime APIs should fail conservatively when the global lock is poisoned
    // NOTE: These intentionally test the deprecated sync APIs for graceful failure.
    assert!(
        run_with_event_task(send_udp(
            1234,
            Ipv4Address::LOOPBACK,
            80,
            test_payload(&[0x1, 0x2]),
        ))
        .is_err()
    );
    assert!(
        run_with_event_task(send_tcp(
            Ipv4Address::LOOPBACK,
            Ipv4Address::LOOPBACK,
            test_payload(&[]),
        ))
        .is_err()
    );
    assert!(run_with_event_task(bind_udp(1234)).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_send_udp_event_task_zero_copy() {
    // Initialize stack and set transmit function to always succeed
    init_default();
    if let Ok(mut guard) = stack().lock() {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(
                |_if_id: Option<super::NetIfId>,
                 _packet: crate::net::datapath::mempool::PacketRef,
                 _meta: kernel_api::service::netdev::NetTxMeta| true,
            );
        }
    }

    let dst = Ipv4Address::new([255, 255, 255, 255]); // Broadcast -> immediate MAC
    let sent = {
        crate::net::l4::endpoint::event::reset_event_system_for_tests();

        let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
        let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let mut executor = crate::task::TestExecutor::new();

        let result_slot_clone = result_slot.clone();
        let completed_clone = completed.clone();
        executor.spawn(crate::task::Task::new(async move {
            let output = send_udp(1234, dst, 80, test_payload(&[1, 2, 3])).await;
            let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(output);
            completed_clone.store(true, core::sync::atomic::Ordering::Release);
        }));
        executor.spawn(crate::task::Task::new(async {
            crate::net::l4::endpoint::tcp_rx::network_event_task().await;
        }));

        let mut output = None;
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if completed.load(core::sync::atomic::Ordering::Acquire) {
                output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                break;
            }
        }

        crate::net::l4::endpoint::event::reset_event_system_for_tests();
        output.expect("send_udp test future timed out")
    };
    assert!(sent.is_ok());
}

#[cfg_attr(test, test_case)]
pub fn test_send_icmp_event_dispatch_smoke() {
    // Initialize stack and set transmit function
    init_default();
    if let Ok(mut guard) = stack().lock() {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(
                |_if_id: Option<super::NetIfId>,
                 _packet: crate::net::datapath::mempool::PacketRef,
                 _meta: kernel_api::service::netdev::NetTxMeta| true,
            );
            // Pre-populate ARP cache so ping will proceed
            let target = Ipv4Address::new([8, 8, 8, 8]);
            s.arp.cache().insert(
                target,
                MacAddress::from_octets(0x52, 0x54, 0x00, 0x12, 0x34, 0x56),
                s.current_time(),
            );
        }
    }

    crate::net::l4::endpoint::event::reset_event_system_for_tests();

    let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
    let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let mut executor = crate::task::TestExecutor::new();

    let result_slot_clone = result_slot.clone();
    let completed_clone = completed.clone();
    executor.spawn(crate::task::Task::new(async move {
        assert!(crate::net::api::icmp::enqueue_icmp_echo_in(
            crate::net::runtime::default_runtime(),
            [8, 8, 8, 8],
            1,
        ));
        crate::task::yield_now().await;
        let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(());
        completed_clone.store(true, core::sync::atomic::Ordering::Release);
    }));
    executor.spawn(crate::task::Task::new(async {
        crate::net::l4::endpoint::tcp_rx::network_event_task().await;
    }));

    for _ in 0..100_000 {
        executor.drive_once_for_test();
        if completed.load(core::sync::atomic::Ordering::Acquire) {
            break;
        }
    }

    crate::net::l4::endpoint::event::reset_event_system_for_tests();
    assert!(completed.load(core::sync::atomic::Ordering::Acquire));
}

#[cfg_attr(test, test_case)]
pub fn test_runtime_scoped_event_task_reads_runtime_local_stack() {
    crate::net::runtime::context::reset_runtime_registry_for_tests();

    let default_runtime = crate::net::runtime::default_runtime();
    let other_runtime = crate::net::runtime::create_runtime();

    let default_ipv6 =
        crate::net::l3::ipv6::Ipv6Config::from_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x11]);
    let other_ipv6 =
        crate::net::l3::ipv6::Ipv6Config::from_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x22]);

    {
        let mut guard = default_runtime
            .context()
            .stack
            .lock_for_init("[TEST][STACK] default runtime init");
        *guard = Some(NetworkStack::new(NetworkConfig {
            ipv6: Some(default_ipv6),
            ..NetworkConfig::default()
        }));
    }
    {
        let mut guard = other_runtime
            .context()
            .stack
            .lock_for_init("[TEST][STACK] other runtime init");
        *guard = Some(NetworkStack::new(NetworkConfig {
            ipv6: Some(other_ipv6),
            ..NetworkConfig::default()
        }));
    }

    let link_local = run_with_event_task_in(other_runtime, async move {
        let (result_slot, waker, command_future) =
            crate::net::runtime::stack::new_command_channel::<Option<[u8; 16]>>();
        let _ = crate::net::l4::endpoint::event::send_event_in(
            other_runtime,
            crate::net::l4::endpoint::event::NetworkEvent::GetLinkLocal { result_slot, waker },
        )
        .await;
        command_future.await
    });

    assert_eq!(link_local, Some(other_ipv6.link_local.octets()));
    assert_ne!(link_local, Some(default_ipv6.link_local.octets()));
}

#[cfg_attr(test, test_case)]
pub fn test_dhcp_v4_ack_updates_stack_config_via_udp_hook() {
    crate::net::runtime::context::reset_runtime_registry_for_tests();
    init_default();

    let client_mac = MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    let client = install_primary_dhcp_v4_client(client_mac);

    let xid = {
        let mut discover = [0u8; crate::net::services::dhcp::DHCP_MAX_MESSAGE_SIZE];
        let _ = client
            .build_discover(&mut discover, 10)
            .expect("build discover");
        u32::from_be_bytes([discover[4], discover[5], discover[6], discover[7]])
    };

    let offered_ip = Ipv4Address::new([10, 0, 2, 99]);
    let server_ip = Ipv4Address::new([10, 0, 2, 2]);
    let subnet = Ipv4Address::new([255, 255, 255, 0]);
    let dns = Ipv4Address::new([1, 1, 1, 1]);

    let mut dhcp_ack = [0u8; 512];
    dhcp_ack[0] = crate::net::services::dhcp::DhcpOperation::Reply as u8;
    dhcp_ack[1] = 1;
    dhcp_ack[2] = 6;
    dhcp_ack[4..8].copy_from_slice(&xid.to_be_bytes());
    dhcp_ack[16..20].copy_from_slice(offered_ip.as_bytes()); // yiaddr
    dhcp_ack[20..24].copy_from_slice(server_ip.as_bytes()); // siaddr
    dhcp_ack[28..34].copy_from_slice(client_mac.as_bytes());

    let mut off = crate::net::services::dhcp::DhcpHeader::SIZE;
    dhcp_ack[off..off + 4].copy_from_slice(&crate::net::services::dhcp::DHCP_MAGIC_COOKIE);
    off += 4;

    dhcp_ack[off] = crate::net::services::dhcp::DhcpOption::MessageType as u8;
    dhcp_ack[off + 1] = 1;
    dhcp_ack[off + 2] = crate::net::services::dhcp::DhcpMessageType::Ack as u8;
    off += 3;

    dhcp_ack[off] = crate::net::services::dhcp::DhcpOption::ServerIdentifier as u8;
    dhcp_ack[off + 1] = 4;
    dhcp_ack[off + 2..off + 6].copy_from_slice(server_ip.as_bytes());
    off += 6;

    dhcp_ack[off] = crate::net::services::dhcp::DhcpOption::SubnetMask as u8;
    dhcp_ack[off + 1] = 4;
    dhcp_ack[off + 2..off + 6].copy_from_slice(subnet.as_bytes());
    off += 6;

    dhcp_ack[off] = crate::net::services::dhcp::DhcpOption::Router as u8;
    dhcp_ack[off + 1] = 4;
    dhcp_ack[off + 2..off + 6].copy_from_slice(server_ip.as_bytes());
    off += 6;

    dhcp_ack[off] = crate::net::services::dhcp::DhcpOption::DnsServer as u8;
    dhcp_ack[off + 1] = 4;
    dhcp_ack[off + 2..off + 6].copy_from_slice(dns.as_bytes());
    off += 6;

    dhcp_ack[off] = crate::net::services::dhcp::DhcpOption::LeaseTime as u8;
    dhcp_ack[off + 1] = 4;
    dhcp_ack[off + 2..off + 6].copy_from_slice(&3600u32.to_be_bytes());
    off += 6;

    dhcp_ack[off] = crate::net::services::dhcp::DhcpOption::End as u8;
    off += 1;

    let src_ip = server_ip;
    let dst_ip = Ipv4Address::new([255, 255, 255, 255]);

    let mut frame = [0u8; MAX_PACKET_SIZE];
    let mut eth = EthernetFrameMut::new(&mut frame).expect("ethernet frame");
    eth.set_destination(client_mac)
        .set_source(MacAddress::from_octets(0x52, 0x54, 0x00, 0x12, 0x34, 0x56))
        .set_ether_type(EtherType::Ipv4);

    let payload = eth.payload_mut();
    let mut ip = Ipv4PacketMut::new(payload).expect("ipv4 packet");
    ip.set_version(4)
        .set_ihl(5)
        .set_ttl(64)
        .set_protocol(IpProtocol::Udp)
        .set_source(src_ip)
        .set_destination(dst_ip);

    let udp_len = UdpProcessor::build_packet(
        ip.payload_mut(),
        src_ip,
        crate::net::services::dhcp::DHCP_SERVER_PORT,
        dst_ip,
        crate::net::services::dhcp::DHCP_CLIENT_PORT,
        &dhcp_ack[..off],
    )
    .expect("udp packet");
    ip.finalize(udp_len);
    eth.set_payload_len(crate::net::l3::ipv4::Ipv4Header::MIN_SIZE + udp_len);

    let packet = crate::net::payload::packet_from_bytes(eth.as_bytes()).expect("ingress packet");
    let handler = crate::net::l4::endpoint::handler::NetworkEventHandler::new();
    let result = handler.handle_event(
        crate::net::l4::endpoint::event::NetworkEvent::IngressPacket {
            if_id: None,
            packet,
        },
    );
    assert!(matches!(
        result,
        crate::net::l4::endpoint::handler::EventHandleResult::Success
    ));

    let guard = match stack().lock() {
        Ok(g) => g,
        Err(_) => panic!("stack lock"),
    };
    let stack_guard = guard.as_ref().expect("stack initialized");
    let cfg = stack_guard.config();
    assert_eq!(cfg.ipv4.address, offered_ip);
    assert_eq!(cfg.ipv4.subnet_mask, subnet);
    assert_eq!(cfg.ipv4.gateway, server_ip);
    assert_eq!(cfg.ipv4.dns, Some(dns));
}

#[cfg_attr(test, test_case)]
pub fn test_dhcp_runtime_public_apis_smoke() {
    crate::net::runtime::context::reset_runtime_registry_for_tests();
    init_default();
    let client = install_primary_dhcp_v4_client(NetworkConfig::default().mac);

    assert!(crate::net::api::dhcp::init_dhcp_runtime().is_ok());

    let st = {
        crate::net::l4::endpoint::event::reset_event_system_for_tests();

        let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
        let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let mut executor = crate::task::TestExecutor::new();

        let result_slot_clone = result_slot.clone();
        let completed_clone = completed.clone();
        executor.spawn(crate::task::Task::new(async move {
            let output =
                crate::net::api::dhcp::dhcp_state_in(crate::net::runtime::default_runtime()).await;
            let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(output);
            completed_clone.store(true, core::sync::atomic::Ordering::Release);
        }));
        executor.spawn(crate::task::Task::new(async {
            crate::net::l4::endpoint::tcp_rx::network_event_task().await;
        }));

        let mut output = None;
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if completed.load(core::sync::atomic::Ordering::Acquire) {
                output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                break;
            }
        }

        crate::net::l4::endpoint::event::reset_event_system_for_tests();
        output.expect("dhcp_state test future timed out")
    };
    assert!(!st.v4_state.is_empty());
    assert!(!st.v6_state.is_empty());

    // 旧同期API (dhcp_discover, dhcp_request, dhcp_release, dhcp_renew,
    // dhcp_last_declined, dhcp_last_released) は削除済み。
    // 非同期版 (dhcp_discover, dhcp_release, ...) は
    // async executor 上でのみテスト可能なため、ここでは dhcp_state のみ検証する。

    // simulate a conflict/decline via internal client API to verify state snapshot
    let test_ip = [192, 168, 123, 45];
    let server_ip = [192, 168, 123, 1];
    let _ = client.send_decline(
        crate::net::l3::ipv4::Ipv4Address::new(test_ip),
        Some(crate::net::l3::ipv4::Ipv4Address::new(server_ip)),
    );

    // verify dhcp_state snapshot reflects the decline
    let snap = {
        crate::net::l4::endpoint::event::reset_event_system_for_tests();

        let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
        let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let mut executor = crate::task::TestExecutor::new();

        let result_slot_clone = result_slot.clone();
        let completed_clone = completed.clone();
        executor.spawn(crate::task::Task::new(async move {
            let output =
                crate::net::api::dhcp::dhcp_state_in(crate::net::runtime::default_runtime()).await;
            let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(output);
            completed_clone.store(true, core::sync::atomic::Ordering::Release);
        }));
        executor.spawn(crate::task::Task::new(async {
            crate::net::l4::endpoint::tcp_rx::network_event_task().await;
        }));

        let mut output = None;
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if completed.load(core::sync::atomic::Ordering::Acquire) {
                output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                break;
            }
        }

        crate::net::l4::endpoint::event::reset_event_system_for_tests();
        output.expect("dhcp_state snapshot future timed out")
    };
    assert_eq!(snap.v4_last_declined, Some(test_ip));
}

#[cfg_attr(test, test_case)]
pub fn test_send_udp_raw_uses_route_selected_interface() {
    let _guard = ManagerStateGuard::new();
    manager::init_network_manager();
    init_default();

    let if0 = manager::register_interface("if0").expect("register if0");
    let if1 = manager::register_interface("if1").expect("register if1");
    let cfg0 = NetworkConfig {
        mac: MacAddress::from_octets(0x02, 0, 0, 0, 0, 1),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 0, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ..NetworkConfig::default()
    };
    let cfg1 = NetworkConfig {
        mac: MacAddress::from_octets(0x02, 0, 0, 0, 0, 2),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 1, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ..NetworkConfig::default()
    };
    manager::set_interface_config(if0, cfg0).expect("cfg if0");
    manager::set_interface_config(if1, cfg1).expect("cfg if1");

    if let Ok(mut guard) = stack().lock() {
        let stack = guard.as_mut().expect("stack");
        stack.set_transmit_fn(record_test_tx_if);
        stack.register_interface_state(if0, cfg0);
        stack.register_interface_state(if1, cfg1);
        let now = stack.current_time();
        stack
            .interfaces
            .get_mut(&if1)
            .expect("if1 state")
            .arp
            .cache()
            .insert(
                Ipv4Address::new([10, 0, 1, 55]),
                MacAddress::from_octets(0x52, 0x54, 0, 0x12, 0x34, 0x56),
                now,
            );
        let payload = test_payload(b"hi");
        let payload = crate::net::payload::PacketPayloadView::new(&payload);
        assert!(stack.send_udp_raw_payload_scoped_auto_ttl(
            crate::net::types::InterfaceScope::Any,
            1234,
            Ipv4Address::new([10, 0, 1, 55]),
            8080,
            &payload,
            64,
        ));
    } else {
        panic!("stack lock");
    }

    let last_if = *TEST_LAST_TX_IF.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(last_if, Some(if1));
}

#[cfg_attr(test, test_case)]
pub fn test_send_udp_raw_without_route_does_not_fallback() {
    let _guard = ManagerStateGuard::new();
    manager::init_network_manager();
    init_default();

    let if0 = manager::register_interface("if0").expect("register if0");
    let cfg0 = NetworkConfig {
        mac: MacAddress::from_octets(0x02, 0, 0, 0, 0, 3),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 0, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ..NetworkConfig::default()
    };
    manager::set_interface_config(if0, cfg0).expect("cfg if0");

    if let Ok(mut guard) = stack().lock() {
        let stack = guard.as_mut().expect("stack");
        stack.set_transmit_fn(record_test_tx_if);
        stack.register_interface_state(if0, cfg0);
        let payload = test_payload(b"hi");
        let payload = crate::net::payload::PacketPayloadView::new(&payload);
        assert!(!stack.send_udp_raw_payload_scoped_auto_ttl(
            crate::net::types::InterfaceScope::Any,
            1234,
            Ipv4Address::new([203, 0, 113, 10]),
            8080,
            &payload,
            64,
        ));
    } else {
        panic!("stack lock");
    }

    let last_if = *TEST_LAST_TX_IF.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(last_if, None);
}

#[cfg_attr(test, test_case)]
pub fn test_send_raw_ipv4_payload_rejects_bad_checksum() {
    let _guard = ManagerStateGuard::new();
    manager::init_network_manager();
    init_default();

    let if0 = manager::register_interface("raw0").expect("register raw0");
    let cfg0 = NetworkConfig {
        mac: MacAddress::from_octets(0x02, 0, 0, 0, 0, 5),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 10, 0, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ..NetworkConfig::default()
    };
    manager::set_interface_config(if0, cfg0).expect("cfg raw0");

    if let Ok(mut guard) = stack().lock() {
        let stack = guard.as_mut().expect("stack");
        stack.set_transmit_fn(record_test_tx_if);
        stack.register_interface_state(if0, cfg0);

        let mut packet = build_ipv4_raw_udp_packet(
            cfg0.ipv4.address,
            Ipv4Address::new([10, 10, 0, 55]),
            1234,
            8080,
            b"checksum",
        );
        packet[10] ^= 0xff;

        let result = stack.send_raw_ip_payload_scoped(
            crate::net::types::InterfaceScope::Pinned(if0),
            test_payload(&packet),
        );
        assert_eq!(result, Err(crate::net::types::NetworkError::InvalidAddress));
    } else {
        panic!("stack lock");
    }

    let last_if = *TEST_LAST_TX_IF.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(last_if, None);
}

#[cfg_attr(test, test_case)]
pub fn test_send_raw_ipv4_payload_respects_pinned_scope() {
    let _guard = ManagerStateGuard::new();
    manager::init_network_manager();
    init_default();

    let if0 = manager::register_interface("raw-pin0").expect("register raw-pin0");
    let cfg0 = NetworkConfig {
        mac: MacAddress::from_octets(0x02, 0, 0, 0, 0, 6),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 20, 0, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ..NetworkConfig::default()
    };
    manager::set_interface_config(if0, cfg0).expect("cfg raw-pin0");

    if let Ok(mut guard) = stack().lock() {
        let stack = guard.as_mut().expect("stack");
        stack.set_transmit_fn(record_test_tx_if);
        stack.register_interface_state(if0, cfg0);
        let now = stack.current_time();
        stack
            .interfaces
            .get_mut(&if0)
            .expect("if0 state")
            .arp
            .cache()
            .insert(
                Ipv4Address::new([10, 20, 0, 55]),
                MacAddress::from_octets(0x52, 0x54, 0, 0x65, 0x43, 0x21),
                now,
            );

        let packet = build_ipv4_raw_udp_packet(
            cfg0.ipv4.address,
            Ipv4Address::new([10, 20, 0, 55]),
            2222,
            8088,
            b"pinned",
        );
        assert!(
            stack
                .send_raw_ip_payload_scoped(
                    crate::net::types::InterfaceScope::Pinned(if0),
                    test_payload(&packet),
                )
                .is_ok()
        );
    } else {
        panic!("stack lock");
    }

    let last_if = *TEST_LAST_TX_IF.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(last_if, Some(if0));
}

#[cfg_attr(test, test_case)]
pub fn test_send_raw_ipv6_payload_rejects_length_mismatch() {
    let _guard = ManagerStateGuard::new();
    manager::init_network_manager();
    init_default();

    let if0 = manager::register_interface("raw6").expect("register raw6");
    let ipv6_cfg =
        crate::net::l3::ipv6::Ipv6Config::from_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x33]);
    let cfg0 = NetworkConfig {
        mac: MacAddress::from_octets(0x02, 0, 0, 0, 0, 7),
        ipv4: Ipv4Config::default(),
        ipv6: Some(ipv6_cfg),
        ..NetworkConfig::default()
    };
    manager::set_interface_config(if0, cfg0).expect("cfg raw6");

    if let Ok(mut guard) = stack().lock() {
        let stack = guard.as_mut().expect("stack");
        stack.register_interface_state(if0, cfg0);

        let mut packet = build_ipv6_raw_udp_packet(
            ipv6_cfg.link_local,
            crate::net::l3::ipv6::Ipv6Address::new([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 0, 0, 0, 0x55,
            ]),
            3333,
            8089,
            b"ipv6",
        );
        packet[4] = 0;
        packet[5] = 1;

        let result = stack.send_raw_ip_payload_scoped(
            crate::net::types::InterfaceScope::Pinned(if0),
            test_payload(&packet),
        );
        assert_eq!(result, Err(crate::net::types::NetworkError::InvalidAddress));
    } else {
        panic!("stack lock");
    }
}

#[cfg_attr(test, test_case)]
pub fn test_process_arp_replies_on_ingress_interface() {
    let _guard = ManagerStateGuard::new();
    manager::init_network_manager();
    init_default();

    let if0 = manager::register_interface("if0").expect("register if0");
    let cfg0 = NetworkConfig {
        mac: MacAddress::from_octets(0x02, 0, 0, 0, 0, 4),
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 1, 0, 1]),
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        },
        ..NetworkConfig::default()
    };
    manager::set_interface_config(if0, cfg0).expect("cfg if0");

    if let Ok(mut guard) = stack().lock() {
        let stack = guard.as_mut().expect("stack");
        stack.set_transmit_fn(record_test_tx_if);
        stack.register_interface_state(if0, cfg0);

        let sender_mac = MacAddress::from_octets(0x52, 0x54, 0, 0xaa, 0xbb, 0xcc);
        let sender_ip = Ipv4Address::new([10, 1, 0, 55]);
        let mut arp = [0u8; crate::net::l2::arp::ArpPacket::SIZE];
        let packet = crate::util::get_mut_ref::<crate::net::l2::arp::ArpPacket>(&mut arp, 0)
            .expect("arp packet");
        packet.init_request(sender_mac, sender_ip, cfg0.ipv4.address);

        let now = stack.current_time();
        stack.process_arp(Some(if0), &arp, now, sender_mac);
    } else {
        panic!("stack lock");
    }

    let last_if = *TEST_LAST_TX_IF.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(last_if, Some(if0));
}

#[cfg_attr(test, test_case)]
pub fn test_redirect_cache_basic() {
    let mut cache = RedirectCache::new();
    let dst = Ipv4Address::new([10, 0, 0, 100]);
    let gateway = Ipv4Address::new([192, 168, 1, 2]);

    // Initially empty
    assert!(cache.get(dst).is_none());

    // Insert and retrieve
    cache.insert(dst, gateway);
    assert_eq!(cache.get(dst), Some(gateway));

    // Update existing entry
    let new_gateway = Ipv4Address::new([192, 168, 1, 3]);
    cache.insert(dst, new_gateway);
    assert_eq!(cache.get(dst), Some(new_gateway));
}

fn redirect_cache_expiry_impl() {
    let mut cache = RedirectCache::new();
    let dst = Ipv4Address::new([10, 0, 0, 100]);
    let gateway = Ipv4Address::new([192, 168, 1, 2]);

    cache.set_time(0);
    cache.insert(dst, gateway);

    cache.set_time(REDIRECT_CACHE_TTL - 1);
    assert_eq!(cache.get(dst), Some(gateway));

    cache.set_time(REDIRECT_CACHE_TTL + 1);
    assert!(cache.get(dst).is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_redirect_cache_expiry() {
    redirect_cache_expiry_impl();
}

#[cfg_attr(test, test_case)]
pub fn test_redirect_cache_cleanup() {
    redirect_cache_expiry_impl();
}

#[cfg_attr(test, test_case)]
pub fn test_redirect_cache_eviction() {
    let mut cache = RedirectCache::new();
    cache.set_time(0);

    for i in 0..REDIRECT_CACHE_SIZE {
        let dst = Ipv4Address::new([10, 0, 1, i as u8]);
        let gw = Ipv4Address::new([192, 168, 1, i as u8]);
        cache.insert(dst, gw);
    }
    assert_eq!(cache.map.len(), REDIRECT_CACHE_SIZE);

    let oldest = Ipv4Address::new([10, 0, 1, 0]);
    let new_dst = Ipv4Address::new([10, 0, 1, 250]);
    let new_gw = Ipv4Address::new([192, 168, 1, 250]);
    cache.insert(new_dst, new_gw);

    assert_eq!(cache.map.len(), REDIRECT_CACHE_SIZE);
    assert!(cache.get(oldest).is_none());
    assert_eq!(cache.get(new_dst), Some(new_gw));
}

#[cfg_attr(test, test_case)]
pub fn test_redirect_cache_reuses_expired_slot_before_oldest() {
    let mut cache = RedirectCache::new();
    let expired_dst = Ipv4Address::new([10, 0, 2, 1]);
    cache.set_time(0);
    cache.insert(expired_dst, Ipv4Address::new([192, 168, 2, 1]));

    cache.set_time(REDIRECT_CACHE_TTL);
    for i in 1..REDIRECT_CACHE_SIZE {
        let dst = Ipv4Address::new([10, 0, 2, i as u8]);
        let gw = Ipv4Address::new([192, 168, 2, i as u8]);
        cache.insert(dst, gw);
    }
    assert_eq!(cache.map.len(), REDIRECT_CACHE_SIZE);

    cache.set_time(REDIRECT_CACHE_TTL + 1);
    assert!(cache.get(expired_dst).is_none());
    assert_eq!(cache.map.len(), REDIRECT_CACHE_SIZE - 1);

    let new_dst = Ipv4Address::new([10, 0, 2, 250]);
    let new_gw = Ipv4Address::new([192, 168, 2, 250]);
    cache.insert(new_dst, new_gw);

    assert_eq!(cache.map.len(), REDIRECT_CACHE_SIZE);
    assert_eq!(cache.get(new_dst), Some(new_gw));
    let retained = Ipv4Address::new([10, 0, 2, 2]);
    assert!(cache.get(retained).is_some());
}

#[cfg_attr(test, test_case)]
pub fn test_ndp_pending_queue_drain_for_preserves_order() {
    let mut queue = NdpPendingQueue::new();
    let src = Ipv6Address::LOOPBACK;
    let target = Ipv6Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let other = Ipv6Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

    queue.enqueue(src, target, test_payload(&[1]), 1);
    queue.enqueue(src, other, test_payload(&[9]), 2);
    queue.enqueue(src, target, test_payload(&[2]), 3);

    let drained = queue.drain_for(&target);
    assert_eq!(drained.len(), 2);
    match &drained[0].payload {
        PendingIpv6Payload::Icmpv6(data) => assert_eq!(payload_bytes(data), [1]),
        _ => panic!("expected icmpv6 payload"),
    }
    match &drained[1].payload {
        PendingIpv6Payload::Icmpv6(data) => assert_eq!(payload_bytes(data), [2]),
        _ => panic!("expected icmpv6 payload"),
    }

    assert_eq!(queue.packets.len(), 1);
    assert_eq!(queue.packets[0].dst, other);
}

#[cfg_attr(test, test_case)]
pub fn test_ndp_pending_queue_retains_udp_and_tcp_variants() {
    let mut queue = NdpPendingQueue::new();
    let src = Ipv6Address::LOOPBACK;
    let dst = Ipv6Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);

    queue.enqueue_udp(src, dst, 1111, 2222, 32, test_payload(b"udp"), 1);
    queue.enqueue_tcp(src, dst, test_payload(b"tcp"), 2);

    let drained = queue.drain_for(&dst);
    assert_eq!(drained.len(), 2);

    match &drained[0].payload {
        PendingIpv6Payload::Udp {
            src_port,
            dst_port,
            hop_limit,
            data,
        } => {
            assert_eq!(*src_port, 1111);
            assert_eq!(*dst_port, 2222);
            assert_eq!(*hop_limit, 32);
            assert_eq!(payload_bytes(data), b"udp");
        }
        _ => panic!("expected udp payload"),
    }

    match &drained[1].payload {
        PendingIpv6Payload::Tcp { segment } => assert_eq!(payload_bytes(segment), b"tcp"),
        _ => panic!("expected tcp payload"),
    }
}
