#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]
#![feature(format_args_nl)]

extern crate alloc;

use alloc::vec::Vec;
use rany_os::net::{self, mempool, stack};
use rany_os::net::ipv4::{Ipv4PacketMut, Ipv4Address, IpProtocol};
use rany_os::net::tcp::{TcpControlBlock, TcpState, SocketAddr as TcpSocketAddr, Ipv4Addr as TcpIpv4Addr};
use alloc::sync::Arc;
use rany_os::sync::PoisonLock;
use boot_proto::ExoBootInfo;

fn test_runner(tests: &[&dyn Fn()]) {
    for test in tests {
        test();
    }
    // Minimal output and hang to observe results in qemu-based test environment
    rany_os::io::log::early_print("[TEST] net_bridge tests passed!\n");
    loop {}
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    rany_os::panic_handler::panic(info)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_boot_info: &'static mut ExoBootInfo) -> ! {
    test_main();
    loop {}
}


#[test_case]
fn test_process_received_packet_zero_copy_integration() {
    // Initialize mempool and stack
    let _ = mempool::init_net_mempool(4);

    // Configure stack to use 127.0.0.1 for tests
    let mut config = net::NetworkConfig::default();
    config.ipv4.address = Ipv4Address::new([127, 0, 0, 1]);
    stack::init(config);

    // Prepare a TCB and register it in the global stack
    let local = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 1000);
    let remote = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 2000);

    let mut tcb = TcpControlBlock::new(local);
    tcb.remote_addr = Some(remote);
    tcb.state = TcpState::Established;
    tcb.rcv_nxt = 1;
    let tcb_arc = Arc::new(PoisonLock::new(tcb));

    // Insert into stack's tcp connections
    match stack::stack().lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.tcp.connections.insert((local, remote), tcb_arc.clone());
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
    for i in 0..header_size { buf[i] = 0; }

    // Ethernet header
    let eth_off = header_size;
    buf[eth_off..eth_off + 6].copy_from_slice(&[0xff; 6]); // dst
    buf[eth_off + 6..eth_off + 12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
    buf[eth_off + 12..eth_off + 14].copy_from_slice(&[0x08, 0x00]); // EtherType = IPv4

    // IPv4 header
    let ip_off = eth_off + 14;
    let mut ipv4_mut = Ipv4PacketMut::new(&mut buf[ip_off..ip_off + 20]).expect("ipv4 mut");
    ipv4_mut
        .init_header()
        .set_source(Ipv4Address::new([127, 0, 0, 1]))
        .set_destination(Ipv4Address::new([127, 0, 0, 1]))
        .set_protocol(IpProtocol::Tcp)
        .set_identification(1);
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
    ipv4_mut.finalize(tcp_len);

    // Set packet length (virtio header + ethernet frame)
    packet.set_len(header_size + eth_total_len);

    // Call bridge zero-copy entry
    net::driver_bridge::process_received_packet_zero_copy(packet, header_size, eth_total_len);

    // Force a batch timeout to flush the packet into the stack
    net::driver_bridge::check_batch_timeout(100_000, 1);

    // Now verify TCB received the payload zero-copy
    if let Ok(mut guard) = tcb_arc.lock() {
        assert!(!guard.recv_buffer.is_empty());
        let first = guard.recv_buffer.front().unwrap();
        assert_eq!(first.data(), payload);
    } else {
        panic!("TCB lock poisoned in test");
    }
}
