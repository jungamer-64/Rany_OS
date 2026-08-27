// ============================================================================
// src/test/benchmark.rs - Performance Benchmarks
// ============================================================================

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::poll_fn;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Poll, Waker};
use kernel_api::resource::net::{PacketByteCount, PacketPayload};
use kernel_api::service::netdev::{
    MacAddress as PortMacAddress, NETDEV_FLAG_ADMIN_UP, NETDEV_FLAG_HEALTHY, NETDEV_FLAG_LINK_UP,
    NetDeviceInfo, NetDevicePort, NetDriverEvent, NetPortId, NetPortRegistration,
    NetPortRuntimeHandle, NetPortStats, NetRxFrameLayout, NetRxMeta, NetTxMeta, PrimaryPortPolicy,
    TxDeviceOutcome, TxSubmission,
};

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::EndpointAddr;
use crate::net::l4::tcp::segment::{TcpSegmentBuilder, send_tcp_segment_payload_in};
use crate::net::l4::udp::UdpEndpoint;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use crate::sync::PoisonLock;

const NETWORK_PATH_ITERATIONS: usize = 128;
const NETWORK_PATH_PAYLOAD_LEN: usize = 256;
const TX_COMPLETION_TIMEOUT_MS: u64 = 5_000;
const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

struct NetworkPathBenchmark {
    name: &'static str,
    iterations: usize,
    payload_bytes: usize,
    total_cycles: u64,
    backing_identity_preserved: bool,
    pool_capacity_delta: usize,
    packet_pool_lease_delta: u64,
    kernel_heap_allocation_delta: u64,
}

impl NetworkPathBenchmark {
    fn report(&self) {
        let average_cycles = self
            .total_cycles
            .checked_div(self.iterations as u64)
            .unwrap_or(0);
        let bytes_per_million_cycles = self
            .payload_bytes
            .saturating_mul(1_000_000)
            .checked_div(usize::try_from(self.total_cycles).unwrap_or(usize::MAX))
            .unwrap_or(0);
        log::info!(
            "  Zero-copy path record: path={} iterations={} backing_identity_preserved={} pool_capacity_delta={} packet_pool_lease_delta={} kernel_heap_allocation_delta={} bytes={} cycles={} average_cycles={} bytes_per_1000000_cycles={}\n",
            self.name,
            self.iterations,
            self.backing_identity_preserved,
            self.pool_capacity_delta,
            self.packet_pool_lease_delta,
            self.kernel_heap_allocation_delta,
            self.payload_bytes,
            self.total_cycles,
            average_cycles,
            bytes_per_million_cycles,
        );
    }
}

struct BenchmarkPortState {
    runtime: PoisonLock<Option<NetPortRuntimeHandle>>,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    expected_tx_payload: PoisonLock<Option<core::ops::Range<u64>>>,
    tx_identity_mismatches: AtomicU64,
    tx_invalid_frames: AtomicU64,
    tx_completion: PoisonLock<Option<Waker>>,
}

impl BenchmarkPortState {
    const fn new() -> Self {
        Self {
            runtime: PoisonLock::new(None),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            expected_tx_payload: PoisonLock::new(None),
            tx_identity_mismatches: AtomicU64::new(0),
            tx_invalid_frames: AtomicU64::new(0),
            tx_completion: PoisonLock::new(None),
        }
    }

    fn submit_rx_frame(&self, frame: &[u8]) -> Result<u64, &'static str> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| "benchmark port runtime lock poisoned")?
            .ok_or("benchmark port runtime is not installed")?;
        let frame_len = PacketByteCount::new(frame.len()).ok_or("empty benchmark RX frame")?;
        let layout = NetRxFrameLayout::whole_payload(frame_len)
            .ok_or("invalid benchmark RX frame layout")?;
        let buffer = runtime
            .lease_rx_buffer()
            .ok_or("benchmark port could not lease an RX buffer")?;
        let region = buffer.writable_region();
        if frame.len() > region.writable_len() {
            return Err("benchmark RX frame exceeds DMA region");
        }
        // SAFETY: the runtime lease grants this benchmark driver exclusive
        // write authority over the advertised region until completion.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), region.cpu_ptr(), frame.len());
        }
        let device_addr = region.device_addr().get();
        let received = buffer
            .complete(NetRxMeta::new(0, layout, 0))
            .map_err(|_| "benchmark RX completion layout is invalid")?;
        runtime.submit_rx(received)?;
        Ok(device_addr)
    }
}

struct BenchmarkPort {
    state: Arc<BenchmarkPortState>,
    info: NetDeviceInfo,
}

impl NetDevicePort for BenchmarkPort {
    fn info(&self) -> NetDeviceInfo {
        self.info
    }

    fn start(&self, runtime: NetPortRuntimeHandle) -> Result<(), &'static str> {
        *self
            .state
            .runtime
            .lock()
            .map_err(|_| "benchmark port runtime lock poisoned")? = Some(runtime);
        Ok(())
    }

    fn submit_tx_chain(
        &self,
        submission: TxSubmission<'_>,
        _meta: NetTxMeta,
    ) -> Result<(), &'static str> {
        let expected_payload = self
            .state
            .expected_tx_payload
            .lock()
            .map_err(|_| "benchmark TX expectation lock poisoned")?
            .clone();
        if let Some(expected) = expected_payload {
            if !valid_benchmark_tcp_frame(submission) {
                self.state.tx_invalid_frames.fetch_add(1, Ordering::Relaxed);
            }
            let preserved = submission.segments().iter().any(|segment| {
                let start = segment.device_addr().get();
                let end = start.saturating_add(segment.len().get() as u64);
                start <= expected.start && expected.end <= end
            });
            if !preserved {
                self.state
                    .tx_identity_mismatches
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        let frame_bytes = submission.segments().iter().fold(0u64, |total, segment| {
            total.saturating_add(segment.len().get() as u64)
        });
        let runtime = self
            .state
            .runtime
            .lock()
            .map_err(|_| "benchmark port runtime lock poisoned")?
            .ok_or("benchmark port runtime is not installed")?;
        runtime.complete_tx_lease(submission.lease_id(), TxDeviceOutcome::Transmitted)?;
        self.state
            .tx_bytes
            .fetch_add(frame_bytes, Ordering::Relaxed);
        self.state.tx_packets.fetch_add(1, Ordering::Release);
        let waiter = self
            .state
            .tx_completion
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
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

    fn stop(&self) -> Result<(), &'static str> {
        *self
            .state
            .runtime
            .lock()
            .map_err(|_| "benchmark port runtime lock poisoned")? = None;
        Ok(())
    }
}

/// Simple cycle counter for benchmarking
#[inline(always)]
fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags)
        );
        ((hi as u64) << 32) | (lo as u64)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // Fallback for non-x86_64
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

fn internet_checksum(mut bytes: impl Iterator<Item = u8>) -> u16 {
    let mut sum = 0u32;
    while let Some(high) = bytes.next() {
        let low = bytes.next().unwrap_or(0);
        sum += u32::from(u16::from_be_bytes([high, low]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Observe the complete descriptor stream before returning the DMA lease.
/// Wire checks deliberately do not use the stack's parsers or checksum code.
fn valid_benchmark_tcp_frame(submission: TxSubmission<'_>) -> bool {
    let frame_len: usize = submission.segments().iter().map(|s| s.len().get()).sum();
    let bytes = || {
        submission.segments().iter().flat_map(|segment| {
            // SAFETY: the driver submission holds read authority for every
            // initialized segment until complete_tx_lease, which is called
            // only after this validation has finished. No view escapes.
            unsafe { core::slice::from_raw_parts(segment.cpu_ptr(), segment.len().get()) }
                .iter()
                .copied()
        })
    };
    let mut header = [0u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + 20];
    if frame_len != header.len() + NETWORK_PATH_PAYLOAD_LEN {
        return false;
    }
    for (slot, byte) in header.iter_mut().zip(bytes()) {
        *slot = byte;
    }
    let ip = &header[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN];
    let ip_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let tcp = &header[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..];
    if header[12..14] != [0x08, 0x00]
        || ip[0] != 0x45
        || ip[9] != 6
        || ip_len + ETHERNET_HEADER_LEN != frame_len
        || internet_checksum(ip.iter().copied()) != 0
        || tcp[12] >> 4 != 5
    {
        return false;
    }
    let tcp_len = (ip_len - IPV4_HEADER_LEN) as u16;
    let mut pseudo = [0u8; 12];
    pseudo[..8].copy_from_slice(&ip[12..20]);
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&tcp_len.to_be_bytes());
    internet_checksum(
        pseudo
            .into_iter()
            .chain(bytes().skip(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)),
    ) == 0
        && bytes().skip(header.len()).all(|byte| byte == 0xa5)
}

fn verify_tcp_segment_vectors(runtime: NetRuntimeHandle) -> Result<(), &'static str> {
    // RFC 9293 section 3.1: the pseudo-header length includes the TCP header,
    // options and odd-length data; final checksum padding is not transmitted.
    // Fixed vector: ports 12345/80, seq/ack 1/2, ACK, window 4096, MSS 1460,
    // data "abcde". These answers do not call production checksum helpers.
    for (local, remote, checksum) in [
        (
            EndpointAddr::new([192, 0, 2, 1], 12345),
            EndpointAddr::new([198, 51, 100, 2], 80),
            0x4189,
        ),
        (
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345),
            EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80),
            0x2dbf,
        ),
    ] {
        for pieces in [&[5usize][..], &[2, 3][..], &[1, 2, 2][..]] {
            for has_headroom in [true, false] {
                let mut packets = Vec::new();
                let mut identities = Vec::new();
                let mut offset = 0;
                for &len in pieces {
                    let mut packet = crate::net::datapath::mempool::alloc_packet_in(runtime)
                        .ok_or("TCP vector packet allocation failed")?;
                    if !has_headroom {
                        if let Some(headroom) = PacketByteCount::new(packet.headroom()) {
                            packet
                                .try_retreat(headroom)
                                .map_err(|_| "TCP vector headroom")?;
                        }
                    }
                    packet
                        .try_resize(len)
                        .map_err(|_| "TCP vector packet resize")?;
                    packet
                        .data_mut()
                        .copy_from_slice(&b"abcde"[offset..offset + len]);
                    offset += len;
                    identities.push(packet.device_address()..packet.device_address() + len as u64);
                    packets.push(packet);
                }
                let payload = PacketPayload::try_from_segments(packets)
                    .map_err(|_| "TCP vector payload construction")?;
                let segment = TcpSegmentBuilder::new(local.port(), remote.port())
                    .seq(1)
                    .ack(2)
                    .ack_flag()
                    .window(4096)
                    .mss(1460)
                    .payload_packet(payload)
                    .build_checked_packet(local, remote)
                    .map_err(|_| "TCP vector segment construction")?;
                let view = crate::net::payload::PacketPayloadView::new(&segment);
                if segment.total_len() != 29
                    || segment.segments().iter().map(|p| p.len()).sum::<usize>() != 29
                    || view.read_u16_be(16) != Some(checksum)
                    || view.read_array::<5>(24) != Some(*b"abcde")
                    || !identities.iter().all(|identity| {
                        segment.segments().iter().any(|packet| {
                            packet.device_address() <= identity.start
                                && identity.end <= packet.device_address() + packet.len() as u64
                        })
                    })
                {
                    return Err("TCP vector wire length, checksum or backing mismatch");
                }
            }
        }
    }
    log::info!("[BENCH] TCP IPv4/IPv6 wire vectors and backing identity passed");
    Ok(())
}

fn build_udp_ipv4_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let udp_len = UDP_HEADER_LEN
        .checked_add(payload.len())
        .ok_or("benchmark UDP length overflow")?;
    let ip_len = IPV4_HEADER_LEN
        .checked_add(udp_len)
        .ok_or("benchmark IPv4 length overflow")?;
    let frame_len = ETHERNET_HEADER_LEN
        .checked_add(ip_len)
        .ok_or("benchmark Ethernet length overflow")?;
    let udp_len = u16::try_from(udp_len).map_err(|_| "benchmark UDP datagram too large")?;
    let ip_len = u16::try_from(ip_len).map_err(|_| "benchmark IPv4 packet too large")?;
    let mut frame = alloc::vec![0u8; frame_len];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip = &mut frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
    ip[4..6].copy_from_slice(&0xb001u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(src_ip.as_bytes());
    ip[16..20].copy_from_slice(dst_ip.as_bytes());
    let checksum = internet_checksum(ip.iter().copied());
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());

    let udp_offset = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;
    let udp = &mut frame[udp_offset..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&0u16.to_be_bytes());
    udp[UDP_HEADER_LEN..].copy_from_slice(payload);
    Ok(frame)
}

fn configure_benchmark_address(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    address: Ipv4Address,
) -> Result<(), &'static str> {
    let mut config = crate::net::runtime::manager::get_interface_in(runtime, if_id)
        .map_err(|_| "benchmark interface lookup failed")?
        .and_then(|interface| interface.config)
        .ok_or("benchmark interface has no configuration")?;
    config.ipv4.address = address;
    crate::net::runtime::manager::set_interface_config_in(runtime, if_id, config)
        .map_err(|_| "benchmark interface configuration failed")
}

fn drain_runtime_commands(
    runtime: NetRuntimeHandle,
    handler: &crate::net::runtime::command_handler::RuntimeCommandHandler,
    online: &crate::cpu::CpuSet,
) -> Result<usize, &'static str> {
    let mut total = 0usize;
    for _ in 0..8 {
        let mut processed = 0usize;
        for cpu_id in online {
            let resources =
                crate::net::runtime::command::command_resources_for_cpu_in(runtime, cpu_id)
                    .map_err(|_| "benchmark command resources unavailable")?;
            let mut stack_guard = resources
                .stack
                .lock()
                .map_err(|_| "benchmark stack lock poisoned")?;
            let core_stack = stack_guard
                .as_mut()
                .ok_or("benchmark stack is not initialized")?;
            while let Some(command) = resources.command_queue.recv() {
                let result = handler.handle_event_with_stack_in(runtime, command, core_stack);
                if !matches!(
                    result,
                    crate::net::runtime::command_handler::EventHandleResult::Success
                ) {
                    return Err("benchmark runtime command failed");
                }
                processed = processed.saturating_add(1);
            }
        }
        total = total.saturating_add(processed);
        if processed == 0 {
            return Ok(total);
        }
    }
    Err("benchmark runtime command queue did not quiesce")
}

fn runtime_pool_stats(
    runtime: NetRuntimeHandle,
) -> Result<crate::net::datapath::mempool::MempoolStats, &'static str> {
    crate::net::datapath::mempool::net_mempool_in(runtime)
        .map(crate::net::datapath::mempool::Mempool::stats)
        .ok_or("benchmark packet pool unavailable")
}

fn payload_matches(payload: &PacketPayload, expected: &[u8]) -> bool {
    let view = crate::net::payload::PacketPayloadView::new(payload);
    if view.total_len() != expected.len() {
        return false;
    }
    let mut offset = 0usize;
    let mut matches = true;
    view.for_each_chunk(|chunk| {
        let end = offset.saturating_add(chunk.len());
        if end > expected.len() || chunk != &expected[offset..end] {
            matches = false;
        }
        offset = end;
    });
    matches && offset == expected.len()
}

async fn wait_for_tx_completion(state: &BenchmarkPortState, expected_packets: u64) {
    poll_fn(|cx| {
        let mut waiter = state
            .tx_completion
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.tx_packets.load(Ordering::Acquire) >= expected_packets {
            Poll::Ready(())
        } else {
            *waiter = Some(cx.waker().clone());
            Poll::Pending
        }
    })
    .await;
}

fn clear_tx_completion_waiter(state: &BenchmarkPortState) {
    *state
        .tx_completion
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
}

/// Benchmark result
pub struct BenchmarkResult {
    pub name: &'static str,
    pub iterations: u64,
    pub total_cycles: u64,
    pub min_cycles: u64,
    pub max_cycles: u64,
    pub avg_cycles: u64,
}

impl BenchmarkResult {
    pub fn new(name: &'static str) -> Self {
        BenchmarkResult {
            name,
            iterations: 0,
            total_cycles: 0,
            min_cycles: u64::MAX,
            max_cycles: 0,
            avg_cycles: 0,
        }
    }

    pub fn record(&mut self, cycles: u64) {
        self.iterations += 1;
        self.total_cycles += cycles;
        self.min_cycles = self.min_cycles.min(cycles);
        self.max_cycles = self.max_cycles.max(cycles);
        self.avg_cycles = self.total_cycles / self.iterations;
    }

    pub fn report(&self) {
        log::info!("  Benchmark: {}\n", self.name);
        log::info!("    Iterations: {}\n", self.iterations);
        log::info!("    Total cycles: {}\n", self.total_cycles);
        log::info!("    Min cycles: {}\n", self.min_cycles);
        log::info!("    Max cycles: {}\n", self.max_cycles);
        log::info!("    Avg cycles: {}\n", self.avg_cycles);
    }
}

async fn benchmark_network_paths() -> Result<(), &'static str> {
    use crate::net::security::firewall::{
        FirewallAction, FirewallDirection, set_default_policy_in,
    };

    let runtime = crate::net::runtime::create_runtime()
        .map_err(|_| "network benchmark runtime allocation failed")?;
    set_default_policy_in(runtime, FirewallDirection::Ingress, FirewallAction::Allow)
        .map_err(|_| "network benchmark ingress policy setup failed")?;
    set_default_policy_in(runtime, FirewallDirection::Egress, FirewallAction::Allow)
        .map_err(|_| "network benchmark egress policy setup failed")?;

    let state = Arc::new(BenchmarkPortState::new());
    let local_mac = [0x02, 0, 0, 0, 0xb0, 1];
    let remote_mac = [0x02, 0, 0, 0, 0xb0, 2];
    let info = NetDeviceInfo {
        port_id: NetPortId::new(0xb001),
        driver_name: "zero-copy-benchmark",
        queue_pairs: 1,
        max_tx_segments: core::num::NonZeroU16::new(8)
            .expect("benchmark TX segment limit is non-zero"),
        mtu: crate::net::runtime::stack::MTU as u32,
        mac: PortMacAddress::new(local_mac),
        flags: NETDEV_FLAG_ADMIN_UP | NETDEV_FLAG_HEALTHY | NETDEV_FLAG_LINK_UP,
        ..NetDeviceInfo::default()
    };
    let driver: Box<dyn NetDevicePort> = Box::new(BenchmarkPort {
        state: Arc::clone(&state),
        info,
    });
    let if_id = crate::net::runtime::device::register_port_in(
        runtime,
        NetPortRegistration::new(info, driver, PrimaryPortPolicy::Auto),
    )?;
    crate::net::services::dhcp::unregister_interface_runtime_in(runtime, if_id);

    let benchmark_result = async {
        verify_tcp_segment_vectors(runtime)?;
        let local_ip = Ipv4Address::new([10, 176, 0, 2]);
        let remote_ip = Ipv4Address::new([10, 176, 0, 1]);
        configure_benchmark_address(runtime, if_id, local_ip)?;
        let online = crate::cpu::snapshot().online().clone();
        if online.is_empty() {
            return Err("network benchmark has no online CPU");
        }
        let handler = crate::net::runtime::command_handler::RuntimeCommandHandler::new();
        drain_runtime_commands(runtime, &handler, &online)?;
        for cpu_id in &online {
            let stack_lock = crate::net::runtime::stack::stack_for_cpu_in(runtime, cpu_id)
                .map_err(|_| "network benchmark stack unavailable")?;
            let mut stack_guard = stack_lock
                .lock()
                .map_err(|_| "network benchmark stack lock poisoned")?;
            stack_guard
                .as_mut()
                .ok_or("network benchmark stack is not initialized")?
                .arp_cache_insert_on(
                    if_id,
                    remote_ip,
                    crate::net::l2::ethernet::MacAddress::new(remote_mac),
                    1,
                );
        }

        let destination_port = 42_176;
        let endpoint = UdpEndpoint::bind_in(
            runtime,
            InterfaceScope::Pinned(if_id),
            destination_port,
            None,
        )
        .map_err(|_| "network benchmark UDP endpoint bind failed")?;
        let payload_bytes = [0x5au8; NETWORK_PATH_PAYLOAD_LEN];
        let frame = build_udp_ipv4_frame(
            local_mac,
            remote_mac,
            remote_ip,
            local_ip,
            40_176,
            destination_port,
            &payload_bytes,
        )?;

        let warmup_dma_addr = state.submit_rx_frame(&frame)?;
        drain_runtime_commands(runtime, &handler, &online)?;
        let (_, _, _, warmup_payload) = endpoint
            .try_recv()
            .ok_or("network benchmark RX warmup was not delivered")?;
        let warmup_expected = warmup_dma_addr
            .checked_add((ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN) as u64)
            .ok_or("network benchmark RX address overflow")?;
        if warmup_payload.segments().len() != 1
            || warmup_payload.segments()[0].device_address() != warmup_expected
            || !payload_matches(&warmup_payload, &payload_bytes)
        {
            return Err("network benchmark RX warmup changed packet backing");
        }
        drop(warmup_payload);

        let rx_pool_before = runtime_pool_stats(runtime)?;
        let rx_heap_before = crate::profiler::profiler()
            .memory
            .stats()
            .kernel_heap_allocations;
        let mut rx_cycles = 0u64;
        let mut rx_identity_preserved = true;
        for _ in 0..NETWORK_PATH_ITERATIONS {
            let start = rdtsc();
            let dma_addr = state.submit_rx_frame(&frame)?;
            drain_runtime_commands(runtime, &handler, &online)?;
            let (_, _, _, received) = endpoint
                .try_recv()
                .ok_or("network benchmark RX packet was not delivered")?;
            let end = rdtsc();
            let expected_payload_addr = dma_addr
                .checked_add((ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN) as u64)
                .ok_or("network benchmark RX address overflow")?;
            rx_identity_preserved &= received.segments().len() == 1
                && received.segments()[0].device_address() == expected_payload_addr
                && payload_matches(&received, &payload_bytes);
            rx_cycles = rx_cycles.saturating_add(end.saturating_sub(start));
        }
        let rx_pool_after = runtime_pool_stats(runtime)?;
        let rx_heap_after = crate::profiler::profiler()
            .memory
            .stats()
            .kernel_heap_allocations;
        NetworkPathBenchmark {
            name: "rx_to_udp_endpoint",
            iterations: NETWORK_PATH_ITERATIONS,
            payload_bytes: NETWORK_PATH_PAYLOAD_LEN.saturating_mul(NETWORK_PATH_ITERATIONS),
            total_cycles: rx_cycles,
            backing_identity_preserved: rx_identity_preserved,
            pool_capacity_delta: rx_pool_after
                .total_buffers
                .saturating_sub(rx_pool_before.total_buffers),
            packet_pool_lease_delta: rx_pool_after
                .alloc_count
                .saturating_sub(rx_pool_before.alloc_count),
            kernel_heap_allocation_delta: rx_heap_after.saturating_sub(rx_heap_before),
        }
        .report();
        if !rx_identity_preserved {
            return Err("network benchmark RX path changed packet backing");
        }

        let local = EndpointAddr::new(local_ip.octets(), 40_177);
        let remote = EndpointAddr::new(remote_ip.octets(), 443);
        let tx_once = async |sequence: u32| -> Result<(), &'static str> {
            let mut packet = crate::net::datapath::mempool::alloc_packet_in(runtime)
                .ok_or("network benchmark TCP payload allocation failed")?;
            packet
                .try_resize(NETWORK_PATH_PAYLOAD_LEN)
                .map_err(|_| "network benchmark TCP payload resize failed")?;
            packet.data_mut().fill(0xa5);
            let owner_addr = packet.device_address();
            let payload_end = owner_addr
                .checked_add(NETWORK_PATH_PAYLOAD_LEN as u64)
                .ok_or("network benchmark TX address overflow")?;
            let payload = PacketPayload::try_single(packet)
                .map_err(|_| "network benchmark TCP payload construction failed")?;
            let segment = TcpSegmentBuilder::new(local.port(), remote.port())
                .seq(sequence)
                .ack(1)
                .ack_flag()
                .psh()
                .payload_packet(payload)
                .build_checked_packet(local, remote)
                .map_err(|_| "network benchmark TCP segment construction failed")?;
            if !segment.segments().iter().any(|packet| {
                let start = packet.device_address();
                let end = start.saturating_add(packet.len() as u64);
                start <= owner_addr && payload_end <= end
            }) {
                return Err("network benchmark TCP builder changed payload backing");
            }
            *state
                .expected_tx_payload
                .lock()
                .map_err(|_| "benchmark TX expectation lock poisoned")? =
                Some(owner_addr..payload_end);
            let expected_packets = state.tx_packets.load(Ordering::Acquire).saturating_add(1);
            if !send_tcp_segment_payload_in(runtime, if_id, local, remote, segment) {
                return Err("network benchmark TCP send was not admitted");
            }
            drain_runtime_commands(runtime, &handler, &online)?;
            wait_for_tx_completion(&state, expected_packets).await;
            if state.tx_invalid_frames.load(Ordering::Acquire) != 0 {
                return Err("network benchmark TX wire length, checksum or payload mismatch");
            }
            Ok(())
        };

        let warmup_result = crate::task::with_timeout(tx_once(0), TX_COMPLETION_TIMEOUT_MS).await;
        clear_tx_completion_waiter(&state);
        match warmup_result {
            crate::task::TimeoutResult::Completed(result) => result?,
            crate::task::TimeoutResult::TimedOut => {
                return Err("network benchmark TX warmup did not complete the lease");
            }
        }
        *state
            .expected_tx_payload
            .lock()
            .map_err(|_| "benchmark TX expectation lock poisoned")? = None;
        let tx_pool_before = runtime_pool_stats(runtime)?;
        let tx_packets_before = state.tx_packets.load(Ordering::Acquire);
        let tx_bytes_before = state.tx_bytes.load(Ordering::Acquire);
        let tx_mismatches_before = state.tx_identity_mismatches.load(Ordering::Acquire);
        let tx_heap_before = crate::profiler::profiler()
            .memory
            .stats()
            .kernel_heap_allocations;
        let mut tx_cycles = 0u64;
        let measured_tx = async {
            for iteration in 0..NETWORK_PATH_ITERATIONS {
                let start = rdtsc();
                tx_once(iteration as u32 + 1).await?;
                let end = rdtsc();
                tx_cycles = tx_cycles.saturating_add(end.saturating_sub(start));
            }
            Ok::<(), &'static str>(())
        };
        let measured_result =
            crate::task::with_timeout(measured_tx, TX_COMPLETION_TIMEOUT_MS).await;
        clear_tx_completion_waiter(&state);
        match measured_result {
            crate::task::TimeoutResult::Completed(result) => result?,
            crate::task::TimeoutResult::TimedOut => {
                return Err("network benchmark TX measurement did not complete all leases");
            }
        }
        *state
            .expected_tx_payload
            .lock()
            .map_err(|_| "benchmark TX expectation lock poisoned")? = None;
        let tx_pool_after = runtime_pool_stats(runtime)?;
        let tx_packets_after = state.tx_packets.load(Ordering::Acquire);
        let tx_bytes_after = state.tx_bytes.load(Ordering::Acquire);
        let tx_mismatches_after = state.tx_identity_mismatches.load(Ordering::Acquire);
        let tx_heap_after = crate::profiler::profiler()
            .memory
            .stats()
            .kernel_heap_allocations;
        let tx_identity_preserved = tx_mismatches_after == tx_mismatches_before
            && tx_packets_after.saturating_sub(tx_packets_before) == NETWORK_PATH_ITERATIONS as u64
            && tx_bytes_after > tx_bytes_before;
        NetworkPathBenchmark {
            name: "tcp_payload_to_driver_completion",
            iterations: NETWORK_PATH_ITERATIONS,
            payload_bytes: NETWORK_PATH_PAYLOAD_LEN.saturating_mul(NETWORK_PATH_ITERATIONS),
            total_cycles: tx_cycles,
            backing_identity_preserved: tx_identity_preserved,
            pool_capacity_delta: tx_pool_after
                .total_buffers
                .saturating_sub(tx_pool_before.total_buffers),
            packet_pool_lease_delta: tx_pool_after
                .alloc_count
                .saturating_sub(tx_pool_before.alloc_count),
            kernel_heap_allocation_delta: tx_heap_after.saturating_sub(tx_heap_before),
        }
        .report();
        if !tx_identity_preserved {
            return Err("network benchmark TCP path changed packet backing");
        }
        Ok(())
    }
    .await;

    let unregistered = crate::net::runtime::device::unregister_port_in(runtime, if_id)?;
    if !unregistered {
        return Err("network benchmark port was not registered during cleanup");
    }
    benchmark_result
}

/// Benchmark network stack performance
fn bench_network() {
    use crate::net::l2::ethernet::{EthernetFrame, MacAddress};
    use crate::net::l3::ipv4::Ipv4Packet;
    use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

    const ITERATIONS: usize = 10000;

    log::info!("\n[BENCH] Network Stack Benchmark\n");

    // Ethernet frame parsing
    let mut eth_parse = BenchmarkResult::new("ethernet_parse");
    let frame_data = {
        let mut data = [0u8; 64];
        data[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        data[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data[12..14].copy_from_slice(&[0x08, 0x00]);
        data
    };

    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let frame = EthernetFrame::parse(&frame_data);
        let end = rdtsc();
        eth_parse.record(end - start);
        core::hint::black_box(frame);
    }
    eth_parse.report();

    // IPv4 packet parsing
    let mut ip_parse = BenchmarkResult::new("ipv4_parse");
    let packet_data = {
        let mut data = [0u8; 40];
        data[0] = 0x45;
        data[2..4].copy_from_slice(&[0x00, 0x28]);
        data[8] = 64;
        data[9] = 6;
        data[12..16].copy_from_slice(&[192, 168, 1, 1]);
        data[16..20].copy_from_slice(&[192, 168, 1, 2]);
        data
    };

    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let packet = Ipv4Packet::parse(&packet_data);
        let end = rdtsc();
        ip_parse.record(end - start);
        core::hint::black_box(packet);
    }
    ip_parse.report();

    // MAC address comparison
    let mut mac_cmp = BenchmarkResult::new("mac_compare");
    let mac1 = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    let mac2 = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x56);

    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let equal = mac1 == mac2;
        let end = rdtsc();
        mac_cmp.record(end - start);
        core::hint::black_box(equal);
    }
    mac_cmp.report();

    // Packet ownership handoff. The packet is allocated before the measured
    // steady-state loop so PacketPayload::One construction and destruction can
    // be observed independently from pool admission.
    let mut packet = crate::net::payload::alloc_packet_with_headroom(256, DEFAULT_PACKET_HEADROOM)
        .expect("network benchmark packet allocation");
    packet.data_mut().fill(0x5a);
    let backing = packet.as_ptr();
    let pool_allocations_before = crate::net::datapath::mempool::net_mempool()
        .map(crate::net::datapath::mempool::Mempool::stats)
        .map_or(0, |stats| stats.alloc_count);
    let mut packet_handoff = BenchmarkResult::new("packet_payload_owner_handoff_256b");
    let heap_before = crate::profiler::profiler()
        .memory
        .stats()
        .kernel_heap_allocations;
    let mut backing_identity_preserved = true;
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let payload =
            PacketPayload::try_single(packet).expect("benchmark packet remains a non-empty owner");
        let mut segments = payload.into_segments();
        packet = segments.next().expect("single payload returns one owner");
        backing_identity_preserved &= packet.as_ptr() == backing;
        let end = rdtsc();
        packet_handoff.record(end - start);
    }
    let pool_allocations_after = crate::net::datapath::mempool::net_mempool()
        .map(crate::net::datapath::mempool::Mempool::stats)
        .map_or(0, |stats| stats.alloc_count);
    let heap_after = crate::profiler::profiler()
        .memory
        .stats()
        .kernel_heap_allocations;
    packet_handoff.report();
    log::info!(
        "  Zero-copy record: backing_identity_preserved={} packet_pool_lease_delta={} kernel_heap_allocation_delta={} bytes={} cycles={}\n",
        backing_identity_preserved,
        pool_allocations_after.saturating_sub(pool_allocations_before),
        heap_after.saturating_sub(heap_before),
        256usize.saturating_mul(ITERATIONS),
        packet_handoff.total_cycles,
    );
    core::hint::black_box(packet);

    log::info!("[BENCH] Network benchmark completed\n\n");
}

pub(super) async fn run_network_benchmarks() -> Result<(), &'static str> {
    log::info!("\n[BENCH] Zero-copy Network Path Benchmark Suite\n");
    bench_network();
    benchmark_network_paths().await?;
    log::info!("[BENCH] Zero-copy network path benchmark suite completed\n\n");
    Ok(())
}
