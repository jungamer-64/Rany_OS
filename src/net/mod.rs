// ============================================================================
// src/net/mod.rs - Network Subsystem
// 設計書 6.2: ネットワークスタック：真のゼロコピー
// ============================================================================

pub mod mempool;
pub mod tcp;

// Phase 4: High-Performance Network
pub mod adaptive_polling;
pub mod zero_copy;

// Phase 5+: Advanced Performance Optimization
pub mod optimization;

// Protocol layers
pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod udp;

// Network services
pub mod dhcp;
pub mod dns;

// Integrated network stack
pub mod stack;

// VirtIO-Net driver bridge
pub mod driver_bridge;

// Endpoint API (旧称: socket → ゼロコピー所有権モデルを反映)
pub mod endpoint;

// TLS support
pub mod tls;

// Re-export mempool
#[allow(unused_imports)]
pub use mempool::{
    Mempool, MempoolStats, PacketBuffer, PacketPool, PacketRef, alloc_packet, init_net_mempool,
    net_mempool,
};

// Re-export TCP
#[allow(unused_imports)]
pub use tcp::{
    // トレイト
    AsyncRead,
    AsyncWrite,
    // アドレス
    Ipv4Addr,
    SocketAddr,
    // エラー
    TcpError,
    TcpListener,
    TcpProcessor,
    TcpState,
    // ストリーム・リスナー
    TcpStream,
};

// Re-export Ethernet
#[allow(unused_imports)]
pub use ethernet::{
    EtherType, EthernetFrame, EthernetFrameMut, EthernetHeader, EthernetProcessor, EthernetStats,
    MacAddress,
};

// Re-export IPv4
#[allow(unused_imports)]
pub use ipv4::{
    IpProtocol, Ipv4Address, Ipv4Config, Ipv4Header, Ipv4Packet, Ipv4PacketMut, Ipv4Processor,
    Ipv4Stats,
};

// Re-export ARP
#[allow(unused_imports)]
pub use arp::{
    ArpCache, ArpEntry, ArpEntryState, ArpHardwareType, ArpOperation, ArpPacket, ArpProcessor,
    ArpResult,
};

// Re-export ICMP
#[allow(unused_imports)]
pub use icmp::{
    DestUnreachCode, IcmpBuilder, IcmpEcho, IcmpEchoBuilder, IcmpEchoHeader, IcmpHeader,
    IcmpPacket, IcmpProcessor, IcmpResult, IcmpStats, IcmpType, TimeExceededCode,
};

// Re-export UDP
#[allow(unused_imports)]
pub use udp::{
    UdpAddr, UdpDatagram, UdpHeader, UdpPacket, UdpPacketMut, UdpProcessor, UdpResult, UdpSocket,
    UdpSocketTable,
};

// Re-export DHCP
#[allow(unused_imports)]
pub use dhcp::{
    DHCP_CLIENT_PORT, DHCP_MAGIC_COOKIE, DHCP_SERVER_PORT, DhcpClient, DhcpHeader, DhcpLease,
    DhcpMessageType, DhcpOperation, DhcpResponseResult, DhcpState, client as dhcp_client,
    init as init_dhcp,
};

// Re-export DNS
#[allow(unused_imports)]
pub use dns::{
    DNS_PORT, DnsCache, DnsCacheEntry, DnsClient, DnsHeader, DnsQueryClass, DnsQueryType,
    DnsRecord, DnsRecordData, DnsResponseCode, DnsStats, init as init_dns,
    resolve_cached as dns_resolve_cached, set_servers as set_dns_servers,
};

// Re-export Network Stack
#[allow(unused_imports)]
pub use stack::{
    MAX_PACKET_SIZE, MTU, NetworkConfig, NetworkStack, NetworkStats, bind_udp, init as init_stack,
    init_default as init_stack_default, receive, send_tcp, send_udp, stack as global_stack,
};

// Re-export VirtIO-Net driver bridge
#[allow(unused_imports)]
pub use driver_bridge::{
    BridgeStats, init_bridge as init_driver_bridge, is_initialized as driver_bridge_initialized,
    process_received_packet, get_bridge_stats, get_real_config, get_real_stats,
    send_real_icmp_echo, get_real_arp_cache,
};

// VirtIO Netドライバはio/virtio_net.rsにある
// 再エクスポート
#[allow(unused_imports)]
pub use crate::io::virtio_net::{
    NetVirtQueue, VirtioNetDevice, VirtioNetHeader, VirtioNetStats, VringDesc as NetVringDesc,
    features as net_features, handle_virtio_net_interrupt, init_virtio_net,
};

// Re-export Phase 4 High-Performance Networking
#[allow(unused_imports)]
pub use adaptive_polling::{
    AdaptivePoller, BusyPollConfig, NapiLike, PerCorePolling, PollingManager, PollingMode,
    init as init_adaptive_polling,
};

#[allow(unused_imports)]
pub use zero_copy::{
    EthernetHeaderView, Ipv4HeaderView, MemoryPool, PacketChain, PoolId, PoolManager,
    SgEntry as ZcSgEntry, SgList, ZeroCopyBuffer, ZeroCopyReader, ZeroCopyWriter,
    init as init_zero_copy,
};

// Re-export Phase 5+ Advanced Optimization
#[allow(unused_imports)]
pub use optimization::{
    AdaptiveCoalescing,
    BatchConfig,
    BatchProcessor,
    BatchStats,
    // CPU Affinity
    CpuAffinity,
    FlowAffinity,
    // GRO/TSO
    GroSegment,
    GroTable,
    // Interrupt coalescing
    InterruptCoalescing,
    MAX_BATCH_SIZE,
    // Metrics
    NetworkMetrics,
    NumaMempool,
    // NUMA
    NumaNode,
    NumaTopology,
    // Batch processing
    PacketBatch,
    TsoContext,
    adaptive_coalescing,
    batch_processor,
    flow_affinity,
    // Initialization
    init as init_optimization,
    metrics,
    numa_topology,
};

// Re-export Endpoint (Socket Layer with Event-Driven Architecture)
#[allow(unused_imports)]
pub use endpoint::{
    AcceptFuture,
    // Accept機能
    AcceptedConnection,
    EventHandleResult,
    EventWaitFuture,
    // イベントシステム
    NetworkEvent,
    NetworkEventHandler,
    NetworkEventQueue,
    OwnedSocket,
    RecvFromFuture,
    // Future
    RecvFuture,
    RetransmitQueue,
    RtoCalculator,
    SendFuture,
    // ソケット
    Socket,
    SocketAddr as EndpointSocketAddr, // tcpのSocketAddrと区別
    // エラー
    SocketError,
    SocketFd,
    SocketManager,
    SocketResult,
    SocketState,
    SocketType,
    TcbTable,
    // TCP制御ブロック
    TcpConnectionState,
    TcpControlBlockEntry,
    TcpSegmentBuilder,
    // 再送タイマー・RTO
    UnackedSegment,
    check_retransmit_timeouts,
    // ヘルパー
    create_tcp_socket,
    create_udp_socket,
    event_queue,
    get_or_create_retransmit_queue,
    init_network_event_handler,
    init_socket_manager,
    network_event_task,
    process_tcp_segment,
    retransmit_queue_ack,
    retransmit_queue_push,
    retransmit_queue_remove,
    send_tcp_segment,
    tcb_table,
    tcp_connect,
    tcp_flags,
    udp_bind,
};

// ============================================================================
// Shell Command API - Public interface for shell network commands
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use spin::Mutex;

extern crate alloc;

/// Network configuration snapshot for shell commands
#[derive(Debug, Clone)]
pub struct NetworkConfigSnapshot {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub mac: [u8; 6],
}

/// Network statistics snapshot for shell commands
#[derive(Debug, Clone, Copy)]
pub struct NetworkStatsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
}

/// TCP connection info for netstat
#[derive(Debug, Clone)]
pub struct TcpConnectionInfo {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
}

/// UDP socket info for netstat
#[derive(Debug, Clone)]
pub struct UdpSocketInfo {
    pub local_addr: String,
    pub remote_addr: String,
}

/// DHCP offer info
#[derive(Debug, Clone)]
pub struct DhcpOfferInfo {
    pub your_ip: [u8; 4],
    pub server_ip: [u8; 4],
    pub gateway: Option<[u8; 4]>,
    pub dns: Option<[u8; 4]>,
}

/// DHCP ACK info
#[derive(Debug, Clone)]
pub struct DhcpAckInfo {
    pub your_ip: [u8; 4],
    pub lease_time: u32,
}

/// DHCP client state
#[derive(Debug, Clone)]
pub struct DhcpStateInfo {
    pub state: String,
    pub assigned_ip: Option<[u8; 4]>,
    pub lease_remaining: Option<u32>,
}

/// ARP cache entry
#[derive(Debug, Clone)]
pub struct ArpCacheEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub complete: bool,
}

// Global network state for shell access
static NETWORK_CONFIG: Mutex<Option<NetworkConfigSnapshot>> = Mutex::new(None);
static LAST_DHCP_OFFER: Mutex<Option<DhcpOfferInfo>> = Mutex::new(None);
static NETWORK_STATS: Mutex<NetworkStatsSnapshot> = Mutex::new(NetworkStatsSnapshot {
    rx_packets: 0,
    tx_packets: 0,
    rx_bytes: 0,
    tx_bytes: 0,
    rx_errors: 0,
    rx_dropped: 0,
});

/// Get current network configuration
pub fn get_network_config() -> Option<NetworkConfigSnapshot> {
    NETWORK_CONFIG.lock().clone()
}

/// Get network statistics
pub fn get_network_stats() -> Option<NetworkStatsSnapshot> {
    // Try to get real stats from NetworkStack
    if let Some(stack_guard) = stack::stack().lock().as_ref() {
        let stats = stack_guard.stats();
        return Some(NetworkStatsSnapshot {
            rx_packets: stats.rx_packets.load(Ordering::Relaxed),
            tx_packets: stats.tx_packets.load(Ordering::Relaxed),
            rx_bytes: stats.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: stats.tx_bytes.load(Ordering::Relaxed),
            rx_errors: stats.rx_errors.load(Ordering::Relaxed),
            rx_dropped: stats.rx_dropped.load(Ordering::Relaxed),
        });
    }
    
    // Fallback to demo stats
    Some(*NETWORK_STATS.lock())
}

/// Send ICMP echo request (ping)
pub fn send_icmp_echo(target: [u8; 4], seq: u16) -> Result<f32, String> {
    // Try to use real NetworkStack
    if let Some(stack_guard) = stack::stack().lock().as_ref() {
        let target_ip = ipv4::Ipv4Address::new(target);
        
        // Attempt to send ICMP echo via stack
        if stack_guard.send_icmp_echo_request(target_ip, seq).is_ok() {
            // For now, return simulated RTT (real RTT would require async wait)
            return match target {
                [127, 0, 0, 1] => Ok(0.1),
                [10, 0, 2, 2] => Ok(1.5),
                [10, 0, 2, ..] => Ok(2.0),
                _ => Ok(10.0),
            };
        }
    }
    
    // Fallback to demo implementation
    let _ = seq;
    match target {
        [127, 0, 0, 1] => Ok(0.1),
        [10, 0, 2, 2] => Ok(1.5),
        [10, 0, 2, ..] => Ok(2.0),
        [8, 8, 8, 8] | [8, 8, 4, 4] => Err(String::from("Network unreachable")),
        _ => Err(String::from("Destination host unreachable")),
    }
}

/// Get TCP connections for netstat
pub fn get_tcp_connections() -> Option<Vec<TcpConnectionInfo>> {
    // Return None to show demo output in shell
    None
}

/// Get UDP sockets for netstat
pub fn get_udp_sockets() -> Option<Vec<UdpSocketInfo>> {
    None
}

/// DNS resolution
pub fn dns_resolve(hostname: &str) -> Result<Vec<[u8; 4]>, String> {
    // Built-in resolutions
    match hostname {
        "localhost" => Ok(alloc::vec![[127, 0, 0, 1]]),
        "gateway" | "router" => Ok(alloc::vec![[10, 0, 2, 2]]),
        _ => Err(String::from("DNS server not configured")),
    }
}

/// DHCP discover
pub fn dhcp_discover() -> Result<DhcpOfferInfo, String> {
    // Simulate QEMU's DHCP response
    let offer = DhcpOfferInfo {
        your_ip: [10, 0, 2, 15],
        server_ip: [10, 0, 2, 2],
        gateway: Some([10, 0, 2, 2]),
        dns: Some([10, 0, 2, 3]),
    };
    
    // Cache the offer
    *LAST_DHCP_OFFER.lock() = Some(offer.clone());
    
    Ok(offer)
}

/// DHCP request (accept offer)
pub fn dhcp_request() -> Result<DhcpAckInfo, String> {
    let offer = LAST_DHCP_OFFER.lock().clone();
    
    match offer {
        Some(offer_info) => {
            // Update network config
            *NETWORK_CONFIG.lock() = Some(NetworkConfigSnapshot {
                ip: offer_info.your_ip,
                netmask: [255, 255, 255, 0],
                gateway: offer_info.gateway.unwrap_or([10, 0, 2, 2]),
                mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            });
            
            Ok(DhcpAckInfo {
                your_ip: offer_info.your_ip,
                lease_time: 86400,
            })
        }
        None => Err(String::from("No DHCP offer available. Run 'dhcp discover' first.")),
    }
}

/// DHCP release
pub fn dhcp_release() {
    *LAST_DHCP_OFFER.lock() = None;
    *NETWORK_CONFIG.lock() = None;
}

/// Get DHCP state
pub fn get_dhcp_state() -> Option<DhcpStateInfo> {
    let offer = LAST_DHCP_OFFER.lock().clone();
    
    let (state_str, assigned_ip) = if let Some(offer_info) = offer {
        ("BOUND", Some(offer_info.your_ip))
    } else {
        ("INIT", None)
    };
    
    Some(DhcpStateInfo {
        state: String::from(state_str),
        assigned_ip,
        lease_remaining: Some(86400),
    })
}

/// Get ARP cache
pub fn get_arp_cache() -> Option<Vec<ArpCacheEntry>> {
    // Try to get real ARP cache from NetworkStack
    if let Some(stack_guard) = stack::stack().lock().as_ref() {
        let arp_entries = stack_guard.arp_cache();
        
        let entries: Vec<ArpCacheEntry> = arp_entries
            .iter()
            .map(|(ip, mac)| ArpCacheEntry {
                ip: *ip.as_bytes(),
                mac: *mac.as_bytes(),
                complete: true,
            })
            .collect();
        
        if !entries.is_empty() {
            return Some(entries);
        }
    }
    
    // Return None to show demo output in shell
    None
}

/// Initialize network for shell commands
pub fn init_network_shell() {
    // Initialize default network config (QEMU user mode networking)
    let default_config = NetworkConfigSnapshot {
        ip: [10, 0, 2, 15],
        netmask: [255, 255, 255, 0],
        gateway: [10, 0, 2, 2],
        mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
    };
    *NETWORK_CONFIG.lock() = Some(default_config);
}
