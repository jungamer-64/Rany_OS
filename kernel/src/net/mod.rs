// ============================================================================
// src/net/mod.rs - Network Subsystem
// 設計書 6.2: ネットワークスタック：真のゼロコピー
// ============================================================================

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use alloc::format;

/// Common Network Errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    PermissionDenied,
    PortInUse,
    InvalidAddress,
    Timeout,
    Unknown,
    /// Connection was closed
    ConnectionClosed,
    /// Internal lock was poisoned
    LockPoisoned,
    /// ARP resolution is pending (retry later)
    ArpResolutionPending,
    /// Buffer too small for operation
    BufferTooSmall,
    /// Transmit operation failed
    TransmitFailed,
}

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
pub mod igmp;
pub mod ipv4;
pub mod ipv6;
pub mod icmpv6;
pub mod ndp;
pub mod udp;

// Network services
pub mod dhcp;
pub mod dns;
pub mod mdns;

// Integrated network stack
pub mod stack;
// Multi-interface manager (transitional groundwork for multi-NIC migration)
pub mod manager;

// VirtIO-Net driver bridge
pub mod driver_bridge;

// VirtIO-Net driver for DriverRegistry
pub mod driver;

// Endpoint API (旧称: socket → ゼロコピー所有権モデルを反映)
pub mod endpoint;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

// ECDH key exchange
pub mod ecdh;

// X.509 certificate parsing
pub mod x509;

// RSA signature verification
pub mod rsa;

// TLS support
pub mod tls;

// Checksum Offload
pub mod checksum_offload;

// Timeout helpers
pub mod stack_timeouts;

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
    MacAddress, VlanEthernetFrameMut, VlanTag, insert_vlan_tag, strip_vlan_tag,
};

// Re-export IPv4
#[allow(unused_imports)]
pub use ipv4::{
    IpProtocol, Ipv4Address, Ipv4Config, Ipv4Header, Ipv4Packet, Ipv4PacketMut, Ipv4Processor,
    Ipv4Stats,
};

// Re-export IPv6
#[allow(unused_imports)]
pub use ipv6::{
    Ipv6Address, Ipv6Config, Ipv6Header, Ipv6Packet, Ipv6PacketMut, Ipv6ProcessResult,
    Ipv6Processor, Ipv6Stats,
};

// Re-export ICMPv6
#[allow(unused_imports)]
pub use icmpv6::{
    Icmpv6EchoBuilder, Icmpv6Header, Icmpv6Processor, Icmpv6Result, Icmpv6Stats, Icmpv6Type,
};

// Re-export NDP
#[allow(unused_imports)]
pub use ndp::{
    NdpOption, NdpProcessor, NdpResult, NdpStats, NeighborCache, NeighborEntry, NeighborState,
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
    UdpSocketSnapshot, UdpSocketTable,
};

// Re-export DHCP
#[allow(unused_imports)]
pub use dhcp::{
    DHCP_CLIENT_PORT, DHCP_MAGIC_COOKIE, DHCP_SERVER_PORT, DhcpClient, DhcpHeader, DhcpLease,
    DhcpMessageType, DhcpOperation, DhcpResponseResult, DhcpState, client as dhcp_client,
    init as init_dhcp,
    // DHCPv6
    DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT, DhcpV6Client, init_v6 as init_dhcpv6, client_v6,
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

// Re-export Network Manager (multi-NIC groundwork)
#[allow(unused_imports)]
pub use manager::{
    Ipv4Route, Ipv6Route, NetIfId, NetworkInterfaceInfo, NetworkManager, RouteFlags,
    add_ipv4_route, add_ipv6_route, del_ipv4_route, del_ipv6_route, get_interface,
    init_network_manager, list_interfaces, list_ipv4_routes, list_ipv6_routes,
    lookup_if_by_virtio_index, lookup_ipv4_route, lookup_ipv6_route, network_manager,
    register_interface, register_virtio_port, set_default_route_v4, set_default_route_v6,
    set_interface_config, set_interface_down, set_interface_up,
};

// Re-export VirtIO-Net driver bridge
#[allow(unused_imports)]
pub use driver_bridge::{
    BridgeInterfaceStats, BridgeStats, get_bridge_stats, get_bridge_stats_for_interface,
    get_real_arp_cache, get_real_config, get_real_config_for_interface, get_real_stats,
    get_real_stats_for_interface, init_bridge as init_driver_bridge,
    is_initialized as driver_bridge_initialized, list_bridge_stats, send_real_icmp_echo,
};

// VirtIO Netドライバはio/virtio/net.rsにある
// 再エクスポート
#[allow(unused_imports)]
pub use crate::io::virtio::{
    NetVirtQueue, VirtioNetDevice, VirtioNetHeader, VirtioNetStats, VringDesc as NetVringDesc,
    handle_virtio_net_interrupt, init_virtio_net, net_features,
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
    TsoEngine,
    TsoHeaderTemplate,
    TsoSegmentInfo,
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
    // 輻輳制御
    CongestionAlgorithm,
    // TCP制御ブロック
    TcpConnectionSnapshot,
    TcpConnectionState,
    TcpControlBlockEntry,
    TcpSegmentBuilder,
    // 再送タイマー・RTO
    UnackedSegment,
    check_retransmit_timeouts,
    // ヘルパー
    create_tcp_socket,
    create_tcp_socket_with_algorithm,
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
    tcp_flags,
};

// Re-export Checksum Offload
#[allow(unused_imports)]
pub use checksum_offload::{
    ChecksumCapabilities, ChecksumOffloadManager, ChecksumStats, RxChecksumStatus,
    TxChecksumAction, internet_checksum, pseudo_header_partial_sum,
};

// Re-export Stack Timeouts
#[allow(unused_imports)]
pub use stack_timeouts::{
    KeepaliveTimer, RetransmitTimer, TimeWaitTimer, TimerEntry, TimerKind, TimeoutWheel,
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

/// DHCP runtime state snapshot for shell/API consumers.
#[derive(Debug, Clone)]
pub struct DhcpRuntimeState {
    pub v4_state: String,
    pub v4_assigned_ip: Option<[u8; 4]>,
    pub v4_lease_remaining: Option<u32>,
    pub v6_state: String,
    pub v6_assigned_ip: Option<[u8; 16]>,
    pub v6_preferred_remaining: Option<u32>,
    pub v6_valid_remaining: Option<u32>,
}

/// ARP cache entry
#[derive(Debug, Clone)]
pub struct ArpCacheEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub complete: bool,
}

// Global network state for shell access
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
    match stack::stack().lock() {
        Ok(guard) => guard.as_ref().map(|stack_guard| {
            let cfg = stack_guard.config();
            NetworkConfigSnapshot {
                ip: *cfg.ipv4.address.as_bytes(),
                netmask: *cfg.ipv4.subnet_mask.as_bytes(),
                gateway: *cfg.ipv4.gateway.as_bytes(),
                mac: *cfg.mac.as_bytes(),
            }
        }),
        Err(_) => {
            log::error!("[NET] Stack lock poisoned (get_network_config)");
            None
        }
    }
}

/// Get network statistics
pub fn get_network_stats() -> Option<NetworkStatsSnapshot> {
    // Try to get real stats from NetworkStack
    // Try to get real stats from NetworkStack
    match stack::stack().lock() {
        Ok(guard) => {
            if let Some(stack_guard) = guard.as_ref() {
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
        }
        Err(_) => {
            log::error!("[NET] Stack lock poisoned (get_network_stats) - using fallback stats");
        }
    }

    // Fallback to demo stats
    Some(*NETWORK_STATS.lock())
}

/// Send ICMP echo request (ping)
pub fn send_icmp_echo(target: [u8; 4], seq: u16) -> Result<f32, String> {
    // Try to use real NetworkStack
    match stack::stack().lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack_guard) = guard.as_mut() {
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
        }
        Err(_) => log::error!(
            "[NET] Stack lock poisoned (send_icmp_echo) - using fallback implementation"
        ),
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
    // Get connections from TCB table
    let snapshots = tcb_table().list_connections();
    
    if snapshots.is_empty() {
        return None;
    }

    let connections = snapshots
        .into_iter()
        .map(|snap| {
            let local_addr = format!("{}", snap.local);
            let remote_addr = format!("{}", snap.remote);
            let state = match snap.state {
                TcpConnectionState::Closed => "CLOSED",
                TcpConnectionState::Listen => "LISTEN",
                TcpConnectionState::SynSent => "SYN_SENT",
                TcpConnectionState::SynReceived => "SYN_RCVD",
                TcpConnectionState::Established => "ESTABLISHED",
                TcpConnectionState::FinWait1 => "FIN_WAIT1",
                TcpConnectionState::FinWait2 => "FIN_WAIT2",
                TcpConnectionState::CloseWait => "CLOSE_WAIT",
                TcpConnectionState::Closing => "CLOSING",
                TcpConnectionState::LastAck => "LAST_ACK",
                TcpConnectionState::TimeWait => "TIME_WAIT",
            };
            TcpConnectionInfo {
                local_addr,
                remote_addr,
                state: String::from(state),
            }
        })
        .collect();

    Some(connections)
}

/// Get UDP sockets for netstat
pub fn get_udp_sockets() -> Option<Vec<UdpSocketInfo>> {
    // Get sockets from UDP processor via global stack
    match stack::stack().lock() {
        Ok(guard) => {
            if let Some(ref stack_guard) = guard.as_ref() {
                let snapshots = stack_guard.list_udp_sockets();
                
                if snapshots.is_empty() {
                    return None;
                }

                let sockets = snapshots
                    .into_iter()
                    .map(|snap| UdpSocketInfo {
                        local_addr: format!("*:{}", snap.local_port),
                        remote_addr: String::from("*:*"),
                    })
                    .collect();

                return Some(sockets);
            }
        }
        Err(_) => {
            log::error!("[NET] Stack lock poisoned (get_udp_sockets)");
        }
    }
    
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

/// 情報構造体: DHCP OFFER の基本情報を外部に公開
#[derive(Debug, Clone)]
pub struct DhcpOfferInfo {
    pub server_ip: [u8; 4],
    pub offered_ip: [u8; 4],
}

/// 外部API: DHCPDISCOVER を試み、現在保持しているオファーがあれば返す
pub fn dhcp_discover() -> Option<DhcpOfferInfo> {
    let now = tcb_table().get_current_tick();
    if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            let _ = client.drive(now, 1000);
            if let Some(offer) = client.offered_lease() {
                return Some(DhcpOfferInfo {
                    server_ip: *offer.server_ip.as_bytes(),
                    offered_ip: *offer.ip_address.as_bytes(),
                });
            }
        }
    }
    None
}

/// 外部API: 単純な DHCPREQUEST を送信
/// サーバーアドレスと要求する IP アドレスを指定する。
pub fn dhcp_request(server_ip: [u8; 4], offered_ip: [u8; 4]) -> bool {
    // build minimal DHCPREQUEST packet
    let mut buf = [0u8; crate::net::dhcp::DHCP_MAX_MESSAGE_SIZE];
    let xid = tcb_table().get_current_tick() as u32 ^ 0xDEADBEEF;
    // header
    buf[0..DhcpHeader::SIZE].fill(0);
    buf[0] = DhcpOperation::Request as u8;
    buf[1] = 1; // Ethernet
    buf[2] = 6; // MAC len
    buf[3] = 0;
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    buf[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
    buf[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
    // chaddr from current config
    if let Some(cfg) = get_network_config() {
        buf[28..34].copy_from_slice(&cfg.mac);
    }
    // options
    let mut offset = DhcpHeader::SIZE;
    buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    offset += 4;
    buf[offset] = crate::net::dhcp::DhcpOption::MessageType as u8;
    buf[offset + 1] = 1;
    buf[offset + 2] = DhcpMessageType::Request as u8;
    offset += 3;
    buf[offset] = crate::net::dhcp::DhcpOption::RequestedIp as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&offered_ip);
    offset += 6;
    buf[offset] = crate::net::dhcp::DhcpOption::ServerIdentifier as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&server_ip);
    offset += 6;
    buf[offset] = crate::net::dhcp::DhcpOption::End as u8;
    offset += 1;

    let dst = if server_ip == [0, 0, 0, 0] {
        Ipv4Address::new([255, 255, 255, 255])
    } else {
        Ipv4Address::new(server_ip)
    };
    stack::send_udp(DHCP_CLIENT_PORT, dst, DHCP_SERVER_PORT, &buf[..offset])
}

/// 外部API: アクティブなリースがあれば RELEASE を送信し状態をリセット
pub fn dhcp_release() {
    if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            client.release();
        }
    }
}

fn dhcp_v4_state_name(state: DhcpState) -> String {
    String::from(match state {
        DhcpState::Init => "Init",
        DhcpState::Selecting => "Selecting",
        DhcpState::Requesting => "Requesting",
        DhcpState::Bound => "Bound",
        DhcpState::Renewing => "Renewing",
        DhcpState::Rebinding => "Rebinding",
    })
}

fn dhcp_v6_state_name(state: dhcp::DhcpV6State) -> String {
    String::from(match state {
        dhcp::DhcpV6State::Init => "Init",
        dhcp::DhcpV6State::SolicitSent => "SolicitSent",
        dhcp::DhcpV6State::Requesting => "Requesting",
        dhcp::DhcpV6State::Bound => "Bound",
        dhcp::DhcpV6State::Renewing => "Renewing",
        dhcp::DhcpV6State::Rebinding => "Rebinding",
    })
}

fn lease_remaining_secs(total: u32, obtained_at: u64, now: u64, tick_rate: u64) -> u32 {
    let elapsed = (now.saturating_sub(obtained_at)) / tick_rate;
    total.saturating_sub(core::cmp::min(elapsed, u32::MAX as u64) as u32)
}

/// Initialize DHCP runtime clients and kick initial solicit/discover sequence.
pub fn init_dhcp_runtime() -> Result<(), String> {
    let mac = match stack::stack().lock() {
        Ok(guard) => match guard.as_ref() {
            Some(stack_guard) => stack_guard.config().mac,
            None => return Err(String::from("Network stack is not initialized")),
        },
        Err(_) => return Err(String::from("Network stack lock poisoned")),
    };

    dhcp::init(mac);
    dhcp::init_v6(mac);

    let now = tcb_table().get_current_tick();
    if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            client.drive(now, 1000).map_err(String::from)?;
        }
    } else {
        return Err(String::from("DHCPv4 global client lock poisoned"));
    }

    if let Ok(guard6) = dhcp::DHCPV6_CLIENT.lock() {
        if let Some(ref client6) = *guard6 {
            client6.check_timeout(now, 1000).map_err(String::from)?;
        }
    } else {
        return Err(String::from("DHCPv6 global client lock poisoned"));
    }

    Ok(())
}

/// Snapshot DHCP runtime state for v4/v6.
pub fn dhcp_state() -> DhcpRuntimeState {
    let now = tcb_table().get_current_tick();
    let tick_rate = 1000u64;

    let mut out = DhcpRuntimeState {
        v4_state: String::from("Init"),
        v4_assigned_ip: None,
        v4_lease_remaining: None,
        v6_state: String::from("Init"),
        v6_assigned_ip: None,
        v6_preferred_remaining: None,
        v6_valid_remaining: None,
    };

    match dhcp::DHCP_CLIENT.lock() {
        Ok(guard) => {
            if let Some(ref client) = *guard {
                out.v4_state = dhcp_v4_state_name(client.state());
                if let Some(lease) = client.lease() {
                    out.v4_assigned_ip = Some(*lease.ip_address.as_bytes());
                    out.v4_lease_remaining =
                        Some(lease_remaining_secs(lease.lease_time, lease.obtained_at, now, tick_rate));
                }
            }
        }
        Err(_) => out.v4_state = String::from("Poisoned"),
    }

    match dhcp::DHCPV6_CLIENT.lock() {
        Ok(guard6) => {
            if let Some(ref client6) = *guard6 {
                out.v6_state = dhcp_v6_state_name(client6.state());
                if let Some(lease6) = client6.lease() {
                    out.v6_assigned_ip = Some(*lease6.addr.as_bytes());
                    out.v6_preferred_remaining = Some(lease_remaining_secs(
                        lease6.preferred_lifetime,
                        lease6.obtained_at,
                        now,
                        tick_rate,
                    ));
                    out.v6_valid_remaining = Some(lease_remaining_secs(
                        lease6.valid_lifetime,
                        lease6.obtained_at,
                        now,
                        tick_rate,
                    ));
                }
            }
        }
        Err(_) => out.v6_state = String::from("Poisoned"),
    }

    out
}

/// Trigger DHCP renew/restart sequence for both v4 and v6 clients.
pub fn dhcp_renew() -> Result<(), String> {
    let now = tcb_table().get_current_tick();
    let mut touched = false;

    match dhcp::DHCP_CLIENT.lock() {
        Ok(guard) => {
            if let Some(ref client) = *guard {
                client.force_renew_or_restart(now);
                client.drive(now, 1000).map_err(String::from)?;
                touched = true;
            }
        }
        Err(_) => return Err(String::from("DHCPv4 global client lock poisoned")),
    }

    match dhcp::DHCPV6_CLIENT.lock() {
        Ok(guard6) => {
            if let Some(ref client6) = *guard6 {
                client6.force_renew_or_restart(now).map_err(String::from)?;
                client6.check_timeout(now, 1000).map_err(String::from)?;
                touched = true;
            }
        }
        Err(_) => return Err(String::from("DHCPv6 global client lock poisoned")),
    }

    if !touched {
        return Err(String::from("DHCP runtime is not initialized"));
    }

    Ok(())
}

/// Get ARP cache
pub fn get_arp_cache() -> Option<Vec<ArpCacheEntry>> {
    // Try to get real ARP cache from NetworkStack
    match stack::stack().lock() {
        Ok(guard) => {
            if let Some(stack_guard) = guard.as_ref() {
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
        }
        Err(_) => log::error!("[NET] Stack lock poisoned (get_arp_cache) - returning demo output"),
    }

    // Return None to show demo output in shell
    None
}

/// Initialize network for shell commands
pub fn init_network_shell() {
    // no-op: runtime state is sourced from the actual network stack/DHCP clients.
}
