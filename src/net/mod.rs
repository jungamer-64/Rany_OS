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
