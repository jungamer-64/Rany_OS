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
pub mod ethernet;
pub mod ipv4;
pub mod arp;
pub mod icmp;
pub mod udp;

// Network services
pub mod dhcp;
pub mod dns;

// Integrated network stack
pub mod stack;

// Socket API
pub mod socket;

// TLS support
pub mod tls;

// Re-export mempool
#[allow(unused_imports)]
pub use mempool::{
    PacketBuffer, PacketRef, Mempool, MempoolStats, PacketPool,
    init_net_mempool, net_mempool, alloc_packet,
};

// Re-export TCP
#[allow(unused_imports)]
pub use tcp::{
    // アドレス
    Ipv4Addr, SocketAddr,
    // ストリーム・リスナー
    TcpStream, TcpListener, TcpProcessor,
    // トレイト
    AsyncRead, AsyncWrite,
    // エラー
    TcpError, TcpState,
};

// Re-export Ethernet
#[allow(unused_imports)]
pub use ethernet::{
    MacAddress, EtherType, EthernetHeader,
    EthernetFrame, EthernetFrameMut,
    EthernetProcessor, EthernetStats,
};

// Re-export IPv4
#[allow(unused_imports)]
pub use ipv4::{
    Ipv4Address, IpProtocol, Ipv4Header,
    Ipv4Packet, Ipv4PacketMut,
    Ipv4Config, Ipv4Processor, Ipv4Stats,
};

// Re-export ARP
#[allow(unused_imports)]
pub use arp::{
    ArpPacket, ArpOperation, ArpHardwareType,
    ArpCache, ArpEntry, ArpEntryState,
    ArpProcessor, ArpResult,
};

// Re-export ICMP
#[allow(unused_imports)]
pub use icmp::{
    IcmpType, IcmpHeader, IcmpEchoHeader,
    IcmpPacket, IcmpEcho,
    IcmpBuilder, IcmpEchoBuilder,
    IcmpProcessor, IcmpResult, IcmpStats,
    DestUnreachCode, TimeExceededCode,
};

// Re-export UDP
#[allow(unused_imports)]
pub use udp::{
    UdpHeader, UdpPacket, UdpPacketMut,
    UdpSocket, UdpDatagram, UdpAddr,
    UdpProcessor, UdpResult, UdpSocketTable,
};

// Re-export DHCP
#[allow(unused_imports)]
pub use dhcp::{
    DhcpClient, DhcpState, DhcpLease, DhcpHeader,
    DhcpMessageType, DhcpOperation, DhcpResponseResult,
    DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DHCP_MAGIC_COOKIE,
    init as init_dhcp, client as dhcp_client,
};

// Re-export DNS
#[allow(unused_imports)]
pub use dns::{
    DnsClient, DnsHeader, DnsRecord, DnsRecordData,
    DnsQueryType, DnsQueryClass, DnsResponseCode,
    DnsCache, DnsCacheEntry, DnsStats,
    DNS_PORT,
    init as init_dns, set_servers as set_dns_servers,
    resolve_cached as dns_resolve_cached,
};

// Re-export Network Stack
#[allow(unused_imports)]
pub use stack::{
    NetworkStack, NetworkConfig, NetworkStats,
    init as init_stack, init_default as init_stack_default,
    stack as global_stack, receive, send_udp, bind_udp,
    MAX_PACKET_SIZE, MTU,
};

// VirtIO Netドライバはio/virtio_net.rsにある
// 再エクスポート
#[allow(unused_imports)]
pub use crate::io::virtio_net::{
    VirtioNetDevice, VirtioNetHeader, VirtioNetStats,
    NetVirtQueue, VringDesc as NetVringDesc,
    init_virtio_net, handle_virtio_net_interrupt,
    features as net_features,
};

// Re-export Phase 4 High-Performance Networking
#[allow(unused_imports)]
pub use adaptive_polling::{
    AdaptivePoller, PollingMode, NapiLike,
    PerCorePolling, BusyPollConfig, PollingManager,
    init as init_adaptive_polling,
};

#[allow(unused_imports)]
pub use zero_copy::{
    PoolId, MemoryPool, ZeroCopyBuffer,
    SgList, SgEntry as ZcSgEntry, PacketChain,
    EthernetHeaderView, Ipv4HeaderView,
    ZeroCopyReader, ZeroCopyWriter, PoolManager,
    init as init_zero_copy,
};

// Re-export Phase 5+ Advanced Optimization
#[allow(unused_imports)]
pub use optimization::{
    // Batch processing
    PacketBatch, BatchProcessor, BatchConfig, BatchStats, MAX_BATCH_SIZE,
    // NUMA
    NumaNode, NumaTopology, NumaMempool,
    // CPU Affinity
    CpuAffinity, FlowAffinity,
    // Interrupt coalescing
    InterruptCoalescing, AdaptiveCoalescing,
    // GRO/TSO
    GroSegment, GroTable, TsoContext,
    // Metrics
    NetworkMetrics,
    // Initialization
    init as init_optimization,
    batch_processor, numa_topology, flow_affinity, adaptive_coalescing, metrics,
};
