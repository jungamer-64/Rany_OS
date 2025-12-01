// ============================================================================
// src/net/mod.rs - Network Subsystem
// 設計書 6.2: ネットワークスタック：真のゼロコピー
// ============================================================================

pub mod mempool;
pub mod tcp;

#[allow(unused_imports)]
pub use mempool::{
    PacketBuffer, PacketRef, Mempool, MempoolStats,
    init_net_mempool, net_mempool, alloc_packet,
};

#[allow(unused_imports)]
pub use tcp::{
    // アドレス
    Ipv4Addr, SocketAddr,
    // ストリーム・リスナー
    TcpStream, TcpListener,
    // トレイト
    AsyncRead, AsyncWrite,
    // エラー
    TcpError, TcpState,
};
