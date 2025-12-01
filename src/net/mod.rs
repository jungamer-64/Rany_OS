// ============================================================================
// src/net/mod.rs - Network Subsystem
// 設計書 6.2: ネットワークスタック：真のゼロコピー
// ============================================================================

pub mod mempool;

#[allow(unused_imports)]
pub use mempool::{
    PacketBuffer, PacketRef, Mempool, MempoolStats,
    init_net_mempool, net_mempool, alloc_packet,
};
