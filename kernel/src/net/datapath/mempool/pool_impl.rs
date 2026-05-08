// ============================================================================
// kernel/src/net/datapath/mempool/pool_impl.rs - データパス / メモリプール / プール実装
// ============================================================================

use super::*;

// ============================================================================
// Global Mempool
// ============================================================================

/// グローバルネットワークメモリプール
pub(crate) static NET_MEMPOOL: spin::Once<Mempool> = spin::Once::new();

/// グローバルメモリプールを初期化
pub fn init_net_mempool(capacity: usize) -> Result<(), &'static str> {
    let pool = NET_MEMPOOL.call_once(|| Mempool::new(0));
    pool.init(capacity)
}

/// ネットワークメモリプールを取得
pub fn net_mempool() -> Option<&'static Mempool> {
    NET_MEMPOOL.get()
}

/// パケットバッファを割り当て
pub fn alloc_packet() -> Option<PacketRef> {
    if let Some(packet) = super::alloc_packet_for_active_dma_device() {
        return Some(packet);
    }

    NET_MEMPOOL.get()?.alloc()
}
