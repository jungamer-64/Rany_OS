// ============================================================================
// kernel/src/net/datapath/mempool/pool_impl.rs - データパス / メモリプール / プール実装
// ============================================================================

use super::*;
use crate::net::runtime::NetRuntimeHandle;

/// ランタイム所有メモリプールを初期化
pub fn init_net_mempool_in(runtime: NetRuntimeHandle, capacity: usize) -> Result<(), &'static str> {
    let pool = runtime
        .context()
        .packet_pool
        .call_once(|| Mempool::new(runtime.id().0 as u32));
    pool.init(capacity)
}

/// ランタイム所有メモリプールを取得
pub fn net_mempool_in(runtime: NetRuntimeHandle) -> Option<&'static Mempool> {
    runtime.context().packet_pool.get()
}

/// パケットバッファを割り当て
pub fn alloc_packet_in(runtime: NetRuntimeHandle) -> Option<PacketRef> {
    if let Some(packet) = super::alloc_packet_for_active_dma_device() {
        return Some(packet);
    }

    net_mempool_in(runtime)?.alloc()
}

/// 境界コード用。通常の runtime path では `alloc_packet_in` を使う。
pub fn init_net_mempool(capacity: usize) -> Result<(), &'static str> {
    init_net_mempool_in(crate::net::runtime::default_runtime(), capacity)
}

/// 境界コード用。通常の runtime path では `net_mempool_in` を使う。
pub fn net_mempool() -> Option<&'static Mempool> {
    net_mempool_in(crate::net::runtime::default_runtime())
}

/// 境界コード用。通常の runtime path では `alloc_packet_in` を使う。
pub fn alloc_packet() -> Option<PacketRef> {
    alloc_packet_in(crate::net::runtime::default_runtime())
}
