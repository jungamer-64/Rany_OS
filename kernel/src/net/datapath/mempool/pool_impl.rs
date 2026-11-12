// ============================================================================
// kernel/src/net/datapath/mempool/pool_impl.rs - Runtime packet pools
// ============================================================================

use super::*;
use crate::net::runtime::NetRuntimeHandle;

/// Packet pools owned by one network runtime. Port RX buffers come from each
/// port's own pool instead; these pools serve generated and application data.
pub(crate) struct RuntimePacketPools {
    frames: PacketPool,
    headers: PacketPool,
}

impl RuntimePacketPools {
    fn new(id: u32, cpu_snapshot: &crate::cpu::CpuSnapshot) -> Result<Self, MempoolError> {
        Ok(Self {
            frames: PacketPool::new(id, PacketPoolGeometry::FRAMES, cpu_snapshot)?,
            headers: PacketPool::new(id, PacketPoolGeometry::HEADERS, cpu_snapshot)?,
        })
    }

    pub(crate) fn provision_possible_cpus(
        &self,
        cpu_snapshot: &crate::cpu::CpuSnapshot,
    ) -> Result<(), MempoolError> {
        self.frames.provision_possible_cpus(cpu_snapshot)?;
        self.headers.provision_possible_cpus(cpu_snapshot)
    }

    /// Smallest pool whose slots hold `headroom + len` bytes.
    pub(crate) fn alloc_fitting(&self, len: usize, headroom: usize) -> Option<PacketRef> {
        let bytes = len.checked_add(headroom)?;
        let pool = if bytes <= self.headers.geometry().slot_bytes() {
            &self.headers
        } else if bytes <= self.frames.geometry().slot_bytes() {
            &self.frames
        } else {
            return None;
        };
        pool.alloc(headroom).ok()
    }
}

fn runtime_pools(runtime: NetRuntimeHandle) -> Option<&'static RuntimePacketPools> {
    runtime.context().packet_pools.get()
}

/// Create the runtime's pools once. Later calls keep the existing pools.
///
/// # Errors
/// Fails when the pools cannot be allocated; a later call may retry.
pub fn init_net_mempool_in(runtime: NetRuntimeHandle) -> Result<(), &'static str> {
    let context = runtime.context();
    context
        .packet_pools
        .try_call_once(|| RuntimePacketPools::new(context.id().0 as u32, &crate::cpu::snapshot()))
        .map(|_| ())
        .map_err(MempoolError::as_str)
}

/// The runtime's frame pool.
pub fn net_mempool_in(runtime: NetRuntimeHandle) -> Option<&'static PacketPool> {
    runtime_pools(runtime).map(|pools| &pools.frames)
}

/// Acquire an empty frame buffer with the default headroom.
pub fn alloc_packet_in(runtime: NetRuntimeHandle) -> Option<PacketRef> {
    net_mempool_in(runtime)?.alloc(DEFAULT_PACKET_HEADROOM).ok()
}

/// Acquire a buffer of the smallest runtime pool that holds `headroom + len`.
pub(crate) fn alloc_fitting_packet_in(
    runtime: NetRuntimeHandle,
    len: usize,
    headroom: usize,
) -> Option<PacketRef> {
    runtime_pools(runtime)?.alloc_fitting(len, headroom)
}

/// 境界コード用。通常の runtime path では `net_mempool_in` を使う。
pub fn net_mempool() -> Option<&'static PacketPool> {
    net_mempool_in(crate::net::runtime::default_runtime())
}

/// 境界コード用。通常の runtime path では `alloc_packet_in` を使う。
pub fn alloc_packet() -> Option<PacketRef> {
    alloc_packet_in(crate::net::runtime::default_runtime())
}
