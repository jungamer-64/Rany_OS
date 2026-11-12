// ============================================================================
// kernel/src/net/datapath/mempool/mod.rs - Packet buffer pools
// ============================================================================
//! Fixed-size packet buffer pools.
//!
//! A pool's RAM holds packet bytes only. Every slot's header, recycle owner
//! and reference count live in ordinary kernel memory, so a device that can
//! reach a slot's bytes through an IOMMU mapping cannot reach the metadata
//! that decides when the slot is reused.
//!
//! A pool stays alive while its owner handle or any acquired slot exists: each
//! acquisition takes one pool reference and the slot's last returned window
//! gives it back. An owner may therefore drop its pool while packets from it
//! are still queued elsewhere; the pool is freed after the last one returns.

use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernel_api::dma::DmaByteCount;
use kernel_api::resource::memory::PhysicalAddress;
pub use kernel_api::resource::net::PacketRef;
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketAcquireError, PacketBufferMemory};

use crate::mm::types::PAGE_SIZE_4K;

mod backing;
mod pool_impl;
pub(crate) use backing::allocate_packet as allocate_packet_backing;
pub use pool_impl::*;

#[cfg(test)]
mod tests;

/// Slots are carved from physically contiguous chunks of at most this size,
/// so a pool never needs one large contiguous allocation.
const POOL_CHUNK_BYTES: usize = 16 * PAGE_SIZE_4K;
const SLOT_ALIGN: usize = 64;
const CPU_CACHE_CAPACITY: usize = 32;
const BATCH_SIZE: usize = 16;

/// Bytes a driver may place in an RX buffer before the frame.
const RX_DEVICE_HEADER_ALLOWANCE: usize = 64;
/// Ethernet header and one VLAN tag around an MTU-sized payload.
const RX_LINK_HEADER_BYTES: usize = 18;

/// Size and count of a pool's slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PacketPoolGeometry {
    slot_bytes: usize,
    slots: usize,
}

impl PacketPoolGeometry {
    /// Generated frames and application payloads of the runtime.
    pub(crate) const FRAMES: Self = Self {
        slot_bytes: 2048,
        slots: 1024,
    };

    /// Generated protocol headers that precede a separately owned body.
    pub(crate) const HEADERS: Self = Self {
        slot_bytes: 256,
        slots: 1024,
    };

    /// RX buffers of one port: the default headroom, a driver header and a
    /// frame of `mtu` bytes, in `slots` buffers.
    pub(crate) fn rx(mtu: u32, slots: usize) -> Option<Self> {
        let bytes = usize::try_from(mtu)
            .ok()?
            .checked_add(
                DEFAULT_PACKET_HEADROOM + RX_DEVICE_HEADER_ALLOWANCE + RX_LINK_HEADER_BYTES,
            )?
            .checked_next_multiple_of(SLOT_ALIGN)?;
        (slots > 0 && u32::try_from(slots).is_ok()).then_some(Self {
            slot_bytes: bytes,
            slots,
        })
    }

    pub(crate) const fn slot_bytes(self) -> usize {
        self.slot_bytes
    }

    fn slots_per_chunk(self) -> usize {
        (POOL_CHUNK_BYTES / self.slot_bytes).max(1)
    }
}

/// One slot: the header of its bytes and the way back to its pool.
struct PoolSlot {
    memory: PacketBufferMemory,
    pool: NonNull<PoolShared>,
    index: u32,
}

struct PoolShared {
    id: u32,
    geometry: PacketPoolGeometry,
    /// Fully initialized before the pool is published; never resized.
    slots: Vec<PoolSlot>,
    free: PoisonLock<Vec<u32>>,
    caches: PoisonRwLock<Vec<PoisonLock<Vec<u32>>>>,
    /// One for the owner handle plus one per acquired slot.
    references: AtomicUsize,
    alloc_count: AtomicU64,
    free_count: AtomicU64,
    alloc_failed: AtomicU64,
}

// SAFETY: slot headers are shared only through their atomic reference
// counts; free and cache indexes are locked; counters are atomic.
unsafe impl Send for PoolShared {}
// SAFETY: as above, every shared mutation is synchronized.
unsafe impl Sync for PoolShared {}

unsafe fn recycle_pool_slot(owner: NonNull<()>) {
    // SAFETY: the pool passes its slot as retirement owner and keeps the slot
    // alive while this acquisition's pool reference is held.
    let slot = unsafe { owner.cast::<PoolSlot>().as_ref() };
    let pool = slot.pool;
    let index = slot.index;
    // SAFETY: this acquisition still holds one pool reference.
    let shared = unsafe { pool.as_ref() };
    shared.return_slot(index);
    // SAFETY: this releases exactly the reference taken at acquisition; the
    // slot and pool are not touched afterwards.
    unsafe { release_pool_reference(pool) };
}

/// # Safety
/// The caller gives up one reference it holds to `pool`.
unsafe fn release_pool_reference(pool: NonNull<PoolShared>) {
    // SAFETY: the caller's reference keeps the pool alive for this access.
    let previous = unsafe { pool.as_ref() }
        .references
        .fetch_sub(1, Ordering::AcqRel);
    if previous == 1 {
        // SAFETY: the last reference is gone: no handle, slot window or
        // retirement callback can reach the pool any more. Slot headers are
        // dropped with it; mapping owners keep their own RAM references.
        drop(unsafe { Box::from_raw(pool.as_ptr()) });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolLock {
    FreeList,
    LocalCache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolError {
    LockPoisoned(MempoolLock),
    CpuCacheAllocationFailed,
    CpuNotProvisioned(crate::cpu::CpuId),
    InvalidGeometry,
    BufferAllocationFailed,
    BufferMetadataAllocationFailed,
    InvalidHeadroom,
    BackingUnavailable(PacketAcquireError),
    OutOfBuffers,
}

impl MempoolError {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LockPoisoned(MempoolLock::FreeList) => "mempool free list poisoned",
            Self::LockPoisoned(MempoolLock::LocalCache) => "mempool local cache poisoned",
            Self::CpuCacheAllocationFailed => "mempool CPU cache allocation failed",
            Self::CpuNotProvisioned(_) => "mempool CPU topology is inconsistent",
            Self::InvalidGeometry => "mempool slot geometry is invalid",
            Self::BufferAllocationFailed => "mempool buffer allocation failed",
            Self::BufferMetadataAllocationFailed => "mempool buffer registry allocation failed",
            Self::InvalidHeadroom => "requested headroom exceeds the slot",
            Self::BackingUnavailable(_) => "mempool backing acquisition rejected",
            Self::OutOfBuffers => "mempool exhausted",
        }
    }
}

impl fmt::Display for MempoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MempoolStats {
    pub total_buffers: usize,
    pub free_buffers: usize,
    pub used_buffers: usize,
    pub alloc_count: u64,
    pub free_count: u64,
    pub alloc_failed: u64,
}

/// Owner handle of a packet pool.
pub struct PacketPool {
    shared: NonNull<PoolShared>,
}

// SAFETY: the handle only reaches synchronized pool state.
unsafe impl Send for PacketPool {}
// SAFETY: as above.
unsafe impl Sync for PacketPool {}

impl fmt::Debug for PacketPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shared = self.shared();
        formatter
            .debug_struct("PacketPool")
            .field("id", &shared.id)
            .field("geometry", &shared.geometry)
            .field("alloc_count", &shared.alloc_count.load(Ordering::Relaxed))
            .field("alloc_failed", &shared.alloc_failed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Drop for PacketPool {
    fn drop(&mut self) {
        // SAFETY: this handle owns one pool reference.
        unsafe { release_pool_reference(self.shared) };
    }
}

impl PacketPool {
    /// Allocate every slot of `geometry`, with one CPU cache per possible CPU
    /// in `cpu_snapshot`.
    ///
    /// # Errors
    /// Fails without retaining anything when the geometry is invalid or RAM,
    /// slot metadata or CPU caches cannot be allocated.
    pub(crate) fn new(
        id: u32,
        geometry: PacketPoolGeometry,
        cpu_snapshot: &crate::cpu::CpuSnapshot,
    ) -> Result<Self, MempoolError> {
        if geometry.slots == 0
            || geometry.slot_bytes < SLOT_ALIGN
            || u32::try_from(geometry.slots).is_err()
        {
            return Err(MempoolError::InvalidGeometry);
        }
        let capacity =
            DmaByteCount::new(geometry.slot_bytes).ok_or(MempoolError::InvalidGeometry)?;
        let per_chunk = geometry.slots_per_chunk();
        let chunk_count = geometry.slots.div_ceil(per_chunk);
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(chunk_count)
            .map_err(|_| MempoolError::BufferMetadataAllocationFailed)?;
        for _ in 0..chunk_count {
            chunks.push(
                backing::PacketStorage::allocate(per_chunk * geometry.slot_bytes)
                    .map_err(|_| MempoolError::BufferAllocationFailed)?,
            );
        }

        let mut caches = Vec::new();
        caches
            .try_reserve_exact(cpu_snapshot.slots().len())
            .map_err(|_| MempoolError::CpuCacheAllocationFailed)?;
        for _ in cpu_snapshot.slots() {
            caches.push(PoisonLock::new(Self::cache_storage()?));
        }
        let mut free = Vec::new();
        free.try_reserve_exact(geometry.slots)
            .map_err(|_| MempoolError::BufferMetadataAllocationFailed)?;
        // Every slot is initialized below before the pool is published.
        free.extend((0..geometry.slots as u32).rev());
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(geometry.slots)
            .map_err(|_| MempoolError::BufferMetadataAllocationFailed)?;
        let shared = Box::try_new(PoolShared {
            id,
            geometry,
            slots,
            free: PoisonLock::new(free),
            caches: PoisonRwLock::new(caches),
            references: AtomicUsize::new(1),
            alloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            alloc_failed: AtomicU64::new(0),
        })
        .map_err(|_| MempoolError::BufferMetadataAllocationFailed)?;
        let shared = NonNull::from(Box::leak(shared));
        // SAFETY: the pool is not yet published; this is its only reference.
        let pool = unsafe { &mut *shared.as_ptr() };
        let slots_base = pool.slots.as_mut_ptr();
        for index in 0..geometry.slots {
            let chunk = &chunks[index / per_chunk];
            let offset = (index % per_chunk) * geometry.slot_bytes;
            let data = chunk
                .pointer()
                .map_err(|_| MempoolError::BufferAllocationFailed);
            let data = match data {
                Ok(data) => data,
                Err(error) => {
                    // SAFETY: the unpublished pool holds only its own reference.
                    unsafe { release_pool_reference(shared) };
                    return Err(error);
                }
            };
            // SAFETY: `offset + slot_bytes` lies within the chunk.
            let data = unsafe { data.add(offset) };
            let physical = PhysicalAddress::new(chunk.physical().as_u64() + offset as u64);
            // The slot's final address: capacity was reserved exactly, so the
            // vector never moves while it is filled.
            // SAFETY: `index` is below the reserved capacity.
            let owner = unsafe { NonNull::new_unchecked(slots_base.add(index)) }.cast();
            // SAFETY: the chunk is initialized RAM retained by every slot
            // header carved from it and by each mapping of it. The owner is
            // this slot, which outlives every window acquired from it.
            let memory = unsafe {
                PacketBufferMemory::new(
                    data,
                    capacity,
                    physical,
                    Arc::clone(chunk) as Arc<dyn Send + Sync>,
                    owner,
                    recycle_pool_slot,
                )
            };
            let index = index as u32;
            pool.slots.push(PoolSlot {
                memory,
                pool: shared,
                index,
            });
        }
        Ok(Self { shared })
    }

    fn cache_storage() -> Result<Vec<u32>, MempoolError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(CPU_CACHE_CAPACITY)
            .map_err(|_| MempoolError::CpuCacheAllocationFailed)?;
        Ok(slots)
    }

    fn shared(&self) -> &PoolShared {
        // SAFETY: this handle owns a pool reference.
        unsafe { self.shared.as_ref() }
    }

    pub(crate) fn geometry(&self) -> PacketPoolGeometry {
        self.shared().geometry
    }

    /// Add CPU caches for possible CPUs discovered since the pool was created.
    ///
    /// # Errors
    /// Fails on cache allocation failure or an inconsistent CPU topology.
    pub(crate) fn provision_possible_cpus(
        &self,
        cpu_snapshot: &crate::cpu::CpuSnapshot,
    ) -> Result<(), MempoolError> {
        let mut caches = self
            .shared()
            .caches
            .write()
            .map_err(|_| MempoolError::LockPoisoned(MempoolLock::LocalCache))?;
        for (index, slot) in cpu_snapshot.slots().iter().enumerate() {
            if slot.id.as_usize() != index {
                return Err(MempoolError::CpuNotProvisioned(slot.id));
            }
        }
        let additional = cpu_snapshot.slots().len().saturating_sub(caches.len());
        caches
            .try_reserve_exact(additional)
            .map_err(|_| MempoolError::CpuCacheAllocationFailed)?;
        for _ in 0..additional {
            caches.push(PoisonLock::new(Self::cache_storage()?));
        }
        Ok(())
    }

    /// Acquire an empty buffer whose data window starts `headroom` bytes into
    /// its slot.
    ///
    /// # Errors
    /// Fails when the headroom exceeds the slot or every slot is acquired.
    pub fn alloc(&self, headroom: usize) -> Result<PacketRef, MempoolError> {
        let shared = self.shared();
        if headroom > shared.geometry.slot_bytes {
            return Err(shared.record_failure(MempoolError::InvalidHeadroom));
        }
        let index = shared
            .take_slot()
            .map_err(|error| shared.record_failure(error))?;
        let slot = &shared.slots[index as usize];
        shared.references.fetch_add(1, Ordering::Relaxed);
        // SAFETY: a free-list index grants exclusive acquisition of this
        // slot, whose header the pool keeps alive until its retirement.
        match unsafe { PacketRef::acquire(NonNull::from(&slot.memory), headroom) } {
            Ok(packet) => {
                shared.alloc_count.fetch_add(1, Ordering::Relaxed);
                Ok(packet)
            }
            Err(cause) => {
                shared.return_slot(index);
                // SAFETY: the reference taken above was not published.
                shared.references.fetch_sub(1, Ordering::Relaxed);
                Err(shared.record_failure(MempoolError::BackingUnavailable(cause)))
            }
        }
    }

    pub fn stats(&self) -> MempoolStats {
        let shared = self.shared();
        let total = shared.slots.len();
        let mut free = shared
            .free
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        for cache in shared
            .caches
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
        {
            free += cache
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len();
        }
        MempoolStats {
            total_buffers: total,
            free_buffers: free,
            used_buffers: total.saturating_sub(free),
            alloc_count: shared.alloc_count.load(Ordering::Relaxed),
            free_count: shared.free_count.load(Ordering::Relaxed),
            alloc_failed: shared.alloc_failed.load(Ordering::Relaxed),
        }
    }
}

impl PoolShared {
    fn record_failure(&self, error: MempoolError) -> MempoolError {
        self.alloc_failed.fetch_add(1, Ordering::Relaxed);
        error
    }

    fn current_cpu() -> Option<usize> {
        crate::cpu::CurrentCpu::acquire().map(|current| current.id().as_usize())
    }

    /// Take a free slot index, preferring this CPU's cache. A CPU without a
    /// cache uses the shared free list directly.
    fn take_slot(&self) -> Result<u32, MempoolError> {
        let caches = self
            .caches
            .read()
            .map_err(|_| MempoolError::LockPoisoned(MempoolLock::LocalCache))?;
        let Some(cpu) = Self::current_cpu().filter(|cpu| *cpu < caches.len()) else {
            return self
                .free
                .lock()
                .map_err(|_| MempoolError::LockPoisoned(MempoolLock::FreeList))?
                .pop()
                .ok_or(MempoolError::OutOfBuffers);
        };
        let mut cache = caches[cpu]
            .lock()
            .map_err(|_| MempoolError::LockPoisoned(MempoolLock::LocalCache))?;
        if let Some(index) = cache.pop() {
            return Ok(index);
        }
        {
            let mut free = self
                .free
                .lock()
                .map_err(|_| MempoolError::LockPoisoned(MempoolLock::FreeList))?;
            let refill = BATCH_SIZE.min(free.len());
            let start = free.len() - refill;
            cache.extend(free.drain(start..));
        }
        if let Some(index) = cache.pop() {
            return Ok(index);
        }
        // The shared list is empty: take half of another CPU's cache.
        for (remote, remote_cache) in caches.iter().enumerate() {
            if remote == cpu {
                continue;
            }
            if let Ok(mut remote_cache) = remote_cache.try_lock()
                && !remote_cache.is_empty()
            {
                let steal = remote_cache.len().div_ceil(2).min(BATCH_SIZE);
                let start = remote_cache.len() - steal;
                cache.extend(remote_cache.drain(start..));
                break;
            }
        }
        cache.pop().ok_or(MempoolError::OutOfBuffers)
    }

    fn return_slot(&self, index: u32) {
        self.free_count.fetch_add(1, Ordering::Relaxed);
        let caches = self
            .caches
            .read()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(cpu) = Self::current_cpu().filter(|cpu| *cpu < caches.len())
            && let Ok(mut cache) = caches[cpu].lock()
        {
            if cache.len() < CPU_CACHE_CAPACITY {
                cache.push(index);
                return;
            }
            let mut free = self.free.lock().unwrap_or_else(|error| error.into_inner());
            let spill = cache.len() / 2;
            let start = cache.len() - spill;
            free.extend(cache.drain(start..));
            free.push(index);
            return;
        }
        self.free
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(index);
    }
}
