// ============================================================================
// kernel/src/net/datapath/mempool/mod.rs - Zero-Copy Network Buffer Pool
// ============================================================================

// ============================================================================
// src/net/mempool.rs - Zero-Copy Network Buffer Pool
// 設計書 6.2: Mempool によるゼロコピーネットワークバッファ管理
// ============================================================================

// Building block: Memory pool types

use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketAcquireError, PacketBufferMemory};
pub use kernel_api::resource::net::{PacketMeta, PacketRef, PacketType};

use crate::mm::types::PAGE_SIZE_4K;

/// DMAページサイズ
mod backing;
mod pool_impl;
pub(crate) use backing::allocate_packet as allocate_packet_backing;
pub use pool_impl::*;

#[cfg(test)]
mod tests;

const DMA_PAGE_SIZE: usize = PAGE_SIZE_4K;

/// Pool identity and recycle owner are separate from the packet's byte window.
#[repr(C)]
#[derive(Debug)]
struct PacketBufferMeta {
    pool: &'static Mempool,
    index: u32,
}

const PACKET_META_ALIGN: usize = core::mem::align_of::<PacketBufferMemory>();
const PACKET_META_SIZE: usize =
    core::mem::size_of::<PacketBufferMemory>() + core::mem::size_of::<PacketBufferMeta>();
const DEFAULT_BUFFER_SIZE: usize = (DMA_PAGE_SIZE - PACKET_META_SIZE) & !(PACKET_META_ALIGN - 1);

#[repr(C, align(4096))]
#[derive(Debug)]
pub struct PacketBuffer {
    data: [u8; DEFAULT_BUFFER_SIZE],
    memory: PacketBufferMemory,
    meta: PacketBufferMeta,
}

unsafe fn recycle_packet(owner: NonNull<()>) {
    let buffer = owner.cast::<PacketBuffer>();
    // SAFETY: the pool supplies its retained allocation as retirement owner.
    // PacketBufferMemory invokes this only after its last window has returned.
    let pool = unsafe { buffer.as_ref().meta.pool };
    pool.return_buffer(buffer);
}

const _: () = assert!(core::mem::size_of::<PacketBuffer>() == DMA_PAGE_SIZE);

const CPU_CACHE_CAPACITY: usize = 32;
const BATCH_SIZE: usize = 16;

pub struct Mempool {
    id: u32,
    buffers: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    free_list: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    local_caches: PoisonRwLock<Vec<Arc<PoisonLock<Vec<NonNull<PacketBuffer>>>>>>,
    alloc_count: AtomicU64,
    free_count: AtomicU64,
    alloc_failed: AtomicU64,
}

// SAFETY: every stable packet page belongs to the permanent pool registry;
// counted packet leases recycle once, and every free/cache index is locked.
unsafe impl Send for Mempool {}
// SAFETY: shared access serializes indexes and acquisition grants one CPU
// window. Backing retention by device mappings grants no CPU byte access.
unsafe impl Sync for Mempool {}

impl fmt::Debug for Mempool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Mempool")
            .field("id", &self.id)
            .field("alloc_count", &self.alloc_count.load(Ordering::Relaxed))
            .field("free_count", &self.free_count.load(Ordering::Relaxed))
            .field("alloc_failed", &self.alloc_failed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolLock {
    BufferRegistry,
    FreeList,
    LocalCache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolError {
    LockPoisoned(MempoolLock),
    CpuCacheAllocationFailed,
    NoCurrentCpu,
    CpuNotProvisioned(crate::cpu::CpuId),
    BufferAllocationFailed,
    BufferMetadataAllocationFailed,
    BackingUnavailable(PacketAcquireError),
    OutOfBuffers,
}

impl MempoolError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LockPoisoned(MempoolLock::BufferRegistry) => "mempool buffer registry poisoned",
            Self::LockPoisoned(MempoolLock::FreeList) => "mempool free list poisoned",
            Self::LockPoisoned(MempoolLock::LocalCache) => "mempool local cache poisoned",
            Self::CpuCacheAllocationFailed => "mempool CPU cache allocation failed",
            Self::NoCurrentCpu => "mempool allocation requires a current CPU",
            Self::CpuNotProvisioned(_) => "mempool cache is not provisioned for the current CPU",
            Self::BufferAllocationFailed => "mempool buffer allocation failed",
            Self::BufferMetadataAllocationFailed => "mempool buffer registry allocation failed",
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

impl Mempool {
    fn prepare_cpu_cache() -> Result<Arc<PoisonLock<Vec<NonNull<PacketBuffer>>>>, MempoolError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(CPU_CACHE_CAPACITY)
            .map_err(|_| MempoolError::CpuCacheAllocationFailed)?;
        Arc::try_new(PoisonLock::new(slots)).map_err(|_| MempoolError::CpuCacheAllocationFailed)
    }
    pub fn new(id: u32, cpu_snapshot: &crate::cpu::CpuSnapshot) -> Result<Self, MempoolError> {
        let mut local_caches = Vec::new();
        local_caches
            .try_reserve_exact(cpu_snapshot.slots().len())
            .map_err(|_| MempoolError::CpuCacheAllocationFailed)?;
        for slot in cpu_snapshot.slots() {
            if slot.id.as_usize() != local_caches.len() {
                return Err(MempoolError::CpuNotProvisioned(slot.id));
            }
            local_caches.push(Self::prepare_cpu_cache()?);
        }

        Ok(Self {
            id,
            buffers: PoisonLock::new(Vec::new()),
            free_list: PoisonLock::new(Vec::new()),
            local_caches: PoisonRwLock::new(local_caches),
            alloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            alloc_failed: AtomicU64::new(0),
        })
    }

    pub fn init(&'static self, capacity: usize) -> Result<(), MempoolError> {
        let mut buffers = self
            .buffers
            .lock()
            .map_err(|_| MempoolError::LockPoisoned(MempoolLock::BufferRegistry))?;
        let mut free_list = self
            .free_list
            .lock()
            .map_err(|_| MempoolError::LockPoisoned(MempoolLock::FreeList))?;
        buffers
            .try_reserve_exact(capacity)
            .map_err(|_| MempoolError::BufferMetadataAllocationFailed)?;
        free_list
            .try_reserve_exact(capacity)
            .map_err(|_| MempoolError::BufferMetadataAllocationFailed)?;
        // LOOP_PROOF: mode=bounded; reason=Initialization admits exactly the requested fixed number of physical packet pages;
        for _ in 0..capacity {
            let index =
                u32::try_from(buffers.len()).map_err(|_| MempoolError::BufferAllocationFailed)?;
            let storage = backing::PacketStorage::allocate(DMA_PAGE_SIZE)
                .map_err(|_| MempoolError::BufferAllocationFailed)?;
            let non_null = storage
                .pointer()
                .map_err(|_| MempoolError::BufferAllocationFailed)?
                .cast::<PacketBuffer>();
            // SAFETY: this freshly initialized page is exclusively owned by
            // storage. The permanent pool registry keeps its stable header;
            // its embedded storage Arc retains RAM through every reuse cycle.
            unsafe { Self::write_initial_packet_buffer(non_null, self, index, storage) };
            buffers.push(non_null);
            free_list.push(non_null);
        }
        Ok(())
    }

    pub(crate) fn provision_possible_cpus(
        &self,
        cpu_snapshot: &crate::cpu::CpuSnapshot,
    ) -> Result<(), MempoolError> {
        let mut local_caches = self
            .local_caches
            .write()
            .map_err(|_| MempoolError::LockPoisoned(MempoolLock::LocalCache))?;
        for index in 0..local_caches.len() {
            let Some(slot) = cpu_snapshot.slots().get(index) else {
                return Err(MempoolError::CpuNotProvisioned(
                    crate::cpu::CpuId::try_from(index).expect("bounded CPU index"),
                ));
            };
            if slot.id.as_usize() != index {
                return Err(MempoolError::CpuNotProvisioned(slot.id));
            }
        }
        let additional = cpu_snapshot
            .slots()
            .len()
            .saturating_sub(local_caches.len());
        local_caches
            .try_reserve_exact(additional)
            .map_err(|_| MempoolError::CpuCacheAllocationFailed)?;
        for slot in &cpu_snapshot.slots()[local_caches.len()..] {
            if slot.id.as_usize() != local_caches.len() {
                return Err(MempoolError::CpuNotProvisioned(slot.id));
            }
            local_caches.push(Self::prepare_cpu_cache()?);
        }
        Ok(())
    }

    fn local_cache(
        &self,
        cpu_id: crate::cpu::CpuId,
    ) -> Result<Arc<PoisonLock<Vec<NonNull<PacketBuffer>>>>, MempoolError> {
        self.local_caches
            .read()
            .map_err(|_| MempoolError::LockPoisoned(MempoolLock::LocalCache))?
            .get(cpu_id.as_usize())
            .cloned()
            .ok_or(MempoolError::CpuNotProvisioned(cpu_id))
    }

    unsafe fn write_initial_packet_buffer(
        buffer: NonNull<PacketBuffer>,
        pool: &'static Mempool,
        index: u32,
        storage: Arc<backing::PacketStorage>,
    ) {
        let buffer_ptr = buffer.as_ptr();
        let physical = storage.physical();
        // SAFETY: the caller owns a whole aligned initialized packet page.
        unsafe {
            core::ptr::addr_of_mut!((*buffer_ptr).data)
                .cast::<u8>()
                .write_bytes(0, DEFAULT_BUFFER_SIZE);
            core::ptr::addr_of_mut!((*buffer_ptr).meta).write(PacketBufferMeta { pool, index });
            let data =
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*buffer_ptr).data).cast::<u8>());
            let capacity = kernel_api::dma::DmaByteCount::new(DEFAULT_BUFFER_SIZE)
                .expect("fixed packet capacity fits a DMA byte count");
            // The allocation is CPU-owned. Device admission must establish an
            // owned mapping before this buffer may be posted to a hardware queue.
            core::ptr::addr_of_mut!((*buffer_ptr).memory).write(PacketBufferMemory::new(
                data,
                capacity,
                kernel_api::resource::memory::PhysicalAddress::new(physical.as_u64()),
                storage,
                buffer.cast(),
                recycle_packet,
            ));
        }
    }

    fn record_alloc_failure(&self, error: MempoolError) -> MempoolError {
        self.alloc_failed.fetch_add(1, Ordering::Relaxed);
        error
    }

    unsafe fn init_buffer_for_alloc(
        buffer: NonNull<PacketBuffer>,
    ) -> Result<PacketRef, MempoolError> {
        // SAFETY: the free-list hands out this buffer exclusively. PacketRef
        // growth initializes only bytes that become software-visible, while RX
        // completion publishes only the device-written prefix.
        // SAFETY: this free-list entry grants unique acquisition. The pool's
        // buffer registry retains its allocation through the recycle callback.
        unsafe {
            PacketRef::acquire(
                NonNull::from(&buffer.as_ref().memory),
                DEFAULT_PACKET_HEADROOM.min(DEFAULT_BUFFER_SIZE),
            )
        }
        .map_err(MempoolError::BackingUnavailable)
    }

    pub fn alloc(&'static self) -> Result<PacketRef, MempoolError> {
        let cpu_id = crate::cpu::CurrentCpu::acquire()
            .map(|current| current.id())
            .ok_or_else(|| self.record_alloc_failure(MempoolError::NoCurrentCpu))?;
        self.alloc_on_cpu(cpu_id)
    }

    fn alloc_on_cpu(&'static self, cpu_id: crate::cpu::CpuId) -> Result<PacketRef, MempoolError> {
        let cache_lock = self
            .local_cache(cpu_id)
            .map_err(|error| self.record_alloc_failure(error))?;
        let mut cache = cache_lock.lock().map_err(|_| {
            self.record_alloc_failure(MempoolError::LockPoisoned(MempoolLock::LocalCache))
        })?;

        if cache.is_empty() {
            let mut refilled = false;
            if let Ok(mut global_free) = self.free_list.lock() {
                if !global_free.is_empty() {
                    let count_to_refill = BATCH_SIZE.min(global_free.len());
                    for _ in 0..count_to_refill {
                        if let Some(buf) = global_free.pop() {
                            cache.push(buf);
                        }
                    }
                    refilled = true;
                }
            }

            if !refilled {
                // Global list is empty. Attempt work stealing from remote CPU local caches.
                // Pass 1: Look for remote caches with multiple buffers (steal half to maintain locality)
                let cpu_snapshot = crate::cpu::snapshot();
                for remote_cpu in cpu_snapshot.online() {
                    if remote_cpu == cpu_id {
                        continue;
                    }
                    let Ok(remote_lock) = self.local_cache(remote_cpu) else {
                        continue;
                    };
                    if let Ok(mut remote_cache) = remote_lock.try_lock() {
                        if remote_cache.len() > 1 {
                            let steal_count = (remote_cache.len() / 2).min(BATCH_SIZE);
                            // LOOP_PROOF: mode=bounded; reason=At most one preallocated CPU cache batch moves between locked free indexes;
                            for _ in 0..steal_count {
                                cache.push(remote_cache.pop().expect("bounded cache batch"));
                            }
                            refilled = true;
                            break;
                        }
                    }
                }
                // Pass 2: Emergency fallback — steal single buffer if any remote cache has one
                if !refilled {
                    for remote_cpu in cpu_snapshot.online() {
                        if remote_cpu == cpu_id {
                            continue;
                        }
                        let Ok(remote_lock) = self.local_cache(remote_cpu) else {
                            continue;
                        };
                        if let Ok(mut remote_cache) = remote_lock.try_lock() {
                            if let Some(buf) = remote_cache.pop() {
                                cache.push(buf);
                                refilled = true;
                                break;
                            }
                        }
                    }
                }
            }

            if !refilled && cache.is_empty() {
                return Err(self.record_alloc_failure(MempoolError::OutOfBuffers));
            }
        }

        let buffer = cache
            .pop()
            .ok_or_else(|| self.record_alloc_failure(MempoolError::OutOfBuffers))?;
        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        unsafe { Self::init_buffer_for_alloc(buffer) }
    }

    fn return_buffer(&self, buffer: NonNull<PacketBuffer>) {
        let cache_lock = crate::cpu::CurrentCpu::acquire()
            .map(|current| current.id())
            .and_then(|cpu_id| self.local_cache(cpu_id).ok());
        if let Some(cache_lock) = cache_lock {
            if let Ok(mut cache) = cache_lock.lock() {
                cache.push(buffer);
                if cache.len() >= CPU_CACHE_CAPACITY {
                    let count = cache.len() / 2;
                    let mut global_free = self.free_list.lock().unwrap_or_else(|e| e.into_inner());
                    // LOOP_PROOF: mode=bounded; reason=Half of one fixed-capacity CPU cache returns to the already reserved pool free index;
                    for _ in 0..count {
                        global_free.push(cache.pop().expect("bounded cache return"));
                    }
                }
                self.free_count.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        self.free_list
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(buffer);
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> MempoolStats {
        let total = self.buffers.lock().unwrap_or_else(|e| e.into_inner()).len();
        let mut free = self
            .free_list
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let local_caches = self
            .local_caches
            .read()
            .unwrap_or_else(|error| error.into_inner());
        for cache_lock in local_caches.iter() {
            free += cache_lock.lock().unwrap_or_else(|e| e.into_inner()).len();
        }
        MempoolStats {
            total_buffers: total,
            free_buffers: free,
            used_buffers: total.saturating_sub(free),
            alloc_count: self.alloc_count.load(Ordering::Relaxed),
            free_count: self.free_count.load(Ordering::Relaxed),
            alloc_failed: self.alloc_failed.load(Ordering::Relaxed),
        }
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
