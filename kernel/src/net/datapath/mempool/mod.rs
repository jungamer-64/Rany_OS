// ============================================================================
// kernel/src/net/datapath/mempool/mod.rs - Zero-Copy Network Buffer Pool
// ============================================================================

// ============================================================================
// src/net/mempool.rs - Zero-Copy Network Buffer Pool
// 設計書 6.2: Mempool によるゼロコピーネットワークバッファ管理
// ============================================================================

// Building block: Memory pool types

use crate::ipc::rref::RRef;
use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering, fence};
use kernel_api::resource::net::{
    DEFAULT_PACKET_HEADROOM, PacketByteCount, PacketRefStorage, PacketRefVTable,
};
pub use kernel_api::resource::net::{PacketMeta, PacketRef, PacketType};
use x86_64::PhysAddr;

use crate::mm::types::PAGE_SIZE_4K;

/// DMAページサイズ
mod pool_impl;
pub use pool_impl::*;

#[cfg(test)]
mod tests;

const DMA_PAGE_SIZE: usize = PAGE_SIZE_4K;

/// パケットバッファのメタデータ
#[repr(C)]
#[derive(Debug)]
struct PacketBufferMeta {
    phys_addr: PhysAddr,
    device_addr: u64,
    pool_id: u32,
    index: u32,
    ref_count: AtomicU64,
    _padding: [u8; 8],
}

const PACKET_META_SIZE: usize = core::mem::size_of::<PacketBufferMeta>();
const PACKET_META_ALIGN: usize = core::mem::align_of::<PacketBufferMeta>();
const DEFAULT_BUFFER_SIZE: usize = (DMA_PAGE_SIZE - PACKET_META_SIZE) & !(PACKET_META_ALIGN - 1);

#[repr(C, align(4096))]
#[derive(Debug)]
pub struct PacketBuffer {
    data: [u8; DEFAULT_BUFFER_SIZE],
    meta: PacketBufferMeta,
}

impl PacketBuffer {
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
    pub fn phys_addr(&self) -> PhysAddr {
        self.meta.phys_addr
    }
    pub fn device_address(&self) -> u64 {
        if self.meta.device_addr != 0 {
            self.meta.device_addr
        } else {
            self.meta.phys_addr.as_u64()
        }
    }
    pub fn set_device_address(&mut self, addr: u64) {
        self.meta.device_addr = addr;
    }
    pub fn add_ref(&self) -> bool {
        self.meta
            .ref_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current == 0 {
                    return None;
                }
                current.checked_add(1)
            })
            .is_ok()
    }

    pub fn release(&self) -> bool {
        loop {
            let current = self.meta.ref_count.load(Ordering::Acquire);
            debug_assert!(current > 0);
            if current == 0 {
                return false;
            }
            let next = current - 1;
            if self
                .meta
                .ref_count
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                if next == 0 {
                    fence(Ordering::Acquire);
                    return true;
                }
                return false;
            }
        }
    }
}

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

unsafe impl Send for Mempool {}
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
    pub fn new(id: u32, cpu_snapshot: &crate::cpu::CpuSnapshot) -> Result<Self, MempoolError> {
        let mut local_caches = Vec::new();
        local_caches
            .try_reserve_exact(cpu_snapshot.slots().len())
            .map_err(|_| MempoolError::CpuCacheAllocationFailed)?;
        for slot in cpu_snapshot.slots() {
            if slot.id.as_usize() != local_caches.len() {
                return Err(MempoolError::CpuNotProvisioned(slot.id));
            }
            local_caches.push(Arc::new(PoisonLock::new(Vec::new())));
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

    pub fn init(&self, capacity: usize) -> Result<(), MempoolError> {
        let mut buffers = self
            .buffers
            .lock()
            .map_err(|_| MempoolError::LockPoisoned(MempoolLock::BufferRegistry))?;
        let mut free_list = self
            .free_list
            .lock()
            .map_err(|_| MempoolError::LockPoisoned(MempoolLock::FreeList))?;
        for i in 0..capacity {
            let layout = alloc::alloc::Layout::new::<PacketBuffer>();
            let nn = crate::mm::cache::exchange_heap::allocate_raw(layout)
                .ok_or(MempoolError::BufferAllocationFailed)?;
            let non_null = nn.cast::<PacketBuffer>();
            crate::sas::register_object(
                non_null.as_ptr() as usize,
                layout.size(),
                crate::sas::DomainId::new(0),
            );
            unsafe { Self::write_initial_packet_buffer(non_null, self.id, i as u32) };
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
            local_caches.push(Arc::new(PoisonLock::new(Vec::new())));
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

    unsafe fn write_initial_packet_buffer(buffer: NonNull<PacketBuffer>, pool_id: u32, index: u32) {
        let buffer_ptr = buffer.as_ptr();
        let virt_addr = buffer_ptr as u64;
        let offset = crate::mm::virt::mapping::physical_memory_offset();
        let phys = if virt_addr >= offset {
            virt_addr - offset
        } else {
            virt_addr
        };
        unsafe {
            core::ptr::addr_of_mut!((*buffer_ptr).data)
                .cast::<u8>()
                .write_bytes(0, DEFAULT_BUFFER_SIZE);
            core::ptr::addr_of_mut!((*buffer_ptr).meta).write(PacketBufferMeta {
                phys_addr: PhysAddr::new(phys),
                device_addr: 0,
                pool_id,
                index,
                ref_count: AtomicU64::new(0),
                _padding: [0; 8],
            });
        }
    }

    fn record_alloc_failure(&self, error: MempoolError) -> MempoolError {
        self.alloc_failed.fetch_add(1, Ordering::Relaxed);
        error
    }

    unsafe fn init_buffer_for_alloc(
        buffer: NonNull<PacketBuffer>,
        pool: &'static Mempool,
    ) -> PacketRef {
        // SAFETY: the free-list hands out this buffer exclusively. PacketRef
        // growth initializes only bytes that become software-visible, while RX
        // completion publishes only the device-written prefix.
        unsafe { buffer.as_ref().meta.ref_count.store(1, Ordering::Release) };
        new_pooled_packet_ref(buffer, pool)
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
                            let split_idx = remote_cache.len() - steal_count;
                            let stolen = remote_cache.split_off(split_idx);
                            cache.extend(stolen);
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
        Ok(unsafe { Self::init_buffer_for_alloc(buffer, self) })
    }

    fn return_buffer(&self, buffer: NonNull<PacketBuffer>) {
        let cache_lock = crate::cpu::CurrentCpu::acquire()
            .map(|current| current.id())
            .and_then(|cpu_id| self.local_cache(cpu_id).ok());
        if let Some(cache_lock) = cache_lock {
            if let Ok(mut cache) = cache_lock.lock() {
                cache.push(buffer);
                if cache.len() >= CPU_CACHE_CAPACITY {
                    let mid = cache.len() / 2;
                    let to_flush = cache.split_off(mid);
                    let mut global_free = self.free_list.lock().unwrap_or_else(|e| e.into_inner());
                    global_free.extend(to_flush);
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
