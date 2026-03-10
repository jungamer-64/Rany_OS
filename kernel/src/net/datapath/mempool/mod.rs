// ============================================================================
// src/net/mempool.rs - Zero-Copy Network Buffer Pool
// 設計書 6.2: Mempool によるゼロコピーネットワークバッファ管理
// ============================================================================

// Building block: Memory pool types
#![allow(dead_code)]

use crate::ipc::rref::RRef;
use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernel_api::dma::{CpuOwned as KapiCpuOwned, DmaSlice as KapiDmaSlice};
pub use kernel_api::resource::net::{PacketMeta, PacketRef, PacketType};
use kernel_api::resource::net::{PacketRefStorage, PacketRefVTable};
use kernel_api::service::kernel::instance as kernel_instance;
use x86_64::PhysAddr;

use crate::mm::types::PAGE_SIZE_4K;

/// DMAページサイズ
mod pool_impl;
pub use pool_impl::*;
const DMA_PAGE_SIZE: usize = PAGE_SIZE_4K;

/// デフォルトのプール容量
const DEFAULT_POOL_CAPACITY: usize = 4096;

/// キャッシュラインサイズ
const CACHE_LINE_SIZE: usize = 64;

/// パケットバッファのメタデータ
#[repr(C)]
#[derive(Debug)]
struct PacketBufferMeta {
    len: AtomicUsize,
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
    pub fn data(&self) -> &[u8] {
        &self.data[..self.meta.len.load(Ordering::Acquire)]
    }
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.meta.len.load(Ordering::Acquire);
        &mut self.data[..len]
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
    pub fn len(&self) -> usize {
        self.meta.len.load(Ordering::Acquire)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn set_len(&self, len: usize) {
        self.meta
            .len
            .store(len.min(DEFAULT_BUFFER_SIZE), Ordering::Release);
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
    pub fn add_ref(&self) {
        self.meta.ref_count.fetch_add(1, Ordering::Relaxed);
    }
    pub fn release(&self) -> bool {
        self.meta.ref_count.fetch_sub(1, Ordering::Release) == 1
    }
}

use crate::io::dma::{CpuOwned as KernelCpuOwned, TypedDmaSlice};
use alloc::sync::Arc;

const NO_PACKET_DMA_DEVICE: u64 = u64::MAX;
const DMA_PACKET_BUFFER_SIZE: usize = DMA_PAGE_SIZE;

static PACKET_DMA_DEVICE_ID: AtomicU64 = AtomicU64::new(NO_PACKET_DMA_DEVICE);

enum DmaBufferOwner {
    Kernel(Arc<PoisonLock<TypedDmaSlice<KernelCpuOwned>>>),
    Kapi(Arc<PoisonLock<KapiDmaSlice<KapiCpuOwned>>>),
}

struct DmaBuffer {
    pub(super) ptr: NonNull<u8>,
    pub(super) phys_addr: PhysAddr,
    pub(super) device_addr: u64,
    pub(super) size: usize,
    owner: DmaBufferOwner,
}

impl fmt::Debug for DmaBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DmaBuffer")
            .field("ptr", &self.ptr)
            .field("phys_addr", &self.phys_addr)
            .field("device_addr", &self.device_addr)
            .field("size", &self.size)
            .finish()
    }
}

impl DmaBuffer {
    fn from_typed(slice: TypedDmaSlice<KernelCpuOwned>) -> Self {
        let size = slice.len();
        let phys = slice.phys_addr();
        let device_addr = slice.device_address();
        let ptr = slice.as_slice().as_ptr() as *mut u8;
        Self {
            ptr: NonNull::new(ptr).expect("TypedDmaSlice returned null pointer"),
            phys_addr: phys,
            device_addr,
            size,
            owner: DmaBufferOwner::Kernel(Arc::new(PoisonLock::new(slice))),
        }
    }

    fn from_kapi(slice: KapiDmaSlice<KapiCpuOwned>) -> Self {
        let size = slice.size();
        let phys_addr = PhysAddr::new(slice.physical_address());
        let device_addr = slice.device_address();
        let ptr = slice.as_ptr();
        Self {
            ptr: NonNull::new(ptr).expect("DmaSlice returned null pointer"),
            phys_addr,
            device_addr,
            size,
            owner: DmaBufferOwner::Kapi(Arc::new(PoisonLock::new(slice))),
        }
    }
}

impl Clone for DmaBufferOwner {
    fn clone(&self) -> Self {
        match self {
            Self::Kernel(owner) => Self::Kernel(owner.clone()),
            Self::Kapi(owner) => Self::Kapi(owner.clone()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PooledPacketState {
    buffer: NonNull<PacketBuffer>,
    pool: &'static Mempool,
    offset: usize,
    len: usize,
}

#[derive(Debug, Clone)]
struct DmaPacketState {
    buf: Arc<DmaBuffer>,
    offset: usize,
    len: usize,
}

#[cfg(any(test, feature = "qemu-test-export"))]
#[derive(Debug, Clone, Copy)]
struct BorrowedTestPacketState {
    ptr: NonNull<u8>,
    cap: usize,
    offset: usize,
    len: usize,
}

unsafe fn pooled_state_ref(storage: &PacketRefStorage) -> &PooledPacketState {
    storage.as_state_ref::<PooledPacketState>()
}
unsafe fn pooled_state_mut(storage: &mut PacketRefStorage) -> &mut PooledPacketState {
    storage.as_state_mut::<PooledPacketState>()
}
unsafe fn pooled_data_ptr(storage: &PacketRefStorage) -> *const u8 {
    let state = pooled_state_ref(storage);
    state.buffer.as_ref().as_ptr().add(state.offset)
}
unsafe fn pooled_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
    let state = pooled_state_mut(storage);
    (*state.buffer.as_ptr()).as_mut_ptr().add(state.offset)
}
unsafe fn pooled_len(storage: &PacketRefStorage) -> usize {
    pooled_state_ref(storage).len
}
unsafe fn pooled_set_len(storage: &mut PacketRefStorage, len: usize) {
    let state = pooled_state_mut(storage);
    let new_len = len.min(DEFAULT_BUFFER_SIZE.saturating_sub(state.offset));
    state.len = new_len;
    state.buffer.as_ref().set_len(new_len);
}
unsafe fn pooled_capacity(_: &PacketRefStorage) -> usize {
    DEFAULT_BUFFER_SIZE
}
unsafe fn pooled_phys_addr(storage: &PacketRefStorage) -> u64 {
    let state = pooled_state_ref(storage);
    state.buffer.as_ref().phys_addr().as_u64() + state.offset as u64
}
unsafe fn pooled_device_address(storage: &PacketRefStorage) -> u64 {
    let state = pooled_state_ref(storage);
    state.buffer.as_ref().device_address() + state.offset as u64
}
unsafe fn pooled_advance(storage: &mut PacketRefStorage, size: usize) {
    let state = pooled_state_mut(storage);
    state.offset = state.offset.saturating_add(size).min(DEFAULT_BUFFER_SIZE);
    state.len = state.len.saturating_sub(size);
}
unsafe fn pooled_clone(storage: &PacketRefStorage) -> PacketRefStorage {
    let state = pooled_state_ref(storage);
    state.buffer.as_ref().add_ref();
    PacketRefStorage::from_state(*state)
}
unsafe fn pooled_drop(storage: &mut PacketRefStorage) {
    let state = pooled_state_mut(storage);
    if state.buffer.as_ref().release() {
        state.pool.return_buffer(state.buffer);
    }
}

static POOLED_PACKET_VTABLE: PacketRefVTable = PacketRefVTable {
    data_ptr: pooled_data_ptr,
    data_mut_ptr: pooled_data_mut_ptr,
    len: pooled_len,
    set_len: pooled_set_len,
    capacity: pooled_capacity,
    phys_addr: pooled_phys_addr,
    device_address: pooled_device_address,
    advance: pooled_advance,
    clone_storage: pooled_clone,
    drop_storage: pooled_drop,
};

unsafe fn dma_state_ref(storage: &PacketRefStorage) -> &DmaPacketState {
    storage.as_state_ref::<DmaPacketState>()
}
unsafe fn dma_state_mut(storage: &mut PacketRefStorage) -> &mut DmaPacketState {
    storage.as_state_mut::<DmaPacketState>()
}
unsafe fn dma_data_ptr(storage: &PacketRefStorage) -> *const u8 {
    let state = dma_state_ref(storage);
    state.buf.ptr.as_ptr().add(state.offset)
}
unsafe fn dma_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
    let state = dma_state_mut(storage);
    state.buf.ptr.as_ptr().add(state.offset)
}
unsafe fn dma_len(storage: &PacketRefStorage) -> usize {
    dma_state_ref(storage).len
}
unsafe fn dma_set_len(storage: &mut PacketRefStorage, len: usize) {
    let state = dma_state_mut(storage);
    state.len = len.min(state.buf.size.saturating_sub(state.offset));
}
unsafe fn dma_capacity(storage: &PacketRefStorage) -> usize {
    dma_state_ref(storage).buf.size
}
unsafe fn dma_phys_addr(storage: &PacketRefStorage) -> u64 {
    let state = dma_state_ref(storage);
    state.buf.phys_addr.as_u64() + state.offset as u64
}
unsafe fn dma_device_address(storage: &PacketRefStorage) -> u64 {
    let state = dma_state_ref(storage);
    state.buf.device_addr + state.offset as u64
}
unsafe fn dma_advance(storage: &mut PacketRefStorage, size: usize) {
    let state = dma_state_mut(storage);
    state.offset = state.offset.saturating_add(size).min(state.buf.size);
    state.len = state.len.saturating_sub(size);
}
unsafe fn dma_clone(storage: &PacketRefStorage) -> PacketRefStorage {
    let state = dma_state_ref(storage);
    PacketRefStorage::from_state(state.clone())
}
unsafe fn dma_drop(storage: &mut PacketRefStorage) {
    core::ptr::drop_in_place(storage.as_state_mut::<DmaPacketState>());
}

static DMA_PACKET_VTABLE: PacketRefVTable = PacketRefVTable {
    data_ptr: dma_data_ptr,
    data_mut_ptr: dma_data_mut_ptr,
    len: dma_len,
    set_len: dma_set_len,
    capacity: dma_capacity,
    phys_addr: dma_phys_addr,
    device_address: dma_device_address,
    advance: dma_advance,
    clone_storage: dma_clone,
    drop_storage: dma_drop,
};

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_state_ref(storage: &PacketRefStorage) -> &BorrowedTestPacketState {
    storage.as_state_ref::<BorrowedTestPacketState>()
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_state_mut(storage: &mut PacketRefStorage) -> &mut BorrowedTestPacketState {
    storage.as_state_mut::<BorrowedTestPacketState>()
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_data_ptr(storage: &PacketRefStorage) -> *const u8 {
    let state = borrowed_state_ref(storage);
    state.ptr.as_ptr().add(state.offset)
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
    let state = borrowed_state_mut(storage);
    state.ptr.as_ptr().add(state.offset)
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_len(storage: &PacketRefStorage) -> usize {
    borrowed_state_ref(storage).len
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_set_len(storage: &mut PacketRefStorage, len: usize) {
    let state = borrowed_state_mut(storage);
    state.len = len.min(state.cap.saturating_sub(state.offset));
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_capacity(storage: &PacketRefStorage) -> usize {
    borrowed_state_ref(storage).cap
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_phys_addr(storage: &PacketRefStorage) -> u64 {
    borrowed_state_ref(storage).offset as u64
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_device_address(storage: &PacketRefStorage) -> u64 {
    borrowed_phys_addr(storage)
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_advance(storage: &mut PacketRefStorage, size: usize) {
    let state = borrowed_state_mut(storage);
    state.offset = state.offset.saturating_add(size).min(state.cap);
    state.len = state.len.saturating_sub(size);
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_clone(storage: &PacketRefStorage) -> PacketRefStorage {
    let state = borrowed_state_ref(storage);
    PacketRefStorage::from_state(*state)
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_drop(_: &mut PacketRefStorage) {}

#[cfg(any(test, feature = "qemu-test-export"))]
static BORROWED_PACKET_VTABLE: PacketRefVTable = PacketRefVTable {
    data_ptr: borrowed_data_ptr,
    data_mut_ptr: borrowed_data_mut_ptr,
    len: borrowed_len,
    set_len: borrowed_set_len,
    capacity: borrowed_capacity,
    phys_addr: borrowed_phys_addr,
    device_address: borrowed_device_address,
    advance: borrowed_advance,
    clone_storage: borrowed_clone,
    drop_storage: borrowed_drop,
};

fn new_pooled_packet_ref(buffer: NonNull<PacketBuffer>, pool: &'static Mempool) -> PacketRef {
    let state = PooledPacketState {
        buffer,
        pool,
        offset: 0,
        len: unsafe { buffer.as_ref().len() },
    };
    unsafe {
        PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &POOLED_PACKET_VTABLE)
    }
}

pub fn packet_ref_from_dma_slice(slice: TypedDmaSlice<KernelCpuOwned>) -> PacketRef {
    let state = DmaPacketState {
        buf: Arc::new(DmaBuffer::from_typed(slice)),
        offset: 0,
        len: 0,
    };
    unsafe { PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &DMA_PACKET_VTABLE) }
}

fn packet_ref_from_kapi_dma_slice(slice: KapiDmaSlice<KapiCpuOwned>) -> PacketRef {
    let state = DmaPacketState {
        buf: Arc::new(DmaBuffer::from_kapi(slice)),
        offset: 0,
        len: 0,
    };
    unsafe { PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &DMA_PACKET_VTABLE) }
}

pub(crate) fn set_packet_dma_device(device_id: Option<u64>) {
    PACKET_DMA_DEVICE_ID.store(device_id.unwrap_or(NO_PACKET_DMA_DEVICE), Ordering::Release);
}

pub(crate) fn alloc_packet_for_active_dma_device() -> Option<PacketRef> {
    let device_id = PACKET_DMA_DEVICE_ID.load(Ordering::Acquire);
    if device_id == NO_PACKET_DMA_DEVICE {
        return None;
    }

    kernel_instance()
        .alloc_dma_for_device(
            DMA_PACKET_BUFFER_SIZE,
            kernel_api::abi::driver::PackedPciLocation::from_raw(device_id),
        )
        .ok()
        .map(packet_ref_from_kapi_dma_slice)
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub unsafe fn packet_ref_from_static_raw_for_tests(ptr: *mut u8, cap: usize) -> Option<PacketRef> {
    if cap == 0 {
        return None;
    }
    let state = BorrowedTestPacketState {
        ptr: NonNull::new(ptr)?,
        cap,
        offset: 0,
        len: 0,
    };
    Some(unsafe {
        PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &BORROWED_PACKET_VTABLE)
    })
}

#[derive(Debug)]
pub struct Mempool {
    id: u32,
    buffers: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    free_list: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    alloc_count: AtomicU64,
    free_count: AtomicU64,
    alloc_failed: AtomicU64,
}

unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}

impl Mempool {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            buffers: PoisonLock::new(Vec::new()),
            free_list: PoisonLock::new(Vec::new()),
            alloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            alloc_failed: AtomicU64::new(0),
        }
    }

    pub fn init(&self, capacity: usize) -> Result<(), &'static str> {
        let mut buffers = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        let mut free_list = self.free_list.lock().unwrap_or_else(|e| e.into_inner());
        for i in 0..capacity {
            let layout = alloc::alloc::Layout::new::<PacketBuffer>();
            let nn = crate::mm::cache::exchange_heap::allocate_raw(layout)
                .ok_or("Failed to allocate buffer")?;
            let non_null = nn.cast::<PacketBuffer>();
            crate::sas::register_object(
                non_null.as_ptr() as usize,
                layout.size(),
                crate::sas::DomainId::new(0),
            );
            unsafe {
                let buffer_ptr = non_null.as_ptr();
                (*buffer_ptr).meta.pool_id = self.id;
                (*buffer_ptr).meta.index = i as u32;
                (*buffer_ptr).meta.len = AtomicUsize::new(0);
                (*buffer_ptr).meta.ref_count = AtomicU64::new(0);
                let virt_addr = buffer_ptr as u64;
                let offset = crate::mm::virt::mapping::physical_memory_offset();
                let phys = if virt_addr >= offset {
                    virt_addr - offset
                } else {
                    virt_addr
                };
                (*buffer_ptr).meta.phys_addr = PhysAddr::new(phys);
            }
            buffers.push(non_null);
            free_list.push(non_null);
        }
        Ok(())
    }

    pub fn alloc(&'static self) -> Option<PacketRef> {
        let buffer = self
            .free_list
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop()?;
        unsafe {
            // Security: Clear the entire buffer to prevent information leaks from previous packets.
            // Previously we only cleared up to prev_len, which failed if an offset was used.
            core::ptr::write_bytes(
                buffer.as_ref().data.as_ptr() as *mut u8,
                0,
                DEFAULT_BUFFER_SIZE,
            );
            buffer.as_ref().meta.len.store(0, Ordering::Release);
            buffer.as_ref().meta.ref_count.store(1, Ordering::Release);
        }
        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        Some(new_pooled_packet_ref(buffer, self))
    }

    fn return_buffer(&self, buffer: NonNull<PacketBuffer>) {
        self.free_list
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(buffer);
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn return_rref(&self, rref: RRef<PacketBuffer>) {
        let (ptr, owner) = rref.into_raw();
        unsafe {
            // Try to transfer ownership back to kernel (domain 0)
            let _ = crate::sas::transfer_ownership(
                ptr.as_ptr() as usize,
                crate::sas::DomainId::new(owner.as_u64()),
                crate::sas::DomainId::new(0),
            );
            // Always return to buffer pool to avoid leakage
            ptr.as_ref().meta.len.store(0, Ordering::Release);
            ptr.as_ref().meta.ref_count.store(0, Ordering::Release);
            self.return_buffer(ptr);
        }
    }

    pub fn stats(&self) -> MempoolStats {
        let total = self.buffers.lock().unwrap_or_else(|e| e.into_inner()).len();
        let free = self
            .free_list
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        MempoolStats {
            total_buffers: total,
            free_buffers: free,
            used_buffers: total - free,
            alloc_count: self.alloc_count.load(Ordering::Relaxed),
            free_count: self.free_count.load(Ordering::Relaxed),
            alloc_failed: self.alloc_failed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MempoolStats {
    pub total_buffers: usize,
    pub free_buffers: usize,
    pub used_buffers: usize,
    pub alloc_count: u64,
    pub free_count: u64,
    pub alloc_failed: u64,
}

#[derive(Debug)]
pub struct PerCoreMempoolCache {
    local_cache: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    cache_capacity: usize,
    parent: &'static Mempool,
}

const BATCH_REFILL_COUNT: usize = 16;

impl PerCoreMempoolCache {
    pub fn new(parent: &'static Mempool, capacity: usize) -> Self {
        Self {
            local_cache: PoisonLock::new(Vec::with_capacity(capacity)),
            cache_capacity: capacity,
            parent,
        }
    }

    #[inline]
    unsafe fn init_buffer_for_alloc(
        buffer: NonNull<PacketBuffer>,
        pool: &'static Mempool,
    ) -> PacketRef {
        // Security: Clear the entire buffer to prevent information leaks from previous packets.
        core::ptr::write_bytes(
            buffer.as_ref().data.as_ptr() as *mut u8,
            0,
            DEFAULT_BUFFER_SIZE,
        );
        buffer.as_ref().meta.len.store(0, Ordering::Release);
        buffer.as_ref().meta.ref_count.store(1, Ordering::Release);
        new_pooled_packet_ref(buffer, pool)
    }

    pub fn alloc(&'static self) -> Option<PacketRef> {
        let mut cache = self.local_cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(buffer) = cache.pop() {
            return Some(unsafe { Self::init_buffer_for_alloc(buffer, self.parent) });
        }
        let refill_count = BATCH_REFILL_COUNT.min(self.cache_capacity);
        let mut free_list = self
            .parent
            .free_list
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let available = free_list.len().min(refill_count);
        if available > 0 {
            let split_at = free_list.len() - available;
            let refilled: Vec<NonNull<PacketBuffer>> = free_list.split_off(split_at);
            let mut iter = refilled.into_iter();
            let first = iter.next();
            for buf in iter {
                cache.push(buf);
            }
            if let Some(buffer) = first {
                self.parent.alloc_count.fetch_add(1, Ordering::Relaxed);
                return Some(unsafe { Self::init_buffer_for_alloc(buffer, self.parent) });
            }
        }
        drop(free_list);
        self.parent.alloc()
    }

    pub fn free(&self, buffer: NonNull<PacketBuffer>) {
        let mut cache = self.local_cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() < self.cache_capacity {
            cache.push(buffer);
            return;
        }
        drop(cache);
        self.parent.return_buffer(buffer);
    }
}

#[derive(Debug)]
pub struct PacketPool {
    buffers: PoisonLock<Vec<Vec<u8>>>,
    buffer_size: usize,
    capacity: usize,
}
