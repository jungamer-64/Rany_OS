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
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
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

use crate::io::dma::{CpuOwned as KernelCpuOwned, TypedDmaSlice};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct PacketWindow {
    capacity: usize,
    offset: usize,
    len: usize,
}

impl PacketWindow {
    fn new(capacity: usize, offset: usize, len: usize) -> Option<Self> {
        (offset <= capacity && len <= capacity - offset).then_some(Self {
            capacity,
            offset,
            len,
        })
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn len(&self) -> usize {
        self.len
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn set_len(&mut self, len: usize) -> bool {
        if len > self.capacity - self.offset {
            return false;
        }
        self.len = len;
        true
    }

    fn advance(&mut self, n: usize) -> bool {
        if n > self.len {
            return false;
        }
        self.offset += n;
        self.len -= n;
        true
    }

    fn retreat(&mut self, n: usize) -> bool {
        let Some(new_offset) = self.offset.checked_sub(n) else {
            return false;
        };
        let Some(new_len) = self.len.checked_add(n) else {
            return false;
        };
        if new_len > self.capacity - new_offset {
            return false;
        }
        self.offset = new_offset;
        self.len = new_len;
        true
    }
}

struct DmaBuffer {
    pub(super) ptr: NonNull<u8>,
    pub(super) phys_addr: PhysAddr,
    pub(super) device_addr: u64,
    pub(super) size: usize,
    ref_count: AtomicU64,
    _slice: PoisonLock<TypedDmaSlice<KernelCpuOwned>>,
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
            ref_count: AtomicU64::new(1),
            _slice: PoisonLock::new(slice),
        }
    }
}

fn dma_add_ref(buf: NonNull<DmaBuffer>) -> bool {
    unsafe {
        buf.as_ref()
            .ref_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current == 0 {
                    return None;
                }
                current.checked_add(1)
            })
            .is_ok()
    }
}

fn dma_release(buf: NonNull<DmaBuffer>) -> bool {
    loop {
        let current = unsafe { buf.as_ref().ref_count.load(Ordering::Acquire) };
        debug_assert!(current > 0);
        if current == 0 {
            return false;
        }
        let next = current - 1;
        if unsafe {
            buf.as_ref().ref_count.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
        }
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

#[derive(Debug, Clone, Copy)]
struct PooledPacketState {
    buffer: NonNull<PacketBuffer>,
    pool: &'static Mempool,
    window: PacketWindow,
}

#[derive(Debug, Clone, Copy)]
struct DmaPacketState {
    buf: NonNull<DmaBuffer>,
    window: PacketWindow,
}

#[cfg(any(test, feature = "qemu-test-export"))]
#[derive(Debug, Clone, Copy)]
struct BorrowedTestPacketState {
    ptr: NonNull<u8>,
    window: PacketWindow,
}

unsafe fn pooled_state_ref(storage: &PacketRefStorage) -> &PooledPacketState {
    // SAFETY: this function is only installed in POOLED_PACKET_VTABLE, whose
    // storage is constructed from PooledPacketState in new_pooled_packet_ref.
    unsafe { storage.as_state_ref::<PooledPacketState>() }
}
unsafe fn pooled_state_mut(storage: &mut PacketRefStorage) -> &mut PooledPacketState {
    // SAFETY: this function is only installed in POOLED_PACKET_VTABLE, whose
    // storage is constructed from PooledPacketState in new_pooled_packet_ref.
    unsafe { storage.as_state_mut::<PooledPacketState>() }
}
unsafe fn pooled_data_ptr(storage: &PacketRefStorage) -> *const u8 {
    // SAFETY: the pooled vtable ties this storage to PooledPacketState, and the
    // PacketWindow offset is bounded by the packet buffer capacity.
    unsafe {
        let state = pooled_state_ref(storage);
        state.buffer.as_ref().as_ptr().add(state.window.offset())
    }
}
unsafe fn pooled_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
    // SAFETY: the pooled vtable ties this storage to PooledPacketState, and
    // mutable PacketRef access gives exclusive access to the packet window.
    unsafe {
        let state = pooled_state_mut(storage);
        (*state.buffer.as_ptr())
            .as_mut_ptr()
            .add(state.window.offset())
    }
}
unsafe fn pooled_len(storage: &PacketRefStorage) -> usize {
    // SAFETY: this function is only called through POOLED_PACKET_VTABLE.
    unsafe { pooled_state_ref(storage).window.len() }
}
unsafe fn pooled_set_len(storage: &mut PacketRefStorage, len: PacketByteCount) -> bool {
    // SAFETY: this function is only called through POOLED_PACKET_VTABLE.
    unsafe {
        let state = pooled_state_mut(storage);
        state.window.set_len(len.get())
    }
}
unsafe fn pooled_capacity(_: &PacketRefStorage) -> usize {
    DEFAULT_BUFFER_SIZE
}
unsafe fn pooled_headroom(storage: &PacketRefStorage) -> usize {
    // SAFETY: this function is only called through POOLED_PACKET_VTABLE.
    unsafe { pooled_state_ref(storage).window.offset() }
}
unsafe fn pooled_phys_addr(storage: &PacketRefStorage) -> u64 {
    // SAFETY: the pooled state owns a live PacketBuffer while the PacketRef is
    // alive; PacketWindow keeps offset within the buffer.
    unsafe {
        let state = pooled_state_ref(storage);
        state.buffer.as_ref().phys_addr().as_u64() + state.window.offset() as u64
    }
}
unsafe fn pooled_device_address(storage: &PacketRefStorage) -> u64 {
    // SAFETY: the pooled state owns a live PacketBuffer while the PacketRef is
    // alive; PacketWindow keeps offset within the buffer.
    unsafe {
        let state = pooled_state_ref(storage);
        state.buffer.as_ref().device_address() + state.window.offset() as u64
    }
}
unsafe fn pooled_advance(storage: &mut PacketRefStorage, size: PacketByteCount) -> bool {
    // SAFETY: this function is only called through POOLED_PACKET_VTABLE.
    unsafe {
        let state = pooled_state_mut(storage);
        state.window.advance(size.get())
    }
}
unsafe fn pooled_retreat(storage: &mut PacketRefStorage, size: PacketByteCount) -> bool {
    // SAFETY: this function is only called through POOLED_PACKET_VTABLE.
    unsafe {
        let state = pooled_state_mut(storage);
        state.window.retreat(size.get())
    }
}
unsafe fn pooled_drop(storage: &mut PacketRefStorage) {
    // SAFETY: this function is only called through POOLED_PACKET_VTABLE, and
    // release returns true only for the last PacketRef to this pooled buffer.
    unsafe {
        let state = pooled_state_mut(storage);
        if state.buffer.as_ref().release() {
            state.pool.return_buffer(state.buffer);
        }
    }
}

unsafe fn pooled_split_front(
    storage: &PacketRefStorage,
    len: PacketByteCount,
) -> Option<(PacketRefStorage, PacketRefStorage)> {
    unsafe {
        let state = *pooled_state_ref(storage);
        let len = len.get();
        if len == 0 || len >= state.window.len() || !state.buffer.as_ref().add_ref() {
            return None;
        }
        let mut front = state;
        let mut remainder = state;
        if !front.window.set_len(len) || !remainder.window.advance(len) {
            return None;
        }
        Some((
            PacketRefStorage::from_state(front),
            PacketRefStorage::from_state(remainder),
        ))
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
    headroom: pooled_headroom,
    advance: pooled_advance,
    retreat: pooled_retreat,
    split_front: pooled_split_front,
    drop_storage: pooled_drop,
};

unsafe fn dma_state_ref(storage: &PacketRefStorage) -> &DmaPacketState {
    // SAFETY: this function is only installed in DMA_PACKET_VTABLE, whose
    // storage is constructed from DmaPacketState by DMA packet constructors.
    unsafe { storage.as_state_ref::<DmaPacketState>() }
}
unsafe fn dma_state_mut(storage: &mut PacketRefStorage) -> &mut DmaPacketState {
    // SAFETY: this function is only installed in DMA_PACKET_VTABLE, whose
    // storage is constructed from DmaPacketState by DMA packet constructors.
    unsafe { storage.as_state_mut::<DmaPacketState>() }
}
unsafe fn dma_data_ptr(storage: &PacketRefStorage) -> *const u8 {
    // SAFETY: the DMA vtable ties this storage to DmaPacketState, and
    // PacketWindow keeps offset within the DMA buffer.
    unsafe {
        let state = dma_state_ref(storage);
        state.buf.as_ref().ptr.as_ptr().add(state.window.offset())
    }
}
unsafe fn dma_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
    // SAFETY: the DMA vtable ties this storage to DmaPacketState, and mutable
    // PacketRef access gives exclusive access to the packet window.
    unsafe {
        let state = dma_state_mut(storage);
        state.buf.as_ref().ptr.as_ptr().add(state.window.offset())
    }
}
unsafe fn dma_len(storage: &PacketRefStorage) -> usize {
    // SAFETY: this function is only called through DMA_PACKET_VTABLE.
    unsafe { dma_state_ref(storage).window.len() }
}
unsafe fn dma_set_len(storage: &mut PacketRefStorage, len: PacketByteCount) -> bool {
    // SAFETY: this function is only called through DMA_PACKET_VTABLE.
    unsafe {
        let state = dma_state_mut(storage);
        state.window.set_len(len.get())
    }
}
unsafe fn dma_capacity(storage: &PacketRefStorage) -> usize {
    // SAFETY: this function is only called through DMA_PACKET_VTABLE.
    unsafe { dma_state_ref(storage).window.capacity() }
}
unsafe fn dma_headroom(storage: &PacketRefStorage) -> usize {
    // SAFETY: this function is only called through DMA_PACKET_VTABLE.
    unsafe { dma_state_ref(storage).window.offset() }
}
unsafe fn dma_phys_addr(storage: &PacketRefStorage) -> u64 {
    // SAFETY: the DMA state owns a live DmaBuffer while the PacketRef is alive;
    // PacketWindow keeps offset within the buffer.
    unsafe {
        let state = dma_state_ref(storage);
        state.buf.as_ref().phys_addr.as_u64() + state.window.offset() as u64
    }
}
unsafe fn dma_device_address(storage: &PacketRefStorage) -> u64 {
    // SAFETY: the DMA state owns a live DmaBuffer while the PacketRef is alive;
    // PacketWindow keeps offset within the buffer.
    unsafe {
        let state = dma_state_ref(storage);
        state.buf.as_ref().device_addr + state.window.offset() as u64
    }
}
unsafe fn dma_advance(storage: &mut PacketRefStorage, size: PacketByteCount) -> bool {
    // SAFETY: this function is only called through DMA_PACKET_VTABLE.
    unsafe {
        let state = dma_state_mut(storage);
        state.window.advance(size.get())
    }
}
unsafe fn dma_retreat(storage: &mut PacketRefStorage, size: PacketByteCount) -> bool {
    // SAFETY: this function is only called through DMA_PACKET_VTABLE.
    unsafe {
        let state = dma_state_mut(storage);
        state.window.retreat(size.get())
    }
}
unsafe fn dma_drop(storage: &mut PacketRefStorage) {
    // SAFETY: this function is only called through DMA_PACKET_VTABLE. The
    // DmaBuffer was allocated with Box::leak by the DMA packet constructors and
    // is reclaimed exactly once when the last PacketRef drops this storage.
    unsafe {
        let state = storage.as_state_mut::<DmaPacketState>();
        let buf = state.buf;
        if dma_release(buf) {
            core::ptr::drop_in_place(state);
            drop(Box::from_raw(buf.as_ptr()));
        }
    }
}

unsafe fn dma_split_front(
    storage: &PacketRefStorage,
    len: PacketByteCount,
) -> Option<(PacketRefStorage, PacketRefStorage)> {
    unsafe {
        let state = *dma_state_ref(storage);
        let len = len.get();
        if len == 0 || len >= state.window.len() || !dma_add_ref(state.buf) {
            return None;
        }
        let mut front = state;
        let mut remainder = state;
        if !front.window.set_len(len) || !remainder.window.advance(len) {
            return None;
        }
        Some((
            PacketRefStorage::from_state(front),
            PacketRefStorage::from_state(remainder),
        ))
    }
}

static DMA_PACKET_VTABLE: PacketRefVTable = PacketRefVTable {
    data_ptr: dma_data_ptr,
    data_mut_ptr: dma_data_mut_ptr,
    len: dma_len,
    set_len: dma_set_len,
    capacity: dma_capacity,
    phys_addr: dma_phys_addr,
    device_address: dma_device_address,
    headroom: dma_headroom,
    advance: dma_advance,
    retreat: dma_retreat,
    split_front: dma_split_front,
    drop_storage: dma_drop,
};

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_state_ref(storage: &PacketRefStorage) -> &BorrowedTestPacketState {
    // SAFETY: this function is only installed in BORROWED_PACKET_VTABLE, whose
    // storage is constructed from BorrowedTestPacketState for tests/export.
    unsafe { storage.as_state_ref::<BorrowedTestPacketState>() }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_state_mut(storage: &mut PacketRefStorage) -> &mut BorrowedTestPacketState {
    // SAFETY: this function is only installed in BORROWED_PACKET_VTABLE, whose
    // storage is constructed from BorrowedTestPacketState for tests/export.
    unsafe { storage.as_state_mut::<BorrowedTestPacketState>() }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_data_ptr(storage: &PacketRefStorage) -> *const u8 {
    // SAFETY: test/export borrowed storage is tied to BorrowedTestPacketState,
    // and PacketWindow keeps offset within the caller-provided capacity.
    unsafe {
        let state = borrowed_state_ref(storage);
        state.ptr.as_ptr().add(state.window.offset())
    }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
    // SAFETY: test/export borrowed storage is tied to BorrowedTestPacketState,
    // and mutable PacketRef access gives exclusive access to the packet window.
    unsafe {
        let state = borrowed_state_mut(storage);
        state.ptr.as_ptr().add(state.window.offset())
    }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_len(storage: &PacketRefStorage) -> usize {
    // SAFETY: this function is only called through BORROWED_PACKET_VTABLE.
    unsafe { borrowed_state_ref(storage).window.len() }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_set_len(storage: &mut PacketRefStorage, len: PacketByteCount) -> bool {
    // SAFETY: this function is only called through BORROWED_PACKET_VTABLE.
    unsafe {
        let state = borrowed_state_mut(storage);
        state.window.set_len(len.get())
    }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_capacity(storage: &PacketRefStorage) -> usize {
    // SAFETY: this function is only called through BORROWED_PACKET_VTABLE.
    unsafe { borrowed_state_ref(storage).window.capacity() }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_headroom(storage: &PacketRefStorage) -> usize {
    // SAFETY: this function is only called through BORROWED_PACKET_VTABLE.
    unsafe { borrowed_state_ref(storage).window.offset() }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_phys_addr(storage: &PacketRefStorage) -> u64 {
    // SAFETY: this function is only called through BORROWED_PACKET_VTABLE.
    unsafe { borrowed_state_ref(storage).window.offset() as u64 }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_device_address(storage: &PacketRefStorage) -> u64 {
    // SAFETY: this function is only called through BORROWED_PACKET_VTABLE.
    unsafe { borrowed_phys_addr(storage) }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_advance(storage: &mut PacketRefStorage, size: PacketByteCount) -> bool {
    // SAFETY: this function is only called through BORROWED_PACKET_VTABLE.
    unsafe {
        let state = borrowed_state_mut(storage);
        state.window.advance(size.get())
    }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_retreat(storage: &mut PacketRefStorage, size: PacketByteCount) -> bool {
    // SAFETY: this function is only called through BORROWED_PACKET_VTABLE.
    unsafe {
        let state = borrowed_state_mut(storage);
        state.window.retreat(size.get())
    }
}
#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_drop(_: &mut PacketRefStorage) {}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_split_front(
    storage: &PacketRefStorage,
    len: PacketByteCount,
) -> Option<(PacketRefStorage, PacketRefStorage)> {
    unsafe {
        let state = *borrowed_state_ref(storage);
        let len = len.get();
        if len == 0 || len >= state.window.len() {
            return None;
        }
        let mut front = state;
        let mut remainder = state;
        if !front.window.set_len(len) || !remainder.window.advance(len) {
            return None;
        }
        Some((
            PacketRefStorage::from_state(front),
            PacketRefStorage::from_state(remainder),
        ))
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
static BORROWED_PACKET_VTABLE: PacketRefVTable = PacketRefVTable {
    data_ptr: borrowed_data_ptr,
    data_mut_ptr: borrowed_data_mut_ptr,
    len: borrowed_len,
    set_len: borrowed_set_len,
    capacity: borrowed_capacity,
    phys_addr: borrowed_phys_addr,
    device_address: borrowed_device_address,
    headroom: borrowed_headroom,
    advance: borrowed_advance,
    retreat: borrowed_retreat,
    split_front: borrowed_split_front,
    drop_storage: borrowed_drop,
};

fn new_pooled_packet_ref(buffer: NonNull<PacketBuffer>, pool: &'static Mempool) -> PacketRef {
    let window = PacketWindow::new(
        DEFAULT_BUFFER_SIZE,
        DEFAULT_PACKET_HEADROOM.min(DEFAULT_BUFFER_SIZE),
        0,
    )
    .expect("pooled packet headroom is bounded by capacity");
    let state = PooledPacketState {
        buffer,
        pool,
        window,
    };
    unsafe {
        PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &POOLED_PACKET_VTABLE)
    }
}

pub fn packet_ref_from_dma_slice(slice: TypedDmaSlice<KernelCpuOwned>) -> PacketRef {
    let headroom = DEFAULT_PACKET_HEADROOM.min(slice.len());
    packet_ref_from_dma_slice_with_headroom(slice, headroom)
        .expect("default DMA packet headroom is bounded by capacity")
}

pub fn packet_ref_from_dma_slice_with_headroom(
    slice: TypedDmaSlice<KernelCpuOwned>,
    headroom: usize,
) -> Option<PacketRef> {
    let size = slice.len();
    let window = PacketWindow::new(size, headroom, 0)?;
    let state = DmaPacketState {
        buf: NonNull::from(Box::leak(Box::new(DmaBuffer::from_typed(slice)))),
        window,
    };
    Some(unsafe {
        PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &DMA_PACKET_VTABLE)
    })
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub unsafe fn packet_ref_from_static_raw_for_tests(ptr: *mut u8, cap: usize) -> Option<PacketRef> {
    if cap == 0 {
        return None;
    }
    let state = BorrowedTestPacketState {
        ptr: NonNull::new(ptr)?,
        window: PacketWindow::new(cap, DEFAULT_PACKET_HEADROOM.min(cap), 0)?,
    };
    Some(unsafe {
        PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &BORROWED_PACKET_VTABLE)
    })
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
                    crate::cpu::CpuId::from_valid_index(index),
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
        // SECURITY: previous packet からの information leak を防ぐため buffer 全体をクリアする。
        unsafe {
            core::ptr::write_bytes(
                buffer.as_ref().data.as_ptr() as *mut u8,
                0,
                DEFAULT_BUFFER_SIZE,
            );
            buffer.as_ref().meta.ref_count.store(1, Ordering::Release);
        }
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
            ptr.as_ref().meta.ref_count.store(0, Ordering::Release);
            self.return_buffer(ptr);
        }
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

    pub fn alloc(&'static self) -> Option<PacketRef> {
        let Ok(mut cache) = self.local_cache.lock() else {
            self.parent
                .record_alloc_failure(MempoolError::LockPoisoned(MempoolLock::LocalCache));
            return None;
        };
        if let Some(buffer) = cache.pop() {
            return Some(unsafe { Mempool::init_buffer_for_alloc(buffer, self.parent) });
        }
        let refill_count = BATCH_REFILL_COUNT.min(self.cache_capacity);
        let Ok(mut free_list) = self.parent.free_list.lock() else {
            self.parent
                .record_alloc_failure(MempoolError::LockPoisoned(MempoolLock::FreeList));
            return None;
        };
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
                return Some(unsafe { Mempool::init_buffer_for_alloc(buffer, self.parent) });
            }
        }
        drop(free_list);
        self.parent.alloc().ok()
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
