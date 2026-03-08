// ============================================================================
// src/net/mempool.rs - Zero-Copy Network Buffer Pool
// 設計書 6.2: Mempool によるゼロコピーネットワークバッファ管理
// ============================================================================

// Building block: Memory pool types
#![allow(dead_code)]

use crate::ipc::rref::RRef;
use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
pub use kernel_api::resource::net::{PacketMeta, PacketRef, PacketType};
use kernel_api::resource::net::{PacketRefStorage, PacketRefVTable};
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
    /// 使用中のデータ長
    len: AtomicUsize,
    /// 物理アドレス（DMA用）
    phys_addr: PhysAddr,
    /// デバイスアドレス（IOMMU用）
    device_addr: u64,
    /// 所属するプールへの参照（デバッグ用）
    pool_id: u32,
    /// バッファインデックス
    index: u32,
    /// 参照カウント
    ref_count: AtomicU64,
    /// パディング（キャッシュライン境界）
    _padding: [u8; 8],
}

const PACKET_META_SIZE: usize = core::mem::size_of::<PacketBufferMeta>();
const PACKET_META_ALIGN: usize = core::mem::align_of::<PacketBufferMeta>();

/// デフォルトのパケットバッファサイズ（メタデータ込みで4Kに収める）
const DEFAULT_BUFFER_SIZE: usize = (DMA_PAGE_SIZE - PACKET_META_SIZE) & !(PACKET_META_ALIGN - 1);

/// パケットバッファ
/// 設計書 6.2: NICのDMAエンジンは、事前に割り当てられた固定サイズのバッファプールに直接パケットを書き込む
#[repr(C, align(4096))] // DMAページ境界にアライン
#[derive(Debug)]
pub struct PacketBuffer {
    /// データ領域
    data: [u8; DEFAULT_BUFFER_SIZE],
    /// メタデータ
    meta: PacketBufferMeta,
}

impl PacketBuffer {
    /// データスライスを取得
    pub fn data(&self) -> &[u8] {
        let len = self.meta.len.load(Ordering::Acquire);
        &self.data[..len]
    }

    /// 可変データスライスを取得
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.meta.len.load(Ordering::Acquire);
        &mut self.data[..len]
    }

    /// 生データポインタを取得
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    /// 可変生データポインタを取得
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// データ長を取得
    pub fn len(&self) -> usize {
        self.meta.len.load(Ordering::Acquire)
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// データ長を設定
    pub fn set_len(&self, len: usize) {
        self.meta
            .len
            .store(len.min(DEFAULT_BUFFER_SIZE), Ordering::Release);
    }

    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        self.meta.phys_addr
    }

    /// デバイスアドレスを取得（IOMMU用）
    pub fn device_address(&self) -> u64 {
        if self.meta.device_addr != 0 {
            self.meta.device_addr
        } else {
            self.meta.phys_addr.as_u64()
        }
    }

    /// デバイスアドレスを設定（IOMMU用）
    pub fn set_device_address(&mut self, addr: u64) {
        self.meta.device_addr = addr;
    }

    /// 参照カウントをインクリメント
    pub fn add_ref(&self) {
        self.meta.ref_count.fetch_add(1, Ordering::Relaxed);
    }

    /// 参照カウントをデクリメント
    /// 0になったらtrueを返す
    pub fn release(&self) -> bool {
        self.meta.ref_count.fetch_sub(1, Ordering::Release) == 1
    }
}

use crate::io::dma::{CpuOwned, TypedDmaSlice};
use alloc::sync::Arc;
use spin::Mutex as SpinMutex;

/// 内部で DMA バッファを保持するためのラッパ
#[derive(Debug)]
struct DmaBuffer {
    pub(super) ptr: NonNull<u8>,
    pub(super) phys_addr: PhysAddr,
    pub(super) size: usize,
    /// 所有権を保持する (TypedDmaSlice を保持することでメモリ寿命を延ばす)
    owner: Arc<SpinMutex<TypedDmaSlice<CpuOwned>>>,
}

impl DmaBuffer {
    fn from_typed(slice: TypedDmaSlice<CpuOwned>) -> Self {
        let size = slice.len();
        let phys = slice.phys_addr();
        // Get raw pointer before moving into Arc
        let ptr = slice.as_slice().as_ptr() as *mut u8;
        let owner = Arc::new(SpinMutex::new(slice));
        Self {
            ptr: NonNull::new(ptr).expect("TypedDmaSlice returned null pointer"),
            phys_addr: phys,
            size,
            owner,
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
    unsafe { storage.as_state_ref::<PooledPacketState>() }
}

unsafe fn pooled_state_mut(storage: &mut PacketRefStorage) -> &mut PooledPacketState {
    unsafe { storage.as_state_mut::<PooledPacketState>() }
}

unsafe fn pooled_data_ptr(storage: &PacketRefStorage) -> *const u8 {
    let state = unsafe { pooled_state_ref(storage) };
    unsafe { state.buffer.as_ref().as_ptr().add(state.offset) }
}

unsafe fn pooled_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
    let state = unsafe { pooled_state_mut(storage) };
    unsafe { (*state.buffer.as_ptr()).as_mut_ptr().add(state.offset) }
}

unsafe fn pooled_len(storage: &PacketRefStorage) -> usize {
    unsafe { pooled_state_ref(storage) }.len
}

unsafe fn pooled_set_len(storage: &mut PacketRefStorage, len: usize) {
    let state = unsafe { pooled_state_mut(storage) };
    let new_len = len.min(DEFAULT_BUFFER_SIZE.saturating_sub(state.offset));
    state.len = new_len;
    unsafe { state.buffer.as_ref().set_len(new_len) };
}

unsafe fn pooled_capacity(_: &PacketRefStorage) -> usize {
    DEFAULT_BUFFER_SIZE
}

unsafe fn pooled_phys_addr(storage: &PacketRefStorage) -> u64 {
    let state = unsafe { pooled_state_ref(storage) };
    unsafe { state.buffer.as_ref().phys_addr().as_u64() + state.offset as u64 }
}

unsafe fn pooled_device_address(storage: &PacketRefStorage) -> u64 {
    let state = unsafe { pooled_state_ref(storage) };
    unsafe { state.buffer.as_ref().device_address() + state.offset as u64 }
}

unsafe fn pooled_advance(storage: &mut PacketRefStorage, size: usize) {
    let state = unsafe { pooled_state_mut(storage) };
    state.offset = state.offset.saturating_add(size).min(DEFAULT_BUFFER_SIZE);
    state.len = state.len.saturating_sub(size);
}

unsafe fn pooled_clone(storage: &PacketRefStorage) -> PacketRefStorage {
    let state = unsafe { pooled_state_ref(storage) };
    unsafe { state.buffer.as_ref().add_ref() };
    unsafe { PacketRefStorage::from_state(*state) }
}

unsafe fn pooled_drop(storage: &mut PacketRefStorage) {
    let state = unsafe { pooled_state_mut(storage) };
    unsafe {
        if state.buffer.as_ref().release() {
            state.pool.return_buffer(state.buffer);
        }
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
    unsafe { storage.as_state_ref::<DmaPacketState>() }
}

unsafe fn dma_state_mut(storage: &mut PacketRefStorage) -> &mut DmaPacketState {
    unsafe { storage.as_state_mut::<DmaPacketState>() }
}

unsafe fn dma_data_ptr(storage: &PacketRefStorage) -> *const u8 {
    let state = unsafe { dma_state_ref(storage) };
    unsafe { state.buf.ptr.as_ptr().add(state.offset) }
}

unsafe fn dma_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
    let state = unsafe { dma_state_mut(storage) };
    unsafe { state.buf.ptr.as_ptr().add(state.offset) }
}

unsafe fn dma_len(storage: &PacketRefStorage) -> usize {
    unsafe { dma_state_ref(storage) }.len
}

unsafe fn dma_set_len(storage: &mut PacketRefStorage, len: usize) {
    let state = unsafe { dma_state_mut(storage) };
    state.len = len.min(state.buf.size.saturating_sub(state.offset));
}

unsafe fn dma_capacity(storage: &PacketRefStorage) -> usize {
    unsafe { dma_state_ref(storage) }.buf.size
}

unsafe fn dma_phys_addr(storage: &PacketRefStorage) -> u64 {
    let state = unsafe { dma_state_ref(storage) };
    state.buf.phys_addr.as_u64() + state.offset as u64
}

unsafe fn dma_device_address(storage: &PacketRefStorage) -> u64 {
    unsafe { dma_phys_addr(storage) }
}

unsafe fn dma_advance(storage: &mut PacketRefStorage, size: usize) {
    let state = unsafe { dma_state_mut(storage) };
    state.offset = state.offset.saturating_add(size).min(state.buf.size);
    state.len = state.len.saturating_sub(size);
}

unsafe fn dma_clone(storage: &PacketRefStorage) -> PacketRefStorage {
    let state = unsafe { dma_state_ref(storage) };
    unsafe { PacketRefStorage::from_state(state.clone()) }
}

unsafe fn dma_drop(storage: &mut PacketRefStorage) {
    unsafe { core::ptr::drop_in_place(storage.as_state_mut::<DmaPacketState>()) };
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
    unsafe { storage.as_state_ref::<BorrowedTestPacketState>() }
}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_state_mut(storage: &mut PacketRefStorage) -> &mut BorrowedTestPacketState {
    unsafe { storage.as_state_mut::<BorrowedTestPacketState>() }
}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_data_ptr(storage: &PacketRefStorage) -> *const u8 {
    let state = unsafe { borrowed_state_ref(storage) };
    unsafe { state.ptr.as_ptr().add(state.offset) }
}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
    let state = unsafe { borrowed_state_mut(storage) };
    unsafe { state.ptr.as_ptr().add(state.offset) }
}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_len(storage: &PacketRefStorage) -> usize {
    unsafe { borrowed_state_ref(storage) }.len
}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_set_len(storage: &mut PacketRefStorage, len: usize) {
    let state = unsafe { borrowed_state_mut(storage) };
    state.len = len.min(state.cap.saturating_sub(state.offset));
}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_capacity(storage: &PacketRefStorage) -> usize {
    unsafe { borrowed_state_ref(storage) }.cap
}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_phys_addr(storage: &PacketRefStorage) -> u64 {
    unsafe { borrowed_state_ref(storage) }.offset as u64
}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_device_address(storage: &PacketRefStorage) -> u64 {
    unsafe { borrowed_phys_addr(storage) }
}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_advance(storage: &mut PacketRefStorage, size: usize) {
    let state = unsafe { borrowed_state_mut(storage) };
    state.offset = state.offset.saturating_add(size).min(state.cap);
    state.len = state.len.saturating_sub(size);
}

#[cfg(any(test, feature = "qemu-test-export"))]
unsafe fn borrowed_clone(storage: &PacketRefStorage) -> PacketRefStorage {
    let state = unsafe { borrowed_state_ref(storage) };
    unsafe { PacketRefStorage::from_state(*state) }
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

pub fn packet_ref_from_dma_slice(slice: TypedDmaSlice<CpuOwned>) -> PacketRef {
    let state = DmaPacketState {
        buf: Arc::new(DmaBuffer::from_typed(slice)),
        offset: 0,
        len: 0,
    };

    unsafe { PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &DMA_PACKET_VTABLE) }
}

/// Construct a `PacketRef` borrowing caller-managed storage (no allocation).
///
/// # Safety
/// Caller must ensure `ptr..ptr+cap` remains valid and uniquely mutable for the
/// lifetime of the returned `PacketRef` and any clones created from it.
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

/// メモリプール
/// 設計書 6.2: バッファ管理
#[derive(Debug)]
pub struct Mempool {
    /// プールID
    id: u32,
    /// バッファストレージ
    buffers: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    /// 空きバッファリスト
    free_list: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    /// 統計: 割り当て回数
    alloc_count: AtomicU64,
    /// 統計: 返却回数
    free_count: AtomicU64,
    /// 統計: 割り当て失敗回数
    alloc_failed: AtomicU64,
}

// MempoolはSend + Sync可能（NonNullはスレッドセーフに管理される）
unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}

impl Mempool {
    /// 新しいメモリプールを作成
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

    /// プールを初期化（バッファを事前割り当て）
    pub fn init(&self, capacity: usize) -> Result<(), &'static str> {
        debug_assert_eq!(core::mem::size_of::<PacketBuffer>(), DMA_PAGE_SIZE);
        debug_assert_eq!(core::mem::align_of::<PacketBuffer>(), DMA_PAGE_SIZE);

        let mut buffers = match self.buffers.lock() {
            Ok(b) => b,
            Err(_) => {
                log::error!("[NET] Mempool buffers poisoned during init");
                return Err("Mempool buffers poisoned");
            }
        };

        let mut free_list = match self.free_list.lock() {
            Ok(f) => f,
            Err(_) => {
                log::error!("[NET] Mempool free_list poisoned during init");
                return Err("Mempool free_list poisoned");
            }
        };

        for i in 0..capacity {
            // バッファを割り当て (Exchange Heap for RRef compatibility)
            let layout = alloc::alloc::Layout::new::<PacketBuffer>();
            let nn = crate::mm::cache::exchange_heap::allocate_raw(layout)
                .ok_or("Failed to allocate buffer")?;
            let non_null = nn.cast::<PacketBuffer>();

            // Heap Registryに登録（Kernel所有として）
            crate::sas::register_object(
                non_null.as_ptr() as usize,
                layout.size(),
                crate::sas::DomainId::new(0),
            );

            // バッファを初期化
            unsafe {
                let buffer_ptr = non_null.as_ptr();
                (*buffer_ptr).meta.pool_id = self.id;
                (*buffer_ptr).meta.index = i as u32;
                (*buffer_ptr).meta.len = AtomicUsize::new(0);
                (*buffer_ptr).meta.ref_count = AtomicU64::new(0);
                // 仮想アドレスから物理アドレスへ変換
                // カーネルヒープはリニアマッピングされているため、
                // HigherHalfのオフセットを引くことで物理アドレスを得る
                let virt_addr = buffer_ptr as u64;
                let offset = crate::mm::virt::mapping::physical_memory_offset();
                let phys = if virt_addr >= offset {
                    virt_addr - offset
                } else {
                    // オフセット未満の場合はそのままとする
                    // （カーネルイメージ内のアドレスなど）
                    virt_addr
                };
                (*buffer_ptr).meta.phys_addr = PhysAddr::new(phys);
            }

            buffers.push(non_null);
            free_list.push(non_null);
        }

        Ok(())
    }

    /// バッファを割り当て
    pub fn alloc(&'static self) -> Option<PacketRef> {
        let buffer = match self.free_list.lock() {
            Ok(mut free_list) => free_list.pop(),
            Err(_) => {
                log::error!("[NET] Mempool free_list poisoned - allocation failed");
                self.alloc_failed.fetch_add(1, Ordering::Relaxed);
                None
            }
        }?;

        unsafe {
            // Security: Zero-out previously used portion to prevent Information
            // Disclosure from previous packets (RFC 4963, RFC 6274).
            // Optimization: only clear the range that was actually written
            // (tracked by meta.len) instead of the entire buffer.
            let prev_len = buffer.as_ref().meta.len.load(Ordering::Acquire);
            if prev_len > 0 {
                core::ptr::write_bytes(
                    buffer.as_ref().data.as_ptr() as *mut u8,
                    0,
                    prev_len.min(DEFAULT_BUFFER_SIZE),
                );
            }

            // 初期化
            buffer.as_ref().meta.len.store(0, Ordering::Release);
            buffer.as_ref().meta.ref_count.store(1, Ordering::Release);
        }

        self.alloc_count.fetch_add(1, Ordering::Relaxed);

        Some(new_pooled_packet_ref(buffer, self))
    }

    /// バッファを返却
    fn return_buffer(&self, buffer: NonNull<PacketBuffer>) {
        match self.free_list.lock() {
            Ok(mut free_list) => free_list.push(buffer),
            Err(_) => {
                log::error!("[NET] Mempool free_list poisoned - return ignored");
                return;
            }
        }
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Return an RRef to the pool (recycling)
    /// Converts RRef back to a free buffer.
    pub fn return_rref(&self, rref: RRef<PacketBuffer>) {
        let (ptr, owner) = rref.into_raw();

        unsafe {
            // Transfer ownership back to Kernel(0)
            if let Err(e) = crate::sas::transfer_ownership(
                ptr.as_ptr() as usize,
                crate::sas::DomainId::new(owner.as_u64()),
                crate::sas::DomainId::new(0),
            ) {
                log::error!("Failed to reclaim RRef ownership: {:?}", e);
                // Do not reuse potentially corrupted buffer
                return;
            }

            // Reset state
            ptr.as_ref().meta.len.store(0, Ordering::Release);
            ptr.as_ref().meta.ref_count.store(0, Ordering::Release);

            self.return_buffer(ptr);
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> MempoolStats {
        let total = match self.buffers.lock() {
            Ok(b) => b.len(),
            Err(_) => {
                log::error!("[NET] Mempool buffers poisoned - returning zeros");
                0
            }
        };

        let free = match self.free_list.lock() {
            Ok(f) => f.len(),
            Err(_) => {
                log::error!("[NET] Mempool free_list poisoned - returning zeros");
                0
            }
        };

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

/// メモリプール統計
#[derive(Debug, Clone)]
pub struct MempoolStats {
    pub total_buffers: usize,
    pub free_buffers: usize,
    pub used_buffers: usize,
    pub alloc_count: u64,
    pub free_count: u64,
    pub alloc_failed: u64,
}

// ============================================================================
// Per-Core Mempool Cache
// ============================================================================

/// コアローカルなメモリプールキャッシュ
/// 設計書 4.3: コアごとの独立性
///
/// 最適化: キャッシュが空のとき、親プールから `BATCH_REFILL_COUNT` 個を
/// 一括で取得し、ロック取得回数を償却する。
#[derive(Debug)]
pub struct PerCoreMempoolCache {
    /// ローカルキャッシュ
    local_cache: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    /// キャッシュ容量
    cache_capacity: usize,
    /// 親プール
    parent: &'static Mempool,
}

/// バッチリフィル時に親プールから一度に取得するバッファ数
const BATCH_REFILL_COUNT: usize = 16;

impl PerCoreMempoolCache {
    /// 新しいキャッシュを作成
    pub fn new(parent: &'static Mempool, capacity: usize) -> Self {
        Self {
            local_cache: PoisonLock::new(Vec::with_capacity(capacity)),
            cache_capacity: capacity,
            parent,
        }
    }

    /// ローカルバッファを初期化して PacketRef を返す
    #[inline]
    unsafe fn init_buffer_for_alloc(
        buffer: NonNull<PacketBuffer>,
        pool: &'static Mempool,
    ) -> PacketRef {
        // Security: Zero-out previously used portion to prevent
        // Information Disclosure (RFC 4963, RFC 6274).
        let prev_len = buffer.as_ref().meta.len.load(Ordering::Acquire);
        if prev_len > 0 {
            core::ptr::write_bytes(
                buffer.as_ref().data.as_ptr() as *mut u8,
                0,
                prev_len.min(DEFAULT_BUFFER_SIZE),
            );
        }

        buffer.as_ref().meta.len.store(0, Ordering::Release);
        buffer.as_ref().meta.ref_count.store(1, Ordering::Release);
        new_pooled_packet_ref(buffer, pool)
    }

    /// バッファを割り当て（ローカルキャッシュから優先）
    ///
    /// キャッシュが空の場合、親プールから最大 `BATCH_REFILL_COUNT` 個を
    /// 一括取得してキャッシュを補充し、ロック取得コストを償却する。
    pub fn alloc(&'static self) -> Option<PacketRef> {
        // まずローカルキャッシュから試みる
        if let Ok(mut cache) = self.local_cache.lock() {
            if let Some(buffer) = cache.pop() {
                return Some(unsafe { Self::init_buffer_for_alloc(buffer, self.parent) });
            }

            // キャッシュが空 → 親プールからバッチリフィル
            let refill_count = BATCH_REFILL_COUNT.min(self.cache_capacity);
            if let Ok(mut free_list) = self.parent.free_list.lock() {
                let available = free_list.len().min(refill_count);
                if available > 0 {
                    // 末尾から一括取得（Vec::split_off は O(n) だが n は小さい）
                    let split_at = free_list.len() - available;
                    let refilled: Vec<NonNull<PacketBuffer>> = free_list.split_off(split_at);
                    // 最初の1つを返却用、残りをキャッシュに積む
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
            }
        } else {
            log::error!("[NET] LocalCache lock poisoned (alloc) - falling back to parent pool");
        }

        // フォールバック: 親プールの通常 alloc
        self.parent.alloc()
    }

    /// バッファを返却（ローカルキャッシュに優先）
    pub fn free(&self, buffer: NonNull<PacketBuffer>) {
        match self.local_cache.lock() {
            Ok(mut cache) => {
                if cache.len() < self.cache_capacity {
                    // ローカルキャッシュに空きがあれば追加
                    cache.push(buffer);
                    return;
                }
                // キャッシュが満杯なら親プールに返却
            }
            Err(_) => {
                log::error!("[NET] LocalCache lock poisoned (free) - returning to parent pool");
                self.parent.return_buffer(buffer);
                return;
            }
        }

        self.parent.return_buffer(buffer);
    }
}

// ============================================================================
// PacketPool - Simple packet buffer pool for transmit
// ============================================================================

/// Simple packet pool for transmit buffers
/// Used by the network stack for building outgoing packets
#[derive(Debug)]
pub struct PacketPool {
    /// Pre-allocated buffers
    buffers: PoisonLock<Vec<Vec<u8>>>,
    /// Buffer size
    buffer_size: usize,
    /// Pool capacity
    capacity: usize,
}
