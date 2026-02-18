// ============================================================================
// src/net/mempool.rs - Zero-Copy Network Buffer Pool
// 設計書 6.2: Mempool によるゼロコピーネットワークバッファ管理
// ============================================================================
#![allow(dead_code)]

use crate::domain_system::DomainId;
use crate::ipc::rref::RRef;
use crate::sync::PoisonLock;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
struct PacketBufferMeta {
    /// 使用中のデータ長
    len: AtomicUsize,
    /// 物理アドレス（DMA用）
    phys_addr: PhysAddr,
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
const DEFAULT_BUFFER_SIZE: usize =
    (DMA_PAGE_SIZE - PACKET_META_SIZE) & !(PACKET_META_ALIGN - 1);

/// パケットバッファ
/// 設計書 6.2: NICのDMAエンジンは、事前に割り当てられた固定サイズのバッファプールに直接パケットを書き込む
#[repr(C, align(4096))] // DMAページ境界にアライン
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

/// パケットバッファへの参照
/// 設計書 6.2: 所有権の連鎖
///
/// 拡張: 真のゼロコピーのために外部DMAバッファ（Virtio の vbuf）を
/// PacketRef として扱えるように `Dma` バリアントを追加します。
use alloc::sync::Arc;
use spin::Mutex as SpinMutex;
use crate::io::dma::{TypedDmaSlice, CpuOwned};

/// 内部で DMA バッファを保持するためのラッパ
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

    fn as_slice(&self) -> &[u8] {
        unsafe { crate::util::raw_ptr_as_slice(self.ptr.as_ptr(), self.size) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { crate::util::raw_ptr_as_slice_mut(self.ptr.as_ptr() as *mut u8, self.size) }
    }
}

/// PacketRef の内部バリアント
enum PacketRefKind {
    /// 既存の Mempool バッファを指す標準バリアント
    Pooled {
        buffer: NonNull<PacketBuffer>,
        pool: &'static Mempool,
        offset: usize,
        len: usize,
    },
    /// DMA バッファから構成されるゼロコピーバリアント
    Dma {
        buf: Arc<DmaBuffer>,
        offset: usize,
        len: usize,
    },
}

pub struct PacketRef {
    kind: PacketRefKind,
}

impl PacketRef {
    /// Create new PacketRef (internal) from pooled buffer
    fn new(buffer: NonNull<PacketBuffer>, pool: &'static Mempool) -> Self {
        let len = unsafe { buffer.as_ref().len() };
        Self {
            kind: PacketRefKind::Pooled {
                buffer,
                pool,
                offset: 0,
                len,
            },
        }
    }

    /// Create PacketRef from a TypedDmaSlice (zero-copy)
    pub fn from_dma_slice(slice: TypedDmaSlice<CpuOwned>) -> Self {
        let db = DmaBuffer::from_typed(slice);
        let arc = Arc::new(db);
        Self {
            kind: PacketRefKind::Dma {
                buf: arc,
                offset: 0,
                len: 0,
            },
        }
    }

    /// データスライスを取得
    pub fn data(&self) -> &[u8] {
        match &self.kind {
            PacketRefKind::Pooled { buffer, offset, len, .. } => unsafe {
                let slice = buffer.as_ref().data();
                if *offset >= slice.len() {
                    return &[];
                }
                let end = (*offset + *len).min(slice.len());
                &slice[*offset..end]
            },
            PacketRefKind::Dma { buf, offset, len } => {
                let cap = buf.size;
                if *offset >= cap {
                    return &[];
                }
                let end = (*offset + *len).min(cap);
                unsafe { crate::util::raw_ptr_as_slice(buf.ptr.as_ptr(), end - *offset) }
            }
        }
    }

    /// 可変データスライスを取得（排他的所有時のみ）
    pub fn data_mut(&mut self) -> &mut [u8] {
        match &mut self.kind {
            PacketRefKind::Pooled { buffer, offset, len, .. } => unsafe {
                let slice = buffer.as_mut().data_mut();
                if *offset >= slice.len() {
                    return &mut [];
                }
                let end = (*offset + *len).min(slice.len());
                &mut slice[*offset..end]
            },
            PacketRefKind::Dma { buf, offset, len } => {
                let cap = buf.size;
                if *offset >= cap {
                    return &mut [];
                }
                let end = (*offset + *len).min(cap);
                // SAFETY: We hold Arc to owner which keeps memory alive.
                unsafe { crate::util::raw_ptr_as_slice_mut(buf.ptr.as_ptr(), end - *offset) }
            }
        }
    }

    /// データ長を設定
    pub fn set_len(&mut self, len_val: usize) {
        match &mut self.kind {
            PacketRefKind::Pooled { len, .. } => *len = len_val,
            PacketRefKind::Dma { len, .. } => *len = len_val,
        }
    }

    /// データ長を取得
    pub fn len(&self) -> usize {
        match &self.kind {
            PacketRefKind::Pooled { len, .. } => *len,
            PacketRefKind::Dma { len, .. } => *len,
        }
    }

    /// 容量を取得
    pub fn capacity(&self) -> usize {
        match &self.kind {
            PacketRefKind::Pooled { .. } => DEFAULT_BUFFER_SIZE,
            PacketRefKind::Dma { buf, .. } => buf.size,
        }
    }

    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        match &self.kind {
            PacketRefKind::Pooled { buffer, offset, .. } => unsafe {
                buffer.as_ref().phys_addr() + *offset as u64
            },
            PacketRefKind::Dma { buf, offset, .. } => {
                let phys = buf.phys_addr;
                phys + *offset as u64
            }
        }
    }

    /// ヘッドルームを消費（オフセットを進める）
    pub fn advance(&mut self, size: usize) {
        match &mut self.kind {
            PacketRefKind::Pooled { offset, len, .. } => {
                *offset += size;
                if *len >= size {
                    *len -= size;
                } else {
                    *len = 0;
                }
            }
            PacketRefKind::Dma { offset, len, .. } => {
                *offset += size;
                if *len >= size {
                    *len -= size;
                } else {
                    *len = 0;
                }
            }
        }
    }

    /// クローン（参照カウントをインクリメント）
    pub fn clone_ref(&self) -> Self {
        match &self.kind {
            PacketRefKind::Pooled { buffer, pool, offset, len } => unsafe {
                buffer.as_ref().add_ref();
                Self {
                    kind: PacketRefKind::Pooled {
                        buffer: *buffer,
                        pool: *pool,
                        offset: *offset,
                        len: *len,
                    },
                }
            },
            PacketRefKind::Dma { buf, offset, len } => Self {
                kind: PacketRefKind::Dma {
                    buf: buf.clone(),
                    offset: *offset,
                    len: *len,
                },
            },
        }
    }

    /// Convert to RRef for zero-copy IPC
    /// Consumes the PacketRef and returns an RRef owned by target_domain.
    /// Requires exclusive access (ref_count == 1).
    /// NOTE: only supported for pooled packet refs (mempool buffers).
    pub fn into_rref(self, target_domain: DomainId) -> Result<RRef<PacketBuffer>, Self> {
        match self.kind {
            PacketRefKind::Pooled { buffer, pool: _, .. } => {
                // Reconstruct original behavior: ensure exclusive ownership
                unsafe {
                    if buffer.as_ref().meta.ref_count.load(Ordering::Acquire) != 1 {
                        return Err(self);
                    }

                    match crate::sas::transfer_ownership(
                        buffer.as_ptr() as usize,
                        crate::sas::DomainId::new(0),
                        crate::sas::DomainId::new(target_domain.as_u64()),
                    ) {
                        Ok(_) => {}
                        Err(e) => {
                            log::error!("Failed to transfer packet ownership: {:?}", e);
                            return Err(self);
                        }
                    }
                }

                // Prevent Drop from running
                core::mem::forget(self);

                unsafe { Ok(RRef::from_raw(buffer, target_domain)) }
            }
            PacketRefKind::Dma { .. } => Err(self), // Cannot convert arbitrary DMA buffer to RRef yet
        }
    }
}

impl Drop for PacketRef {
    fn drop(&mut self) {
        match &self.kind {
            PacketRefKind::Pooled { buffer, pool, .. } => unsafe {
                if buffer.as_ref().release() {
                    pool.return_buffer(*buffer);
                }
            },
            PacketRefKind::Dma { .. } => {
                // Arc drop will reclaim the TypedDmaSlice when last reference is gone
            }
        }
    }
}

// PacketRefはSend可能（別のスレッド/コアに移動可能）
unsafe impl Send for PacketRef {}

/// メモリプール
/// 設計書 6.2: バッファ管理
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
            // 初期化
            buffer.as_ref().meta.len.store(0, Ordering::Release);
            buffer.as_ref().meta.ref_count.store(1, Ordering::Release);
        }

        self.alloc_count.fetch_add(1, Ordering::Relaxed);

        Some(PacketRef::new(buffer, self))
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
            if let Err(e) =
                crate::sas::transfer_ownership(ptr.as_ptr() as usize, crate::sas::DomainId::new(owner.as_u64()), crate::sas::DomainId::new(0))
            {
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
pub struct PerCoreMempoolCache {
    /// ローカルキャッシュ
    local_cache: PoisonLock<Vec<NonNull<PacketBuffer>>>,
    /// キャッシュ容量
    cache_capacity: usize,
    /// 親プール
    parent: &'static Mempool,
}

impl PerCoreMempoolCache {
    /// 新しいキャッシュを作成
    pub fn new(parent: &'static Mempool, capacity: usize) -> Self {
        Self {
            local_cache: PoisonLock::new(Vec::with_capacity(capacity)),
            cache_capacity: capacity,
            parent,
        }
    }

    /// バッファを割り当て（ローカルキャッシュから優先）
    pub fn alloc(&'static self) -> Option<PacketRef> {
        // まずローカルキャッシュから試みる
        if let Ok(mut cache) = self.local_cache.lock() {
            if let Some(buffer) = cache.pop() {
                unsafe {
                    buffer.as_ref().meta.len.store(0, Ordering::Release);
                    buffer.as_ref().meta.ref_count.store(1, Ordering::Release);
                }
                return Some(PacketRef::new(buffer, self.parent));
            }
        } else {
            log::error!("[NET] LocalCache lock poisoned (alloc) - falling back to parent pool");
        }

        // キャッシュが空なら親プールから取得
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
pub struct PacketPool {
    /// Pre-allocated buffers
    buffers: PoisonLock<Vec<Vec<u8>>>,
    /// Buffer size
    buffer_size: usize,
    /// Pool capacity
    capacity: usize,
}
