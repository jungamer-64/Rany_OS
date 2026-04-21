// ============================================================================
// kernel/src/net/datapath/zero_copy/mod.rs - Zero-Copy Network Stack
// ============================================================================
//!
//! # ゼロコピーネットワークスタック
//!
//! 設計書6.2に基づく真のゼロコピーネットワーク通信の実装。
//! パケットの所有権をNICドライバからアプリケーションまで
//! コピーなしで移動させる。
//!
//! ## 機能
//! - ゼロコピーパケットバッファ管理
//! - 所有権ベースのバッファライフサイクル
//! - メモリプール管理
//! - 散布/収集I/O（Scatter-Gather）
//! - DMA対応バッファアライメント

// Building block: Zero-copy buffer types
#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Deref;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};
use crate::sync::{LockFreeIndexStack, MpmcRingBuffer};

// ============================================================================
// Configuration
// ============================================================================

/// デフォルトのバッファサイズ
mod send_future;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
const DEFAULT_BUFFER_SIZE: usize = 2048;

/// DMAアライメント要件
const DMA_ALIGNMENT: usize = 64;

/// 最大MTU
const MAX_MTU: usize = 9000; // Jumbo frames

/// バッファヘッドルーム（プロトコルヘッダ用）
const BUFFER_HEADROOM: usize = 128;

/// バッファテールルーム
const BUFFER_TAILROOM: usize = 64;

/// Per-CPU ローカルフリーキャッシュ容量
const LOCAL_FREE_CACHE_CAPACITY: usize = 64;
/// 一度にローカルキャッシュに補充するエントリ数
const LOCAL_FREE_REFILL_BATCH: usize = 16;
/// ローカルキャッシュが飽和した際にグローバルへ移すエントリ数
const LOCAL_FREE_SPILL_BATCH: usize = 16;

// ============================================================================
// Buffer Pool
// ============================================================================

/// バッファプールID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PoolId(u32);

impl PoolId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// バッファプール統計
#[derive(Debug, Default)]
pub struct PoolStats {
    /// 割り当て回数
    pub allocations: AtomicU64,
    /// 解放回数
    pub frees: AtomicU64,
    /// 割り当て失敗回数
    pub alloc_failures: AtomicU64,
    /// 現在使用中のバッファ数
    pub in_use: AtomicUsize,
    /// プール総バッファ数
    pub total: AtomicUsize,
}

/// ZeroCopyBuffer 操作エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroCopyError {
    /// 共有中のバッファに対して可変アクセスを要求した
    SharedMutationDenied,
    /// 範囲外アクセス
    OutOfBounds,
    /// 参照カウントが上限に達した
    RefcountOverflow,
}

struct BufferSlot {
    /// バッファ実体（DropでDMAメモリを解放）
    _dma: CoherentDmaBuffer,
    /// CPU仮想アドレスのベース
    base_ptr: NonNull<u8>,
    /// デバイスDMAアドレス (translated hardware-visible DMA address)
    device_base_addr: u64,
    /// ペイロード容量（headroom/tailroom除く）
    payload_capacity: usize,
    /// スロット共有参照カウント
    ref_count: AtomicU64,
}

// `CoherentDmaBuffer` は `Send` のみだが、ここでは初期化後に `base_ptr`/`device_base_addr`
// の読み取りと `ref_count` の原子的更新だけを共有し、DMAバッファ本体の可変操作は行わない。
unsafe impl Sync for BufferSlot {}

// Per-CPU local free cache. The hot path is lock-free (`MpmcRingBuffer`).
struct PerCpuCache {
    ring: MpmcRingBuffer<u32, LOCAL_FREE_CACHE_CAPACITY>,
}

impl PerCpuCache {
    const CAPACITY: usize = LOCAL_FREE_CACHE_CAPACITY;

    fn new() -> Self {
        Self {
            ring: MpmcRingBuffer::new(),
        }
    }

    /// Try to pop one index from the local cache.
    fn try_pop(&self) -> Option<u32> {
        self.ring.try_pop()
    }

    /// Push an index into the local cache. Returns `Err(idx)` if the cache is
    /// full or if `try_push` loses a race.
    fn try_push(&self, idx: u32) -> Result<(), u32> {
        self.ring.try_push(idx)?;
        Ok(())
    }

    /// Move up to `LOCAL_FREE_REFILL_BATCH` entries from the global pool into the
    /// local cache.  Called by `alloc_slot_index` when the local cache is empty.
    fn refill_from_global(&self, global: &LockFreeIndexStack) {
        for _ in 0..LOCAL_FREE_REFILL_BATCH {
            let Some(idx) = global.pop() else {
                break;
            };
            if let Err(idx) = self.try_push(idx) {
                if let Err(err) = global.push(idx) {
                    log::error!(
                        "[NET] zero_copy refill failed to return slot {} to global free-list: {:?}",
                        idx,
                        err
                    );
                    debug_assert!(false, "zero_copy refill return-to-global failed");
                }
                break;
            }
        }
    }

    /// Spill a few entries back to the global pool when the local cache is
    /// excessively full.  Keeps the global list from starving other CPUs.
    fn spill_to_global(&self, global: &LockFreeIndexStack) {
        for _ in 0..LOCAL_FREE_SPILL_BATCH {
            let Some(idx) = self.try_pop() else {
                break;
            };
            if let Err(err) = global.push(idx) {
                log::error!(
                    "[NET] zero_copy spill failed to push slot {} to global free-list: {:?}",
                    idx,
                    err
                );
                debug_assert!(false, "zero_copy spill push-to-global failed");
                // Best effort: avoid leaking the index if the global push fails.
                let _ = self.try_push(idx);
                break;
            }
        }
    }

    fn len(&self) -> usize {
        self.ring.len()
    }

    fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }
}

struct MemoryPoolInner {
    id: PoolId,
    slots: Vec<BufferSlot>,
    global_free: LockFreeIndexStack,
    per_cpu: Vec<PerCpuCache>,
    stats: PoolStats,
}

impl MemoryPoolInner {
    #[inline]
    fn current_cpu_cache(&self) -> Option<&PerCpuCache> {
        if self.per_cpu.is_empty() {
            return None;
        }

        let cpu_id = crate::cpu::try_current_id().unwrap_or(0);
        if cpu_id < self.per_cpu.len() {
            return Some(&self.per_cpu[cpu_id]);
        }

        debug_assert!(
            false,
            "zero_copy current cpu id {} out of range for per_cpu cache len {}",
            cpu_id,
            self.per_cpu.len()
        );
        self.per_cpu.get(0)
    }

    fn alloc_slot_index(&self) -> Option<u32> {
        // try local cache first
        if let Some(cache) = self.current_cpu_cache() {
            if let Some(idx) = cache.try_pop() {
                return Some(idx);
            }

            // nothing locally, refill a batch and try again
            cache.refill_from_global(&self.global_free);
            if let Some(idx) = cache.try_pop() {
                return Some(idx);
            }
        }

        // fall back to global list
        self.global_free.pop()
    }

    fn return_slot_index(&self, idx: u32) {
        if let Some(cache) = self.current_cpu_cache() {
            if cache.try_push(idx).is_ok() {
                return;
            }

            cache.spill_to_global(&self.global_free);

            if cache.try_push(idx).is_ok() {
                return;
            }
        }

        if let Err(err) = self.global_free.push(idx) {
            log::error!(
                "[NET] zero_copy return_slot_index failed to push slot {} to global free-list: {:?}",
                idx,
                err
            );
            debug_assert!(false, "zero_copy return_slot_index global push failed");
        }
    }

    fn available(&self) -> usize {
        let mut tot = self.global_free.len();
        for cache in &self.per_cpu {
            tot += cache.len();
        }
        tot
    }

    fn slot(&self, slot_idx: u32) -> &BufferSlot {
        &self.slots[slot_idx as usize]
    }
}

/// メモリプール（事前割り当てバッファのプール）
///
/// DMA-safe なバッファをプールし、ゼロコピーネットワーク I/O を実現する。
/// 各バッファは `CoherentDmaBuffer` で割り当てられ、正しい物理/デバイスアドレス
/// が保証される。
pub struct MemoryPool {
    inner: Arc<MemoryPoolInner>,
}

unsafe impl Send for MemoryPool {}
unsafe impl Sync for MemoryPool {}

impl MemoryPool {
    /// 新しいメモリプールを作成
    pub fn new(id: PoolId, buffer_size: usize, count: usize) -> Self {
        let aligned_size = (buffer_size + DMA_ALIGNMENT - 1) & !(DMA_ALIGNMENT - 1);
        let total_size = aligned_size + BUFFER_HEADROOM + BUFFER_TAILROOM;

        let mut slots = Vec::with_capacity(count);

        // バッファを事前割り当て (CoherentDmaBuffer経由で正しい物理アドレスを取得)
        for _ in 0..count {
            if let Some(buf) = CoherentDmaBuffer::new(total_size, DmaMemoryAttributes::MMIO) {
                let virt_ptr = unsafe { buf.as_slice().as_ptr() } as *mut u8;
                let dev_addr = buf.device_addr();
                if let Some(nn) = NonNull::new(virt_ptr) {
                    slots.push(BufferSlot {
                        _dma: buf,
                        base_ptr: nn,
                        device_base_addr: dev_addr,
                        payload_capacity: aligned_size,
                        ref_count: AtomicU64::new(0),
                    });
                }
            }
        }

        assert!(
            slots.len() <= u32::MAX as usize,
            "zero_copy MemoryPool slots exceed u32::MAX"
        );

        let global_free = LockFreeIndexStack::new_filled(slots.len());

        // Create a cache for every logical CPU slot to avoid aliasing when APs
        // come online after the pool is created.
        let cpu_count = crate::per_cpu::MAX_CPUS;
        let mut per_cpu = Vec::with_capacity(cpu_count);
        for _ in 0..cpu_count {
            per_cpu.push(PerCpuCache::new());
        }

        let inner = Arc::new(MemoryPoolInner {
            id,
            slots,
            global_free,
            per_cpu,
            stats: PoolStats::default(),
        });
        inner
            .stats
            .total
            .store(inner.slots.len(), Ordering::Release);
        Self { inner }
    }

    /// バッファを割り当て
    pub fn alloc(&self) -> Option<ZeroCopyBuffer> {
        let Some(slot_idx) = self.inner.alloc_slot_index() else {
            self.inner
                .stats
                .alloc_failures
                .fetch_add(1, Ordering::Relaxed);
            return None;
        };

        let slot = self.inner.slot(slot_idx);
        match slot
            .ref_count
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(prev) => {
                log::error!(
                    "[NET] zero_copy alloc got busy slot {} (ref_count={})",
                    slot_idx,
                    prev
                );
                self.inner.return_slot_index(slot_idx);
                self.inner
                    .stats
                    .alloc_failures
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }

        self.inner.stats.allocations.fetch_add(1, Ordering::Relaxed);
        self.inner.stats.in_use.fetch_add(1, Ordering::Relaxed);

        Some(ZeroCopyBuffer {
            pool: self.inner.clone(),
            slot_idx,
            segment_start: 0,
            segment_capacity: slot.payload_capacity,
            headroom: BUFFER_HEADROOM,
            len: 0,
        })
    }

    /// バッファを解放
    pub fn free(&self, buffer: ZeroCopyBuffer) {
        drop(buffer);
    }

    /// プールIDを取得
    pub fn id(&self) -> PoolId {
        self.inner.id
    }

    /// 統計を取得
    pub fn stats(&self) -> &PoolStats {
        &self.inner.stats
    }

    /// 空きバッファ数を取得（並行操作中は概算値、静止時は正確）
    pub fn available(&self) -> usize {
        self.inner.available()
    }

    // --- test helpers ----------------------------------------------------
    #[cfg(any(test, feature = "qemu-test-export"))]
    pub fn local_cache_len(&self, cpu: usize) -> usize {
        if cpu < self.inner.per_cpu.len() {
            self.inner.per_cpu[cpu].len()
        } else {
            0
        }
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub fn global_cache_len(&self) -> usize {
        self.inner.global_free.len()
    }
}

// ============================================================================
// Zero-Copy Buffer
// ============================================================================

/// ゼロコピーバッファ
pub struct ZeroCopyBuffer {
    /// 親メモリプール（スロット寿命を保持）
    pool: Arc<MemoryPoolInner>,
    /// スロットID
    slot_idx: u32,
    /// スロットベースから見た、このビューの開始位置
    segment_start: usize,
    /// 現在のデータ長
    len: usize,
    /// バッファ容量（このビューの最大データ長）
    segment_capacity: usize,
    /// ヘッドルームオフセット
    headroom: usize,
}

unsafe impl Send for ZeroCopyBuffer {}
unsafe impl Sync for ZeroCopyBuffer {}

impl ZeroCopyBuffer {
    fn slot(&self) -> &BufferSlot {
        self.pool.slot(self.slot_idx)
    }

    fn data_offset(&self) -> usize {
        self.segment_start + self.headroom
    }

    fn try_add_shared_ref(&self) -> Result<(), ZeroCopyError> {
        let slot = self.slot();
        let mut current = slot.ref_count.load(Ordering::Acquire);
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            if current == u64::MAX {
                return Err(ZeroCopyError::RefcountOverflow);
            }
            match slot.ref_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    /// データスライスを取得
    pub fn as_slice(&self) -> &[u8] {
        let slot = self.slot();
        unsafe { crate::util::nonnull_ptr_as_slice(slot.base_ptr, self.data_offset(), self.len) }
    }

    /// データスライスを取得（可変、排他的所有時のみ）
    pub fn try_as_mut_slice(&mut self) -> Result<&mut [u8], ZeroCopyError> {
        let slot = self.slot();
        if slot.ref_count.load(Ordering::Acquire) != 1 {
            return Err(ZeroCopyError::SharedMutationDenied);
        }
        Ok(unsafe {
            crate::util::nonnull_ptr_as_slice_mut(slot.base_ptr, self.data_offset(), self.len)
        })
    }

    /// データスライスを取得（可変）
    ///
    /// 共有参照がある状態で呼び出すと panic する。
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.try_as_mut_slice()
            .expect("ZeroCopyBuffer::as_mut_slice requires unique ownership")
    }

    /// データを取得
    pub fn data(&self) -> &[u8] {
        self.as_slice()
    }

    /// 可変データを取得（排他的所有時のみ）
    pub fn data_mut(&mut self) -> Result<&mut [u8], ZeroCopyError> {
        self.try_as_mut_slice()
    }

    /// データを書き込む（必要に応じて長さを更新）
    pub fn write(&mut self, data: &[u8]) -> usize {
        if self.slot().ref_count.load(Ordering::Acquire) != 1 {
            return 0;
        }

        self.set_len(data.len());
        let len = self.len;
        if len == 0 {
            return 0;
        }
        let dst = self
            .try_as_mut_slice()
            .expect("unique ref_count checked above for ZeroCopyBuffer::write");
        dst[..len].copy_from_slice(&data[..len]);
        len
    }

    /// データ長を取得
    pub fn len(&self) -> usize {
        self.len
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 容量を取得
    pub fn capacity(&self) -> usize {
        self.segment_capacity
    }

    /// データ長を設定
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(self.segment_capacity);
    }

    /// ヘッドルームを予約（プロトコルヘッダ追加用）
    /// ヘッドルームを予約（プロトコルヘッダ追加用）
    ///
    /// 以前の実装は `len` を増やしていたため、ペイロード容量が
    /// 一杯の状態では常にエラーが返っていた。 予約はデータを書き込む
    /// 前の操作であり、`len` はヘッダが実際に書き込まれたときにのみ
    /// 増加させるべきである。
    pub fn reserve_headroom(&mut self, size: usize) -> Result<(), &'static str> {
        if self.headroom < size {
            return Err("Insufficient headroom");
        }
        let Some(new_capacity) = self.segment_capacity.checked_add(size) else {
            return Err("Out of bounds");
        };

        // Preserve the segment tail boundary while moving the data pointer
        // backwards into available headroom.
        self.headroom -= size;
        self.segment_capacity = new_capacity;
        Ok(())
    }

    /// ヘッドルームを消費（ヘッダ削除用）
    pub fn consume_headroom(&mut self, size: usize) -> Result<(), &'static str> {
        if self.len < size {
            return Err("Insufficient data");
        }
        if self.segment_capacity < size {
            return Err("Out of bounds");
        }

        // Keep the segment tail boundary unchanged while stripping bytes from
        // the front; otherwise subsequent `set_len` could extend beyond the
        // original slot span.
        self.headroom += size;
        self.len -= size;
        self.segment_capacity -= size;
        Ok(())
    }

    /// DMAアドレスを取得（ヘッドルームオフセット適用済み）
    ///
    /// translated DMA マッピング済みの device-visible address を返す。
    pub fn dma_addr(&self) -> u64 {
        self.slot().device_base_addr + self.data_offset() as u64
    }

    /// プールIDを取得
    pub fn pool_id(&self) -> PoolId {
        self.pool.id
    }

    /// 参照を追加
    pub fn clone_ref(&self) -> Self {
        self.try_add_shared_ref()
            .expect("ZeroCopyBuffer::clone_ref refcount overflow");
        Self {
            pool: self.pool.clone(),
            slot_idx: self.slot_idx,
            segment_start: self.segment_start,
            len: self.len,
            segment_capacity: self.segment_capacity,
            headroom: self.headroom,
        }
    }

    /// 分割（ゼロコピーでスライス）
    pub fn split_at(&mut self, mid: usize) -> Option<ZeroCopyBuffer> {
        if mid > self.len {
            return None;
        }
        self.try_add_shared_ref().ok()?;

        let second_half = Self {
            pool: self.pool.clone(),
            slot_idx: self.slot_idx,
            segment_start: self.segment_start + self.headroom + mid,
            len: self.len - mid,
            segment_capacity: self.segment_capacity.saturating_sub(mid),
            headroom: 0,
        };

        self.len = mid;
        self.segment_capacity = mid;

        Some(second_half)
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub(crate) fn debug_ref_count(&self) -> u64 {
        self.slot().ref_count.load(Ordering::Acquire)
    }
}

impl Deref for ZeroCopyBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Drop for ZeroCopyBuffer {
    fn drop(&mut self) {
        let slot = self.pool.slot(self.slot_idx);
        let prev = slot.ref_count.fetch_sub(1, Ordering::AcqRel);
        if prev == 0 {
            log::error!(
                "[NET] zero_copy double-drop/underflow detected: pool={} slot={}",
                self.pool.id.as_u32(),
                self.slot_idx
            );
            slot.ref_count.store(0, Ordering::Release);
            return;
        }

        if prev == 1 {
            self.pool.stats.frees.fetch_add(1, Ordering::Relaxed);
            self.pool.stats.in_use.fetch_sub(1, Ordering::Relaxed);
            self.pool.return_slot_index(self.slot_idx);
        }
    }
}

// ============================================================================
// Scatter-Gather List
// ============================================================================

/// DMA Scatter-Gatherエントリ（物理/IOVAアドレス専用）
///
/// `scatter_gather::SgEntry`（仮想アドレスベース）との混同を避けるため、
/// DMA固有の名前を使用。
#[derive(Debug, Clone, Copy)]
pub struct DmaSgEntry {
    /// DMAアドレス
    pub addr: u64,
    /// 長さ
    pub len: u32,
}

/// Scatter-Gatherリスト
/// Scatter-Gatherリスト
///
/// `SgList` keeps ownership of the underlying `ZeroCopyBuffer` objects so that
/// DMA drivers may safely use the addresses after the caller drops their
/// references.  The previous implementation only stored `(addr,len)` tuples and
/// allowed the buffers to be freed, leading to a use-after-free on the NIC.
pub struct SgList {
    buffers: Vec<ZeroCopyBuffer>,
    total_len: usize,
}

impl SgList {
    /// 新しいSGリストを作成
    pub fn new() -> Self {
        Self {
            buffers: Vec::new(),
            total_len: 0,
        }
    }

    /// エントリを追加（所有権を奪う）
    pub fn push(&mut self, buffer: ZeroCopyBuffer) {
        self.total_len += buffer.len();
        self.buffers.push(buffer);
    }

    /// エントリ数を取得
    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    /// 合計長を取得
    pub fn total_len(&self) -> usize {
        self.total_len
    }

    /// DMAドライバに渡すためのDmaSgEntry配列を生成
    pub fn entries(&self) -> Vec<DmaSgEntry> {
        self.buffers
            .iter()
            .map(|buf| DmaSgEntry {
                addr: buf.dma_addr(),
                len: buf.len() as u32,
            })
            .collect()
    }
}

impl Default for SgList {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Packet Chain (for GSO/GRO)
// ============================================================================

/// パケットチェーン（複数パケットのリンクリスト）
pub struct PacketChain {
    buffers: VecDeque<ZeroCopyBuffer>,
    total_len: usize,
}

impl PacketChain {
    /// 新しいチェーンを作成
    pub fn new() -> Self {
        Self {
            buffers: VecDeque::new(),
            total_len: 0,
        }
    }

    /// パケットを追加
    pub fn push(&mut self, buffer: ZeroCopyBuffer) {
        self.total_len += buffer.len();
        self.buffers.push_back(buffer);
    }

    /// パケットを取得（FIFO）
    pub fn pop(&mut self) -> Option<ZeroCopyBuffer> {
        if let Some(buf) = self.buffers.pop_front() {
            self.total_len -= buf.len();
            Some(buf)
        } else {
            None
        }
    }

    /// エントリ数
    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    /// 合計長を取得
    pub fn total_len(&self) -> usize {
        self.total_len
    }
}

impl Default for PacketChain {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Zero-Copy Send/Receive Operations
// ============================================================================

/// ゼロコピー送信操作
pub struct ZeroCopySend {
    /// 送信バッファ
    buffer: ZeroCopyBuffer,
    /// 送信先アドレス（オプション）
    dest_addr: Option<[u8; 6]>, // MACアドレス
}

impl ZeroCopySend {
    /// 新しい送信操作を作成
    pub fn new(buffer: ZeroCopyBuffer) -> Self {
        Self {
            buffer,
            dest_addr: None,
        }
    }

    /// 送信先を設定
    pub fn with_dest(mut self, addr: [u8; 6]) -> Self {
        self.dest_addr = Some(addr);
        self
    }

    /// バッファを取得
    pub fn buffer(&self) -> &ZeroCopyBuffer {
        &self.buffer
    }

    /// バッファを消費
    pub fn into_buffer(self) -> ZeroCopyBuffer {
        self.buffer
    }
}

/// ゼロコピー受信操作
pub struct ZeroCopyRecv {
    /// 受信バッファ
    buffer: ZeroCopyBuffer,
    /// 送信元MACアドレス
    src_mac: [u8; 6],
    /// タイムスタンプ（ナノ秒）
    timestamp_ns: u64,
    /// RSS/RPS ハッシュ
    rss_hash: u32,
}

impl ZeroCopyRecv {
    /// 新しい受信操作を作成
    pub fn new(buffer: ZeroCopyBuffer, src_mac: [u8; 6]) -> Self {
        Self {
            buffer,
            src_mac,
            timestamp_ns: 0,
            rss_hash: 0,
        }
    }

    /// タイムスタンプを設定
    pub fn with_timestamp(mut self, ts: u64) -> Self {
        self.timestamp_ns = ts;
        self
    }

    /// RSSハッシュを設定
    pub fn with_rss_hash(mut self, hash: u32) -> Self {
        self.rss_hash = hash;
        self
    }

    /// バッファを取得
    pub fn buffer(&self) -> &ZeroCopyBuffer {
        &self.buffer
    }

    /// バッファを消費
    pub fn into_buffer(self) -> ZeroCopyBuffer {
        self.buffer
    }

    /// 送信元MACを取得
    pub fn src_mac(&self) -> [u8; 6] {
        self.src_mac
    }

    /// タイムスタンプを取得
    pub fn timestamp(&self) -> u64 {
        self.timestamp_ns
    }

    /// RSSハッシュを取得
    pub fn rss_hash(&self) -> u32 {
        self.rss_hash
    }
}

// ============================================================================
// Protocol Buffer Views (Zero-Copy Parsing)
// ============================================================================

/// イーサネットヘッダビュー
#[repr(C, packed)]
pub struct EthernetHeaderView {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: [u8; 2],
}

impl EthernetHeaderView {
    /// バッファからビューを取得
    pub fn from_buffer(buffer: &ZeroCopyBuffer) -> Option<&Self> {
        if buffer.len() < 14 {
            return None;
        }
        crate::util::get_ref::<Self>(buffer.as_slice(), 0)
    }

    /// EtherTypeを取得
    pub fn ether_type(&self) -> u16 {
        u16::from_be_bytes(self.ether_type)
    }
}

/// IPv4ヘッダビュー
#[repr(C, packed)]
pub struct Ipv4HeaderView {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: [u8; 2],
    pub identification: [u8; 2],
    pub flags_fragment: [u8; 2],
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: [u8; 2],
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
}

impl Ipv4HeaderView {
    /// バッファからビューを取得（イーサネットヘッダの後）
    pub fn from_buffer(buffer: &ZeroCopyBuffer) -> Option<&Self> {
        if buffer.len() < 34 {
            // 14 (eth) + 20 (ip)
            return None;
        }
        crate::util::get_ref::<Self>(buffer.as_slice(), 14)
    }

    /// ヘッダ長を取得（バイト）
    pub fn header_len(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }

    /// 合計長を取得
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes(self.total_length)
    }

    /// プロトコルを取得
    pub fn protocol(&self) -> u8 {
        self.protocol
    }
}

// ============================================================================
// Async Zero-Copy Stream
// ============================================================================

/// 非同期ゼロコピーリーダー
pub struct ZeroCopyReader {
    pool: Arc<MemoryPool>,
    pending: VecDeque<ZeroCopyBuffer>,
    waker: Option<Waker>,
}

impl ZeroCopyReader {
    pub fn new(pool: Arc<MemoryPool>) -> Self {
        Self {
            pool,
            pending: VecDeque::new(),
            waker: None,
        }
    }

    /// データを受信（ゼロコピー）
    pub async fn recv(&mut self) -> Option<ZeroCopyBuffer> {
        ZeroCopyRecvFuture { reader: self }.await
    }

    /// データが到着した時に呼ばれる
    pub fn on_data(&mut self, buffer: ZeroCopyBuffer) {
        self.pending.push_back(buffer);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

struct ZeroCopyRecvFuture<'a> {
    reader: &'a mut ZeroCopyReader,
}

impl<'a> Future for ZeroCopyRecvFuture<'a> {
    type Output = Option<ZeroCopyBuffer>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(buffer) = self.reader.pending.pop_front() {
            Poll::Ready(Some(buffer))
        } else {
            self.reader.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// 非同期ゼロコピーライター
pub struct ZeroCopyWriter {
    pool: Arc<MemoryPool>,
    waker: Option<Waker>,
}

impl ZeroCopyWriter {
    pub fn new(pool: Arc<MemoryPool>) -> Self {
        Self { pool, waker: None }
    }

    /// バッファを確保
    pub fn alloc(&self) -> Option<ZeroCopyBuffer> {
        self.pool.alloc()
    }

    /// データを送信（ゼロコピー）
    pub async fn send(&mut self, buffer: ZeroCopyBuffer) -> Result<(), &'static str> {
        ZeroCopySendFuture {
            writer: self,
            buffer: Some(buffer),
        }
        .await
    }

    /// Enqueue a `PacketRef` for true zero-copy transmit via the registered net device.
    ///
    /// Returns Ok(()) if the packet was successfully queued. This performs no
    /// completion wait — completion and cleanup occurs in the device interrupt
    /// handler which will return the buffer to the mempool.
    pub fn enqueue_via_net_device(
        packet: crate::net::datapath::mempool::PacketRef,
    ) -> Result<(), &'static str> {
        if crate::net::runtime::device::transmit_packet(
            None,
            kernel_api::resource::net::PacketPayload::single(packet),
            kernel_api::service::netdev::NetTxMeta::default(),
        ) {
            Ok(())
        } else {
            Err("NotInitialized")
        }
    }
}

struct ZeroCopySendFuture<'a> {
    writer: &'a mut ZeroCopyWriter,
    buffer: Option<ZeroCopyBuffer>,
}
