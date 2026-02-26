// ============================================================================
// src/net/zero_copy.rs - Zero-Copy Network Stack
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


use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Deref;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crate::sync::PoisonLock;

use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};

// ============================================================================
// Configuration
// ============================================================================

/// デフォルトのバッファサイズ
mod send_future;
pub use send_future::*;
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
/// グローバルフリーリストからの補充バッチ数
const LOCAL_FREE_REFILL_BATCH: usize = 16;
/// ローカルキャッシュ満杯時にグローバルへ戻す最大数
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
    /// デバイスDMAアドレス (IOVA or physical)
    device_base_addr: u64,
    /// ペイロード容量（headroom/tailroom除く）
    payload_capacity: usize,
    /// スロット共有参照カウント
    ref_count: AtomicU64,
}

// `CoherentDmaBuffer` は `Send` のみだが、ここでは初期化後に `base_ptr`/`device_base_addr`
// の読み取りと `ref_count` の原子的更新だけを共有し、DMAバッファ本体の可変操作は行わない。
unsafe impl Sync for BufferSlot {}

struct MemoryPoolInner {
    id: PoolId,
    slots: Vec<BufferSlot>,
    global_free: PoisonLock<Vec<u32>>,
    local_free: Vec<PoisonLock<Vec<u32>>>,
    stats: PoolStats,
}

impl MemoryPoolInner {
    fn cpu_local_cache_index(&self) -> Option<usize> {
        let cpu = crate::smp::cpu_index();
        (cpu < self.local_free.len()).then_some(cpu)
    }

    fn alloc_slot_index(&self) -> Option<u32> {
        if let Some(cpu_idx) = self.cpu_local_cache_index() {
            if let Ok(mut local) = self.local_free[cpu_idx].lock() {
                if let Some(idx) = local.pop() {
                    return Some(idx);
                }
            }

            let mut batch = Vec::with_capacity(LOCAL_FREE_REFILL_BATCH);
            if let Ok(mut global) = self.global_free.lock() {
                for _ in 0..LOCAL_FREE_REFILL_BATCH {
                    let Some(idx) = global.pop() else {
                        break;
                    };
                    batch.push(idx);
                }
            }

            if let Some(idx) = batch.pop() {
                if !batch.is_empty() {
                    if let Ok(mut local) = self.local_free[cpu_idx].lock() {
                        local.extend(batch);
                    }
                }
                return Some(idx);
            }
            return None;
        }

        if let Ok(mut global) = self.global_free.lock() {
            global.pop()
        } else {
            None
        }
    }

    fn return_slot_index(&self, idx: u32) {
        if let Some(cpu_idx) = self.cpu_local_cache_index() {
            let spill = {
                if let Ok(mut local) = self.local_free[cpu_idx].lock() {
                    if local.len() < LOCAL_FREE_CACHE_CAPACITY {
                        local.push(idx);
                        return;
                    }

                    let mut batch = Vec::with_capacity(LOCAL_FREE_SPILL_BATCH);
                    batch.push(idx);
                    while batch.len() < LOCAL_FREE_SPILL_BATCH {
                        let Some(entry) = local.pop() else {
                            break;
                        };
                        batch.push(entry);
                    }
                    batch
                } else {
                    Vec::new()
                }
            };

            let mut spill = spill;
            if let Ok(mut global) = self.global_free.lock() {
                global.append(&mut spill);
            }
            return;
        }

        if let Ok(mut global) = self.global_free.lock() {
            global.push(idx);
        }
    }

    fn available(&self) -> usize {
        let mut total = self.global_free.lock().map(|g| g.len()).unwrap_or(0);
        for cache in &self.local_free {
            total += cache.lock().map(|c| c.len()).unwrap_or(0);
        }
        total
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
        let mut global_free = Vec::with_capacity(count);

        // バッファを事前割り当て (CoherentDmaBuffer経由で正しい物理アドレスを取得)
        for _ in 0..count {
            if let Some(buf) = CoherentDmaBuffer::new(total_size, DmaMemoryAttributes::MMIO) {
                let virt_ptr = unsafe { buf.as_slice().as_ptr() } as *mut u8;
                let dev_addr = buf.device_addr();
                if let Some(nn) = NonNull::new(virt_ptr) {
                    let slot_idx = slots.len() as u32;
                    slots.push(BufferSlot {
                        _dma: buf,
                        base_ptr: nn,
                        device_base_addr: dev_addr,
                        payload_capacity: aligned_size,
                        ref_count: AtomicU64::new(0),
                    });
                    global_free.push(slot_idx);
                }
            }
        }

        let local_count = (crate::smp::cpu_count() as usize).max(1);
        let mut local_free = Vec::with_capacity(local_count);
        for _ in 0..local_count {
            local_free.push(PoisonLock::new(Vec::with_capacity(LOCAL_FREE_CACHE_CAPACITY)));
        }

        let inner = Arc::new(MemoryPoolInner {
            id,
            slots,
            global_free: PoisonLock::new(global_free),
            local_free,
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

    /// 空きバッファ数を取得
    pub fn available(&self) -> usize {
        self.inner.available()
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

    /// 互換API: データを取得
    pub fn data(&self) -> &[u8] {
        self.as_slice()
    }

    /// 互換API: 可変データを取得（排他的所有時のみ）
    pub fn data_mut(&mut self) -> Result<&mut [u8], ZeroCopyError> {
        self.try_as_mut_slice()
    }

    /// 互換API: データを書き込む（必要に応じて長さを更新）
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
    pub fn reserve_headroom(&mut self, size: usize) -> Result<(), &'static str> {
        if self.headroom < size {
            return Err("Insufficient headroom");
        }
        if self.len.saturating_add(size) > self.segment_capacity {
            return Err("Out of bounds");
        }
        self.headroom -= size;
        self.len += size;
        Ok(())
    }

    /// ヘッドルームを消費（ヘッダ削除用）
    pub fn consume_headroom(&mut self, size: usize) -> Result<(), &'static str> {
        if self.len < size {
            return Err("Insufficient data");
        }
        self.headroom += size;
        self.len -= size;
        Ok(())
    }

    /// DMAアドレスを取得（ヘッドルームオフセット適用済み）
    ///
    /// IOMMU が有効な場合は IOVA、それ以外は物理アドレスを返す。
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

/// Scatter-Gatherエントリ
#[derive(Debug, Clone, Copy)]
pub struct SgEntry {
    /// DMAアドレス
    pub addr: u64,
    /// 長さ
    pub len: u32,
}

/// Scatter-Gatherリスト
pub struct SgList {
    entries: Vec<SgEntry>,
    total_len: usize,
}

impl SgList {
    /// 新しいSGリストを作成
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            total_len: 0,
        }
    }

    /// エントリを追加
    pub fn push(&mut self, buffer: &ZeroCopyBuffer) {
        self.entries.push(SgEntry {
            addr: buffer.dma_addr(),
            len: buffer.len() as u32,
        });
        self.total_len += buffer.len();
    }

    /// エントリ数を取得
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 合計長を取得
    pub fn total_len(&self) -> usize {
        self.total_len
    }

    /// エントリのスライスを取得
    pub fn entries(&self) -> &[SgEntry] {
        &self.entries
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
    head: Option<ZeroCopyBuffer>,
    tail_ptr: Option<NonNull<ZeroCopyBuffer>>,
    count: usize,
    total_len: usize,
}

impl PacketChain {
    /// 新しいチェーンを作成
    pub fn new() -> Self {
        Self {
            head: None,
            tail_ptr: None,
            count: 0,
            total_len: 0,
        }
    }

    /// パケットを追加
    pub fn push(&mut self, buffer: ZeroCopyBuffer) {
        self.total_len += buffer.len();
        self.count += 1;

        if self.head.is_none() {
            self.head = Some(buffer);
        }
        // 注：実際の実装ではリンクリストでつなぐ
    }

    /// パケットを取得
    pub fn pop(&mut self) -> Option<ZeroCopyBuffer> {
        if let Some(head) = self.head.take() {
            self.count -= 1;
            self.total_len -= head.len();
            Some(head)
        } else {
            None
        }
    }

    /// パケット数を取得
    pub fn len(&self) -> usize {
        self.count
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
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

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

/// 非同期ゼロコピーリーダー
pub struct ZeroCopyReader {
    pool: Arc<MemoryPool>,
    pending: Option<ZeroCopyBuffer>,
    waker: Option<Waker>,
}

impl ZeroCopyReader {
    pub fn new(pool: Arc<MemoryPool>) -> Self {
        Self {
            pool,
            pending: None,
            waker: None,
        }
    }

    /// データを受信（ゼロコピー）
    pub async fn recv(&mut self) -> Option<ZeroCopyBuffer> {
        ZeroCopyRecvFuture { reader: self }.await
    }

    /// データが到着した時に呼ばれる
    pub fn on_data(&mut self, buffer: ZeroCopyBuffer) {
        self.pending = Some(buffer);
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
        if let Some(buffer) = self.reader.pending.take() {
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

    /// Enqueue a `PacketRef` for true zero-copy transmit via the VirtIO device.
    ///
    /// Returns Ok(()) if the packet was successfully queued. This performs no
    /// completion wait — completion and cleanup occurs in the device interrupt
    /// handler which will return the buffer to the mempool.
    pub fn enqueue_via_virtio(packet: crate::net::PacketRef) -> Result<(), &'static str> {
        // Check device presence first to avoid moving packet into a closure that
        // might not be executed (which would drop the PacketRef unexpectedly).
        if crate::io::virtio::with_virtio_net(|_| ()).is_none() {
            return Err("NotInitialized");
        }

        match crate::io::virtio::with_virtio_net(|dev| dev.enqueue_send_zero_copy(packet)) {
            Some(Ok(())) => Ok(()),
            Some(Err(_)) => Err("DeviceError"),
            None => Err("NotInitialized"),
        }
    }
}

struct ZeroCopySendFuture<'a> {
    writer: &'a mut ZeroCopyWriter,
    buffer: Option<ZeroCopyBuffer>,
}
