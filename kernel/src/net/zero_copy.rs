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

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

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

/// メモリプール（事前割り当てバッファのプール）
///
/// DMA-safe なバッファをプールし、ゼロコピーネットワーク I/O を実現する。
/// 各バッファは `CoherentDmaBuffer` で割り当てられ、正しい物理/デバイスアドレス
/// が保証される。
pub struct MemoryPool {
    /// プールID
    id: PoolId,
    /// バッファサイズ
    buffer_size: usize,
    /// フリーリスト (virtual address pointers)
    free_list: Mutex<Vec<NonNull<u8>>>,
    /// 統計
    stats: PoolStats,
    /// DMAバッファストレージ: virt_addr -> (CoherentDmaBuffer, device_base_addr)
    dma_buffers: Mutex<BTreeMap<usize, (CoherentDmaBuffer, u64)>>,
}

unsafe impl Send for MemoryPool {}
unsafe impl Sync for MemoryPool {}

impl MemoryPool {
    /// 新しいメモリプールを作成
    pub fn new(id: PoolId, buffer_size: usize, count: usize) -> Self {
        let aligned_size = (buffer_size + DMA_ALIGNMENT - 1) & !(DMA_ALIGNMENT - 1);
        let total_size = aligned_size + BUFFER_HEADROOM + BUFFER_TAILROOM;

        let mut free_list = Vec::with_capacity(count);
        let mut dma_buffers = BTreeMap::new();

        // バッファを事前割り当て (CoherentDmaBuffer経由で正しい物理アドレスを取得)
        for _ in 0..count {
            if let Some(buf) = CoherentDmaBuffer::new(total_size, DmaMemoryAttributes::MMIO) {
                let virt_ptr = unsafe { buf.as_slice().as_ptr() } as *mut u8;
                let dev_addr = buf.device_addr();
                if let Some(nn) = NonNull::new(virt_ptr) {
                    free_list.push(nn);
                    dma_buffers.insert(virt_ptr as usize, (buf, dev_addr));
                }
            }
        }

        let pool = Self {
            id,
            buffer_size: total_size,
            free_list: Mutex::new(free_list),
            stats: PoolStats::default(),
            dma_buffers: Mutex::new(dma_buffers),
        };

        pool.stats.total.store(count, Ordering::Release);
        pool
    }

    /// バッファを割り当て
    pub fn alloc(&self) -> Option<ZeroCopyBuffer> {
        let mut free_list = self.free_list.lock();

        if let Some(ptr) = free_list.pop() {
            self.stats.allocations.fetch_add(1, Ordering::Relaxed);
            self.stats.in_use.fetch_add(1, Ordering::Relaxed);

            // デバイスアドレスを取得
            let dev_base = self.dma_buffers.lock()
                .get(&(ptr.as_ptr() as usize))
                .map(|(_, dev)| *dev)
                .unwrap_or(ptr.as_ptr() as u64);

            Some(ZeroCopyBuffer {
                data: ptr,
                len: 0,
                capacity: self.buffer_size - BUFFER_HEADROOM - BUFFER_TAILROOM,
                headroom: BUFFER_HEADROOM,
                pool_id: self.id,
                ref_count: AtomicU32::new(1),
                device_base_addr: dev_base,
            })
        } else {
            self.stats.alloc_failures.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// バッファを解放
    pub fn free(&self, buffer: ZeroCopyBuffer) {
        // 参照カウントをデクリメント
        if buffer.ref_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            let mut free_list = self.free_list.lock();
            free_list.push(buffer.data);
            self.stats.frees.fetch_add(1, Ordering::Relaxed);
            self.stats.in_use.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// プールIDを取得
    pub fn id(&self) -> PoolId {
        self.id
    }

    /// 統計を取得
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// 空きバッファ数を取得
    pub fn available(&self) -> usize {
        self.free_list.lock().len()
    }
}

impl Drop for MemoryPool {
    fn drop(&mut self) {
        // CoherentDmaBuffer の Drop が自動的にメモリを解放するため、
        // フリーリストのポインタは無視し、dma_buffers のドロップに任せる
        let _ = self.free_list.lock();
        // dma_buffers はフィールドのDropで自動解放
    }
}

// ============================================================================
// Zero-Copy Buffer
// ============================================================================

/// ゼロコピーバッファ
pub struct ZeroCopyBuffer {
    /// データポインタ (CPU virtual address)
    data: NonNull<u8>,
    /// 現在のデータ長
    len: usize,
    /// バッファ容量
    capacity: usize,
    /// ヘッドルームオフセット
    headroom: usize,
    /// プールID
    pool_id: PoolId,
    /// 参照カウント
    ref_count: AtomicU32,
    /// ベースデバイスアドレス (IOVA or physical)
    device_base_addr: u64,
}

unsafe impl Send for ZeroCopyBuffer {}
unsafe impl Sync for ZeroCopyBuffer {}

impl ZeroCopyBuffer {
    /// データスライスを取得
    pub fn as_slice(&self) -> &[u8] {
        // Use central helper to build a slice from NonNull pointer with offset and length.
        unsafe { crate::util::nonnull_ptr_as_slice(self.data, self.headroom, self.len) }
    }

    /// データスライスを取得（可変）
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // Use central helper to build a mutable slice from NonNull pointer with offset and length.
        unsafe { crate::util::nonnull_ptr_as_slice_mut(self.data, self.headroom, self.len) }
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
        self.capacity
    }

    /// データ長を設定
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(self.capacity);
    }

    /// ヘッドルームを予約（プロトコルヘッダ追加用）
    pub fn reserve_headroom(&mut self, size: usize) -> Result<(), &'static str> {
        if self.headroom < size {
            return Err("Insufficient headroom");
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
        self.device_base_addr + self.headroom as u64
    }

    /// プールIDを取得
    pub fn pool_id(&self) -> PoolId {
        self.pool_id
    }

    /// 参照を追加
    pub fn clone_ref(&self) -> Self {
        self.ref_count.fetch_add(1, Ordering::AcqRel);
        Self {
            data: self.data,
            len: self.len,
            capacity: self.capacity,
            headroom: self.headroom,
            pool_id: self.pool_id,
            ref_count: AtomicU32::new(1), // 新しいバッファは独自のカウント
            device_base_addr: self.device_base_addr,
        }
    }

    /// 分割（ゼロコピーでスライス）
    pub fn split_at(&mut self, mid: usize) -> Option<ZeroCopyBuffer> {
        if mid > self.len {
            return None;
        }

        let second_half = Self {
            data: NonNull::new(unsafe { self.data.as_ptr().add(self.headroom + mid) })
                .expect("split pointer resulted in null"),
            len: self.len - mid,
            capacity: self.capacity - mid,
            headroom: 0,
            pool_id: self.pool_id,
            ref_count: AtomicU32::new(1),
            device_base_addr: self.device_base_addr + (self.headroom + mid) as u64,
        };

        self.len = mid;
        self.capacity = mid;

        // 参照カウントを増やす（元のプールバッファを共有）
        self.ref_count.fetch_add(1, Ordering::AcqRel);

        Some(second_half)
    }
}

impl Deref for ZeroCopyBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for ZeroCopyBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
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
