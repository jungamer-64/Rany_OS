// ============================================================================
// kernel/src/net/datapath/optimization/mod.rs - Network Performance Optimization
// ============================================================================

// ============================================================================
// src/net/optimization.rs - Network Performance Optimization
// 設計書 6章: 高性能ネットワーク最適化
// ============================================================================

//! # ネットワーク性能最適化
//!
//! このモジュールは以下の最適化を提供します:
//! - バッチ処理 (Batching)
//! - NUMA対応メモリ配置
//! - CPU親和性設定
//! - インテリジェント割り込み合体 (Interrupt Coalescing)

use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::mempool::PacketRef;

// ============================================================================
// Batch Processing - バッチ処理
// ============================================================================

/// 最大バッチサイズ (DPDK/NAPIの典型値)
pub const MAX_BATCH_SIZE: usize = 64;

/// パケットバッチ - 複数パケットをまとめて処理
pub struct PacketBatch {
    /// パケットリスト
    packets: Vec<PacketRef>,
    /// バッチサイズ上限
    capacity: usize,
}

impl PacketBatch {
    /// 新しい空のバッチを作成
    pub const fn new() -> Self {
        Self {
            packets: Vec::new(),
            capacity: MAX_BATCH_SIZE,
        }
    }

    /// パケットをバッチに追加
    pub fn push(&mut self, packet: PacketRef) -> bool {
        if self.packets.len() >= self.capacity {
            return false;
        }
        self.packets.push(packet);
        true
    }

    /// バッチが満杯か
    #[inline]
    pub fn is_full(&self) -> bool {
        self.packets.len() >= self.capacity
    }

    /// バッチが空か
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// バッチ内のパケット数
    #[inline]
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// バッチをクリア
    pub fn clear(&mut self) {
        self.packets.clear();
    }

    /// パケットスライスへの参照を取得
    #[inline]
    pub fn as_slice(&self) -> &[PacketRef] {
        &self.packets
    }

    /// プリフェッチ付きイテレータを返す
    ///
    /// 次パケットのデータをCPUキャッシュにプリフェッチしながら
    /// 現在のパケットを処理する。L1d への読み込み要求を先行発行し、
    /// キャッシュミスによるストールを削減。
    pub fn iter_prefetch(&self) -> PrefetchIterator<'_> {
        // 最初のパケットをプリフェッチ
        if let Some(first) = self.packets.first() {
            let ptr = first.data().as_ptr();
            prefetch_l1(ptr);
        }
        PrefetchIterator {
            packets: &self.packets,
            index: 0,
        }
    }
}

/// CPU キャッシュプリフェッチ (L1d, read)
///
/// x86 `PREFETCHT0` — 全キャッシュレベルにロード。
/// no_std 環境で安全に使用可能。アドレスが無効でも fault しない。
#[inline(always)]
pub fn prefetch_l1(ptr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_prefetch(ptr as *const i8, core::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = ptr;
    }
}

/// CPU キャッシュプリフェッチ (L2, read)
///
/// x86 `PREFETCHT1` — L2 以上にロード。
#[inline(always)]
pub fn prefetch_l2(ptr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_prefetch(ptr as *const i8, core::arch::x86_64::_MM_HINT_T1);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = ptr;
    }
}

/// プリフェッチ付きバッチイテレータ
///
/// 現在のパケットを返すとき、2つ先のパケットデータをプリフェッチする。
/// これにより次のイテレーションでキャッシュヒットする確率を大幅に向上させる。
pub struct PrefetchIterator<'a> {
    packets: &'a [PacketRef],
    index: usize,
}

impl<'a> Iterator for PrefetchIterator<'a> {
    type Item = &'a PacketRef;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.packets.len() {
            return None;
        }

        let current = &self.packets[self.index];

        // 2つ先のパケット（look-ahead=2）をプリフェッチ
        let prefetch_idx = self.index + 2;
        if prefetch_idx < self.packets.len() {
            let future_pkt = &self.packets[prefetch_idx];
            let ptr = future_pkt.data().as_ptr();
            prefetch_l1(ptr);
        }

        self.index += 1;
        Some(current)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.packets.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for PrefetchIterator<'a> {}

impl Default for PacketBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for PacketBatch {
    type Item = PacketRef;
    type IntoIter = alloc::vec::IntoIter<PacketRef>;

    fn into_iter(self) -> Self::IntoIter {
        self.packets.into_iter()
    }
}

// ============================================================================
// Batch Processor - バッチ処理エンジン
// ============================================================================

/// バッチ処理統計
#[derive(Debug, Default)]
pub struct BatchStats {
    /// 処理したバッチ数
    pub batches_processed: AtomicU64,
    /// 処理したパケット総数
    pub packets_processed: AtomicU64,
    /// 平均バッチサイズ (x100)
    pub avg_batch_size_x100: AtomicU64,
    /// 最大バッチサイズ
    pub max_batch_size: AtomicUsize,
    /// フラッシュ回数
    pub flush_count: AtomicU64,
    /// タイムアウトフラッシュ回数
    pub timeout_flushes: AtomicU64,
}

impl BatchStats {
    pub const fn new() -> Self {
        Self {
            batches_processed: AtomicU64::new(0),
            packets_processed: AtomicU64::new(0),
            avg_batch_size_x100: AtomicU64::new(0),
            max_batch_size: AtomicUsize::new(0),
            flush_count: AtomicU64::new(0),
            timeout_flushes: AtomicU64::new(0),
        }
    }

    fn record_batch(&self, size: usize) {
        let total = self.batches_processed.fetch_add(1, Ordering::Relaxed);
        let packets = self
            .packets_processed
            .fetch_add(size as u64, Ordering::Relaxed);

        // 移動平均の更新
        if total > 0 {
            let new_avg = (packets + size as u64) * 100 / (total + 1);
            self.avg_batch_size_x100.store(new_avg, Ordering::Relaxed);
        }

        // 最大サイズの更新
        let mut current_max = self.max_batch_size.load(Ordering::Relaxed);
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while size > current_max {
            match self.max_batch_size.compare_exchange_weak(
                current_max,
                size,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new) => current_max = new,
            }
        }
    }
}

/// バッチ処理設定
#[derive(Debug, Clone, Copy)]
pub struct BatchConfig {
    /// 最大バッチサイズ
    pub max_batch_size: usize,
    /// フラッシュまでの最大待ち時間 (マイクロ秒)
    pub max_delay_us: u32,
    /// バッチ処理を有効にする最小パケット数/秒
    pub min_pps_threshold: u64,
    /// 動的バッチサイズ調整を有効化
    pub adaptive_batching: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 32,
            max_delay_us: 50,
            min_pps_threshold: 10000,
            adaptive_batching: true,
        }
    }
}

/// バッチプロセッサ
pub struct BatchProcessor {
    config: BatchConfig,
    current_batch: PoisonLock<PacketBatch>,
    stats: BatchStats,
    last_flush_tsc: AtomicU64,
    enabled: AtomicBool,
}

impl BatchProcessor {
    pub const fn new(config: BatchConfig) -> Self {
        Self {
            config,
            current_batch: PoisonLock::new(PacketBatch::new()),
            stats: BatchStats::new(),
            last_flush_tsc: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
        }
    }

    /// パケットをバッチに追加
    pub fn enqueue(&self, packet: PacketRef) -> Option<PacketBatch> {
        if !self.enabled.load(Ordering::Relaxed) {
            // バッチ処理無効時は即座に単一パケットバッチを返す
            let mut batch = PacketBatch::new();
            batch.push(packet);
            return Some(batch);
        }

        let Ok(mut batch_guard) = self.current_batch.lock() else {
            return None;
        };
        batch_guard.push(packet);

        if batch_guard.is_full() {
            let ready_batch = core::mem::take(&mut *batch_guard);
            // capacity was reset by mem::take (default PacketBatch), restore it?
            // Default PacketBatch has capacity=MAX_BATCH_SIZE (64).
            // So it's fine.
            drop(batch_guard); // Release lock before stats/return

            self.stats.record_batch(ready_batch.len());
            self.stats.flush_count.fetch_add(1, Ordering::Relaxed);
            Some(ready_batch)
        } else {
            None
        }
    }

    /// バッチを強制フラッシュ
    pub fn flush(&self) -> Option<PacketBatch> {
        let Ok(mut batch_guard) = self.current_batch.lock() else {
            return None;
        };
        if batch_guard.is_empty() {
            return None;
        }

        let ready_batch = core::mem::take(&mut *batch_guard);
        drop(batch_guard);

        self.stats.record_batch(ready_batch.len());
        self.stats.flush_count.fetch_add(1, Ordering::Relaxed);
        Some(ready_batch)
    }

    /// タイムアウトチェック
    #[inline]
    pub fn check_timeout(&self, current_tsc: u64, tsc_freq_mhz: u64) -> Option<PacketBatch> {
        let last = self.last_flush_tsc.load(Ordering::Relaxed);
        let elapsed_us = (current_tsc - last) / tsc_freq_mhz;

        if elapsed_us >= self.config.max_delay_us as u64 {
            self.last_flush_tsc.store(current_tsc, Ordering::Relaxed);
            // タイムアウトしてもバッチが空なら何もしない
            let Ok(mut batch_guard) = self.current_batch.lock() else {
                return None;
            };
            if !batch_guard.is_empty() {
                let ready_batch = core::mem::take(&mut *batch_guard);
                drop(batch_guard);
                self.stats.timeout_flushes.fetch_add(1, Ordering::Relaxed);
                self.stats.record_batch(ready_batch.len());
                return Some(ready_batch);
            }
        }
        None
    }

    /// バッチ処理を有効/無効化
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// 統計を取得
    pub fn stats(&self) -> &BatchStats {
        &self.stats
    }
}

/// ネットワークフロー用CPU親和性マネージャ
pub struct FlowAffinity;

impl FlowAffinity {
    /// 5タプルからフローハッシュを計算（改良版 Toeplitz ハッシュ）
    ///
    /// Microsoft RSS 標準鍵を使用した Toeplitz ハッシュにより、
    /// フロー分散の均一性を改善し、特定CPUコアへの偏りを低減する。
    pub fn hash_5tuple(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> u32 {
        // Microsoft RSS 標準ハッシュキー (40バイト — 先頭13バイトで十分)
        static RSS_KEY: [u8; 40] = [
            0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
            0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
            0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
        ];

        // 入力を12バイト（src_ip:4 + dst_ip:4 + src_port:2 + dst_port:2）に
        // パックしてから Toeplitz ハッシュを計算
        let mut input = [0u8; 13];
        input[0..4].copy_from_slice(&src_ip.to_be_bytes());
        input[4..8].copy_from_slice(&dst_ip.to_be_bytes());
        input[8..10].copy_from_slice(&src_port.to_be_bytes());
        input[10..12].copy_from_slice(&dst_port.to_be_bytes());
        input[12] = protocol;

        toeplitz_hash(&input, &RSS_KEY)
    }
}

/// Toeplitz ハッシュ計算
///
/// NIC RSS と互換性のある Toeplitz ハッシュ関数。
/// `key` は少なくとも `input.len() + 4` バイトの長さが必要。
fn toeplitz_hash(input: &[u8], key: &[u8]) -> u32 {
    let mut result: u32 = 0;

    // key の最初の4バイトを初期値として32ビットに展開
    let mut k: u32 = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);

    for (i, &byte) in input.iter().enumerate() {
        // key から次のバイトを取得して k をシフト
        let next_key_byte = if i + 4 < key.len() { key[i + 4] } else { 0 };

        for bit in (0..8).rev() {
            if byte & (1 << bit) != 0 {
                result ^= k;
            }
            // k を1ビット左シフトし、next_key_byte の対応ビットを右端に入れる
            k = (k << 1) | ((next_key_byte as u32 >> bit) & 1);
        }
    }

    result
}

// ============================================================================
// Interrupt Coalescing - 割り込み合体
// ============================================================================

/// 割り込み合体設定
#[derive(Debug, Clone, Copy)]
pub struct InterruptCoalescing {
    /// RX合体: パケット数閾値
    pub rx_max_packets: u16,
    /// RX合体: 最大待ち時間 (マイクロ秒)
    pub rx_max_usec: u16,
    /// TX合体: パケット数閾値
    pub tx_max_packets: u16,
    /// TX合体: 最大待ち時間 (マイクロ秒)
    pub tx_max_usec: u16,
    /// 適応型合体を有効化
    pub adaptive: bool,
}

impl Default for InterruptCoalescing {
    fn default() -> Self {
        Self {
            rx_max_packets: 64,
            rx_max_usec: 100,
            tx_max_packets: 128,
            tx_max_usec: 200,
            adaptive: true,
        }
    }
}

/// 適応型割り込み合体コントローラ
pub struct AdaptiveCoalescing {
    config: InterruptCoalescing,
    current_rx_usec: AtomicU64,
    current_tx_usec: AtomicU64,
    packets_per_second: AtomicU64,
    last_update_tsc: AtomicU64,
    packet_count: AtomicU64,
}

impl AdaptiveCoalescing {
    pub const fn new(config: InterruptCoalescing) -> Self {
        Self {
            config,
            current_rx_usec: AtomicU64::new(config.rx_max_usec as u64),
            current_tx_usec: AtomicU64::new(config.tx_max_usec as u64),
            packets_per_second: AtomicU64::new(0),
            last_update_tsc: AtomicU64::new(0),
            packet_count: AtomicU64::new(0),
        }
    }

    /// パケット処理を記録
    pub fn record_packet(&self) {
        self.packet_count.fetch_add(1, Ordering::Relaxed);
    }

    /// 割り込み合体設定を更新
    pub fn update(&self, current_tsc: u64, tsc_freq_mhz: u64) {
        if !self.config.adaptive {
            return;
        }

        let last = self.last_update_tsc.load(Ordering::Relaxed);
        let elapsed_us = (current_tsc - last) / tsc_freq_mhz;

        // 100ms毎に更新
        if elapsed_us < 100_000 {
            return;
        }

        self.last_update_tsc.store(current_tsc, Ordering::Relaxed);

        let packets = self.packet_count.swap(0, Ordering::Relaxed);
        let pps = packets * 1_000_000 / elapsed_us;
        self.packets_per_second.store(pps, Ordering::Relaxed);

        // パケットレートに基づいて合体時間を調整
        let new_rx_usec = if pps > 1_000_000 {
            // 高負荷: 合体時間を延長
            self.config.rx_max_usec as u64
        } else if pps > 100_000 {
            // 中負荷
            self.config.rx_max_usec as u64 / 2
        } else {
            // 低負荷: 合体時間を短縮
            10
        };

        self.current_rx_usec.store(new_rx_usec, Ordering::Relaxed);
    }

    /// 現在のRX合体時間を取得
    pub fn rx_usec(&self) -> u64 {
        self.current_rx_usec.load(Ordering::Relaxed)
    }

    /// 現在のTX合体時間を取得
    pub fn tx_usec(&self) -> u64 {
        self.current_tx_usec.load(Ordering::Relaxed)
    }

    /// 推定パケットレート
    pub fn packets_per_second(&self) -> u64 {
        self.packets_per_second.load(Ordering::Relaxed)
    }
}
