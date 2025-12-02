// ============================================================================
// src/net/adaptive_polling.rs - Adaptive Polling Network Driver
// ============================================================================
//!
//! # 適応的ポーリングネットワークドライバ
//!
//! 設計書6.1に基づく高性能ネットワーク処理の実装。
//! トラフィック量に応じて割り込み駆動とポーリング駆動を動的に切り替える。
//!
//! ## 機能
//! - 適応的モード切り替え（NAPI風）
//! - ビジーポーリングモード
//! - 割り込み駆動モード
//! - 動的閾値調整
//! - 統計収集

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use spin::Mutex;

// ============================================================================
// Configuration
// ============================================================================

/// ポーリングモード閾値（パケット/秒）
const POLLING_THRESHOLD_HIGH: u64 = 100_000;  // 10万pps以上でポーリングへ
const POLLING_THRESHOLD_LOW: u64 = 50_000;    // 5万pps以下で割り込みへ

/// ポーリングバジェット（1回のポーリングで処理する最大パケット数）
const POLL_BUDGET: usize = 64;

/// 適応調整間隔（ミリ秒）
const ADAPTATION_INTERVAL_MS: u64 = 100;

/// 最大ポーリング時間（マイクロ秒）
const MAX_POLL_TIME_US: u64 = 1000;

// ============================================================================
// Polling Mode
// ============================================================================

/// ポーリングモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollingMode {
    /// 割り込み駆動モード（低トラフィック時）
    InterruptDriven,
    /// ハイブリッドモード（中程度のトラフィック）
    Hybrid,
    /// ビジーポーリングモード（高トラフィック時）
    BusyPolling,
}

impl Default for PollingMode {
    fn default() -> Self {
        Self::InterruptDriven
    }
}

// ============================================================================
// Packet Buffer
// ============================================================================

/// パケットバッファ（ゼロコピー対応）
#[derive(Debug)]
pub struct PacketBuffer {
    /// データへのポインタ
    data: *mut u8,
    /// バッファサイズ
    capacity: usize,
    /// 実際のデータ長
    len: usize,
    /// ヘッドルーム（プロトコルヘッダ用）
    headroom: usize,
    /// プール参照（返却用）
    pool_id: u32,
}

unsafe impl Send for PacketBuffer {}
unsafe impl Sync for PacketBuffer {}

impl PacketBuffer {
    /// 新しいパケットバッファを作成
    pub fn new(data: *mut u8, capacity: usize, pool_id: u32) -> Self {
        Self {
            data,
            capacity,
            len: 0,
            headroom: 64, // イーサネット + IP + TCP/UDPヘッダ用
            pool_id,
        }
    }

    /// データスライスを取得
    pub fn data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data.add(self.headroom), self.len) }
    }

    /// データスライスを取得（可変）
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.data.add(self.headroom), self.len) }
    }

    /// データ長を設定
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(self.capacity - self.headroom);
    }

    /// ヘッドルームを調整（プロトコルヘッダ追加用）
    pub fn reserve_headroom(&mut self, size: usize) {
        if self.headroom >= size {
            self.headroom -= size;
        }
    }

    /// プールIDを取得
    pub fn pool_id(&self) -> u32 {
        self.pool_id
    }
}

// ============================================================================
// Ring Buffer (Lock-free)
// ============================================================================

/// ロックフリーリングバッファ
pub struct RingBuffer<T> {
    buffer: Vec<Option<T>>,
    head: AtomicU32,
    tail: AtomicU32,
    capacity: u32,
}

impl<T> RingBuffer<T> {
    /// 新しいリングバッファを作成
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two() as u32;
        let mut buffer = Vec::with_capacity(capacity as usize);
        for _ in 0..capacity {
            buffer.push(None);
        }
        
        Self {
            buffer,
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            capacity,
        }
    }

    /// アイテムを追加
    pub fn push(&mut self, item: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        
        let next_tail = (tail + 1) & (self.capacity - 1);
        if next_tail == head {
            return Err(item); // Full
        }
        
        self.buffer[tail as usize] = Some(item);
        self.tail.store(next_tail, Ordering::Release);
        Ok(())
    }

    /// アイテムを取得
    pub fn pop(&mut self) -> Option<T> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        
        if head == tail {
            return None; // Empty
        }
        
        let item = self.buffer[head as usize].take();
        let next_head = (head + 1) & (self.capacity - 1);
        self.head.store(next_head, Ordering::Release);
        item
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }

    /// 要素数
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        ((tail + self.capacity - head) & (self.capacity - 1)) as usize
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// ネットワーク統計
#[derive(Debug, Default)]
pub struct NetworkStats {
    /// 受信パケット数
    pub rx_packets: AtomicU64,
    /// 送信パケット数
    pub tx_packets: AtomicU64,
    /// 受信バイト数
    pub rx_bytes: AtomicU64,
    /// 送信バイト数
    pub tx_bytes: AtomicU64,
    /// 受信エラー数
    pub rx_errors: AtomicU64,
    /// 送信エラー数
    pub tx_errors: AtomicU64,
    /// ドロップ数
    pub rx_dropped: AtomicU64,
    /// 割り込み数
    pub interrupts: AtomicU64,
    /// ポーリング回数
    pub poll_cycles: AtomicU64,
    /// モード切り替え回数
    pub mode_switches: AtomicU64,
}

impl NetworkStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// パケットレート（pps）を計算
    pub fn packets_per_second(&self, elapsed_ms: u64) -> u64 {
        if elapsed_ms == 0 {
            return 0;
        }
        let total = self.rx_packets.load(Ordering::Relaxed)
            + self.tx_packets.load(Ordering::Relaxed);
        total * 1000 / elapsed_ms
    }
}

// ============================================================================
// Adaptive Poller
// ============================================================================

/// 適応的ポーラー
pub struct AdaptivePoller {
    /// 現在のモード
    mode: PollingMode,
    /// 統計
    stats: NetworkStats,
    /// 最後の適応調整時刻
    last_adaptation: u64,
    /// 最後の統計スナップショット
    last_stats_snapshot: (u64, u64), // (rx, tx)
    /// 高閾値（カスタマイズ可能）
    threshold_high: u64,
    /// 低閾値（カスタマイズ可能）
    threshold_low: u64,
    /// ポーリングバジェット
    budget: usize,
    /// 割り込みマスク状態
    interrupts_masked: AtomicBool,
    /// アクティブフラグ
    active: AtomicBool,
}

impl AdaptivePoller {
    /// 新しい適応的ポーラーを作成
    pub fn new() -> Self {
        Self {
            mode: PollingMode::InterruptDriven,
            stats: NetworkStats::new(),
            last_adaptation: 0,
            last_stats_snapshot: (0, 0),
            threshold_high: POLLING_THRESHOLD_HIGH,
            threshold_low: POLLING_THRESHOLD_LOW,
            budget: POLL_BUDGET,
            interrupts_masked: AtomicBool::new(false),
            active: AtomicBool::new(true),
        }
    }

    /// 現在のモードを取得
    pub fn mode(&self) -> PollingMode {
        self.mode
    }

    /// 閾値を設定
    pub fn set_thresholds(&mut self, high: u64, low: u64) {
        self.threshold_high = high;
        self.threshold_low = low;
    }

    /// バジェットを設定
    pub fn set_budget(&mut self, budget: usize) {
        self.budget = budget;
    }

    /// 適応調整を実行
    pub fn adapt(&mut self, current_time_ms: u64) {
        // 調整間隔をチェック
        if current_time_ms - self.last_adaptation < ADAPTATION_INTERVAL_MS {
            return;
        }

        let elapsed = current_time_ms - self.last_adaptation;
        self.last_adaptation = current_time_ms;

        // 現在のパケットレートを計算
        let rx_now = self.stats.rx_packets.load(Ordering::Relaxed);
        let tx_now = self.stats.tx_packets.load(Ordering::Relaxed);
        let (rx_last, tx_last) = self.last_stats_snapshot;
        
        let packets = (rx_now - rx_last) + (tx_now - tx_last);
        let pps = packets * 1000 / elapsed;

        self.last_stats_snapshot = (rx_now, tx_now);

        // モード決定
        let new_mode = match self.mode {
            PollingMode::InterruptDriven => {
                if pps >= self.threshold_high {
                    PollingMode::BusyPolling
                } else if pps >= self.threshold_low {
                    PollingMode::Hybrid
                } else {
                    PollingMode::InterruptDriven
                }
            }
            PollingMode::Hybrid => {
                if pps >= self.threshold_high {
                    PollingMode::BusyPolling
                } else if pps < self.threshold_low / 2 {
                    PollingMode::InterruptDriven
                } else {
                    PollingMode::Hybrid
                }
            }
            PollingMode::BusyPolling => {
                if pps < self.threshold_low {
                    PollingMode::Hybrid
                } else {
                    PollingMode::BusyPolling
                }
            }
        };

        // モード切り替え
        if new_mode != self.mode {
            self.switch_mode(new_mode);
        }
    }

    /// モードを切り替え
    fn switch_mode(&mut self, new_mode: PollingMode) {
        match new_mode {
            PollingMode::InterruptDriven => {
                self.enable_interrupts();
            }
            PollingMode::Hybrid => {
                // ハイブリッド：割り込みは有効、ポーリングも併用
                self.enable_interrupts();
            }
            PollingMode::BusyPolling => {
                self.disable_interrupts();
            }
        }

        self.mode = new_mode;
        self.stats.mode_switches.fetch_add(1, Ordering::Relaxed);
    }

    /// 割り込みを有効化
    fn enable_interrupts(&self) {
        self.interrupts_masked.store(false, Ordering::Release);
        // 実際のハードウェア割り込み有効化はドライバが行う
    }

    /// 割り込みを無効化
    fn disable_interrupts(&self) {
        self.interrupts_masked.store(true, Ordering::Release);
        // 実際のハードウェア割り込み無効化はドライバが行う
    }

    /// 割り込みがマスクされているか
    pub fn interrupts_masked(&self) -> bool {
        self.interrupts_masked.load(Ordering::Acquire)
    }

    /// ポーリング処理を実行
    pub fn poll<F>(&mut self, mut process_packet: F) -> usize
    where
        F: FnMut() -> Option<usize>,
    {
        self.stats.poll_cycles.fetch_add(1, Ordering::Relaxed);

        let mut processed = 0;
        
        for _ in 0..self.budget {
            match process_packet() {
                Some(bytes) => {
                    processed += 1;
                    self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                    self.stats.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
                }
                None => break,
            }
        }

        processed
    }

    /// 統計を取得
    pub fn stats(&self) -> &NetworkStats {
        &self.stats
    }

    /// 割り込みハンドラから呼ばれる
    pub fn on_interrupt(&mut self) {
        self.stats.interrupts.fetch_add(1, Ordering::Relaxed);
        
        // ビジーポーリングモードでは割り込みを無視
        if self.mode == PollingMode::BusyPolling {
            return;
        }

        // ハイブリッドモードまたは割り込みモードでは
        // Wakerを起こして処理を促す
    }
}

// ============================================================================
// Polling Driver Interface
// ============================================================================

/// ポーリングドライバインターフェース
pub trait PollingDriver {
    /// 受信キューをポーリング
    fn poll_rx(&mut self, budget: usize) -> usize;
    
    /// 送信完了をポーリング
    fn poll_tx(&mut self, budget: usize) -> usize;
    
    /// 割り込みを有効化
    fn enable_interrupts(&mut self);
    
    /// 割り込みを無効化
    fn disable_interrupts(&mut self);
    
    /// リンク状態を取得
    fn link_up(&self) -> bool;
}

// ============================================================================
// NAPI-like Structure
// ============================================================================

/// NAPI風ポーリング構造体
pub struct NapiLike {
    /// 適応的ポーラー
    poller: AdaptivePoller,
    /// スケジュール状態
    scheduled: AtomicBool,
    /// 重み（相対的なCPU時間配分）
    weight: u32,
}

impl NapiLike {
    /// 新しいNAPI構造体を作成
    pub fn new(weight: u32) -> Self {
        Self {
            poller: AdaptivePoller::new(),
            scheduled: AtomicBool::new(false),
            weight,
        }
    }

    /// ポーリングをスケジュール
    pub fn schedule(&self) -> bool {
        self.scheduled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// スケジュールを完了
    pub fn complete(&self) {
        self.scheduled.store(false, Ordering::Release);
    }

    /// スケジュール済みかどうか
    pub fn is_scheduled(&self) -> bool {
        self.scheduled.load(Ordering::Acquire)
    }

    /// ポーラーを取得
    pub fn poller(&self) -> &AdaptivePoller {
        &self.poller
    }

    /// ポーラーを取得（可変）
    pub fn poller_mut(&mut self) -> &mut AdaptivePoller {
        &mut self.poller
    }
}

// ============================================================================
// Per-Core Polling
// ============================================================================

/// コアごとのポーリングコンテキスト
pub struct PerCorePolling {
    /// コアID
    core_id: u32,
    /// NAPI構造体のリスト
    napi_list: Vec<NapiLike>,
    /// アクティブフラグ
    active: AtomicBool,
    /// ポーリング中フラグ
    polling: AtomicBool,
}

impl PerCorePolling {
    /// 新しいコアポーリングコンテキストを作成
    pub fn new(core_id: u32) -> Self {
        Self {
            core_id,
            napi_list: Vec::new(),
            active: AtomicBool::new(true),
            polling: AtomicBool::new(false),
        }
    }

    /// NAPIを追加
    pub fn add_napi(&mut self, napi: NapiLike) {
        self.napi_list.push(napi);
    }

    /// ポーリングループを実行
    pub fn poll_loop<F>(&mut self, mut driver_poll: F)
    where
        F: FnMut(usize) -> usize,
    {
        if self.polling.swap(true, Ordering::AcqRel) {
            return; // Already polling
        }

        while self.active.load(Ordering::Acquire) {
            let mut work_done = 0;

            for napi in &mut self.napi_list {
                if napi.is_scheduled() {
                    let processed = napi.poller_mut().poll(|| {
                        let bytes = driver_poll(1);
                        if bytes > 0 {
                            Some(bytes)
                        } else {
                            None
                        }
                    });
                    work_done += processed;

                    // バジェットを使い切らなかったら完了
                    if processed < POLL_BUDGET {
                        napi.complete();
                    }
                }
            }

            // 何も処理しなかった場合はCPUを譲る
            if work_done == 0 {
                core::hint::spin_loop();
            }
        }

        self.polling.store(false, Ordering::Release);
    }

    /// ポーリングを停止
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }
}

// ============================================================================
// Busy Polling Socket Option
// ============================================================================

/// ビジーポーリング設定
#[derive(Debug, Clone, Copy)]
pub struct BusyPollConfig {
    /// ビジーポーリングを有効化
    pub enabled: bool,
    /// ポーリング時間（マイクロ秒）
    pub poll_us: u64,
    /// バジェット
    pub budget: usize,
}

impl Default for BusyPollConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_us: 50,
            budget: 8,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// グローバルな適応的ポーリングマネージャー
static POLLING_MANAGER: Mutex<Option<PollingManager>> = Mutex::new(None);

/// ポーリングマネージャー
pub struct PollingManager {
    /// コアごとのポーリングコンテキスト
    per_core: Vec<PerCorePolling>,
    /// グローバル統計
    global_stats: NetworkStats,
}

impl PollingManager {
    /// 新しいマネージャーを作成
    pub fn new(num_cores: u32) -> Self {
        let mut per_core = Vec::new();
        for i in 0..num_cores {
            per_core.push(PerCorePolling::new(i));
        }

        Self {
            per_core,
            global_stats: NetworkStats::new(),
        }
    }

    /// コアのポーリングコンテキストを取得
    pub fn get_core(&mut self, core_id: u32) -> Option<&mut PerCorePolling> {
        self.per_core.get_mut(core_id as usize)
    }

    /// グローバル統計を取得
    pub fn stats(&self) -> &NetworkStats {
        &self.global_stats
    }
}

/// ポーリングマネージャーを初期化
pub fn init(num_cores: u32) {
    let manager = PollingManager::new(num_cores);
    *POLLING_MANAGER.lock() = Some(manager);
}

/// ポーリングマネージャーにアクセス
pub fn with_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut PollingManager) -> R,
{
    POLLING_MANAGER.lock().as_mut().map(f)
}

// ============================================================================
// Async Future for Polling
// ============================================================================

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

/// 適応的ポーリングFuture
pub struct AdaptivePollFuture<F>
where
    F: FnMut() -> Option<usize>,
{
    poll_fn: F,
    config: BusyPollConfig,
    waker: Option<Waker>,
}

impl<F> AdaptivePollFuture<F>
where
    F: FnMut() -> Option<usize>,
{
    pub fn new(poll_fn: F, config: BusyPollConfig) -> Self {
        Self {
            poll_fn,
            config,
            waker: None,
        }
    }
}

impl<F> Future for AdaptivePollFuture<F>
where
    F: FnMut() -> Option<usize> + Unpin,
{
    type Output = usize;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Wakerを保存
        self.waker = Some(cx.waker().clone());

        // ビジーポーリング
        if self.config.enabled {
            for _ in 0..self.config.budget {
                if let Some(bytes) = (self.poll_fn)() {
                    return Poll::Ready(bytes);
                }
            }
        }

        // データがなければPending
        Poll::Pending
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polling_mode_default() {
        let poller = AdaptivePoller::new();
        assert_eq!(poller.mode(), PollingMode::InterruptDriven);
    }

    #[test]
    fn test_ring_buffer() {
        let mut ring: RingBuffer<u32> = RingBuffer::new(4);
        assert!(ring.is_empty());
        
        ring.push(1).unwrap();
        ring.push(2).unwrap();
        assert_eq!(ring.len(), 2);
        
        assert_eq!(ring.pop(), Some(1));
        assert_eq!(ring.pop(), Some(2));
        assert!(ring.is_empty());
    }

    #[test]
    fn test_network_stats() {
        let stats = NetworkStats::new();
        stats.rx_packets.fetch_add(100, Ordering::Relaxed);
        stats.tx_packets.fetch_add(50, Ordering::Relaxed);
        
        let pps = stats.packets_per_second(1000);
        assert_eq!(pps, 150);
    }
}
