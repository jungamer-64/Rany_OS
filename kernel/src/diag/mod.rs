// ============================================================================
// src/diag/mod.rs - 低レベル診断・ベンチマークシステム
// ============================================================================
//!
//! # 低レベル診断・ベンチマークシステム
//!
//! カーネルの低レベルパフォーマンス測定およびデバッグ支援機能を提供。
//!
//! ## 責務（本モジュール固有）
//! - TSCベースの時間計測 (`rdtsc`, `MeasureScope`)
//! - 統計ヒストグラム (`Histogram`)
//! - パフォーマンスカウンタ (`PerfStats`)
//! - リソースモニタリング (`ResourceMonitor`)
//! - トレースポイント / リングバッファ (`TraceBuffer`)
//! - マイクロベンチマーク (`BenchmarkRunner`)
//!
//! ## 関連モジュール（可観測性ファミリー）
//! - `profiler/` — サンプリングベースCPU/メモリ/I/Oプロファイリング
//! - `monitor/` — システムスナップショット・ダッシュボード
//!
//! CPUプロファイリング機能は `profiler::CpuProfiler` に統合されており、
//! 本モジュールには含まれません。
use crate::sync::PoisonLock;
use crate::time::rdtsc;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// ============================================================================
// Time Measurement
// ============================================================================

mod accessors;
// The accessors module provides helpers that may be consumed by
// other crates/tests. We don't re-export its contents here to
// avoid unused-import warnings, though the module is kept for
// organization and future use.

/// 高精度タイムスタンプ（RDTSCP）
#[inline(always)]
pub fn rdtscp() -> (u64, u32) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        let aux: u32;
        core::arch::asm!(
            "rdtscp",
            out("eax") lo,
            out("edx") hi,
            out("ecx") aux,
            options(nomem, nostack)
        );
        (((hi as u64) << 32) | (lo as u64), aux)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        (0, 0)
    }
}

/// 計測スコープ
pub struct MeasureScope {
    start: u64,
    name: &'static str,
}

impl MeasureScope {
    pub fn new(name: &'static str) -> Self {
        Self {
            start: crate::time::rdtsc(),
            name,
        }
    }

    /// 経過サイクルを取得
    pub fn elapsed_cycles(&self) -> u64 {
        crate::time::rdtsc().saturating_sub(self.start)
    }
}

impl Drop for MeasureScope {
    fn drop(&mut self) {
        let cycles = self.elapsed_cycles();
        // 統計に記録
        if let Some(ref stats) = *PERF_STATS.lock().unwrap_or_else(|e| e.into_inner()) {
            stats.record(self.name, cycles);
        }
    }
}

/// 計測マクロ
#[macro_export]
macro_rules! measure {
    ($name:expr, $block:block) => {{
        let _scope = $crate::diag::MeasureScope::new($name);
        $block
    }};
}

// ============================================================================
// Histogram
// ============================================================================

/// レイテンシヒストグラム
pub struct Histogram {
    /// バケット（対数スケール）
    buckets: [AtomicU64; 64],
    /// 合計
    sum: AtomicU64,
    /// カウント
    count: AtomicU64,
    /// 最小値
    min: AtomicU64,
    /// 最大値
    max: AtomicU64,
}

impl Histogram {
    pub const fn new() -> Self {
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            buckets: [ZERO; 64],
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
            min: AtomicU64::new(u64::MAX),
            max: AtomicU64::new(0),
        }
    }

    /// 値を記録
    pub fn record(&self, value: u64) {
        // バケットインデックスを計算（対数スケール）
        let bucket_idx = if value == 0 {
            0
        } else {
            (64 - value.leading_zeros()) as usize
        };
        let bucket_idx = bucket_idx.min(63);

        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // 最小値更新
        let mut current_min = self.min.load(Ordering::Relaxed);
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while value < current_min {
            match self.min.compare_exchange_weak(
                current_min,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => current_min = v,
            }
        }

        // 最大値更新
        let mut current_max = self.max.load(Ordering::Relaxed);
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while value > current_max {
            match self.max.compare_exchange_weak(
                current_max,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => current_max = v,
            }
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> HistogramStats {
        let count = self.count.load(Ordering::Relaxed);
        let sum = self.sum.load(Ordering::Relaxed);
        let min = self.min.load(Ordering::Relaxed);
        let max = self.max.load(Ordering::Relaxed);

        HistogramStats {
            count,
            sum,
            min: if count > 0 { min } else { 0 },
            max: if count > 0 { max } else { 0 },
            avg: if count > 0 { sum / count } else { 0 },
        }
    }

    /// パーセンタイルを計算
    pub fn percentile(&self, p: f64) -> u64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return 0;
        }

        let target = (count as f64 * p / 100.0) as u64;
        let mut cumulative = 0u64;

        for (i, bucket) in self.buckets.iter().enumerate() {
            cumulative += bucket.load(Ordering::Relaxed);
            if cumulative >= target {
                return 1u64 << i;
            }
        }

        self.max.load(Ordering::Relaxed)
    }

    /// リセット
    pub fn reset(&self) {
        for bucket in &self.buckets {
            bucket.store(0, Ordering::Relaxed);
        }
        self.sum.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
        self.min.store(u64::MAX, Ordering::Relaxed);
        self.max.store(0, Ordering::Relaxed);
    }
}

/// ヒストグラム統計
#[derive(Debug, Clone, Copy)]
pub struct HistogramStats {
    pub count: u64,
    pub sum: u64,
    pub min: u64,
    pub max: u64,
    pub avg: u64,
}

// ============================================================================
// Performance Statistics
// ============================================================================

/// パフォーマンス統計コレクション
pub struct PerfStats {
    /// 名前付きヒストグラム
    histograms: PoisonLock<BTreeMap<&'static str, Box<Histogram>>>,
    /// カウンタ
    counters: PoisonLock<BTreeMap<&'static str, AtomicU64>>,
}

impl PerfStats {
    pub fn new() -> Self {
        Self {
            histograms: PoisonLock::new(BTreeMap::new()),
            counters: PoisonLock::new(BTreeMap::new()),
        }
    }

    /// 値を記録
    pub fn record(&self, name: &'static str, value: u64) {
        let mut histograms = self.histograms.lock().unwrap_or_else(|e| e.into_inner());
        if !histograms.contains_key(name) {
            histograms.insert(name, Box::new(Histogram::new()));
        }
        if let Some(hist) = histograms.get(name) {
            hist.record(value);
        }
    }

    /// カウンタをインクリメント
    pub fn increment(&self, name: &'static str) {
        self.add(name, 1);
    }

    /// カウンタに加算
    pub fn add(&self, name: &'static str, value: u64) {
        let mut counters = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(counter) = counters.get(name) {
            counter.fetch_add(value, Ordering::Relaxed);
        } else {
            let counter = AtomicU64::new(value);
            counters.insert(name, counter);
        }
    }

    /// ヒストグラム統計を取得
    pub fn get_histogram_stats(&self, name: &'static str) -> Option<HistogramStats> {
        self.histograms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .map(|h| h.stats())
    }

    /// カウンタ値を取得
    pub fn get_counter(&self, name: &'static str) -> u64 {
        self.counters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// すべてのヒストグラム名を取得
    pub fn histogram_names(&self) -> Vec<&'static str> {
        self.histograms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// すべてのカウンタ名を取得
    pub fn counter_names(&self) -> Vec<&'static str> {
        self.counters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }
}

// ============================================================================
// Resource Monitor
// ============================================================================

/// リソース使用量スナップショット
#[derive(Debug, Clone, Default)]
pub struct ResourceSnapshot {
    /// 使用メモリ（バイト）
    pub memory_used: u64,
    /// 空きメモリ（バイト）
    pub memory_free: u64,
    /// CPU使用率（パーセント * 100）
    pub cpu_usage: u32,
    /// I/O読み取りバイト
    pub io_read_bytes: u64,
    /// I/O書き込みバイト
    pub io_write_bytes: u64,
    /// ネットワーク受信バイト
    pub net_rx_bytes: u64,
    /// ネットワーク送信バイト
    pub net_tx_bytes: u64,
    /// タスク数
    pub task_count: u32,
    /// タイムスタンプ
    pub timestamp: u64,
}

/// リソースモニター
pub struct ResourceMonitor {
    /// 最新のスナップショット
    latest: PoisonLock<ResourceSnapshot>,
    /// 履歴
    history: PoisonLock<Vec<ResourceSnapshot>>,
    /// 履歴の最大サイズ
    history_max: usize,
    /// サンプリング間隔（サイクル）
    sample_interval: AtomicU64,
    /// 最後のサンプリング時刻
    last_sample: AtomicU64,
}

impl ResourceMonitor {
    pub fn new(history_max: usize) -> Self {
        Self {
            latest: PoisonLock::new(ResourceSnapshot::default()),
            history: PoisonLock::new(Vec::with_capacity(history_max)),
            history_max,
            sample_interval: AtomicU64::new(1_000_000_000), // 1秒相当
            last_sample: AtomicU64::new(0),
        }
    }

    /// スナップショットを更新
    pub fn update(&self, snapshot: ResourceSnapshot) {
        let now = rdtsc();
        let last = self.last_sample.load(Ordering::Relaxed);
        let interval = self.sample_interval.load(Ordering::Relaxed);

        // 間隔チェック
        if now.saturating_sub(last) < interval {
            return;
        }

        self.last_sample.store(now, Ordering::Relaxed);

        let mut latest = self.latest.lock().unwrap_or_else(|e| e.into_inner());
        *latest = snapshot.clone();

        let mut history = self.history.lock().unwrap_or_else(|e| e.into_inner());
        if history.len() >= self.history_max {
            history.remove(0);
        }
        history.push(snapshot);
    }

    /// 最新のスナップショットを取得
    pub fn latest(&self) -> ResourceSnapshot {
        self.latest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 履歴を取得
    pub fn history(&self) -> Vec<ResourceSnapshot> {
        self.history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// サンプリング間隔を設定
    pub fn set_sample_interval(&self, interval: u64) {
        self.sample_interval.store(interval, Ordering::Relaxed);
    }
}

// ============================================================================
// Trace Points
// ============================================================================

/// トレースポイントID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TracePointId(pub u32);

/// トレースイベント
#[derive(Debug, Clone)]
pub struct TraceEvent {
    pub id: TracePointId,
    pub timestamp: u64,
    pub cpu: u32,
    pub data: u64,
}

/// トレースバッファ
pub struct TraceBuffer {
    /// イベントバッファ
    events: PoisonLock<Vec<TraceEvent>>,
    /// 最大サイズ
    max_events: usize,
    /// 有効フラグ
    enabled: AtomicBool,
    /// ドロップカウント
    dropped: AtomicU64,
}

impl TraceBuffer {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: PoisonLock::new(Vec::with_capacity(max_events)),
            max_events,
            enabled: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
        }
    }

    /// トレースを有効化
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// トレースを無効化
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// イベントを記録
    pub fn record(&self, id: TracePointId, cpu: u32, data: u64) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }

        let event = TraceEvent {
            id,
            timestamp: rdtsc(),
            cpu,
            data,
        };

        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if events.len() >= self.max_events {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            events.remove(0);
        }
        events.push(event);
    }

    /// イベントを取得してクリア
    pub fn drain(&self) -> Vec<TraceEvent> {
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        core::mem::take(&mut *events)
    }

    /// ドロップカウントを取得
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// トレースマクロ
#[macro_export]
macro_rules! trace_point {
    ($id:expr, $cpu:expr, $data:expr) => {
        $crate::diag::with_trace_buffer(|buf| {
            buf.record($crate::diag::TracePointId($id), $cpu, $data);
        });
    };
}

// ============================================================================
// Micro-Benchmark Framework (diag固有)
// ============================================================================

/// マイクロベンチマーク結果（サイクル単位）
#[derive(Debug, Clone)]
pub struct MicroBenchmarkResult {
    pub name: String,
    pub iterations: u64,
    pub total_cycles: u64,
    pub cycles_per_op: u64,
    pub min_cycles: u64,
    pub max_cycles: u64,
}

/// マイクロベンチマークランナー（サイクル単位の低レベル計測）
pub struct MicroBenchmarkRunner;

impl MicroBenchmarkRunner {
    /// マイクロベンチマークを実行（サイクル単位）
    pub fn run<F>(name: &str, iterations: u64, mut f: F) -> MicroBenchmarkResult
    where
        F: FnMut(),
    {
        // ウォームアップ
        for _ in 0..100 {
            f();
        }

        let mut min = u64::MAX;
        let mut max = 0u64;
        let mut total = 0u64;

        for _ in 0..iterations {
            let start = rdtsc();
            f();
            let elapsed = rdtsc().saturating_sub(start);

            total += elapsed;
            min = min.min(elapsed);
            max = max.max(elapsed);
        }

        MicroBenchmarkResult {
            name: String::from(name),
            iterations,
            total_cycles: total,
            cycles_per_op: total / iterations,
            min_cycles: min,
            max_cycles: max,
        }
    }

    /// スループットベンチマーク
    pub fn throughput<F>(name: &str, duration_cycles: u64, mut f: F) -> ThroughputResult
    where
        F: FnMut() -> u64, // 処理したバイト数を返す
    {
        let start = rdtsc();
        let mut total_bytes = 0u64;
        let mut ops = 0u64;

        while rdtsc().saturating_sub(start) < duration_cycles {
            total_bytes += f();
            ops += 1;
        }

        let elapsed = rdtsc().saturating_sub(start);

        ThroughputResult {
            name: String::from(name),
            total_bytes,
            total_ops: ops,
            elapsed_cycles: elapsed,
            bytes_per_cycle: if elapsed > 0 {
                total_bytes / elapsed
            } else {
                0
            },
        }
    }
}

/// スループット結果
#[derive(Debug, Clone)]
pub struct ThroughputResult {
    pub name: String,
    pub total_bytes: u64,
    pub total_ops: u64,
    pub elapsed_cycles: u64,
    pub bytes_per_cycle: u64,
}

// ============================================================================
// Global Instances
// ============================================================================

static PERF_STATS: PoisonLock<Option<PerfStats>> = PoisonLock::new(None);
static RESOURCE_MONITOR: PoisonLock<Option<ResourceMonitor>> = PoisonLock::new(None);
static TRACE_BUFFER: PoisonLock<Option<TraceBuffer>> = PoisonLock::new(None);

/// 診断システムを初期化
pub fn init() {
    *PERF_STATS.lock().unwrap_or_else(|e| e.into_inner()) = Some(PerfStats::new());
    *RESOURCE_MONITOR.lock().unwrap_or_else(|e| e.into_inner()) = Some(ResourceMonitor::new(1000));
    *TRACE_BUFFER.lock().unwrap_or_else(|e| e.into_inner()) = Some(TraceBuffer::new(10000));
}
