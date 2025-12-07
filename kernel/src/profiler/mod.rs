//! システムプロファイラ
//!
//! ExoRust用の高精度プロファイリングシステム
//! - CPU使用率プロファイリング
//! - メモリプロファイリング
//! - I/Oレイテンシ測定
//! - フレームグラフ生成サポート

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

// =============================================================================
// 定数
// =============================================================================

/// 最大サンプル数
const MAX_SAMPLES: usize = 65536;

/// 最大コールスタック深度
const MAX_STACK_DEPTH: usize = 64;

/// ヒストグラムバケット数
const HISTOGRAM_BUCKETS: usize = 64;

// =============================================================================
// プロファイルタイプ
// =============================================================================

/// プロファイルモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileMode {
    /// CPU使用率
    Cpu,
    /// メモリ割り当て
    Memory,
    /// I/Oレイテンシ
    IoLatency,
    /// ロック競合
    LockContention,
    /// コンテキストスイッチ
    ContextSwitch,
    /// カスタムイベント
    Custom,
}

/// サンプルソース
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleSource {
    /// タイマー割り込み
    Timer,
    /// PMU (Performance Monitoring Unit)
    Pmu,
    /// ソフトウェアイベント
    Software,
    /// トレースポイント
    Tracepoint,
}

// =============================================================================
// コールスタック
// =============================================================================

/// スタックフレーム
#[derive(Debug, Clone, Copy)]
pub struct StackFrame {
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
}

impl StackFrame {
    pub const fn new(ip: u64, sp: u64, fp: u64) -> Self {
        Self {
            instruction_pointer: ip,
            stack_pointer: sp,
            frame_pointer: fp,
        }
    }
}

/// コールスタック
#[derive(Debug, Clone)]
pub struct CallStack {
    frames: Vec<StackFrame>,
    timestamp: u64,
}

impl CallStack {
    pub fn new() -> Self {
        Self {
            frames: Vec::with_capacity(MAX_STACK_DEPTH),
            timestamp: 0,
        }
    }

    pub fn capture() -> Self {
        let mut stack = Self::new();
        stack.timestamp = rdtsc();

        // スタックウォーク（x86_64）
        unsafe {
            let mut fp: u64;
            core::arch::asm!("mov {}, rbp", out(reg) fp);

            for _ in 0..MAX_STACK_DEPTH {
                if fp == 0 || fp & 0x7 != 0 {
                    break;
                }

                // 戻りアドレスはフレームポインタ + 8
                let ret_addr = core::ptr::read_volatile((fp + 8) as *const u64);
                let prev_fp = core::ptr::read_volatile(fp as *const u64);

                if ret_addr == 0 {
                    break;
                }

                stack.frames.push(StackFrame::new(ret_addr, 0, fp));
                fp = prev_fp;
            }
        }

        stack
    }

    pub fn frames(&self) -> &[StackFrame] {
        &self.frames
    }

    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

// =============================================================================
// サンプル
// =============================================================================

/// プロファイルサンプル
#[derive(Debug, Clone)]
pub struct ProfileSample {
    pub timestamp: u64,
    pub cpu_id: u32,
    pub task_id: u64,
    pub mode: ProfileMode,
    pub value: u64,
    pub stack: Option<CallStack>,
}

impl ProfileSample {
    pub fn new(mode: ProfileMode, value: u64) -> Self {
        Self {
            timestamp: rdtsc(),
            cpu_id: 0,
            task_id: 0,
            mode,
            value,
            stack: None,
        }
    }

    pub fn with_stack(mut self) -> Self {
        self.stack = Some(CallStack::capture());
        self
    }
}

// =============================================================================
// ヒストグラム
// =============================================================================

/// 対数ヒストグラム
#[derive(Debug)]
pub struct LogHistogram {
    buckets: [AtomicU64; HISTOGRAM_BUCKETS],
    min: AtomicU64,
    max: AtomicU64,
    sum: AtomicU64,
    count: AtomicU64,
}

impl LogHistogram {
    pub const fn new() -> Self {
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            buckets: [ZERO; HISTOGRAM_BUCKETS],
            min: AtomicU64::new(u64::MAX),
            max: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// 値を追加
    pub fn record(&self, value: u64) {
        // バケットインデックスを計算（対数スケール）
        let bucket = if value == 0 {
            0
        } else {
            (64 - value.leading_zeros()) as usize
        };
        let bucket = bucket.min(HISTOGRAM_BUCKETS - 1);

        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.min.fetch_min(value, Ordering::Relaxed);
        self.max.fetch_max(value, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// 統計を取得
    pub fn stats(&self) -> HistogramStats {
        let count = self.count.load(Ordering::Relaxed);
        let sum = self.sum.load(Ordering::Relaxed);
        let min = self.min.load(Ordering::Relaxed);
        let max = self.max.load(Ordering::Relaxed);

        HistogramStats {
            count,
            min: if min == u64::MAX { 0 } else { min },
            max,
            mean: if count > 0 { sum / count } else { 0 },
            p50: self.percentile(50),
            p95: self.percentile(95),
            p99: self.percentile(99),
        }
    }

    /// パーセンタイル値を計算
    pub fn percentile(&self, p: u32) -> u64 {
        let total = self.count.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }

        let target = (total as u128 * p as u128 / 100) as u64;
        let mut cumulative = 0u64;

        for (i, bucket) in self.buckets.iter().enumerate() {
            cumulative += bucket.load(Ordering::Relaxed);
            if cumulative >= target {
                // バケットの中央値を返す
                return if i == 0 { 0 } else { 1u64 << (i - 1) };
            }
        }

        self.max.load(Ordering::Relaxed)
    }

    /// リセット
    pub fn reset(&self) {
        for bucket in &self.buckets {
            bucket.store(0, Ordering::Relaxed);
        }
        self.min.store(u64::MAX, Ordering::Relaxed);
        self.max.store(0, Ordering::Relaxed);
        self.sum.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
    }
}

/// ヒストグラム統計
#[derive(Debug, Clone)]
pub struct HistogramStats {
    pub count: u64,
    pub min: u64,
    pub max: u64,
    pub mean: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
}

// =============================================================================
// CPUプロファイラ
// =============================================================================

/// CPUプロファイラ
pub struct CpuProfiler {
    samples: Mutex<Vec<ProfileSample>>,
    enabled: AtomicBool,
    sample_rate_hz: AtomicU64,

    // 集計データ
    function_hits: RwLock<BTreeMap<u64, u64>>,

    // 統計
    total_samples: AtomicU64,
    dropped_samples: AtomicU64,
}

impl CpuProfiler {
    pub const fn new() -> Self {
        Self {
            samples: Mutex::new(Vec::new()),
            enabled: AtomicBool::new(false),
            sample_rate_hz: AtomicU64::new(1000), // デフォルト: 1kHz
            function_hits: RwLock::new(BTreeMap::new()),
            total_samples: AtomicU64::new(0),
            dropped_samples: AtomicU64::new(0),
        }
    }

    /// プロファイリングを開始
    pub fn start(&self, sample_rate_hz: u64) {
        self.sample_rate_hz.store(sample_rate_hz, Ordering::SeqCst);
        self.enabled.store(true, Ordering::SeqCst);
    }

    /// プロファイリングを停止
    pub fn stop(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    /// サンプルを記録
    pub fn record_sample(&self) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let sample = ProfileSample::new(ProfileMode::Cpu, 1).with_stack();

        let mut samples = self.samples.lock();
        if samples.len() < MAX_SAMPLES {
            // スタックのトップアドレスを集計
            if let Some(ref stack) = sample.stack {
                if let Some(frame) = stack.frames().first() {
                    let mut hits = self.function_hits.write();
                    *hits.entry(frame.instruction_pointer).or_insert(0) += 1;
                }
            }

            samples.push(sample);
            self.total_samples.fetch_add(1, Ordering::Relaxed);
        } else {
            self.dropped_samples.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// サンプルをクリア
    pub fn clear(&self) {
        self.samples.lock().clear();
        self.function_hits.write().clear();
    }

    /// ホットスポットを取得
    pub fn hot_spots(&self, limit: usize) -> Vec<(u64, u64)> {
        let hits = self.function_hits.read();
        let mut sorted: Vec<_> = hits.iter().map(|(&k, &v)| (k, v)).collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(limit);
        sorted
    }

    /// 統計を取得
    pub fn stats(&self) -> CpuProfilerStats {
        CpuProfilerStats {
            total_samples: self.total_samples.load(Ordering::Relaxed),
            dropped_samples: self.dropped_samples.load(Ordering::Relaxed),
            sample_rate_hz: self.sample_rate_hz.load(Ordering::Relaxed),
            unique_locations: self.function_hits.read().len(),
        }
    }
}

/// CPUプロファイラ統計
#[derive(Debug, Clone)]
pub struct CpuProfilerStats {
    pub total_samples: u64,
    pub dropped_samples: u64,
    pub sample_rate_hz: u64,
    pub unique_locations: usize,
}

// =============================================================================
// メモリプロファイラ
// =============================================================================

/// メモリ割り当てイベント
#[derive(Debug, Clone, Copy)]
pub enum AllocEvent {
    Alloc { size: usize, align: usize },
    Dealloc { size: usize, align: usize },
    Realloc { old_size: usize, new_size: usize },
}

/// メモリプロファイラ
pub struct MemoryProfiler {
    events: Mutex<Vec<(u64, AllocEvent, Option<CallStack>)>>,
    enabled: AtomicBool,

    // 統計
    total_allocated: AtomicU64,
    total_freed: AtomicU64,
    current_allocated: AtomicU64,
    peak_allocated: AtomicU64,
    alloc_count: AtomicU64,
    free_count: AtomicU64,

    // サイズ別ヒストグラム
    size_histogram: LogHistogram,
}

impl MemoryProfiler {
    pub const fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            enabled: AtomicBool::new(false),
            total_allocated: AtomicU64::new(0),
            total_freed: AtomicU64::new(0),
            current_allocated: AtomicU64::new(0),
            peak_allocated: AtomicU64::new(0),
            alloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            size_histogram: LogHistogram::new(),
        }
    }

    /// プロファイリングを開始
    pub fn start(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    /// プロファイリングを停止
    pub fn stop(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    /// 割り当てを記録
    pub fn record_alloc(&self, size: usize, align: usize) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let event = AllocEvent::Alloc { size, align };
        let stack = CallStack::capture();

        self.events.lock().push((rdtsc(), event, Some(stack)));

        self.total_allocated
            .fetch_add(size as u64, Ordering::Relaxed);
        self.alloc_count.fetch_add(1, Ordering::Relaxed);

        let current = self
            .current_allocated
            .fetch_add(size as u64, Ordering::Relaxed)
            + size as u64;
        self.peak_allocated.fetch_max(current, Ordering::Relaxed);

        self.size_histogram.record(size as u64);
    }

    /// 解放を記録
    pub fn record_dealloc(&self, size: usize, align: usize) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let event = AllocEvent::Dealloc { size, align };

        self.events.lock().push((rdtsc(), event, None));

        self.total_freed.fetch_add(size as u64, Ordering::Relaxed);
        self.free_count.fetch_add(1, Ordering::Relaxed);
        self.current_allocated
            .fetch_sub(size as u64, Ordering::Relaxed);
    }

    /// 統計を取得
    pub fn stats(&self) -> MemoryProfilerStats {
        MemoryProfilerStats {
            total_allocated: self.total_allocated.load(Ordering::Relaxed),
            total_freed: self.total_freed.load(Ordering::Relaxed),
            current_allocated: self.current_allocated.load(Ordering::Relaxed),
            peak_allocated: self.peak_allocated.load(Ordering::Relaxed),
            alloc_count: self.alloc_count.load(Ordering::Relaxed),
            free_count: self.free_count.load(Ordering::Relaxed),
            size_histogram: self.size_histogram.stats(),
        }
    }

    /// イベントをクリア
    pub fn clear(&self) {
        self.events.lock().clear();
    }
}

/// メモリプロファイラ統計
#[derive(Debug, Clone)]
pub struct MemoryProfilerStats {
    pub total_allocated: u64,
    pub total_freed: u64,
    pub current_allocated: u64,
    pub peak_allocated: u64,
    pub alloc_count: u64,
    pub free_count: u64,
    pub size_histogram: HistogramStats,
}

// =============================================================================
// レイテンシプロファイラ
// =============================================================================

/// レイテンシプロファイラ
pub struct LatencyProfiler {
    histograms: RwLock<BTreeMap<String, Arc<LogHistogram>>>,
    enabled: AtomicBool,
}

impl LatencyProfiler {
    pub const fn new() -> Self {
        Self {
            histograms: RwLock::new(BTreeMap::new()),
            enabled: AtomicBool::new(false),
        }
    }

    /// プロファイリングを開始
    pub fn start(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    /// プロファイリングを停止
    pub fn stop(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    /// ヒストグラムを取得または作成
    pub fn histogram(&self, name: &str) -> Arc<LogHistogram> {
        {
            let histograms = self.histograms.read();
            if let Some(h) = histograms.get(name) {
                return h.clone();
            }
        }

        let mut histograms = self.histograms.write();
        histograms
            .entry(name.into())
            .or_insert_with(|| Arc::new(LogHistogram::new()))
            .clone()
    }

    /// レイテンシを記録
    pub fn record(&self, name: &str, latency_ns: u64) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        self.histogram(name).record(latency_ns);
    }

    /// スコープ測定用ガード
    pub fn scope(&self, name: &'static str) -> LatencyScope<'_> {
        LatencyScope {
            profiler: self,
            name,
            start: rdtsc(),
        }
    }

    /// 全ヒストグラムの統計を取得
    pub fn all_stats(&self) -> BTreeMap<String, HistogramStats> {
        self.histograms
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.stats()))
            .collect()
    }
}

/// レイテンシ測定スコープ
pub struct LatencyScope<'a> {
    profiler: &'a LatencyProfiler,
    name: &'static str,
    start: u64,
}

impl<'a> Drop for LatencyScope<'a> {
    fn drop(&mut self) {
        let elapsed = rdtsc() - self.start;
        // TSCをナノ秒に変換（簡略化: 3GHz仮定）
        let ns = elapsed * 1000 / 3000;
        self.profiler.record(self.name, ns);
    }
}

// =============================================================================
// 統合プロファイラ
// =============================================================================

/// 統合プロファイラ
pub struct Profiler {
    pub cpu: CpuProfiler,
    pub memory: MemoryProfiler,
    pub latency: LatencyProfiler,
}

impl Profiler {
    pub const fn new() -> Self {
        Self {
            cpu: CpuProfiler::new(),
            memory: MemoryProfiler::new(),
            latency: LatencyProfiler::new(),
        }
    }

    /// 全プロファイリングを開始
    pub fn start_all(&self, cpu_sample_rate: u64) {
        self.cpu.start(cpu_sample_rate);
        self.memory.start();
        self.latency.start();
    }

    /// 全プロファイリングを停止
    pub fn stop_all(&self) {
        self.cpu.stop();
        self.memory.stop();
        self.latency.stop();
    }

    /// レポートを生成
    pub fn report(&self) -> ProfileReport {
        ProfileReport {
            cpu_stats: self.cpu.stats(),
            memory_stats: self.memory.stats(),
            latency_stats: self.latency.all_stats(),
            hot_spots: self.cpu.hot_spots(20),
        }
    }
}

/// プロファイルレポート
#[derive(Debug)]
pub struct ProfileReport {
    pub cpu_stats: CpuProfilerStats,
    pub memory_stats: MemoryProfilerStats,
    pub latency_stats: BTreeMap<String, HistogramStats>,
    pub hot_spots: Vec<(u64, u64)>,
}

// =============================================================================
// ユーティリティ
// =============================================================================

/// TSCを読み取り
#[inline]
fn rdtsc() -> u64 {
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem)
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}

/// TSCPを読み取り（シリアライズ）
#[inline]
#[allow(dead_code)]
fn rdtscp() -> (u64, u32) {
    unsafe {
        let lo: u32;
        let hi: u32;
        let aux: u32;
        core::arch::asm!(
            "rdtscp",
            out("eax") lo,
            out("edx") hi,
            out("ecx") aux,
            options(nostack, nomem)
        );
        (((hi as u64) << 32) | (lo as u64), aux)
    }
}

// =============================================================================
// グローバルインスタンス
// =============================================================================

static PROFILER: spin::Once<Profiler> = spin::Once::new();

pub fn profiler() -> &'static Profiler {
    PROFILER.call_once(Profiler::new)
}

/// プロファイラを初期化
pub fn init() {
    let _ = profiler();
}

/// CPUプロファイリングを開始
pub fn start_cpu_profiling(sample_rate_hz: u64) {
    profiler().cpu.start(sample_rate_hz);
}

/// 全プロファイリングを開始
pub fn start_all(cpu_sample_rate: u64) {
    profiler().start_all(cpu_sample_rate);
}

/// 全プロファイリングを停止
pub fn stop_all() {
    profiler().stop_all();
}

/// レポートを取得
pub fn report() -> ProfileReport {
    profiler().report()
}

/// レイテンシ測定マクロ用
#[macro_export]
macro_rules! profile_latency {
    ($name:expr) => {
        let _guard = $crate::profiler::profiler().latency.scope($name);
    };
}
