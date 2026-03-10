// ============================================================================
// src/io/io_scheduler.rs - Polling/Executor連携 I/Oスケジューラ
// ============================================================================
//
// 設計目標:
// 1. 負荷適応型のポーリング/割り込み切り替え
// 2. Futureベースの非同期I/O統合
// 3. デバイス横断の統一的なI/Oスケジューリング
// 4. 割り込みからWakerへのブリッジ
// ============================================================================

#![allow(dead_code)]

use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

// ============================================================================
// I/O Operation Types
// ============================================================================

/// I/O操作の種類
mod scheduler_impl;
pub use scheduler_impl::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperationType {
    /// 読み取り
    Read,
    /// 書き込み
    Write,
    /// フラッシュ
    Flush,
    /// IOCTL
    Ioctl,
    /// ポーリング
    Poll,
    /// カスタム操作
    Custom(u32),
}

/// I/O操作の優先度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IoPriority {
    /// バックグラウンド（最低）
    Background = 0,
    /// アイドル
    Idle = 1,
    /// 通常
    Normal = 2,
    /// 高優先度
    High = 3,
    /// リアルタイム（最高）
    Realtime = 4,
}

impl Default for IoPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// I/O操作の状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoState {
    /// キュー待ち
    Pending,
    /// 実行中
    InProgress,
    /// 完了
    Completed,
    /// エラー
    Failed,
    /// キャンセル
    Cancelled,
}

// ============================================================================
// I/O Request
// ============================================================================

/// I/Oリクエスト識別子
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IoRequestId(pub u64);

impl IoRequestId {
    fn next() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

/// デバイス識別子
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceId {
    /// NVMe デバイス
    Nvme { controller: u8, namespace: u32 },
    /// VirtIO ブロック
    VirtioBlk { index: u8 },
    /// VirtIO ネットワーク
    VirtioNet { index: u8 },
    /// AHCI/SATA
    Ahci { port: u8 },
    /// USB
    Usb { bus: u8, device: u8 },
    /// カスタム
    Custom(u32),
}

// ============================================================================
// Device-Neutral I/O Command (新設計)
// ============================================================================

/// DMA バッファハンドル（IOVA + 長さ）
#[derive(Debug, Clone, Copy)]
pub struct DmaBufHandle {
    /// デバイス可視アドレス (IOVA)
    pub iova: u64,
    /// バッファサイズ
    pub len: usize,
}

/// デバイス操作トレイト（抽象化レイヤー）
///
/// ドライバはこのトレイトを実装して、具体的なI/O処理を提供する。
/// スケジューラはデバイスの詳細（PCI/MMIO等）を知らずにこのトレイトを通じて操作する。
pub trait DeviceOps: Send + Sync {
    /// リクエストをサブミット（非同期）
    ///
    /// * `req`: I/Oリクエスト
    /// * `cpu_idx`: 送信元CPUのインデックス（0-based, contiguous）
    fn submit(&self, req: &IoRequest, cpu_idx: usize) -> Result<(), IoError>;

    /// デバイスが準備完了か
    fn is_ready(&self) -> bool;
}

/// I/Oコマンド（デバイス中立）
///
/// `DeviceOps::submit` 内でドライバが変換する。
#[derive(Debug, Clone)]
pub enum IoCommand {
    /// ブロック読み取り（連続バッファ）
    BlockRead {
        lba: u64,
        blocks: u16,
        bytes: usize,
        buf: DmaBufHandle,
    },
    /// ブロック書き込み（連続バッファ）
    BlockWrite {
        lba: u64,
        blocks: u16,
        bytes: usize,
        buf: DmaBufHandle,
    },
    /// キャッシュフラッシュ
    Flush,
    /// TRIM/Discard
    Discard { lba: u64, blocks: u16 },
    /// デバイス固有コマンド（ioctl的）
    ///
    /// コードとバッファの解釈はデバイスドライバに委ねられる
    Ioctl { code: u32, buf: DmaBufHandle },
}

// ============================================================================
// Legacy I/O Payload (後方互換用)
// ============================================================================

// Legacy `IoPayload` removed - use `IoCommand` variants instead.
// (Removed types: IoPayload, NvmeRwPayload, NvmeSglPayload, NvmeDsmPayload)

/// NVMe SGL ディスクリプタ（I/Oスケジューラ用）
#[derive(Debug, Clone, Copy)]
pub struct NvmeSglDescriptor {
    pub addr: u64,
    pub length: u32,
    pub type_specific: u8,
}

impl NvmeSglDescriptor {
    pub fn data_block(addr: u64, length: u32) -> Self {
        Self {
            addr,
            length,
            type_specific: 0x00 << 4,
        }
    }

    pub fn last_segment(addr: u64, length: u32) -> Self {
        Self {
            addr,
            length,
            type_specific: 0x03 << 4,
        }
    }
}

/// I/Oリクエスト記述子
#[derive(Clone)]
pub struct IoRequest {
    /// リクエストID
    pub id: IoRequestId,
    /// デバイスID
    pub device: DeviceId,
    /// 操作タイプ
    pub operation: IoOperationType,
    /// デバイス中立コマンド（新API）
    pub command: Option<IoCommand>,
    /// 優先度
    pub priority: IoPriority,
    /// 状態
    pub state: IoState,
    /// 開始時刻 (tick)
    pub submitted_at: u64,
    /// 完了時刻 (tick)
    pub completed_at: Option<u64>,
    /// Waker（完了通知用）
    pub waker: Option<Waker>,
    /// 結果
    pub result: Option<IoResult>,
    /// 呼び出し側が破棄済みか
    pub abandoned: bool,
}

/// I/O結果
#[derive(Debug, Clone)]
pub enum IoResult {
    /// 成功（転送バイト数）
    Success(usize),
    /// エラー
    Error(IoError),
}

/// I/Oエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    /// デバイスエラー
    DeviceError,
    /// タイムアウト
    Timeout,
    /// キャンセル
    Cancelled,
    /// 無効なパラメータ
    InvalidParameter,
    /// リソース不足
    NoResources,
    /// デバイスビジー
    Busy,
    /// 未サポート
    NotSupported,
}

/// I/O完了フック
pub trait IoCompletionHook: Send {
    fn run(self: Box<Self>, result: IoResult);
}

impl<F> IoCompletionHook for F
where
    F: FnOnce(IoResult) + Send + 'static,
{
    fn run(self: Box<Self>, result: IoResult) {
        (*self)(result);
    }
}

/// I/O完了フック型
pub type CompletionHook = Box<dyn IoCompletionHook>;

// ============================================================================
// Adaptive I/O Mode Controller
// ============================================================================

/// I/Oモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoMode {
    /// 割り込みモード（低負荷時）
    Interrupt,
    /// ポーリングモード（高負荷時）
    Polling,
    /// ハイブリッドモード（適応型）
    Hybrid,
}

/// モード切り替えの閾値設定
#[derive(Debug, Clone)]
pub struct ModeThresholds {
    /// ポーリングへ切り替えるIOPS閾値
    pub polling_threshold_iops: u64,
    /// 割り込みへ切り替えるIOPS閾値
    pub interrupt_threshold_iops: u64,
    /// ポーリングへ切り替えるレイテンシ閾値（μs）
    pub polling_threshold_latency_us: u64,
    /// 割り込みへ切り替えるレイテンシ閾値（μs）
    pub interrupt_threshold_latency_us: u64,
    /// モード切り替え判定間隔（tick）
    pub evaluation_interval: u64,
    /// ヒステリシス回数
    pub hysteresis_count: u32,
}

impl Default for ModeThresholds {
    fn default() -> Self {
        Self {
            polling_threshold_iops: 50_000,      // 50k IOPS
            interrupt_threshold_iops: 10_000,    // 10k IOPS
            polling_threshold_latency_us: 50,    // 50μs
            interrupt_threshold_latency_us: 500, // 500μs
            evaluation_interval: 100,            // 100 tick
            hysteresis_count: 3,
        }
    }
}

/// デバイスごとのI/Oモードコントローラ
pub struct DeviceIoModeController {
    /// デバイスID
    device: DeviceId,
    /// 現在のモード
    mode: AtomicU32,
    /// 設定
    thresholds: ModeThresholds,
    /// 統計
    stats: IoModeStats,
    /// ヒステリシスカウンター
    hysteresis: AtomicU32,
    /// 最後の評価時刻
    last_evaluation: AtomicU64,
}

impl DeviceIoModeController {
    pub fn new(device: DeviceId, thresholds: ModeThresholds) -> Self {
        Self {
            device,
            mode: AtomicU32::new(IoMode::Interrupt as u32),
            thresholds,
            stats: IoModeStats::new(),
            hysteresis: AtomicU32::new(0),
            last_evaluation: AtomicU64::new(0),
        }
    }

    /// 現在のモードを取得
    pub fn current_mode(&self) -> IoMode {
        match self.mode.load(Ordering::Acquire) {
            0 => IoMode::Interrupt,
            1 => IoMode::Polling,
            _ => IoMode::Hybrid,
        }
    }

    /// I/O完了を記録
    pub fn record_completion(&self, latency_us: u64) {
        self.stats.record_io(latency_us);
    }

    /// モードを評価し、必要なら切り替え
    pub fn evaluate_mode(&self, current_tick: u64) -> Option<IoMode> {
        let last = self.last_evaluation.load(Ordering::Acquire);
        if current_tick - last < self.thresholds.evaluation_interval {
            return None;
        }

        // CAS で更新
        if self
            .last_evaluation
            .compare_exchange(last, current_tick, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }

        let current = self.current_mode();
        let iops = self.stats.iops();
        let avg_latency = self.stats.avg_latency_us();

        let suggested = self.suggest_mode(iops, avg_latency);

        if suggested != current {
            // fetch_add は加算前の値を返すので +1
            let count = self.hysteresis.fetch_add(1, Ordering::Relaxed) + 1;
            if count >= self.thresholds.hysteresis_count {
                self.switch_mode(suggested);
                self.hysteresis.store(0, Ordering::Relaxed);
                return Some(suggested);
            }
        } else {
            self.hysteresis.store(0, Ordering::Relaxed);
        }

        None
    }

    fn suggest_mode(&self, iops: u64, latency_us: u64) -> IoMode {
        // 高負荷 → ポーリング
        if iops >= self.thresholds.polling_threshold_iops
            || latency_us <= self.thresholds.polling_threshold_latency_us
        {
            return IoMode::Polling;
        }

        // 低負荷 → 割り込み
        if iops <= self.thresholds.interrupt_threshold_iops
            || latency_us >= self.thresholds.interrupt_threshold_latency_us
        {
            return IoMode::Interrupt;
        }

        // 中間 → ハイブリッド
        IoMode::Hybrid
    }

    fn switch_mode(&self, new_mode: IoMode) {
        let mode_val = match new_mode {
            IoMode::Interrupt => 0,
            IoMode::Polling => 1,
            IoMode::Hybrid => 2,
        };
        self.mode.store(mode_val, Ordering::Release);
    }

    /// 統計を取得
    pub fn stats(&self) -> &IoModeStats {
        &self.stats
    }
}

/// I/Oモード統計
pub struct IoModeStats {
    /// 完了I/O数
    io_count: AtomicU64,
    /// 累積レイテンシ（μs）
    total_latency: AtomicU64,
    /// 最小レイテンシ（μs）
    min_latency: AtomicU64,
    /// 最大レイテンシ（μs）
    max_latency: AtomicU64,
    /// 直近の時間窓でのI/O数
    recent_count: AtomicU64,
    /// 時間窓開始時刻
    window_start: AtomicU64,
}

impl IoModeStats {
    pub fn new() -> Self {
        Self {
            io_count: AtomicU64::new(0),
            total_latency: AtomicU64::new(0),
            min_latency: AtomicU64::new(u64::MAX),
            max_latency: AtomicU64::new(0),
            recent_count: AtomicU64::new(0),
            window_start: AtomicU64::new(0),
        }
    }

    pub fn record_io(&self, latency_us: u64) {
        self.io_count.fetch_add(1, Ordering::Relaxed);
        self.total_latency.fetch_add(latency_us, Ordering::Relaxed);
        self.recent_count.fetch_add(1, Ordering::Relaxed);

        // min/max 更新
        loop {
            let current_min = self.min_latency.load(Ordering::Relaxed);
            if latency_us >= current_min {
                break;
            }
            if self
                .min_latency
                .compare_exchange_weak(
                    current_min,
                    latency_us,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }

        loop {
            let current_max = self.max_latency.load(Ordering::Relaxed);
            if latency_us <= current_max {
                break;
            }
            if self
                .max_latency
                .compare_exchange_weak(
                    current_max,
                    latency_us,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }

    pub fn avg_latency_us(&self) -> u64 {
        let count = self.io_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0;
        }
        self.total_latency.load(Ordering::Relaxed) / count
    }

    pub fn iops(&self) -> u64 {
        // 簡易的なIOPS計算（実際には時間窓で計算すべき）
        self.recent_count.swap(0, Ordering::Relaxed)
    }

    pub fn total_count(&self) -> u64 {
        self.io_count.load(Ordering::Relaxed)
    }
}

impl Default for IoModeStats {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// I/O Scheduler
// ============================================================================

/// I/Oスケジューラ
pub struct IoScheduler {
    /// 優先度別キュー
    queues: [PoisonLock<VecDeque<IoRequestId>>; 5],
    /// リクエストマップ
    requests: PoisonRwLock<BTreeMap<IoRequestId, IoRequest>>,
    /// デバイスごとのモードコントローラ
    mode_controllers: PoisonRwLock<BTreeMap<DeviceId, Arc<DeviceIoModeController>>>,
    /// デバイス操作ハンドラ（依存逆転用）
    device_ops: PoisonRwLock<BTreeMap<DeviceId, Arc<dyn DeviceOps>>>,
    /// グローバルI/O統計
    stats: IoSchedulerStats,
    /// 完了フック
    completion_hooks: PoisonLock<BTreeMap<IoRequestId, CompletionHook>>,
    /// ポーリング有効フラグ
    polling_enabled: AtomicBool,
    /// シャットダウンフラグ
    shutdown: AtomicBool,
}

/// スケジューラ統計
pub struct IoSchedulerStats {
    /// 総サブミット数
    pub total_submitted: AtomicU64,
    /// 総完了数
    pub total_completed: AtomicU64,
    /// 総エラー数
    pub total_errors: AtomicU64,
    /// 現在キュー長
    pub current_queue_depth: AtomicU64,
    /// 最大キュー長
    pub max_queue_depth: AtomicU64,
}

impl IoSchedulerStats {
    pub const fn new() -> Self {
        Self {
            total_submitted: AtomicU64::new(0),
            total_completed: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            current_queue_depth: AtomicU64::new(0),
            max_queue_depth: AtomicU64::new(0),
        }
    }
}

impl Default for IoSchedulerStats {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Polling Executor
// ============================================================================

/// ポーリングエグゼキュータ
///
/// 高負荷時にポーリングベースでI/O完了を処理
pub struct PollingExecutor {
    /// スケジューラ参照
    scheduler: Arc<IoScheduler>,
    /// ポーリングハンドラ
    poll_handlers: PoisonRwLock<BTreeMap<DeviceId, Vec<Box<dyn PollHandler + Send + Sync>>>>,
    /// 最大ポーリング反復回数
    max_poll_iterations: u32,
    /// ポーリング間隔（μs）
    poll_interval_us: u64,
    /// アクティブフラグ
    active: AtomicBool,
}

/// ポーリングハンドラトレイト
pub trait PollHandler {
    /// 完了をポーリング
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)>;

    /// デバイスが準備完了か
    fn is_ready(&self) -> bool;

    /// このハンドラを処理すべきCPU index（None = 全CPU、Some(n) = CPU n のみ）
    ///
    /// cpu_index() と同じ 0-based 連番を返す。
    fn affinity_cpu_index(&self) -> Option<usize> {
        None // デフォルト: どのCPUでも処理可
    }
}

impl PollingExecutor {
    pub fn new(scheduler: Arc<IoScheduler>) -> Self {
        Self {
            scheduler,
            poll_handlers: PoisonRwLock::new(BTreeMap::new()),
            max_poll_iterations: 64,
            poll_interval_us: 10,
            active: AtomicBool::new(false),
        }
    }

    /// ポーリングハンドラを登録
    pub fn register_handler(&self, device: DeviceId, handler: Box<dyn PollHandler + Send + Sync>) {
        self.poll_handlers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .entry(device)
            .or_insert_with(Vec::new)
            .push(handler);
    }

    pub fn unregister_handler(&self, device: DeviceId) -> bool {
        self.poll_handlers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&device)
            .is_some()
    }

    /// ポーリングを開始
    pub fn start(&self) {
        self.active.store(true, Ordering::Release);
    }

    /// ポーリングを停止
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }

    /// 1回のポーリングサイクル
    pub fn poll_once(&self) -> usize {
        if !self.active.load(Ordering::Acquire) {
            return 0;
        }

        let mut completed = 0;
        let handlers = self.poll_handlers.read().unwrap_or_else(|e| e.into_inner());

        for (_device, handlers) in handlers.iter() {
            for handler in handlers.iter() {
                if handler.is_ready() {
                    for (id, result) in handler.poll_completions() {
                        self.scheduler.complete_request(id, result);
                        completed += 1;
                    }
                }
            }
        }

        completed
    }

    /// コールバック付きポーリング（pending_requests 掃除用）
    ///
    /// 完了ごとに (DeviceId, IoRequestId, IoResult) でコールバックを呼ぶ.
    pub fn poll_once_with<F>(&self, mut on_complete: F) -> usize
    where
        F: FnMut(DeviceId, IoRequestId, IoResult),
    {
        if !self.active.load(Ordering::Acquire) {
            return 0;
        }

        let mut completed = 0;
        let handlers = self.poll_handlers.read().unwrap_or_else(|e| e.into_inner());

        for (device, handlers) in handlers.iter() {
            for handler in handlers.iter() {
                if handler.is_ready() {
                    for (id, result) in handler.poll_completions() {
                        on_complete(*device, id, result.clone());
                        self.scheduler.complete_request(id, result);
                        completed += 1;
                    }
                }
            }
        }

        completed
    }

    /// 現在のCPUに紐づくハンドラのみポーリング（per-CPU tick用）
    pub fn poll_once_local(&self) -> usize {
        if !self.active.load(Ordering::Acquire) {
            return 0;
        }

        let cpu_idx = crate::smp::cpu_index();
        let mut completed = 0;
        let handlers = self.poll_handlers.read().unwrap_or_else(|e| e.into_inner());

        for (_device, handlers) in handlers.iter() {
            for handler in handlers.iter() {
                match handler.affinity_cpu_index() {
                    Some(idx) if idx != cpu_idx => continue,
                    _ => {}
                }

                if handler.is_ready() {
                    for (id, result) in handler.poll_completions() {
                        self.scheduler.complete_request(id, result);
                        completed += 1;
                    }
                }
            }
        }

        completed
    }

    /// バッチポーリング
    pub fn poll_batch(&self) -> usize {
        let mut total = 0;

        for _ in 0..self.max_poll_iterations {
            let count = self.poll_once();
            if count == 0 {
                break;
            }
            total += count;
        }

        total
    }

    /// アクティブ状態か
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

// ============================================================================
// I/O Future
// ============================================================================

/// I/O操作のFuture
pub struct IoFuture {
    scheduler: Arc<IoScheduler>,
    request_id: IoRequestId,
    registered: bool,
}

impl IoFuture {
    pub fn new(scheduler: Arc<IoScheduler>, request_id: IoRequestId) -> Self {
        Self {
            scheduler,
            request_id,
            registered: false,
        }
    }

    pub fn request_id(&self) -> IoRequestId {
        self.request_id
    }
}
