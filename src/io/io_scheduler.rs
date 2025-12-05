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

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use spin::{Mutex, RwLock};

// ============================================================================
// I/O Operation Types
// ============================================================================

/// I/O操作の種類
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

/// I/Oリクエスト記述子
pub struct IoRequest {
    /// リクエストID
    pub id: IoRequestId,
    /// デバイスID
    pub device: DeviceId,
    /// 操作タイプ
    pub operation: IoOperationType,
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
            let count = self.hysteresis.fetch_add(1, Ordering::Relaxed);
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
                .compare_exchange_weak(current_min, latency_us, Ordering::Relaxed, Ordering::Relaxed)
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
                .compare_exchange_weak(current_max, latency_us, Ordering::Relaxed, Ordering::Relaxed)
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
    queues: [Mutex<VecDeque<IoRequestId>>; 5],
    /// リクエストマップ
    requests: RwLock<BTreeMap<IoRequestId, IoRequest>>,
    /// デバイスごとのモードコントローラ
    mode_controllers: RwLock<BTreeMap<DeviceId, Arc<DeviceIoModeController>>>,
    /// グローバルI/O統計
    stats: IoSchedulerStats,
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

impl IoScheduler {
    /// 新しいI/Oスケジューラを作成
    pub const fn new() -> Self {
        Self {
            queues: [
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
            ],
            requests: RwLock::new(BTreeMap::new()),
            mode_controllers: RwLock::new(BTreeMap::new()),
            stats: IoSchedulerStats::new(),
            polling_enabled: AtomicBool::new(true),
            shutdown: AtomicBool::new(false),
        }
    }

    /// デバイスのモードコントローラを登録
    pub fn register_device(&self, device: DeviceId, thresholds: ModeThresholds) {
        let controller = Arc::new(DeviceIoModeController::new(device, thresholds));
        self.mode_controllers
            .write()
            .insert(device, controller);
    }

    /// I/Oリクエストをサブミット
    pub fn submit(&self, device: DeviceId, operation: IoOperationType, priority: IoPriority) -> IoRequestId {
        let id = IoRequestId::next();
        let request = IoRequest {
            id,
            device,
            operation,
            priority,
            state: IoState::Pending,
            submitted_at: current_tick(),
            completed_at: None,
            waker: None,
            result: None,
        };

        // リクエストを登録
        self.requests.write().insert(id, request);

        // 優先度キューに追加
        let queue_idx = priority as usize;
        self.queues[queue_idx].lock().push_back(id);

        // 統計更新
        self.stats.total_submitted.fetch_add(1, Ordering::Relaxed);
        let depth = self.stats.current_queue_depth.fetch_add(1, Ordering::Relaxed) + 1;

        // 最大キュー長を更新
        loop {
            let max = self.stats.max_queue_depth.load(Ordering::Relaxed);
            if depth <= max {
                break;
            }
            if self
                .stats
                .max_queue_depth
                .compare_exchange_weak(max, depth, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        id
    }

    /// I/OリクエストにWakerを設定
    pub fn set_waker(&self, id: IoRequestId, waker: Waker) {
        if let Some(request) = self.requests.write().get_mut(&id) {
            request.waker = Some(waker);
        }
    }

    /// 次のリクエストを取得（優先度順）
    pub fn next_request(&self) -> Option<IoRequestId> {
        // 高優先度から順にチェック
        for i in (0..5).rev() {
            if let Some(id) = self.queues[i].lock().pop_front() {
                return Some(id);
            }
        }
        None
    }

    /// リクエストを開始状態にする
    pub fn start_request(&self, id: IoRequestId) -> Option<IoRequest> {
        let mut requests = self.requests.write();
        if let Some(request) = requests.get_mut(&id) {
            if request.state == IoState::Pending {
                request.state = IoState::InProgress;
            }
        }
        requests.get(&id).cloned()
    }

    /// リクエスト完了を通知
    pub fn complete_request(&self, id: IoRequestId, result: IoResult) {
        let waker = {
            let mut requests = self.requests.write();
            if let Some(request) = requests.get_mut(&id) {
                request.state = match &result {
                    IoResult::Success(_) => IoState::Completed,
                    IoResult::Error(_) => IoState::Failed,
                };
                request.completed_at = Some(current_tick());
                request.result = Some(result.clone());

                // 統計更新
                self.stats.total_completed.fetch_add(1, Ordering::Relaxed);
                self.stats.current_queue_depth.fetch_sub(1, Ordering::Relaxed);

                if matches!(result, IoResult::Error(_)) {
                    self.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                }

                // モードコントローラにレイテンシを報告
                if let Some(completed) = request.completed_at {
                    let latency_us = (completed - request.submitted_at) * 1000; // tick to μs (仮)
                    if let Some(controller) = self.mode_controllers.read().get(&request.device) {
                        controller.record_completion(latency_us);
                    }
                }

                request.waker.take()
            } else {
                None
            }
        };

        // Wakerを起動
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// リクエストをキャンセル
    pub fn cancel_request(&self, id: IoRequestId) -> bool {
        let waker = {
            let mut requests = self.requests.write();
            if let Some(request) = requests.get_mut(&id) {
                if request.state == IoState::Pending {
                    request.state = IoState::Cancelled;
                    request.result = Some(IoResult::Error(IoError::Cancelled));
                    self.stats.current_queue_depth.fetch_sub(1, Ordering::Relaxed);
                    request.waker.take()
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(w) = waker {
            w.wake();
            true
        } else {
            false
        }
    }

    /// リクエストの状態を取得
    pub fn get_state(&self, id: IoRequestId) -> Option<IoState> {
        self.requests.read().get(&id).map(|r| r.state)
    }

    /// リクエストの結果を取得
    pub fn get_result(&self, id: IoRequestId) -> Option<IoResult> {
        self.requests.read().get(&id).and_then(|r| r.result.clone())
    }

    /// デバイスのI/Oモードを取得
    pub fn device_mode(&self, device: DeviceId) -> IoMode {
        self.mode_controllers
            .read()
            .get(&device)
            .map(|c| c.current_mode())
            .unwrap_or(IoMode::Interrupt)
    }

    /// モード評価を実行
    pub fn evaluate_modes(&self, current_tick: u64) {
        for (_, controller) in self.mode_controllers.read().iter() {
            controller.evaluate_mode(current_tick);
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> &IoSchedulerStats {
        &self.stats
    }

    /// シャットダウン
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// シャットダウン状態か
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

// IoRequest の Clone を実装（簡易版）
impl Clone for IoRequest {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            device: self.device,
            operation: self.operation,
            priority: self.priority,
            state: self.state,
            submitted_at: self.submitted_at,
            completed_at: self.completed_at,
            waker: None, // Waker は clone しない
            result: self.result.clone(),
        }
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
    poll_handlers: RwLock<BTreeMap<DeviceId, Box<dyn PollHandler + Send + Sync>>>,
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
}

impl PollingExecutor {
    pub fn new(scheduler: Arc<IoScheduler>) -> Self {
        Self {
            scheduler,
            poll_handlers: RwLock::new(BTreeMap::new()),
            max_poll_iterations: 64,
            poll_interval_us: 10,
            active: AtomicBool::new(false),
        }
    }

    /// ポーリングハンドラを登録
    pub fn register_handler(&self, device: DeviceId, handler: Box<dyn PollHandler + Send + Sync>) {
        self.poll_handlers.write().insert(device, handler);
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
        let handlers = self.poll_handlers.read();

        for (_device, handler) in handlers.iter() {
            if handler.is_ready() {
                for (id, result) in handler.poll_completions() {
                    self.scheduler.complete_request(id, result);
                    completed += 1;
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
}

impl Future for IoFuture {
    type Output = Result<usize, IoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // 状態をチェック
        if let Some(state) = self.scheduler.get_state(self.request_id) {
            match state {
                IoState::Completed => {
                    if let Some(result) = self.scheduler.get_result(self.request_id) {
                        return Poll::Ready(match result {
                            IoResult::Success(bytes) => Ok(bytes),
                            IoResult::Error(e) => Err(e),
                        });
                    }
                }
                IoState::Failed | IoState::Cancelled => {
                    if let Some(result) = self.scheduler.get_result(self.request_id) {
                        return Poll::Ready(match result {
                            IoResult::Success(bytes) => Ok(bytes),
                            IoResult::Error(e) => Err(e),
                        });
                    }
                    return Poll::Ready(Err(IoError::DeviceError));
                }
                IoState::Pending | IoState::InProgress => {
                    // Wakerを登録
                    if !self.registered {
                        self.scheduler.set_waker(self.request_id, cx.waker().clone());
                        self.registered = true;
                    }
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Err(IoError::InvalidParameter))
    }
}

// ============================================================================
// Interrupt-to-Waker Bridge
// ============================================================================

/// 割り込み-Wakerブリッジ
///
/// デバイス割り込みからI/Oスケジューラへの通知を行う
pub struct IoInterruptBridge {
    scheduler: Arc<IoScheduler>,
    /// デバイスごとの保留中リクエスト
    pending_requests: RwLock<BTreeMap<DeviceId, VecDeque<IoRequestId>>>,
}

impl IoInterruptBridge {
    pub fn new(scheduler: Arc<IoScheduler>) -> Self {
        Self {
            scheduler,
            pending_requests: RwLock::new(BTreeMap::new()),
        }
    }

    /// リクエストを保留リストに追加
    pub fn register_pending(&self, device: DeviceId, request_id: IoRequestId) {
        self.pending_requests
            .write()
            .entry(device)
            .or_insert_with(VecDeque::new)
            .push_back(request_id);
    }

    /// 割り込みハンドラから呼ばれる
    pub fn handle_interrupt(&self, device: DeviceId, results: &[(IoRequestId, IoResult)]) {
        for (id, result) in results {
            self.scheduler.complete_request(*id, result.clone());
        }

        // 保留リストからも削除
        if let Some(pending) = self.pending_requests.write().get_mut(&device) {
            pending.retain(|id| {
                results.iter().all(|(rid, _)| rid != id)
            });
        }
    }

    /// 保留中のリクエスト数を取得
    pub fn pending_count(&self, device: DeviceId) -> usize {
        self.pending_requests
            .read()
            .get(&device)
            .map(|q| q.len())
            .unwrap_or(0)
    }
}

// ============================================================================
// Hybrid I/O Coordinator
// ============================================================================

/// ハイブリッドI/Oコーディネーター
///
/// 負荷に応じてポーリングと割り込みを動的に切り替え
pub struct HybridIoCoordinator {
    scheduler: Arc<IoScheduler>,
    polling_executor: Arc<PollingExecutor>,
    interrupt_bridge: Arc<IoInterruptBridge>,
    /// グローバルモード
    global_mode: AtomicU32,
}

impl HybridIoCoordinator {
    pub fn new(scheduler: Arc<IoScheduler>) -> Self {
        let polling_executor = Arc::new(PollingExecutor::new(scheduler.clone()));
        let interrupt_bridge = Arc::new(IoInterruptBridge::new(scheduler.clone()));

        Self {
            scheduler,
            polling_executor,
            interrupt_bridge,
            global_mode: AtomicU32::new(IoMode::Interrupt as u32),
        }
    }

    /// ポーリングエグゼキュータを取得
    pub fn polling_executor(&self) -> Arc<PollingExecutor> {
        self.polling_executor.clone()
    }

    /// 割り込みブリッジを取得
    pub fn interrupt_bridge(&self) -> Arc<IoInterruptBridge> {
        self.interrupt_bridge.clone()
    }

    /// I/Oをサブミット
    pub fn submit_io(
        &self,
        device: DeviceId,
        operation: IoOperationType,
        priority: IoPriority,
    ) -> IoFuture {
        let id = self.scheduler.submit(device, operation, priority);

        // モードに応じて登録先を選択
        let mode = self.scheduler.device_mode(device);
        match mode {
            IoMode::Interrupt => {
                self.interrupt_bridge.register_pending(device, id);
            }
            IoMode::Polling => {
                // ポーリングの場合は特に登録不要
            }
            IoMode::Hybrid => {
                // 両方に登録
                self.interrupt_bridge.register_pending(device, id);
            }
        }

        IoFuture::new(self.scheduler.clone(), id)
    }

    /// メインループの1回の反復
    pub fn tick(&self, current_tick: u64) {
        // モード評価
        self.scheduler.evaluate_modes(current_tick);

        // ポーリングモードならポーリング実行
        let global_mode = match self.global_mode.load(Ordering::Acquire) {
            0 => IoMode::Interrupt,
            1 => IoMode::Polling,
            _ => IoMode::Hybrid,
        };

        match global_mode {
            IoMode::Polling => {
                self.polling_executor.poll_batch();
            }
            IoMode::Hybrid => {
                // ハイブリッドでは軽いポーリングを行う
                self.polling_executor.poll_once();
            }
            IoMode::Interrupt => {
                // 割り込み待ち
            }
        }
    }

    /// グローバルモードを設定
    pub fn set_global_mode(&self, mode: IoMode) {
        let mode_val = match mode {
            IoMode::Interrupt => 0,
            IoMode::Polling => 1,
            IoMode::Hybrid => 2,
        };
        self.global_mode.store(mode_val, Ordering::Release);

        match mode {
            IoMode::Polling => self.polling_executor.start(),
            _ => self.polling_executor.stop(),
        }
    }

    /// グローバルモードを取得
    pub fn global_mode(&self) -> IoMode {
        match self.global_mode.load(Ordering::Acquire) {
            0 => IoMode::Interrupt,
            1 => IoMode::Polling,
            _ => IoMode::Hybrid,
        }
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static IO_SCHEDULER: spin::Once<Arc<IoScheduler>> = spin::Once::new();
static HYBRID_COORDINATOR: spin::Once<Arc<HybridIoCoordinator>> = spin::Once::new();

/// I/Oスケジューラを初期化
pub fn init_io_scheduler() {
    IO_SCHEDULER.call_once(|| Arc::new(IoScheduler::new()));
    HYBRID_COORDINATOR.call_once(|| {
        Arc::new(HybridIoCoordinator::new(io_scheduler()))
    });
}

/// グローバルI/Oスケジューラを取得
pub fn io_scheduler() -> Arc<IoScheduler> {
    IO_SCHEDULER
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(IoScheduler::new()))
}

/// ハイブリッドコーディネーターを取得
pub fn hybrid_coordinator() -> Arc<HybridIoCoordinator> {
    HYBRID_COORDINATOR
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(HybridIoCoordinator::new(io_scheduler())))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// 現在のtickを取得（仮実装）
fn current_tick() -> u64 {
    #[cfg(feature = "task")]
    {
        crate::task::current_tick()
    }
    #[cfg(not(feature = "task"))]
    {
        static TICK: AtomicU64 = AtomicU64::new(0);
        TICK.fetch_add(1, Ordering::Relaxed)
    }
}

// ============================================================================
// Convenience API
// ============================================================================

/// 非同期I/O読み取り
pub async fn async_read(device: DeviceId, priority: IoPriority) -> Result<usize, IoError> {
    hybrid_coordinator()
        .submit_io(device, IoOperationType::Read, priority)
        .await
}

/// 非同期I/O書き込み
pub async fn async_write(device: DeviceId, priority: IoPriority) -> Result<usize, IoError> {
    hybrid_coordinator()
        .submit_io(device, IoOperationType::Write, priority)
        .await
}

/// 非同期フラッシュ
pub async fn async_flush(device: DeviceId) -> Result<usize, IoError> {
    hybrid_coordinator()
        .submit_io(device, IoOperationType::Flush, IoPriority::High)
        .await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_priority_ordering() {
        assert!(IoPriority::Realtime > IoPriority::High);
        assert!(IoPriority::High > IoPriority::Normal);
        assert!(IoPriority::Normal > IoPriority::Idle);
        assert!(IoPriority::Idle > IoPriority::Background);
    }

    #[test]
    fn test_io_mode_stats() {
        let stats = IoModeStats::new();
        stats.record_io(100);
        stats.record_io(200);
        stats.record_io(50);

        assert_eq!(stats.total_count(), 3);
        assert_eq!(stats.avg_latency_us(), 116); // (100+200+50)/3
    }

    #[test]
    fn test_scheduler_submit() {
        let scheduler = IoScheduler::new();
        let device = DeviceId::Nvme {
            controller: 0,
            namespace: 1,
        };

        let id = scheduler.submit(device, IoOperationType::Read, IoPriority::Normal);
        assert_eq!(scheduler.get_state(id), Some(IoState::Pending));

        scheduler.complete_request(id, IoResult::Success(512));
        assert_eq!(scheduler.get_state(id), Some(IoState::Completed));
    }
}
