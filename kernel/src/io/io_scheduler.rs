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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
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
    Discard {
        lba: u64,
        blocks: u16,
    },
    /// デバイス固有コマンド（ioctl的）
    ///
    /// コードとバッファの解釈はデバイスドライバに委ねられる
    Ioctl {
        code: u32,
        buf: DmaBufHandle,
    },
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
    queues: [Mutex<VecDeque<IoRequestId>>; 5],
    /// リクエストマップ
    requests: RwLock<BTreeMap<IoRequestId, IoRequest>>,
    /// デバイスごとのモードコントローラ
    mode_controllers: RwLock<BTreeMap<DeviceId, Arc<DeviceIoModeController>>>,
    /// デバイス操作ハンドラ（依存逆転用）
    device_ops: RwLock<BTreeMap<DeviceId, Arc<dyn DeviceOps>>>,
    /// グローバルI/O統計
    stats: IoSchedulerStats,
    /// 完了フック
    completion_hooks: Mutex<BTreeMap<IoRequestId, CompletionHook>>,
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
            device_ops: RwLock::new(BTreeMap::new()),
            stats: IoSchedulerStats::new(),
            completion_hooks: Mutex::new(BTreeMap::new()),
            polling_enabled: AtomicBool::new(true),
            shutdown: AtomicBool::new(false),
        }
    }

    /// デバイスのモードコントローラを登録
    pub fn register_device(&self, device: DeviceId, thresholds: ModeThresholds) {
        let controller = Arc::new(DeviceIoModeController::new(device, thresholds));
        self.mode_controllers.write().insert(device, controller);
    }

    /// デバイス操作ハンドラを登録（依存逆転）
    ///
    /// 具体デバイス（NVMe, VirtIO等）は起動時にこのメソッドで登録し、
    /// スケジューラはDeviceOps経由でのみデバイスと対話する。
    pub fn register_device_ops(&self, device: DeviceId, ops: Arc<dyn DeviceOps>) {
        self.device_ops.write().insert(device, ops);
    }

    /// デバイス操作ハンドラを取得
    pub fn get_device_ops(&self, device: DeviceId) -> Option<Arc<dyn DeviceOps>> {
        self.device_ops.read().get(&device).cloned()
    }

    /// I/Oリクエストをサブミット
    #[allow(deprecated)]
    pub fn submit(
        &self,
        device: DeviceId,
        operation: IoOperationType,
        priority: IoPriority,
    ) -> IoRequestId {
        let id = IoRequestId::next();
        let request = IoRequest {
            id,
            device,
            operation,
            command: None,
            priority,
            state: IoState::Pending,
            submitted_at: current_tick(),
            completed_at: None,
            waker: None,
            result: None,
            abandoned: false,
        };

        // リクエストを登録
        self.requests.write().insert(id, request);

        // 優先度キューに追加
        let queue_idx = priority as usize;
        self.queues[queue_idx].lock().push_back(id);

        // 統計更新
        self.stats.total_submitted.fetch_add(1, Ordering::Relaxed);
        let depth = self
            .stats
            .current_queue_depth
            .fetch_add(1, Ordering::Relaxed)
            + 1;

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



    /// デバイス中立コマンドでI/Oをサブミット（新API）
    ///
    /// `IoCommand` を使用し、デバイス固有形式（PRP/SGL等）は
    /// ドライバの `DeviceOps::submit` 内で変換される。
    #[allow(deprecated)]
    pub fn submit_command(
        &self,
        device: DeviceId,
        command: IoCommand,
        priority: IoPriority,
    ) -> IoRequestId {
        let id = IoRequestId::next();
        let operation = match &command {
            IoCommand::BlockRead { .. } => IoOperationType::Read,
            IoCommand::BlockWrite { .. } => IoOperationType::Write,
            IoCommand::Flush => IoOperationType::Flush,
            IoCommand::Discard { .. } => IoOperationType::Custom(0),
            IoCommand::Ioctl { code: _, .. } => IoOperationType::Ioctl,
        };
        let request = IoRequest {
            id,
            device,
            operation,
            command: Some(command),
            priority,
            state: IoState::Pending,
            submitted_at: current_tick(),
            completed_at: None,
            waker: None,
            result: None,
            abandoned: false,
        };
        self.requests.write().insert(id, request);
        let queue_idx = priority as usize;
        self.queues[queue_idx].lock().push_back(id);
        self.stats.total_submitted.fetch_add(1, Ordering::Relaxed);
        let depth = self.stats.current_queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        loop {
            let max = self.stats.max_queue_depth.load(Ordering::Relaxed);
            if depth <= max { break; }
            if self.stats.max_queue_depth.compare_exchange_weak(max, depth, Ordering::Relaxed, Ordering::Relaxed).is_ok() { break; }
        }
        id
    }

    /// I/OリクエストにWakerを設定
    pub fn set_waker(&self, id: IoRequestId, waker: Waker) {
        if let Some(request) = self.requests.write().get_mut(&id) {
            request.waker = Some(waker);
        }
    }

    /// I/OリクエストのWakerを取得
    pub fn get_waker(&self, id: IoRequestId) -> Option<Waker> {
        self.requests.read().get(&id).and_then(|r| r.waker.clone())
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

    /// 完了統計とレイテンシレポートを記録する
    fn report_completion_stats(&self, request: &IoRequest, result: &IoResult) {
        self.stats.total_completed.fetch_add(1, Ordering::Relaxed);
        self.stats
            .current_queue_depth
            .fetch_sub(1, Ordering::Relaxed);

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
    }

    /// リクエスト完了を通知
    pub fn complete_request(&self, id: IoRequestId, result: IoResult) {
        let (waker, abandoned) = {
            let mut requests = self.requests.write();
            if let Some(request) = requests.get_mut(&id) {
                request.state = match &result {
                    IoResult::Success(_) => IoState::Completed,
                    IoResult::Error(_) => IoState::Failed,
                };
                request.completed_at = Some(current_tick());
                request.result = Some(result.clone());

                self.report_completion_stats(request, &result);

                (request.waker.take(), request.abandoned)
            } else {
                (None, false)
            }
        };

        if let Some(hook) = self.completion_hooks.lock().remove(&id) {
            hook.run(result);
        }

        // Wakerを起動
        if let Some(w) = waker {
            w.wake();
        }

        if abandoned {
            self.requests.write().remove(&id);
        }
    }

    /// リクエストをキャンセル
    pub fn cancel_request(&self, id: IoRequestId) -> bool {
        let result = IoResult::Error(IoError::Cancelled);
        let (waker, abandoned) = {
            let mut requests = self.requests.write();
            if let Some(request) = requests.get_mut(&id) {
                if request.state == IoState::Pending {
                    request.state = IoState::Cancelled;
                    request.result = Some(result.clone());
                    self.stats
                        .current_queue_depth
                        .fetch_sub(1, Ordering::Relaxed);
                    (request.waker.take(), request.abandoned)
                } else {
                    (None, request.abandoned)
                }
            } else {
                (None, false)
            }
        };

        if let Some(hook) = self.completion_hooks.lock().remove(&id) {
            hook.run(result);
        }

        if let Some(ref w) = waker {
            w.wake_by_ref();
        }

        if abandoned {
            self.requests.write().remove(&id);
        }

        waker.is_some()
    }

    /// Pending 状態のリクエストのみキャンセル（Future drop 用）
    ///
    /// InProgress のリクエストは絶対に remove しない。
    /// 完了時に `complete_request()` で回収される。
    pub fn cancel_request_if_pending(&self, id: IoRequestId) -> bool {
        let result = IoResult::Error(IoError::Cancelled);
        let (waker, should_remove) = {
            let mut requests = self.requests.write();
            let Some(request) = requests.get_mut(&id) else {
                return false;
            };

            if request.state != IoState::Pending {
                // InProgress 等は触らない
                return false;
            }

            request.state = IoState::Cancelled;
            request.result = Some(result.clone());
            request.abandoned = true; // drop 由来なので即回収OK
            self.stats.current_queue_depth.fetch_sub(1, Ordering::Relaxed);
            (request.waker.take(), true)
        };

        if let Some(hook) = self.completion_hooks.lock().remove(&id) {
            hook.run(result);
        }

        if let Some(w) = waker {
            w.wake();
        }

        if should_remove {
            self.requests.write().remove(&id);
        }

        true
    }

    /// リクエストを破棄（Future drop 時に使用）
    pub fn abandon_request(&self, id: IoRequestId) {
        let mut requests = self.requests.write();
        if let Some(request) = requests.get_mut(&id) {
            request.abandoned = true;
            request.waker = None;
            if matches!(
                request.state,
                IoState::Completed | IoState::Failed | IoState::Cancelled
            ) {
                requests.remove(&id);
            }
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

    /// 完了済みリクエストの結果を取り出して削除
    pub fn take_result(&self, id: IoRequestId) -> Option<IoResult> {
        let mut requests = self.requests.write();
        let should_remove = requests
            .get(&id)
            .map(|r| matches!(r.state, IoState::Completed | IoState::Failed | IoState::Cancelled))
            .unwrap_or(false);
        if should_remove {
            let result = requests.get(&id).and_then(|r| r.result.clone());
            requests.remove(&id);
            return result;
        }
        None
    }

    /// IoFuture用: 状態確認とWaker登録を1つのロックで行う（lost wake防止）
    ///
    /// このAPIは `get_state()` と `set_waker()` の間のレース条件を防ぐ。
    /// 同一 write lock 内で:
    /// 1. 完了済みなら結果を返す
    /// 2. Pending/InProgress なら waker を登録して Pending を返す
    pub fn poll_result_or_register_waker(
        &self,
        id: IoRequestId,
        waker: &Waker,
        registered: &mut bool,
    ) -> Poll<Result<usize, IoError>> {
        let mut reqs = self.requests.write();
        let Some(req) = reqs.get_mut(&id) else {
            return Poll::Ready(Err(IoError::InvalidParameter));
        };

        match req.state {
            IoState::Completed | IoState::Failed | IoState::Cancelled => {
                // 完了済み: 結果を取り出して削除
                let result = req.result.take().unwrap_or(IoResult::Error(IoError::DeviceError));
                reqs.remove(&id);
                Poll::Ready(match result {
                    IoResult::Success(n) => Ok(n),
                    IoResult::Error(e) => Err(e),
                })
            }
            IoState::Pending | IoState::InProgress => {
                // Waker 更新が必要か判定
                let needs_update = if *registered {
                    req.waker.as_ref().map(|old| !old.will_wake(waker)).unwrap_or(true)
                } else {
                    true
                };
                if needs_update {
                    req.waker = Some(waker.clone());
                    *registered = true;
                }

                // ★同ロック内で再チェック（complete_request がこの間に来ても安全）
                // （実際は上の match で state を見てるので、ここでの再チェックは
                //   将来の "state が変わるケース" への防御として残す）
                Poll::Pending
            }
        }
    }

    /// 完了フックを登録
    pub fn register_completion_hook(&self, id: IoRequestId, hook: CompletionHook) {
        self.completion_hooks.lock().insert(id, hook);

        if let Some(result) = self.get_result(id) {
            if let Some(hook) = self.completion_hooks.lock().remove(&id) {
                hook.run(result);
            }
        }
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
            command: self.command.clone(),
            priority: self.priority,
            state: self.state,
            submitted_at: self.submitted_at,
            completed_at: self.completed_at,
            waker: None, // Waker は clone しない
            result: self.result.clone(),
            abandoned: self.abandoned,
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
    poll_handlers: RwLock<BTreeMap<DeviceId, Vec<Box<dyn PollHandler + Send + Sync>>>>,
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
            poll_handlers: RwLock::new(BTreeMap::new()),
            max_poll_iterations: 64,
            poll_interval_us: 10,
            active: AtomicBool::new(false),
        }
    }

    /// ポーリングハンドラを登録
    pub fn register_handler(&self, device: DeviceId, handler: Box<dyn PollHandler + Send + Sync>) {
        self.poll_handlers
            .write()
            .entry(device)
            .or_insert_with(Vec::new)
            .push(handler);
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
    /// 完了ごとに (DeviceId, IoRequestId, IoResult) でコールバックを呼ぶ。
    /// これにより Coordinator が scheduler.complete_request() と
    /// bridge.complete_pending() の両方を呼べる。
    pub fn poll_once_with<F>(&self, mut on_complete: F) -> usize
    where
        F: FnMut(DeviceId, IoRequestId, IoResult),
    {
        if !self.active.load(Ordering::Acquire) {
            return 0;
        }

        let mut completed = 0;
        let handlers = self.poll_handlers.read();

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
    ///
    /// マルチコア環境では各CPUが自分のhandlerのみをpollするべき。
    /// これにより NVMe queue のような per-CPU リソースへの競合を防ぐ。
    pub fn poll_once_local(&self) -> usize {
        if !self.active.load(Ordering::Acquire) {
            return 0;
        }

        // cpu_index() で 0-based 連番を取得（deferred queue と同じ）
        let cpu_idx = crate::smp::cpu_index();
        let mut completed = 0;
        let handlers = self.poll_handlers.read();

        for (_device, handlers) in handlers.iter() {
            for handler in handlers.iter() {
                // affinity_cpu_index() が None = 全CPUで処理可
                // affinity_cpu_index() が Some(idx) = その CPU index でのみ処理
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

impl Future for IoFuture {
    type Output = Result<usize, IoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // 原子的に状態チェックとWaker登録を行う（lost wake race 防止）
        // Borrow checker回避: self.scheduler(immutable) と &mut self.registered(mutable) が競合するため
        // Arcをクローンして別の所有権/参照パスを作る
        let scheduler = self.scheduler.clone();
        scheduler.poll_result_or_register_waker(
            self.request_id,
            cx.waker(),
            &mut self.registered,
        )
    }
}

impl Drop for IoFuture {
    fn drop(&mut self) {
        // Pending のときだけキャンセル＆削除して終わり
        if self.scheduler.cancel_request_if_pending(self.request_id) {
            return;
        }
        // InProgress なら request は残して完了時に回収させる
        // (abandoned=true にして wake を無効化)
        self.scheduler.abandon_request(self.request_id);
    }
}

// ============================================================================
// Deferred I/O Completions (ISR-safe queue)
// ============================================================================
//
// 設計: Per-CPU キュー（SPSC-safe）
// - 各CPUのISRは自分のキューにのみpush
// - consumer (tick/bottom-half) は同じCPUのキューからpop
// - これによりMPMCレースを回避し、lock-free で安全に動作
//
// API:
// - defer_io_completion(): 現在CPUのキューにpush
// - process_deferred_completions(): 全CPUキューをドレイン
// - process_deferred_completions_local(): 現在CPUのみ処理
// ============================================================================

const IO_COMPLETION_QUEUE_SIZE: usize = 256;
const IO_COMPLETION_QUEUE_MASK: usize = IO_COMPLETION_QUEUE_SIZE - 1;
const IO_RESULT_ERROR_FLAG: u64 = 1 << 63;

/// ISR-safe deferred I/O completion queue (SPSC想定、MPMC非対応)
struct DeferredIoCompletionQueue {
    head: AtomicUsize,
    tail: AtomicUsize,
    devices: [AtomicU64; IO_COMPLETION_QUEUE_SIZE],
    ids: [AtomicU64; IO_COMPLETION_QUEUE_SIZE],
    results: [AtomicU64; IO_COMPLETION_QUEUE_SIZE],
}

impl DeferredIoCompletionQueue {
    const fn new() -> Self {
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            devices: [ZERO; IO_COMPLETION_QUEUE_SIZE],
            ids: [ZERO; IO_COMPLETION_QUEUE_SIZE],
            results: [ZERO; IO_COMPLETION_QUEUE_SIZE],
        }
    }

    fn push(&self, device: DeviceId, id: IoRequestId, result: IoResult) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= IO_COMPLETION_QUEUE_SIZE {
            return false;
        }

        let idx = head & IO_COMPLETION_QUEUE_MASK;
        self.devices[idx].store(encode_device_id(device), Ordering::Release);
        self.ids[idx].store(id.0, Ordering::Release);
        self.results[idx].store(encode_io_result(result), Ordering::Release);
        self.head.store(head.wrapping_add(1), Ordering::Release);
        true
    }

    fn pop(&self) -> Option<(DeviceId, IoRequestId, IoResult)> {
        loop {
            let tail = self.tail.load(Ordering::Relaxed);
            let head = self.head.load(Ordering::Acquire);
            if tail == head {
                return None;
            }
            let idx = tail & IO_COMPLETION_QUEUE_MASK;
            if self
                .tail
                .compare_exchange_weak(
                    tail,
                    tail.wrapping_add(1),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                let device_raw = self.devices[idx].load(Ordering::Acquire);
                let id_raw = self.ids[idx].load(Ordering::Acquire);
                let result_raw = self.results[idx].load(Ordering::Acquire);

                self.devices[idx].store(0, Ordering::Release);
                self.ids[idx].store(0, Ordering::Release);
                self.results[idx].store(0, Ordering::Release);

                let device =
                    decode_device_id(device_raw).unwrap_or(DeviceId::Custom(0));
                let id = IoRequestId(id_raw);
                let result = decode_io_result(result_raw);
                return Some((device, id, result));
            }
            core::hint::spin_loop();
        }
    }
}

// ============================================================================
// Per-CPU Deferred Completion Queues (SPSC-safe design)
// ============================================================================
//
// 各CPUのISRは自分のキューにのみpushし、
// consumer (tick/bottom-half) は同じCPUのキューから popする。
// これによりSPSC条件が満たされ、MPMCレースを回避。

/// 最大サポートCPU数
const MAX_CPUS: usize = 64;

/// Per-CPU キュー配列
struct PerCpuDeferredCompletionQueues {
    queues: [DeferredIoCompletionQueue; MAX_CPUS],
}

impl PerCpuDeferredCompletionQueues {
    const fn new() -> Self {
        const QUEUE: DeferredIoCompletionQueue = DeferredIoCompletionQueue::new();
        Self {
            queues: [QUEUE; MAX_CPUS],
        }
    }

    /// 現在のCPUのキューにpush（ISRから呼び出し）
    fn push(&self, device: DeviceId, id: IoRequestId, result: IoResult) -> bool {
        // cpu_index() は 0-based 連番を返す（APIC ID ではない）
        let cpu_idx = crate::smp::cpu_index();
        debug_assert!(cpu_idx < MAX_CPUS, "CPU index {} exceeds MAX_CPUS", cpu_idx);
        if cpu_idx >= MAX_CPUS {
            // 万が一範囲外なら失敗（overflow_flag が立つ）
            return false;
        }
        self.queues[cpu_idx].push(device, id, result)
    }

    /// 指定CPUのキューからpop
    fn pop_from_cpu(&self, cpu_idx: usize) -> Option<(DeviceId, IoRequestId, IoResult)> {
        if cpu_idx >= MAX_CPUS {
            return None;
        }
        self.queues[cpu_idx].pop()
    }

    /// 全CPUのキューからドレイン（メインloop用）
    fn drain_all<F>(&self, mut callback: F) -> usize
    where
        F: FnMut(DeviceId, IoRequestId, IoResult),
    {
        let mut total = 0;
        for queue in &self.queues {
            while let Some((device, id, result)) = queue.pop() {
                callback(device, id, result);
                total += 1;
            }
        }
        total
    }
}

static DEFERRED_IO_COMPLETIONS: PerCpuDeferredCompletionQueues = PerCpuDeferredCompletionQueues::new();

/// 割り込みコンテキストから完了を遅延キューに追加
fn defer_io_completion(device: DeviceId, id: IoRequestId, result: IoResult) -> bool {
    DEFERRED_IO_COMPLETIONS.push(device, id, result)
}

/// 遅延完了を処理（全CPUキューをドレイン）
pub fn process_deferred_completions() -> usize {
    let coordinator = hybrid_coordinator();
    let scheduler = coordinator.scheduler.clone();
    let bridge = coordinator.interrupt_bridge();

    DEFERRED_IO_COMPLETIONS.drain_all(|device, id, result| {
        scheduler.complete_request(id, result);
        bridge.complete_pending(device, id);
    })
}

/// 現在のCPUの遅延完了のみ処理（per-CPU tick用）
pub fn process_deferred_completions_local() -> usize {
    // IMPORTANT: push() と同じ cpu_index() を使用して SPSC 条件を満たす
    let cpu_idx = crate::smp::cpu_index();
    let coordinator = hybrid_coordinator();
    let scheduler = coordinator.scheduler.clone();
    let bridge = coordinator.interrupt_bridge();
    let mut processed = 0;

    while let Some((device, id, result)) = DEFERRED_IO_COMPLETIONS.pop_from_cpu(cpu_idx) {
        scheduler.complete_request(id, result);
        bridge.complete_pending(device, id);
        processed += 1;
    }

    processed
}

fn encode_device_id(device: DeviceId) -> u64 {
    const KIND_NVME: u64 = 1;
    const KIND_VIRTIO_BLK: u64 = 2;
    const KIND_VIRTIO_NET: u64 = 3;
    const KIND_AHCI: u64 = 4;
    const KIND_USB: u64 = 5;
    const KIND_CUSTOM: u64 = 6;
    const KIND_SHIFT: u64 = 56;

    match device {
        DeviceId::Nvme {
            controller,
            namespace,
        } => {
            (KIND_NVME << KIND_SHIFT)
                | ((controller as u64) << 48)
                | (namespace as u64)
        }
        DeviceId::VirtioBlk { index } => (KIND_VIRTIO_BLK << KIND_SHIFT) | ((index as u64) << 48),
        DeviceId::VirtioNet { index } => (KIND_VIRTIO_NET << KIND_SHIFT) | ((index as u64) << 48),
        DeviceId::Ahci { port } => (KIND_AHCI << KIND_SHIFT) | ((port as u64) << 48),
        DeviceId::Usb { bus, device } => {
            (KIND_USB << KIND_SHIFT) | ((bus as u64) << 48) | ((device as u64) << 40)
        }
        DeviceId::Custom(code) => (KIND_CUSTOM << KIND_SHIFT) | (code as u64),
    }
}

fn decode_device_id(raw: u64) -> Option<DeviceId> {
    if raw == 0 {
        return None;
    }
    let kind = (raw >> 56) & 0xFF;
    match kind {
        1 => Some(DeviceId::Nvme {
            controller: ((raw >> 48) & 0xFF) as u8,
            namespace: (raw & 0xFFFF_FFFF) as u32,
        }),
        2 => Some(DeviceId::VirtioBlk {
            index: ((raw >> 48) & 0xFF) as u8,
        }),
        3 => Some(DeviceId::VirtioNet {
            index: ((raw >> 48) & 0xFF) as u8,
        }),
        4 => Some(DeviceId::Ahci {
            port: ((raw >> 48) & 0xFF) as u8,
        }),
        5 => Some(DeviceId::Usb {
            bus: ((raw >> 48) & 0xFF) as u8,
            device: ((raw >> 40) & 0xFF) as u8,
        }),
        6 => Some(DeviceId::Custom((raw & 0xFFFF_FFFF) as u32)),
        _ => None,
    }
}

fn encode_io_result(result: IoResult) -> u64 {
    match result {
        IoResult::Success(bytes) => {
            let raw = bytes as u64;
            if raw >= IO_RESULT_ERROR_FLAG {
                IO_RESULT_ERROR_FLAG | (io_error_to_u8(IoError::InvalidParameter) as u64)
            } else {
                raw
            }
        }
        IoResult::Error(err) => IO_RESULT_ERROR_FLAG | (io_error_to_u8(err) as u64),
    }
}

fn decode_io_result(raw: u64) -> IoResult {
    if (raw & IO_RESULT_ERROR_FLAG) == 0 {
        return IoResult::Success(raw as usize);
    }
    let code = (raw & 0xFF) as u8;
    IoResult::Error(io_error_from_u8(code))
}

fn io_error_to_u8(err: IoError) -> u8 {
    match err {
        IoError::DeviceError => 1,
        IoError::Timeout => 2,
        IoError::Cancelled => 3,
        IoError::InvalidParameter => 4,
        IoError::NoResources => 5,
        IoError::Busy => 6,
        IoError::NotSupported => 7,
    }
}

fn io_error_from_u8(code: u8) -> IoError {
    match code {
        1 => IoError::DeviceError,
        2 => IoError::Timeout,
        3 => IoError::Cancelled,
        4 => IoError::InvalidParameter,
        5 => IoError::NoResources,
        6 => IoError::Busy,
        7 => IoError::NotSupported,
        _ => IoError::DeviceError,
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
    /// 遅延キュー満杯でドロップした完了数（デバッグ/統計用）
    dropped_completions: AtomicU64,
    /// 遅延キューオーバーフローフラグ（次tickで追加ポーリング）
    overflow_flag: AtomicBool,
}

impl IoInterruptBridge {
    pub fn new(scheduler: Arc<IoScheduler>) -> Self {
        Self {
            scheduler,
            pending_requests: RwLock::new(BTreeMap::new()),
            dropped_completions: AtomicU64::new(0),
            overflow_flag: AtomicBool::new(false),
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
    ///
    /// ISR-safe: ロックを最小化し、遅延キューに追加のみ
    pub fn handle_interrupt(&self, device: DeviceId, results: &[(IoRequestId, IoResult)]) {
        for (id, result) in results {
            if !defer_io_completion(device, *id, result.clone()) {
                // キュー満杯: ISRから直接 complete_request は unsafe なので
                // オーバーフローカウンタをインクリメントし、次tickでpoll強制
                self.dropped_completions.fetch_add(1, Ordering::Relaxed);
                self.overflow_flag.store(true, Ordering::Release);
                // この完了はポーリングで回収される（NVMe CQ等に残っている）
            }
        }
    }

    /// オーバーフローフラグをチェック＆クリア
    pub fn check_and_clear_overflow(&self) -> bool {
        self.overflow_flag.swap(false, Ordering::AcqRel)
    }

    /// ドロップされた完了数を取得
    pub fn dropped_completions(&self) -> u64 {
        self.dropped_completions.load(Ordering::Relaxed)
    }

    fn complete_pending(&self, device: DeviceId, request_id: IoRequestId) {
        let mut pending_requests = self.pending_requests.write();
        if let Some(pending) = pending_requests.get_mut(&device) {
            pending.retain(|id| *id != request_id);
            if pending.is_empty() {
                pending_requests.remove(&device);
            }
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
    #[allow(deprecated)]
    pub fn submit_io(
        &self,
        device: DeviceId,
        operation: IoOperationType,
        priority: IoPriority,
    ) -> IoFuture {
        match operation {
            IoOperationType::Flush => self.submit_io_command(device, IoCommand::Flush, priority),
            _ => {
                // Fall back to creating a command-less request (deprecated pattern)
                let id = self.scheduler.submit(device, operation, priority);

                let global_mode = match self.global_mode.load(Ordering::Acquire) {
                    0 => IoMode::Interrupt,
                    1 => IoMode::Polling,
                    _ => IoMode::Hybrid,
                };

                // Polling 以外はpending登録（Interrupt/Hybrid両方で有効）
                if !matches!(global_mode, IoMode::Polling) {
                    let mode = self.scheduler.device_mode(device);
                    if !matches!(mode, IoMode::Polling) {
                        self.interrupt_bridge.register_pending(device, id);
                    }
                }

                IoFuture::new(self.scheduler.clone(), id)
            }
        }
    }

    /// IoCommandでI/Oをサブミット（新API）
    ///
    /// デバイス中立な `IoCommand` を使用。PRP/SGL変換は
    /// `DeviceOps::submit` 内でドライバが行う。
    pub fn submit_io_command(
        &self,
        device: DeviceId,
        command: IoCommand,
        priority: IoPriority,
    ) -> IoFuture {
        let id = self.scheduler.submit_command(device, command, priority);

        let global_mode = match self.global_mode.load(Ordering::Acquire) {
            0 => IoMode::Interrupt,
            1 => IoMode::Polling,
            _ => IoMode::Hybrid,
        };

        // Polling 以外はpending登録（Interrupt/Hybrid両方で有効）
        if !matches!(global_mode, IoMode::Polling) {
            let mode = self.scheduler.device_mode(device);
            if !matches!(mode, IoMode::Polling) {
                self.interrupt_bridge.register_pending(device, id);
            }
        }

        IoFuture::new(self.scheduler.clone(), id)
    }

    /// オーバーフロー時の強制ポーリング回収
    fn recover_overflow(&self) {
        let was_active = self.polling_executor.is_active();
        if !was_active {
            self.polling_executor.start();
        }
        
        // poll_batch 相当を callback 付きで回す
        // これにより、回収された完了に対して pending_requests の掃除が行われる
        for _ in 0..self.polling_executor.max_poll_iterations {
            let n = self.polling_executor.poll_once_with(|device, id, _res| {
                self.interrupt_bridge.complete_pending(device, id);
            });
            if n == 0 {
                break;
            }
        }

        if !was_active && matches!(self.global_mode(), IoMode::Interrupt) {
            self.polling_executor.stop();
        }
    }

    /// グローバルモードに応じたポーリング実行
    fn poll_by_global_mode(&self) {
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

    /// 定期的なメンテナンス（タイマー割り込み等から呼ぶ）
    pub fn tick<F>(&self, process_interrupts: F)
    where
        F: FnOnce(),
    {
        // 1. 割り込み処理（外部注入）
        process_interrupts();

        // 2. ローカルキューの遅延完了を処理
        let cpu_idx = crate::smp::cpu_index();
        while let Some((device, id, result)) = DEFERRED_IO_COMPLETIONS.pop_from_cpu(cpu_idx) {
            self.scheduler.complete_request(id, result);
            self.interrupt_bridge.complete_pending(device, id);
        }

        // 1.5. オーバーフロー時は強制ポーリングで回収
        if self.interrupt_bridge.check_and_clear_overflow() {
            self.recover_overflow();
        }

        // 2. モード評価
        self.scheduler.evaluate_modes(current_tick());

        // 3. ペンディングI/Oをディスパッチ
        self.dispatch_pending();

        // 4. ポーリングモードならポーリング実行
        self.poll_by_global_mode();
    }

    fn dispatch_pending(&self) {
        const DISPATCH_BATCH_LIMIT: usize = 64;

        for _ in 0..DISPATCH_BATCH_LIMIT {
            let id = match self.scheduler.next_request() {
                Some(id) => id,
                None => break,
            };

            let request = match self.scheduler.start_request(id) {
                Some(request) => request,
                None => continue,
            };

            if !matches!(request.state, IoState::InProgress) {
                continue;
            }

            // 依存逆転: デバイス固有コードへの直接参照を除去
            // DeviceOpsレジストリ経由でデバイスへ投入
            let ops = self.scheduler.get_device_ops(request.device);
            let cpu_idx = crate::smp::cpu_index();
            let result = match ops {
                Some(ops) => ops.submit(&request, cpu_idx),
                None => Err(IoError::NotSupported),
            };

            if let Err(err) = result {
                self.scheduler
                    .complete_request(id, IoResult::Error(err));
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

        // Polling と Hybrid ではポーリングを有効化
        // Interrupt のみポーリングを停止
        match mode {
            IoMode::Polling | IoMode::Hybrid => self.polling_executor.start(),
            IoMode::Interrupt => self.polling_executor.stop(),
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
    HYBRID_COORDINATOR.call_once(|| Arc::new(HybridIoCoordinator::new(io_scheduler())));
    hybrid_coordinator().set_global_mode(IoMode::Polling);
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
        crate::task::timer::current_tick()
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
mod tests;

