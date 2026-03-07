use super::*;

mod io_future;
pub use io_future::*;
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

    /// 登録済みデバイスIDのスナップショットを返す。
    pub fn registered_devices(&self) -> Vec<DeviceId> {
        self.device_ops.read().keys().copied().collect()
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
        let depth = self
            .stats
            .current_queue_depth
            .fetch_add(1, Ordering::Relaxed)
            + 1;
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
    pub(super) fn report_completion_stats(&self, request: &IoRequest, result: &IoResult) {
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
            self.stats
                .current_queue_depth
                .fetch_sub(1, Ordering::Relaxed);
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
            .map(|r| {
                matches!(
                    r.state,
                    IoState::Completed | IoState::Failed | IoState::Cancelled
                )
            })
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
                let result = req
                    .result
                    .take()
                    .unwrap_or(IoResult::Error(IoError::DeviceError));
                reqs.remove(&id);
                Poll::Ready(match result {
                    IoResult::Success(n) => Ok(n),
                    IoResult::Error(e) => Err(e),
                })
            }
            IoState::Pending | IoState::InProgress => {
                // Waker 更新が必要か判定
                let needs_update = if *registered {
                    req.waker
                        .as_ref()
                        .map(|old| !old.will_wake(waker))
                        .unwrap_or(true)
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
