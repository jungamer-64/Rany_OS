use super::*;

mod io_future;
pub use io_future::*;
impl IoScheduler {
    /// 新しいI/Oスケジューラを作成
    pub const fn new() -> Self {
        Self {
            queues: [
                PoisonLock::new(VecDeque::new()),
                PoisonLock::new(VecDeque::new()),
                PoisonLock::new(VecDeque::new()),
                PoisonLock::new(VecDeque::new()),
                PoisonLock::new(VecDeque::new()),
            ],
            requests: PoisonRwLock::new(BTreeMap::new()),
            mode_controllers: PoisonRwLock::new(BTreeMap::new()),
            device_ops: PoisonRwLock::new(BTreeMap::new()),
            stats: IoSchedulerStats::new(),
            completion_hooks: PoisonLock::new(BTreeMap::new()),
            polling_enabled: AtomicBool::new(true),
            shutdown: AtomicBool::new(false),
        }
    }

    /// デバイスのモードコントローラを登録
    pub fn register_device(&self, device: DeviceId, thresholds: ModeThresholds) {
        let controller = Arc::new(DeviceIoModeController::new(device, thresholds));
        self.mode_controllers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(device, controller);
    }

    /// デバイス操作ハンドラを登録（依存逆転）
    ///
    /// 具体デバイス（NVMe, VirtIO等）は起動時にこのメソッドで登録し、
    /// スケジューラはDeviceOps経由でのみデバイスと対話する。
    pub fn register_device_ops(&self, device: DeviceId, ops: Arc<dyn DeviceOps>) {
        self.device_ops
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(device, ops);
    }

    pub fn unregister_device(&self, device: DeviceId) -> bool {
        self.mode_controllers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&device);
        self.device_ops
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&device)
            .is_some()
    }

    /// デバイス操作ハンドラを取得
    pub fn get_device_ops(&self, device: DeviceId) -> Option<Arc<dyn DeviceOps>> {
        self.device_ops
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&device)
            .cloned()
    }

    /// 登録済みデバイスIDのスナップショットを返す。
    pub fn registered_devices(&self) -> Vec<DeviceId> {
        self.device_ops
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// I/Oリクエストをサブミット
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
        self.requests
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, request);

        // 優先度キューに追加
        let queue_idx = priority as usize;
        self.queues[queue_idx]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(id);

        // 統計更新
        self.stats.total_submitted.fetch_add(1, Ordering::Relaxed);
        let depth = self
            .stats
            .current_queue_depth
            .fetch_add(1, Ordering::Relaxed)
            + 1;

        // 最大キュー長を更新
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
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
        self.requests
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, request);
        let queue_idx = priority as usize;
        self.queues[queue_idx]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(id);
        self.stats.total_submitted.fetch_add(1, Ordering::Relaxed);
        let depth = self
            .stats
            .current_queue_depth
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
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
        if let Some(request) = self
            .requests
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&id)
        {
            request.waker = Some(waker);
        }
    }

    /// I/OリクエストのWakerを取得
    pub fn get_waker(&self, id: IoRequestId) -> Option<Waker> {
        self.requests
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .and_then(|r| r.waker.clone())
    }

    /// 次のリクエストを取得（優先度順）
    pub fn next_request(&self) -> Option<IoRequestId> {
        // 高優先度から順にチェック
        for i in (0..5).rev() {
            if let Some(id) = self.queues[i]
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front()
            {
                return Some(id);
            }
        }
        None
    }

    /// リクエストを開始状態にする
    pub fn start_request(&self, id: IoRequestId) -> Option<IoRequest> {
        let mut requests = self.requests.write().unwrap_or_else(|e| e.into_inner());
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
            let latency_us = completed.saturating_sub(request.submitted_at) * 1000; // tick to μs (仮)
            if let Some(controller) = self
                .mode_controllers
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&request.device)
            {
                controller.record_completion(latency_us);
            }
        }
    }

    /// リクエスト完了を通知
    pub fn complete_request(&self, id: IoRequestId, result: IoResult) {
        let (waker, abandoned) = {
            let mut requests = self.requests.write().unwrap_or_else(|e| e.into_inner());
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

        if let Some(hook) = self
            .completion_hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
        {
            hook.run(result);
        }

        // Wakerを起動
        if let Some(w) = waker {
            w.wake();
        }

        if abandoned {
            self.requests
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
        }
    }

    /// リクエストをキャンセル
    pub fn cancel_request(&self, id: IoRequestId) -> bool {
        let result = IoResult::Error(IoError::Cancelled);
        let (waker, abandoned) = {
            let mut requests = self.requests.write().unwrap_or_else(|e| e.into_inner());
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

        if let Some(hook) = self
            .completion_hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
        {
            hook.run(result);
        }

        if let Some(ref w) = waker {
            w.wake_by_ref();
        }

        if abandoned {
            self.requests
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
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
            let mut requests = self.requests.write().unwrap_or_else(|e| e.into_inner());
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

        if let Some(hook) = self
            .completion_hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
        {
            hook.run(result);
        }

        if let Some(w) = waker {
            w.wake();
        }

        if should_remove {
            self.requests
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
        }

        true
    }

    /// リクエストを破棄（Future drop 時に使用）
    pub fn abandon_request(&self, id: IoRequestId) {
        let mut requests = self.requests.write().unwrap_or_else(|e| e.into_inner());
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
        self.requests
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .map(|r| r.state)
    }

    /// リクエストの結果を取得
    pub fn get_result(&self, id: IoRequestId) -> Option<IoResult> {
        self.requests
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .and_then(|r| r.result.clone())
    }

    /// 完了済みリクエストの結果を取り出して削除
    pub fn take_result(&self, id: IoRequestId) -> Option<IoResult> {
        let mut requests = self.requests.write().unwrap_or_else(|e| e.into_inner());
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
        let mut reqs = self.requests.write().unwrap_or_else(|e| e.into_inner());
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
                Poll::Pending
            }
        }
    }

    /// 完了フックを登録
    pub fn register_completion_hook(&self, id: IoRequestId, hook: CompletionHook) {
        self.completion_hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, hook);

        if let Some(result) = self.get_result(id) {
            if let Some(hook) = self
                .completion_hooks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id)
            {
                hook.run(result);
            }
        }
    }

    /// デバイスのI/Oモードを取得
    pub fn device_mode(&self, device: DeviceId) -> IoMode {
        self.mode_controllers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&device)
            .map(|c| c.current_mode())
            .unwrap_or(IoMode::Interrupt)
    }

    /// モード評価を実行
    pub fn evaluate_modes(&self, current_tick: u64) {
        for (_, controller) in self
            .mode_controllers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
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
