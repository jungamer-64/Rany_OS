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
            abandoned_completions: PoisonLock::new(Vec::new()),
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
    /// 具体デバイスは起動時にこのメソッドで登録し、
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

    /// Enqueue one owned command. The scheduler retains its DMA lease until a
    /// device consumes the resulting [`IoSubmission`].
    pub fn submit_command(
        &self,
        device: DeviceId,
        command: IoCommand,
        priority: IoPriority,
    ) -> IoRequestId {
        let id = IoRequestId::next();
        let operation = command.operation();
        let request = IoRequest {
            id,
            device,
            operation,
            command: Some(command),
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

    /// Move one pending command into a device submission exactly once.
    pub fn take_submission(&self, id: IoRequestId) -> Option<IoSubmission> {
        let mut requests = self.requests.write().unwrap_or_else(|e| e.into_inner());
        let request = requests.get_mut(&id)?;
        if request.state != IoState::Pending {
            return None;
        }
        let command = request
            .command
            .take()
            .expect("pending request must retain its command owner");
        request.state = IoState::InProgress;
        Some(IoSubmission {
            request_id: request.id,
            device: request.device,
            command,
        })
    }

    /// 完了統計とレイテンシレポートを記録する
    pub(super) fn report_completion_stats(&self, request: &IoRequest, result: &IoResult) {
        self.stats.total_completed.fetch_add(1, Ordering::Relaxed);
        self.stats
            .current_queue_depth
            .fetch_sub(1, Ordering::Relaxed);

        if matches!(result, IoResult::Error(_) | IoResult::OutcomeUnknown(_)) {
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

    /// Record one terminal device outcome and preserve its ownership until a
    /// future consumes it or the explicit abandoned-completion owner drains it.
    pub fn complete_request(&self, id: IoRequestId, completion: IoCompletion) {
        let status = completion.result();
        let mut completion = Some(completion);
        let (waker, abandoned) = {
            let mut requests = self.requests.write().unwrap_or_else(|e| e.into_inner());
            let Some(request) = requests.get_mut(&id) else {
                drop(requests);
                self.abandoned_completions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(completion.take().expect("completion is moved exactly once"));
                return;
            };
            request.state = match status {
                IoResult::Success(_) => IoState::Completed,
                IoResult::Error(IoError::Cancelled) => IoState::Cancelled,
                IoResult::Error(_) | IoResult::OutcomeUnknown(_) => IoState::Failed,
            };
            request.completed_at = Some(current_tick());
            request.result = completion.take();
            self.report_completion_stats(request, &status);
            (request.waker.take(), request.abandoned)
        };

        if let Some(hook) = self
            .completion_hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
        {
            hook.run(status);
        }

        if let Some(waker) = waker {
            waker.wake();
        }

        if abandoned {
            let completion = self
                .requests
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id)
                .and_then(|mut request| request.result.take());
            if let Some(completion) = completion {
                self.abandoned_completions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(completion);
            }
        }
    }

    /// Cancel only a command that has not crossed the device boundary. Its
    /// original transfer lease is retained in the resulting completion.
    pub fn cancel_request(&self, id: IoRequestId) -> bool {
        let command = {
            let mut requests = self.requests.write().unwrap_or_else(|e| e.into_inner());
            let Some(request) = requests.get_mut(&id) else {
                return false;
            };
            if request.state != IoState::Pending {
                return false;
            }
            request
                .command
                .take()
                .expect("pending request must retain its command owner")
        };
        self.complete_request(id, IoCompletion::rejected(command, IoError::Cancelled));
        true
    }

    /// Relinquish the future's observation right without discarding resource
    /// ownership. Pending commands are cancelled before device acceptance;
    /// active commands remain with the driver until completion/reconciliation.
    pub fn abandon_request(&self, id: IoRequestId) {
        let state = {
            let mut requests = self.requests.write().unwrap_or_else(|e| e.into_inner());
            let Some(request) = requests.get_mut(&id) else {
                return;
            };
            request.abandoned = true;
            request.waker = None;
            request.state
        };
        if state == IoState::Pending {
            let _cancelled = self.cancel_request(id);
        } else if matches!(
            state,
            IoState::Completed | IoState::Failed | IoState::Cancelled
        ) {
            let completion = self
                .requests
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id)
                .and_then(|mut request| request.result.take());
            if let Some(completion) = completion {
                self.abandoned_completions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(completion);
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
            .and_then(|request| request.result.as_ref().map(IoCompletion::result))
    }

    /// Consume the terminal completion, including returned DMA ownership.
    pub fn take_result(&self, id: IoRequestId) -> Option<IoCompletion> {
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
            return requests
                .remove(&id)
                .and_then(|mut request| request.result.take());
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
    ) -> Poll<IoCompletion> {
        let mut reqs = self.requests.write().unwrap_or_else(|e| e.into_inner());
        let Some(req) = reqs.get_mut(&id) else {
            return Poll::Ready(IoCompletion::control(Err(IoError::InvalidParameter)));
        };

        match req.state {
            IoState::Completed | IoState::Failed | IoState::Cancelled => {
                // 完了済み: 結果を取り出して削除
                let completion = req
                    .result
                    .take()
                    .unwrap_or(IoCompletion::control(Err(IoError::DeviceError)));
                reqs.remove(&id);
                Poll::Ready(completion)
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

    /// Transfer ownership of completions whose observing future was dropped.
    /// The shutdown/reconciliation owner must explicitly close every returned
    /// CPU lease and retain any fallible close outcome.
    pub(crate) fn take_abandoned_completions(&self) -> Vec<IoCompletion> {
        core::mem::take(
            &mut *self
                .abandoned_completions
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        )
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
