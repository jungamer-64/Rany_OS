use super::*;

mod io_future;
pub use io_future::*;

impl Default for IoScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl IoScheduler {
    pub const fn new() -> Self {
        Self {
            queues: [
                PoisonLock::new(VecDeque::new()),
                PoisonLock::new(VecDeque::new()),
                PoisonLock::new(VecDeque::new()),
                PoisonLock::new(VecDeque::new()),
                PoisonLock::new(VecDeque::new()),
            ],
            requests: PoisonLock::new(BTreeMap::new()),
            mode_controllers: PoisonRwLock::new(BTreeMap::new()),
            device_ops: PoisonRwLock::new(BTreeMap::new()),
            stats: IoSchedulerStats::new(),
            abandoned_completions: PoisonLock::new(Vec::new()),
            failed_closes: PoisonLock::new(Vec::new()),
            shutdown: AtomicBool::new(false),
        }
    }

    pub fn register_device(&self, device: DeviceId, thresholds: ModeThresholds) {
        self.mode_controllers
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                device,
                Arc::new(DeviceIoModeController::new(device, thresholds)),
            );
    }

    pub fn register_device_ops(&self, device: DeviceId, ops: Arc<dyn DeviceOps>) {
        self.device_ops
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .insert(device, ops);
    }

    pub fn unregister_device(&self, device: DeviceId) -> bool {
        self.mode_controllers
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&device);
        self.device_ops
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&device)
            .is_some()
    }

    pub fn get_device_ops(&self, device: DeviceId) -> Option<Arc<dyn DeviceOps>> {
        self.device_ops
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .get(&device)
            .cloned()
    }

    pub fn registered_devices(&self) -> Vec<DeviceId> {
        self.device_ops
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// Enqueue one owned command. Shutdown rejection still returns its complete
    /// CPU ownership through the same completion consumer as normal requests.
    ///
    /// # Panics
    /// Request identity exhaustion is terminal; identities must never wrap and
    /// replace live requests. No further command is admitted in that case.
    pub fn submit_command(
        self: &Arc<Self>,
        device: DeviceId,
        command: IoCommand,
        priority: IoPriority,
    ) -> IoFuture {
        let id = IoRequestId::next();
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let phase = if self.shutdown.load(Ordering::Acquire) {
            RequestPhase::Finished(IoCompletion::rejected(command, IoError::Cancelled))
        } else {
            RequestPhase::Queued(command)
        };
        let pending = matches!(phase, RequestPhase::Queued(_));
        requests.insert(
            id,
            IoRequest {
                id,
                device,
                phase,
                submitted_at: current_tick(),
                waker: None,
                hook: None,
                abandoned: false,
            },
        );
        self.stats.total_submitted.fetch_add(1, Ordering::Relaxed);
        if pending {
            let depth = self
                .stats
                .current_queue_depth
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            self.stats
                .max_queue_depth
                .fetch_max(depth, Ordering::Relaxed);
            self.queues[priority as usize]
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push_back(id);
        } else {
            self.stats.total_completed.fetch_add(1, Ordering::Relaxed);
            self.stats.total_errors.fetch_add(1, Ordering::Relaxed);
        }
        IoFuture {
            scheduler: self.clone(),
            request_id: id,
        }
    }

    fn next_request(&self) -> Option<IoRequestId> {
        for queue in self.queues.iter().rev() {
            if let Some(id) = queue
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pop_front()
            {
                return Some(id);
            }
        }
        None
    }

    /// Dispatch and cancellation both consume Queued under the same lock.
    /// No command can be borrowed, cloned, or dispatched twice.
    fn take_submission(&self, id: IoRequestId) -> Option<IoSubmission> {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.shutdown.load(Ordering::Acquire) {
            return None;
        }
        let request = requests.get_mut(&id)?;
        if !matches!(request.phase, RequestPhase::Queued(_)) {
            return None;
        }
        let RequestPhase::Queued(command) =
            core::mem::replace(&mut request.phase, RequestPhase::Dispatched)
        else {
            unreachable!("queued phase was checked under exclusive ownership")
        };
        Some(IoSubmission {
            completion: IoCompletionRoute {
                request_id: request.id,
                device: request.device,
            },
            command,
        })
    }

    fn report_completion_stats(&self, device: DeviceId, submitted_at: u64, status: IoResult) {
        self.stats.total_completed.fetch_add(1, Ordering::Relaxed);
        self.stats
            .current_queue_depth
            .fetch_sub(1, Ordering::Relaxed);
        if !matches!(status, IoResult::Success(_)) {
            self.stats.total_errors.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(controller) = self
            .mode_controllers
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .get(&device)
        {
            controller.record_completion(
                current_tick()
                    .saturating_sub(submitted_at)
                    .saturating_mul(1000),
            );
        }
    }

    /// Accept only the terminal outcome of a dispatched request. A duplicate,
    /// late, or unmatched event cannot overwrite another completion or consume
    /// queued CPU ownership; its resources remain in the finalization owner.
    pub(super) fn complete_request(&self, event: DeviceCompletion) {
        let DeviceCompletion { route, completion } = event;
        let id = route.request_id;
        let status = completion.result();
        let notification = {
            let mut requests = self
                .requests
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let Some(request) = requests.get_mut(&id).filter(|request| {
                request.device == route.device && matches!(request.phase, RequestPhase::Dispatched)
            }) else {
                drop(requests);
                self.retain_abandoned(completion);
                self.stats
                    .unmatched_completions
                    .fetch_add(1, Ordering::Relaxed);
                return;
            };
            request.phase = RequestPhase::Finished(completion);
            let notification = (
                request.device,
                request.submitted_at,
                request.waker.take(),
                request.hook.take(),
            );
            if request.abandoned {
                let request = requests
                    .remove(&id)
                    .expect("request remains under the same lock");
                let RequestPhase::Finished(completion) = request.phase else {
                    unreachable!("terminal phase was just installed")
                };
                self.retain_abandoned(completion);
            }
            notification
        };
        self.deliver_completion(notification, status);
    }

    fn deliver_completion(
        &self,
        (device, submitted_at, waker, hook): (DeviceId, u64, Option<Waker>, Option<CompletionHook>),
        status: IoResult,
    ) {
        self.report_completion_stats(device, submitted_at, status);
        // No scheduler lock may be held while invoking a reentrant consumer.
        if let Some(hook) = hook {
            hook.run(status);
        }
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Cancel before dispatch and preserve the original CPU lease. Once
    /// dispatched, cancellation is only abandonment of observation, never a
    /// claim that device access has stopped.
    pub(super) fn cancel_request(&self, id: IoRequestId) -> bool {
        let notification = {
            let mut requests = self
                .requests
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let Some(request) = requests.get_mut(&id) else {
                return false;
            };
            if !request.phase.cancel() {
                return false;
            }
            let notification = (
                request.device,
                request.submitted_at,
                request.waker.take(),
                request.hook.take(),
            );
            if request.abandoned {
                let request = requests
                    .remove(&id)
                    .expect("request remains under the same lock");
                let RequestPhase::Finished(completion) = request.phase else {
                    unreachable!("terminal phase was just installed")
                };
                self.retain_abandoned(completion);
            }
            notification
        };
        self.deliver_completion(notification, IoResult::Error(IoError::Cancelled));
        true
    }

    /// A dropped future cannot release a driver's in-flight buffer. A returned
    /// or not-yet-submitted lease is moved to this scheduler's finalization owner.
    fn abandon_request(&self, id: IoRequestId) {
        let (retired_waker, notification) = {
            let mut requests = self
                .requests
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let Some(request) = requests.get_mut(&id) else {
                return;
            };
            request.abandoned = true;
            let retired_waker = request.waker.take();
            let notification = request.phase.cancel().then(|| {
                (
                    request.device,
                    request.submitted_at,
                    None,
                    request.hook.take(),
                )
            });
            if matches!(request.phase, RequestPhase::Finished(_)) {
                let request = requests
                    .remove(&id)
                    .expect("request remains under the same lock");
                let RequestPhase::Finished(completion) = request.phase else {
                    unreachable!("terminal phase was checked under exclusive ownership")
                };
                self.retain_abandoned(completion);
            }
            (retired_waker, notification)
        };
        drop(retired_waker);
        if let Some(notification) = notification {
            self.deliver_completion(notification, IoResult::Error(IoError::Cancelled));
        }
    }

    pub fn get_state(&self, id: IoRequestId) -> Option<IoState> {
        self.requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&id)
            .map(|request| request.phase.state())
    }

    /// A status projection has no ownership or completion-publication authority.
    pub fn get_result(&self, id: IoRequestId) -> Option<IoResult> {
        self.requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&id)
            .and_then(|request| match &request.phase {
                RequestPhase::Finished(completion) => Some(completion.result()),
                _ => None,
            })
    }

    /// Poll and waker registration share a lock with completion publication.
    fn poll_result_or_register_waker(&self, id: IoRequestId, waker: &Waker) -> Poll<IoCompletion> {
        // RawWaker clone/drop callbacks may be reentrant. Neither runs while
        // holding scheduler state, including when replacing an older waker.
        let replacement = waker.clone();
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(request) = requests.get_mut(&id) else {
            return Poll::Ready(IoCompletion::control(Err(IoError::InvalidParameter)));
        };
        if matches!(request.phase, RequestPhase::Finished(_)) {
            let request = requests
                .remove(&id)
                .expect("request remains under the same lock");
            let RequestPhase::Finished(completion) = request.phase else {
                unreachable!("terminal phase was checked under exclusive ownership")
            };
            Poll::Ready(completion)
        } else {
            let retired = if request
                .waker
                .as_ref()
                .is_none_or(|old| !old.will_wake(waker))
            {
                request.waker.replace(replacement)
            } else {
                Some(replacement)
            };
            drop(requests);
            drop(retired);
            Poll::Pending
        }
    }

    /// Register one status observer. Returning the hook on failure preserves
    /// the caller's notification responsibility.
    ///
    /// # Errors
    /// Returns the hook if the request was consumed or already has an observer.
    pub fn register_completion_hook(
        &self,
        id: IoRequestId,
        hook: CompletionHook,
    ) -> Result<(), CompletionHook> {
        let status = {
            let mut requests = self
                .requests
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let Some(request) = requests.get_mut(&id) else {
                return Err(hook);
            };
            if request.hook.is_some() {
                return Err(hook);
            }
            match &request.phase {
                RequestPhase::Finished(completion) => completion.result(),
                _ => {
                    request.hook = Some(hook);
                    return Ok(());
                }
            }
        };
        hook.run(status);
        Ok(())
    }

    fn retain_abandoned(&self, completion: IoCompletion) {
        self.abandoned_completions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(completion);
    }

    /// Attempt fallible finalization outside the request lock. Failed unmaps
    /// remain owned here until the device-reset reconciliation owner claims them.
    pub fn reap_abandoned(&self) {
        let completions = core::mem::take(
            &mut *self
                .abandoned_completions
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        );
        for completion in completions {
            if let IoCompletion::TransferReturned { buffer, .. } = completion
                && let Err(failure) = buffer.close()
            {
                self.failed_closes
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(failure);
            }
        }
    }

    pub fn device_mode(&self, device: DeviceId) -> IoMode {
        self.mode_controllers
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .get(&device)
            .map_or(IoMode::Interrupt, |controller| controller.current_mode())
    }

    pub fn evaluate_modes(&self, current_tick: u64) {
        for controller in self
            .mode_controllers
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .values()
        {
            controller.evaluate_mode(current_tick);
        }
    }

    pub fn stats(&self) -> &IoSchedulerStats {
        &self.stats
    }

    /// Stop admission, cancel queued owners, and leave dispatched requests with
    /// their device owners. This does not assert hardware shutdown completion.
    pub fn shutdown(&self) {
        let pending: Vec<_> = {
            let requests = self
                .requests
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            self.shutdown.store(true, Ordering::Release);
            requests
                .iter()
                .filter_map(|(id, request)| {
                    matches!(request.phase, RequestPhase::Queued(_)).then_some(*id)
                })
                .collect()
        };
        for id in pending {
            self.cancel_request(id);
        }
        self.reap_abandoned();
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}
