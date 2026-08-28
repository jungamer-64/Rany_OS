use super::*;
use crate::sync::PoisonRwLock;

mod coordinator_helpers;
pub use coordinator_helpers::*;

impl Future for IoFuture {
    type Output = IoCompletion;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let scheduler = self.scheduler.clone();
        scheduler.poll_result_or_register_waker(self.request_id, cx.waker(), &mut self.registered)
    }
}

impl Drop for IoFuture {
    fn drop(&mut self) {
        self.scheduler.abandon_request(self.request_id);
    }
}

// ============================================================================
// Interrupt-to-Waker Bridge
// ============================================================================

pub struct IoInterruptBridge {
    pending_requests: PoisonRwLock<BTreeMap<DeviceId, VecDeque<IoRequestId>>>,
}

impl IoInterruptBridge {
    pub fn new(_scheduler: Arc<IoScheduler>) -> Self {
        Self {
            pending_requests: PoisonRwLock::new(BTreeMap::new()),
        }
    }

    pub fn register_pending(&self, device: DeviceId, request_id: IoRequestId) {
        let mut guard = self
            .pending_requests
            .write()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .entry(device)
            .or_insert_with(VecDeque::new)
            .push_back(request_id);
    }

    pub(super) fn complete_pending(&self, device: DeviceId, request_id: IoRequestId) {
        let mut pending_requests = self
            .pending_requests
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(pending) = pending_requests.get_mut(&device) {
            pending.retain(|id| *id != request_id);
            if pending.is_empty() {
                pending_requests.remove(&device);
            }
        }
    }

    pub fn pending_count(&self, device: DeviceId) -> usize {
        let guard = self
            .pending_requests
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard.get(&device).map(|q| q.len()).unwrap_or(0)
    }
}

// ============================================================================
// Hybrid I/O Coordinator
// ============================================================================

pub struct HybridIoCoordinator {
    pub(crate) scheduler: Arc<IoScheduler>,
    polling_executor: Arc<PollingExecutor>,
    interrupt_bridge: Arc<IoInterruptBridge>,
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

    pub fn polling_executor(&self) -> Arc<PollingExecutor> {
        self.polling_executor.clone()
    }
    pub fn interrupt_bridge(&self) -> Arc<IoInterruptBridge> {
        self.interrupt_bridge.clone()
    }

    pub fn submit_io_command(
        &self,
        device: DeviceId,
        command: IoCommand,
        priority: IoPriority,
    ) -> IoFuture {
        let id = self.scheduler.submit_command(device, command, priority);
        let global_mode = self.global_mode();
        if !matches!(global_mode, IoMode::Polling) {
            let mode = self.scheduler.device_mode(device);
            if !matches!(mode, IoMode::Polling) {
                self.interrupt_bridge.register_pending(device, id);
            }
        }
        IoFuture::new(self.scheduler.clone(), id)
    }

    pub(super) fn poll_by_global_mode(&self) {
        match self.global_mode() {
            IoMode::Polling => {
                self.polling_executor.poll_batch();
            }
            IoMode::Hybrid => {
                self.polling_executor.poll_once();
            }
            IoMode::Interrupt => {}
        }
    }

    pub fn tick<F>(&self, process_interrupts: F)
    where
        F: FnOnce(),
    {
        process_interrupts();
        self.scheduler.evaluate_modes(current_tick());
        self.dispatch_pending();
        self.poll_by_global_mode();
    }

    pub(super) fn dispatch_pending(&self) {
        const DISPATCH_BATCH_LIMIT: usize = 64;
        let Some(cpu_id) = crate::cpu::CurrentCpu::acquire().map(|current| current.id()) else {
            return;
        };
        for _ in 0..DISPATCH_BATCH_LIMIT {
            let id = match self.scheduler.next_request() {
                Some(id) => id,
                None => break,
            };
            let submission = match self.scheduler.take_submission(id) {
                Some(submission) => submission,
                None => continue,
            };
            let device = submission.device();
            let operation = submission.command.operation();
            let outcome = match self.scheduler.get_device_ops(device) {
                Some(ops) => ops.submit(submission, cpu_id),
                None => IoSubmitOutcome::Rejected {
                    cause: IoError::NotSupported,
                    submission,
                },
            };
            match outcome {
                IoSubmitOutcome::Accepted => {}
                IoSubmitOutcome::Rejected { cause, submission } => {
                    let (returned_id, returned_device, command) = submission.into_parts();
                    let cause = if returned_id == id && returned_device == device {
                        cause
                    } else {
                        IoError::DeviceError
                    };
                    self.scheduler
                        .complete_request(id, IoCompletion::rejected(command, cause));
                }
                IoSubmitOutcome::OutcomeUnknown { cause } => self
                    .scheduler
                    .complete_request(id, IoCompletion::outcome_unknown(operation, cause)),
            }
        }
    }

    pub fn set_global_mode(&self, mode: IoMode) {
        let mode_val = match mode {
            IoMode::Interrupt => 0,
            IoMode::Polling => 1,
            IoMode::Hybrid => 2,
        };
        self.global_mode.store(mode_val, Ordering::Release);
        match mode {
            IoMode::Polling | IoMode::Hybrid => self.polling_executor.start(),
            IoMode::Interrupt => self.polling_executor.stop(),
        }
    }

    pub fn global_mode(&self) -> IoMode {
        match self.global_mode.load(Ordering::Acquire) {
            0 => IoMode::Interrupt,
            1 => IoMode::Polling,
            _ => IoMode::Hybrid,
        }
    }
}

pub(crate) static IO_SCHEDULER: spin::Once<Arc<IoScheduler>> = spin::Once::new();
pub(crate) static HYBRID_COORDINATOR: spin::Once<Arc<HybridIoCoordinator>> = spin::Once::new();

pub fn init_io_scheduler() {
    let _ = io_scheduler();
    let _ = hybrid_coordinator();
    hybrid_coordinator().set_global_mode(IoMode::Polling);
}

pub fn io_scheduler() -> Arc<IoScheduler> {
    IO_SCHEDULER.call_once(|| Arc::new(IoScheduler::new()));
    IO_SCHEDULER
        .get()
        .expect("IO_SCHEDULER must be initialized")
        .clone()
}
