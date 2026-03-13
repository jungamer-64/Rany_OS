use super::*;
use crate::sync::{MpscRingBuffer, PoisonRwLock};

mod coordinator_helpers;
pub use coordinator_helpers::*;

impl Future for IoFuture {
    type Output = Result<usize, IoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let scheduler = self.scheduler.clone();
        scheduler.poll_result_or_register_waker(self.request_id, cx.waker(), &mut self.registered)
    }
}

impl Drop for IoFuture {
    fn drop(&mut self) {
        if self.scheduler.cancel_request_if_pending(self.request_id) {
            return;
        }
        self.scheduler.abandon_request(self.request_id);
    }
}

// ============================================================================
// Deferred I/O Completions (ISR-safe queue)
// ============================================================================

pub(crate) const IO_COMPLETION_QUEUE_SIZE: usize = 256;
pub(crate) const IO_COMPLETION_QUEUE_BACKING_SIZE: usize = IO_COMPLETION_QUEUE_SIZE + 1;
pub(crate) const IO_RESULT_ERROR_FLAG: u64 = 1 << 63;
type DeferredIoCompletion = (u64, u64, u64);

pub(crate) struct DeferredIoCompletionQueue {
    queue: MpscRingBuffer<DeferredIoCompletion, IO_COMPLETION_QUEUE_BACKING_SIZE>,
}

impl DeferredIoCompletionQueue {
    pub(super) const CAPACITY: usize = IO_COMPLETION_QUEUE_SIZE;

    pub(super) const fn new() -> Self {
        Self {
            queue: MpscRingBuffer::new(),
        }
    }

    pub(super) fn push(&self, device: DeviceId, id: IoRequestId, result: IoResult) -> bool {
        self.queue
            .push((encode_device_id(device), id.0, encode_io_result(result)))
            .is_ok()
    }

    pub(super) fn pop(&self) -> Option<(DeviceId, IoRequestId, IoResult)> {
        self.queue.pop().map(|(device_raw, id_raw, result_raw)| {
            let device = decode_device_id(device_raw).unwrap_or(DeviceId::Custom(0));
            let id = IoRequestId(id_raw);
            let result = decode_io_result(result_raw);
            (device, id, result)
        })
    }

    pub(super) fn len(&self) -> usize {
        self.queue.len()
    }

    pub(super) const fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

pub(crate) const MAX_CPUS: usize = 64;

pub(crate) struct PerCpuDeferredCompletionQueues {
    queues: [DeferredIoCompletionQueue; MAX_CPUS],
}

impl PerCpuDeferredCompletionQueues {
    pub(super) const fn new() -> Self {
        const QUEUE: DeferredIoCompletionQueue = DeferredIoCompletionQueue::new();
        Self {
            queues: [QUEUE; MAX_CPUS],
        }
    }

    pub(super) fn push(&self, device: DeviceId, id: IoRequestId, result: IoResult) -> bool {
        let cpu_idx = crate::cpu::current_id();
        if cpu_idx >= MAX_CPUS {
            return false;
        }
        self.queues[cpu_idx].push(device, id, result)
    }

    pub(super) fn pop_from_cpu(&self, cpu_idx: usize) -> Option<(DeviceId, IoRequestId, IoResult)> {
        if cpu_idx >= MAX_CPUS {
            return None;
        }
        self.queues[cpu_idx].pop()
    }

    pub(super) fn drain_all<F>(&self, mut callback: F) -> usize
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

pub(crate) static DEFERRED_IO_COMPLETIONS: PerCpuDeferredCompletionQueues =
    PerCpuDeferredCompletionQueues::new();

pub(crate) fn defer_io_completion(device: DeviceId, id: IoRequestId, result: IoResult) -> bool {
    DEFERRED_IO_COMPLETIONS.push(device, id, result)
}

pub fn process_deferred_completions() -> usize {
    let coordinator = hybrid_coordinator();
    let scheduler = coordinator.scheduler.clone();
    let bridge = coordinator.interrupt_bridge();
    DEFERRED_IO_COMPLETIONS.drain_all(|device, id, result| {
        scheduler.complete_request(id, result);
        bridge.complete_pending(device, id);
    })
}

pub fn process_deferred_completions_local() -> usize {
    let cpu_idx = crate::cpu::current_id();
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

pub(crate) fn encode_device_id(device: DeviceId) -> u64 {
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
        } => (KIND_NVME << KIND_SHIFT) | ((controller as u64) << 48) | (namespace as u64),
        DeviceId::VirtioBlk { index } => (KIND_VIRTIO_BLK << KIND_SHIFT) | ((index as u64) << 48),
        DeviceId::VirtioNet { index } => (KIND_VIRTIO_NET << KIND_SHIFT) | ((index as u64) << 48),
        DeviceId::Ahci { port } => (KIND_AHCI << KIND_SHIFT) | ((port as u64) << 48),
        DeviceId::Usb { bus, device } => {
            (KIND_USB << KIND_SHIFT) | ((bus as u64) << 48) | ((device as u64) << 40)
        }
        DeviceId::Custom(code) => (KIND_CUSTOM << KIND_SHIFT) | (code as u64),
    }
}

pub(crate) fn decode_device_id(raw: u64) -> Option<DeviceId> {
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

pub(crate) fn encode_io_result(result: IoResult) -> u64 {
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

pub(crate) fn decode_io_result(raw: u64) -> IoResult {
    if (raw & IO_RESULT_ERROR_FLAG) == 0 {
        return IoResult::Success(raw as usize);
    }
    let code = (raw & 0xFF) as u8;
    IoResult::Error(io_error_from_u8(code))
}

pub(crate) fn io_error_to_u8(err: IoError) -> u8 {
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

pub(crate) fn io_error_from_u8(code: u8) -> IoError {
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

pub struct IoInterruptBridge {
    scheduler: Arc<IoScheduler>,
    pending_requests: PoisonRwLock<BTreeMap<DeviceId, VecDeque<IoRequestId>>>,
    dropped_completions: AtomicU64,
    overflow_flag: AtomicBool,
}

impl IoInterruptBridge {
    pub fn new(scheduler: Arc<IoScheduler>) -> Self {
        Self {
            scheduler,
            pending_requests: PoisonRwLock::new(BTreeMap::new()),
            dropped_completions: AtomicU64::new(0),
            overflow_flag: AtomicBool::new(false),
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

    pub fn handle_interrupt(&self, device: DeviceId, results: &[(IoRequestId, IoResult)]) {
        for (id, result) in results {
            if !defer_io_completion(device, *id, result.clone()) {
                self.dropped_completions.fetch_add(1, Ordering::Relaxed);
                self.overflow_flag.store(true, Ordering::Release);
            }
        }
    }

    pub fn check_and_clear_overflow(&self) -> bool {
        self.overflow_flag.swap(false, Ordering::AcqRel)
    }

    pub fn dropped_completions(&self) -> u64 {
        self.dropped_completions.load(Ordering::Relaxed)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn deferred_io_completion_queue_preserves_full_capacity() {
        let queue = DeferredIoCompletionQueue::new();

        for i in 0..IO_COMPLETION_QUEUE_SIZE {
            assert!(
                queue.push(
                    DeviceId::Custom(i as u32),
                    IoRequestId(i as u64 + 1),
                    IoResult::Success(i),
                ),
                "failed at {}",
                i
            );
        }
        assert!(!queue.push(
            DeviceId::Custom(u32::MAX),
            IoRequestId(u64::MAX),
            IoResult::Success(0),
        ));
        assert_eq!(queue.len(), IO_COMPLETION_QUEUE_SIZE);
        assert_eq!(queue.capacity(), IO_COMPLETION_QUEUE_SIZE);
        assert!(!queue.is_empty());

        for i in 0..IO_COMPLETION_QUEUE_SIZE {
            match queue.pop() {
                Some((device_id, request_id, IoResult::Success(result))) => {
                    assert_eq!(device_id, DeviceId::Custom(i as u32));
                    assert_eq!(request_id, IoRequestId(i as u64 + 1));
                    assert_eq!(result, i);
                }
                other => panic!("unexpected completion entry: {:?}", other),
            }
        }
        assert!(queue.pop().is_none());
        assert!(queue.is_empty());
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
                let id = self.scheduler.submit(device, operation, priority);
                let global_mode = self.global_mode();
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

    pub(super) fn recover_overflow(&self) {
        let was_active = self.polling_executor.is_active();
        if !was_active {
            self.polling_executor.start();
        }
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
        let cpu_idx = crate::cpu::current_id();
        while let Some((device, id, result)) = DEFERRED_IO_COMPLETIONS.pop_from_cpu(cpu_idx) {
            self.scheduler.complete_request(id, result);
            self.interrupt_bridge.complete_pending(device, id);
        }
        if self.interrupt_bridge.check_and_clear_overflow() {
            self.recover_overflow();
        }
        self.scheduler.evaluate_modes(current_tick());
        self.dispatch_pending();
        self.poll_by_global_mode();
    }

    pub(super) fn dispatch_pending(&self) {
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
            let ops = self.scheduler.get_device_ops(request.device);
            let cpu_idx = crate::cpu::current_id();
            let result = match ops {
                Some(ops) => ops.submit(&request, cpu_idx),
                None => Err(IoError::NotSupported),
            };
            if let Err(err) = result {
                self.scheduler.complete_request(id, IoResult::Error(err));
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
