use super::*;


mod _split_1;
pub use _split_1::*;
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

pub(crate) const IO_COMPLETION_QUEUE_SIZE: usize = 256;
pub(crate) const IO_COMPLETION_QUEUE_MASK: usize = IO_COMPLETION_QUEUE_SIZE - 1;
pub(crate) const IO_RESULT_ERROR_FLAG: u64 = 1 << 63;

/// ISR-safe deferred I/O completion queue (SPSC想定、MPMC非対応)
pub(crate) struct DeferredIoCompletionQueue {
    head: AtomicUsize,
    tail: AtomicUsize,
    devices: [AtomicU64; IO_COMPLETION_QUEUE_SIZE],
    ids: [AtomicU64; IO_COMPLETION_QUEUE_SIZE],
    results: [AtomicU64; IO_COMPLETION_QUEUE_SIZE],
}

impl DeferredIoCompletionQueue {
    pub(super) const fn new() -> Self {
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            devices: [ZERO; IO_COMPLETION_QUEUE_SIZE],
            ids: [ZERO; IO_COMPLETION_QUEUE_SIZE],
            results: [ZERO; IO_COMPLETION_QUEUE_SIZE],
        }
    }

    pub(super) fn push(&self, device: DeviceId, id: IoRequestId, result: IoResult) -> bool {
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

    pub(super) fn pop(&self) -> Option<(DeviceId, IoRequestId, IoResult)> {
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
pub(crate) const MAX_CPUS: usize = 64;

/// Per-CPU キュー配列
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

    /// 現在のCPUのキューにpush（ISRから呼び出し）
    pub(super) fn push(&self, device: DeviceId, id: IoRequestId, result: IoResult) -> bool {
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
    pub(super) fn pop_from_cpu(&self, cpu_idx: usize) -> Option<(DeviceId, IoRequestId, IoResult)> {
        if cpu_idx >= MAX_CPUS {
            return None;
        }
        self.queues[cpu_idx].pop()
    }

    /// 全CPUのキューからドレイン（メインloop用）
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

pub(crate) static DEFERRED_IO_COMPLETIONS: PerCpuDeferredCompletionQueues = PerCpuDeferredCompletionQueues::new();

/// 割り込みコンテキストから完了を遅延キューに追加
pub(crate) fn defer_io_completion(device: DeviceId, id: IoRequestId, result: IoResult) -> bool {
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

    pub(super) fn complete_pending(&self, device: DeviceId, request_id: IoRequestId) {
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
    pub(super) fn recover_overflow(&self) {
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
    pub(super) fn poll_by_global_mode(&self) {
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

pub(crate) static IO_SCHEDULER: spin::Once<Arc<IoScheduler>> = spin::Once::new();
pub(crate) static HYBRID_COORDINATOR: spin::Once<Arc<HybridIoCoordinator>> = spin::Once::new();

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
