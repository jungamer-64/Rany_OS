// ============================================================================
// src/task/executor.rs - Lock-Free Executor with Work Stealing
// 設計書 4.1: Async/await firstのスケジューリング
// 設計書 4.3: マルチコアスケーリング
// ============================================================================
//!
//! # ロックフリー Executor（BSP / シングルコア段階用）
//!
//! ## アーキテクチャ上の位置づけ
//!
//! 本モジュールは **BSP（Bootstrap Processor）**起動直後から使用される
//! プライマリExecutorです。`kmain_inner` のメインループで駆動されます。
//!
//! **注意:** [`per_core_executor`](super::per_core_executor) にも `TaskId`,
//! `Task`, `TaskState` 型が独立して定義されていますが、これは **意図的な設計**
//! です。本モジュールは `super::TaskId`（`task/mod.rs` で定義）を使用し、
//! BSP段階のシンプルなタスク管理に特化しています。SMP起動後の Per-Core
//! Executor は独自のライフサイクル管理が必要なため、型を分離しています。
//!
//! ## 設計方針
//! - ロックフリーキューでコンテンション削減
//! - Per-CPUローカルキャッシュによるキャッシュ効率向上
//! - Work Stealingによる負荷分散
//!
//! ## 実装
//! - AtomicベースのMPSC Queueを内部で実装
//! - ローカルキュー → グローバルキュー → スティールの優先順位
//! - batch処理でスループット向上
//! - Per-coreタスクストアでロックコンテンション削減（設計書 4.3）
#![allow(dead_code)]

use super::{Task, TaskId, create_waker};
use crate::sync::{MpscRingBuffer, PoisonLock};
use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};
#[cfg(not(feature = "qemu-test-export"))]
use x86_64::instructions::interrupts;

// ============================================================================
// ロックフリーキュー（単一コンシューマー向け MPSC 実装）
// ============================================================================

/// ロックフリーのタスクID キュー
///
/// 実際のタスクはPer-coreタスクストアに保存し、
/// キューはTaskIdのみを管理してオーバーヘッド削減。
mod stats_impl;
pub struct LockFreeQueue {
    buffer: MpscRingBuffer<TaskId, QUEUE_BACKING_SIZE>,
}

const QUEUE_SIZE: usize = 1024;
const QUEUE_BACKING_SIZE: usize = QUEUE_SIZE + 1;

impl LockFreeQueue {
    /// 新しいキューを作成
    pub const fn new() -> Self {
        Self {
            buffer: MpscRingBuffer::new(),
        }
    }

    /// タスクIDをプッシュ（try）
    pub fn push(&self, task_id: TaskId) -> bool {
        self.buffer.push(task_id).is_ok()
    }

    /// タスクIDをポップ（try）
    pub fn pop(&self) -> Option<TaskId> {
        self.buffer.pop()
    }

    /// キューが空かどうか
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// キュー内のアイテム数
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
}

// ============================================================================
// グローバルキュー
// ============================================================================

/// グローバルなロックフリータスクキュー
static GLOBAL_QUEUE: LockFreeQueue = LockFreeQueue::new();

/// 最大CPU数
const MAX_CPUS: usize = 64;

/// Per-coreタスクストア
/// 設計書 4.3: コアローカルなタスク管理でロックコンテンション削減
struct PerCoreTaskStore {
    /// タスク保存マップ（Per-core）
    tasks: PoisonLock<BTreeMap<TaskId, Task>>,
    /// このCPUが有効かどうか
    active: AtomicBool,
    /// 保存タスク数（統計用）
    task_count: AtomicUsize,
}

impl PerCoreTaskStore {
    const fn new() -> Self {
        Self {
            tasks: PoisonLock::new(BTreeMap::new()),
            active: AtomicBool::new(false),
            task_count: AtomicUsize::new(0),
        }
    }

    /// タスクを追加
    fn insert(&self, task_id: TaskId, task: Task) {
        match self.tasks.lock() {
            Ok(mut guard) => {
                guard.insert(task_id, task);
                self.task_count.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                log::error!("[EXECUTOR] Per-core tasks lock poisoned during insert; dropping task");
            }
        }
    }

    /// タスクを取り出し
    fn remove(&self, task_id: &TaskId) -> Option<Task> {
        match self.tasks.lock() {
            Ok(mut guard) => {
                let result = guard.remove(task_id);
                if result.is_some() {
                    self.task_count.fetch_sub(1, Ordering::Relaxed);
                }
                result
            }
            Err(_) => {
                log::error!(
                    "[EXECUTOR] Per-core tasks lock poisoned during remove; cannot remove task"
                );
                None
            }
        }
    }

    /// タスク数を取得
    fn len(&self) -> usize {
        self.task_count.load(Ordering::Relaxed)
    }

    /// Work Stealing: タスクを1つ盗む
    fn steal_one(&self) -> Option<(TaskId, Task)> {
        match self.tasks.lock() {
            Ok(mut guard) => {
                if let Some((&task_id, _)) = guard.iter().next() {
                    if let Some(task) = guard.remove(&task_id) {
                        self.task_count.fetch_sub(1, Ordering::Relaxed);
                        return Some((task_id, task));
                    }
                }
                None
            }
            Err(_) => {
                log::error!("[EXECUTOR] Per-core tasks lock poisoned during steal - cannot steal");
                None
            }
        }
    }
}

/// Per-coreタスクストア配列
static PER_CORE_STORES: [PerCoreTaskStore; MAX_CPUS] = {
    const INIT: PerCoreTaskStore = PerCoreTaskStore::new();
    [INIT; MAX_CPUS]
};

// Legacy global task store removed — migrate to `PER_CORE_STORES` instead.

/// Wake queue（ISR-safe ロックフリー）
static WAKE_QUEUE: LockFreeQueue = LockFreeQueue::new();

/// 統計情報
static EXECUTOR_STATS: ExecutorStats = ExecutorStats::new();
static EXECUTOR_INITDBG_STAGE: AtomicUsize = AtomicUsize::new(0);
static EXECUTOR_SPAWNDBG_COUNT: AtomicUsize = AtomicUsize::new(0);
// Keep RUNDBG poll spam disabled in normal runtime unless this counter is
// explicitly reset by debug-only instrumentation.
// `usize::MAX` would wrap to 0 at first `fetch_add`, unintentionally enabling
// debug spam. Start from the cutoff so default runtime stays quiet.
static EXECUTOR_RUNDBG_POLLS: AtomicUsize = AtomicUsize::new(1024);
const NO_POLLED_TASK_ID: u64 = u64::MAX;
const NO_POLLED_TASK_CPU: usize = usize::MAX;
static CURRENT_POLLED_TASK_ID: AtomicU64 = AtomicU64::new(NO_POLLED_TASK_ID);
static CURRENT_POLLED_TASK_DOMAIN: AtomicU64 = AtomicU64::new(0);
static CURRENT_POLLED_TASK_CPU: AtomicUsize = AtomicUsize::new(NO_POLLED_TASK_CPU);
const EXECUTOR_PHASE_IDLE: u8 = 0;
const EXECUTOR_PHASE_LOOP: u8 = 1;
const EXECUTOR_PHASE_SUSPENDED: u8 = 2;
const EXECUTOR_PHASE_RUN_READY: u8 = 3;
const EXECUTOR_PHASE_POLLING: u8 = 4;
const EXECUTOR_PHASE_WAKE_QUEUE: u8 = 5;
const EXECUTOR_PHASE_FETCH_GLOBAL: u8 = 6;
const EXECUTOR_PHASE_WORK_STEAL: u8 = 7;
const EXECUTOR_PHASE_QUIESCENT: u8 = 8;
const EXECUTOR_PHASE_WAITING: u8 = 9;
static CURRENT_EXECUTOR_PHASE: [AtomicU8; MAX_CPUS] = {
    const INIT: AtomicU8 = AtomicU8::new(EXECUTOR_PHASE_IDLE);
    [INIT; MAX_CPUS]
};
static REMOTE_WAKE_READY: [AtomicBool; MAX_CPUS] = {
    const INIT: AtomicBool = AtomicBool::new(false);
    [INIT; MAX_CPUS]
};

#[inline]
fn executor_serial_mark(marker: u8) {
    crate::io::log::debug_serial_mark(marker);
}

/// アクティブCPU数
static ACTIVE_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolledTaskContext {
    pub cpu_id: usize,
    pub task_id: u64,
    pub domain_id: u64,
}

fn mark_current_polled_task(
    cpu_id: usize,
    task_id: TaskId,
    domain_id: crate::domain_system::DomainId,
) {
    CURRENT_POLLED_TASK_CPU.store(cpu_id, Ordering::Release);
    CURRENT_POLLED_TASK_DOMAIN.store(domain_id.as_u64(), Ordering::Release);
    CURRENT_POLLED_TASK_ID.store(task_id.as_u64(), Ordering::Release);
}

fn clear_current_polled_task() {
    CURRENT_POLLED_TASK_ID.store(NO_POLLED_TASK_ID, Ordering::Release);
    CURRENT_POLLED_TASK_DOMAIN.store(0, Ordering::Release);
    CURRENT_POLLED_TASK_CPU.store(NO_POLLED_TASK_CPU, Ordering::Release);
}

pub fn current_polled_task_context() -> Option<PolledTaskContext> {
    let task_id = CURRENT_POLLED_TASK_ID.load(Ordering::Acquire);
    if task_id == NO_POLLED_TASK_ID {
        return None;
    }

    let cpu_id = CURRENT_POLLED_TASK_CPU.load(Ordering::Acquire);
    if cpu_id == NO_POLLED_TASK_CPU {
        return None;
    }

    Some(PolledTaskContext {
        cpu_id,
        task_id,
        domain_id: CURRENT_POLLED_TASK_DOMAIN.load(Ordering::Acquire),
    })
}

fn set_current_executor_phase(cpu_id: usize, phase: u8) {
    if cpu_id < MAX_CPUS {
        CURRENT_EXECUTOR_PHASE[cpu_id].store(phase, Ordering::Release);
    }
}

fn executor_phase_name(phase: u8) -> Option<&'static str> {
    match phase {
        EXECUTOR_PHASE_IDLE => Some("idle"),
        EXECUTOR_PHASE_LOOP => Some("loop"),
        EXECUTOR_PHASE_SUSPENDED => Some("suspended"),
        EXECUTOR_PHASE_RUN_READY => Some("run_ready"),
        EXECUTOR_PHASE_POLLING => Some("polling"),
        EXECUTOR_PHASE_WAKE_QUEUE => Some("wake_queue"),
        EXECUTOR_PHASE_FETCH_GLOBAL => Some("fetch_global"),
        EXECUTOR_PHASE_WORK_STEAL => Some("work_steal"),
        EXECUTOR_PHASE_QUIESCENT => Some("quiescent"),
        EXECUTOR_PHASE_WAITING => Some("waiting"),
        _ => None,
    }
}

pub fn current_executor_phase(cpu_id: usize) -> Option<&'static str> {
    if cpu_id >= MAX_CPUS {
        return None;
    }

    executor_phase_name(CURRENT_EXECUTOR_PHASE[cpu_id].load(Ordering::Acquire))
}

fn mark_remote_wake_ready(cpu_id: usize) {
    if cpu_id < MAX_CPUS {
        REMOTE_WAKE_READY[cpu_id].store(true, Ordering::Release);
    }
}

fn has_ready_remote_workers() -> bool {
    for cpu_id in 1..active_cpu_count().min(MAX_CPUS) {
        if REMOTE_WAKE_READY[cpu_id].load(Ordering::Acquire) {
            return true;
        }
    }
    false
}

fn should_notify_remote_workers() -> bool {
    active_cpu_count() > 1 && crate::smp::runtime_workers_released() && has_ready_remote_workers()
}

fn notify_remote_workers_if_needed() {
    if should_notify_remote_workers() {
        crate::io::interrupt_manager::broadcast_ipi(crate::interrupts::EXECUTOR_WAKE_VECTOR);
    }
}

/// CPUをアクティブとして登録
pub fn register_cpu(cpu_id: usize) {
    if cpu_id < MAX_CPUS {
        PER_CORE_STORES[cpu_id]
            .active
            .store(true, Ordering::Release);
    }
}

/// アクティブCPU数を取得
pub fn active_cpu_count() -> usize {
    ACTIVE_CPU_COUNT.load(Ordering::Relaxed)
}

/// ブート時に既知のアクティブCPU数を反映する。
pub fn set_active_cpu_count(count: usize) {
    ACTIVE_CPU_COUNT.store(count.max(1).min(MAX_CPUS), Ordering::Release);
}

/// タスクをwake queueに追加（Wakerから呼ばれる）
pub fn wake_task(task_id: TaskId) {
    WAKE_QUEUE.push(task_id);
    EXECUTOR_STATS.wakeups.fetch_add(1, Ordering::Relaxed);
    notify_remote_workers_if_needed();
}

pub(crate) fn run_boxed_cold_start(cpu_id: usize) -> ! {
    // Keep the helper name stable for the AP handoff path, but avoid touching
    // the global allocator before the worker has fully entered the primary
    // executor loop.
    crate::smp::set_runtime_worker_stage(cpu_id, crate::smp::RuntimeWorkerStage::ColdStartHelper);
    let mut executor = Executor::with_cpu_id_cold_start(cpu_id);
    crate::smp::set_runtime_worker_stage(
        cpu_id,
        crate::smp::RuntimeWorkerStage::ExecutorConstructed,
    );
    crate::smp::set_runtime_worker_stage(cpu_id, crate::smp::RuntimeWorkerStage::ExecutorRun);
    executor.run();
}

// ============================================================================
// Executor本体
// ============================================================================

/// ロックフリー Executor
pub struct Executor {
    /// ローカルキュー（Per-CPU）
    local_queue: VecDeque<Task>,
    /// クォータ制御で一時停止中のタスク
    suspended_queue: VecDeque<(u64, Task)>,
    /// ローカルキャッシュ（高速アクセス用）
    local_cache: VecDeque<TaskId>,
    /// CPUインデックス（Work Stealing用）
    cpu_id: usize,
    /// バッチサイズ
    batch_size: usize,
}

impl Executor {
    /// 新しいExecutorを作成
    pub fn new() -> Self {
        Self::with_cpu_id(0)
    }

    /// CPU IDを指定してExecutorを作成
    pub fn with_cpu_id(cpu_id: usize) -> Self {
        Self::with_cpu_id_internal(cpu_id, true)
    }

    /// AP handoff 直後は allocator への初回タッチを減らしたいので
    /// preallocation なしの cold-start executor も用意する。
    pub(crate) fn with_cpu_id_cold_start(cpu_id: usize) -> Self {
        Self::with_cpu_id_internal(cpu_id, false)
    }

    fn with_cpu_id_internal(cpu_id: usize, preallocate: bool) -> Self {
        Self {
            local_queue: if preallocate {
                VecDeque::with_capacity(256)
            } else {
                VecDeque::new()
            },
            suspended_queue: if preallocate {
                VecDeque::with_capacity(64)
            } else {
                VecDeque::new()
            },
            local_cache: if preallocate {
                VecDeque::with_capacity(64)
            } else {
                VecDeque::new()
            },
            cpu_id,
            batch_size: 32,
        }
    }

    /// タスクをローカルキューにスケジュール
    pub fn spawn(&mut self, task: Task) {
        let _ = EXECUTOR_SPAWNDBG_COUNT.fetch_add(1, Ordering::Relaxed);
        self.local_queue.push_back(task);
        EXECUTOR_STATS.tasks_spawned.fetch_add(1, Ordering::Relaxed);
    }

    /// グローバルキューにタスクを追加
    pub fn spawn_global(task: Task) {
        let task_id = task.id;
        // CPU 0のper-coreストアに追加（デフォルト）
        PER_CORE_STORES[0].insert(task_id, task);
        GLOBAL_QUEUE.push(task_id);
        EXECUTOR_STATS.tasks_spawned.fetch_add(1, Ordering::Relaxed);
        notify_remote_workers_if_needed();
    }

    /// 指定CPUにタスクをスポーン
    pub fn spawn_on_cpu(task: Task, cpu_id: usize) {
        let task_id = task.id;
        let target_cpu = if cpu_id < MAX_CPUS { cpu_id } else { 0 };
        crate::task::fuel::Fuel::refill(crate::task::fuel::FuelConfig::DEFAULT.default_fuel);
        PER_CORE_STORES[target_cpu].insert(task_id, task);
        GLOBAL_QUEUE.push(task_id);
        EXECUTOR_STATS.tasks_spawned.fetch_add(1, Ordering::Relaxed);
        notify_remote_workers_if_needed();
    }

    #[inline]
    fn runs_global_runtime_maintenance(&self) -> bool {
        self.cpu_id == 0
    }

    #[inline]
    fn runs_cross_cpu_work_stealing(&self) -> bool {
        self.cpu_id == 0
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub(crate) fn drive_once_for_test(&mut self) {
        // Keep this in sync with the non-idle portion of `run()` so qemu-test
        // runtime suites exercise the same phase-2 executor path.
        if self.runs_global_runtime_maintenance() {
            crate::interrupts::poll_timer_events();
            crate::io::hid::keyboard::process_pending_wakes();
            crate::task::timer::process_pending_timer_wakers();
            crate::task::interrupt_waker::process_interrupt_events();
            crate::io::io_scheduler::process_deferred_completions();
            crate::sync::process_deferred_wakes();
            crate::sync::process_deferred_waker_queue_wakes();
            crate::io::io_scheduler::hybrid_coordinator().tick(|| {
                crate::task::interrupt_waker::process_interrupt_events();
            });
            crate::io::iommu::api::process_pending_command_queues();
        }
        self.process_suspended_tasks();
        crate::task::fuel::Fuel::refill(crate::task::fuel::FuelConfig::DEFAULT.default_fuel);
        self.run_ready_tasks();
        self.process_wake_queue();
        self.fetch_from_global();
        if self.runs_cross_cpu_work_stealing()
            && self.local_queue.is_empty()
            && self.local_cache.is_empty()
        {
            self.try_steal();
        }
        crate::loader::live_update::enter_quiescent_state();
        if self.runs_global_runtime_maintenance() {
            crate::loader::live_update::poll_pending_updates();
            crate::driver_domain::hot_swap::poll_validation_windows();
            crate::io::log::kick_serial_tx();
        }
    }

    /// メインループ
    pub fn run(&mut self) -> ! {
        let bsp_debug = false;
        if !bsp_debug {
            executor_serial_mark(b'M');
            executor_serial_mark(b'0' + (self.cpu_id as u8 % 10));
        }
        if !crate::interrupts::are_interrupts_enabled() {
            if !bsp_debug {
                executor_serial_mark(b'N');
            }
            if self.cpu_id != 0 {
                mark_remote_wake_ready(self.cpu_id);
            }
            set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_LOOP);
            crate::interrupts::enable_interrupts();
            if !bsp_debug {
                executor_serial_mark(b'O');
            }
        }

        // LOOP_PROOF: mode=event; reason=Executor loop is intentional for kernel lifetime and each pass handles finite work slices.;
        loop {
            if !bsp_debug {
                executor_serial_mark(b'P');
            }
            if self.cpu_id != 0 {
                mark_remote_wake_ready(self.cpu_id);
            }
            set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_LOOP);
            let initdbg_stage = EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed);
            if bsp_debug
                && initdbg_stage == 0
                && EXECUTOR_INITDBG_STAGE
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                crate::io::log::early_print("[RUNDBG] loop entered\n");
            } else if bsp_debug
                && initdbg_stage == 17
                && EXECUTOR_INITDBG_STAGE
                    .compare_exchange(17, 100, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                crate::io::log::early_print("[RUNDBG] second loop entered\n");
            }
            // 0. Process pending interrupt events and deferred waker notifications (non-ISR)
            if self.runs_global_runtime_maintenance() {
                crate::interrupts::poll_timer_events();
                if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 1 {
                    crate::io::log::early_print("[RUNDBG] after poll_timer_events\n");
                    EXECUTOR_INITDBG_STAGE.store(2, Ordering::Release);
                } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 100 {
                    crate::io::log::early_print("[RUNDBG2] after poll_timer_events\n");
                    EXECUTOR_INITDBG_STAGE.store(101, Ordering::Release);
                }
                crate::io::hid::keyboard::process_pending_wakes();
                if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 2 {
                    crate::io::log::early_print("[RUNDBG] after keyboard wakes\n");
                    EXECUTOR_INITDBG_STAGE.store(3, Ordering::Release);
                } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 101 {
                    crate::io::log::early_print("[RUNDBG2] after keyboard wakes\n");
                    EXECUTOR_INITDBG_STAGE.store(102, Ordering::Release);
                }
                crate::task::timer::process_pending_timer_wakers();
                if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 3 {
                    crate::io::log::early_print("[RUNDBG] after timer wakers\n");
                    EXECUTOR_INITDBG_STAGE.store(4, Ordering::Release);
                } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 102 {
                    crate::io::log::early_print("[RUNDBG2] after timer wakers\n");
                    EXECUTOR_INITDBG_STAGE.store(103, Ordering::Release);
                }
                crate::task::interrupt_waker::process_interrupt_events();
                if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 4 {
                    crate::io::log::early_print("[RUNDBG] after interrupt events\n");
                    EXECUTOR_INITDBG_STAGE.store(5, Ordering::Release);
                } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 103 {
                    crate::io::log::early_print("[RUNDBG2] after interrupt events\n");
                    EXECUTOR_INITDBG_STAGE.store(104, Ordering::Release);
                }
                crate::io::io_scheduler::process_deferred_completions();
                if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 5 {
                    crate::io::log::early_print("[RUNDBG] after deferred completions\n");
                    EXECUTOR_INITDBG_STAGE.store(6, Ordering::Release);
                } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 104 {
                    crate::io::log::early_print("[RUNDBG2] after deferred completions\n");
                    EXECUTOR_INITDBG_STAGE.store(105, Ordering::Release);
                }
                crate::sync::process_deferred_wakes();
                if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 6 {
                    crate::io::log::early_print("[RUNDBG] after deferred atomic wakes\n");
                    EXECUTOR_INITDBG_STAGE.store(7, Ordering::Release);
                } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 105 {
                    crate::io::log::early_print("[RUNDBG2] after deferred atomic wakes\n");
                    EXECUTOR_INITDBG_STAGE.store(106, Ordering::Release);
                }
                crate::sync::process_deferred_waker_queue_wakes();
                if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 7 {
                    crate::io::log::early_print("[RUNDBG] after deferred waker queue wakes\n");
                    EXECUTOR_INITDBG_STAGE.store(8, Ordering::Release);
                } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 106 {
                    crate::io::log::early_print("[RUNDBG2] after deferred waker queue wakes\n");
                    EXECUTOR_INITDBG_STAGE.store(107, Ordering::Release);
                }
                crate::io::io_scheduler::hybrid_coordinator().tick(|| {
                    crate::task::interrupt_waker::process_interrupt_events();
                });
                if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 8 {
                    crate::io::log::early_print("[RUNDBG] after io tick\n");
                    EXECUTOR_INITDBG_STAGE.store(9, Ordering::Release);
                } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 107 {
                    crate::io::log::early_print("[RUNDBG2] after io tick\n");
                    EXECUTOR_INITDBG_STAGE.store(108, Ordering::Release);
                }
                // IOMMU command queue processing
                crate::io::iommu::api::process_pending_command_queues();
                if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 9 {
                    crate::io::log::early_print("[RUNDBG] after iommu cq\n");
                    EXECUTOR_INITDBG_STAGE.store(10, Ordering::Release);
                } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 108 {
                    crate::io::log::early_print("[RUNDBG2] after iommu cq\n");
                    EXECUTOR_INITDBG_STAGE.store(109, Ordering::Release);
                }
            }

            // 0.5 Suspend期限到達タスクを再投入
            set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_SUSPENDED);
            self.process_suspended_tasks();
            if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 10 {
                crate::io::log::early_print("[RUNDBG] after suspended tasks\n");
                EXECUTOR_INITDBG_STAGE.store(11, Ordering::Release);
            } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 109 {
                crate::io::log::early_print("[RUNDBG2] after suspended tasks\n");
                EXECUTOR_INITDBG_STAGE.store(110, Ordering::Release);
            }

            // 1. Refill fuel for this executor slice and process local tasks
            crate::task::fuel::Fuel::refill(crate::task::fuel::FuelConfig::DEFAULT.default_fuel);
            set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_RUN_READY);
            self.run_ready_tasks();
            if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 11 {
                crate::io::log::early_print("[RUNDBG] after run_ready_tasks\n");
                EXECUTOR_INITDBG_STAGE.store(12, Ordering::Release);
            } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 110 {
                crate::io::log::early_print("[RUNDBG2] after run_ready_tasks\n");
                EXECUTOR_INITDBG_STAGE.store(111, Ordering::Release);
            }

            // 2. Wake queueを処理
            set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_WAKE_QUEUE);
            self.process_wake_queue();
            if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 12 {
                crate::io::log::early_print("[RUNDBG] after process_wake_queue\n");
                EXECUTOR_INITDBG_STAGE.store(13, Ordering::Release);
            }

            // 3. グローバルキューからバッチ取得
            set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_FETCH_GLOBAL);
            self.fetch_from_global();
            if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 13 {
                crate::io::log::early_print("[RUNDBG] after fetch_from_global\n");
                EXECUTOR_INITDBG_STAGE.store(14, Ordering::Release);
            }

            // 4. Work Stealing（他のCPUから盗む）
            if self.runs_cross_cpu_work_stealing()
                && self.local_queue.is_empty()
                && self.local_cache.is_empty()
            {
                set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_WORK_STEAL);
                self.try_steal();
            }
            if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 14 {
                crate::io::log::early_print("[RUNDBG] after try_steal\n");
                EXECUTOR_INITDBG_STAGE.store(15, Ordering::Release);
            }

            // 4.5. Quiescent Point (設計書 3.5.3: Epoch-based Reclamation)
            // ライブアップデートのために「安全な状態」を通知
            set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_QUIESCENT);
            crate::loader::live_update::enter_quiescent_state();
            if self.runs_global_runtime_maintenance() {
                crate::loader::live_update::poll_pending_updates();
                crate::driver_domain::hot_swap::poll_validation_windows();
            }
            if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 15 {
                crate::io::log::early_print("[RUNDBG] after quiescent\n");
                EXECUTOR_INITDBG_STAGE.store(16, Ordering::Release);
            }

            // 4.6. Per-coreログバッファをシリアルへフラッシュ
            // Busyループ中もログが排出されるよう、idle以外でも呼ぶ。
            if self.runs_global_runtime_maintenance() {
                crate::io::log::kick_serial_tx();
            }
            if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 16 {
                crate::io::log::early_print("[RUNDBG] after kick_serial_tx\n");
                EXECUTOR_INITDBG_STAGE.store(17, Ordering::Release);
            }

            // 5. アイドル状態
            if self.local_queue.is_empty() && self.local_cache.is_empty() {
                EXECUTOR_STATS.idle_cycles.fetch_add(1, Ordering::Relaxed);
                set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_WAITING);

                #[cfg(feature = "qemu-test-export")]
                {
                    core::hint::spin_loop();
                    continue;
                }
                #[cfg(not(feature = "qemu-test-export"))]
                interrupts::enable_and_hlt();
            }
        }
    }

    /// ローカルキューのタスクを実行
    fn run_ready_tasks(&mut self) {
        let bsp_debug = false;
        // バッチ処理
        let mut processed = 0;
        if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 11 {
            if self.local_queue.is_empty() {
                crate::io::log::early_print("[RUNDBG] local_queue empty at run_ready entry\n");
            } else {
                crate::io::log::early_print("[RUNDBG] local_queue has tasks at run_ready entry\n");
            }
        } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 110 {
            crate::io::log::early_print("[RUNDBG2] run_ready entry\n");
        }

        // LOOP_PROOF: mode=condition; reason=Loop drains local ready tasks and exits when queue empties or batch and preemption break triggers.;
        while let Some(mut task) = self.local_queue.pop_front() {
            if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 11 {
                crate::io::log::early_print("[RUNDBG] popped one task\n");
            } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 110 {
                crate::io::log::early_print("[RUNDBG2] popped one task\n");
            }
            if bsp_debug && EXECUTOR_RUNDBG_POLLS.load(Ordering::Relaxed) < 8 {
                crate::io::log::early_print("[RUNDBG] task id=");
                crate::io::log::early_print_hex(task.id.as_u64());
                crate::io::log::early_print(" domain=");
                crate::io::log::early_print_hex(task.domain_id.as_u64());
                crate::io::log::early_print("\n");
            }
            let debug_seq = EXECUTOR_RUNDBG_POLLS.load(Ordering::Relaxed);
            if bsp_debug && debug_seq < 8 {
                log::info!(
                    target: "run_dbg",
                    "about to poll task id={} domain={}",
                    task.id.as_u64(),
                    task.domain_id.as_u64()
                );
            }
            let now_ns = crate::time::precise_time_nanos();
            if !crate::domain_system::is_domain_runnable_now(task.domain_id, now_ns) {
                if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 11 {
                    crate::io::log::early_print("[RUNDBG] task suspended (domain not runnable)\n");
                }
                let deadline = crate::domain_system::quota_suspend_deadline_ns(task.domain_id)
                    .unwrap_or_else(|| {
                        now_ns.saturating_add(crate::domain_system::CPU_QUOTA_SUSPEND_WINDOW_NS)
                    });
                self.suspended_queue.push_back((deadline, task));
                continue;
            }

            let waker = create_waker(task.id);
            let mut context = Context::from_waker(&waker);
            let start_ns = crate::time::precise_time_nanos();
            crate::domain_system::set_current_domain(task.domain_id);
            crate::task::preemption::set_current_task_domain(task.domain_id.as_u64());
            crate::task::notify_task_started(crate::task::current_tick());
            mark_current_polled_task(self.cpu_id, task.id, task.domain_id);
            set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_POLLING);
            if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 11 {
                crate::io::log::early_print("[RUNDBG] polling task future\n");
            } else if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 110 {
                crate::io::log::early_print("[RUNDBG2] polling task future\n");
            }

            match task.poll(&mut context) {
                Poll::Ready(()) => {
                    if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 11 {
                        crate::io::log::early_print("[RUNDBG] task returned Ready\n");
                    }
                    // タスク完了
                    EXECUTOR_STATS
                        .tasks_completed
                        .fetch_add(1, Ordering::Relaxed);
                }
                Poll::Pending => {
                    if bsp_debug && EXECUTOR_INITDBG_STAGE.load(Ordering::Relaxed) == 11 {
                        crate::io::log::early_print("[RUNDBG] task returned Pending\n");
                    }
                    let end_ns = crate::time::precise_time_nanos();
                    let elapsed_ns = end_ns.saturating_sub(start_ns);
                    let exceeded = if task.domain_id == crate::domain_system::DomainId::KERNEL {
                        false
                    } else {
                        crate::domain::quota::quota_manager().consume_cpu_time(
                            task.domain_id,
                            elapsed_ns,
                            end_ns,
                        )
                    };

                    let action = if exceeded {
                        crate::domain_system::report_cpu_quota_exceeded(task.domain_id, end_ns)
                    } else {
                        crate::domain_system::report_cpu_quota_ok(task.domain_id);
                        crate::domain_system::CpuQuotaAction::None
                    };

                    match action {
                        crate::domain_system::CpuQuotaAction::Suspend { until_ns } => {
                            self.suspended_queue.push_back((until_ns, task));
                            crate::task::preemption::request_yield();
                        }
                        crate::domain_system::CpuQuotaAction::YieldDemote => {
                            PER_CORE_STORES[self.cpu_id].insert(task.id, task);
                            crate::task::preemption::request_yield();
                        }
                        crate::domain_system::CpuQuotaAction::None => {
                            // ペンディング状態のタスクをper-coreストアに保存
                            PER_CORE_STORES[self.cpu_id].insert(task.id, task);
                        }
                    }
                }
            }
            clear_current_polled_task();
            set_current_executor_phase(self.cpu_id, EXECUTOR_PHASE_RUN_READY);
            crate::task::preemption::set_current_task_domain(0);
            crate::domain_system::set_current_domain(crate::domain_system::DomainId::KERNEL);
            let poll_seq = EXECUTOR_RUNDBG_POLLS.fetch_add(1, Ordering::Relaxed);
            if bsp_debug && poll_seq < 32 {
                crate::io::log::early_print("[RUNDBG] task poll completed\n");
            }

            processed += 1;

            // Preemption integration: if a timer-triggered preemption is pending, force fuel exhaustion
            // so long-running tasks hit `check_fuel!()` and yield soon. Also clear the preemption flag.
            if crate::task::preemption::is_preemption_pending() {
                crate::task::fuel::Fuel::exhaust();
                crate::task::preemption::clear_preemption_pending();
                break;
            }

            // Check for explicit yield request (set by ISR / preemption handler)
            if crate::task::preemption::check_and_clear_yield_request() {
                break;
            }

            // バッチ上限で一旦中断（他の処理を許可）
            if processed >= self.batch_size {
                break;
            }
        }

        if processed > 0 {
            EXECUTOR_STATS
                .poll_cycles
                .fetch_add(processed as u64, Ordering::Relaxed);
        }
    }

    fn process_suspended_tasks(&mut self) {
        if self.suspended_queue.is_empty() {
            return;
        }

        let now_ns = crate::time::precise_time_nanos();
        let mut pending = VecDeque::with_capacity(self.suspended_queue.len());

        // LOOP_PROOF: mode=condition; reason=Each suspended entry is visited once and loop exits after the suspended queue is fully consumed.;
        while let Some((deadline, task)) = self.suspended_queue.pop_front() {
            if now_ns >= deadline
                && crate::domain_system::is_domain_runnable_now(task.domain_id, now_ns)
            {
                self.local_queue.push_back(task);
            } else {
                pending.push_back((deadline, task));
            }
        }

        self.suspended_queue = pending;
    }

    /// Wake queueを処理
    /// Search PER_CORE_STORES for a task: own core first, then others.
    /// When `check_active` is true, skip stores that are not marked active.
    fn find_task_in_stores(&self, task_id: TaskId, check_active: bool) -> Option<Task> {
        if let Some(task) = PER_CORE_STORES[self.cpu_id].remove(&task_id) {
            return Some(task);
        }
        for (cpu_id, store) in PER_CORE_STORES.iter().enumerate() {
            if cpu_id == self.cpu_id {
                continue;
            }
            if check_active && !store.active.load(Ordering::Acquire) {
                continue;
            }
            if let Some(task) = store.remove(&task_id) {
                return Some(task);
            }
        }
        None
    }

    fn process_wake_queue(&mut self) {
        // ロックフリーでWake queueを処理
        let mut woken = 0;
        // LOOP_PROOF: mode=condition; reason=Wake loop exits when wake queue is empty or when the configured batch limit is reached.;
        while let Some(task_id) = WAKE_QUEUE.pop() {
            if let Some(task) = self.find_task_in_stores(task_id, true) {
                self.local_queue.push_back(task);
                woken += 1;
            } else {
                self.local_cache.push_back(task_id);
            }

            // バッチ上限
            if woken >= self.batch_size {
                break;
            }
        }
    }

    /// グローバルキューからタスクを取得
    fn fetch_from_global(&mut self) {
        let mut fetched = 0;
        // LOOP_PROOF: mode=condition; reason=Fetch loop is bounded by batch_size and exits early when GLOBAL_QUEUE has no pending task ID.;
        while fetched < self.batch_size {
            if let Some(task_id) = GLOBAL_QUEUE.pop() {
                if let Some(task) = self.find_task_in_stores(task_id, false) {
                    self.local_queue.push_back(task);
                    fetched += 1;
                } else {
                    // Task not found in any per-core store; cache the id for later.
                    self.local_cache.push_back(task_id);
                }
            } else {
                break;
            }
        }

        if fetched > 0 {
            EXECUTOR_STATS
                .global_fetches
                .fetch_add(fetched as u64, Ordering::Relaxed);
        }
    }

    /// Work Stealing: 他のCPUからタスクを盗む
    /// 【設計書 4.3】NUMA優先の3段階ワークスティーリング:
    /// 1. 同一LLC/Hyperthread siblingから
    /// 2. 同一NUMAノード内のコアから
    /// 3. 他のNUMAノードのコアから
    fn try_steal(&mut self) {
        // アクティブCPUが1つしかない場合はスキップ
        if ACTIVE_CPU_COUNT.load(Ordering::Relaxed) <= 1 {
            return;
        }

        // NUMA トポロジ情報を取得
        let numa_info = super::work_stealing_advanced::NumaTopology::get();
        let core_id = self.cpu_id as u32;
        let mut stolen = 0;

        // Phase 1: 同一LLCを共有するコア（Hyperthread sibling）からスチール
        if self.steal_from_llc_siblings(numa_info, core_id, &mut stolen) {
            return;
        }

        // Phase 2: 同一NUMAノード内の他コアからスチール
        let my_numa_node = numa_info.get_numa_node(core_id);
        if self.steal_from_numa_node_cores(numa_info, core_id, my_numa_node, true, &mut stolen) {
            return;
        }

        // Phase 3: 他のNUMAノードからスチール（最後の手段）
        for node in 0..numa_info.num_nodes() {
            if node == my_numa_node {
                continue;
            }
            if self.steal_from_numa_node_cores(numa_info, core_id, node, false, &mut stolen) {
                return;
            }
        }
    }

    /// 指定コアのストアから1タスクをスチールしてローカルキューにpush。
    /// バッチサイズ半分に達したらtrueを返す。
    fn try_steal_from_store(&mut self, target_core: u32, stolen: &mut usize) -> bool {
        if target_core as usize >= MAX_CPUS {
            return false;
        }
        let store = &PER_CORE_STORES[target_core as usize];
        if !store.active.load(Ordering::Acquire) {
            return false;
        }
        if store.len() <= 1 {
            return false;
        }
        if let Some((_, task)) = store.steal_one() {
            self.local_queue.push_back(task);
            *stolen += 1;
            EXECUTOR_STATS.steals.fetch_add(1, Ordering::Relaxed);
            return *stolen >= self.batch_size / 2;
        }
        false
    }

    /// Phase 1: LLCを共有するsiblingコアからスチール
    fn steal_from_llc_siblings(
        &mut self,
        numa_info: &super::work_stealing_advanced::NumaTopology,
        core_id: u32,
        stolen: &mut usize,
    ) -> bool {
        for &sibling_id in numa_info.get_llc_siblings(core_id) {
            if sibling_id == core_id {
                continue;
            }
            if self.try_steal_from_store(sibling_id, stolen) {
                return true;
            }
        }
        false
    }

    /// 指定NUMAノード内のコアからスチール。skip_llc=trueならLLC共有コアはスキップ。
    fn steal_from_numa_node_cores(
        &mut self,
        numa_info: &super::work_stealing_advanced::NumaTopology,
        core_id: u32,
        node: usize,
        skip_llc: bool,
        stolen: &mut usize,
    ) -> bool {
        for &target_core in numa_info.get_cores_in_node(node) {
            if target_core == core_id {
                continue;
            }
            if skip_llc && numa_info.shares_llc(core_id, target_core) {
                continue;
            }
            if self.try_steal_from_store(target_core, stolen) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
fn reset_executor_state_for_tests() {
    while GLOBAL_QUEUE.pop().is_some() {}
    while WAKE_QUEUE.pop().is_some() {}

    for store in &PER_CORE_STORES {
        store.active.store(false, Ordering::Release);
        store.task_count.store(0, Ordering::Release);
        if let Ok(mut guard) = store.tasks.lock() {
            guard.clear();
        }
    }

    ACTIVE_CPU_COUNT.store(1, Ordering::Release);
    EXECUTOR_SPAWNDBG_COUNT.store(0, Ordering::Release);
    clear_current_polled_task();
    for phase in &CURRENT_EXECUTOR_PHASE {
        phase.store(EXECUTOR_PHASE_IDLE, Ordering::Release);
    }
    for ready in &REMOTE_WAKE_READY {
        ready.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn register_cpu_is_idempotent_for_active_count() {
        reset_executor_state_for_tests();
        set_active_cpu_count(4);

        register_cpu(2);
        register_cpu(2);

        assert!(PER_CORE_STORES[2].active.load(Ordering::Acquire));
        assert_eq!(active_cpu_count(), 4);
    }

    #[test_case]
    fn wake_notification_requires_multiple_released_workers() {
        reset_executor_state_for_tests();
        crate::smp::reset_runtime_workers_for_tests();

        set_active_cpu_count(1);
        assert!(!should_notify_remote_workers());

        set_active_cpu_count(2);
        assert!(!should_notify_remote_workers());

        crate::smp::release_runtime_workers();
        assert!(should_notify_remote_workers());
    }

    #[test_case]
    fn ap_workers_skip_bsp_only_runtime_paths() {
        let bsp = Executor::with_cpu_id(0);
        let ap = Executor::with_cpu_id(3);

        assert!(bsp.runs_global_runtime_maintenance());
        assert!(bsp.runs_cross_cpu_work_stealing());
        assert!(!ap.runs_global_runtime_maintenance());
        assert!(!ap.runs_cross_cpu_work_stealing());
    }

    #[test_case]
    fn polled_task_context_round_trips() {
        reset_executor_state_for_tests();

        mark_current_polled_task(
            2,
            TaskId::from_raw(77),
            crate::domain_system::DomainId::new(9),
        );
        let ctx = current_polled_task_context().expect("missing polled task context");
        assert_eq!(ctx.cpu_id, 2);
        assert_eq!(ctx.task_id, 77);
        assert_eq!(ctx.domain_id, 9);

        clear_current_polled_task();
        assert!(current_polled_task_context().is_none());
    }

    #[test_case]
    fn lock_free_queue_preserves_full_capacity() {
        let queue = LockFreeQueue::new();

        for i in 0..QUEUE_SIZE {
            assert!(queue.push(TaskId::from_raw(i as u64)), "failed at {}", i);
        }
        assert!(!queue.push(TaskId::from_raw(u64::MAX)));
        assert_eq!(queue.len(), QUEUE_SIZE);

        for i in 0..QUEUE_SIZE {
            assert_eq!(queue.pop(), Some(TaskId::from_raw(i as u64)));
        }
        assert!(queue.pop().is_none());
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 統計情報
// ============================================================================

/// Executor統計
pub struct ExecutorStats {
    /// スポーンされたタスク数
    pub tasks_spawned: AtomicU64,
    /// 完了したタスク数
    pub tasks_completed: AtomicU64,
    /// Wakeup回数
    pub wakeups: AtomicU64,
    /// Pollサイクル数
    pub poll_cycles: AtomicU64,
    /// グローバルからのフェッチ数
    pub global_fetches: AtomicU64,
    /// アイドルサイクル数
    pub idle_cycles: AtomicU64,
    /// Work Stealingで盗んだタスク数
    pub steals: AtomicU64,
}
