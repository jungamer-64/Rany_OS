// ============================================================================
// src/task/scheduler.rs - Task Scheduler
// 設計書 4.3: プリエンプティブスケジューラ
//
// ラウンドロビン + 優先度ベースのスケジューリング
// ============================================================================
#![allow(dead_code)]

use crate::sync::IrqMutex;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::TaskId;
use super::context::{TaskControlBlock, TaskState, schedule_switch};

/// 優先度レベル数
const PRIORITY_LEVELS: usize = 8;

/// タイムスライス（ティック数）
const DEFAULT_TIME_SLICE: u64 = 10;

/// Send を実装した TCB ポインタのラッパー
#[derive(Clone, Copy)]
struct TcbPtr(*mut TaskControlBlock);

// SAFETY: TcbPtr へのアクセスは IrqMutex で保護されている
unsafe impl Send for TcbPtr {}

/// Per-CPU スケジューラ
pub struct PerCpuScheduler {
    /// CPU ID
    cpu_id: usize,
    /// 優先度別のレディキュー
    ready_queues: [VecDeque<TcbPtr>; PRIORITY_LEVELS],
    /// 現在実行中のタスク
    current: Option<TcbPtr>,
    /// アイドルタスク
    idle_task: Option<TcbPtr>,
    /// 残りタイムスライス
    remaining_slice: u64,
    /// スケジューリングが必要かどうか
    need_reschedule: AtomicBool,
}

// SAFETY: TCBポインタはスケジューラが適切に管理する
unsafe impl Send for PerCpuScheduler {}

impl PerCpuScheduler {
    /// 新しいスケジューラを作成
    pub const fn new(cpu_id: usize) -> Self {
        const EMPTY_QUEUE: VecDeque<TcbPtr> = VecDeque::new();
        Self {
            cpu_id,
            ready_queues: [EMPTY_QUEUE; PRIORITY_LEVELS],
            current: None,
            idle_task: None,
            remaining_slice: DEFAULT_TIME_SLICE,
            need_reschedule: AtomicBool::new(false),
        }
    }

    /// アイドルタスクを設定
    pub fn set_idle_task(&mut self, idle: *mut TaskControlBlock) {
        self.idle_task = Some(TcbPtr(idle));
        if self.current.is_none() {
            self.current = Some(TcbPtr(idle));
        }
    }

    /// タスクをレディキューに追加
    pub fn enqueue(&mut self, tcb: *mut TaskControlBlock) {
        // SAFETY: tcb は有効なポインタと仮定
        let priority = unsafe { (*tcb).priority as usize };
        let queue_idx = priority.min(PRIORITY_LEVELS - 1);

        self.ready_queues[queue_idx].push_back(TcbPtr(tcb));
    }

    /// 最高優先度のタスクを取得
    fn dequeue_highest(&mut self) -> Option<*mut TaskControlBlock> {
        for queue in &mut self.ready_queues {
            if let Some(tcb) = queue.pop_front() {
                return Some(tcb.0);
            }
        }
        None
    }

    /// 次に実行するタスクを選択
    pub fn pick_next(&mut self) -> *mut TaskControlBlock {
        // 最高優先度のタスクを選択
        if let Some(next) = self.dequeue_highest() {
            return next;
        }

        // レディキューが空ならアイドルタスク
        self.idle_task.expect("Idle task not set").0
    }

    /// タイマーティック時の処理
    ///
    /// # Returns
    /// true if reschedule is needed
    pub fn tick(&mut self) -> bool {
        if self.remaining_slice > 0 {
            self.remaining_slice -= 1;
        }

        // タイムスライス消費でリスケジュール
        if self.remaining_slice == 0 {
            self.need_reschedule.store(true, Ordering::Release);
            return true;
        }

        false
    }

    /// スケジュール実行
    ///
    /// # Safety
    /// 割り込みが禁止された状態で呼び出す必要がある
    pub unsafe fn schedule(&mut self) {
        if !self.need_reschedule.swap(false, Ordering::AcqRel) {
            return;
        }

        let current = match self.current {
            Some(c) => c.0,
            None => return,
        };

        // 現在のタスクをレディキューに戻す（アイドルタスク以外）
        // SAFETY: current は有効なポインタ
        unsafe {
            if (*current).priority < 255 {
                self.enqueue(current);
            }
        }

        // 次のタスクを選択
        let next = self.pick_next();

        if current != next {
            self.current = Some(TcbPtr(next));
            self.remaining_slice = DEFAULT_TIME_SLICE;

            // SAFETY: 呼び出し元が保証
            unsafe {
                schedule_switch(self.cpu_id, current, next);
            }
        }
    }

    /// リスケジュールを要求
    pub fn request_reschedule(&self) {
        self.need_reschedule.store(true, Ordering::Release);
    }

    /// 現在のタスクをブロック
    ///
    /// # Safety
    /// 割り込みが禁止された状態で呼び出す必要がある
    pub unsafe fn block_current(&mut self) {
        if let Some(current) = self.current {
            // SAFETY: current は有効なポインタ
            unsafe {
                (*current.0).state = TaskState::Blocked;
            }
            self.request_reschedule();
        }
    }

    /// タスクをアンブロック
    pub fn unblock(&mut self, tcb: *mut TaskControlBlock) {
        // SAFETY: tcb は有効なポインタと仮定
        unsafe {
            (*tcb).state = TaskState::Ready;
        }
        self.enqueue(tcb);
        self.request_reschedule();
    }
}

// ============================================================================
// グローバルスケジューラ管理 (Lock-Free via spin::Once)
// ============================================================================

/// 最大CPU数
const MAX_CPUS: usize = 64;

/// Per-CPU スケジューラ配列 (OnceCell pattern)
///
/// Each CPU initializes its scheduler exactly once, then accesses it lock-free.
/// UnsafeCell is used for mutable access since each CPU only accesses its own scheduler.
struct PerCpuSchedulerStorage {
    schedulers: [spin::Once<core::cell::UnsafeCell<PerCpuScheduler>>; MAX_CPUS],
}

impl PerCpuSchedulerStorage {
    const fn new() -> Self {
        const UNINIT: spin::Once<core::cell::UnsafeCell<PerCpuScheduler>> = spin::Once::new();
        Self {
            schedulers: [UNINIT; MAX_CPUS],
        }
    }

    /// Initialize scheduler for a CPU (called once per CPU)
    fn init(&self, cpu_id: usize) {
        if cpu_id >= MAX_CPUS {
            return;
        }

        self.schedulers[cpu_id].call_once(|| {
            let mut scheduler = PerCpuScheduler::new(cpu_id);
            
            // アイドルタスクを作成
            let idle_tcb = Box::leak(Box::new(TaskControlBlock::idle(cpu_id)));
            scheduler.set_idle_task(idle_tcb);
            
            core::cell::UnsafeCell::new(scheduler)
        });
    }

    /// Get scheduler for a CPU (lock-free after init)
    #[inline]
    fn get(&self, cpu_id: usize) -> Option<&core::cell::UnsafeCell<PerCpuScheduler>> {
        if cpu_id >= MAX_CPUS {
            return None;
        }
        self.schedulers[cpu_id].get()
    }

    /// Check if scheduler is initialized for a CPU
    #[inline]
    fn is_initialized(&self, cpu_id: usize) -> bool {
        cpu_id < MAX_CPUS && self.schedulers[cpu_id].get().is_some()
    }
}

// SAFETY: Each CPU only accesses its own scheduler
unsafe impl Sync for PerCpuSchedulerStorage {}

static SCHEDULERS: PerCpuSchedulerStorage = PerCpuSchedulerStorage::new();

/// グローバルタスクリスト（全タスクの所有権）
/// Note: This still uses IrqMutex as it's accessed from multiple CPUs
static TASK_LIST: IrqMutex<Vec<TcbPtr>> = IrqMutex::new(Vec::new());

/// スケジューラを初期化
pub fn init_scheduler(cpu_id: usize) {
    SCHEDULERS.init(cpu_id);
}

/// スケジューラが初期化済みか確認
pub fn is_scheduler_initialized(cpu_id: usize) -> bool {
    SCHEDULERS.is_initialized(cpu_id)
}

/// タスクを生成してスケジューラに追加
pub fn spawn_task(entry_point: fn(u64) -> !, arg: u64, priority: u8) -> Option<TaskId> {
    let tcb = TaskControlBlock::new(entry_point, arg, priority)?;
    let tcb_ptr = Box::leak(Box::new(tcb));
    let task_id = (*tcb_ptr).id;

    // グローバルリストに追加
    TASK_LIST.lock().push(TcbPtr(tcb_ptr));

    // CPU 0 のスケジューラに追加 (lock-free after init)
    if let Some(sched_cell) = SCHEDULERS.get(0) {
        // SAFETY: We're on the owning CPU (or during init)
        unsafe {
            (*sched_cell.get()).enqueue(tcb_ptr);
        }
    }

    Some(task_id)
}

/// タイマーティック処理 (lock-free)
pub fn timer_tick(cpu_id: usize) {
    if let Some(sched_cell) = SCHEDULERS.get(cpu_id) {
        // SAFETY: Called from timer interrupt on this CPU
        unsafe {
            (*sched_cell.get()).tick();
        }
    }
}

/// スケジュール実行 (lock-free)
///
/// # Safety
/// 割り込みコンテキストまたは適切なタイミングで呼び出す必要がある
pub unsafe fn schedule(cpu_id: usize) {
    if let Some(sched_cell) = SCHEDULERS.get(cpu_id) {
        // SAFETY: Called from same CPU
        unsafe {
            (*sched_cell.get()).schedule();
        }
    }
}

/// リスケジュールを要求 (lock-free)
pub fn request_reschedule(cpu_id: usize) {
    if let Some(sched_cell) = SCHEDULERS.get(cpu_id) {
        // SAFETY: Reading AtomicBool is always safe
        unsafe {
            (*sched_cell.get()).request_reschedule();
        }
    }
}

/// 現在のタスクを yield
pub fn yield_current(cpu_id: usize) {
    request_reschedule(cpu_id);
    // SAFETY: yield は任意のタイミングで安全
    unsafe {
        schedule(cpu_id);
    }
}

/// コンテキストスイッチ回数を取得
pub fn context_switch_count() -> u64 {
    super::context::CONTEXT_SWITCH_COUNT.load(Ordering::Relaxed)
}

/// スケジューラにタスクを追加（指定CPU）
pub fn enqueue_task(cpu_id: usize, tcb: *mut TaskControlBlock) {
    if let Some(sched_cell) = SCHEDULERS.get(cpu_id) {
        // SAFETY: Called with proper synchronization
        unsafe {
            (*sched_cell.get()).enqueue(tcb);
        }
    }
}

/// タスクをアンブロック（指定CPU）
pub fn unblock_task(cpu_id: usize, tcb: *mut TaskControlBlock) {
    if let Some(sched_cell) = SCHEDULERS.get(cpu_id) {
        // SAFETY: Called with proper synchronization
        unsafe {
            (*sched_cell.get()).unblock(tcb);
        }
    }
}

