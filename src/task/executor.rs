// ============================================================================
// src/task/executor.rs - Simplified Executor with Proper Waker Integration
// ============================================================================
#![allow(dead_code)]

use super::{create_waker, Task, TaskId};
use alloc::collections::{BTreeMap, VecDeque};
use core::task::{Context, Poll};
use spin::Mutex;
use x86_64::instructions::interrupts;

/// グローバルなタスクキュー
static TASK_QUEUE: Mutex<VecDeque<Task>> = Mutex::new(VecDeque::new());

/// ペンディング状態のタスクストア
static TASK_STORE: Mutex<BTreeMap<TaskId, Task>> = Mutex::new(BTreeMap::new());

/// Wake queue（ISR-safe）
static WAKE_QUEUE: Mutex<VecDeque<TaskId>> = Mutex::new(VecDeque::new());

/// タスクをwake queueに追加（Wakerから呼ばれる）
pub fn wake_task(task_id: TaskId) {
    WAKE_QUEUE.lock().push_back(task_id);
}

/// Executor
pub struct Executor {
    local_queue: VecDeque<Task>,
}

impl Executor {
    pub fn new() -> Self {
        Self {
            local_queue: VecDeque::new(),
        }
    }

    /// タスクをスケジュール
    pub fn spawn(&mut self, task: Task) {
        self.local_queue.push_back(task);
    }

    /// グローバルキューにタスクを追加
    pub fn spawn_global(task: Task) {
        TASK_QUEUE.lock().push_back(task);
    }

    /// メインループ
    pub fn run(&mut self) -> ! {
        loop {
            // ローカルキューのタスクを処理
            self.run_ready_tasks();

            // Wake queueを処理
            self.process_wake_queue();

            // グローバルキューからタスクを取得
            while let Some(task) = TASK_QUEUE.lock().pop_front() {
                self.local_queue.push_back(task);
            }

            // アイドル状態
            if self.local_queue.is_empty() {
                interrupts::enable_and_hlt();
            }
        }
    }

    fn run_ready_tasks(&mut self) {
        while let Some(mut task) = self.local_queue.pop_front() {
            let waker = create_waker(task.id);
            let mut context = Context::from_waker(&waker);

            match task.poll(&mut context) {
                Poll::Ready(()) => {
                    // タスク完了
                }
                Poll::Pending => {
                    // ペンディング状態のタスクをストアに保存
                    TASK_STORE.lock().insert(task.id, task);
                }
            }
        }
    }

    fn process_wake_queue(&mut self) {
        while let Some(task_id) = WAKE_QUEUE.lock().pop_front() {
            if let Some(task) = TASK_STORE.lock().remove(&task_id) {
                self.local_queue.push_back(task);
            }
        }
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}
