// ============================================================================
// src/task/work_stealing.rs - Lock-Free Global Injector Queue
// ============================================================================
//!
//! # グローバルタスク注入キュー
//!
//! ロックフリー MPMC キューによるグローバルタスク注入。
//! ISRや他のコアから `inject_global()` でタスクを注入し、
//! Executor が `steal_from_global()` で取得する。
//!
//! ## 責務
//! - グローバルな注入/取得キュー（`inject_global` / `steal_from_global`）
//! - キュー統計（`global_queue_len`, `global_queue_stats`）
//!
//! ## `work_stealing_advanced` との共存理由
//!
//! 本モジュールは **グローバルインジェクションキューのみ** を提供します。
//! ISRや外部ドメインからのタスク注入（`inject_global`）は、特定のコアに
//! 紐付かない「入口」として機能するため、Per-Core スケジューラ
//! (`work_stealing_advanced`) とは独立して存在する必要があります。
//!
//! ```text
//! ISR / 外部ドメイン
//!       │
//!       ▼
//!  ┌──────────────────┐
//!  │ work_stealing.rs  │  ← グローバルインジェクションキュー
//!  │ (inject_global)   │
//!  └────────┬─────────┘
//!           │ steal_from_global()
//!           ▼
//!  ┌──────────────────────────┐
//!  │ work_stealing_advanced/  │  ← NUMA対応 Per-Core スケジューラ
//!  │ (PerCoreWorker,          │     3段階スティーリング
//!  │  GlobalScheduler)        │
//!  └──────────────────────────┘
//! ```
//!
//! ## 関連モジュール
//! - `work_stealing_advanced/` — NUMA対応のPer-Coreスケジューラ
//!   （旧 Per-Core WorkStealingQueue はそちらに移行済み）
//! - `executor` — プライマリExecutorループ
//!
// 設計書 4.3: マルチコアスケーリングとShare-Nothingアーキテクチャ
// ============================================================================
#![allow(dead_code)]

use super::Task;
use crate::sync::MpmcRingBuffer;

use core::sync::atomic::{AtomicUsize, Ordering};

// ============================================================================
// Lock-Free Global Injector Queue
// ============================================================================
// MPMC lock-free queue for global task injection.

const GLOBAL_QUEUE_CAPACITY: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalQueueStats {
    pub len: usize,
    pub capacity: usize,
    pub enqueued: usize,
    pub dequeued: usize,
    pub dropped: usize,
}

/// Lock-free global injector queue
#[repr(C, align(64))]
struct LockFreeGlobalInjector {
    /// Shared MPMC task queue
    queue: MpmcRingBuffer<Task, GLOBAL_QUEUE_CAPACITY>,
    /// Statistics
    enqueued: AtomicUsize,
    dequeued: AtomicUsize,
    dropped: AtomicUsize,
}

impl LockFreeGlobalInjector {
    const CAPACITY: usize = GLOBAL_QUEUE_CAPACITY;

    const fn new() -> Self {
        Self {
            queue: MpmcRingBuffer::new(),
            enqueued: AtomicUsize::new(0),
            dequeued: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    /// Inject a task into the global queue (lock-free)
    fn inject(&self, task: Task) -> bool {
        match self.queue.push(task) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Steal a task from the global queue (lock-free)
    fn steal(&self) -> Option<Task> {
        let task = self.queue.pop();
        if task.is_some() {
            self.dequeued.fetch_add(1, Ordering::Relaxed);
        }
        task
    }

    /// Get current queue length (approximate)
    fn len(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    /// Get statistics
    fn stats(&self) -> GlobalQueueStats {
        GlobalQueueStats {
            len: self.len(),
            capacity: self.capacity(),
            enqueued: self.enqueued.load(Ordering::Relaxed),
            dequeued: self.dequeued.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
}

static GLOBAL_INJECTOR: LockFreeGlobalInjector = LockFreeGlobalInjector::new();

/// グローバルキューにタスクを注入（ロックフリー）
pub fn inject_global(task: Task) {
    let _ = GLOBAL_INJECTOR.inject(task);
}

/// グローバルキューからタスクを取得（ロックフリー）
pub fn steal_from_global() -> Option<Task> {
    GLOBAL_INJECTOR.steal()
}

/// グローバルキューの長さを取得
pub fn global_queue_len() -> usize {
    GLOBAL_INJECTOR.len()
}

/// グローバルキューの論理容量を取得
pub fn global_queue_capacity() -> usize {
    GLOBAL_INJECTOR.capacity()
}

/// グローバルキューが空かどうか
pub fn global_queue_is_empty() -> bool {
    GLOBAL_INJECTOR.is_empty()
}

/// グローバルキューの統計を取得
pub fn global_queue_stats() -> GlobalQueueStats {
    GLOBAL_INJECTOR.stats()
}

#[cfg(test)]
fn reset_global_injector_for_tests() {
    while GLOBAL_INJECTOR.steal().is_some() {}
    GLOBAL_INJECTOR.enqueued.store(0, Ordering::Release);
    GLOBAL_INJECTOR.dequeued.store(0, Ordering::Release);
    GLOBAL_INJECTOR.dropped.store(0, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn global_injector_tracks_stats_and_drops_when_full() {
        reset_global_injector_for_tests();

        for _ in 0..GLOBAL_QUEUE_CAPACITY {
            assert!(GLOBAL_INJECTOR.inject(Task::new(async {})));
        }
        assert!(!GLOBAL_INJECTOR.inject(Task::new(async {})));

        let stats = GLOBAL_INJECTOR.stats();
        assert_eq!(stats.len, GLOBAL_QUEUE_CAPACITY);
        assert_eq!(stats.capacity, GLOBAL_QUEUE_CAPACITY);
        assert_eq!(stats.enqueued, GLOBAL_QUEUE_CAPACITY);
        assert_eq!(stats.dequeued, 0);
        assert_eq!(stats.dropped, 1);
        assert_eq!(global_queue_len(), GLOBAL_QUEUE_CAPACITY);
        assert_eq!(global_queue_capacity(), GLOBAL_QUEUE_CAPACITY);
        assert!(!GLOBAL_INJECTOR.is_empty());
        assert!(!global_queue_is_empty());

        let mut drained = 0;
        while GLOBAL_INJECTOR.steal().is_some() {
            drained += 1;
        }
        assert_eq!(drained, GLOBAL_QUEUE_CAPACITY);

        let stats = GLOBAL_INJECTOR.stats();
        assert_eq!(stats.len, 0);
        assert_eq!(stats.capacity, GLOBAL_QUEUE_CAPACITY);
        assert_eq!(stats.enqueued, GLOBAL_QUEUE_CAPACITY);
        assert_eq!(stats.dequeued, GLOBAL_QUEUE_CAPACITY);
        assert_eq!(stats.dropped, 1);
        assert_eq!(global_queue_len(), 0);
        assert!(GLOBAL_INJECTOR.is_empty());
        assert!(global_queue_is_empty());

        reset_global_injector_for_tests();
    }
}
