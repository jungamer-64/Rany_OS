// ============================================================================
// src/task/waker.rs - Lock-Free Waker Queue
// ============================================================================
//! Lock-free wake queue for ISR-safe task notification.
//!
//! Uses a bounded MPSC ring buffer to avoid lock contention when waking
//! tasks from interrupt contexts.

use super::TaskId;
use crate::sync::MpscRingBuffer;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::Waker;

// ============================================================================
// Lock-Free Wake Queue
// ============================================================================

const WAKE_QUEUE_CAPACITY: usize = 1024;
const WAKE_QUEUE_BACKING_CAPACITY: usize = WAKE_QUEUE_CAPACITY + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeQueueStats {
    pub len: usize,
    pub capacity: usize,
    pub enqueued: usize,
    pub dropped: usize,
}

/// Lock-free MPSC wake queue
///
/// Multiple producers (ISRs, tasks) can enqueue task IDs concurrently.
/// Single consumer (executor) dequeues them.
#[repr(C, align(64))]
struct LockFreeWakeQueue {
    /// Shared MPSC wake queue
    queue: MpscRingBuffer<TaskId, WAKE_QUEUE_BACKING_CAPACITY>,
    /// Statistics
    enqueued: AtomicUsize,
    dropped: AtomicUsize,
}

impl LockFreeWakeQueue {
    const CAPACITY: usize = WAKE_QUEUE_CAPACITY;

    const fn new() -> Self {
        Self {
            queue: MpscRingBuffer::new(),
            enqueued: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    /// Enqueue a task ID (lock-free, ISR-safe)
    fn push(&self, task_id: TaskId) -> bool {
        match self.queue.push(task_id) {
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

    /// Dequeue a task ID (single consumer)
    fn pop(&self) -> Option<TaskId> {
        self.queue.pop()
    }

    /// Get queue length (approximate)
    #[inline]
    fn len(&self) -> usize {
        self.queue.len()
    }

    #[inline]
    fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    /// Check if queue is empty
    #[inline]
    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn stats(&self) -> WakeQueueStats {
        WakeQueueStats {
            len: self.len(),
            capacity: self.capacity(),
            enqueued: self.enqueued.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
}

/// Global lock-free wake queue
static WAKE_QUEUE: LockFreeWakeQueue = LockFreeWakeQueue::new();

// ============================================================================
// Waker Implementation
// ============================================================================

/// ArcWakeトレイトを使った効率的なWaker実装
struct TaskWaker {
    task_id: TaskId,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Lock-free enqueue - ISR-safe
        let _ = WAKE_QUEUE.push(self.task_id);
    }
}

/// Wakerを作成する公開API
pub fn create_waker(task_id: TaskId) -> Waker {
    Waker::from(Arc::new(TaskWaker { task_id }))
}

/// Wake queueからタスクIDを取り出す（ロックフリー）
pub fn pop_woken_task() -> Option<TaskId> {
    WAKE_QUEUE.pop()
}

/// Wake queueの長さを取得
pub fn wake_queue_len() -> usize {
    WAKE_QUEUE.len()
}

/// Wake queueの論理容量を取得
pub fn wake_queue_capacity() -> usize {
    WAKE_QUEUE.capacity()
}

/// Wake queueが空かどうか
pub fn wake_queue_is_empty() -> bool {
    WAKE_QUEUE.is_empty()
}

/// Wake queueの統計を取得
pub fn wake_queue_stats() -> WakeQueueStats {
    WAKE_QUEUE.stats()
}

#[cfg(test)]
fn reset_wake_queue_for_tests() {
    while WAKE_QUEUE.pop().is_some() {}
    WAKE_QUEUE.enqueued.store(0, Ordering::Release);
    WAKE_QUEUE.dropped.store(0, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_waker_wake() {
        reset_wake_queue_for_tests();

        let task_id = TaskId::new();
        let waker = create_waker(task_id);

        // Wake should push to queue
        waker.wake_by_ref();

        // Should be able to pop the task
        assert_eq!(pop_woken_task(), Some(task_id));

        let stats = wake_queue_stats();
        assert_eq!(stats.len, 0);
        assert_eq!(stats.capacity, WAKE_QUEUE_CAPACITY);
        assert_eq!(stats.enqueued, 1);
        assert_eq!(stats.dropped, 0);

        reset_wake_queue_for_tests();
    }

    #[test_case]
    fn wake_queue_preserves_full_capacity() {
        reset_wake_queue_for_tests();

        for _ in 0..WAKE_QUEUE_CAPACITY {
            assert!(WAKE_QUEUE.push(TaskId::new()));
        }
        assert!(!WAKE_QUEUE.push(TaskId::new()));

        let stats = wake_queue_stats();
        assert_eq!(stats.len, WAKE_QUEUE_CAPACITY);
        assert_eq!(stats.capacity, WAKE_QUEUE_CAPACITY);
        assert_eq!(stats.enqueued, WAKE_QUEUE_CAPACITY);
        assert_eq!(stats.dropped, 1);

        for _ in 0..WAKE_QUEUE_CAPACITY {
            assert!(pop_woken_task().is_some());
        }
        assert_eq!(pop_woken_task(), None);

        reset_wake_queue_for_tests();
    }
}
