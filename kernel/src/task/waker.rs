// ============================================================================
// src/task/waker.rs - Lock-Free Waker Queue
// ============================================================================
//! Lock-free wake queue for ISR-safe task notification.
//!
//! Uses a bounded MPSC ring buffer to avoid lock contention when waking
//! tasks from interrupt contexts.

use super::TaskId;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::Waker;

// ============================================================================
// Lock-Free Wake Queue
// ============================================================================

/// Queue size (power of 2)
const WAKE_QUEUE_SIZE: usize = 1024;
const WAKE_QUEUE_MASK: usize = WAKE_QUEUE_SIZE - 1;

/// Lock-free MPSC wake queue
///
/// Multiple producers (ISRs, tasks) can enqueue task IDs concurrently.
/// Single consumer (executor) dequeues them.
#[repr(C, align(64))]
struct LockFreeWakeQueue {
    /// Producer head (where new items are added)
    head: AtomicUsize,
    _pad1: [u8; 56],
    /// Consumer tail (where items are removed)
    tail: AtomicUsize,
    _pad2: [u8; 56],
    /// Ring buffer of TaskId values (stored as u64)
    buffer: [AtomicUsize; WAKE_QUEUE_SIZE],
    /// Statistics
    enqueued: AtomicUsize,
    dropped: AtomicUsize,
}

impl LockFreeWakeQueue {
    const fn new() -> Self {
        const ZERO: AtomicUsize = AtomicUsize::new(0);
        Self {
            head: AtomicUsize::new(0),
            _pad1: [0; 56],
            tail: AtomicUsize::new(0),
            _pad2: [0; 56],
            buffer: [ZERO; WAKE_QUEUE_SIZE],
            enqueued: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    /// Enqueue a task ID (lock-free, ISR-safe)
    fn push(&self, task_id: TaskId) -> bool {
        let id_val = task_id.as_u64() as usize;
        
        loop {
            let head = self.head.load(Ordering::Acquire);
            let tail = self.tail.load(Ordering::Acquire);

            // Check if queue is full
            if head.wrapping_sub(tail) >= WAKE_QUEUE_SIZE {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            }

            let idx = head & WAKE_QUEUE_MASK;

            // Try to claim the slot
            match self.head.compare_exchange_weak(
                head,
                head.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // Store the task ID (add 1 to distinguish from empty slot)
                    self.buffer[idx].store(id_val + 1, Ordering::Release);
                    self.enqueued.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Dequeue a task ID (single consumer)
    fn pop(&self) -> Option<TaskId> {
        loop {
            let tail = self.tail.load(Ordering::Acquire);
            let head = self.head.load(Ordering::Acquire);

            if tail == head {
                // Queue is empty
                return None;
            }

            let idx = tail & WAKE_QUEUE_MASK;

            // Try to claim this slot
            match self.tail.compare_exchange_weak(
                tail,
                tail.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // Wait for the producer to finish writing
                    let mut val;
                    loop {
                        val = self.buffer[idx].swap(0, Ordering::Acquire);
                        if val != 0 {
                            break;
                        }
                        core::hint::spin_loop();
                    }
                    // Subtract 1 to get original TaskId value
                    return Some(TaskId::from_raw((val - 1) as u64));
                }
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Get queue length (approximate)
    #[inline]
    fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    /// Check if queue is empty
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get statistics (enqueued, dropped)
    fn stats(&self) -> (usize, usize) {
        (
            self.enqueued.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
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

/// Wake queueが空かどうか
pub fn wake_queue_is_empty() -> bool {
    WAKE_QUEUE.is_empty()
}

/// Wake queueの統計を取得 (enqueued, dropped)
pub fn wake_queue_stats() -> (usize, usize) {
    WAKE_QUEUE.stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_waker_wake() {
        let task_id = TaskId::new();
        let waker = create_waker(task_id);

        // Wake should push to queue
        waker.wake_by_ref();

        // Should be able to pop the task
        assert_eq!(pop_woken_task(), Some(task_id));
    }

    #[test_case]
    fn test_wake_queue_stats() {
        let (enqueued, dropped) = wake_queue_stats();
        // Stats should be non-negative
        assert!(enqueued >= 0);
        assert!(dropped >= 0);
    }
}
