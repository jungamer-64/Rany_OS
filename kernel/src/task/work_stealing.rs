// ============================================================================
// src/task/work_stealing.rs - Lock-Free Work-Stealing Queue
// 設計書 4.3: マルチコアスケーリングとShare-Nothingアーキテクチャ
// ============================================================================
#![allow(dead_code)]

use super::Task;

use core::sync::atomic::{AtomicUsize, Ordering};


/// ワーカーのメタデータ
/// NUMA優先スティーリングのためにCPUコアIDとNUMAノードIDを保持
#[derive(Clone, Copy, Debug)]
pub struct WorkerMetadata {
    /// このワーカーが属するCPUコアID
    pub core_id: u32,
    /// このワーカーが属するNUMAノードID
    pub numa_node: u32,
}

impl WorkerMetadata {
    pub fn new(core_id: u32, numa_node: u32) -> Self {
        Self { core_id, numa_node }
    }
}

impl Default for WorkerMetadata {
    fn default() -> Self {
        Self {
            core_id: 0,
            numa_node: 0,
        }
    }
}

// WorkStealingQueue and per-core logic removed (migrated to work_stealing_advanced.rs)

// ============================================================================
// Lock-Free Global Injector Queue
// ============================================================================
// MPMC lock-free queue for global task injection.
// Uses atomic head/tail indices with bounded buffer.

const GLOBAL_QUEUE_SIZE: usize = 1024;
const GLOBAL_QUEUE_MASK: usize = GLOBAL_QUEUE_SIZE - 1;

/// Lock-free global injector queue
#[repr(C, align(64))]
struct LockFreeGlobalInjector {
    /// Producer head (where tasks are injected)
    head: AtomicUsize,
    _pad1: [u8; 56], // Avoid false sharing
    /// Consumer tail (where tasks are taken)
    tail: AtomicUsize,
    _pad2: [u8; 56], // Avoid false sharing
    /// Task buffer (Box pointers stored as usize)
    buffer: [AtomicUsize; GLOBAL_QUEUE_SIZE],
    /// Statistics
    enqueued: AtomicUsize,
    dequeued: AtomicUsize,
    dropped: AtomicUsize,
}

impl LockFreeGlobalInjector {
    const fn new() -> Self {
        const ZERO: AtomicUsize = AtomicUsize::new(0);
        Self {
            head: AtomicUsize::new(0),
            _pad1: [0; 56],
            tail: AtomicUsize::new(0),
            _pad2: [0; 56],
            buffer: [ZERO; GLOBAL_QUEUE_SIZE],
            enqueued: AtomicUsize::new(0),
            dequeued: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    /// Inject a task into the global queue (lock-free)
    fn inject(&self, task: Task) -> bool {
        // Box the task and get pointer
        let boxed = alloc::boxed::Box::new(task);
        let ptr = alloc::boxed::Box::into_raw(boxed) as usize;

        loop {
            let head = self.head.load(Ordering::Acquire);
            let tail = self.tail.load(Ordering::Acquire);

            // Check if queue is full
            if head.wrapping_sub(tail) >= GLOBAL_QUEUE_SIZE {
                // Queue is full, drop the task
                unsafe {
                    let _ = alloc::boxed::Box::from_raw(ptr as *mut Task);
                }
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            }

            let idx = head & GLOBAL_QUEUE_MASK;

            // Try to claim the slot
            match self.head.compare_exchange_weak(
                head,
                head.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // Store the task pointer
                    self.buffer[idx].store(ptr, Ordering::Release);
                    self.enqueued.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(_) => {
                    // Contention, retry
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Steal a task from the global queue (lock-free)
    fn steal(&self) -> Option<Task> {
        loop {
            let tail = self.tail.load(Ordering::Acquire);
            let head = self.head.load(Ordering::Acquire);

            if tail == head {
                // Queue is empty
                return None;
            }

            let idx = tail & GLOBAL_QUEUE_MASK;

            // Try to claim this slot
            match self.tail.compare_exchange_weak(
                tail,
                tail.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // Wait for the producer to finish writing
                    let mut ptr;
                    loop {
                        ptr = self.buffer[idx].swap(0, Ordering::Acquire);
                        if ptr != 0 {
                            break;
                        }
                        // Producer hasn't finished yet
                        core::hint::spin_loop();
                    }

                    // Reconstruct the task
                    let task = unsafe { *alloc::boxed::Box::from_raw(ptr as *mut Task) };
                    self.dequeued.fetch_add(1, Ordering::Relaxed);
                    return Some(task);
                }
                Err(_) => {
                    // Contention, retry
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Get current queue length (approximate)
    fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    /// Get statistics (enqueued, dequeued, dropped)
    fn stats(&self) -> (usize, usize, usize) {
        (
            self.enqueued.load(Ordering::Relaxed),
            self.dequeued.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
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

/// グローバルキューの統計を取得 (enqueued, dequeued, dropped)
pub fn global_queue_stats() -> (usize, usize, usize) {
    GLOBAL_INJECTOR.stats()
}

// Legacy code removed.

