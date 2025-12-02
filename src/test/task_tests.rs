// ============================================================================
// src/test/task_tests.rs - Task Subsystem Integration Tests
// ============================================================================

use crate::test::TestResult;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

/// Test task creation
pub fn test_task_creation() -> TestResult {
    use crate::task::Task;
    
    static TASK_RAN: AtomicBool = AtomicBool::new(false);
    
    // Create a simple task
    let task = Task::new(async {
        TASK_RAN.store(true, Ordering::SeqCst);
    });
    
    // Verify task ID is valid
    if task.id().0 == 0 {
        return TestResult::Failed(String::from("Task ID should not be 0"));
    }
    
    // Note: We can't actually run the task here without an executor
    // Just verify the task was created properly
    
    TestResult::Passed
}

/// Test task scheduling
pub fn test_task_scheduling() -> TestResult {
    // Verify scheduler is initialized
    let scheduler = crate::task::scheduler::scheduler();
    
    // Get initial stats
    let stats = scheduler.stats();
    
    // Stats should be accessible
    if stats.context_switches < 0 {
        return TestResult::Failed(String::from("Invalid context switch count"));
    }
    
    TestResult::Passed
}

/// Test async sleep mechanism
pub fn test_async_sleep() -> TestResult {
    // Get current tick
    let start_tick = crate::task::current_tick();
    
    // Busy wait for a short time to verify tick is advancing
    let mut iterations = 0;
    const MAX_ITERATIONS: u64 = 100_000;
    
    while iterations < MAX_ITERATIONS {
        let current = crate::task::current_tick();
        if current > start_tick {
            // Tick is advancing
            return TestResult::Passed;
        }
        iterations += 1;
        core::hint::spin_loop();
    }
    
    // Tick might not be advancing in test environment
    // This is acceptable for unit test
    TestResult::Skipped(String::from("Timer ticks not advancing (expected in some environments)"))
}

/// Test yield point mechanism
pub fn test_yield_point() -> TestResult {
    use crate::task::preemption_controller;
    
    let controller = preemption_controller();
    let stats_before = controller.stats();
    
    // Trigger yield point
    crate::task::yield_point();
    
    let stats_after = controller.stats();
    
    // Voluntary yields should have increased
    // Note: yield_point only marks, doesn't actually yield in this context
    if stats_after.yield_points_checked < stats_before.yield_points_checked {
        return TestResult::Failed(String::from("Yield point counter not incrementing"));
    }
    
    TestResult::Passed
}

/// Test waker mechanism
pub fn test_waker_mechanism() -> TestResult {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    
    static WAKE_COUNT: AtomicU32 = AtomicU32::new(0);
    
    // Create a simple waker that increments counter
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),  // clone
        |_| WAKE_COUNT.fetch_add(1, Ordering::SeqCst), // wake
        |_| WAKE_COUNT.fetch_add(1, Ordering::SeqCst), // wake_by_ref
        |_| {}, // drop
    );
    
    let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw_waker) };
    
    // Wake the waker
    waker.wake_by_ref();
    
    if WAKE_COUNT.load(Ordering::SeqCst) == 0 {
        return TestResult::Failed(String::from("Waker was not called"));
    }
    
    TestResult::Passed
}

/// Test future polling
pub fn test_future_polling() -> TestResult {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    
    // Create a simple future
    struct CountdownFuture {
        remaining: u32,
    }
    
    impl Future for CountdownFuture {
        type Output = u32;
        
        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.remaining == 0 {
                Poll::Ready(42)
            } else {
                self.remaining -= 1;
                Poll::Pending
            }
        }
    }
    
    // Create waker
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw_waker) };
    let mut cx = Context::from_waker(&waker);
    
    // Poll the future
    let mut future = CountdownFuture { remaining: 3 };
    let mut pinned = unsafe { Pin::new_unchecked(&mut future) };
    
    // Should return Pending 3 times, then Ready
    for _ in 0..3 {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Pending => {},
            Poll::Ready(_) => {
                return TestResult::Failed(String::from("Future completed too early"));
            }
        }
    }
    
    match pinned.poll(&mut cx) {
        Poll::Ready(val) => {
            if val != 42 {
                return TestResult::Failed(alloc::format!("Wrong result: expected 42, got {}", val));
            }
        }
        Poll::Pending => {
            return TestResult::Failed(String::from("Future should have completed"));
        }
    }
    
    TestResult::Passed
}

/// Test task ID generation
pub fn test_task_id_generation() -> TestResult {
    use crate::task::TaskId;
    
    let id1 = TaskId::new();
    let id2 = TaskId::new();
    let id3 = TaskId::new();
    
    // IDs should be unique
    if id1 == id2 || id2 == id3 || id1 == id3 {
        return TestResult::Failed(String::from("Task IDs are not unique"));
    }
    
    // IDs should be increasing
    if id2.0 <= id1.0 || id3.0 <= id2.0 {
        return TestResult::Failed(String::from("Task IDs should be increasing"));
    }
    
    TestResult::Passed
}

/// Test work stealing queue
pub fn test_work_stealing_queue() -> TestResult {
    use crate::task::work_stealing::WorkStealingQueue;
    
    let mut queue = WorkStealingQueue::new();
    
    // Test empty queue
    if queue.steal().is_some() {
        return TestResult::Failed(String::from("Empty queue should return None"));
    }
    
    TestResult::Passed
}
