// ============================================================================
// src/task/waker.rs - Simplified Waker (without crossbeam)
// ============================================================================
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::collections::VecDeque;
use core::task::Waker;
use spin::Mutex;
use super::TaskId;

/// ISR-safe wake queue
/// 注意: crossbeam::SegQueue の代わりに Mutex<VecDeque> を使用
/// 本来はロックフリーが理想だが、一旦これで動作確認
static WAKE_QUEUE: Mutex<VecDeque<TaskId>> = Mutex::new(VecDeque::new());

/// ArcWakeトレイトを使った効率的なWaker実装
struct TaskWaker {
    task_id: TaskId,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Wake queueにタスクIDを追加
        // ISR内から呼ばれる可能性があるため、できるだけ短時間でロックを解放
        WAKE_QUEUE.lock().push_back(self.task_id);
    }
}

/// Wakerを作成する公開API
pub fn create_waker(task_id: TaskId) -> Waker {
    Waker::from(Arc::new(TaskWaker { task_id }))
}

/// Wake queueからタスクIDを取り出す
pub fn pop_woken_task() -> Option<TaskId> {
    WAKE_QUEUE.lock().pop_front()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waker_wake() {
        let task_id = TaskId::new();
        let waker = create_waker(task_id);
        
        // Wake should push to queue
        waker.wake_by_ref();
        
        // Should be able to pop the task
        assert_eq!(pop_woken_task(), Some(task_id));
    }
}
