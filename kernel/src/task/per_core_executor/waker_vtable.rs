use super::*;


pub(crate) const WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

pub(crate) unsafe fn waker_clone(data: *const ()) -> RawWaker {
    let data = unsafe { &*(data as *const TaskWakerData) };

    // タスクの参照カウントを増やす
    let task = unsafe { raw::arc_from_raw(data.task as *const Task) };
    let _ = task.clone();
    core::mem::forget(task);

    let new_data = Box::new(TaskWakerData {
        task: data.task,
        core_id: data.core_id,
    });

    RawWaker::new(Box::into_raw(new_data) as *const (), &WAKER_VTABLE)
}

pub(crate) unsafe fn waker_wake(data: *const ()) {
    unsafe {
        waker_wake_by_ref(data);
    }
    unsafe {
        waker_drop(data);
    }
}

pub(crate) unsafe fn waker_wake_by_ref(data: *const ()) {
    let data = unsafe { &*(data as *const TaskWakerData) };

    // タスクを復元
    let task = unsafe { raw::arc_from_raw(data.task as *const Task) };
    let task_clone = task.clone();
    core::mem::forget(task); // 参照カウントを維持

    // エグゼキュータマネージャにタスクを再スケジュール
    if let Some(executor) = EXECUTOR_MANAGER.get_executor(data.core_id) {
        executor.schedule(task_clone);
    } else {
        // フォールバック: グローバルキューへ
        EXECUTOR_MANAGER.spawn(task_clone);
    }
}

pub(crate) unsafe fn waker_drop(data: *const ()) {
    let data = unsafe { raw::box_from_raw(data as *mut TaskWakerData) };

    // タスクの参照カウントを減らす
    let _ = unsafe { raw::arc_from_raw(data.task as *const Task) };
}

// ============================================================================
// Global Instance
// ============================================================================

/// グローバルエグゼキュータマネージャ
pub(crate) static EXECUTOR_MANAGER: ExecutorManager = ExecutorManager::new();

/// エグゼキュータマネージャにアクセス
pub fn executor_manager() -> &'static ExecutorManager {
    &EXECUTOR_MANAGER
}

/// エグゼキュータを初期化
pub fn init_executors(core_count: usize) {
    EXECUTOR_MANAGER.init(core_count);
}

/// タスクをspawn（便利関数）
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = Task::new(future, Priority::Normal, None);
    EXECUTOR_MANAGER.spawn(task);
}

/// 優先度付きでタスクをspawn
pub fn spawn_with_priority<F>(future: F, priority: Priority, domain_id: Option<u64>)
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = Task::new(future, priority, domain_id);
    EXECUTOR_MANAGER.spawn(task);
}

// ============================================================================
// Helper Functions
// ============================================================================

/// TSCを読み取る
#[inline]
pub(crate) fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// 現在のコアIDを取得
#[inline]
pub(crate) fn current_core_id() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // LAPICレジスタからIDを取得
        crate::io::apic::local_apic().id() as u32
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

