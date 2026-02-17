use super::*;

#[test_case]
fn test_task_id_generation() {
    let id1 = TaskId::new();
    let id2 = TaskId::new();
    assert_ne!(id1, id2);
}

#[test_case]
fn test_priority_ordering() {
    assert!(Priority::Realtime < Priority::High);
    assert!(Priority::High < Priority::Normal);
    assert!(Priority::Normal < Priority::Low);
    assert!(Priority::Low < Priority::Idle);
}

#[test_case]
fn test_executor_creation() {
    let executor = PerCoreExecutor::new(0);
    assert_eq!(executor.core_id(), 0);
    assert_eq!(executor.queue_length(), 0);
}

#[test_case]
fn test_high_priority_queue_poisoned_spawn_uses_local_queue() {
    use crate::sync::set_panicking;

    let exec = PerCoreExecutor::new(0);

    // create a high-priority task
    let task = Task::new(async {}, Priority::High, None);

    // Poison the high_priority_queue
    set_panicking(true);
    if let Ok(_g) = exec.high_priority_queue.lock() {
        // drop marks as poisoned
    }
    set_panicking(false);

    // spawn should not panic and should fall back to local queue
    exec.spawn(task.clone());
    assert_eq!(exec.queue_length(), 1);
}

#[test_case]
fn test_executor_manager_spawn_falls_back_to_global_queue_when_executors_poisoned() {
    use crate::sync::set_panicking;

    let manager = ExecutorManager::new();

    let task = Task::new(async {}, Priority::Normal, None);

    // Poison executors lock
    set_panicking(true);
    if let Ok(_g) = manager.executors.lock() {
        // drop marks as poisoned
    }
    set_panicking(false);

    manager.spawn(task.clone());

    // global_queue should have the task
    match manager.global_queue.lock() {
        Ok(g) => assert_eq!(g.len(), 1),
        Err(_) => panic!("global_queue poisoned in test"),
    }
}

#[test_case]
fn test_all_stats_poisoned_returns_empty() {
    use crate::sync::set_panicking;

    let manager = ExecutorManager::new();

    // Poison executors lock
    set_panicking(true);
    if let Ok(_g) = manager.executors.lock() {
        // drop marks as poisoned
    }
    set_panicking(false);

    let stats = manager.all_stats();
    assert!(stats.is_empty());
}
