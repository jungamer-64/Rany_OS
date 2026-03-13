use super::*;

#[test_case]
fn priority_ordering_matches_runtime_expectations() {
    assert!(Priority::Realtime < Priority::High);
    assert!(Priority::High < Priority::Normal);
    assert!(Priority::Normal < Priority::Low);
    assert!(Priority::Low < Priority::Idle);
}

#[test_case]
fn executor_creation_tracks_core_id() {
    let executor = PerCoreExecutor::new(3);
    assert_eq!(executor.core_id(), 3);
    assert_eq!(executor.queue_length(), 0);
}

#[test_case]
fn polled_task_context_round_trips() {
    mark_current_polled_task(
        2,
        crate::task::TaskId::from_raw(77),
        crate::domain_system::DomainId::new(9),
    );
    let context = current_polled_task_context().expect("missing polled task context");
    assert_eq!(context.cpu_id, 2);
    assert_eq!(context.task_id, 77);
    assert_eq!(context.domain_id, 9);
    clear_current_polled_task();
    assert!(current_polled_task_context().is_none());
}

#[test_case]
fn manager_spawn_and_steal_operate_on_canonical_tasks() {
    let manager = ExecutorManager::new();
    manager.init(2);

    let victim = manager.get_executor(0).expect("missing victim executor");
    let thief = manager.get_executor(1).expect("missing thief executor");

    let task_a = ScheduledTask::new(crate::task::Task::new(async {}), Priority::Normal, 0);
    let task_b = ScheduledTask::new(crate::task::Task::new(async {}), Priority::Normal, 0);
    assert!(victim.enqueue_spawned_task(task_a));
    assert!(victim.enqueue_spawned_task(task_b));

    assert!(thief.try_steal());
    assert!(thief.queue_length() >= 1);
    assert!(thief.stats().tasks_stolen >= 1);
    assert!(victim.stats().tasks_stolen_from >= 1);
}

#[test_case]
fn remote_wake_targets_logical_cpu_mapping() {
    crate::smp::reset_cpu_routing_for_tests();
    crate::smp::reset_runtime_workers_for_tests();
    crate::smp::register_cpu_apic_mapping(0, 2);
    crate::smp::register_cpu_apic_mapping(1, 41);
    crate::smp::release_runtime_workers();

    LAST_REMOTE_WAKE_APIC.store(u64::MAX, Ordering::Release);
    REMOTE_WAKE_BROADCASTS.store(0, Ordering::Release);

    let manager = ExecutorManager::new();
    manager.init(2);
    let task = ScheduledTask::new(crate::task::Task::new(async {}), Priority::Normal, 1);

    manager.queue_wake(task);

    assert_eq!(LAST_REMOTE_WAKE_APIC.load(Ordering::Acquire), 41);
    assert_eq!(REMOTE_WAKE_BROADCASTS.load(Ordering::Acquire), 0);
}

#[test_case]
fn remote_wake_broadcasts_when_apic_mapping_is_missing() {
    crate::smp::reset_cpu_routing_for_tests();
    crate::smp::reset_runtime_workers_for_tests();
    crate::smp::register_cpu_apic_mapping(0, 2);
    crate::smp::release_runtime_workers();

    LAST_REMOTE_WAKE_APIC.store(u64::MAX, Ordering::Release);
    REMOTE_WAKE_BROADCASTS.store(0, Ordering::Release);

    let manager = ExecutorManager::new();
    manager.init(2);
    let task = ScheduledTask::new(crate::task::Task::new(async {}), Priority::Normal, 1);

    manager.queue_wake(task);

    assert_eq!(LAST_REMOTE_WAKE_APIC.load(Ordering::Acquire), u64::MAX);
    assert_eq!(REMOTE_WAKE_BROADCASTS.load(Ordering::Acquire), 1);
}
