use super::*;
use alloc::sync::Arc;

fn test_ap_boot_info(bootable_aps: usize) -> boot_proto::ApBootInfo {
    if bootable_aps == 0 {
        return boot_proto::ApBootInfo::default();
    }
    boot_proto::ApBootLayout::new(
        bootable_aps as u16,
        bootable_aps as u16,
        ap_trampoline::TrampolinePhysAddr::new(0x8000).unwrap(),
        ap_trampoline::TRAMPOLINE_SIZE as u64,
        0x20_0000,
        0x20_000,
    )
    .unwrap()
    .into_boot_info()
}

fn install_cpu_topology(apics: &[u8]) {
    let mut snapshot = boot_proto::AcpiBootSnapshot::default();
    snapshot.local_apic_count = apics.len() as u16;
    for (index, apic_id) in apics.iter().copied().enumerate() {
        snapshot.local_apics[index].apic_id = apic_id;
        snapshot.local_apics[index].processor_id = apic_id;
        snapshot.local_apics[index].flags = boot_proto::acpi_local_apic_flags::ENABLED;
    }

    let bootable_aps = apics.len().saturating_sub(1) as u16;
    let ap_boot = test_ap_boot_info(bootable_aps as usize);

    crate::smp::topology::reset();
    let topology = crate::smp::topology::CpuTopology::from_sources(
        &snapshot,
        &boot_proto::NumaInfo::default(),
        &ap_boot,
        apics.first().copied().unwrap_or(0) as u32,
    );
    crate::smp::topology::install(topology.clone());
    crate::smp::lifecycle::initialize_from_topology(&topology);
    crate::smp::lifecycle::set_cpu_stage(0, crate::smp::lifecycle::CpuLifecycleStage::PerCpuReady);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn priority_ordering_matches_runtime_expectations() {
    assert!(Priority::Realtime < Priority::High);
    assert!(Priority::High < Priority::Normal);
    assert!(Priority::Normal < Priority::Low);
    assert!(Priority::Low < Priority::Idle);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn executor_creation_tracks_core_id() {
    let executor = PerCoreExecutor::new(3);
    assert_eq!(executor.core_id(), 3);
    assert_eq!(executor.queue_length(), 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn manager_spawn_and_steal_operate_on_canonical_tasks() {
    let manager = ExecutorManager::new();
    manager.init(2);

    let victim = manager.get_executor(0).expect("missing victim executor");
    let thief = manager.get_executor(1).expect("missing thief executor");

    let task_a = ScheduledTask::new(
        crate::task::Task::new(async {}),
        Priority::Normal,
        u64::MAX,
        0,
        None,
    );
    let task_b = ScheduledTask::new(
        crate::task::Task::new(async {}),
        Priority::Normal,
        u64::MAX,
        0,
        None,
    );
    assert!(victim.enqueue_spawned_task(task_a));
    assert!(victim.enqueue_spawned_task(task_b));

    assert!(thief.try_steal());
    assert!(thief.queue_length() >= 1);
    assert!(thief.stats().tasks_stolen >= 1);
    assert!(victim.stats().tasks_stolen_from >= 1);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn manager_provision_expands_without_resetting_existing_executor_state() {
    let manager = ExecutorManager::new();
    manager.provision(1);

    let bsp = manager.get_executor(0).expect("missing bootstrap executor");
    let task = ScheduledTask::new(
        crate::task::Task::new(async {}),
        Priority::Normal,
        u64::MAX,
        0,
        None,
    );
    assert!(bsp.enqueue_spawned_task(task));

    manager.provision(4);

    let bsp_after = manager
        .get_executor(0)
        .expect("bootstrap executor must remain installed");
    assert!(Arc::ptr_eq(&bsp, &bsp_after));
    assert_eq!(manager.active_cpu_count(), 4);
    assert_eq!(bsp_after.queue_length(), 1);
    assert!(manager.get_executor(3).is_some());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn remote_wake_targets_logical_cpu_mapping() {
    crate::smp::reset_runtime_workers_for_tests();
    install_cpu_topology(&[2, 41]);
    crate::cpu::release_workers();

    LAST_REMOTE_WAKE_APIC.store(u64::MAX, Ordering::Release);
    REMOTE_WAKE_BROADCASTS.store(0, Ordering::Release);

    let manager = ExecutorManager::new();
    manager.init(2);
    let task = ScheduledTask::new(
        crate::task::Task::new(async {}),
        Priority::Normal,
        u64::MAX,
        1,
        None,
    );

    manager.queue_wake(task);

    assert_eq!(LAST_REMOTE_WAKE_APIC.load(Ordering::Acquire), 41);
    assert_eq!(REMOTE_WAKE_BROADCASTS.load(Ordering::Acquire), 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn remote_wake_broadcasts_when_apic_mapping_is_missing() {
    crate::smp::reset_runtime_workers_for_tests();
    install_cpu_topology(&[2]);
    crate::cpu::release_workers();

    LAST_REMOTE_WAKE_APIC.store(u64::MAX, Ordering::Release);
    REMOTE_WAKE_BROADCASTS.store(0, Ordering::Release);

    let manager = ExecutorManager::new();
    manager.init(2);
    let task = ScheduledTask::new(
        crate::task::Task::new(async {}),
        Priority::Normal,
        u64::MAX,
        1,
        None,
    );

    manager.queue_wake(task);

    assert_eq!(LAST_REMOTE_WAKE_APIC.load(Ordering::Acquire), u64::MAX);
    assert_eq!(REMOTE_WAKE_BROADCASTS.load(Ordering::Acquire), 1);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn pick_target_cpu_respects_affinity_mask() {
    let manager = ExecutorManager::new();
    manager.init(3);

    let task = ScheduledTask::new(
        crate::task::Task::new(async {}),
        Priority::Normal,
        u64::MAX,
        0,
        None,
    );
    task.affinity_mask.store(1u64 << 2, Ordering::Release);
    task.set_preferred_cpu(0);

    assert_eq!(manager.pick_target_cpu_for_task(&task), 2);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn steal_from_skips_tasks_that_cannot_run_on_thief_cpu() {
    let manager = ExecutorManager::new();
    manager.init(2);

    let victim = manager.get_executor(0).expect("missing victim executor");
    let thief = manager.get_executor(1).expect("missing thief executor");

    let cpu0_only = ScheduledTask::new(
        crate::task::Task::new(async {}),
        Priority::Normal,
        1,
        0,
        None,
    );
    cpu0_only.affinity_mask.store(1, Ordering::Release);
    assert!(victim.enqueue_spawned_task(cpu0_only));

    assert!(!thief.steal_from(&victim));
    assert_eq!(victim.queue_length(), 1);
    assert_eq!(thief.queue_length(), 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn executor_run_mode_transitions_from_boot_to_runtime() {
    configure_boot_run_mode(false);
    assert_eq!(current_run_mode(), ExecutorRunMode::Boot);
    assert!(!interrupts_allowed_for_executor());

    configure_runtime_interrupts(true);
    transition_to_runtime_run_mode();

    assert_eq!(current_run_mode(), ExecutorRunMode::Runtime);
    assert!(interrupts_allowed_for_executor());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn spawn_on_cpu_with_priority_enqueues_work_on_requested_executor() {
    init_executors(4);

    let executor = executor_manager()
        .get_executor(3)
        .expect("missing executor for cpu3");
    assert_eq!(executor.queue_length(), 0);

    let _ = spawn_on_cpu_with_priority(3, Priority::High, async {});

    assert_eq!(executor.queue_length(), 1);
}
