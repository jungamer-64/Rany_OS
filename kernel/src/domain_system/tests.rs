use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_set_and_get_domain_numa() {
    let id = create_domain(String::from("numa_test")).expect("create_domain failed");
    assert_eq!(get_domain_numa(id), None);
    set_domain_numa(id, 3);
    assert_eq!(get_domain_numa(id), Some(3usize));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_quota_sync_and_unregister_on_terminate() {
    use crate::domain::quota::{DomainPriority, quota_manager};

    let id = create_domain(String::from("quota_sync")).expect("create_domain failed");

    let initial = quota_manager()
        .get_stats(id)
        .expect("quota should be registered on create");
    assert_eq!(initial.priority, DomainPriority::Normal);

    set_domain_priority(id, DomainPriority::Low).expect("set_domain_priority failed");
    set_domain_resource_limits(id, 50, 2 * 1024 * 1024, 4 * 1024 * 1024)
        .expect("set_domain_resource_limits failed");

    let updated = quota_manager()
        .get_stats(id)
        .expect("quota should be present after updates");
    assert_eq!(updated.priority, DomainPriority::Low);
    assert_eq!(updated.memory_limit, 2 * 1024 * 1024);

    terminate_domain(id).expect("terminate_domain failed");
    assert!(
        quota_manager().get_stats(id).is_none(),
        "quota must be removed on terminate"
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_domain_poisoned_readers_return_defaults() {
    use crate::sync::set_panicking;

    let id = create_domain(String::from("poison_test")).expect("create_domain failed");

    // Poison the registry lock
    set_panicking(true);
    if let Ok(_g) = REGISTRY.lock() {
        // dropping _g while panicking will mark the lock as poisoned
    }
    set_panicking(false);

    assert!(get_domain_state(id).is_none());
    assert!(with_domain(id, |_d| 1).is_none());
    assert!(with_domain_mut(id, |_d| 1).is_none());
    assert!(start_domain(id).is_err());

    let stats = get_domain_stats();
    assert_eq!(stats.total, 0);

    // print_domain_list should not panic
    print_domain_list();
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_create_domain_poisoned_returns_error() {
    use crate::error::{DomainErrorKind, KernelError};
    use crate::sync::set_panicking;

    // Poison the registry
    set_panicking(true);
    if let Ok(_g) = REGISTRY.lock() {
        // dropping _g will poison the lock
    }
    set_panicking(false);

    let res = create_domain(String::from("poison_test2"));
    assert_eq!(
        res,
        Err(KernelError::Domain(DomainErrorKind::RegistryPoisoned))
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_domain_poisoned_add_remove_task_no_panic() {
    use crate::sync::set_panicking;

    let id = create_domain(String::from("task_poison")).expect("create_domain failed");

    set_panicking(true);
    if let Ok(_g) = REGISTRY.lock() {
        // drop marks as poisoned
    }
    set_panicking(false);

    // should not panic
    add_task_to_domain(id, 1234);
    remove_task_from_domain(id, 1234);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_reclaim_domain_resources_poisoned_no_panic() {
    use crate::sync::set_panicking;

    let id = create_domain(String::from("reclaim_poison")).expect("create_domain failed");

    set_panicking(true);
    if let Ok(_g) = REGISTRY.lock() {
        // drop marks as poisoned
    }
    set_panicking(false);

    reclaim_domain_resources(id);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_cpu_quota_demote_then_suspend() {
    use crate::domain::quota::DomainPriority;

    let id = create_domain(String::from("cpu_quota_demote")).expect("create_domain failed");
    set_domain_priority(id, DomainPriority::High).expect("set_domain_priority failed");

    assert_eq!(
        report_cpu_quota_exceeded(id, 1),
        CpuQuotaAction::YieldDemote,
        "first violation should demote and yield"
    );
    assert_eq!(
        get_domain_snapshot(id)
            .expect("domain snapshot missing")
            .priority,
        DomainPriority::Normal
    );

    assert_eq!(
        report_cpu_quota_exceeded(id, 2),
        CpuQuotaAction::YieldDemote,
        "second violation should demote and yield"
    );
    assert_eq!(
        get_domain_snapshot(id)
            .expect("domain snapshot missing")
            .priority,
        DomainPriority::Low
    );

    let action = report_cpu_quota_exceeded(id, 10);
    let until = match action {
        CpuQuotaAction::Suspend { until_ns } => until_ns,
        other => panic!("expected suspend action, got {:?}", other),
    };
    assert_eq!(
        get_domain_snapshot(id)
            .expect("domain snapshot missing")
            .state,
        DomainState::Suspended
    );
    assert!(
        until >= 10 + CPU_QUOTA_SUSPEND_WINDOW_NS,
        "suspend deadline should include configured window"
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_quota_suspend_auto_resume_after_window() {
    let id = create_domain(String::from("cpu_quota_resume")).expect("create_domain failed");

    let mut deadline = 0;
    for now in [100u64, 200, 300] {
        let action = report_cpu_quota_exceeded(id, now);
        if let CpuQuotaAction::Suspend { until_ns } = action {
            deadline = until_ns;
        }
    }
    assert!(deadline > 0, "domain should enter suspended state");
    assert!(!is_domain_runnable_now(id, deadline.saturating_sub(1)));
    assert!(is_domain_runnable_now(id, deadline.saturating_add(1)));

    let snapshot = get_domain_snapshot(id).expect("domain snapshot missing");
    assert_eq!(snapshot.state, DomainState::Running);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_kernel_domain_is_runnable_before_registry_lookup() {
    assert!(
        is_domain_runnable_now(DomainId::KERNEL, 0),
        "kernel boot tasks must stay runnable during early executor handoff"
    );
}

#[cfg(feature = "full_mm_tests")]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_reclaim_domain_resources_also_reclaims_dma_handles() {
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DMA_DROP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    let _dma_guard = crate::service_impl::acquire_test_dma_state_guard();
    DMA_DROP_COUNTER.store(0, Ordering::SeqCst);

    let owner = create_domain(String::from("dma_reclaim")).expect("create_domain failed");
    let other = create_domain(String::from("dma_other")).expect("create_domain failed");

    let handle = crate::service_impl::register_test_dma_entry(
        owner.as_u64(),
        0x9000,
        4096,
        &DMA_DROP_COUNTER,
    );
    let other_handle = crate::service_impl::register_test_dma_entry(
        other.as_u64(),
        0xA000,
        2048,
        &DMA_DROP_COUNTER,
    );

    reclaim_domain_resources(owner);

    assert!(!crate::service_impl::test_dma_handle_exists(handle));
    assert!(!crate::service_impl::test_dma_phys_owned_by(
        0x9000,
        4096,
        owner.as_u64()
    ));
    assert!(crate::service_impl::test_dma_handle_exists(other_handle));
    assert!(crate::service_impl::test_dma_phys_owned_by(
        0xA000,
        2048,
        other.as_u64()
    ));
    assert_eq!(DMA_DROP_COUNTER.load(Ordering::SeqCst), 1);
}
