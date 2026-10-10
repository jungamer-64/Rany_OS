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

    let guard = REGISTRY.lock().expect("registry acquisition");
    set_panicking(true);
    drop(guard);
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

    let guard = REGISTRY.lock().expect("registry acquisition");
    set_panicking(true);
    drop(guard);
    set_panicking(false);

    let res = create_domain(String::from("poison_test2"));
    assert_eq!(
        res,
        Err(KernelError::Domain(DomainErrorKind::RegistryPoisoned))
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_reclaim_domain_resources_poisoned_no_panic() {
    use crate::sync::set_panicking;

    let id = create_domain(String::from("reclaim_poison")).expect("create_domain failed");

    let guard = REGISTRY.lock().expect("registry acquisition");
    set_panicking(true);
    drop(guard);
    set_panicking(false);

    assert_eq!(
        terminate_domain(id),
        Err(DomainLifecycleError::RegistryPoisoned)
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn cpu_quota_waits_until_the_next_serialized_period() {
    let quota =
        crate::domain::quota::CpuQuota::new(20, core::time::Duration::from_millis(100)).unwrap();
    assert_eq!(quota.wait_deadline(0), None);
    assert!(quota.consume(20_000_001, 30_000_000));
    assert_eq!(quota.wait_deadline(99_999_999), Some(100_000_000));
    assert_eq!(quota.wait_deadline(100_000_000), None);
    assert!(!quota.consume(1, 100_000_001));
    let zero =
        crate::domain::quota::CpuQuota::new(0, core::time::Duration::from_millis(100)).unwrap();
    assert_eq!(zero.wait_deadline(0), Some(100_000_000));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn invalid_resource_policy_preserves_published_limits() {
    let id = create_domain("resource-policy".into()).unwrap();
    let before = with_domain(id, |domain| {
        (
            domain.cpu_limit_percent,
            domain.memory_limit_bytes,
            domain.io_bandwidth_limit,
        )
    })
    .unwrap();
    assert_eq!(
        set_domain_resource_limits(id, 101, 512, 1024),
        Err(DomainPolicyError::Quota(
            QuotaError::CpuPercentageOutOfRange { requested: 101 }
        ))
    );
    assert_eq!(
        with_domain(id, |domain| {
            (
                domain.cpu_limit_percent,
                domain.memory_limit_bytes,
                domain.io_bandwidth_limit,
            )
        }),
        Some(before)
    );
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

    let _dma_guard = crate::resource_registry::dma::testing::acquire_test_dma_state_guard();
    DMA_DROP_COUNTER.store(0, Ordering::SeqCst);

    let owner = create_domain(String::from("dma_reclaim")).expect("create_domain failed");
    let other = create_domain(String::from("dma_other")).expect("create_domain failed");

    let handle = crate::resource_registry::dma::testing::register_test_dma_entry(
        owner.as_u64(),
        0x9000,
        4096,
        &DMA_DROP_COUNTER,
    );
    let other_handle = crate::resource_registry::dma::testing::register_test_dma_entry(
        other.as_u64(),
        0xA000,
        2048,
        &DMA_DROP_COUNTER,
    );

    terminate_domain(owner).expect("domain termination failed");

    assert!(!crate::resource_registry::dma::testing::test_dma_handle_exists(handle));
    assert!(
        !crate::resource_registry::dma::testing::test_dma_phys_owned_by(
            0x9000,
            4096,
            owner.as_u64()
        )
    );
    assert!(crate::resource_registry::dma::testing::test_dma_handle_exists(other_handle));
    assert!(
        crate::resource_registry::dma::testing::test_dma_phys_owned_by(
            0xA000,
            2048,
            other.as_u64()
        )
    );
    assert_eq!(DMA_DROP_COUNTER.load(Ordering::SeqCst), 1);
}

#[cfg(test)]
mod lifecycle_contract_tests {
    use super::*;
    use crate::domain::{DomainState, create_domain};

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_domain_lifecycle() {
        // ドメイン作成
        let id = crate::domain::create_domain("test_domain".into()).expect("create_domain failed");

        // 状態確認
        let state = with_domain(id, |d| d.state);
        assert_eq!(state, Some(DomainState::Initializing));

        // 状態変更
        crate::domain::start_domain(id).expect("initializing domain starts");
        let state = with_domain(id, |d| d.state);
        assert_eq!(state, Some(DomainState::Running));

        // 終了
        let result = crate::domain::terminate_domain(id);
        assert!(result.is_ok());
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn completed_stop_preserves_memory_account_and_reclaimed_domain_cannot_restart() {
        let id = create_domain("retained_restart".into()).unwrap();
        let binding = crate::domain::quota_manager().bind_memory(id).unwrap();
        let credit = binding.reserve(123).unwrap();
        assert_eq!(
            crate::domain::stop_domain(id).unwrap(),
            crate::domain::DomainStopOutcome::Complete
        );
        restart_domain(id).unwrap();
        assert_eq!(
            crate::domain::quota_manager()
                .get_stats(id)
                .unwrap()
                .memory_used,
            123
        );
        crate::domain::terminate_domain(id).unwrap();
        assert!(matches!(
            restart_domain(id),
            Err(DomainError::Lifecycle(
                crate::domain::DomainLifecycleError::InvalidState(DomainState::Terminated)
            ))
        ));
        assert!(matches!(
            binding.reserve(1),
            Err(crate::domain::QuotaError::Retired { .. })
        ));
        drop(credit);
        drop(binding);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn rejected_policy_update_preserves_domain_metadata() {
        let id = create_domain("policy_failure".into()).unwrap();
        crate::domain::set_domain_resource_limits(id, 100, 513, 0).unwrap();
        let binding = crate::domain::quota_manager().bind_memory(id).unwrap();
        let credit = binding.reserve(512).unwrap();
        crate::domain::terminate_domain(id).unwrap();
        assert!(matches!(
            crate::domain::set_domain_resource_limits(id, 50, 19, 0),
            Err(crate::domain::DomainPolicyError::Quota(
                crate::domain::quota::QuotaError::Retired { .. }
            ))
        ));
        assert_eq!(
            crate::domain::get_domain_snapshot(id)
                .unwrap()
                .memory_limit_bytes,
            513
        );
        assert_eq!(
            crate::domain::quota_manager()
                .get_stats(id)
                .unwrap()
                .memory_used,
            512
        );
        drop(credit);
        drop(binding);
    }
}
