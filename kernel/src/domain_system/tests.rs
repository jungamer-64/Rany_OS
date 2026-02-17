use super::*;

#[test_case]
fn test_set_and_get_domain_numa() {
    let id = create_domain(String::from("numa_test")).expect("create_domain failed");
    assert_eq!(get_domain_numa(id), None);
    set_domain_numa(id, 3);
    assert_eq!(get_domain_numa(id), Some(3usize));
}

#[test_case]
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

#[test_case]
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

#[test_case]
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

#[test_case]
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
