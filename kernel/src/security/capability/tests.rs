use super::*;

fn fresh_manager() -> CapabilityManager {
    CapabilityManager::new()
}

fn with_global_manager_test<T>(f: impl FnOnce() -> T) -> T {
    let _guard = crate::host_test_support::guard();
    reset_for_tests();
    f()
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_capability_set() {
    let mut caps = CapabilitySet::with_permitted(CAP_NET_BIND | CAP_NET_RAW);

    assert!(caps.has_capability(CAP_NET_BIND));
    assert!(caps.has_capability(CAP_NET_RAW));
    assert!(!caps.has_capability(CAP_SYS_ADMIN));

    caps.drop(CAP_NET_BIND);
    assert!(!caps.has_capability(CAP_NET_BIND));

    // Can raise again since it's still permitted
    assert!(caps.raise(CAP_NET_BIND).is_ok());
    assert!(caps.has_capability(CAP_NET_BIND));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_raise_not_permitted() {
    let mut caps = CapabilitySet::with_permitted(CAP_NET_BIND);

    assert!(caps.raise(CAP_SYS_ADMIN).is_err());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_grant_with_options() {
    let manager = fresh_manager();
    let caller: u64 = 1001;
    let target: u64 = 2001;

    // Caller has permitted CAP_NET_BIND
    manager.set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

    // Grant with expiry and no delegation
    let res = manager.grant_capability_with_opts(caller, target, CAP_NET_BIND, Some(9999), false);
    assert!(res.is_ok(), "grant_with_opts failed: {:?}", res);
    let token = res.unwrap();

    // Capability should be present
    assert!(manager.has_capability(target, CAP_NET_BIND));

    let grants = manager.list_grants(target, target);
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id, token);
    assert_eq!(grants[0].delegatable, false);
    assert_eq!(grants[0].expires, Some(9999));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_revoke_grant() {
    let manager = fresh_manager();
    let caller: u64 = 1010;
    let target: u64 = 2010;

    manager.set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

    let token = manager
        .grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false)
        .unwrap();
    assert!(manager.has_capability(target, CAP_NET_BIND));

    // Revoke by issuer (mark revoked but keep token for reclamation)
    assert!(manager.revoke_grant(caller, token, false).is_ok());
    assert!(!manager.has_capability(target, CAP_NET_BIND));

    // Token should remain but be marked revoked
    let grants = manager.list_grants(target, target);
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id, token);
    assert!(grants[0].revoked);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_expire_grants() {
    let manager = fresh_manager();
    let caller: u64 = 1100;
    let target: u64 = 2100;

    manager.set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

    // Grant with expiry equal to 0 -- in tests 'now' is defined as 0, so this should expire immediately
    let _token = manager
        .grant_capability_with_opts(caller, target, CAP_NET_BIND, Some(0), false)
        .unwrap();
    // Immediately expire internal list
    manager.expire_grants();

    // Capability should be removed
    assert!(!manager.has_capability(target, CAP_NET_BIND));
    // Token should be gone
    assert!(manager.list_grants(target, target).is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_expire_grants_wrapper() {
    with_global_manager_test(|| {
        let caller: u64 = 1300;
        let target: u64 = 2300;

        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));
        let _token = manager()
            .grant_capability_with_opts(caller, target, CAP_NET_BIND, Some(0), false)
            .unwrap();
        assert!(manager().has_capability(target, CAP_NET_BIND));

        // Use public wrapper
        expire_grants_now();

        assert!(!manager().has_capability(target, CAP_NET_BIND));
        assert!(manager().list_grants(target, target).is_empty());
    });
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_spawn_expiry_daemon_task_idempotent() {
    with_global_manager_test(|| {
        spawn_expiry_daemon_task();
        spawn_expiry_daemon_task();
    });
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_grant_requires_permissions_manager() {
    let manager = fresh_manager();
    // Use numeric domain ids to avoid depending on process_manager here
    let caller: u64 = 1000;
    let target: u64 = 2000;

    // caller has no capabilities
    manager.set_capabilities(caller, CapabilitySet::empty());

    let res = manager.grant_capability(caller, target, CAP_NET_BIND);
    assert!(res.is_err(), "Expected grant to fail without permissions");
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_reclaim_token() {
    let manager = fresh_manager();
    let caller: u64 = 1200;
    let target: u64 = 2200;

    manager.set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));
    let token = manager
        .grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false)
        .unwrap();
    assert!(manager.has_capability(target, CAP_NET_BIND));

    // Revoke (mark revoked)
    assert!(manager.revoke_grant(caller, token, false).is_ok());
    assert!(!manager.has_capability(target, CAP_NET_BIND));

    // Reclamation status should report revoked
    match manager.reclamation_status(token) {
        Some(ReclamationStatus::Revoked { revoked_at: _ }) => {}
        other => panic!("Expected token to be revoked, got {:?}", other),
    }

    // Now reclaim it
    assert!(manager.reclaim_token(token).is_ok());
    // Token should be gone
    assert!(manager.list_grants(target, target).is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_in_flight_blocks_reclaim() {
    let manager = fresh_manager();
    let caller: u64 = 1400;
    let target: u64 = 2400;

    manager.set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));
    let token = manager
        .grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false)
        .unwrap();

    // Simulate an in-flight user
    assert!(manager.increment_in_flight(token).is_ok());

    // Revoke (mark revoked)
    assert!(manager.revoke_grant(caller, token, false).is_ok());
    assert!(!manager.has_capability(target, CAP_NET_BIND));

    // reclaim_now should not remove while in-flight
    manager.reclaim_revoked_now();
    let grants = manager.list_grants(target, target);
    assert_eq!(grants.len(), 1);

    // manual reclaim should fail with busy
    match manager.reclaim_token(token) {
        Err(CapabilityError::ReclamationBusy) => {}
        other => panic!("Expected ReclamationBusy, got {:?}", other),
    }

    // release in-flight
    assert!(manager.decrement_in_flight(token).is_ok());

    // now reclaim
    manager.reclaim_revoked_now();
    assert!(manager.list_grants(target, target).is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_list_grants_cross_domain_requires_cap_fowner() {
    let manager = fresh_manager();
    let issuer: u64 = 5000;
    let observer: u64 = 5001;
    let target: u64 = 5002;

    manager.set_capabilities(issuer, CapabilitySet::with_permitted(CAP_NET_BIND));
    manager.set_capabilities(observer, CapabilitySet::empty());
    manager.set_capabilities(target, CapabilitySet::empty());

    let token = manager
        .grant_capability_with_opts(issuer, target, CAP_NET_BIND, None, false)
        .unwrap();
    let self_visible = manager.list_grants(target, target);
    assert_eq!(self_visible.len(), 1);
    assert_eq!(self_visible[0].id, token);

    // Cross-domain observer without CAP_FOWNER cannot enumerate target grants.
    assert!(manager.list_grants(observer, target).is_empty());

    manager.set_capabilities(observer, CapabilitySet::full());
    let visible = manager.list_grants(observer, target);
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].id, token);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_spawn_reclamation_daemon_task_idempotent() {
    with_global_manager_test(|| {
        spawn_reclamation_daemon_task();
        spawn_reclamation_daemon_task();
    });
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_capability_init_idempotent() {
    with_global_manager_test(|| {
        init();
        init();

        assert!(manager().has_capability(0, CAP_NET_BIND));
        assert!(manager().has_capability(0, CAP_SYS_ADMIN));
    });
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_grant_with_permitted_manager() {
    let manager = fresh_manager();
    let caller: u64 = 1001;
    let target: u64 = 2001;

    // give caller permitted CAP_NET_BIND
    manager.set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

    let res = manager.grant_capability(caller, target, CAP_NET_BIND);
    assert!(
        res.is_ok(),
        "Expected grant to succeed when caller is permitted"
    );

    // target should now have effective capability
    assert!(manager.has_capability(target, CAP_NET_BIND));
}
