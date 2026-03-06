use super::*;

#[test_case]
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

#[test_case]
fn test_raise_not_permitted() {
    let mut caps = CapabilitySet::with_permitted(CAP_NET_BIND);

    assert!(caps.raise(CAP_SYS_ADMIN).is_err());
}

#[test_case]
fn test_grant_with_options() {
    let caller: u64 = 1001;
    let target: u64 = 2001;

    // Caller has permitted CAP_NET_BIND
    manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

    // Grant with expiry and no delegation
    let res = manager().grant_capability_with_opts(caller, target, CAP_NET_BIND, Some(9999), false);
    assert!(res.is_ok(), "grant_with_opts failed: {:?}", res);
    let token = res.unwrap();

    // Capability should be present
    assert!(manager().has_capability(target, CAP_NET_BIND));

    let grants = manager().list_grants(target);
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id, token);
    assert_eq!(grants[0].delegatable, false);
    assert_eq!(grants[0].expires, Some(9999));
}

#[test_case]
fn test_revoke_grant() {
    let caller: u64 = 1010;
    let target: u64 = 2010;

    manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

    let token = manager()
        .grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false)
        .unwrap();
    assert!(manager().has_capability(target, CAP_NET_BIND));

    // Revoke by issuer (mark revoked but keep token for reclamation)
    assert!(manager().revoke_grant(caller, token, false).is_ok());
    assert!(!manager().has_capability(target, CAP_NET_BIND));

    // Token should remain but be marked revoked
    let grants = manager().list_grants(target);
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id, token);
    assert!(grants[0].revoked);
}

#[test_case]
fn test_expire_grants() {
    let caller: u64 = 1100;
    let target: u64 = 2100;

    manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

    // Grant with expiry equal to 0 -- in tests 'now' is defined as 0, so this should expire immediately
    let token = manager()
        .grant_capability_with_opts(caller, target, CAP_NET_BIND, Some(0), false)
        .unwrap();
    // Immediately expire internal list
    manager().expire_grants();

    // Capability should be removed
    assert!(!manager().has_capability(target, CAP_NET_BIND));
    // Token should be gone
    assert!(manager().list_grants(target).is_empty());
}

#[test_case]
fn test_expire_grants_wrapper() {
    let caller: u64 = 1300;
    let target: u64 = 2300;

    manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));
    let token = manager()
        .grant_capability_with_opts(caller, target, CAP_NET_BIND, Some(0), false)
        .unwrap();
    assert!(manager().has_capability(target, CAP_NET_BIND));

    // Use public wrapper
    expire_grants_now();

    assert!(!manager().has_capability(target, CAP_NET_BIND));
    assert!(manager().list_grants(target).is_empty());
}

#[test_case]
fn test_spawn_expiry_daemon_task_idempotent() {
    spawn_expiry_daemon_task();
    spawn_expiry_daemon_task();
}

#[test_case]
fn test_grant_requires_permissions_manager() {
    // Use numeric domain ids to avoid depending on process_manager here
    let caller: u64 = 1000;
    let target: u64 = 2000;

    // caller has no capabilities
    manager().set_capabilities(caller, CapabilitySet::empty());

    let res = manager().grant_capability(caller, target, CAP_NET_BIND);
    assert!(res.is_err(), "Expected grant to fail without permissions");
}

#[test_case]
fn test_reclaim_token() {
    let caller: u64 = 1200;
    let target: u64 = 2200;

    manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));
    let token = manager()
        .grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false)
        .unwrap();
    assert!(manager().has_capability(target, CAP_NET_BIND));

    // Revoke (mark revoked)
    assert!(manager().revoke_grant(caller, token, false).is_ok());
    assert!(!manager().has_capability(target, CAP_NET_BIND));

    // Reclamation status should report revoked
    match manager().reclamation_status(token) {
        Some(ReclamationStatus::Revoked { revoked_at: _ }) => {}
        other => panic!("Expected token to be revoked, got {:?}", other),
    }

    // Now reclaim it
    assert!(manager().reclaim_token(token).is_ok());
    // Token should be gone
    assert!(manager().list_grants(target).is_empty());
}

#[test_case]
fn test_in_flight_blocks_reclaim() {
    let caller: u64 = 1400;
    let target: u64 = 2400;

    manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));
    let token = manager()
        .grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false)
        .unwrap();

    // Simulate an in-flight user
    assert!(manager().increment_in_flight(token).is_ok());

    // Revoke (mark revoked)
    assert!(manager().revoke_grant(caller, token, false).is_ok());
    assert!(!manager().has_capability(target, CAP_NET_BIND));

    // reclaim_now should not remove while in-flight
    manager().reclaim_revoked_now();
    let grants = manager().list_grants(target);
    assert_eq!(grants.len(), 1);

    // manual reclaim should fail with busy
    match manager().reclaim_token(token) {
        Err(CapabilityError::ReclamationBusy) => {}
        other => panic!("Expected ReclamationBusy, got {:?}", other),
    }

    // release in-flight
    assert!(manager().decrement_in_flight(token).is_ok());

    // now reclaim
    manager().reclaim_revoked_now();
    assert!(manager().list_grants(target).is_empty());
}

#[test_case]
fn test_spawn_reclamation_daemon_task_idempotent() {
    spawn_reclamation_daemon_task();
    spawn_reclamation_daemon_task();
}

#[test_case]
fn test_grant_with_permitted_manager() {
    let caller: u64 = 1001;
    let target: u64 = 2001;

    // give caller permitted CAP_NET_BIND
    manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

    let res = manager().grant_capability(caller, target, CAP_NET_BIND);
    assert!(
        res.is_ok(),
        "Expected grant to succeed when caller is permitted"
    );

    // target should now have effective capability
    assert!(manager().has_capability(target, CAP_NET_BIND));
}
