use super::*;
use crate::security::capability::{manager, CapabilitySet, CAP_NET_BIND};
use crate::task::process::{ProcessId, process_manager, set_current_process};

#[test_case]
fn test_spawn_with_caps_success() {
    let parent = process_manager().create(ProcessId::INIT, "parent_test").unwrap();
    set_current_process(parent);
    manager().set_capabilities(parent.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

    let req = RequestedCap { cap: CAP_NET_BIND, expires: None, delegatable: false };
    let res = spawn_with_caps("child_test", &[req]).unwrap();
    let (child, tokens) = res;
    assert!(!tokens.is_empty());
    assert!(manager().has_capability(child.as_u64(), CAP_NET_BIND));
}

#[test_case]
fn test_spawn_with_caps_denied() {
    let parent = process_manager().create(ProcessId::INIT, "parent_test2").unwrap();
    set_current_process(parent);
    manager().set_capabilities(parent.as_u64(), CapabilitySet::empty());

    let req = RequestedCap { cap: CAP_NET_BIND, expires: None, delegatable: false };
    let res = spawn_with_caps("child_test2", &[req]);
    assert!(res.is_err());
}

#[test_case]
fn test_spawn_with_caps_revoke() {
    let parent = process_manager().create(ProcessId::INIT, "parent_test3").unwrap();
    set_current_process(parent);
    manager().set_capabilities(parent.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

    let req = RequestedCap { cap: CAP_NET_BIND, expires: None, delegatable: false };
    let (child, tokens) = spawn_with_caps("child_test3", &[req]).unwrap();
    assert!(!tokens.is_empty());
    let t = tokens[0];

    // Non-issuer cannot revoke
    let attacker = process_manager().create(ProcessId::INIT, "attacker").unwrap();
    let res = manager().revoke_grant(attacker.as_u64(), t, false);
    assert!(res.is_err());

    // Issuer revokes (mark revoked but keep token)
    assert!(manager().revoke_grant(parent.as_u64(), t, false).is_ok());
    assert!(!manager().has_capability(child.as_u64(), CAP_NET_BIND));

    // Token should remain but be marked revoked
    let grants = manager().list_grants(child.as_u64());
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id, t);
    assert!(grants[0].revoked);
}

#[test_case]
fn test_spawn_with_caps_rollback_on_partial_failure() {
    use crate::security::capability::CAP_NET_RAW;
    let parent = process_manager().create(ProcessId::INIT, "parent_test4").unwrap();
    set_current_process(parent);
    // parent allowed both caps
    manager().set_capabilities(parent.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND | CAP_NET_RAW));

    // Force second grant (CAP_NET_RAW) to fail
    manager().force_fail_next_grant_for(CAP_NET_RAW);

    // Request two caps: first should succeed, second will be forced to fail
    let reqs = [
        RequestedCap { cap: CAP_NET_BIND, expires: None, delegatable: false },
        RequestedCap { cap: CAP_NET_RAW, expires: None, delegatable: false },
    ];

    let res = spawn_with_caps("child_test4", &reqs);
    assert!(res.is_err());

    // Child should not have any of the requested capabilities and no tokens remain
    let child_pid = process_manager().list().last().copied().unwrap();
    assert!(!manager().has_capability(child_pid.as_u64(), CAP_NET_BIND));
    assert!(!manager().has_capability(child_pid.as_u64(), CAP_NET_RAW));
    assert!(manager().list_grants(child_pid.as_u64()).is_empty());
}

#[test_case]
fn test_spawn_with_caps_in_flight_reclaim() {
    let parent = process_manager().create(ProcessId::INIT, "parent_ifr").unwrap();
    set_current_process(parent);
    manager().set_capabilities(parent.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

    let req = RequestedCap { cap: CAP_NET_BIND, expires: None, delegatable: false };
    let (child, tokens) = spawn_with_caps("child_ifr", &[req]).unwrap();
    let t = tokens[0];
    assert_eq!(manager().in_flight_count(t), 1);

    // Issuer revokes (mark revoked but keep token)
    assert!(manager().revoke_grant(parent.as_u64(), t, false).is_ok());

    // Immediate reclaim should fail due to in-flight
    assert!(matches!(manager().reclaim_token(t), Err(crate::security::capability::CapabilityError::ReclamationBusy)));

    // Now exit and reap child, which should decrement in-flight
    assert!(PROCESS_MANAGER.exit(child, ExitCode(0)).is_ok());
    assert!(PROCESS_MANAGER.reap(child).is_ok());

    assert_eq!(manager().in_flight_count(t), 0);
    // Now reclaim should succeed
    assert!(manager().reclaim_token(t).is_ok());
}
