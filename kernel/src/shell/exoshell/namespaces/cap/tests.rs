use super::*;
use crate::domain_system::{DomainCredentials, DomainId, DomainSecurity};
use crate::security::capability::*;
use crate::task::context::{TaskControlBlock, get_current_task, set_current_task};
use alloc::boxed::Box;
use alloc::sync::Arc;

fn idle_entry(_: u64) -> ! {
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        core::hint::spin_loop();
    }
}

struct CurrentTaskGuard {
    prev: Option<*mut TaskControlBlock>,
    current: *mut TaskControlBlock,
}

impl Drop for CurrentTaskGuard {
    fn drop(&mut self) {
        let cpu_id = crate::smp::current_cpu() as usize;
        let prev_ptr = self.prev.unwrap_or(core::ptr::null_mut());
        unsafe {
            set_current_task(cpu_id, prev_ptr);
            drop(Box::from_raw(self.current));
        }
    }
}

fn set_current_subject(domain_id: DomainId) -> CurrentTaskGuard {
    let cpu_id = crate::smp::current_cpu() as usize;
    let prev = get_current_task(cpu_id);
    let mut tcb =
        TaskControlBlock::new(idle_entry, 0, 0, domain_id).expect("failed to create test TCB");
    let caps = manager().get_capabilities(domain_id.as_u64());
    tcb.security = Arc::new(DomainSecurity {
        credentials: DomainCredentials::ROOT,
        caps,
    });
    let boxed = Box::new(tcb);
    let current = Box::into_raw(boxed);
    unsafe {
        set_current_task(cpu_id, current);
    }
    CurrentTaskGuard { prev, current }
}

#[test_case]
fn test_grant_requires_permissions() {
    let caller = DomainId::new(100);
    let _guard = set_current_subject(caller);
    // caller has no capabilities
    manager().set_capabilities(caller.as_u64(), CapabilitySet::empty());

    let target = DomainId::new(101);

    let res = CapNamespace::grant(
        "/net/bind",
        &[],
        &format!("{}", target.as_u64()),
        None,
        false,
    );
    match res {
        ExoValue::Error(_) => {}
        other => panic!("Expected error, got {:?}", other),
    }
}

#[test_case]
fn test_grant_with_permitted() {
    let caller = DomainId::new(110);
    let _guard = set_current_subject(caller);
    // give caller permitted CAP_NET_BIND
    manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

    let target = DomainId::new(111);

    let res = CapNamespace::grant(
        "/net/bind",
        &[],
        &format!("{}", target.as_u64()),
        None,
        false,
    );

    match res {
        ExoValue::Capability(cap) => {
            assert_eq!(cap.resource, "/net/bind");
            // Should have a token id
            assert!(cap.id > 0);
            // target should now have effective capability
            assert!(manager().has_capability(target.as_u64(), CAP_NET_BIND));
            let grants = manager().list_grants(target.as_u64());
            assert_eq!(grants.len(), 1);
            assert_eq!(grants[0].id, cap.id);
        }
        other => panic!("grant failed: {:?}", other),
    }
}

#[test_case]
fn test_tokens_listing_and_revoke() {
    let caller = DomainId::new(120);
    let mut _guard = set_current_subject(caller);
    manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

    let target = DomainId::new(121);

    // Grant a token
    let res = CapNamespace::grant(
        "/net/bind",
        &[],
        &format!("{}", target.as_u64()),
        None,
        false,
    );
    let token_id = match res {
        ExoValue::Capability(cap) => cap.id,
        other => panic!("grant failed: {:?}", other),
    };

    // Switch to target and list tokens
    _guard = set_current_subject(target);
    match CapNamespace::tokens(None) {
        ExoValue::Array(arr) => {
            assert_eq!(arr.len(), 1);
            match &arr[0] {
                ExoValue::Capability(cap) => assert_eq!(cap.id, token_id),
                other => panic!("Expected capability token, got {:?}", other),
            }
        }
        other => panic!("tokens() failed: {:?}", other),
    }

    // Try to revoke as non-issuer (should fail)
    _guard = set_current_subject(target);
    match CapNamespace::revoke(token_id) {
        ExoValue::Error(_) => {}
        other => panic!("Expected error on unauthorized revoke, got {:?}", other),
    }

    // Revoke as issuer
    _guard = set_current_subject(caller);
    match CapNamespace::revoke(token_id) {
        ExoValue::Bool(true) => {}
        other => panic!("Expected success on revoke by issuer, got {:?}", other),
    }

    // Token removed
    assert!(manager().list_grants(target.as_u64()).is_empty());
}

#[test_case]
fn test_sysadmin_can_revoke() {
    let issuer = DomainId::new(130);
    let mut _guard = set_current_subject(issuer);
    manager().set_capabilities(issuer.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

    let target = DomainId::new(131);

    let res = CapNamespace::grant(
        "/net/bind",
        &[],
        &format!("{}", target.as_u64()),
        None,
        false,
    );
    let token_id = match res {
        ExoValue::Capability(cap) => cap.id,
        other => panic!("grant failed: {:?}", other),
    };

    let admin = DomainId::new(132);
    manager().set_capabilities(admin.as_u64(), CapabilitySet::with_permitted(CAP_SYS_ADMIN));

    _guard = set_current_subject(admin);
    match CapNamespace::revoke(token_id) {
        ExoValue::Bool(true) => {}
        other => panic!("Expected admin revoke to succeed, got {:?}", other),
    }

    assert!(manager().list_grants(target.as_u64()).is_empty());
}

#[test_case]
fn test_delegation_allows_regrant() {
    let parent = DomainId::new(140);
    let mut _guard = set_current_subject(parent);
    manager().set_capabilities(parent.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

    let child = DomainId::new(141);
    let grand = DomainId::new(142);

    // Parent grants to child with delegatable=true
    let _t = match CapNamespace::grant("/net/bind", &[], &format!("{}", child.as_u64()), None, true)
    {
        ExoValue::Capability(cap) => cap.id,
        other => panic!("grant failed: {:?}", other),
    };

    // Child re-grants to grand
    _guard = set_current_subject(child);
    let res = CapNamespace::grant(
        "/net/bind",
        &[],
        &format!("{}", grand.as_u64()),
        None,
        false,
    );
    match res {
        ExoValue::Capability(cap) => {
            assert!(manager().has_capability(grand.as_u64(), CAP_NET_BIND));
        }
        other => panic!("regrant failed: {:?}", other),
    }
}

#[test_case]
fn test_delegation_denies_regrant_when_not_delegatable() {
    let parent = DomainId::new(150);
    let mut _guard = set_current_subject(parent);
    manager().set_capabilities(parent.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

    let child = DomainId::new(151);
    let grand = DomainId::new(152);

    // Parent grants to child with delegatable=false
    let _t = match CapNamespace::grant(
        "/net/bind",
        &[],
        &format!("{}", child.as_u64()),
        None,
        false,
    ) {
        ExoValue::Capability(cap) => cap.id,
        other => panic!("grant failed: {:?}", other),
    };

    // Child tries to re-grant to grand and should fail
    _guard = set_current_subject(child);
    match CapNamespace::grant(
        "/net/bind",
        &[],
        &format!("{}", grand.as_u64()),
        None,
        false,
    ) {
        ExoValue::Error(_) => {}
        other => panic!("Expected regrant to fail, got {:?}", other),
    }
}
