use super::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use crate::domain_system::{DomainCredentials, DomainSecurity};
use crate::security::capability::{manager, CapabilitySet, CAP_IPC_LOCK};
use crate::task::context::{get_current_task, set_current_task, TaskControlBlock};

fn idle_entry(_: u64) -> ! {
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
    let mut tcb = TaskControlBlock::new(idle_entry, 0, 0, domain_id)
        .expect("failed to create test TCB");
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
fn test_shared_memory_basic() {
    let id = shm_manager().create(
        ShmKey::IPC_PRIVATE,
        ShmSize::new(4096),
        ShmPermissions::default(),
        ShmFlags {
            create: true,
            ..Default::default()
        },
    )
    .unwrap();

    let handle = shm_manager().attach(id).unwrap();
    assert!(handle.is_attached());
    assert_eq!(handle.size(), 4096);

    // 書き込みテスト
    handle.write_at(0, b"Hello").unwrap();

    // 読み取りテスト
    let mut buf = [0u8; 5];
    handle.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf, b"Hello");
}

#[test_case]
fn test_named_shared_memory() {
    let name = "/test_shm";
    let id = shm_manager().create_named(
        name,
        ShmSize::new(8192),
        ShmPermissions::default(),
        ShmFlags {
            create: true,
            exclusive: true,
            ..Default::default()
        },
    )
    .unwrap();

    let handle = shm_manager().attach(id).unwrap();
    handle.write_at(0, b"Named SHM").unwrap();

    let id2 = shm_manager().get_by_name(name).expect("named region must exist");
    assert_eq!(id, id2);
}

#[test_case]
fn test_zero_copy_region() {
    let domain1 = DomainId::new(1);

    let region: ZeroCopyRegion<u64> = ZeroCopyRegion::new("/zero_copy_test", domain1).unwrap();

    // 値を書き込み
    region.write(42u64).unwrap();

    // RRefとして読み取り
    let rref = region.read_as_rref().unwrap();
    assert_eq!(*rref, 42);
    assert_eq!(rref.owner(), domain1);
}

#[test_case]
fn test_shm_attach_with_token_reclaim() {
    // Setup: create caller and target domains
    let caller = DomainId::new(1);
    let target = DomainId::new(2);

    // Caller gets permission to grant CAP_IPC_LOCK
    manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_IPC_LOCK));
    let _caller_guard = set_current_subject(caller);

    // Grant token to target
    let token = manager().grant_capability_with_opts(
        caller.as_u64(),
        target.as_u64(),
        CAP_IPC_LOCK,
        None,
        false,
    )
    .unwrap();

    // Caller creates the named shared memory
    let name = "/token_shm";
    let id = shm_manager().create_named(
        name,
        ShmSize::new(4096),
        ShmPermissions::default(),
        ShmFlags {
            create: true,
            ..Default::default()
        },
    )
    .unwrap();

    // Target attaches using token
    let handle = {
        let _target_guard = set_current_subject(target);
        let handle = shm_manager().attach_with_token(id, Some(token)).unwrap();
        assert!(handle.is_attached());
        assert_eq!(manager().in_flight_count(token), 1);
        handle
    };

    // Issuer revokes token
    assert!(manager().revoke_grant(caller.as_u64(), token, false).is_ok());

    // Immediate reclaim should fail (in-flight)
    match manager().reclaim_token(token) {
        Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
        other => panic!("expected ReclamationBusy, got {:?}", other),
    }

    // Now detach (target releases resource)
    {
        let _target_guard = set_current_subject(target);
        handle.detach().unwrap();
    }

    assert_eq!(manager().in_flight_count(token), 0);
    // Now reclaim should succeed
    assert!(manager().reclaim_token(token).is_ok());
}
