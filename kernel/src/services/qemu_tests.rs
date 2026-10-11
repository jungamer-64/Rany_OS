// ============================================================================
// kernel/src/services/qemu_tests.rs - Kernel service caller ownership
// ============================================================================

use super::*;
use crate::domain::DomainId;
use crate::security::CapabilitySet;
use crate::services::device_registration::authorize_dma_device_for_current_subject;
use crate::services::host::KERNEL_SERVICE_HOST;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::ipc::{RRef, RRefError};

fn fixture_domain(name: &str) -> DomainId {
    let id =
        crate::domain::create_domain(alloc::string::String::from(name)).expect("domain creation");
    crate::domain::set_domain_capabilities(id, CapabilitySet::full()).expect("domain capabilities");
    crate::domain::start_domain(id).expect("domain start");
    id
}

fn finish_domain(id: DomainId) {
    crate::domain::terminate_domain(id).expect("fixture domain termination");
}

fn complete_immediately<F: core::future::Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let mut context = core::task::Context::from_waker(core::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        core::task::Poll::Ready(value) => value,
        core::task::Poll::Pending => {
            panic!("completed operation unexpectedly remained pending")
        }
    }
}

fn authorize_dma_device_for_current_subject_rejects_unbound_domain() {
    let owner = fixture_domain("kapi_unbound_dma");
    let subject_guard = crate::task::enter_domain(owner).expect("domain entry");
    let locator = PackedPciLocation::new(0, 0, 6, 0);
    let err = authorize_dma_device_for_current_subject(locator).unwrap_err();
    assert!(matches!(err, KapiError::PermissionDenied));
    drop(subject_guard);
    finish_domain(owner);
}

fn authorize_dma_device_for_current_subject_allows_kernel_domain() {
    let _subject_guard = crate::task::enter_domain(DomainId::KERNEL).expect("domain entry");
    let locator = PackedPciLocation::new(0x1234, 0x56, 0x07, 0x01);
    let device = authorize_dma_device_for_current_subject(locator)
        .expect("kernel domain should bypass driver binding lookup");

    assert_eq!(device.segment, 0x1234);
    assert_eq!(device.bus, 0x56);
    assert_eq!(device.device, 0x07);
    assert_eq!(device.function, 0x01);
}

fn fs_close_rejects_foreign_owner() {
    let owner = fixture_domain("fs_close_rejects_foreign_owner_owner");
    let caller = fixture_domain("fs_close_rejects_foreign_owner_caller");

    let handle = {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        let mut open =
            KERNEL_SERVICE_HOST.fs_open_with_token("foreign-close-test", OpenMode::Write, None);
        match open.as_mut().poll(&mut core::task::Context::from_waker(
            core::task::Waker::noop(),
        )) {
            core::task::Poll::Ready(result) => result.expect("owner should open file"),
            core::task::Poll::Pending => {
                panic!("volatile memfs open should complete immediately")
            }
        }
    };
    let handle_id = handle.id();
    let mode = handle.mode();

    {
        let _caller_guard = crate::task::enter_domain(caller).expect("domain entry");
        let err = KERNEL_SERVICE_HOST.fs_close(handle).unwrap_err();
        assert!(matches!(err, KapiError::PermissionDenied));
    }

    {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        KERNEL_SERVICE_HOST
            .fs_close(FileHandle::new(handle_id, mode))
            .expect("owner should still be able to close file");
    }
    finish_domain(owner);
    finish_domain(caller);
}

fn nvme_direct_handle_rejects_use_after_close(device_id: u64) {
    let owner = fixture_domain("nvme_direct_handle_rejects_use_after_close_owner");
    let handle = {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        KERNEL_SERVICE_HOST
            .nvme_open_direct_with_token(device_id, 0, 1, None)
            .expect("owner should open direct handle")
    };

    {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        KERNEL_SERVICE_HOST
            .nvme_close_direct(handle)
            .expect("owner should close direct handle");
    }

    {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        let err = complete_immediately(KERNEL_SERVICE_HOST.nvme_flush_direct(handle)).unwrap_err();
        assert!(matches!(err, KapiError::InvalidHandle));
    }
    finish_domain(owner);
}

fn nvme_direct_handle_rejects_foreign_domain_use(device_id: u64) {
    let owner = fixture_domain("nvme_direct_handle_rejects_foreign_domain_use_owner");
    let caller = fixture_domain("nvme_direct_handle_rejects_foreign_domain_use_caller");
    let handle = {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        KERNEL_SERVICE_HOST
            .nvme_open_direct_with_token(device_id, 0, 1, None)
            .expect("owner should open direct handle")
    };

    {
        let _caller_guard = crate::task::enter_domain(caller).expect("domain entry");
        let err = complete_immediately(KERNEL_SERVICE_HOST.nvme_flush_direct(handle)).unwrap_err();
        assert!(matches!(err, KapiError::PermissionDenied));
    }

    {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        KERNEL_SERVICE_HOST
            .nvme_close_direct(handle)
            .expect("owner should still be able to close direct handle");
    }
    finish_domain(owner);
    finish_domain(caller);
}

fn ipc_close_rejects_foreign_owner() {
    let owner = fixture_domain("ipc_close_rejects_foreign_owner_owner");
    let caller = fixture_domain("ipc_close_rejects_foreign_owner_caller");

    let (sender, receiver) = {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        KERNEL_SERVICE_HOST
            .ipc_create_channel()
            .expect("owner should create channel")
    };
    let sender_id = sender.id();

    {
        let _caller_guard = crate::task::enter_domain(caller).expect("domain entry");
        let err = KERNEL_SERVICE_HOST.ipc_close(sender).unwrap_err();
        assert!(matches!(err, KapiError::PermissionDenied));
    }

    {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        KERNEL_SERVICE_HOST
            .ipc_close(ChannelHandle::new(sender_id))
            .expect("owner should close sender");
        KERNEL_SERVICE_HOST
            .ipc_close(receiver)
            .expect("owner should close receiver");
    }
    finish_domain(owner);
    finish_domain(caller);
}

fn ipc_send_and_recv_reject_foreign_owner() {
    let owner = fixture_domain("ipc_send_and_recv_reject_foreign_owner_owner");
    let caller = fixture_domain("ipc_send_and_recv_reject_foreign_owner_caller");

    let (sender, receiver) = {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        KERNEL_SERVICE_HOST
            .ipc_create_channel()
            .expect("owner should create channel")
    };
    let sender_id = sender.id();
    let receiver_id = receiver.id();

    {
        let _caller_guard = crate::task::enter_domain(caller).expect("domain entry");
        let err = RRef::<u64>::new(7)
            .expect("caller should allocate exchange object")
            .send(ChannelHandle::new(sender_id))
            .unwrap_err();
        assert!(matches!(
            err,
            RRefError::Kernel(KapiError::PermissionDenied)
        ));
    }

    {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        RRef::<u64>::new(42)
            .expect("owner should allocate exchange object")
            .send(ChannelHandle::new(sender_id))
            .expect("owner should send on owned channel");
    }

    {
        let _caller_guard = crate::task::enter_domain(caller).expect("domain entry");
        let err = RRef::<u64>::recv(ChannelHandle::new(receiver_id))
            .err()
            .expect("foreign receive must be rejected");
        assert!(matches!(
            err,
            RRefError::Kernel(KapiError::PermissionDenied)
        ));
    }

    {
        let _owner_guard = crate::task::enter_domain(owner).expect("domain entry");
        let value = RRef::<u64>::recv(ChannelHandle::new(receiver_id))
            .expect("owner should still receive queued value");
        assert_eq!(*value, 42);
        KERNEL_SERVICE_HOST
            .ipc_close(ChannelHandle::new(sender_id))
            .expect("owner should close sender");
        KERNEL_SERVICE_HOST
            .ipc_close(ChannelHandle::new(receiver_id))
            .expect("owner should close receiver");
    }
    finish_domain(owner);
    finish_domain(caller);
}

fn test_fs_open_with_token_reclaim() {
    // Setup: create caller and target domains
    let caller = fixture_domain("kapi_token_caller");
    let target = fixture_domain("kapi_token_target");

    // Caller gets permission to grant CAP_FOWNER
    crate::security::capability::manager().set_capabilities(
        caller.as_u64(),
        CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER),
    );
    let _caller_guard = crate::task::enter_domain(caller).expect("domain entry");

    // Grant token to target
    let token = crate::security::capability::manager()
        .grant_capability_with_opts(
            caller.as_u64(),
            target.as_u64(),
            crate::security::capability::CAP_FOWNER,
            None,
            false,
        )
        .unwrap();

    // Target opens using token
    let handle = {
        let _target_guard = crate::task::enter_domain(target).expect("domain entry");
        let mut open = KERNEL_SERVICE_HOST.fs_open_with_token(
            "test_token_file",
            kernel_api::resource::fs::OpenMode::Write,
            Some(token),
        );
        match open.as_mut().poll(&mut core::task::Context::from_waker(
            core::task::Waker::noop(),
        )) {
            core::task::Poll::Ready(result) => result.expect("open should succeed"),
            core::task::Poll::Pending => {
                panic!("volatile memfs open should complete immediately")
            }
        }
    };
    assert_eq!(
        crate::security::capability::manager().in_flight_count(token),
        1
    );

    // Issue revocation
    assert!(
        crate::security::capability::manager()
            .revoke_grant(caller.as_u64(), token, false)
            .is_ok()
    );

    // Immediate reclaim should fail (in-flight)
    match crate::security::capability::manager().reclaim_token(token) {
        Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
        other => panic!("expected ReclamationBusy, got {:?}", other),
    }

    // Close file handle
    {
        let _target_guard = crate::task::enter_domain(target).expect("domain entry");
        assert!(KERNEL_SERVICE_HOST.fs_close(handle).is_ok());
    }

    // Now reclaim should succeed
    assert!(
        crate::security::capability::manager()
            .reclaim_token(token)
            .is_ok()
    );
    drop(_caller_guard);
    finish_domain(target);
    finish_domain(caller);
}

pub(crate) fn run_kernel_service_ownership_suite() -> bool {
    authorize_dma_device_for_current_subject_rejects_unbound_domain();
    log::info!(target: "init", "[kernel-test][kapi] case authorize_dma_device_for_current_subject_rejects_unbound_domain ok");
    authorize_dma_device_for_current_subject_allows_kernel_domain();
    log::info!(target: "init", "[kernel-test][kapi] case authorize_dma_device_for_current_subject_allows_kernel_domain ok");
    fs_close_rejects_foreign_owner();
    log::info!(target: "init", "[kernel-test][kapi] case fs_close_rejects_foreign_owner ok");
    ipc_close_rejects_foreign_owner();
    log::info!(target: "init", "[kernel-test][kapi] case ipc_close_rejects_foreign_owner ok");
    ipc_send_and_recv_reject_foreign_owner();
    log::info!(target: "init", "[kernel-test][kapi] case ipc_send_and_recv_reject_foreign_owner ok");
    test_fs_open_with_token_reclaim();
    log::info!(target: "init", "[kernel-test][kapi] case test_fs_open_with_token_reclaim ok");
    true
}

pub(crate) fn run_block_handle_ownership_suite() -> bool {
    let scheduler = crate::io::io_scheduler::io_scheduler();
    let device_id = scheduler
        .registered_devices()
        .into_iter()
        .find_map(|device| {
            let geometry = scheduler.get_device_ops(device)?.block_geometry()?;
            (geometry.block_count.get() != 0)
                .then(|| device.storage_id())
                .flatten()
        })
        .expect("storage profile must publish a usable block device");
    nvme_direct_handle_rejects_use_after_close(device_id);
    log::info!(target: "init", "[kernel-test][kapi] case nvme_direct_handle_rejects_use_after_close ok");
    nvme_direct_handle_rejects_foreign_domain_use(device_id);
    log::info!(target: "init", "[kernel-test][kapi] case nvme_direct_handle_rejects_foreign_domain_use ok");
    true
}
