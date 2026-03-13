// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod nvme_tests {
    use super::*;
    use crate::domain_system::{DomainCredentials, DomainId, DomainSecurity};
    use crate::security::capability::{self, CapabilitySet};
    use crate::service_impl::kernel_services::gui_services::EXOKERNEL;
    use crate::task::context::{TaskControlBlock, get_current_task, set_current_task};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use kernel_api::service::kernel::KernelServices;

    pub(super) fn idle_entry(_: u64) -> ! {
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            core::hint::spin_loop();
        }
    }

    pub(super) struct CurrentTaskGuard {
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

    pub(super) fn set_current_subject(domain_id: DomainId) -> CurrentTaskGuard {
        let cpu_id = crate::smp::current_cpu() as usize;
        let prev = get_current_task(cpu_id);
        let mut tcb =
            TaskControlBlock::new(idle_entry, 0, 0, domain_id).expect("failed to create test TCB");
        let caps = crate::security::capability::manager().get_capabilities(domain_id.as_u64());
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
    pub(super) fn test_nvme_open_with_token_reclaim() {
        // Setup: create caller and target domains
        let caller = DomainId::new(300);
        let target = DomainId::new(301);

        // Caller gets permission to grant CAP_DMA
        crate::security::capability::manager().set_capabilities(
            caller.as_u64(),
            CapabilitySet::with_permitted(crate::security::capability::CAP_DMA),
        );
        let _caller_guard = set_current_subject(caller);

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(
                caller.as_u64(),
                target.as_u64(),
                crate::security::capability::CAP_DMA,
                None,
                false,
            )
            .unwrap();

        // Target opens using token
        let handle = {
            let _target_guard = set_current_subject(target);
            EXOKERNEL
                .nvme_open_direct_with_token(0, 0, 1, Some(token))
                .expect("open should succeed")
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

        // Target closes handle
        {
            let _target_guard = set_current_subject(target);
            assert!(EXOKERNEL.nvme_close_direct(handle).is_ok());
        }

        assert_eq!(
            crate::security::capability::manager().in_flight_count(token),
            0
        );

        // Now reclaim should succeed
        assert!(
            crate::security::capability::manager()
                .reclaim_token(token)
                .is_ok()
        );
    }
}
