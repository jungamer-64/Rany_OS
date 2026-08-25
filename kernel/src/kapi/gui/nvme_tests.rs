// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod nvme_tests {
    use super::*;
    use crate::domain::{DomainCredentials, DomainId};
    use crate::kapi::EXOKERNEL;
    use crate::security::capability::{self, CapabilitySet};
    use crate::task::{ExecutionContext, Subject, TaskId};
    use kernel_api::service::kernel::KernelServices;

    pub(super) fn set_current_subject(domain_id: DomainId) -> crate::cpu::ExecutionContextGuard {
        let current = crate::cpu::CurrentCpu::acquire().expect("test CPU-local state");
        let caps = crate::security::capability::manager().get_capabilities(domain_id.as_u64());
        current.enter_execution(ExecutionContext {
            subject: Subject {
                domain: domain_id,
                task: TaskId::new(),
                cred: DomainCredentials::ROOT,
                caps,
            },
        })
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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
