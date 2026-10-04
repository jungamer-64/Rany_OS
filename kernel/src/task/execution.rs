use crate::cpu::CurrentCpu;
use crate::domain::quota::{MemoryBinding, MemoryCredit, QuotaError};
use crate::domain::{DomainCredentials, DomainId, DomainSecurityLookupError};
use crate::security::CapabilitySet;

use super::TaskId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subject {
    pub domain: DomainId,
    pub task: TaskId,
    pub cred: DomainCredentials,
    pub caps: CapabilitySet,
}

impl Subject {
    /// Resolve the task's security subject at execution admission. Missing or
    /// terminated owners never inherit the kernel's credentials/capabilities.
    pub fn for_task(domain: DomainId, task: TaskId) -> Result<Self, DomainSecurityLookupError> {
        let security = crate::domain::domain_security_handle(domain)?;
        Ok(Self {
            domain,
            task,
            cred: security.credentials,
            caps: security.caps,
        })
    }

    pub fn kernel() -> Self {
        let security = crate::domain::DomainSecurity::kernel();
        Self {
            domain: DomainId::KERNEL,
            task: TaskId::from_raw(0),
            cred: security.credentials,
            caps: security.caps,
        }
    }
}

/// Security lookup and quota binding are independently fallible admission
/// steps. No context is installed when either step rejects the task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionAdmissionError {
    Security(DomainSecurityLookupError),
    Quota(QuotaError),
}

impl core::fmt::Display for ExecutionAdmissionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Security(error) => write!(formatter, "execution security lookup failed: {error}"),
            Self::Quota(error) => write!(formatter, "execution quota admission failed: {error}"),
        }
    }
}

/// An execution owns its quota binding. Task admission binds its subject's
/// account; framework recovery may fund bookkeeping without changing the
/// subject. CPU-local installation always moves the complete context.
#[derive(Debug)]
pub struct ExecutionContext {
    subject: Subject,
    memory: MemoryBinding,
    pub(crate) cell: Option<crate::loader::CellId>,
    pub(crate) finalization: Option<FinalizationAuthority>,
}

#[derive(Debug, Clone)]
pub(crate) struct FinalizationAuthority {
    pub(crate) code: Option<alloc::sync::Arc<crate::loader::code::CodeLease>>,
}

impl ExecutionContext {
    /// Fund framework recovery without acquiring domain or quota registry locks.
    /// Destructors invoked by recovery retain the initiating subject's authority.
    /// With no installed execution, the caller is still in bootstrap/kernel
    /// context, whose security value is constructed without heap allocation.
    pub(crate) fn housekeeping(subject: Option<Subject>) -> Self {
        let subject = subject.unwrap_or_else(Subject::kernel);
        Self {
            subject,
            memory: MemoryBinding::kernel(),
            cell: None,
            finalization: None,
        }
    }

    pub fn for_task(task: TaskId, domain: DomainId) -> Result<Self, ExecutionAdmissionError> {
        let subject = Subject::for_task(domain, task).map_err(ExecutionAdmissionError::Security)?;
        let memory = if domain == DomainId::KERNEL {
            MemoryBinding::kernel()
        } else {
            crate::domain::quota::quota_manager()
                .bind_memory(domain)
                .map_err(ExecutionAdmissionError::Quota)?
        };
        Ok(Self {
            subject,
            memory,
            cell: None,
            finalization: None,
        })
    }

    pub fn from_subject(subject: Subject) -> Result<Self, QuotaError> {
        let memory = crate::domain::quota::quota_manager().bind_memory(subject.domain)?;
        Ok(Self {
            subject,
            memory,
            cell: None,
            finalization: None,
        })
    }

    pub(crate) fn with_cell(mut self, cell: Option<crate::loader::CellId>) -> Self {
        self.cell = cell;
        self
    }

    pub(crate) fn with_finalization(mut self, authority: FinalizationAuthority) -> Self {
        self.finalization = Some(authority);
        self
    }

    pub(crate) fn subject(&self) -> Subject {
        self.subject
    }

    pub(crate) fn reserve_memory(&self, bytes: u64) -> Result<Option<MemoryCredit>, QuotaError> {
        self.memory.reserve(bytes)
    }
}

#[derive(Debug)]
pub enum ExecutionContextUnavailable {
    UnboundCpu,
    NoExecution,
    Admission(ExecutionAdmissionError),
    CodeUnavailable,
}

pub fn current_subject() -> Subject {
    CurrentCpu::acquire()
        .and_then(|cpu| cpu.execution())
        .unwrap_or_else(Subject::kernel)
}

pub fn current_task_id() -> u64 {
    CurrentCpu::acquire()
        .and_then(|cpu| cpu.execution())
        .map(|subject| subject.task.as_u64())
        .unwrap_or(0)
}

pub(crate) fn enter_domain(
    domain: DomainId,
) -> Result<crate::cpu::ExecutionContextGuard, ExecutionContextUnavailable> {
    let current = CurrentCpu::acquire().ok_or(ExecutionContextUnavailable::UnboundCpu)?;
    let subject = current
        .execution()
        .ok_or(ExecutionContextUnavailable::NoExecution)?;
    let lease = crate::domain::registry::acquire_execution_code_lease(domain)
        .ok_or(ExecutionContextUnavailable::CodeUnavailable)?;
    let context = ExecutionContext::for_task(subject.task, domain)
        .map_err(ExecutionContextUnavailable::Admission)?;
    Ok(current
        .enter_execution(context.with_cell(lease.cell()))
        .retain_code(lease))
}

/// The nested entry owns its code lease on the executing task's stack.
pub(crate) fn enter_cell_domain(
    domain: DomainId,
    cell: crate::loader::CellId,
) -> Result<crate::cpu::ExecutionContextGuard, ExecutionContextUnavailable> {
    let current = CurrentCpu::acquire().ok_or(ExecutionContextUnavailable::UnboundCpu)?;
    let subject = current
        .execution()
        .ok_or(ExecutionContextUnavailable::NoExecution)?;
    let lease = crate::domain::registry::acquire_cell_execution_lease(domain, cell)
        .ok_or(ExecutionContextUnavailable::CodeUnavailable)?;
    let context = ExecutionContext::for_task(subject.task, domain)
        .map_err(ExecutionContextUnavailable::Admission)?;
    Ok(current
        .enter_execution(context.with_cell(Some(cell)))
        .retain_code(lease))
}

pub(crate) fn enter_domain_teardown(
    domain: DomainId,
    code: Option<&alloc::sync::Arc<crate::loader::code::CodeLease>>,
) -> Result<crate::cpu::ExecutionContextGuard, ExecutionContextUnavailable> {
    let current = CurrentCpu::acquire().ok_or(ExecutionContextUnavailable::UnboundCpu)?;
    let subject = current
        .execution()
        .ok_or(ExecutionContextUnavailable::NoExecution)?;
    let lease = crate::domain::registry::acquire_teardown_code_lease(
        domain,
        code.map(|code| code.as_ref()),
    )
    .ok_or(ExecutionContextUnavailable::CodeUnavailable)?;
    let context = ExecutionContext::for_task(subject.task, domain)
        .map_err(ExecutionContextUnavailable::Admission)?;
    Ok(current
        .enter_execution(
            context
                .with_cell(lease.cell())
                .with_finalization(FinalizationAuthority {
                    code: code.cloned(),
                }),
        )
        .retain_code(lease))
}

/// Registered invocation keeps its owner's exact code generation until return.
pub(crate) fn enter_resource_callback(
    domain: DomainId,
    resource: &crate::domain::DomainCodeLease,
    invocation: crate::domain::registry::ResourceInvocation,
) -> Result<crate::cpu::ExecutionContextGuard, ExecutionContextUnavailable> {
    let current = CurrentCpu::acquire().ok_or(ExecutionContextUnavailable::UnboundCpu)?;
    let subject = current
        .execution()
        .ok_or(ExecutionContextUnavailable::NoExecution)?;
    let lease =
        crate::domain::registry::acquire_resource_execution_lease(domain, resource, invocation)
            .ok_or(ExecutionContextUnavailable::CodeUnavailable)?;
    let context = ExecutionContext::for_task(subject.task, domain)
        .map_err(ExecutionContextUnavailable::Admission)?;
    let finalization = match invocation {
        crate::domain::registry::ResourceInvocation::Finalize => Some(FinalizationAuthority {
            code: resource
                .retain_finalization_code()
                .map_err(|_| ExecutionContextUnavailable::CodeUnavailable)?,
        }),
        crate::domain::registry::ResourceInvocation::Operation => None,
    };
    let mut context = context.with_cell(lease.cell());
    context.finalization = finalization;
    Ok(current.enter_execution(context).retain_code(lease))
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn security_and_quota_admission_report_independent_rejections() {
        crate::domain::init();
        let task = TaskId::from_raw(0x5345_4355);
        let missing = DomainId::new(u64::MAX);
        assert!(matches!(
            ExecutionContext::for_task(task, missing),
            Err(ExecutionAdmissionError::Security(DomainSecurityLookupError::UnknownDomain(id)))
                if id == missing
        ));
        let domain =
            crate::domain::create_domain(alloc::string::String::from("execution_admission"))
                .expect("fixture domain admission");
        let subject = Subject::for_task(domain, task).expect("live security subject");
        assert_eq!(subject.domain, domain);
        assert_eq!(subject.task, task);
        assert_eq!(subject.caps, CapabilitySet::empty());
        let retained = crate::domain::quota_manager()
            .bind_memory(domain)
            .expect("fixture account binding");
        crate::domain::quota_manager().unregister(domain);
        assert!(matches!(
            ExecutionContext::for_task(task, domain),
            Err(ExecutionAdmissionError::Quota(QuotaError::Retired { domain_id }))
                if domain_id == domain
        ));
        assert!(Subject::for_task(domain, task).is_ok());
        drop(retained);
        crate::domain::quota_manager()
            .register(crate::domain::DomainQuota::new(
                domain,
                crate::domain::DomainPriority::Normal,
            ))
            .expect("quiescent account can be explicitly re-admitted");
        crate::domain::terminate_domain(domain).expect("fixture domain retirement");
        assert!(matches!(
            ExecutionContext::for_task(task, domain),
            Err(ExecutionAdmissionError::Security(DomainSecurityLookupError::Terminated(id)))
                if id == domain
        ));
    }

    #[test]
    fn recovery_funding_preserves_subject_and_retains_retired_account() {
        let domain = crate::domain::create_domain(alloc::string::String::from("recovery_subject"))
            .expect("domain admission");
        crate::domain::set_domain_resource_limits(domain, 100, 1, 0).expect("one byte quota");
        let subject = Subject {
            domain,
            task: TaskId::from_raw(0x5245_434f),
            cred: DomainCredentials { uid: 123, gid: 456 },
            caps: CapabilitySet::empty(),
        };
        let admitted = ExecutionContext::from_subject(subject).expect("execution admission");
        assert!(admitted.reserve_memory(2).is_err());
        let recovery = ExecutionContext::housekeeping(Some(subject));
        assert_eq!(recovery.subject(), subject);
        assert!(matches!(recovery.reserve_memory(1), Ok(None)));
        crate::domain::terminate_domain(domain).expect("retire initiating domain");
        drop(recovery);
        assert_eq!(admitted.subject(), subject);
        assert!(
            matches!(admitted.reserve_memory(1), Err(QuotaError::Retired { domain_id }) if domain_id == domain)
        );
        assert!(crate::domain::quota_manager().get_stats(domain).is_some());
        drop(admitted);
        assert!(crate::domain::quota_manager().get_stats(domain).is_none());
    }

    #[test]
    fn bootstrap_recovery_uses_the_kernel_subject_without_admission() {
        let recovery = ExecutionContext::housekeeping(None);
        let security = crate::domain::DomainSecurity::kernel();
        assert_eq!(
            recovery.subject(),
            Subject {
                domain: DomainId::KERNEL,
                task: TaskId::from_raw(0),
                cred: security.credentials,
                caps: security.caps,
            }
        );
        assert!(matches!(recovery.reserve_memory(u64::MAX), Ok(None)));
    }
}
