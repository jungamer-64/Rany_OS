use crate::cpu::CurrentCpu;
use crate::domain::quota::{MemoryBinding, MemoryCredit, QuotaError};
use crate::domain::{DomainCredentials, DomainId};
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

    pub fn kernel() -> Self {
        Self::for_task(DomainId::KERNEL, TaskId::from_raw(0))
    }
}

/// An execution owns its quota binding. Task admission binds its subject's
/// account; framework recovery may fund bookkeeping without changing the
/// subject. CPU-local installation always moves the complete context.
#[derive(Debug)]
pub struct ExecutionContext {
    subject: Subject,
    memory: MemoryBinding,
}

impl ExecutionContext {
    /// Admit a kernel task at the cold security-context boundary.
    pub(crate) fn kernel(task: TaskId) -> Self {
        Self {
            subject: Subject::for_task(DomainId::KERNEL, task),
            memory: MemoryBinding::kernel(),
        }
    }

    /// Fund framework recovery without acquiring domain or quota registry locks.
    /// Destructors invoked by recovery retain the initiating subject's authority.
    /// With no installed execution, the caller is still in bootstrap/kernel
    /// context, whose security value is constructed without heap allocation.
    pub(crate) fn housekeeping(subject: Option<Subject>) -> Self {
        let subject = subject.unwrap_or_else(|| {
            let security = crate::domain::DomainSecurity::kernel();
            Subject {
                domain: DomainId::KERNEL,
                task: TaskId::from_raw(0),
                cred: security.credentials,
                caps: security.caps,
            }
        });
        Self {
            subject,
            memory: MemoryBinding::kernel(),
        }
    }

    pub fn for_task(task: TaskId, domain: DomainId) -> Result<Self, QuotaError> {
        if domain == DomainId::KERNEL {
            return Ok(Self::kernel(task));
        }
        Self::from_subject(Subject::for_task(domain, task))
    }

    pub fn from_subject(subject: Subject) -> Result<Self, QuotaError> {
        let memory = crate::domain::quota::quota_manager().bind_memory(subject.domain)?;
        Ok(Self { subject, memory })
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
    Quota(QuotaError),
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
    let context = ExecutionContext::for_task(subject.task, domain)
        .map_err(ExecutionContextUnavailable::Quota)?;
    Ok(current.enter_execution(context))
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn recovery_funding_preserves_subject_and_restores_retired_admission() {
        let domain = crate::domain::create_domain(alloc::string::String::from("recovery_subject"))
            .expect("domain admission");
        crate::domain::set_domain_resource_limits(domain, 100, 1, 0).expect("one byte quota");
        let subject = Subject {
            domain,
            task: TaskId::from_raw(0x5245_434f),
            cred: DomainCredentials { uid: 123, gid: 456 },
            caps: CapabilitySet::empty(),
        };
        let current = CurrentCpu::acquire().expect("bound CPU");
        let admitted = current
            .enter_execution(ExecutionContext::from_subject(subject).expect("execution admission"));
        let current = CurrentCpu::acquire().expect("bound CPU");
        assert!(current.reserve_memory(2).is_err());
        let recovery = current.enter_execution(ExecutionContext::housekeeping(Some(subject)));
        let current = CurrentCpu::acquire().expect("bound CPU");
        assert_eq!(current.execution(), Some(subject));
        assert!(matches!(current.reserve_memory(1), Ok(None)));
        crate::domain::terminate_domain(domain).expect("retire initiating domain");
        drop(recovery);
        let current = CurrentCpu::acquire().expect("bound CPU");
        assert_eq!(current.execution(), Some(subject));
        assert!(matches!(
            current.reserve_memory(1),
            Err(QuotaError::Retired { domain_id }) if domain_id == domain
        ));
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
