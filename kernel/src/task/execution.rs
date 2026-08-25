use crate::cpu::CurrentCpu;
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
    pub fn for_task(domain: DomainId, task: TaskId) -> Self {
        let security = crate::domain::domain_security_handle(domain);
        Self {
            domain,
            task,
            cred: security.credentials,
            caps: security.caps,
        }
    }

    pub fn kernel() -> Self {
        Self::for_task(DomainId::KERNEL, TaskId::from_raw(0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionContext {
    pub subject: Subject,
}

impl ExecutionContext {
    pub fn for_task(task: TaskId, domain: DomainId) -> Self {
        Self {
            subject: Subject::for_task(domain, task),
        }
    }

    pub fn with_domain(self, domain: DomainId) -> Self {
        Self::for_task(self.subject.task, domain)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionContextUnavailable;

pub fn current_execution_context() -> Option<ExecutionContext> {
    CurrentCpu::acquire()?.execution()
}

pub fn current_subject() -> Subject {
    current_execution_context()
        .map(|context| context.subject)
        .unwrap_or_else(Subject::kernel)
}

pub fn current_task_id() -> u64 {
    current_execution_context()
        .map(|context| context.subject.task.as_u64())
        .unwrap_or(0)
}

pub(crate) fn enter_domain(
    domain: DomainId,
) -> Result<crate::cpu::ExecutionContextGuard, ExecutionContextUnavailable> {
    let current = CurrentCpu::acquire().ok_or(ExecutionContextUnavailable)?;
    let context = current.execution().ok_or(ExecutionContextUnavailable)?;
    Ok(current.enter_execution(context.with_domain(domain)))
}
