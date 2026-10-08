//! The image-lifetime service host owns background admission and its failure.

use super::host::{KERNEL_SERVICE_HOST, KernelServiceHost};
use crate::io::iommu::types::IommuError;
use kernel_api::resource::task::{SpawnError, TaskId, TaskOptions};
use kernel_api::service::time::TimerError;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Failure {
    Timer(TimerError),
    Iommu(IommuError),
    ExecutionUnavailable,
    Returned,
}

impl core::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Timer(cause) => write!(formatter, "timer: {cause}"),
            Self::Iommu(cause) => write!(formatter, "IOMMU: {cause:?}"),
            Self::ExecutionUnavailable => formatter.write_str("service has no current CPU"),
            Self::Returned => formatter.write_str("service returned unexpectedly"),
        }
    }
}

pub(super) enum State {
    Idle,
    Running(TaskId),
    Failed { task: TaskId, cause: Failure },
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Job {
    Maintenance,
    BlockIo,
    CapabilityGrants,
    SecurityMonitor,
    IntelCommands,
    IntelFaults,
    AmdCommands,
    AmdFaults,
}

#[derive(Debug)]
pub(crate) enum ServiceTaskError {
    Admission {
        job: Job,
        cause: SpawnError,
    },
    Failed {
        job: Job,
        task: TaskId,
        cause: Failure,
    },
}

impl core::fmt::Display for ServiceTaskError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Admission { job, cause } => {
                write!(formatter, "{job:?} admission failed: {cause}")
            }
            Self::Failed { job, task, cause } => {
                write!(formatter, "{job:?} task={} failed: {cause}", task.as_u64())
            }
        }
    }
}

impl KernelServiceHost {
    fn job_state(&self, job: Job) -> &crate::sync::Mutex<State> {
        match job {
            Job::Maintenance => &self.maintenance,
            Job::BlockIo => &self.block_io,
            Job::CapabilityGrants => &self.capability_grants,
            Job::SecurityMonitor => &self.security_monitor,
            Job::IntelCommands => &self.intel_commands,
            Job::IntelFaults => &self.intel_faults,
            Job::AmdCommands => &self.amd_commands,
            Job::AmdFaults => &self.amd_faults,
        }
    }

    fn start_job(&'static self, job: Job) -> Result<(), ServiceTaskError> {
        let mut state = self.job_state(job).lock();
        match &*state {
            State::Running(_) => return Ok(()),
            State::Failed { task, cause } => {
                return Err(ServiceTaskError::Failed {
                    job,
                    task: *task,
                    cause: *cause,
                });
            }
            State::Idle => {}
        }
        // Host code and dependencies live in the kernel image. A driver callback
        // requesting admission does not become the background task's domain.
        let task = crate::task::spawn_in_domain(
            async move {
                let result = match job {
                    Job::Maintenance => self.maintain_runtime().await.map_err(Failure::Timer),
                    Job::BlockIo => self.service_block_io().await,
                    Job::CapabilityGrants => crate::security::capability::maintain_grants().await.map_err(Failure::Timer),
                    Job::SecurityMonitor => {
                        crate::io::iommu::runtime::security::security_monitor_task()
                            .await
                            .map_err(Failure::Timer)
                    }
                    Job::IntelCommands => crate::io::iommu::vendors::intel::controller::init_global::command_queue_worker()
                        .await.map_err(Failure::Iommu),
                    Job::IntelFaults => crate::io::iommu::vendors::intel::controller::fault::fault_handler_task()
                        .await.map_err(Failure::Timer),
                    Job::AmdCommands => crate::io::iommu::vendors::amd::command_queue_worker()
                        .await
                        .map_err(Failure::Iommu),
                    Job::AmdFaults => crate::io::iommu::vendors::amd::fault_handler_task()
                        .await
                        .map_err(Failure::Iommu),
                };
                {
                    let cause = result.err().unwrap_or(Failure::Returned);
                    let mut state = self.job_state(job).lock();
                    let State::Running(task) = *state else {
                        unreachable!(
                            "service admission publishes its task before releasing the lock"
                        );
                    };
                    *state = State::Failed { task, cause };
                    log::error!(
                        "service {job:?} task={} failed with its owner retained: {cause}",
                        task.as_u64()
                    );
                }
            },
            TaskOptions::any(),
            crate::domain::DomainId::KERNEL,
        )
        .map_err(|cause| ServiceTaskError::Admission { job, cause })?;
        *state = State::Running(task);
        Ok(())
    }

    async fn service_block_io(&self) -> Result<(), Failure> {
        let coordinator = crate::io::io_scheduler::hybrid_coordinator();
        // LOOP_PROOF: mode=event; reason=The service host owns this worker, each bounded I/O turn waits for a timer and failure returns to the host.;
        loop {
            {
                let current =
                    crate::cpu::CurrentCpu::acquire().ok_or(Failure::ExecutionUnavailable)?;
                coordinator.service_turn(&current);
            }
            kernel_api::service::time::sleep_ms(1)
                .await
                .map_err(Failure::Timer)?;
        }
    }

    async fn maintain_runtime(&self) -> Result<(), TimerError> {
        // LOOP_PROOF: mode=event; reason=The service host owns this worker, each iteration waits for an admitted timer and reports timer failure to that owner.;
        loop {
            crate::integration::progress_device_retirement();
            crate::driver_domain::lifecycle::progress_startups();
            crate::driver_domain::fault::progress_restarts();
            crate::loader::live_update::poll_pending_updates();
            crate::driver_domain::hot_swap::poll_validation_windows();
            crate::io::iommu::vendors::amd::poll_firmware_event_logs();
            kernel_api::service::time::sleep_ms(10).await?;
        }
    }
}

/// Boot treats missing essential background admission as a terminal error.
/// The service host retains every already admitted task if a later admission fails.
pub(crate) fn start_runtime_maintenance() -> Result<(), ServiceTaskError> {
    for job in [Job::Maintenance, Job::BlockIo, Job::CapabilityGrants] {
        KERNEL_SERVICE_HOST.start_job(job)?;
    }
    Ok(())
}

pub(crate) fn start_security_monitor() -> Result<(), ServiceTaskError> {
    KERNEL_SERVICE_HOST.start_job(Job::SecurityMonitor)
}

/// A published backend remains retained if either admission fails. The host
/// keeps the first task's receipt and retries only a job still in Idle.
pub(crate) fn start_amd_services() -> Result<(), IommuError> {
    for job in [Job::AmdCommands, Job::AmdFaults] {
        KERNEL_SERVICE_HOST
            .start_job(job)
            .map_err(|error| match error {
                ServiceTaskError::Admission { cause, .. } => IommuError::ServiceAdmission(cause),
                ServiceTaskError::Failed {
                    cause: Failure::Iommu(cause),
                    ..
                } => cause,
                ServiceTaskError::Failed { .. } => IommuError::RuntimeUnavailable,
            })?;
    }
    Ok(())
}

pub(crate) fn start_intel_services() -> Result<(), IommuError> {
    for job in [Job::IntelCommands, Job::IntelFaults] {
        KERNEL_SERVICE_HOST
            .start_job(job)
            .map_err(|error| match error {
                ServiceTaskError::Admission { cause, .. } => IommuError::ServiceAdmission(cause),
                ServiceTaskError::Failed {
                    cause: Failure::Iommu(cause),
                    ..
                } => cause,
                ServiceTaskError::Failed { .. } => IommuError::RuntimeUnavailable,
            })?;
    }
    Ok(())
}
