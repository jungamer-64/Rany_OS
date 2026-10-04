//! The service host owns one consumer per runtime/CPU resource queue. Consumers
//! may move at poll boundaries; closing admission drains accepted commands and
//! returns the task slot before the CPU can be retired.

use crate::cpu::CpuId;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::context::{NetCpuResourceError, NetCpuResources, NetRuntimeId};
use alloc::sync::Arc;
use kernel_api::resource::task::{SpawnError, TaskId, TaskOptions};

use super::host::{KERNEL_SERVICE_HOST, KernelServiceHost};

#[derive(Debug)]
pub(crate) enum NetworkServiceError {
    Resources(NetCpuResourceError),
    Admission(SpawnError),
    Draining { task: TaskId },
}

impl core::fmt::Display for NetworkServiceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Resources(cause) => write!(formatter, "CPU resources: {cause:?}"),
            Self::Admission(cause) => write!(formatter, "{cause}"),
            Self::Draining { task } => {
                write!(formatter, "consumer task {} is draining", task.as_u64())
            }
        }
    }
}

pub(super) struct Consumer {
    key: (NetRuntimeId, CpuId),
    task: TaskId,
}

impl KernelServiceHost {
    fn start_network_commands(
        &'static self,
        runtime: NetRuntimeHandle,
        resources: Arc<NetCpuResources>,
    ) -> Result<(), NetworkServiceError> {
        let key = (runtime.id(), resources.cpu_id);
        let mut consumers = self.network_consumers.lock();
        if let Some(consumer) = consumers.iter().find(|consumer| consumer.key == key) {
            return if resources.command_queue.is_accepting() {
                Ok(())
            } else {
                Err(NetworkServiceError::Draining {
                    task: consumer.task,
                })
            };
        }
        // Reserve the owner's receipt before publishing a scheduler task.
        consumers
            .try_reserve(1)
            .map_err(|_| NetworkServiceError::Admission(SpawnError::PhysicalMemoryExhausted))?;
        let task_resources = Arc::clone(&resources);
        let task = crate::task::spawn_in_domain(
            async move {
                // Admission publishes the receipt and opens the queue before
                // this worker can begin on another CPU.
                {
                    let consumers = self.network_consumers.lock();
                    assert!(consumers.iter().any(|consumer| consumer.key == key));
                }
                // LOOP_PROOF: mode=event; reason=Each consumer waits for commands or closed admission, and a drain rollback restarts it only after reopening that queue.;
                loop {
                    crate::net::runtime::command_loop::runtime_command_task_in(
                        runtime,
                        Arc::clone(&task_resources),
                    )
                    .await;
                    let mut consumers = self.network_consumers.lock();
                    if task_resources.command_queue.is_accepting() {
                        continue;
                    }
                    let slot = consumers
                        .iter()
                        .position(|consumer| consumer.key == key)
                        .expect("consumer completion must retain its admission receipt");
                    consumers.swap_remove(slot);
                    return;
                }
            },
            TaskOptions::prefer_cpu(resources.cpu_id),
            crate::domain::DomainId::KERNEL,
        )
        .map_err(NetworkServiceError::Admission)?;
        consumers.push(Consumer { key, task });
        resources.command_queue.publish_online();
        Ok(())
    }
}

pub(crate) fn start_network_commands(
    runtime: NetRuntimeHandle,
    cpu: CpuId,
) -> Result<(), NetworkServiceError> {
    let resources = runtime
        .context()
        .cpu_resources(cpu)
        .map_err(NetworkServiceError::Resources)?;
    KERNEL_SERVICE_HOST.start_network_commands(runtime, resources)
}

pub(crate) fn network_consumer_active(runtime: NetRuntimeId, cpu: CpuId) -> bool {
    KERNEL_SERVICE_HOST
        .network_consumers
        .lock()
        .iter()
        .any(|consumer| consumer.key == (runtime, cpu))
}
