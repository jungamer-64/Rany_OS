use super::*;

pub(crate) fn spawn_task(
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
) -> Result<TaskHandle, KapiError> {
    let domain_id = context::current_subject().domain.as_u64();
    let task_id =
        crate::task::spawn_detached_in_domain(future, crate::domain::DomainId::new(domain_id))
            .as_u64();
    Ok(TaskHandle::new(task_id))
}

pub(crate) fn current_tick() -> u64 {
    crate::task::current_tick()
}

pub(crate) fn current_task_id() -> u64 {
    context::current_task_id()
}
