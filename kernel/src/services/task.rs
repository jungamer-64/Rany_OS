use super::*;

pub(super) fn spawn_task(
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
) -> Result<TaskHandle, KapiError> {
    let task_id = crate::task::spawn(future, crate::task::TaskPlacement::Any)
        .map_err(|_| KapiError::ResourceExhausted)?
        .as_u64();
    Ok(TaskHandle::new(task_id))
}

pub(super) fn current_tick() -> u64 {
    crate::task::current_tick()
}

pub(super) fn current_task_id() -> u64 {
    super::current_task_id()
}
