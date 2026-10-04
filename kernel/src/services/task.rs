use super::*;

pub(super) fn spawn(
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
    options: TaskOptions,
) -> Result<TaskId, SpawnError> {
    crate::task::spawn(future, options)
}

pub(super) fn current_tick() -> u64 {
    crate::task::current_tick()
}

pub(super) fn current_task_id() -> u64 {
    super::current_task_id()
}
