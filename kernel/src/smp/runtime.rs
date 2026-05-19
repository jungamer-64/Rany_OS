pub(crate) fn reset_runtime_state() {
    crate::smp::lifecycle::reset_state();
}

#[cfg(test)]
pub(crate) fn reset_runtime_workers_for_tests() {
    reset_runtime_state();
}
