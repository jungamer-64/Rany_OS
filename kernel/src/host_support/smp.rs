pub fn current_cpu() -> u32 {
    0
}
pub fn cpu_count() -> usize {
    1
}
pub fn cpu_index() -> usize {
    0
}
pub fn try_current_cpu_id() -> Option<u32> {
    Some(0)
}
pub fn apic_id_for_cpu(cpu_id: usize) -> Option<u32> {
    Some(cpu_id as u32)
}
pub fn cpu_for_apic_id(apic_id: u32) -> Option<usize> {
    Some(apic_id as usize)
}
pub fn runtime_workers_released() -> bool {
    false
}
pub fn release_runtime_workers() {}
pub fn wait_for_runtime_workers() {}
pub fn register_cpu_apic_mapping(_cpu_id: usize, _apic_id: u32) {}
pub fn reset_cpu_routing_for_tests() {}
pub fn reset_runtime_workers_for_tests() {}
