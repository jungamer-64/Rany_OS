use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_priority_ordering() {
    assert!(ShrinkerPriority::Lowest < ShrinkerPriority::Low);
    assert!(ShrinkerPriority::Low < ShrinkerPriority::Normal);
    assert!(ShrinkerPriority::Normal < ShrinkerPriority::High);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_pressure_levels() {
    assert!(MemoryPressureLevel::None < MemoryPressureLevel::Low);
    assert!(MemoryPressureLevel::High < MemoryPressureLevel::Critical);
}
