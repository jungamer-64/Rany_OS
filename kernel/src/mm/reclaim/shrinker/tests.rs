use super::*;

#[test_case]
fn test_priority_ordering() {
    assert!(ShrinkerPriority::Lowest < ShrinkerPriority::Low);
    assert!(ShrinkerPriority::Low < ShrinkerPriority::Normal);
    assert!(ShrinkerPriority::Normal < ShrinkerPriority::High);
}

#[test_case]
fn test_pressure_levels() {
    assert!(MemoryPressureLevel::None < MemoryPressureLevel::Low);
    assert!(MemoryPressureLevel::High < MemoryPressureLevel::Critical);
}
