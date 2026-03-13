use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_io_priority_ordering() {
    assert!(IoPriority::Realtime > IoPriority::High);
    assert!(IoPriority::High > IoPriority::Normal);
    assert!(IoPriority::Normal > IoPriority::Idle);
    assert!(IoPriority::Idle > IoPriority::Background);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_io_mode_stats() {
    let stats = IoModeStats::new();
    stats.record_io(100);
    stats.record_io(200);
    stats.record_io(50);

    assert_eq!(stats.total_count(), 3);
    assert_eq!(stats.avg_latency_us(), 116); // (100+200+50)/3
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_scheduler_submit() {
    let scheduler = IoScheduler::new();
    let device = DeviceId::Nvme {
        controller: 0,
        namespace: 1,
    };

    let id = scheduler.submit(device, IoOperationType::Read, IoPriority::Normal);
    assert_eq!(scheduler.get_state(id), Some(IoState::Pending));

    scheduler.complete_request(id, IoResult::Success(512));
    assert_eq!(scheduler.get_state(id), Some(IoState::Completed));
}
