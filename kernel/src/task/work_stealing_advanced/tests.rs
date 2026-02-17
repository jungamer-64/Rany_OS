use super::*;

#[test_case]
fn test_core_affinity() {
    let all = CoreAffinity::all();
    assert!(all.is_allowed(0));
    assert!(all.is_allowed(63));

    let single = CoreAffinity::single(5);
    assert!(single.is_allowed(5));
    assert!(!single.is_allowed(0));
    assert_eq!(single.preferred_core(), Some(5));
}

#[test_case]
fn test_priority_ordering() {
    assert!(Priority::RealTime > Priority::High);
    assert!(Priority::High > Priority::Normal);
    assert!(Priority::Normal > Priority::Low);
    assert!(Priority::Low > Priority::Idle);
}

#[test_case]
fn test_deque_operations() {
    let mut deque = WorkStealingDeque::new(16);
    assert!(deque.is_empty());

    let task = Box::new(StealableTask::new(TaskId(1), Priority::Normal));
    assert!(unsafe { deque.push(task) }.is_ok());
    assert_eq!(deque.len(), 1);

    let popped = unsafe { deque.pop() };
    assert!(popped.is_some());
    assert!(deque.is_empty());
}
