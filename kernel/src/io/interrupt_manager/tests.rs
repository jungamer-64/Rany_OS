use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_msi_allocation() {
    let manager = InterruptManager::new();
    manager.init();

    let result = manager.allocate_msi_vector(
        0x0100, // BDF
        "test_device".into(),
        Some(0),
    );

    assert!(result.is_ok());
    let alloc = result.unwrap();
    assert!(alloc.vector >= MSI_VECTORS_START);
    assert!(alloc.vector <= MSI_VECTORS_END);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_gsi_allocation() {
    let manager = InterruptManager::new();
    manager.init();

    let result = manager.allocate_gsi_vector(
        1, // IRQ 1 (keyboard)
        "keyboard".into(),
        TriggerMode::Edge,
        Polarity::ActiveHigh,
    );

    assert!(result.is_ok());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_vector_free() {
    let manager = InterruptManager::new();
    manager.init();

    let alloc = manager
        .allocate_msi_vector(0x0100, "test".into(), None)
        .unwrap();

    let vector = alloc.vector;
    manager.free_vector(vector);

    // 同じベクタを再割り当てできるはず
    let alloc2 = manager
        .allocate_msi_vector(0x0200, "test2".into(), None)
        .unwrap();

    // 空いているベクタが割り当てられる
    assert!(alloc2.vector >= MSI_VECTORS_START);
}

// ========================================================================
// InterruptQueue Tests (設計書 4.2: ロックフリーキュー)
// ========================================================================

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_interrupt_queue_push_pop() {
    let queue = InterruptQueue::new();

    // Push some vectors
    assert!(queue.push(32)); // Timer
    assert!(queue.push(33)); // Keyboard

    // Pop in FIFO order
    assert_eq!(queue.pop(), Some(32));
    assert_eq!(queue.pop(), Some(33));

    // Empty
    assert_eq!(queue.pop(), None);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_interrupt_queue_empty() {
    let queue = InterruptQueue::new();

    assert!(queue.is_empty());
    assert_eq!(queue.capacity(), InterruptQueue::CAPACITY);
    assert_eq!(queue.len(), 0);

    queue.push(32);
    assert!(!queue.is_empty());
    assert_eq!(queue.len(), 1);

    queue.pop();
    assert!(queue.is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_interrupt_queue_full() {
    let queue = InterruptQueue::new();

    // Fill the queue (all 1024 slots are usable)
    for i in 0..InterruptQueue::CAPACITY {
        assert!(queue.push(i as u8), "Failed at {}", i);
    }

    // Should reject when full
    assert!(!queue.push(255));
    assert_eq!(queue.len(), InterruptQueue::CAPACITY);
    assert_eq!(queue.capacity(), InterruptQueue::CAPACITY);
}

// ========================================================================
// WakerRegistry Tests (設計書 4.2: Waker管理)
// ========================================================================

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_waker_registry_register_count() {
    let registry = WakerRegistry::new();

    assert_eq!(registry.count(), 0);

    // We can't easily create real Wakers in tests without an executor,
    // so we just test the count functionality
}
