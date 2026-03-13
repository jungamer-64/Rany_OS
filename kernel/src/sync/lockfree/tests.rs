use super::*;
use alloc::vec::Vec;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_spsc_basic() {
    let rb: SpscRingBuffer<u32, 8> = SpscRingBuffer::new();

    assert!(rb.is_empty());
    assert!(!rb.is_full());

    // Push some values
    for i in 0..7 {
        assert!(rb.push(i).is_ok());
    }

    // Buffer should be full now
    assert!(rb.is_full());
    assert!(rb.push(100).is_err());

    // Pop values
    for i in 0..7 {
        assert_eq!(rb.pop(), Some(i));
    }

    assert!(rb.is_empty());
    assert_eq!(rb.pop(), None);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mpsc_basic() {
    let rb: MpscRingBuffer<u32, 8> = MpscRingBuffer::new();

    assert!(rb.is_empty());

    assert!(rb.push(1).is_ok());
    assert!(rb.push(2).is_ok());
    assert!(rb.push(3).is_ok());

    assert_eq!(rb.len(), 3);

    assert_eq!(rb.pop(), Some(1));
    assert_eq!(rb.pop(), Some(2));
    assert_eq!(rb.pop(), Some(3));
    assert_eq!(rb.pop(), None);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mpsc_try_push_success_and_full() {
    let rb: MpscRingBuffer<u32, 4> = MpscRingBuffer::new();

    assert!(rb.try_push(1).is_ok());
    assert!(rb.try_push(2).is_ok());
    assert!(rb.try_push(3).is_ok());
    assert!(rb.try_push(4).is_err());

    assert_eq!(rb.pop(), Some(1));
    assert_eq!(rb.pop(), Some(2));
    assert_eq!(rb.pop(), Some(3));
    assert_eq!(rb.pop(), None);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mpmc_basic() {
    let rb: MpmcRingBuffer<u32, 8> = MpmcRingBuffer::new();

    assert!(rb.is_empty());

    // Push values
    assert!(rb.push(1).is_ok());
    assert!(rb.push(2).is_ok());
    assert!(rb.push(3).is_ok());

    assert_eq!(rb.len(), 3);

    // Pop values
    assert_eq!(rb.pop(), Some(1));
    assert_eq!(rb.pop(), Some(2));
    assert_eq!(rb.pop(), Some(3));
    assert_eq!(rb.pop(), None);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mpmc_try_operations() {
    let rb: MpmcRingBuffer<u32, 4> = MpmcRingBuffer::new();

    // try_push
    assert!(rb.try_push(1).is_ok());
    assert!(rb.try_push(2).is_ok());
    assert!(rb.try_push(3).is_ok());
    assert!(rb.try_push(4).is_ok());

    // Buffer should be full
    assert!(rb.try_push(5).is_err());

    // try_pop
    assert_eq!(rb.try_pop(), Some(1));
    assert_eq!(rb.try_pop(), Some(2));

    // Can push again
    assert!(rb.try_push(5).is_ok());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mpmc_static_initialization() {
    static RB: MpmcRingBuffer<u64, 8> = MpmcRingBuffer::new();

    while RB.pop().is_some() {}

    assert!(RB.push(11).is_ok());
    assert!(RB.push(22).is_ok());
    assert_eq!(RB.pop(), Some(11));
    assert_eq!(RB.pop(), Some(22));
    assert_eq!(RB.pop(), None);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_lock_free_index_stack_basic() {
    let stack = LockFreeIndexStack::new_empty(4);

    assert_eq!(stack.capacity(), 4);
    assert_eq!(stack.len(), 0);
    assert!(stack.is_empty());
    assert_eq!(stack.pop(), None);

    assert_eq!(stack.push(1), Ok(()));
    assert_eq!(stack.push(3), Ok(()));
    assert_eq!(stack.len(), 2);
    assert!(!stack.is_empty());

    assert_eq!(stack.pop(), Some(3));
    assert_eq!(stack.pop(), Some(1));
    assert_eq!(stack.pop(), None);
    assert!(stack.is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_lock_free_index_stack_new_filled_drains_unique() {
    let cap = 8;
    let stack = LockFreeIndexStack::new_filled(cap);
    assert_eq!(stack.capacity(), cap);
    assert_eq!(stack.len(), cap);

    let mut seen = [false; 8];
    let mut popped = Vec::new();
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while let Some(idx) = stack.pop() {
        popped.push(idx);
        seen[idx as usize] = true;
    }

    assert_eq!(popped.len(), cap);
    assert!(seen.into_iter().all(|v| v));
    assert_eq!(stack.len(), 0);
    assert!(stack.is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_lock_free_index_stack_push_out_of_range() {
    let stack = LockFreeIndexStack::new_empty(2);
    assert_eq!(stack.push(2), Err(LockFreeIndexStackPushError::OutOfRange));
    assert_eq!(stack.len(), 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_lock_free_index_stack_push_duplicate_returns_already_present() {
    let stack = LockFreeIndexStack::new_empty(4);

    assert_eq!(stack.push(1), Ok(()));
    assert_eq!(
        stack.push(1),
        Err(LockFreeIndexStackPushError::AlreadyPresent)
    );
    assert_eq!(stack.len(), 1);
    assert_eq!(stack.pop(), Some(1));
    assert_eq!(stack.pop(), None);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_lock_free_index_stack_pop_then_repush_succeeds() {
    let stack = LockFreeIndexStack::new_empty(4);

    assert_eq!(stack.push(2), Ok(()));
    assert_eq!(stack.pop(), Some(2));
    assert_eq!(stack.push(2), Ok(()));
    assert_eq!(stack.pop(), Some(2));
    assert!(stack.is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_backoff() {
    let mut backoff = Backoff::new();

    assert!(!backoff.is_completed());

    // Spin several times
    for _ in 0..12 {
        backoff.spin();
    }

    assert!(backoff.is_completed());

    // Reset
    backoff.reset();
    assert!(!backoff.is_completed());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_seqlock() {
    let lock: Seqlock<u64> = Seqlock::new(0);

    assert_eq!(lock.read(), 0);

    lock.write(42);
    assert_eq!(lock.read(), 42);

    {
        let mut guard = lock.write_guard();
        *guard = 100;
    }

    assert_eq!(lock.read(), 100);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_bounded_channel_static() {
    static BUF: MpscRingBuffer<u64, 8> = MpscRingBuffer::new();
    let (tx, rx) = BoundedChannel::from_static(&BUF);

    assert!(tx.send(1u64).is_ok());
    assert_eq!(rx.recv(), Some(1u64));

    // Fill up to capacity (N-1)
    for i in 0..BUF.capacity() {
        assert!(tx.send(i as u64).is_ok());
    }

    // Now it should be full
    assert!(tx.send(99u64).is_err());

    for i in 0..BUF.capacity() {
        assert_eq!(rx.recv(), Some(i as u64));
    }

    assert!(rx.recv().is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_bounded_channel_new_leak() {
    let (tx, rx) = BoundedChannel::<u32, 8>::new();
    assert!(tx.send(42u32).is_ok());
    assert_eq!(rx.recv(), Some(42u32));
}
