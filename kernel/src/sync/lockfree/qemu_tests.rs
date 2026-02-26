use super::*;

pub fn spsc_basic_smoke() -> bool {
    let rb: SpscRingBuffer<u32, 8> = SpscRingBuffer::new();

    if !rb.is_empty() { return false; }
    if rb.is_full() { return false; }

    for i in 0..7u32 {
        if rb.push(i).is_err() { return false; }
    }

    if !rb.is_full() { return false; }
    if rb.push(100).is_ok() { return false; }

    for i in 0..7u32 {
        if rb.pop() != Some(i) { return false; }
    }

    rb.is_empty() && rb.pop().is_none()
}

pub fn mpsc_basic_smoke() -> bool {
    let rb: MpscRingBuffer<u32, 8> = MpscRingBuffer::new();

    if !rb.is_empty() { return false; }

    if rb.push(1).is_err() { return false; }
    if rb.push(2).is_err() { return false; }
    if rb.push(3).is_err() { return false; }

    if rb.len() != 3 { return false; }

    rb.pop() == Some(1)
        && rb.pop() == Some(2)
        && rb.pop() == Some(3)
        && rb.pop().is_none()
}

pub fn mpmc_basic_smoke() -> bool {
    let rb: MpmcRingBuffer<u32, 8> = MpmcRingBuffer::new();

    if !rb.is_empty() { return false; }

    if rb.push(1).is_err() { return false; }
    if rb.push(2).is_err() { return false; }
    if rb.push(3).is_err() { return false; }

    if rb.len() != 3 { return false; }

    rb.pop() == Some(1)
        && rb.pop() == Some(2)
        && rb.pop() == Some(3)
        && rb.pop().is_none()
}

pub fn mpmc_try_operations_smoke() -> bool {
    let rb: MpmcRingBuffer<u32, 4> = MpmcRingBuffer::new();

    if rb.try_push(1).is_err() { return false; }
    if rb.try_push(2).is_err() { return false; }
    if rb.try_push(3).is_err() { return false; }
    if rb.try_push(4).is_err() { return false; }

    // Full
    if rb.try_push(5).is_ok() { return false; }

    if rb.try_pop() != Some(1) { return false; }
    if rb.try_pop() != Some(2) { return false; }

    rb.try_push(5).is_ok()
}

pub fn lock_free_index_stack_smoke() -> bool {
    let stack = LockFreeIndexStack::new_empty(4);

    if stack.capacity() != 4 { return false; }
    if !stack.is_empty() { return false; }
    if stack.len() != 0 { return false; }
    if stack.pop().is_some() { return false; }

    if stack.push(0).is_err() { return false; }
    if stack.push(2).is_err() { return false; }
    if stack.push(0) != Err(LockFreeIndexStackPushError::AlreadyPresent) { return false; }
    if stack.push(4) != Err(LockFreeIndexStackPushError::OutOfRange) { return false; }

    if stack.len() != 2 { return false; }
    if stack.pop() != Some(2) { return false; }
    if stack.pop() != Some(0) { return false; }
    if stack.push(0).is_err() { return false; }
    if stack.pop() != Some(0) { return false; }
    if stack.pop().is_some() { return false; }

    stack.is_empty()
}

pub fn backoff_smoke() -> bool {
    let mut backoff = Backoff::new();

    if backoff.is_completed() { return false; }

    for _ in 0..12 {
        backoff.spin();
    }

    if !backoff.is_completed() { return false; }

    backoff.reset();
    !backoff.is_completed()
}

pub fn seqlock_smoke() -> bool {
    let lock: Seqlock<u64> = Seqlock::new(0);

    if lock.read() != 0 { return false; }

    lock.write(42);
    if lock.read() != 42 { return false; }

    {
        let mut guard = lock.write_guard();
        *guard = 100;
    }

    lock.read() == 100
}

pub fn bounded_channel_static_smoke() -> bool {
    static BUF: MpscRingBuffer<u64, 8> = MpscRingBuffer::new();
    let (tx, rx) = BoundedChannel::from_static(&BUF);

    if tx.send(1u64).is_err() { return false; }
    if rx.recv() != Some(1u64) { return false; }

    let cap = BUF.capacity();
    for i in 0..cap {
        if tx.send(i as u64).is_err() { return false; }
    }

    // Full
    if tx.send(99u64).is_ok() { return false; }

    for i in 0..cap {
        if rx.recv() != Some(i as u64) { return false; }
    }

    rx.recv().is_none()
}

pub fn bounded_channel_new_leak_smoke() -> bool {
    let (tx, rx) = BoundedChannel::<u32, 8>::new();
    if tx.send(42u32).is_err() { return false; }
    rx.recv() == Some(42u32)
}
