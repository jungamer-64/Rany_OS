// ============================================================================
// kernel/src/net/l4/test_support.rs - L4 / test support
// ============================================================================

use crate::domain::DomainId;
use crate::net::datapath::mempool::PacketRef;
use crate::task::context::{TaskControlBlock, get_current_task, set_current_task};
use alloc::boxed::Box;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{RawWaker, RawWakerVTable, Waker};

unsafe fn noop_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &NOOP_WAKER_VTABLE)
}

unsafe fn noop_wake(_: *const ()) {}

unsafe fn noop_wake_by_ref(_: *const ()) {}

unsafe fn noop_drop(_: *const ()) {}

static NOOP_WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(noop_clone, noop_wake, noop_wake_by_ref, noop_drop);

unsafe fn counting_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &COUNTING_WAKER_VTABLE)
}

unsafe fn counting_wake(data: *const ()) {
    let counter = unsafe { &*(data as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::SeqCst);
}

unsafe fn counting_wake_by_ref(data: *const ()) {
    let counter = unsafe { &*(data as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::SeqCst);
}

unsafe fn counting_drop(_: *const ()) {}

static COUNTING_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    counting_clone,
    counting_wake,
    counting_wake_by_ref,
    counting_drop,
);

pub(crate) fn noop_waker() -> Waker {
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &NOOP_WAKER_VTABLE)) }
}

pub(crate) fn counting_waker(counter: &'static AtomicUsize) -> Waker {
    unsafe {
        Waker::from_raw(RawWaker::new(
            counter as *const AtomicUsize as *const (),
            &COUNTING_WAKER_VTABLE,
        ))
    }
}

fn idle_entry(_: u64) -> ! {
    // LOOP_PROOF: mode=halt; reason=Idle test entry intentionally spins forever because the harness never returns from the parked CPU stub.
    loop {
        core::hint::spin_loop();
    }
}

pub(crate) struct CurrentTaskGuard {
    prev: Option<NonNull<TaskControlBlock>>,
    current: NonNull<TaskControlBlock>,
}

impl Drop for CurrentTaskGuard {
    fn drop(&mut self) {
        let cpu_id = crate::cpu::current_id();
        let prev_ptr = self.prev.map_or(core::ptr::null_mut(), NonNull::as_ptr);
        // SAFETY: `prev_ptr` was read from the per-CPU slot and `current` was allocated
        // by `Box::into_raw` in `set_current_subject`, so both pointers remain valid here.
        unsafe {
            set_current_task(cpu_id, prev_ptr);
            drop(Box::from_raw(self.current.as_ptr()));
        }
    }
}

pub(crate) fn set_current_subject(domain_id: DomainId) -> CurrentTaskGuard {
    let cpu_id = crate::cpu::current_id();
    let prev = get_current_task(cpu_id).and_then(NonNull::new);
    let mut tcb =
        TaskControlBlock::new(idle_entry, 0, 0, domain_id).expect("failed to create test TCB");
    tcb.security = crate::domain::domain_security_handle(domain_id);
    let current = NonNull::from(Box::leak(Box::new(tcb)));
    // SAFETY: `current` points to a leaked `TaskControlBlock` that stays valid until the guard drops.
    unsafe {
        set_current_task(cpu_id, current.as_ptr());
    }
    CurrentTaskGuard { prev, current }
}

pub(crate) fn leaked_test_packet(cap: usize) -> PacketRef {
    assert!(cap > 0, "test packet capacity must be non-zero");
    let backing = Box::leak(alloc::vec![0u8; cap].into_boxed_slice());
    // SAFETY: `backing` is intentionally leaked for the duration of the test process,
    // so the raw pointer remains valid for any borrowed `PacketRef` created from it.
    unsafe {
        crate::net::datapath::mempool::packet_ref_from_static_raw_for_tests(
            backing.as_mut_ptr(),
            backing.len(),
        )
        .expect("create leaked test packet")
    }
}

pub(crate) fn leaked_test_packet_with_data(data: &[u8]) -> PacketRef {
    let cap = data.len().max(1);
    let mut packet = leaked_test_packet(cap);
    packet.set_len(data.len());
    packet.data_mut()[..data.len()].copy_from_slice(data);
    packet
}
