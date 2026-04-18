use crate::domain::{DomainCredentials, DomainId, DomainSecurity};
use crate::net::datapath::mempool::PacketRef;
use crate::net::l4::socket::Endpoint;
use crate::net::l4::types::{EndpointState, EndpointType};
use crate::net::l4::tcp::TcpConnection;
use crate::net::runtime::default_runtime;
use crate::security::capability::manager;
use crate::task::context::{TaskControlBlock, get_current_task, set_current_task};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::Waker;

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

struct CounterWake {
    counter: &'static AtomicUsize,
}

impl Wake for CounterWake {
    fn wake(self: Arc<Self>) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }
}

struct SharedCounterWake {
    counter: Arc<AtomicUsize>,
}

impl Wake for SharedCounterWake {
    fn wake(self: Arc<Self>) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }
}

pub(crate) fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWake))
}

pub(crate) fn counting_waker(counter: &'static AtomicUsize) -> Waker {
    Waker::from(Arc::new(CounterWake { counter }))
}

pub(crate) fn shared_counting_waker(counter: Arc<AtomicUsize>) -> Waker {
    Waker::from(Arc::new(SharedCounterWake { counter }))
}

pub(crate) fn new_test_endpoint(endpoint_type: EndpointType) -> Endpoint {
    Endpoint::new_registered_in(endpoint_type, default_runtime())
}

pub(crate) fn tcp_connection_from_endpoint(endpoint: &Endpoint) -> Option<TcpConnection> {
    (endpoint.socket_type() == EndpointType::Tcp && endpoint.state() == EndpointState::Connected)
        .then(|| TcpConnection::from_retained_endpoint(endpoint.clone()))
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
    let caps = manager().get_capabilities(domain_id.as_u64());
    tcb.security = Arc::new(DomainSecurity {
        credentials: DomainCredentials::ROOT,
        caps,
    });
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
