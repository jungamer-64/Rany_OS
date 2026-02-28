use super::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use crate::domain_system::{DomainCredentials, DomainId, DomainSecurity};
use crate::security::capability::{manager, CapabilitySet, CAP_NET_BIND};
use crate::task::context::{get_current_task, set_current_task, TaskControlBlock};

fn idle_entry(_: u64) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

struct CurrentTaskGuard {
    prev: Option<*mut TaskControlBlock>,
    current: *mut TaskControlBlock,
}

impl Drop for CurrentTaskGuard {
    fn drop(&mut self) {
        let cpu_id = crate::smp::current_cpu() as usize;
        let prev_ptr = self.prev.unwrap_or(core::ptr::null_mut());
        unsafe {
            set_current_task(cpu_id, prev_ptr);
            drop(Box::from_raw(self.current));
        }
    }
}

fn set_current_subject(domain_id: DomainId) -> CurrentTaskGuard {
    let cpu_id = crate::smp::current_cpu() as usize;
    let prev = get_current_task(cpu_id);
    let mut tcb = TaskControlBlock::new(idle_entry, 0, 0, domain_id)
        .expect("failed to create test TCB");
    let caps = manager().get_capabilities(domain_id.as_u64());
    tcb.security = Arc::new(DomainSecurity {
        credentials: DomainCredentials::ROOT,
        caps,
    });
    let boxed = Box::new(tcb);
    let current = Box::into_raw(boxed);
    unsafe {
        set_current_task(cpu_id, current);
    }
    CurrentTaskGuard { prev, current }
}

#[cfg_attr(test, test_case)]
pub fn test_udp_packet() {
    let mut buffer = [0u8; 64];

    let src_ip = Ipv4Address::from_octets(192, 168, 1, 1);
    let dst_ip = Ipv4Address::from_octets(192, 168, 1, 2);

    let len =
        UdpProcessor::build_packet(&mut buffer, src_ip, 12345, dst_ip, 53, b"hello").unwrap();

    assert_eq!(len, UdpHeader::SIZE + 5);

    let packet = UdpPacket::parse(&buffer[..len]).unwrap();
    assert_eq!(packet.src_port(), 12345);
    assert_eq!(packet.dst_port(), 53);
    assert_eq!(packet.payload(), b"hello");
    assert!(packet.verify_checksum(src_ip, dst_ip));
}

#[cfg_attr(test, test_case)]
pub fn test_udp_socket_poisoned_methods_return_defaults() {
    use crate::sync::set_panicking;

    let socket = UdpSocket::new(12345);

    // Poison the inner lock
    set_panicking(true);
    if let Ok(_g) = socket.inner.lock() {
        // drop marks as poisoned
    }
    set_panicking(false);

    assert_eq!(socket.local_port(), 0);
    assert!(socket.is_closed());
    assert_eq!(socket.rx_queue_len(), 0);

    // Close should be a no-op
    socket.close();
}

#[cfg_attr(test, test_case)]
pub fn test_bind_with_token_reclaim() {
    // Setup: create caller and target domains
    let caller = DomainId::new(1);
    let target = DomainId::new(2);

    // Caller gets permission to grant CAP_NET_BIND
    manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));
    let _caller_guard = set_current_subject(caller);

    // Grant token to target
    let token = manager()
        .grant_capability_with_opts(caller.as_u64(), target.as_u64(), CAP_NET_BIND, None, false)
        .unwrap();

    // Target binds using token
    {
        let _target_guard = set_current_subject(target);
        let sock = crate::net::stack::bind_udp_with_token(40000, Some(token));
        assert!(sock.is_some());
        assert_eq!(manager().in_flight_count(token), 1);
    }

    // Issuer revokes token (mark revoked)
    assert!(manager().revoke_grant(caller.as_u64(), token, false).is_ok());

    // Immediate reclaim should fail (in-flight)
    match manager().reclaim_token(token) {
        Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
        other => panic!("expected ReclamationBusy, got {:?}", other),
    }

    // Now unbind the socket (target releases resource)
    {
        let _target_guard = set_current_subject(target);
        crate::net::stack::unbind_udp(40000);
    }

    assert_eq!(manager().in_flight_count(token), 0);
    // Now reclaim should succeed
    assert!(manager().reclaim_token(token).is_ok());
}

#[cfg_attr(test, test_case)]
pub fn test_udp_recv_future_poisoned_returns_closed() {
    use crate::sync::set_panicking;
    use core::task::{RawWaker, RawWakerVTable, Waker, Context};
    use core::pin::Pin;
    use core::task::Poll;
    use core::ptr;

    fn noop_raw_waker() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker { noop_raw_waker() }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        RawWaker::new(ptr::null(), &RawWakerVTable::new(clone, wake, wake_by_ref, drop))
    }

    fn noop_waker() -> Waker { unsafe { Waker::from_raw(noop_raw_waker()) } }

    let socket = UdpSocket::new(54321);

    // Poison the inner lock
    set_panicking(true);
    if let Ok(_g) = socket.inner.lock() {
        // drop marks as poisoned
    }
    set_panicking(false);

    let mut fut = socket.recv();
    let w = noop_waker();
    let mut cx = Context::from_waker(&w);

    assert!(matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Ready(None)));
}

#[cfg_attr(test, test_case)]
pub fn test_udp_processor_poisoned_bind_and_process() {
    use crate::sync::set_panicking;

    let proc = UdpProcessor::new();

    // Poison the socket table lock
    set_panicking(true);
    if let Ok(_g) = proc.sockets.sockets.lock() {
        // drop marks as poisoned
    }
    set_panicking(false);

    // Bind should fail (token-aware API returns Err on failure)
    assert!(proc.bind_with_token(10000, None).is_err());

    // Build a packet and process - should be NoSocket and stats increment rx_dropped
    let src_ip = Ipv4Address::from_octets(1, 2, 3, 4);
    let dst_ip = Ipv4Address::from_octets(1, 2, 3, 4);
    let mut buffer = [0u8; 64];
    let len = UdpProcessor::build_packet(&mut buffer, src_ip, 1234, dst_ip, 10000, b"x").unwrap();

    let res = proc.process(&buffer[..len], src_ip, dst_ip);
    assert_eq!(res, UdpResult::NoSocket);

    let stats = proc.sockets.stats();
    assert_eq!(stats.2, 1); // rx_dropped == 1
}

#[cfg_attr(test, test_case)]
pub fn test_udp_socket_multiple_waiters_woken_on_deliver() {
    use core::pin::Pin;
    use core::ptr::addr_of_mut;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    static mut WAITERS_TEST_PACKET: [u8; 3] = [0; 3];

    fn counting_waker(counter: &AtomicUsize) -> Waker {
        unsafe fn clone(data: *const ()) -> RawWaker {
            RawWaker::new(data, &VTABLE)
        }
        unsafe fn wake(data: *const ()) {
            let counter = &*(data as *const AtomicUsize);
            counter.fetch_add(1, Ordering::SeqCst);
        }
        unsafe fn wake_by_ref(data: *const ()) {
            wake(data);
        }
        unsafe fn drop_waker(_: *const ()) {}

        static VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);

        unsafe { Waker::from_raw(RawWaker::new(counter as *const _ as *const (), &VTABLE)) }
    }

    let socket = UdpSocket::new(54322);
    let mut fut1 = socket.recv();
    let mut fut2 = socket.recv();

    let wake_count = AtomicUsize::new(0);
    let waker = counting_waker(&wake_count);
    let mut cx = Context::from_waker(&waker);

    assert!(matches!(Pin::new(&mut fut1).poll(&mut cx), Poll::Pending));
    assert!(matches!(Pin::new(&mut fut2).poll(&mut cx), Poll::Pending));

    let mut packet = unsafe {
        crate::net::mempool::PacketRef::from_static_raw_for_tests(
            addr_of_mut!(WAITERS_TEST_PACKET) as *mut u8,
            3,
        )
        .expect("static test packet")
    };
    packet.set_len(3);
    packet.data_mut().copy_from_slice(b"abc");

    let src = UdpAddr::new(Ipv4Address::from_octets(1, 2, 3, 4), 9999);
    socket.deliver(src, packet);

    assert_eq!(wake_count.load(Ordering::SeqCst), 2);

    match Pin::new(&mut fut1).poll(&mut cx) {
        Poll::Ready(Some((addr, packet))) => {
            assert_eq!(addr, src);
            assert_eq!(packet.data(), b"abc");
        }
        _ => panic!("expected ready packet after wake"),
    }

    assert!(matches!(Pin::new(&mut fut2).poll(&mut cx), Poll::Pending));
}

#[cfg_attr(test, test_case)]
pub fn test_udp_processor_process_enqueues_zero_copy_packet() {
    use core::pin::Pin;
    use core::ptr;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(ptr::null(), &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop_waker(_: *const ()) {}

        static VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);

        unsafe { Waker::from_raw(RawWaker::new(ptr::null(), &VTABLE)) }
    }

    let proc = UdpProcessor::new();
    let socket = proc
        .bind_with_token(10000, None)
        .expect("bind udp socket for zero-copy enqueue test");

    let src_ip = Ipv4Address::from_octets(10, 0, 0, 1);
    let dst_ip = Ipv4Address::from_octets(10, 0, 0, 2);
    let payload = b"zc";
    let mut buf = [0u8; 64];
    let len = UdpProcessor::build_packet(&mut buf, src_ip, 1234, dst_ip, 10000, payload).unwrap();

    #[cfg(feature = "qemu-test-export")]
    {
        use core::ptr::addr_of_mut;

        // QEMU required suite runs without a reliable exchange-heap setup for
        // mempool growth, so validate the parse+deliver zero-copy path with a
        // static packet buffer instead of `process()`'s internal allocation.
        // Force UDP checksum to 0 ("no checksum") so this smoke stays focused
        // on enqueue/recv behavior; checksum coverage lives in udp packet tests.
        buf[6] = 0;
        buf[7] = 0;
        static mut UDP_PROCESS_TEST_PACKET: [u8; 2] = [0; 2];
        let mut packet = unsafe {
            crate::net::mempool::PacketRef::from_static_raw_for_tests(
                addr_of_mut!(UDP_PROCESS_TEST_PACKET) as *mut u8,
                payload.len(),
            )
            .expect("create static packet for udp zero-copy enqueue test")
        };
        packet.set_len(payload.len());
        packet.data_mut().copy_from_slice(payload);

        assert_eq!(
            proc.process_with_packet(&buf[..len], src_ip, dst_ip, packet),
            UdpResult::Delivered
        );
    }
    #[cfg(not(feature = "qemu-test-export"))]
    {
        match crate::net::mempool::net_mempool() {
            None => crate::net::mempool::init_net_mempool(4)
                .expect("initialize mempool for udp zero-copy enqueue test"),
            Some(pool) if pool.stats().free_buffers == 0 => crate::net::mempool::init_net_mempool(1)
                .expect("top up mempool for udp zero-copy enqueue test"),
            Some(_) => {}
        }

        assert_eq!(proc.process(&buf[..len], src_ip, dst_ip), UdpResult::Delivered);
    }

    let mut fut = socket.recv();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    match Pin::new(&mut fut).poll(&mut cx) {
        Poll::Ready(Some((addr, packet))) => {
            assert_eq!(addr, UdpAddr::new(src_ip, 1234));
            assert_eq!(packet.data(), payload);
        }
        _ => panic!("expected delivered packet"),
    }
}
