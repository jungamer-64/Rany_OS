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

#[test_case]
fn test_udp_packet() {
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

#[test_case]
fn test_udp_socket_poisoned_methods_return_defaults() {
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

#[test_case]
fn test_bind_with_token_reclaim() {
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

#[test_case]
fn test_udp_recv_future_poisoned_returns_closed() {
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

    assert_eq!(Pin::new(&mut fut).poll(&mut cx), Poll::Ready(None));
}

#[test_case]
fn test_udp_processor_poisoned_bind_and_process() {
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
