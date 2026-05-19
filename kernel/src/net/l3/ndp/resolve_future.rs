// ============================================================================
// kernel/src/net/l3/ndp/resolve_future.rs - 非同期NDP解決Future
// ============================================================================
//! # 非同期NDP解決Future
//!
//! NDP Neighbor Solicitation をイベントキュー経由で送信し、
//! Neighbor Advertisement 受信時の解決完了をWakerベースで待機する。

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use super::Ipv6Address;
use crate::net::l2::ethernet::MacAddress;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::try_enqueue_command_in;
use crate::sync::{AtomicWaker, PoisonLock};

// ============================================================================
// NDP Resolve Waiter Registry
// ============================================================================

struct NdpWaiter {
    id: u64,
    if_id: Option<u16>,
    ip: [u8; 16],
    result: Option<MacAddress>,
    waker: AtomicWaker,
    created_at_ms: u64,
    completed_at_ms: Option<u64>,
}

const NDP_WAITER_CAPACITY: usize = 32;
const NDP_RESOLVE_TIMEOUT_MS: u64 = 5_000;

pub(crate) struct NdpWaiterRegistry {
    waiters: PoisonLock<Vec<NdpWaiter>>,
    next_id: AtomicU64,
}

impl NdpWaiterRegistry {
    pub(crate) const fn new() -> Self {
        Self {
            waiters: PoisonLock::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }
}

pub(crate) fn ndp_waiters_in(runtime: NetRuntimeHandle) -> &'static NdpWaiterRegistry {
    &runtime.context().ndp_waiters
}

#[inline]
fn current_time_ms() -> u64 {
    crate::time::get_uptime_ms()
}

#[cfg(test)]
fn reset_ndp_waiters_for_tests(runtime: NetRuntimeHandle) {
    let registry = ndp_waiters_in(runtime);
    if let Ok(mut waiters) = registry.waiters.lock() {
        waiters.clear();
    }
    registry.next_id.store(1, Ordering::Relaxed);
}

#[inline]
fn waiter_matches_resolution(waiter: &NdpWaiter, if_id: Option<u16>, ip: [u8; 16]) -> bool {
    if waiter.ip != ip {
        return false;
    }

    // if_id指定なしの待機者は「任意インターフェースでの解決」を受理する。
    waiter.if_id.is_none() || waiter.if_id == if_id
}

pub fn notify_ndp_resolved_in(
    runtime: NetRuntimeHandle,
    if_id: Option<u16>,
    ip: [u8; 16],
    mac: [u8; 6],
) {
    let now_ms = current_time_ms();
    let resolved_mac = MacAddress::new(mac);
    let Ok(mut waiters) = ndp_waiters_in(runtime).waiters.lock() else {
        return;
    };

    for waiter in waiters.iter_mut() {
        if waiter_matches_resolution(waiter, if_id, ip) && waiter.result.is_none() {
            waiter.result = Some(resolved_mac);
            waiter.completed_at_ms = Some(now_ms);
            waiter.waker.wake();
        }
    }
}

fn register_ndp_waiter(
    runtime: NetRuntimeHandle,
    if_id: Option<u16>,
    ip: [u8; 16],
    waker: &Waker,
) -> Option<u64> {
    let registry = ndp_waiters_in(runtime);
    let Ok(mut waiters) = registry.waiters.lock() else {
        return None;
    };

    if waiters.len() >= NDP_WAITER_CAPACITY {
        return None;
    }

    let waiter_id = registry.next_id.fetch_add(1, Ordering::Relaxed);
    let waiter = NdpWaiter {
        id: waiter_id,
        if_id,
        ip,
        result: None,
        waker: AtomicWaker::new(),
        created_at_ms: current_time_ms(),
        completed_at_ms: None,
    };
    waiter.waker.register(waker);
    waiters.push(waiter);
    Some(waiter_id)
}

fn update_ndp_waiter_waker(runtime: NetRuntimeHandle, waiter_id: u64, waker: &Waker) -> bool {
    let Ok(mut waiters) = ndp_waiters_in(runtime).waiters.lock() else {
        return false;
    };

    if let Some(waiter) = waiters.iter_mut().find(|w| w.id == waiter_id) {
        waiter.waker.register(waker);
        return true;
    }

    false
}

fn poll_ndp_result(runtime: NetRuntimeHandle, waiter_id: u64) -> Option<MacAddress> {
    let Ok(waiters) = ndp_waiters_in(runtime).waiters.lock() else {
        return None;
    };

    waiters
        .iter()
        .find_map(|waiter| (waiter.id == waiter_id).then_some(waiter.result).flatten())
}

fn remove_ndp_waiter(runtime: NetRuntimeHandle, waiter_id: u64) -> bool {
    let Ok(mut waiters) = ndp_waiters_in(runtime).waiters.lock() else {
        return false;
    };

    let before = waiters.len();
    waiters.retain(|w| w.id != waiter_id);
    waiters.len() != before
}

#[cfg(test)]
fn waiter_exists(runtime: NetRuntimeHandle, waiter_id: u64) -> bool {
    let Ok(waiters) = ndp_waiters_in(runtime).waiters.lock() else {
        return false;
    };

    waiters.iter().any(|w| w.id == waiter_id)
}

// ============================================================================
// NdpResolveFuture
// ============================================================================

pub struct NdpResolveFuture {
    runtime: NetRuntimeHandle,
    target_ip: Ipv6Address,
    if_id: Option<u16>,
    waiter_id: Option<u64>,
    request_sent: bool,
    poll_count: u32,
}

impl NdpResolveFuture {
    pub fn new_in(runtime: NetRuntimeHandle, target_ip: Ipv6Address) -> Self {
        Self {
            runtime,
            target_ip,
            if_id: None,
            waiter_id: None,
            request_sent: false,
            poll_count: 0,
        }
    }

    pub fn new_on_in(runtime: NetRuntimeHandle, if_id: u16, target_ip: Ipv6Address) -> Self {
        Self {
            runtime,
            target_ip,
            if_id: Some(if_id),
            waiter_id: None,
            request_sent: false,
            poll_count: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpResolveError {
    Timeout,
    ResourceExhausted,
    InvalidTarget,
}

impl Future for NdpResolveFuture {
    type Output = Result<MacAddress, NdpResolveError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let ip_bytes = *self.target_ip.as_bytes();

        if self.target_ip.is_multicast() {
            return Poll::Ready(Ok(MacAddress::new(self.target_ip.multicast_mac())));
        }

        if self.target_ip.is_unspecified() {
            return Poll::Ready(Err(NdpResolveError::InvalidTarget));
        }

        if self.waiter_id.is_none() {
            self.waiter_id = register_ndp_waiter(self.runtime, self.if_id, ip_bytes, cx.waker());
            if self.waiter_id.is_none() {
                return Poll::Ready(Err(NdpResolveError::ResourceExhausted));
            }
        }

        if let Some(waiter_id) = self.waiter_id {
            if let Some(mac) = poll_ndp_result(self.runtime, waiter_id) {
                let _ = remove_ndp_waiter(self.runtime, waiter_id);
                self.waiter_id = None;
                return Poll::Ready(Ok(mac));
            }

            if !update_ndp_waiter_waker(self.runtime, waiter_id, cx.waker()) {
                self.waiter_id = None;
                return Poll::Ready(Err(NdpResolveError::Timeout));
            }
        }

        self.poll_count = self.poll_count.saturating_add(1);
        if self.poll_count > 50 {
            if let Some(waiter_id) = self.waiter_id.take() {
                let _ = remove_ndp_waiter(self.runtime, waiter_id);
            }
            return Poll::Ready(Err(NdpResolveError::Timeout));
        }

        if !self.request_sent || self.poll_count % 10 == 0 {
            let _ = try_enqueue_command_in(
                self.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(
                    crate::net::runtime::command::ControlCommand::NdpResolveRequest {
                        if_id: self.if_id,
                        target_ip: ip_bytes,
                    },
                ),
            );
            self.request_sent = true;
        }

        Poll::Pending
    }
}

impl Drop for NdpResolveFuture {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id.take() {
            let _ = remove_ndp_waiter(self.runtime, waiter_id);
        }
    }
}

pub async fn resolve_neighbor_in(
    runtime: NetRuntimeHandle,
    target_ip: Ipv6Address,
) -> Result<MacAddress, NdpResolveError> {
    NdpResolveFuture::new_in(runtime, target_ip).await
}

pub async fn resolve_neighbor_on_in(
    runtime: NetRuntimeHandle,
    if_id: u16,
    target_ip: Ipv6Address,
) -> Result<MacAddress, NdpResolveError> {
    NdpResolveFuture::new_on_in(runtime, if_id, target_ip).await
}

pub fn cleanup_ndp_waiters_in(runtime: NetRuntimeHandle) {
    let now_ms = current_time_ms();
    if let Ok(mut waiters) = ndp_waiters_in(runtime).waiters.lock() {
        for waiter in waiters.iter() {
            let age_base = waiter.completed_at_ms.unwrap_or(waiter.created_at_ms);
            let expired = now_ms.saturating_sub(age_base) > NDP_RESOLVE_TIMEOUT_MS;

            if expired && waiter.result.is_none() {
                waiter.waker.wake();
            }
        }

        waiters.retain(|waiter| {
            let age_base = waiter.completed_at_ms.unwrap_or(waiter.created_at_ms);
            now_ms.saturating_sub(age_base) <= NDP_RESOLVE_TIMEOUT_MS
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::task::{Context, RawWaker, RawWakerVTable, Waker};

    fn noop_waker() -> Waker {
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}

        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);

        // SAFETY: no-op vtable with null data pointer is valid for a no-op waker.
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }

    #[cfg_attr(test, test_case)]
    fn ndp_waiter_notify_matches_interface_scope() {
        let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
        reset_ndp_waiters_for_tests(runtime);

        let ip = Ipv6Address::LOOPBACK.octets();
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x77];

        let waiter_any = register_ndp_waiter(runtime, None, ip, &noop_waker())
            .expect("failed to register any waiter");
        let waiter_if1 = register_ndp_waiter(runtime, Some(1), ip, &noop_waker())
            .expect("failed to register if1 waiter");
        let waiter_if2 = register_ndp_waiter(runtime, Some(2), ip, &noop_waker())
            .expect("failed to register if2 waiter");

        notify_ndp_resolved_in(runtime, Some(1), ip, mac);

        assert_eq!(
            poll_ndp_result(runtime, waiter_any),
            Some(MacAddress::new(mac))
        );
        assert_eq!(
            poll_ndp_result(runtime, waiter_if1),
            Some(MacAddress::new(mac))
        );
        assert_eq!(poll_ndp_result(runtime, waiter_if2), None);

        let _ = remove_ndp_waiter(runtime, waiter_any);
        let _ = remove_ndp_waiter(runtime, waiter_if1);
        let _ = remove_ndp_waiter(runtime, waiter_if2);
    }

    #[cfg_attr(test, test_case)]
    fn ndp_resolve_future_returns_ready_after_notification() {
        let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
        reset_ndp_waiters_for_tests(runtime);

        let ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0x42];
        let target_ip = Ipv6Address::new(ip);
        let resolved_mac = MacAddress::from_octets(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = NdpResolveFuture::new_in(runtime, target_ip);
        fut.request_sent = true;

        assert!(matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending));

        notify_ndp_resolved_in(runtime, None, ip, *resolved_mac.as_bytes());

        let poll = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(mac)) if mac == resolved_mac));
    }

    #[cfg_attr(test, test_case)]
    fn ndp_resolve_future_timeout_removes_registered_waiter() {
        let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
        reset_ndp_waiters_for_tests(runtime);

        let ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0x09];
        let waiter_id = register_ndp_waiter(runtime, None, ip, &noop_waker())
            .expect("failed to register waiter");
        assert!(waiter_exists(runtime, waiter_id));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = NdpResolveFuture::new_in(runtime, Ipv6Address::new(ip));
        fut.request_sent = true;
        fut.waiter_id = Some(waiter_id);
        fut.poll_count = 50;

        let poll = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(poll, Poll::Ready(Err(NdpResolveError::Timeout))));
        assert!(!waiter_exists(runtime, waiter_id));
    }
}
