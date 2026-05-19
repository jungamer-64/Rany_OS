// ============================================================================
// kernel/src/net/runtime/icmp.rs - runtime-owned ICMP state
// ============================================================================

use crate::net::l4::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::sync::{AtomicWaker, PoisonLock};
use alloc::collections::BTreeMap;
use core::task::Poll;

extern crate alloc;

#[derive(Debug, Clone, Copy)]
pub struct IcmpEchoResult {
    pub source: [u8; 4],
    pub sequence: u16,
    pub rtt_us: u64,
}

struct PingWaiter {
    waker: AtomicWaker,
    result: Option<IcmpEchoResult>,
    start_tick: u64,
    timeout_us: u64,
}

struct IcmpEchoRegistry {
    waiters: BTreeMap<(u32, u16), PingWaiter>,
}

impl IcmpEchoRegistry {
    const fn new() -> Self {
        Self {
            waiters: BTreeMap::new(),
        }
    }

    fn register(&mut self, target: [u8; 4], sequence: u16, timeout_us: u64) {
        let key = (u32::from_be_bytes(target), sequence);
        let now = crate::task::current_tick();
        self.waiters.insert(
            key,
            PingWaiter {
                waker: AtomicWaker::new(),
                result: None,
                start_tick: now,
                timeout_us,
            },
        );
    }

    fn set_waker(&mut self, target: [u8; 4], sequence: u16, waker: &core::task::Waker) {
        let key = (u32::from_be_bytes(target), sequence);
        if let Some(entry) = self.waiters.get_mut(&key) {
            entry.waker.register(waker);
        }
    }

    fn notify_reply(&mut self, source: [u8; 4], sequence: u16, rtt_us: u64) {
        let key = (u32::from_be_bytes(source), sequence);
        if let Some(entry) = self.waiters.get_mut(&key) {
            entry.result = Some(IcmpEchoResult {
                source,
                sequence,
                rtt_us,
            });
            entry.waker.wake();
        }
    }

    fn poll_result(
        &mut self,
        target: [u8; 4],
        sequence: u16,
    ) -> Poll<Result<IcmpEchoResult, EndpointError>> {
        let key = (u32::from_be_bytes(target), sequence);
        if let Some(entry) = self.waiters.get(&key) {
            if let Some(result) = entry.result {
                self.waiters.remove(&key);
                return Poll::Ready(Ok(result));
            }
            let now = crate::task::current_tick();
            let elapsed = now.saturating_sub(entry.start_tick);
            if elapsed > entry.timeout_us {
                self.waiters.remove(&key);
                return Poll::Ready(Err(EndpointError::Timeout));
            }
            Poll::Pending
        } else {
            Poll::Ready(Err(EndpointError::NotFound))
        }
    }

    fn cleanup_expired(&mut self) {
        let now = crate::task::current_tick();
        self.waiters.retain(|_, entry| {
            let elapsed = now.saturating_sub(entry.start_tick);
            elapsed <= entry.timeout_us
        });
    }
}

pub(crate) struct IcmpRuntimeState {
    echo_registry: PoisonLock<IcmpEchoRegistry>,
}

impl IcmpRuntimeState {
    pub(crate) const fn new() -> Self {
        Self {
            echo_registry: PoisonLock::new(IcmpEchoRegistry::new()),
        }
    }

    pub(crate) fn register_echo_waiter(
        &self,
        target: [u8; 4],
        sequence: u16,
        timeout_us: u64,
    ) -> Result<(), EndpointError> {
        let mut registry = self
            .echo_registry
            .lock()
            .map_err(|_| EndpointError::Internal)?;
        registry.register(target, sequence, timeout_us);
        Ok(())
    }

    pub(crate) fn poll_echo_result(
        &self,
        target: [u8; 4],
        sequence: u16,
        waker: &core::task::Waker,
    ) -> Poll<Result<IcmpEchoResult, EndpointError>> {
        let Ok(mut registry) = self.echo_registry.lock() else {
            return Poll::Ready(Err(EndpointError::Internal));
        };
        registry.set_waker(target, sequence, waker);
        registry.poll_result(target, sequence)
    }

    pub(crate) fn notify_echo_reply(&self, source: [u8; 4], sequence: u16, rtt_us: u64) {
        if let Ok(mut registry) = self.echo_registry.lock() {
            registry.notify_reply(source, sequence, rtt_us);
        }
    }

    pub(crate) fn cleanup_echo_waiters(&self) {
        if let Ok(mut registry) = self.echo_registry.lock() {
            registry.cleanup_expired();
        }
    }
}

pub(crate) fn icmp_runtime_in(runtime: NetRuntimeHandle) -> &'static IcmpRuntimeState {
    &runtime.context().icmp
}
