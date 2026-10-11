// ============================================================================
// kernel/src/net/l2/arp/resolve_future.rs - 非同期ARP解決Future
// ============================================================================
//! ARP requests enter the runtime command queue; replies and timeout maintenance
//! publish completion to the runtime-owned neighbor registry.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use super::{Ipv4Address, MacAddress};
use crate::net::neighbor_wait::{NeighborWait, NeighborWaitError};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{ControlCommand, RuntimeCommand, try_enqueue_command_in};
use crate::net::runtime::manager::NetIfId;

/// The registration owns cancellation until completion or Future destruction.
/// Timeout is elapsed uptime, independent of unrelated wake/poll frequency.
pub struct ArpResolveFuture {
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    target_ip: Ipv4Address,
    wait: Option<NeighborWait<'static, 4>>,
    next_request_at_ms: u64,
}

impl ArpResolveFuture {
    pub fn new_in(runtime: NetRuntimeHandle, if_id: NetIfId, target_ip: Ipv4Address) -> Self {
        Self {
            runtime,
            if_id,
            target_ip,
            wait: None,
            next_request_at_ms: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpResolveError {
    Timeout,
    CapacityExhausted,
    IdentityExhausted,
    CommandRejected,
    RegistryPoisoned,
}

impl From<NeighborWaitError> for ArpResolveError {
    fn from(error: NeighborWaitError) -> Self {
        match error {
            NeighborWaitError::Timeout => Self::Timeout,
            NeighborWaitError::CapacityExhausted => Self::CapacityExhausted,
            NeighborWaitError::IdentityExhausted => Self::IdentityExhausted,
            NeighborWaitError::RegistryPoisoned => Self::RegistryPoisoned,
        }
    }
}

impl Future for ArpResolveFuture {
    type Output = Result<MacAddress, ArpResolveError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.target_ip.is_broadcast() {
            return Poll::Ready(Ok(MacAddress::BROADCAST));
        }
        if self.target_ip.is_multicast() {
            let ip = self.target_ip.as_bytes();
            return Poll::Ready(Ok(MacAddress::new([
                0x01,
                0x00,
                0x5e,
                ip[1] & 0x7f,
                ip[2],
                ip[3],
            ])));
        }

        let now_ms = crate::time::get_uptime_ms();
        let ip = *self.target_ip.as_bytes();
        if self.wait.is_none() {
            let wait = match self
                .runtime
                .context()
                .arp_waiters
                .register(self.if_id, ip, now_ms)
            {
                Ok(wait) => wait,
                Err(error) => return Poll::Ready(Err(error.into())),
            };
            self.wait = Some(wait);
        }
        if let Some(wait) = self.wait.as_mut()
            && let Poll::Ready(result) = wait.poll(cx, now_ms)
        {
            self.wait = None;
            return Poll::Ready(result.map_err(ArpResolveError::from));
        }

        // Subsequent polls may retry after the interval. Runtime timeout
        // maintenance supplies the terminal wake even when no reply arrives.
        if now_ms >= self.next_request_at_ms {
            let command = RuntimeCommand::Control(ControlCommand::ArpResolveRequest {
                if_id: self.if_id,
                target_ip: ip,
            });
            if try_enqueue_command_in(self.runtime, command).is_err() {
                self.wait = None;
                return Poll::Ready(Err(ArpResolveError::CommandRejected));
            }
            self.next_request_at_ms = now_ms.saturating_add(1_000);
        }
        Poll::Pending
    }
}

pub fn notify_arp_resolved_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    ip: [u8; 4],
    mac: [u8; 6],
) {
    runtime.context().arp_waiters.notify(
        if_id,
        ip,
        MacAddress::new(mac),
        crate::time::get_uptime_ms(),
    );
}

pub fn cleanup_arp_waiters_in(runtime: NetRuntimeHandle) {
    runtime
        .context()
        .arp_waiters
        .expire(crate::time::get_uptime_ms());
}
