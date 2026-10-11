// ============================================================================
// kernel/src/net/l3/ndp/resolve_future.rs - 非同期NDP解決Future
// ============================================================================
//! NDP solicitations enter the runtime command queue; advertisements and timeout
//! maintenance publish completion to the runtime-owned neighbor registry.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use super::Ipv6Address;
use crate::net::l2::ethernet::MacAddress;
use crate::net::neighbor_wait::{NeighborWait, NeighborWaitError};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{ControlCommand, RuntimeCommand, try_enqueue_command_in};
use crate::net::runtime::manager::NetIfId;

/// The registration owns cancellation until completion or Future destruction.
/// Timeout is elapsed uptime, independent of unrelated wake/poll frequency.
pub struct NdpResolveFuture {
    runtime: NetRuntimeHandle,
    target_ip: Ipv6Address,
    if_id: NetIfId,
    wait: Option<NeighborWait<'static, 16>>,
    next_request_at_ms: u64,
}

impl NdpResolveFuture {
    pub fn new_on_in(runtime: NetRuntimeHandle, if_id: NetIfId, target_ip: Ipv6Address) -> Self {
        Self {
            runtime,
            target_ip,
            if_id,
            wait: None,
            next_request_at_ms: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpResolveError {
    Timeout,
    CapacityExhausted,
    IdentityExhausted,
    CommandRejected,
    InvalidTarget,
    RegistryPoisoned,
}

impl From<NeighborWaitError> for NdpResolveError {
    fn from(error: NeighborWaitError) -> Self {
        match error {
            NeighborWaitError::Timeout => Self::Timeout,
            NeighborWaitError::CapacityExhausted => Self::CapacityExhausted,
            NeighborWaitError::IdentityExhausted => Self::IdentityExhausted,
            NeighborWaitError::RegistryPoisoned => Self::RegistryPoisoned,
        }
    }
}

impl Future for NdpResolveFuture {
    type Output = Result<MacAddress, NdpResolveError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.target_ip.is_multicast() {
            return Poll::Ready(Ok(MacAddress::new(self.target_ip.multicast_mac())));
        }
        if self.target_ip.is_unspecified() {
            return Poll::Ready(Err(NdpResolveError::InvalidTarget));
        }

        let now_ms = crate::time::get_uptime_ms();
        let ip = *self.target_ip.as_bytes();
        if self.wait.is_none() {
            let wait = match self
                .runtime
                .context()
                .ndp_waiters
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
            return Poll::Ready(result.map_err(NdpResolveError::from));
        }

        // Subsequent polls may retry after the interval. Runtime timeout
        // maintenance supplies the terminal wake even when no reply arrives.
        if now_ms >= self.next_request_at_ms {
            let command = RuntimeCommand::Control(ControlCommand::NdpResolveRequest {
                if_id: self.if_id,
                target_ip: ip,
            });
            if try_enqueue_command_in(self.runtime, command).is_err() {
                self.wait = None;
                return Poll::Ready(Err(NdpResolveError::CommandRejected));
            }
            self.next_request_at_ms = now_ms.saturating_add(1_000);
        }
        Poll::Pending
    }
}

pub fn notify_ndp_resolved_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    ip: [u8; 16],
    mac: [u8; 6],
) {
    runtime.context().ndp_waiters.notify(
        if_id,
        ip,
        MacAddress::new(mac),
        crate::time::get_uptime_ms(),
    );
}

pub fn cleanup_ndp_waiters_in(runtime: NetRuntimeHandle) {
    runtime
        .context()
        .ndp_waiters
        .expire(crate::time::get_uptime_ms());
}
