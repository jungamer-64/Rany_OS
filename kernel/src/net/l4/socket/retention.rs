// ============================================================================
// kernel/src/net/l4/socket/retention.rs - Received packet retention budget
// ============================================================================
//! Runtime-wide bound on received packet backing held by socket queues.
//!
//! A payload waiting in a socket's receive queue keeps every packet buffer it
//! spans out of its pool, however few bytes it holds. Each queued payload is
//! charged its segment count against one budget per runtime, so all receive
//! queues together retain at most `RX_SOCKET_RETENTION_LIMIT` buffers; a port's
//! RX pool is sized to cover this limit. A payload that cannot be charged is
//! not queued.

use core::sync::atomic::{AtomicUsize, Ordering};
use kernel_api::resource::net::PacketPayload;

/// Packet segments that all socket receive queues of one runtime may hold.
pub(crate) const RX_SOCKET_RETENTION_LIMIT: usize = 512;

pub(crate) struct SocketRetentionBudget {
    used: AtomicUsize,
}

impl SocketRetentionBudget {
    pub(crate) const fn new() -> Self {
        Self {
            used: AtomicUsize::new(0),
        }
    }

    /// Charge the segments `payload` retains, if the budget has room.
    pub(crate) fn try_charge(&'static self, payload: &PacketPayload) -> Option<SocketRetention> {
        let segments = payload.segments().len();
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(segments)
                    .filter(|total| *total <= RX_SOCKET_RETENTION_LIMIT)
            })
            .ok()?;
        Some(SocketRetention {
            used: &self.used,
            segments,
        })
    }
}

/// The charge of one queued payload, returned when the payload leaves its
/// queue.
#[derive(Debug)]
pub(crate) struct SocketRetention {
    used: &'static AtomicUsize,
    segments: usize,
}

impl Drop for SocketRetention {
    fn drop(&mut self) {
        self.used.fetch_sub(self.segments, Ordering::AcqRel);
    }
}
