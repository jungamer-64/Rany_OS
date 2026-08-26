// ============================================================================
// kernel/src/net/l4/tcp/ooo_queue.rs - TCP Out-of-Order receive ownership
// ============================================================================
//! Each TCB owns its bounded out-of-order queue. A runtime-wide permit budget
//! bounds the aggregate packet backing retained by all connections.

use crate::net::l4::types::{EndpointAddr, seq_before};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::{tcp_runtime_in, tcp_table_in};
use arrayvec::ArrayVec;
use core::sync::atomic::{AtomicUsize, Ordering};
use kernel_api::resource::net::PacketPayload;

const MAX_OOO_SEGMENTS: usize = 16;
const GLOBAL_MAX_OOO_SEGMENTS: usize = 512;

#[derive(Debug)]
pub(in crate::net::l4::tcp) struct OooPermit {
    total_count: &'static AtomicUsize,
}

impl Drop for OooPermit {
    fn drop(&mut self) {
        self.total_count.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_reserve_ooo_slot(total_count: &'static AtomicUsize) -> Option<OooPermit> {
    let mut observed = total_count.load(Ordering::Acquire);
    // LOOP_PROOF: mode=condition; reason=compare_exchange either succeeds or refreshes observed.
    loop {
        if observed >= GLOBAL_MAX_OOO_SEGMENTS {
            return None;
        }
        match total_count.compare_exchange_weak(
            observed,
            observed + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(OooPermit { total_count }),
            Err(actual) => observed = actual,
        }
    }
}

#[derive(Debug)]
struct OooSegment {
    seq: u32,
    payload: PacketPayload,
    _permit: OooPermit,
}

impl OooSegment {
    fn end_seq(&self) -> u32 {
        self.seq.wrapping_add(self.payload.total_len() as u32)
    }
}

#[derive(Debug)]
pub(in crate::net::l4::tcp) struct ConnectionOooQueue {
    segments: ArrayVec<OooSegment, MAX_OOO_SEGMENTS>,
    fin_seq: Option<u32>,
}

impl ConnectionOooQueue {
    pub(in crate::net::l4::tcp) const fn new() -> Self {
        Self {
            segments: ArrayVec::new_const(),
            fin_seq: None,
        }
    }

    fn insert(
        &mut self,
        seq: u32,
        data: Option<PacketPayload>,
        fin: bool,
        permit: Option<OooPermit>,
    ) {
        let Some(data) = data else {
            if fin {
                self.fin_seq = Some(seq);
            }
            return;
        };
        let Some(permit) = permit else {
            return;
        };

        let fragment_end = seq.wrapping_add(data.total_len() as u32);
        if self.segments.iter().any(|segment| {
            seq_before(seq, segment.end_seq()) && seq_before(segment.seq, fragment_end)
        }) {
            log::warn!(
                "[NET-TCP] overlapping OOO segment at seq {}, dropping the connection queue",
                seq
            );
            self.clear();
            return;
        }

        if self.segments.is_full() {
            let last_seq = self
                .segments
                .last()
                .map(|segment| segment.seq)
                .expect("full OOO queue has a last segment");
            if seq_before(seq, last_seq) {
                self.segments.pop();
            } else {
                return;
            }
        }

        let position = self
            .segments
            .iter()
            .position(|segment| seq_before(seq, segment.seq))
            .unwrap_or(self.segments.len());
        self.segments.insert(
            position,
            OooSegment {
                seq,
                payload: data,
                _permit: permit,
            },
        );
        if fin {
            self.fin_seq = Some(fragment_end);
        }
    }

    fn prune_outdated(&mut self, rcv_nxt: u32) {
        let mut index = 0usize;
        // LOOP_PROOF: mode=condition; reason=index advances or removal reduces segments.len().
        while index < self.segments.len() {
            if !seq_before(self.segments[index].seq, rcv_nxt) {
                index += 1;
                continue;
            }
            let segment = self.segments.remove(index);
            let segment_end = segment.end_seq();
            if !seq_before(rcv_nxt, segment_end) {
                continue;
            }
            let overlap = rcv_nxt.wrapping_sub(segment.seq) as usize;
            let retained_len = segment_end.wrapping_sub(rcv_nxt) as usize;
            let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                &segment.payload,
                overlap,
                retained_len,
            ) else {
                continue;
            };
            let OooSegment {
                payload,
                _permit: permit,
                ..
            } = segment;
            let Some(trimmed) = bounds
                .take_from(payload)
                .and_then(|window| window.into_payload().ok())
            else {
                continue;
            };
            let trimmed_end = rcv_nxt.wrapping_add(trimmed.total_len() as u32);
            if self.segments.iter().any(|queued| {
                seq_before(rcv_nxt, queued.end_seq()) && seq_before(queued.seq, trimmed_end)
            }) {
                continue;
            }
            let position = self
                .segments
                .iter()
                .position(|queued| seq_before(rcv_nxt, queued.seq))
                .unwrap_or(self.segments.len());
            self.segments.insert(
                position,
                OooSegment {
                    seq: rcv_nxt,
                    payload: trimmed,
                    _permit: permit,
                },
            );
        }
    }

    fn drain_contiguous_with<F>(&mut self, mut rcv_nxt: u32, mut deliver: F) -> (u32, bool)
    where
        F: FnMut(u32, PacketPayload) -> (usize, Option<PacketPayload>),
    {
        self.prune_outdated(rcv_nxt);
        // LOOP_PROOF: mode=event; reason=each iteration removes a segment or exits.
        loop {
            let Some(position) = self
                .segments
                .iter()
                .position(|segment| segment.seq == rcv_nxt)
            else {
                break;
            };
            let OooSegment {
                payload,
                _permit: permit,
                ..
            } = self.segments.remove(position);
            let payload_len = payload.total_len();
            let (pushed, remainder) = deliver(rcv_nxt, payload);
            let pushed = pushed.min(payload_len);
            rcv_nxt = rcv_nxt.wrapping_add(pushed as u32);
            if pushed < payload_len {
                if let Some(remainder) = remainder {
                    let position = self
                        .segments
                        .iter()
                        .position(|segment| seq_before(rcv_nxt, segment.seq))
                        .unwrap_or(self.segments.len());
                    self.segments.insert(
                        position,
                        OooSegment {
                            seq: rcv_nxt,
                            payload: remainder,
                            _permit: permit,
                        },
                    );
                }
                break;
            }
            drop(permit);
            self.prune_outdated(rcv_nxt);
        }

        let fin_encountered = self.fin_seq == Some(rcv_nxt);
        if fin_encountered {
            self.fin_seq = None;
        }
        (rcv_nxt, fin_encountered)
    }

    pub(in crate::net::l4::tcp) fn is_empty(&self) -> bool {
        self.segments.is_empty() && self.fin_seq.is_none()
    }

    pub(in crate::net::l4::tcp) fn clear(&mut self) {
        self.segments.clear();
        self.fin_seq = None;
    }
}

pub(crate) struct OooRuntimeState {
    total_count: AtomicUsize,
}

impl OooRuntimeState {
    pub(crate) const fn new() -> Self {
        Self {
            total_count: AtomicUsize::new(0),
        }
    }
}

pub fn insert_ooo_segment(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    seq: u32,
    data: Option<PacketPayload>,
    fin: bool,
) {
    if data.is_none() && !fin {
        return;
    }
    let state = tcp_runtime_in(runtime).ooo();
    let permit = if data.is_some() {
        let Some(permit) = try_reserve_ooo_slot(&state.total_count) else {
            return;
        };
        Some(permit)
    } else {
        None
    };
    let _ = tcp_table_in(runtime).mutate_ooo_queue(if_id, local, remote, |queue| {
        queue.insert(seq, data, fin, permit);
    });
}

pub fn drain_ooo_contiguous<F>(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    rcv_nxt: u32,
    deliver: F,
) -> (u32, bool)
where
    F: FnMut(u32, PacketPayload) -> (usize, Option<PacketPayload>),
{
    tcp_table_in(runtime)
        .mutate_ooo_queue(if_id, local, remote, |queue| {
            queue.drain_contiguous_with(rcv_nxt, deliver)
        })
        .unwrap_or((rcv_nxt, false))
}

pub fn remove_ooo_queue(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
) {
    let _ = tcp_table_in(runtime).mutate_ooo_queue(if_id, local, remote, ConnectionOooQueue::clear);
}

#[inline]
pub fn has_ooo_segments(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
) -> bool {
    tcp_table_in(runtime)
        .read_ooo_queue(if_id, local, remote, |queue| !queue.is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

    fn test_payload(byte: u8) -> PacketPayload {
        let mut packet =
            crate::net::payload::alloc_packet_with_headroom(1, DEFAULT_PACKET_HEADROOM)
                .expect("test packet allocation");
        packet.data_mut()[0] = byte;
        PacketPayload::try_single(packet).expect("test payload is non-empty")
    }

    fn test_budget() -> &'static AtomicUsize {
        Box::leak(Box::new(AtomicUsize::new(0)))
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn global_budget_is_reserved_before_admission_and_released_on_drop() {
        let budget = test_budget();
        let mut permits = Vec::new();
        for _ in 0..GLOBAL_MAX_OOO_SEGMENTS {
            permits.push(try_reserve_ooo_slot(budget).expect("budget slot"));
        }
        assert!(try_reserve_ooo_slot(budget).is_none());
        assert_eq!(budget.load(Ordering::Acquire), GLOBAL_MAX_OOO_SEGMENTS);

        permits.truncate(GLOBAL_MAX_OOO_SEGMENTS / 2);
        assert_eq!(budget.load(Ordering::Acquire), GLOBAL_MAX_OOO_SEGMENTS / 2);
        drop(permits);
        assert_eq!(budget.load(Ordering::Acquire), 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn overlap_and_clear_release_every_connection_permit() {
        let budget = test_budget();
        let mut queue = ConnectionOooQueue::new();
        queue.insert(
            100,
            Some(test_payload(1)),
            false,
            try_reserve_ooo_slot(budget),
        );
        assert_eq!(budget.load(Ordering::Acquire), 1);

        queue.insert(
            100,
            Some(test_payload(2)),
            false,
            try_reserve_ooo_slot(budget),
        );
        assert!(queue.is_empty());
        assert_eq!(budget.load(Ordering::Acquire), 0);

        queue.insert(
            200,
            Some(test_payload(3)),
            false,
            try_reserve_ooo_slot(budget),
        );
        queue.clear();
        assert_eq!(budget.load(Ordering::Acquire), 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn full_connection_queue_releases_evicted_and_rejected_permits() {
        let budget = test_budget();
        let mut queue = ConnectionOooQueue::new();
        for index in 0..MAX_OOO_SEGMENTS {
            queue.insert(
                100 + index as u32 * 2,
                Some(test_payload(index as u8)),
                false,
                try_reserve_ooo_slot(budget),
            );
        }
        assert_eq!(budget.load(Ordering::Acquire), MAX_OOO_SEGMENTS);

        queue.insert(
            1000,
            Some(test_payload(0xff)),
            false,
            try_reserve_ooo_slot(budget),
        );
        assert_eq!(budget.load(Ordering::Acquire), MAX_OOO_SEGMENTS);

        queue.insert(
            50,
            Some(test_payload(0xfe)),
            false,
            try_reserve_ooo_slot(budget),
        );
        assert_eq!(budget.load(Ordering::Acquire), MAX_OOO_SEGMENTS);
        queue.clear();
        assert_eq!(budget.load(Ordering::Acquire), 0);
    }
}
