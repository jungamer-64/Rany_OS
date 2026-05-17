// ============================================================================
// kernel/src/net/obs/trace.rs - obs / trace
// ============================================================================

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::sync::PoisonLock;

extern crate alloc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetLayer {
    L2,
    L3,
    L4,
    Service,
    Security,
    Driver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetEventKind {
    Rx,
    Tx,
    Drop,
    Error,
    Timeout,
    QueuePressure,
}

#[derive(Debug, Clone, Copy)]
pub struct NetTraceEvent {
    pub ts_ms: u64,
    pub layer: NetLayer,
    pub kind: NetEventKind,
    pub message: &'static str,
}

const MAX_EVENTS: usize = 256;

pub struct NetTraceLog {
    events: PoisonLock<VecDeque<NetTraceEvent>>,
}

impl NetTraceLog {
    pub const fn new() -> Self {
        Self {
            events: PoisonLock::new(VecDeque::new()),
        }
    }

    pub fn push(&self, layer: NetLayer, kind: NetEventKind, message: &'static str) {
        let event = NetTraceEvent {
            ts_ms: crate::time::get_uptime_ms(),
            layer,
            kind,
            message,
        };

        if let Ok(mut events) = self.events.lock() {
            if events.len() >= MAX_EVENTS {
                events.pop_front();
            }
            events.push_back(event);
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<NetTraceEvent> {
        if let Ok(events) = self.events.lock() {
            let n = core::cmp::min(limit, events.len());
            return events.iter().rev().take(n).copied().collect();
        }
        Vec::new()
    }
}
