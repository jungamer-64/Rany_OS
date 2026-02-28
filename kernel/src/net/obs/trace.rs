use alloc::collections::VecDeque;
use alloc::string::String;
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

#[derive(Debug, Clone)]
pub struct NetTraceEvent {
    pub ts_ms: u64,
    pub layer: NetLayer,
    pub kind: NetEventKind,
    pub message: String,
}

const MAX_EVENTS: usize = 256;
static TRACE_EVENTS: PoisonLock<VecDeque<NetTraceEvent>> = PoisonLock::new(VecDeque::new());

pub fn push_event(layer: NetLayer, kind: NetEventKind, message: impl Into<String>) {
    let event = NetTraceEvent {
        ts_ms: crate::time::get_uptime_ms(),
        layer,
        kind,
        message: message.into(),
    };

    if let Ok(mut q) = TRACE_EVENTS.lock() {
        if q.len() >= MAX_EVENTS {
            q.pop_front();
        }
        q.push_back(event);
    }
}

pub fn recent_events(limit: usize) -> Vec<NetTraceEvent> {
    if let Ok(q) = TRACE_EVENTS.lock() {
        let n = core::cmp::min(limit, q.len());
        return q.iter().rev().take(n).cloned().collect();
    }
    Vec::new()
}
