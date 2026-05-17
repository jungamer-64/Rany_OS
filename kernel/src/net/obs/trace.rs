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
