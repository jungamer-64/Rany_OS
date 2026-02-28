use alloc::vec::Vec;

use crate::net::obs::counters;
use crate::net::obs::trace::{NetTraceEvent, recent_events};

extern crate alloc;

#[derive(Debug, Clone)]
pub struct InterfaceSnapshot {
    pub name: alloc::string::String,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone)]
pub struct NetSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub drops: u64,
    pub errors: u64,
    pub interfaces: Vec<InterfaceSnapshot>,
    pub recent_events: Vec<NetTraceEvent>,
}

pub fn snapshot() -> NetSnapshot {
    let c = counters::global();
    NetSnapshot {
        rx_packets: c.rx_packets.load(core::sync::atomic::Ordering::Relaxed),
        tx_packets: c.tx_packets.load(core::sync::atomic::Ordering::Relaxed),
        rx_bytes: c.rx_bytes.load(core::sync::atomic::Ordering::Relaxed),
        tx_bytes: c.tx_bytes.load(core::sync::atomic::Ordering::Relaxed),
        drops: c.drops.load(core::sync::atomic::Ordering::Relaxed),
        errors: c.errors.load(core::sync::atomic::Ordering::Relaxed),
        interfaces: Vec::new(),
        recent_events: recent_events(64),
    }
}
