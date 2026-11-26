// ============================================================================
// kernel/src/net/l4/tcp/mod.rs - L4 / TCP モジュール
// ============================================================================
//! TCP public facade plus TCP-specific internals.

pub(crate) mod congestion;
mod connection;
pub(crate) mod flow_control;
pub(crate) mod ooo_queue;
pub(crate) mod retransmit;
pub(crate) mod segment;
pub(crate) mod tcb;
pub(crate) mod tcp_rx;
pub(crate) mod termination;
pub(crate) mod timer_wheel;
pub(crate) mod window_scale;

pub use crate::net::l4::types::EndpointAddr;
pub use connection::*;

/// TCP state machine values shared with the endpoint TCB table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// TCP connection statistics owned by the endpoint state.
#[derive(Debug, Default, Clone, Copy)]
pub struct TcpStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub app_bytes_delivered: u64,
}

impl TcpStats {
    #[inline]
    pub fn record_tx_enqueued(&mut self, len: usize) {
        self.bytes_sent = self.bytes_sent.saturating_add(len as u64);
        self.packets_sent = self.packets_sent.saturating_add(1);
    }

    #[inline]
    pub fn record_rx_segment(&mut self, len: usize) {
        self.bytes_received = self.bytes_received.saturating_add(len as u64);
        self.packets_received = self.packets_received.saturating_add(1);
    }

    #[inline]
    pub fn record_rx_delivered(&mut self, len: usize) {
        self.app_bytes_delivered = self.app_bytes_delivered.saturating_add(len as u64);
    }
}
