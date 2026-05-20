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
pub(crate) mod timer_wheel;
pub(crate) mod window_scale;

pub use crate::net::l4::types::EndpointAddr;
pub use crate::net::types::Ipv4Addr;
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
    pub retransmissions: u64,
    pub rtt_us: u64,
    pub oom_dropped_packets: u64,
    pub oom_dropped_bytes: u64,
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

    #[inline]
    pub fn record_oom_drop(&mut self, len: usize) {
        self.oom_dropped_packets = self.oom_dropped_packets.saturating_add(1);
        self.oom_dropped_bytes = self.oom_dropped_bytes.saturating_add(len as u64);
    }
}

/// Minimal TCP header constants shared across the networking stack.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub const FLAG_FIN: u16 = 0x0001;
    pub const FLAG_SYN: u16 = 0x0002;
    pub const FLAG_RST: u16 = 0x0004;
    pub const FLAG_PSH: u16 = 0x0008;
    pub const FLAG_ACK: u16 = 0x0010;
    pub const FLAG_URG: u16 = 0x0020;
    pub const FLAG_ECE: u16 = 0x0040;
    pub const FLAG_CWR: u16 = 0x0080;
    pub const FLAG_NS: u16 = 0x0100;
    pub const MIN_HEADER_LEN: usize = 20;

    #[inline]
    pub fn data_offset(&self) -> usize {
        (((u16::from_be(self.data_offset_flags) >> 12) & 0x0f) as usize) * 4
    }

    #[inline]
    pub fn flags(&self) -> u16 {
        u16::from_be(self.data_offset_flags) & 0x01ff
    }
}
