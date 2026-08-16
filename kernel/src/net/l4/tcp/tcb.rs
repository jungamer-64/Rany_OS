// ============================================================================
// kernel/src/net/l4/tcp/tcb.rs - TCP Control Block - 接続状態管理
// ============================================================================
//! # TCP Control Block - 接続状態管理
//!
//! TcpConnectionState, TcpControlBlock, TcbTable, tcp_flags

use crate::sync::PoisonRwLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::congestion::TcpCongestionController;
use super::flow_control::FlowController;
use super::window_scale::WindowScaleOption;
use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId, conn_key_hash, seq_after};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;

/// TCPフラグ
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

pub use crate::net::l4::tcp::TcpState as TcpConnectionState;

/// TCP制御ブロック（RFC 5681/7323準拠）
#[derive(Debug)]
pub struct TcpControlBlock {
    socket_id: SocketId,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    state: TcpTcbState,
    pending_error: Option<EndpointError>,
}

#[derive(Debug, Clone, Copy)]
struct TcpSequenceSpace {
    snd_nxt: u32,
    snd_una: u32,
    rcv_nxt: u32,
}

#[derive(Debug)]
struct TcpHandshakeData {
    seq: TcpSequenceSpace,
    snd_wnd: u16,
    max_snd_wnd: u32,
    rcv_wnd: u16,
    last_send_tick: u64,
    window_scale: WindowScaleOption,
    mss: u32,
    sack_enabled: bool,
    ts_enabled: bool,
    ts_val: u32,
    ts_ecr: u32,
    nagle_enabled: bool,
}

#[derive(Debug)]
struct TcpConnectionData {
    seq: TcpSequenceSpace,
    snd_wnd: u16,
    max_snd_wnd: u32,
    rcv_wnd: u16,
    retransmit_count: u8,
    last_send_tick: u64,
    congestion: TcpCongestionController,
    window_scale: WindowScaleOption,
    flow_control: FlowController,
    mss: u32,
    rcv_up: u32,
    rcv_urg: bool,
    sack_enabled: bool,
    ts_enabled: bool,
    ts_val: u32,
    ts_ecr: u32,
    nagle_enabled: bool,
    delayed_ack_pending: u8,
    delayed_ack_timer: u64,
}

#[derive(Debug)]
enum TcpTcbState {
    Closed,
    Listen,
    SynSent(TcpHandshakeData),
    SynReceived(TcpHandshakeData),
    Established(TcpConnectionData),
    FinWait1(TcpConnectionData),
    FinWait2(TcpConnectionData),
    CloseWait(TcpConnectionData),
    Closing(TcpConnectionData),
    LastAck(TcpConnectionData),
    TimeWait(TcpConnectionData),
}

impl TcpTcbState {
    fn kind(&self) -> TcpConnectionState {
        match self {
            Self::Closed => TcpConnectionState::Closed,
            Self::Listen => TcpConnectionState::Listen,
            Self::SynSent(_) => TcpConnectionState::SynSent,
            Self::SynReceived(_) => TcpConnectionState::SynReceived,
            Self::Established(_) => TcpConnectionState::Established,
            Self::FinWait1(_) => TcpConnectionState::FinWait1,
            Self::FinWait2(_) => TcpConnectionState::FinWait2,
            Self::CloseWait(_) => TcpConnectionState::CloseWait,
            Self::Closing(_) => TcpConnectionState::Closing,
            Self::LastAck(_) => TcpConnectionState::LastAck,
            Self::TimeWait(_) => TcpConnectionState::TimeWait,
        }
    }

    fn sequence(&self) -> Option<TcpSequenceSpace> {
        match self {
            Self::Closed | Self::Listen => None,
            Self::SynSent(data) | Self::SynReceived(data) => Some(data.seq),
            Self::Established(data)
            | Self::FinWait1(data)
            | Self::FinWait2(data)
            | Self::CloseWait(data)
            | Self::Closing(data)
            | Self::LastAck(data)
            | Self::TimeWait(data) => Some(data.seq),
        }
    }

    fn sequence_mut(&mut self) -> Option<&mut TcpSequenceSpace> {
        match self {
            Self::Closed | Self::Listen => None,
            Self::SynSent(data) | Self::SynReceived(data) => Some(&mut data.seq),
            Self::Established(data)
            | Self::FinWait1(data)
            | Self::FinWait2(data)
            | Self::CloseWait(data)
            | Self::Closing(data)
            | Self::LastAck(data)
            | Self::TimeWait(data) => Some(&mut data.seq),
        }
    }

    fn connection_data(&self) -> Option<&TcpConnectionData> {
        match self {
            Self::Established(data)
            | Self::FinWait1(data)
            | Self::FinWait2(data)
            | Self::CloseWait(data)
            | Self::Closing(data)
            | Self::LastAck(data)
            | Self::TimeWait(data) => Some(data),
            _ => None,
        }
    }

    fn connection_data_mut(&mut self) -> Option<&mut TcpConnectionData> {
        match self {
            Self::Established(data)
            | Self::FinWait1(data)
            | Self::FinWait2(data)
            | Self::CloseWait(data)
            | Self::Closing(data)
            | Self::LastAck(data)
            | Self::TimeWait(data) => Some(data),
            _ => None,
        }
    }

    fn handshake_data(&self) -> Option<&TcpHandshakeData> {
        match self {
            Self::SynSent(data) | Self::SynReceived(data) => Some(data),
            _ => None,
        }
    }

    fn handshake_data_mut(&mut self) -> Option<&mut TcpHandshakeData> {
        match self {
            Self::SynSent(data) | Self::SynReceived(data) => Some(data),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcpControlBlockSnapshot {
    pub socket_id: SocketId,
    pub if_id: NetIfId,
    pub local: EndpointAddr,
    pub remote: EndpointAddr,
    pub state: TcpConnectionState,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub rcv_nxt: u32,
    pub max_snd_wnd: u32,
    pub scaled_snd_wnd: u32,
    pub effective_send_window: u32,
    pub advertised_recv_window: u16,
    pub effective_recv_window: u32,
    pub mss: u32,
    pub sack_enabled: bool,
    pub ts_enabled: bool,
    pub ts_ecr: u32,
    pub nagle_enabled: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(in crate::net::l4::tcp) struct TcpHandshakeOptions {
    pub peer_ts_val: Option<u32>,
    pub local_ts_val: Option<u32>,
    pub sack_permitted: bool,
    pub peer_mss: Option<u16>,
    pub peer_window_scale: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::net::l4::tcp) struct PassiveOpenSynAck {
    pub window_scale_enabled: bool,
    pub sack_enabled: bool,
    pub timestamp_enabled: bool,
    pub isn: u32,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::net::l4::tcp) struct DelayedAckDue {
    pub if_id: NetIfId,
    pub local: EndpointAddr,
    pub remote: EndpointAddr,
    pub rcv_nxt: u32,
    pub snd_nxt: u32,
    pub window: u16,
    pub timestamp_enabled: bool,
    pub timestamp_echo: u32,
}

impl TcpHandshakeData {
    fn new(isn: u32, nodelay: bool) -> Self {
        Self {
            seq: TcpSequenceSpace {
                snd_nxt: isn,
                snd_una: isn,
                rcv_nxt: 0,
            },
            snd_wnd: 65535,
            max_snd_wnd: 65535,
            rcv_wnd: 65535,
            last_send_tick: 0,
            window_scale: WindowScaleOption::default_enabled(),
            mss: 536,
            sack_enabled: false,
            ts_enabled: false,
            ts_val: 0,
            ts_ecr: 0,
            nagle_enabled: !nodelay,
        }
    }

    fn apply_options(&mut self, options: TcpHandshakeOptions) {
        if let Some(peer_ts_val) = options.peer_ts_val {
            self.ts_enabled = true;
            self.ts_ecr = peer_ts_val;
            if let Some(local_ts_val) = options.local_ts_val {
                self.ts_val = local_ts_val;
            }
        }
        if options.sack_permitted {
            self.sack_enabled = true;
        }
        if let Some(mss) = options.peer_mss {
            self.mss = mss as u32;
        }
        if let Some(ws) = options.peer_window_scale {
            self.window_scale.enabled = true;
            self.window_scale.set_snd_scale(ws);
        } else {
            self.window_scale.enabled = false;
        }
    }

    fn into_connection(self) -> TcpConnectionData {
        let mut congestion = TcpCongestionController::new();
        congestion.update_mss(self.mss);
        TcpConnectionData {
            seq: self.seq,
            snd_wnd: self.snd_wnd,
            max_snd_wnd: self.max_snd_wnd,
            rcv_wnd: self.rcv_wnd,
            retransmit_count: 0,
            last_send_tick: self.last_send_tick,
            congestion,
            window_scale: self.window_scale,
            flow_control: FlowController::new(),
            mss: self.mss,
            rcv_up: 0,
            rcv_urg: false,
            sack_enabled: self.sack_enabled,
            ts_enabled: self.ts_enabled,
            ts_val: self.ts_val,
            ts_ecr: self.ts_ecr,
            nagle_enabled: self.nagle_enabled,
            delayed_ack_pending: 0,
            delayed_ack_timer: 0,
        }
    }
}

impl TcpConnectionData {
    fn new(isn: u32, nodelay: bool) -> Self {
        Self {
            seq: TcpSequenceSpace {
                snd_nxt: isn,
                snd_una: isn,
                rcv_nxt: 0,
            },
            snd_wnd: 65535,
            max_snd_wnd: 65535,
            rcv_wnd: 65535,
            retransmit_count: 0,
            last_send_tick: 0,
            congestion: TcpCongestionController::new(),
            window_scale: WindowScaleOption::default_enabled(),
            flow_control: FlowController::new(),
            mss: 536,
            rcv_up: 0,
            rcv_urg: false,
            sack_enabled: false,
            ts_enabled: false,
            ts_val: 0,
            ts_ecr: 0,
            nagle_enabled: !nodelay,
            delayed_ack_pending: 0,
            delayed_ack_timer: 0,
        }
    }

    fn set_mss(&mut self, mss: u32) {
        self.mss = mss;
        self.congestion.update_mss(mss);
    }

    fn effective_send_window(&self) -> u32 {
        let scaled_rwnd = self.window_scale.scale_snd_window(self.snd_wnd);
        self.congestion.available_window(scaled_rwnd)
    }

    fn effective_recv_window(&self) -> u32 {
        self.flow_control.advertised_window()
    }

    fn advertised_recv_window(&self) -> u16 {
        self.window_scale
            .advertised_window(self.flow_control.advertised_window())
    }
}

impl From<&TcpControlBlock> for TcpControlBlockSnapshot {
    fn from(value: &TcpControlBlock) -> Self {
        let state = value.state.kind();
        let seq = value.state.sequence().unwrap_or(TcpSequenceSpace {
            snd_nxt: 0,
            snd_una: 0,
            rcv_nxt: 0,
        });
        let (
            max_snd_wnd,
            scaled_snd_wnd,
            effective_send_window,
            advertised_recv_window,
            effective_recv_window,
            mss,
            sack_enabled,
            ts_enabled,
            ts_ecr,
            nagle_enabled,
        ) = match (value.state.handshake_data(), value.state.connection_data()) {
            (Some(data), _) => {
                let scaled = data.window_scale.scale_snd_window(data.snd_wnd);
                (
                    data.max_snd_wnd,
                    scaled,
                    scaled,
                    data.rcv_wnd,
                    data.rcv_wnd as u32,
                    data.mss,
                    data.sack_enabled,
                    data.ts_enabled,
                    data.ts_ecr,
                    data.nagle_enabled,
                )
            }
            (_, Some(data)) => (
                data.max_snd_wnd,
                data.window_scale.scale_snd_window(data.snd_wnd),
                data.effective_send_window(),
                data.advertised_recv_window(),
                data.effective_recv_window(),
                data.mss,
                data.sack_enabled,
                data.ts_enabled,
                data.ts_ecr,
                data.nagle_enabled,
            ),
            _ => (0, 0, 0, 0, 0, 536, false, false, 0, true),
        };
        Self {
            socket_id: value.socket_id,
            if_id: value.if_id,
            local: value.local,
            remote: value.remote,
            state,
            snd_nxt: seq.snd_nxt,
            snd_una: seq.snd_una,
            rcv_nxt: seq.rcv_nxt,
            max_snd_wnd,
            scaled_snd_wnd,
            effective_send_window,
            advertised_recv_window,
            effective_recv_window,
            mss,
            sack_enabled,
            ts_enabled,
            ts_ecr,
            nagle_enabled,
        }
    }
}

impl TcpControlBlockSnapshot {
    pub fn effective_send_window(self) -> u32 {
        self.effective_send_window
    }

    pub fn advertised_recv_window(self) -> u16 {
        self.advertised_recv_window
    }

    pub fn effective_recv_window(self) -> u32 {
        self.effective_recv_window
    }

    pub fn is_outstanding(self) -> bool {
        self.snd_nxt != self.snd_una
    }

    pub fn should_delay_send(self, data_len: usize) -> bool {
        if data_len >= self.mss as usize {
            return false;
        }
        let sws_threshold = self.max_snd_wnd / 2;
        let scaled_rwnd = self.scaled_snd_wnd;
        if scaled_rwnd >= sws_threshold && scaled_rwnd > 0 && data_len > 0 {
        } else if self.is_outstanding() {
            return true;
        }
        if !self.nagle_enabled {
            return false;
        }
        if self.is_outstanding() {
            return true;
        }
        false
    }
}

impl TcpControlBlock {
    fn closed(
        socket_id: SocketId,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> Self {
        Self {
            socket_id,
            if_id,
            local,
            remote,
            state: TcpTcbState::Closed,
            pending_error: None,
        }
    }

    pub(crate) fn start_connect(
        socket_id: SocketId,
        local: EndpointAddr,
        remote: EndpointAddr,
        isn: u32,
        nodelay: bool,
        if_id: NetIfId,
    ) -> Self {
        let mut tcb = Self::closed(socket_id, if_id, local, remote);
        tcb.state = TcpTcbState::SynSent(TcpHandshakeData::new(isn, nodelay));
        tcb
    }

    pub fn state(&self) -> TcpConnectionState {
        self.state.kind()
    }

    fn is_state(&self, state: TcpConnectionState) -> bool {
        self.state.kind() == state
    }

    fn is_syn_received(&self) -> bool {
        self.is_state(TcpConnectionState::SynReceived)
    }

    fn last_send_tick(&self) -> u64 {
        if let Some(data) = self.state.connection_data() {
            data.last_send_tick
        } else if let Some(data) = self.state.handshake_data() {
            data.last_send_tick
        } else {
            0
        }
    }

    pub(crate) fn route_interface(&self) -> NetIfId {
        self.if_id
    }

    pub(in crate::net::l4::tcp) fn established_from_syncookie(
        socket_id: SocketId,
        local: EndpointAddr,
        remote: EndpointAddr,
        ack_num: u32,
        seq_num: u32,
        mss: u32,
        if_id: NetIfId,
    ) -> Self {
        let mut data = TcpConnectionData::new(ack_num, false);
        data.seq.snd_una = ack_num.wrapping_sub(1);
        data.seq.snd_nxt = ack_num;
        data.seq.rcv_nxt = seq_num;
        data.set_mss(mss);
        let mut tcb = Self::closed(socket_id, if_id, local, remote);
        tcb.state = TcpTcbState::Established(data);
        tcb
    }

    pub(in crate::net::l4::tcp) fn passive_open(
        socket_id: SocketId,
        local: EndpointAddr,
        remote: EndpointAddr,
        isn: u32,
        seq_num: u32,
        nodelay: bool,
        if_id: NetIfId,
        options: TcpHandshakeOptions,
    ) -> Self {
        let mut handshake = TcpHandshakeData::new(isn, nodelay);
        handshake.seq.rcv_nxt = seq_num.wrapping_add(1);
        handshake.apply_options(options);
        handshake.seq.snd_nxt = handshake.seq.snd_nxt.wrapping_add(1);
        let mut tcb = Self::closed(socket_id, if_id, local, remote);
        tcb.state = TcpTcbState::SynReceived(handshake);
        tcb
    }

    pub(in crate::net::l4::tcp) fn passive_open_syn_ack(&self) -> PassiveOpenSynAck {
        let Some(data) = self.state.handshake_data() else {
            return PassiveOpenSynAck {
                window_scale_enabled: false,
                sack_enabled: false,
                timestamp_enabled: false,
                isn: 0,
            };
        };
        PassiveOpenSynAck {
            window_scale_enabled: data.window_scale.enabled,
            sack_enabled: data.sack_enabled,
            timestamp_enabled: data.ts_enabled,
            isn: data.seq.snd_nxt.wrapping_sub(1),
        }
    }

    pub(in crate::net::l4::tcp) fn delayed_ack_due(
        &self,
        now: u64,
        timeout_ms: u64,
    ) -> Option<DelayedAckDue> {
        let data = self.state.connection_data()?;
        if data.delayed_ack_pending == 0 {
            return None;
        }
        if now.saturating_sub(data.delayed_ack_timer) < timeout_ms {
            return None;
        }
        Some(DelayedAckDue {
            if_id: self.if_id,
            local: self.local,
            remote: self.remote,
            rcv_nxt: data.seq.rcv_nxt,
            snd_nxt: data.seq.snd_nxt,
            window: self.advertised_recv_window(),
            timestamp_enabled: data.ts_enabled,
            timestamp_echo: data.ts_ecr,
        })
    }

    pub fn effective_send_window(&self) -> u32 {
        self.state
            .connection_data()
            .map_or(0, TcpConnectionData::effective_send_window)
    }

    pub fn advertised_recv_window(&self) -> u16 {
        self.state
            .connection_data()
            .map_or(65535, TcpConnectionData::advertised_recv_window)
    }

    pub fn on_ack_received(
        &mut self,
        ack_num: u32,
        is_dup: bool,
        current_time_ms: u64,
        rtt_sample_ms: u64,
    ) {
        let Some(data) = self.state.connection_data_mut() else {
            return;
        };
        let is_valid_ack = (ack_num.wrapping_sub(data.seq.snd_una) as i32) > 0
            && (ack_num.wrapping_sub(data.seq.snd_nxt) as i32) <= 0;

        let bytes_acked = if is_valid_ack && !is_dup {
            ack_num.wrapping_sub(data.seq.snd_una)
        } else {
            0
        };

        data.congestion.on_ack(
            bytes_acked,
            is_dup,
            ack_num,
            data.seq.snd_nxt,
            current_time_ms,
            rtt_sample_ms,
        );

        if !is_dup && is_valid_ack {
            data.seq.snd_una = ack_num;
        }
    }

    pub fn on_data_received(&mut self, bytes: u32) {
        if let Some(data) = self.state.connection_data_mut() {
            data.flow_control.on_receive(bytes);
            data.rcv_wnd = data.advertised_recv_window();
        }
    }

    pub fn on_data_consumed(&mut self, bytes: u32) {
        if let Some(data) = self.state.connection_data_mut() {
            data.flow_control.on_consume(bytes);
            data.rcv_wnd = data.advertised_recv_window();
        }
    }

    pub fn on_send(&mut self, bytes: u32) {
        if let Some(data) = self.state.connection_data_mut() {
            let tick = data.last_send_tick;
            data.congestion.on_send(bytes, tick);
            data.delayed_ack_pending = 0;
        }
    }

    pub fn update_peer_window(&mut self, window: u16) {
        if let Some(data) = self.state.connection_data_mut() {
            data.snd_wnd = window;
            let scaled = data.window_scale.scale_snd_window(window);
            data.flow_control.update_peer_window(scaled);
            if scaled > data.max_snd_wnd {
                data.max_snd_wnd = scaled;
            }
        } else if let Some(data) = self.state.handshake_data_mut() {
            data.snd_wnd = window;
            let scaled = data.window_scale.scale_snd_window(window);
            if scaled > data.max_snd_wnd {
                data.max_snd_wnd = scaled;
            }
        }
    }

    pub fn on_urgent_received(&mut self, seg_seq: u32, urgent_ptr: u16) -> bool {
        let Some(data) = self.state.connection_data_mut() else {
            return false;
        };
        let new_up = seg_seq.wrapping_add(urgent_ptr as u32);
        let is_newer = seq_after(new_up, data.rcv_up);
        if is_newer && new_up != data.rcv_up {
            data.rcv_up = new_up;
            data.rcv_urg = true;
            return true;
        }
        false
    }

    pub fn on_icmp_error(&mut self, error: EndpointError) {
        self.pending_error = Some(error);
    }
}

const TCB_BUCKET_COUNT: usize = 1024;

pub struct TcbTable {
    storage: PoisonRwLock<Option<TcbStorage>>,
    seq_counter: AtomicU32,
    pub current_tick: AtomicU64,
    total_count: AtomicUsize,
    syn_recv_count: AtomicUsize,
    /// SYN Cookie 用のシークレットキー
    syncookie_secret: PoisonRwLock<[u8; 32]>,
    /// ISN 生成用の安定したシークレットキー (RFC 6528)
    isn_secret: PoisonRwLock<[u8; 32]>,
    secrets_initialized: AtomicBool,
}

const MAX_TCB_ENTRIES: usize = 8192;
const MAX_SYN_RECEIVED_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TcpFlowKey {
    pub(crate) if_id: NetIfId,
    pub(crate) local: EndpointAddr,
    pub(crate) remote: EndpointAddr,
}

impl TcpFlowKey {
    pub(crate) const fn new(if_id: NetIfId, local: EndpointAddr, remote: EndpointAddr) -> Self {
        Self {
            if_id,
            local,
            remote,
        }
    }
}

struct TcbBucketEntry {
    key: TcpFlowKey,
    entry: TcpControlBlock,
    next: Option<usize>,
}

struct TcbStorage {
    entries: Vec<TcbBucketEntry>,
    buckets: [Option<usize>; TCB_BUCKET_COUNT],
}

impl TcbStorage {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_TCB_ENTRIES),
            buckets: [None; TCB_BUCKET_COUNT],
        }
    }

    fn bucket_for(key: TcpFlowKey) -> usize {
        (conn_key_hash(&key.local, &key.remote) ^ u32::from(key.if_id.0)) as usize
            % TCB_BUCKET_COUNT
    }

    fn find_index(&self, key: TcpFlowKey) -> Option<usize> {
        let bucket = Self::bucket_for(key);
        let mut cursor = self.buckets[bucket];
        while let Some(index) = cursor {
            let entry = &self.entries[index];
            if entry.key == key {
                return Some(index);
            }
            cursor = entry.next;
        }
        None
    }

    fn get(&self, key: TcpFlowKey) -> Option<&TcpControlBlock> {
        self.find_index(key).map(|index| &self.entries[index].entry)
    }

    fn get_mut(&mut self, key: TcpFlowKey) -> Option<&mut TcpControlBlock> {
        let index = self.find_index(key)?;
        Some(&mut self.entries[index].entry)
    }

    fn insert(
        &mut self,
        key: TcpFlowKey,
        entry: TcpControlBlock,
    ) -> Result<Option<TcpControlBlock>, TcpControlBlock> {
        if let Some(index) = self.find_index(key) {
            let old = core::mem::replace(&mut self.entries[index].entry, entry);
            return Ok(Some(old));
        }
        if self.entries.len() >= MAX_TCB_ENTRIES {
            return Err(entry);
        }
        let bucket = Self::bucket_for(key);
        let next = self.buckets[bucket];
        self.entries.push(TcbBucketEntry { key, entry, next });
        self.buckets[bucket] = Some(self.entries.len() - 1);
        Ok(None)
    }

    fn remove(&mut self, key: TcpFlowKey) -> Option<TcpControlBlock> {
        let index = self.find_index(key)?;
        let removed = self.entries.swap_remove(index).entry;
        self.rebuild_index();
        Some(removed)
    }

    fn remove_by_socket_id(&mut self, socket_id: SocketId) -> Option<TcpControlBlock> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.entry.socket_id == socket_id)?;
        let removed = self.entries.swap_remove(index).entry;
        self.rebuild_index();
        Some(removed)
    }

    fn rebuild_index(&mut self) {
        self.buckets = [None; TCB_BUCKET_COUNT];
        for index in 0..self.entries.len() {
            let key = self.entries[index].key;
            let bucket = Self::bucket_for(key);
            self.entries[index].next = self.buckets[bucket];
            self.buckets[bucket] = Some(index);
        }
    }
}

impl TcbTable {
    pub const fn new() -> Self {
        Self {
            storage: PoisonRwLock::new(None),
            seq_counter: AtomicU32::new(0),
            current_tick: AtomicU64::new(0),
            total_count: AtomicUsize::new(0),
            syn_recv_count: AtomicUsize::new(0),
            syncookie_secret: PoisonRwLock::new([0u8; 32]),
            isn_secret: PoisonRwLock::new([0u8; 32]),
            secrets_initialized: AtomicBool::new(false),
        }
    }

    /// シークレットキーを初期化する
    pub fn init_syncookies(&self) -> Result<(), crate::net::security::tls::crypto::RandomError> {
        if self
            .secrets_initialized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }

        if let Ok(mut secret) = self.syncookie_secret.write() {
            let random_bytes = match crate::net::security::tls::crypto::generate_random() {
                Ok(random_bytes) => random_bytes,
                Err(error) => {
                    self.secrets_initialized.store(false, Ordering::Release);
                    return Err(error);
                }
            };
            secret.copy_from_slice(&random_bytes[0..32]);
        }
        if let Ok(mut secret) = self.isn_secret.write() {
            let random_bytes = match crate::net::security::tls::crypto::generate_random() {
                Ok(random_bytes) => random_bytes,
                Err(error) => {
                    self.secrets_initialized.store(false, Ordering::Release);
                    return Err(error);
                }
            };
            secret.copy_from_slice(&random_bytes[0..32]);
        }
        log::info!("[TCP] SYN Cookies and ISN secrets initialized.");
        Ok(())
    }

    /// SYN Cookie を生成する (RFC 4987)
    pub fn generate_syncookie(
        &self,
        local: EndpointAddr,
        remote: EndpointAddr,
        client_isn: u32,
        mss_idx: u8,
    ) -> u32 {
        use crate::net::security::tls::crypto::hmac::hmac_sha256;

        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&local.as_bytes());
        data.extend_from_slice(&remote.as_bytes());
        data.extend_from_slice(&client_isn.to_be_bytes());

        // 5ビットのタイムスタンプ（分単位、32分でループ）
        let time_bits = ((self.current_tick.load(Ordering::Relaxed) / 60000) & 0x1F) as u32;
        data.extend_from_slice(&time_bits.to_be_bytes());

        // HMAC-SHA256 でハッシュ生成 (RFC 4987)
        let hash_val = if let Ok(secret) = self.syncookie_secret.read() {
            let h = hmac_sha256(&*secret, &data);
            u32::from_be_bytes([h[0], h[1], h[2], h[3]])
        } else {
            0 // フォールバック（通常は起こらない）
        };

        // Cookie 構造: [ Hash(24 bits) | Time(5 bits) | MSS Index(3 bits) ]
        (hash_val & 0xFFFFFF00) | (time_bits << 3) | (mss_idx as u32 & 0x07)
    }

    /// SYN Cookie を検証し、有効なら MSS インデックスを返す
    pub fn verify_syncookie(
        &self,
        local: EndpointAddr,
        remote: EndpointAddr,
        ack_num: u32,
        client_isn: u32,
    ) -> Option<u8> {
        use crate::net::security::tls::crypto::hmac::hmac_sha256;

        let cookie = ack_num.wrapping_sub(1);
        let mss_idx = (cookie & 0x07) as u8;
        let time_bits_received = (cookie >> 3) & 0x1F;

        let current_tick = self.current_tick.load(Ordering::Relaxed);
        let time_bits_now = (current_tick / 60000) & 0x1F;

        // タイムスタンプ有効期限チェック（最大数分間）
        let diff = (time_bits_now as i32 - time_bits_received as i32).rem_euclid(32);
        if diff > 4 {
            return None;
        }

        // ハッシュ再計算
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&local.as_bytes());
        data.extend_from_slice(&remote.as_bytes());
        data.extend_from_slice(&client_isn.to_be_bytes());
        data.extend_from_slice(&(time_bits_received as u32).to_be_bytes());

        let hash_val = if let Ok(secret) = self.syncookie_secret.read() {
            let h = hmac_sha256(&*secret, &data);
            u32::from_be_bytes([h[0], h[1], h[2], h[3]])
        } else {
            return None;
        };

        if (cookie & 0xFFFFFF00) == (hash_val & 0xFFFFFF00) {
            Some(mss_idx)
        } else {
            None
        }
    }

    /// RFC 6528 準拠の初期シーケンス番号 (ISN) 生成
    pub fn generate_isn(&self, local: EndpointAddr, remote: EndpointAddr) -> u32 {
        use crate::net::security::tls::crypto::hmac::hmac_sha256;

        // ISN = M + F(local, remote, secret)
        // M: 4マイクロ秒精度のタイマー (ここでは tick * 250 で近似)
        let m = (self.current_tick.load(Ordering::Relaxed) as u32).wrapping_mul(250);

        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&local.as_bytes());
        data.extend_from_slice(&remote.as_bytes());

        let hash_f = if let Ok(secret) = self.isn_secret.read() {
            let h = hmac_sha256(&*secret, &data);
            u32::from_be_bytes([h[0], h[1], h[2], h[3]])
        } else {
            0
        };

        let counter = self.seq_counter.fetch_add(1, Ordering::Relaxed);
        m.wrapping_add(hash_f).wrapping_add(counter)
    }

    pub fn tick(&self, runtime: NetRuntimeHandle) {
        let tick = self.current_tick.fetch_add(1, Ordering::Relaxed);
        if tick % 100 == 0 {
            super::retransmit::check_retransmit_timeouts(runtime);
            self.check_zero_window_probes(runtime, tick);
            self.scavenge_syn_received(tick);
            self.scavenge_time_wait(tick);
            self.scavenge_fin_wait_2(tick);
        }
    }

    fn scavenge_fin_wait_2(&self, current_tick: u64) {
        const FIN_WAIT_2_TIMEOUT_TICKS: u64 = 60_000;
        const MAX_SCAVENGE_FIN_WAIT_2: usize = 128;
        let mut guard = self.storage.write().unwrap_or_else(|e| e.into_inner());
        let Some(entries) = guard.as_mut() else {
            return;
        };
        let mut to_remove: Vec<TcpFlowKey> = Vec::new();
        for bucket_entry in entries.entries.iter() {
            let entry = &bucket_entry.entry;
            if entry.is_state(TcpConnectionState::FinWait2)
                && current_tick.saturating_sub(entry.last_send_tick()) > FIN_WAIT_2_TIMEOUT_TICKS
            {
                to_remove.push(bucket_entry.key);
                if to_remove.len() >= MAX_SCAVENGE_FIN_WAIT_2 {
                    break;
                }
            }
        }
        for key in to_remove {
            entries.remove(key);
            self.total_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn check_zero_window_probes(&self, runtime: NetRuntimeHandle, current_tick: u64) {
        use super::retransmit::retransmit_queue_push;
        use super::segment::TcpSegmentBuilder;
        use crate::net::l4::socket::lookup_socket_in;
        let mut guard = self.storage.write().unwrap_or_else(|e| e.into_inner());
        let Some(entries) = guard.as_mut() else {
            return;
        };
        for bucket_entry in entries.entries.iter_mut() {
            let key = bucket_entry.key;
            let entry = &mut bucket_entry.entry;
            if !matches!(entry.state.kind(), TcpConnectionState::Established) {
                continue;
            }
            let Some(data) = entry.state.connection_data_mut() else {
                continue;
            };
            if data.seq.snd_nxt != data.seq.snd_una {
                continue;
            }
            if !data.flow_control.should_send_probe(current_tick) {
                continue;
            }
            if let Some(socket) = lookup_socket_in(runtime, entry.socket_id) {
                if let Some(probe_payload) = socket
                    .with_inner_mut(|inner| inner.take_send_segment_window(1))
                    .flatten()
                {
                    let seq = data.seq.snd_nxt;
                    let mut builder = TcpSegmentBuilder::new(key.local.port(), key.remote.port())
                        .seq(seq)
                        .ack(data.seq.rcv_nxt)
                        .ack_flag()
                        .psh()
                        .window(data.advertised_recv_window())
                        .payload_packet(probe_payload);
                    if data.ts_enabled {
                        let ts_val = (current_tick / 10) as u32;
                        builder = builder.nop().nop().timestamp(ts_val, data.ts_ecr);
                    }
                    let Ok(segment) = builder.build_checked_packet(key.local, key.remote) else {
                        continue;
                    };
                    retransmit_queue_push(
                        runtime, key.if_id, key.local, key.remote, seq, 1, segment,
                    );
                    if super::retransmit::retransmit_queue_transmit_ready(
                        runtime, key.if_id, key.local, key.remote, seq,
                    ) {
                        data.seq.snd_nxt = data.seq.snd_nxt.wrapping_add(1);
                        data.flow_control.on_probe_sent(current_tick);
                    } else {
                        log::warn!(
                            "[TCP] zero-window probe TX ownership transition failed for {} -> {}",
                            key.local,
                            key.remote
                        );
                    }
                }
            }
        }
    }

    fn scavenge_time_wait(&self, current_tick: u64) {
        const TIME_WAIT_TIMEOUT_TICKS: u64 = 240_000;
        const MAX_SCAVENGE_TIME_WAIT: usize = 256;
        let mut guard = self.storage.write().unwrap_or_else(|e| e.into_inner());
        let Some(entries) = guard.as_mut() else {
            return;
        };
        let mut to_remove: Vec<TcpFlowKey> = Vec::new();
        for bucket_entry in entries.entries.iter() {
            let entry = &bucket_entry.entry;
            if entry.is_state(TcpConnectionState::TimeWait)
                && current_tick.saturating_sub(entry.last_send_tick()) > TIME_WAIT_TIMEOUT_TICKS
            {
                to_remove.push(bucket_entry.key);
                if to_remove.len() >= MAX_SCAVENGE_TIME_WAIT {
                    break;
                }
            }
        }
        for key in to_remove {
            entries.remove(key);
        }
    }

    fn scavenge_syn_received(&self, current_tick: u64) {
        // 通常のタイムアウト: 3秒
        const SYN_RECV_TIMEOUT_TICKS: u64 = 3000;
        // 圧迫時のタイムアウト: 500ms
        const AGGRESSIVE_TIMEOUT_TICKS: u64 = 500;

        let count = self.syn_recv_count.load(Ordering::Relaxed);
        if count < MAX_SYN_RECEIVED_ENTRIES / 4 {
            return;
        }

        // 負荷に応じてタイムアウトを短縮し、1回のスキャンで消去する数を増やす
        let (timeout, max_per_shard) = if count > (MAX_SYN_RECEIVED_ENTRIES * 3 / 4) {
            (AGGRESSIVE_TIMEOUT_TICKS, 32) // 高負荷時
        } else {
            (SYN_RECV_TIMEOUT_TICKS, 8) // 低・中負荷時
        };

        let mut guard = self.storage.write().unwrap_or_else(|e| e.into_inner());
        let Some(entries) = guard.as_mut() else {
            return;
        };
        let mut to_remove: alloc::vec::Vec<TcpFlowKey> =
            alloc::vec::Vec::with_capacity(max_per_shard);
        for bucket_entry in entries.entries.iter() {
            let entry = &bucket_entry.entry;
            if entry.is_syn_received()
                && current_tick.saturating_sub(entry.last_send_tick()) > timeout
            {
                to_remove.push(bucket_entry.key);
                if to_remove.len() >= max_per_shard {
                    break;
                }
            }
        }
        for key in to_remove {
            if let Some(entry) = entries.remove(key) {
                self.total_count.fetch_sub(1, Ordering::Relaxed);
                if entry.is_syn_received() {
                    self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub fn get_current_tick(&self) -> u64 {
        self.current_tick.load(Ordering::Relaxed)
    }

    /// 受信済みの SYN の数
    pub fn syn_recv_count(&self) -> usize {
        self.syn_recv_count.load(Ordering::Relaxed)
    }

    pub fn insert(&self, entry: TcpControlBlock) -> Result<(), &'static str> {
        if self.total_count.load(Ordering::Relaxed) >= MAX_TCB_ENTRIES {
            return Err("TCB table full");
        }
        if entry.is_syn_received() {
            if self.syn_recv_count.load(Ordering::Relaxed) >= MAX_SYN_RECEIVED_ENTRIES {
                return Err("Too many SYN-RECV connections");
            }
        }
        let key = TcpFlowKey::new(entry.if_id, entry.local, entry.remote);
        let mut shard = self.storage.write().unwrap_or_else(|e| e.into_inner());
        let storage = shard.get_or_insert_with(TcbStorage::new);
        let is_syn_recv = entry.is_syn_received();
        match storage.insert(key, entry) {
            Ok(None) => {
                self.total_count.fetch_add(1, Ordering::Relaxed);
                if is_syn_recv {
                    self.syn_recv_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(Some(old)) => {
                if old.is_syn_received() && !is_syn_recv {
                    self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
                } else if !old.is_syn_received() && is_syn_recv {
                    self.syn_recv_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(_) => return Err("TCB shard full"),
        }
        Ok(())
    }

    pub fn read<R, F>(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        f: F,
    ) -> Option<R>
    where
        F: FnOnce(&TcpControlBlock) -> R,
    {
        let shard = self.storage.read().unwrap_or_else(|e| e.into_inner());
        shard
            .as_ref()?
            .get(TcpFlowKey::new(if_id, local, remote))
            .map(f)
    }

    pub fn read_by_socket_id<R, F>(&self, socket_id: SocketId, f: F) -> Option<R>
    where
        F: FnOnce(&TcpControlBlock) -> R,
    {
        let shard = self.storage.read().unwrap_or_else(|e| e.into_inner());
        shard
            .as_ref()?
            .entries
            .iter()
            .find(|bucket_entry| bucket_entry.entry.socket_id == socket_id)
            .map(|bucket_entry| f(&bucket_entry.entry))
    }

    fn mutate_entry<F>(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        f: F,
    ) -> bool
    where
        F: FnOnce(&mut TcpControlBlock),
    {
        let mut shard = self.storage.write().unwrap_or_else(|e| e.into_inner());
        let Some(storage) = shard.as_mut() else {
            return false;
        };
        if let Some(entry) = storage.get_mut(TcpFlowKey::new(if_id, local, remote)) {
            let old_state = entry.state.kind();
            f(entry);
            let new_state = entry.state.kind();
            if old_state != new_state {
                if old_state == TcpConnectionState::SynReceived {
                    self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
                }
                if new_state == TcpConnectionState::SynReceived {
                    self.syn_recv_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            true
        } else {
            false
        }
    }

    fn mutate_by_socket_id<F>(&self, socket_id: SocketId, f: F) -> bool
    where
        F: FnOnce(&mut TcpControlBlock),
    {
        let mut shard = self.storage.write().unwrap_or_else(|e| e.into_inner());
        let Some(storage) = shard.as_mut() else {
            return false;
        };
        let Some(entry) = storage
            .entries
            .iter_mut()
            .find(|bucket_entry| bucket_entry.entry.socket_id == socket_id)
            .map(|bucket_entry| &mut bucket_entry.entry)
        else {
            return false;
        };
        let old_state = entry.state.kind();
        f(entry);
        let new_state = entry.state.kind();
        if old_state != new_state {
            if old_state == TcpConnectionState::SynReceived {
                self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
            }
            if new_state == TcpConnectionState::SynReceived {
                self.syn_recv_count.fetch_add(1, Ordering::Relaxed);
            }
        }
        true
    }

    pub(crate) fn record_data_received_by_socket_id(
        &self,
        socket_id: SocketId,
        bytes: u32,
    ) -> bool {
        self.mutate_by_socket_id(socket_id, |entry| entry.on_data_received(bytes))
    }

    pub(crate) fn record_data_consumed_by_socket_id(
        &self,
        socket_id: SocketId,
        bytes: u32,
    ) -> bool {
        self.mutate_by_socket_id(socket_id, |entry| entry.on_data_consumed(bytes))
    }

    pub(in crate::net::l4::tcp) fn update_peer_window(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        window: u16,
    ) -> bool {
        self.mutate_entry(if_id, local, remote, |entry| {
            entry.update_peer_window(window)
        })
    }

    pub(in crate::net::l4::tcp) fn record_ack_received(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        ack_num: u32,
        is_dup: bool,
        current_time_ms: u64,
        rtt_sample_ms: u64,
    ) -> bool {
        self.mutate_entry(if_id, local, remote, |entry| {
            entry.on_ack_received(ack_num, is_dup, current_time_ms, rtt_sample_ms);
        })
    }

    pub(in crate::net::l4::tcp) fn record_receive_progress(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        rcv_nxt: u32,
    ) -> bool {
        self.mutate_entry(if_id, local, remote, |entry| {
            if let Some(seq) = entry.state.sequence_mut() {
                seq.rcv_nxt = rcv_nxt;
            }
        })
    }

    pub(in crate::net::l4::tcp) fn record_receive_progress_with_delayed_ack(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        rcv_nxt: u32,
        current_tick: u64,
        timestamp_echo: Option<(u32, u32)>,
    ) -> Option<u8> {
        let mut pending = None;
        self.mutate_entry(if_id, local, remote, |entry| {
            let Some(data) = entry.state.connection_data_mut() else {
                return;
            };
            data.seq.rcv_nxt = rcv_nxt;
            if data.delayed_ack_pending == 0 {
                data.delayed_ack_timer = current_tick;
            }
            data.delayed_ack_pending = data.delayed_ack_pending.saturating_add(1);

            if data.ts_enabled {
                if let Some((peer_ts_val, local_ts_val)) = timestamp_echo {
                    data.ts_ecr = peer_ts_val;
                    data.ts_val = local_ts_val;
                }
            }
            pending = Some(data.delayed_ack_pending);
        })
        .then_some(())?;
        pending
    }

    pub(in crate::net::l4::tcp) fn clear_delayed_ack(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> bool {
        self.mutate_entry(if_id, local, remote, |entry| {
            if let Some(data) = entry.state.connection_data_mut() {
                data.delayed_ack_pending = 0;
            }
        })
    }

    pub(in crate::net::l4::tcp) fn record_timestamp_echo(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        peer_ts_val: u32,
        local_ts_val: u32,
    ) -> bool {
        self.mutate_entry(if_id, local, remote, |entry| {
            if let Some(data) = entry.state.connection_data_mut() {
                data.ts_ecr = peer_ts_val;
                data.ts_val = local_ts_val;
            } else if let Some(data) = entry.state.handshake_data_mut() {
                data.ts_ecr = peer_ts_val;
                data.ts_val = local_ts_val;
            }
        })
    }

    pub(in crate::net::l4::tcp) fn enter_simultaneous_syn_received(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        seq_num: u32,
        options: TcpHandshakeOptions,
    ) -> bool {
        let mut accepted = false;
        self.mutate_entry(if_id, local, remote, |entry| {
            let old = core::mem::replace(&mut entry.state, TcpTcbState::Closed);
            match old {
                TcpTcbState::SynSent(mut data) => {
                    data.seq.rcv_nxt = seq_num.wrapping_add(1);
                    data.apply_options(options);
                    entry.state = TcpTcbState::SynReceived(data);
                    accepted = true;
                }
                other => {
                    entry.state = other;
                }
            }
        });
        accepted
    }

    pub(in crate::net::l4::tcp) fn establish_syn_received(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        ack_num: u32,
    ) -> bool {
        let mut accepted = false;
        self.mutate_entry(if_id, local, remote, |entry| {
            let old = core::mem::replace(&mut entry.state, TcpTcbState::Closed);
            match old {
                TcpTcbState::SynReceived(mut data) => {
                    data.seq.snd_una = ack_num;
                    entry.state = TcpTcbState::Established(data.into_connection());
                    accepted = true;
                }
                other => {
                    entry.state = other;
                }
            }
        });
        accepted
    }

    pub(in crate::net::l4::tcp) fn establish_from_syn_ack(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        seq_num: u32,
        ack_num: u32,
        options: TcpHandshakeOptions,
    ) -> bool {
        let mut accepted = false;
        self.mutate_entry(if_id, local, remote, |entry| {
            let old = core::mem::replace(&mut entry.state, TcpTcbState::Closed);
            match old {
                TcpTcbState::SynSent(mut data) => {
                    data.seq.rcv_nxt = seq_num.wrapping_add(1);
                    data.seq.snd_una = ack_num;
                    data.apply_options(options);
                    entry.state = TcpTcbState::Established(data.into_connection());
                    accepted = true;
                }
                other => {
                    entry.state = other;
                }
            }
        });
        accepted
    }

    pub(in crate::net::l4::tcp) fn record_icmp_error(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        error: EndpointError,
    ) -> Option<SocketId> {
        let mut failed_socket = None;
        self.mutate_entry(if_id, local, remote, |entry| {
            if entry.is_state(TcpConnectionState::SynSent) {
                match error {
                    EndpointError::ConnectionRefused | EndpointError::ProtocolUnreachable => {
                        failed_socket = Some(entry.socket_id);
                    }
                    _ => {}
                }
            }
            entry.on_icmp_error(error);
        })
        .then_some(())?;
        failed_socket
    }

    pub(in crate::net::l4::tcp) fn close_for_reset(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> bool {
        self.mutate_entry(if_id, local, remote, |entry| {
            entry.state = TcpTcbState::Closed;
        })
    }

    pub(in crate::net::l4::tcp) fn record_ack_and_close_progress(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        ack_num: u32,
        is_dup: bool,
        current_time_ms: u64,
    ) -> Option<bool> {
        let mut should_remove = false;
        self.mutate_entry(if_id, local, remote, |entry| {
            entry.on_ack_received(ack_num, is_dup, current_time_ms, 0);

            if !is_dup {
                let old = core::mem::replace(&mut entry.state, TcpTcbState::Closed);
                entry.state = match old {
                    TcpTcbState::FinWait1(mut data) => {
                        data.retransmit_count = 0;
                        if ack_num == data.seq.snd_nxt {
                            TcpTcbState::FinWait2(data)
                        } else {
                            TcpTcbState::FinWait1(data)
                        }
                    }
                    TcpTcbState::Closing(mut data) => {
                        data.retransmit_count = 0;
                        if ack_num == data.seq.snd_nxt {
                            TcpTcbState::TimeWait(data)
                        } else {
                            TcpTcbState::Closing(data)
                        }
                    }
                    TcpTcbState::LastAck(mut data) => {
                        data.retransmit_count = 0;
                        if ack_num == data.seq.snd_nxt {
                            should_remove = true;
                            TcpTcbState::Closed
                        } else {
                            TcpTcbState::LastAck(data)
                        }
                    }
                    TcpTcbState::Established(mut data) => {
                        data.retransmit_count = 0;
                        TcpTcbState::Established(data)
                    }
                    TcpTcbState::FinWait2(mut data) => {
                        data.retransmit_count = 0;
                        TcpTcbState::FinWait2(data)
                    }
                    TcpTcbState::CloseWait(mut data) => {
                        data.retransmit_count = 0;
                        TcpTcbState::CloseWait(data)
                    }
                    TcpTcbState::TimeWait(mut data) => {
                        data.retransmit_count = 0;
                        TcpTcbState::TimeWait(data)
                    }
                    other => other,
                };
            }
        })
        .then_some(should_remove)
    }

    pub(in crate::net::l4::tcp) fn set_socket_id(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        socket_id: SocketId,
    ) -> bool {
        self.mutate_entry(if_id, local, remote, |entry| {
            entry.socket_id = socket_id;
        })
    }

    pub(in crate::net::l4::tcp) fn record_fin_received(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        rcv_nxt_at_fin: u32,
        current_tick: u64,
    ) -> Option<(u32, bool)> {
        let mut should_ack = false;
        let mut final_rcv_nxt = rcv_nxt_at_fin;
        self.mutate_entry(if_id, local, remote, |entry| {
            if let Some(seq) = entry.state.sequence_mut() {
                seq.rcv_nxt = rcv_nxt_at_fin.wrapping_add(1);
                final_rcv_nxt = seq.rcv_nxt;
            }

            let old = core::mem::replace(&mut entry.state, TcpTcbState::Closed);
            entry.state = match old {
                TcpTcbState::Established(data) => {
                    should_ack = true;
                    log::info!(
                        "[TCP] FIN received in ESTABLISHED: {} <- {} -> CLOSE_WAIT",
                        entry.local,
                        entry.remote
                    );
                    TcpTcbState::CloseWait(data)
                }
                TcpTcbState::FinWait1(data) => {
                    should_ack = true;
                    log::info!(
                        "[TCP] FIN received in FIN_WAIT_1: {} <- {} -> CLOSING",
                        entry.local,
                        entry.remote
                    );
                    TcpTcbState::Closing(data)
                }
                TcpTcbState::FinWait2(mut data) => {
                    data.last_send_tick = current_tick;
                    should_ack = true;
                    log::info!(
                        "[TCP] FIN received in FIN_WAIT_2: {} <- {} -> TIME_WAIT",
                        entry.local,
                        entry.remote
                    );
                    TcpTcbState::TimeWait(data)
                }
                other => {
                    should_ack = true;
                    other
                }
            };
        })
        .then_some((final_rcv_nxt, should_ack))
    }

    pub(in crate::net::l4::tcp) fn record_urgent_received(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        seq_num: u32,
        urgent_ptr: u16,
    ) -> Option<SocketId> {
        let mut socket_id = None;
        self.mutate_entry(if_id, local, remote, |entry| {
            if entry.on_urgent_received(seq_num, urgent_ptr) {
                socket_id = Some(entry.socket_id);
            }
        })
        .then_some(())?;
        socket_id
    }

    pub(crate) fn mark_payload_sent(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        bytes: u32,
    ) -> bool {
        self.mutate_entry(if_id, local, remote, |entry| {
            entry.on_send(bytes);
            if let Some(seq) = entry.state.sequence_mut() {
                seq.snd_nxt = seq.snd_nxt.wrapping_add(bytes);
            }
        })
    }

    pub(crate) fn mark_syn_sent(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> bool {
        self.mutate_entry(if_id, local, remote, |entry| {
            if let Some(seq) = entry.state.sequence_mut() {
                seq.snd_nxt = seq.snd_nxt.wrapping_add(1);
            }
        })
    }

    pub(crate) fn begin_active_close(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> Option<u32> {
        let mut seq = None;
        self.mutate_entry(if_id, local, remote, |entry| {
            let old = core::mem::replace(&mut entry.state, TcpTcbState::Closed);
            entry.state = match old {
                TcpTcbState::Established(mut data) => {
                    seq = Some(data.seq.snd_nxt);
                    data.seq.snd_nxt = data.seq.snd_nxt.wrapping_add(1);
                    TcpTcbState::FinWait1(data)
                }
                other => other,
            };
        });
        seq
    }

    pub(crate) fn begin_passive_close_ack(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> Option<u32> {
        let mut seq = None;
        self.mutate_entry(if_id, local, remote, |entry| {
            let old = core::mem::replace(&mut entry.state, TcpTcbState::Closed);
            entry.state = match old {
                TcpTcbState::CloseWait(mut data) => {
                    seq = Some(data.seq.snd_nxt);
                    data.seq.snd_nxt = data.seq.snd_nxt.wrapping_add(1);
                    TcpTcbState::LastAck(data)
                }
                other => other,
            };
        });
        seq
    }

    pub fn remove(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> Option<TcpControlBlock> {
        let mut shard = self.storage.write().unwrap_or_else(|e| e.into_inner());
        let storage = shard.as_mut()?;
        if let Some(entry) = storage.remove(TcpFlowKey::new(if_id, local, remote)) {
            self.total_count.fetch_sub(1, Ordering::Relaxed);
            if entry.is_syn_received() {
                self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
            }
            Some(entry)
        } else {
            None
        }
    }

    pub fn remove_by_socket_id(&self, socket_id: SocketId) -> Option<TcpControlBlock> {
        let mut guard = self.storage.write().unwrap_or_else(|e| e.into_inner());
        if let Some(storage) = guard.as_mut() {
            if let Some(entry) = storage.remove_by_socket_id(socket_id) {
                self.total_count.fetch_sub(1, Ordering::Relaxed);
                if entry.is_syn_received() {
                    self.syn_recv_count.fetch_sub(1, Ordering::Relaxed);
                }
                return Some(entry);
            }
        }
        None
    }

    pub fn list_connections(&self) -> alloc::vec::Vec<TcpConnectionSnapshot> {
        let mut result = alloc::vec::Vec::new();
        let guard = self.storage.read().unwrap_or_else(|e| e.into_inner());
        if let Some(storage) = guard.as_ref() {
            result.extend(storage.entries.iter().map(|bucket_entry| {
                let entry = &bucket_entry.entry;
                TcpConnectionSnapshot {
                    local: entry.local,
                    remote: entry.remote,
                    state: entry.state.kind(),
                }
            }));
        }
        result
    }

    pub fn validate_icmp_sequence(
        &self,
        if_id: NetIfId,
        local: EndpointAddr,
        remote: EndpointAddr,
        seq: u32,
    ) -> bool {
        if let Some(snapshot) = self.read(if_id, local, remote, |entry| {
            TcpControlBlockSnapshot::from(entry)
        }) {
            if snapshot.state == TcpConnectionState::SynSent {
                return seq == snapshot.snd_una;
            }
            match snapshot.state {
                TcpConnectionState::Closed | TcpConnectionState::Listen => return false,
                _ => {}
            }
            let una = snapshot.snd_una;
            let nxt = snapshot.snd_nxt;
            let diff_una = seq.wrapping_sub(una);
            let diff_nxt = nxt.wrapping_sub(una);
            return diff_una <= diff_nxt;
        }
        false
    }

    pub fn for_each_established<F>(&self, mut f: F)
    where
        F: FnMut(&TcpControlBlock),
    {
        let guard = self.storage.read().unwrap_or_else(|e| e.into_inner());
        if let Some(storage) = guard.as_ref() {
            for bucket_entry in &storage.entries {
                let entry = &bucket_entry.entry;
                if entry.is_state(TcpConnectionState::Established) {
                    f(entry);
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct TcpConnectionSnapshot {
    pub local: EndpointAddr,
    pub remote: EndpointAddr,
    pub state: TcpConnectionState,
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const TEST_IF: NetIfId = NetIfId(7);

    fn test_endpoints() -> (EndpointAddr, EndpointAddr) {
        (
            EndpointAddr::new([192, 168, 1, 1], 12345),
            EndpointAddr::new([192, 168, 1, 2], 80),
        )
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_connection_state() {
        let state = TcpConnectionState::Closed;
        assert!(matches!(state, TcpConnectionState::Closed));
        let state = TcpConnectionState::Established;
        assert!(matches!(state, TcpConnectionState::Established));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_closed_has_no_sequence_space() {
        let socket_id = SocketId::from_raw(1);
        let local = EndpointAddr::new([192, 168, 1, 1], 12345);
        let remote = EndpointAddr::new([192, 168, 1, 2], 80);
        let tcb = TcpControlBlock::closed(socket_id, TEST_IF, local, remote);
        assert_eq!(tcb.state(), TcpConnectionState::Closed);
        let snapshot = TcpControlBlockSnapshot::from(&tcb);
        assert_eq!(snapshot.snd_nxt, 0);
        assert_eq!(snapshot.snd_una, 0);
        assert_eq!(snapshot.rcv_nxt, 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_tcb_table_syn_sent_to_established() {
        let table = TcbTable::new();
        let (local, remote) = test_endpoints();
        let tcb = TcpControlBlock::start_connect(
            SocketId::from_raw(2),
            local,
            remote,
            1000,
            false,
            TEST_IF,
        );
        table.insert(tcb).expect("insert syn-sent tcb");
        assert!(table.mark_syn_sent(TEST_IF, local, remote));

        assert!(table.establish_from_syn_ack(
            TEST_IF,
            local,
            remote,
            2000,
            1001,
            TcpHandshakeOptions::default(),
        ));

        let snapshot = table
            .read(TEST_IF, local, remote, TcpControlBlockSnapshot::from)
            .expect("established tcb snapshot");
        assert_eq!(snapshot.state, TcpConnectionState::Established);
        assert_eq!(snapshot.snd_una, 1001);
        assert_eq!(snapshot.rcv_nxt, 2001);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_tcb_table_syn_received_count_tracks_establish() {
        let table = TcbTable::new();
        let (local, remote) = test_endpoints();
        let tcb = TcpControlBlock::passive_open(
            SocketId::from_raw(3),
            local,
            remote,
            7000,
            3000,
            false,
            TEST_IF,
            TcpHandshakeOptions::default(),
        );
        table.insert(tcb).expect("insert syn-received tcb");

        assert_eq!(table.syn_recv_count(), 1);
        assert!(table.establish_syn_received(TEST_IF, local, remote, 7001));
        assert_eq!(table.syn_recv_count(), 0);

        let state = table
            .read(TEST_IF, local, remote, |entry| {
                TcpControlBlockSnapshot::from(entry).state
            })
            .expect("established tcb state");
        assert_eq!(state, TcpConnectionState::Established);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_tcb_table_rejects_invalid_transition() {
        let table = TcbTable::new();
        let (local, remote) = test_endpoints();
        let tcb = TcpControlBlock::closed(SocketId::from_raw(4), TEST_IF, local, remote);
        table.insert(tcb).expect("insert closed tcb");

        assert!(!table.establish_syn_received(TEST_IF, local, remote, 1));
        assert!(table.begin_active_close(TEST_IF, local, remote).is_none());
        assert!(
            table
                .begin_passive_close_ack(TEST_IF, local, remote)
                .is_none()
        );

        let state = table
            .read(TEST_IF, local, remote, |entry| {
                TcpControlBlockSnapshot::from(entry).state
            })
            .expect("closed tcb state");
        assert_eq!(state, TcpConnectionState::Closed);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_tcb_table_established_close_transitions() {
        let table = TcbTable::new();
        let (local, remote) = test_endpoints();
        let tcb = TcpControlBlock::start_connect(
            SocketId::from_raw(5),
            local,
            remote,
            9000,
            false,
            TEST_IF,
        );
        table.insert(tcb).expect("insert syn-sent tcb");
        assert!(table.mark_syn_sent(TEST_IF, local, remote));
        assert!(table.establish_from_syn_ack(
            TEST_IF,
            local,
            remote,
            4000,
            9001,
            TcpHandshakeOptions::default(),
        ));

        assert_eq!(table.begin_active_close(TEST_IF, local, remote), Some(9001));
        let snapshot = table
            .read(TEST_IF, local, remote, TcpControlBlockSnapshot::from)
            .expect("fin-wait tcb snapshot");
        assert_eq!(snapshot.state, TcpConnectionState::FinWait1);
        assert_eq!(snapshot.snd_nxt, 9002);

        let (final_rcv_nxt, should_ack) = table
            .record_fin_received(TEST_IF, local, remote, snapshot.rcv_nxt, 123)
            .expect("fin receive transition");
        assert!(should_ack);
        assert_eq!(final_rcv_nxt, snapshot.rcv_nxt.wrapping_add(1));
        let state = table
            .read(TEST_IF, local, remote, |entry| {
                TcpControlBlockSnapshot::from(entry).state
            })
            .expect("closing tcb state");
        assert_eq!(state, TcpConnectionState::Closing);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_tcb_table_separates_identical_five_tuple_by_interface() {
        let table = TcbTable::new();
        let (local, remote) = test_endpoints();
        let other_if = NetIfId(8);
        table
            .insert(TcpControlBlock::closed(
                SocketId::from_raw(10),
                TEST_IF,
                local,
                remote,
            ))
            .expect("insert first interface flow");
        table
            .insert(TcpControlBlock::closed(
                SocketId::from_raw(11),
                other_if,
                local,
                remote,
            ))
            .expect("insert second interface flow");

        assert_eq!(
            table.read(TEST_IF, local, remote, |entry| entry.socket_id),
            Some(SocketId::from_raw(10))
        );
        assert_eq!(
            table.read(other_if, local, remote, |entry| entry.socket_id),
            Some(SocketId::from_raw(11))
        );
        assert_eq!(table.total_count.load(Ordering::Relaxed), 2);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_tcp_flags() {
        assert_eq!(tcp_flags::FIN, 0x01);
        assert_eq!(tcp_flags::SYN, 0x02);
        assert_eq!(tcp_flags::RST, 0x04);
        assert_eq!(tcp_flags::PSH, 0x08);
        assert_eq!(tcp_flags::ACK, 0x10);
        let syn_ack = tcp_flags::SYN | tcp_flags::ACK;
        assert_eq!(syn_ack, 0x12);
    }
}
