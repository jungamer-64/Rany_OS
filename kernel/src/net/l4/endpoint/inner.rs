// ============================================================================
// kernel/src/net/l4/endpoint/inner.rs
// ============================================================================
//! # EndpointInner - 細粒度ロック用の内部状態
//!
//! ソケットの可変状態（Mutex保護対象）
//!
//! ## プロトコル分離
//!
//! TCP固有・UDP固有のフィールドは [`ProtocolState`] enumで分離し、
//! 不可能な状態（TCP + UDPが同時に存在）を型レベルで排除する。

use alloc::collections::VecDeque;

use crate::net::l4::tcp::TcpStats;
use crate::net::l4::udp::UdpEndpoint as RawUdpSocket;
use crate::net::payload::PacketPayloadView;
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use kernel_api::resource::net::{PacketChain, PacketPayload};

use super::congestion::CongestionAlgorithm;
use super::types::{
    AcceptedConnection, EndpointAddr, EndpointError, EndpointResult, EndpointState,
};

// ============================================================================
// プロトコル固有の状態
// ============================================================================

/// TCP固有のプロトコル状態
pub struct TcpProtocolState {
    /// Acceptキュー: ハンドシェイク完了済みの接続
    pub accept_queue: VecDeque<AcceptedConnection>,
    /// Acceptキューのバックログサイズ
    pub accept_backlog: usize,
    /// Packet-backed receive queue owned by the endpoint.
    pub recv_payload_queue: VecDeque<PacketPayload>,
    /// Total queued bytes in `recv_payload_queue`.
    pub recv_payload_bytes: usize,
    /// Packet-backed send queue owned by the endpoint.
    pub send_payload_queue: VecDeque<PacketPayload>,
    /// Total queued bytes in `send_payload_queue`.
    pub send_payload_bytes: usize,
    /// TCP_NODELAY (Nagleアルゴリズム無効化)
    pub nodelay: bool,
    /// Urgent data pending flag (TCP OOB data)
    pub urgent_pending: bool,
    /// 輻輳制御アルゴリズム選択（TCB作成時に使用）
    pub congestion_algorithm: Option<CongestionAlgorithm>,
    /// TCP statistics snapshot for the endpoint-backed stream API.
    pub stats: TcpStats,
}

impl TcpProtocolState {
    /// デフォルトのAcceptバックログサイズ
    pub const DEFAULT_BACKLOG: usize = 128;

    /// 新規作成
    pub fn new() -> Self {
        Self {
            accept_queue: VecDeque::with_capacity(Self::DEFAULT_BACKLOG),
            accept_backlog: Self::DEFAULT_BACKLOG,
            recv_payload_queue: VecDeque::new(),
            recv_payload_bytes: 0,
            send_payload_queue: VecDeque::new(),
            send_payload_bytes: 0,
            nodelay: false,
            urgent_pending: false,
            congestion_algorithm: None,
            stats: TcpStats::default(),
        }
    }
}

impl Default for TcpProtocolState {
    fn default() -> Self {
        Self::new()
    }
}

/// UDP固有のプロトコル状態
pub struct UdpProtocolState {
    /// UDPソケット
    pub socket: Option<RawUdpSocket>,
    /// 保留中のパケット
    pub pending_packets: VecDeque<(NetIfId, EndpointAddr, PacketPayload)>,
}

impl UdpProtocolState {
    /// 新規作成
    pub fn new() -> Self {
        Self {
            socket: None,
            pending_packets: VecDeque::with_capacity(16),
        }
    }
}

impl Default for UdpProtocolState {
    fn default() -> Self {
        Self::new()
    }
}

/// RAW固有のプロトコル状態
pub struct RawProtocolState {
    /// 保留中のIPパケット
    pub pending_payloads: VecDeque<(NetIfId, PacketPayload)>,
}

impl RawProtocolState {
    pub fn new() -> Self {
        Self {
            pending_payloads: VecDeque::with_capacity(16),
        }
    }
}

impl Default for RawProtocolState {
    fn default() -> Self {
        Self::new()
    }
}

/// プロトコル固有の内部状態
///
/// TCP/UDPの状態を排他的に保持し、
/// 不可能な状態（例: TCP + UDPが同時にアクティブ）を型レベルで防ぐ。
pub enum ProtocolState {
    /// プロトコル未確定（作成直後）
    Unset,
    /// TCP接続/リスナー
    Tcp(TcpProtocolState),
    /// UDPソケット
    Udp(UdpProtocolState),
    /// RAW IPソケット
    Raw(RawProtocolState),
}

impl Default for ProtocolState {
    fn default() -> Self {
        Self::Unset
    }
}

// ============================================================================
// EndpointInner
// ============================================================================

/// ソケットの可変状態（Mutex保護対象）
pub struct EndpointInner {
    /// 現在の状態
    pub state: EndpointState,
    /// ローカルアドレス
    pub local_addr: Option<EndpointAddr>,
    /// リモートアドレス
    pub remote_addr: Option<EndpointAddr>,
    /// このソケットに適用されたインターフェース選択ポリシー
    pub scope: InterfaceScope,
    /// 直近の ingress/accept インターフェース
    pub last_ingress_if_id: Option<NetIfId>,
    /// 受信バッファ上限
    pub recv_buffer_limit: usize,
    /// 送信バッファ上限
    pub send_buffer_limit: usize,
    /// プロトコル固有の状態（TCP / UDP / 未確定）
    pub protocol: ProtocolState,
    /// エラー状態
    pub last_error: Option<EndpointError>,
    /// 受信待ちWaker（非同期通知用）
    pub recv_waker: Option<core::task::Waker>,
    /// 送信待ちWaker（非同期通知用）
    pub send_waker: Option<core::task::Waker>,
    /// 接続待ちWaker（非同期通知用）
    pub connect_waker: Option<core::task::Waker>,
    /// Accept待ちWaker（非同期通知用）
    pub accept_waker: Option<core::task::Waker>,
    /// QoS優先度 (DSCP値, 6ビット)
    pub priority: u8,
}

impl EndpointInner {
    /// デフォルトバッファサイズ
    pub const DEFAULT_BUFFER_SIZE: usize = 8192;
    /// 最大バッファサイズ
    pub const MAX_BUFFER_SIZE: usize = 65536;
    /// デフォルトの Accept バックログサイズ
    pub const DEFAULT_BACKLOG: usize = TcpProtocolState::DEFAULT_BACKLOG;

    /// 新規作成
    pub fn new() -> Self {
        Self {
            state: EndpointState::Created,
            local_addr: None,
            remote_addr: None,
            scope: InterfaceScope::Any,
            last_ingress_if_id: None,
            recv_buffer_limit: Self::MAX_BUFFER_SIZE,
            send_buffer_limit: Self::MAX_BUFFER_SIZE,
            protocol: ProtocolState::Unset,
            last_error: None,
            recv_waker: None,
            send_waker: None,
            connect_waker: None,
            accept_waker: None,
            priority: 0,
        }
    }

    // ================================================================
    // プロトコル状態アクセサ
    // ================================================================

    /// TCP状態の読み取り参照を取得
    #[inline]
    pub fn tcp(&self) -> Option<&TcpProtocolState> {
        match &self.protocol {
            ProtocolState::Tcp(tcp) => Some(tcp),
            _ => None,
        }
    }

    /// TCP状態の可変参照を取得
    #[inline]
    pub fn tcp_mut(&mut self) -> Option<&mut TcpProtocolState> {
        match &mut self.protocol {
            ProtocolState::Tcp(tcp) => Some(tcp),
            _ => None,
        }
    }

    /// TCP状態を保証して可変参照を返す（未設定なら初期化）
    #[inline]
    pub fn ensure_tcp(&mut self) -> &mut TcpProtocolState {
        if !matches!(self.protocol, ProtocolState::Tcp(_)) {
            self.protocol = ProtocolState::Tcp(TcpProtocolState::new());
        }
        match &mut self.protocol {
            ProtocolState::Tcp(tcp) => tcp,
            _ => unreachable!(),
        }
    }

    /// UDP状態の読み取り参照を取得
    #[inline]
    pub fn udp(&self) -> Option<&UdpProtocolState> {
        match &self.protocol {
            ProtocolState::Udp(udp) => Some(udp),
            _ => None,
        }
    }

    /// UDP状態の可変参照を取得
    #[inline]
    pub fn udp_mut(&mut self) -> Option<&mut UdpProtocolState> {
        match &mut self.protocol {
            ProtocolState::Udp(udp) => Some(udp),
            _ => None,
        }
    }

    /// UDP状態を保証して可変参照を返す（未設定なら初期化）
    #[inline]
    pub fn ensure_udp(&mut self) -> &mut UdpProtocolState {
        if !matches!(self.protocol, ProtocolState::Udp(_)) {
            self.protocol = ProtocolState::Udp(UdpProtocolState::new());
        }
        match &mut self.protocol {
            ProtocolState::Udp(udp) => udp,
            _ => unreachable!(),
        }
    }

    /// RAW状態の読み取り参照を取得
    #[inline]
    pub fn raw(&self) -> Option<&RawProtocolState> {
        match &self.protocol {
            ProtocolState::Raw(raw) => Some(raw),
            _ => None,
        }
    }

    /// RAW状態の可変参照を取得
    #[inline]
    pub fn raw_mut(&mut self) -> Option<&mut RawProtocolState> {
        match &mut self.protocol {
            ProtocolState::Raw(raw) => Some(raw),
            _ => None,
        }
    }

    /// RAW状態を保証して可変参照を返す（未設定なら初期化）
    #[inline]
    pub fn ensure_raw(&mut self) -> &mut RawProtocolState {
        if !matches!(self.protocol, ProtocolState::Raw(_)) {
            self.protocol = ProtocolState::Raw(RawProtocolState::new());
        }
        match &mut self.protocol {
            ProtocolState::Raw(raw) => raw,
            _ => unreachable!(),
        }
    }

    /// プロトコル状態をリセット（close時）
    #[inline]
    pub fn clear_protocol(&mut self) {
        self.protocol = ProtocolState::Unset;
    }

    #[inline]
    fn trim_empty_payloads(queue: &mut VecDeque<PacketPayload>) {
        while matches!(queue.front(), Some(payload) if payload.is_empty()) {
            queue.pop_front();
        }
    }

    fn queued_prefix(queue: &VecDeque<PacketPayload>, len: usize) -> Option<PacketPayload> {
        if len == 0 {
            return Some(PacketPayload::default());
        }

        let mut remaining = len;
        let mut segments = alloc::vec::Vec::new();

        for payload in queue {
            if remaining == 0 {
                break;
            }
            let take = remaining.min(payload.total_len());
            let prefix = payload.slice(0, take)?;
            segments.extend(prefix.into_segments());
            remaining -= take;
        }

        if remaining != 0 {
            return None;
        }

        if segments.len() == 1 {
            Some(PacketPayload::single(segments.remove(0)))
        } else {
            Some(PacketPayload::chain(PacketChain::from_segments(segments)))
        }
    }

    fn consume_queued_prefix(queue: &mut VecDeque<PacketPayload>, len: usize) -> usize {
        let mut remaining = len;
        let mut consumed = 0usize;

        while remaining > 0 {
            let Some(front) = queue.front_mut() else {
                break;
            };

            if front.is_empty() {
                queue.pop_front();
                continue;
            }

            let take = remaining.min(front.total_len());
            let used = front.consume_prefix(take);
            consumed += used;
            remaining = remaining.saturating_sub(used);

            if front.is_empty() {
                queue.pop_front();
            }

            if used == 0 {
                break;
            }
        }

        consumed
    }

    // ================================================================
    // TCP専用状態ヘルパー
    // ================================================================

    /// Set urgent data pending flag
    #[inline]
    pub fn set_urgent_pending(&mut self, pending: bool) {
        if let Some(tcp) = self.tcp_mut() {
            tcp.urgent_pending = pending;
        }
    }

    /// Check if urgent data is pending
    #[inline]
    pub fn has_urgent_pending(&self) -> bool {
        self.tcp().map_or(false, |t| t.urgent_pending)
    }

    /// 状態遷移（ガード付き）
    #[inline]
    pub fn transition_to(&mut self, new_state: EndpointState) -> EndpointResult<()> {
        let valid = match (self.state, new_state) {
            // Created からの遷移
            (EndpointState::Created, EndpointState::Bound) => true,
            (EndpointState::Created, EndpointState::Connecting) => true,
            (EndpointState::Created, EndpointState::Closed) => true,
            // Bound からの遷移
            (EndpointState::Bound, EndpointState::Listening) => true,
            (EndpointState::Bound, EndpointState::Connecting) => true,
            (EndpointState::Bound, EndpointState::Connected) => true, // UDP
            (EndpointState::Bound, EndpointState::Closed) => true,
            // Listening からの遷移
            (EndpointState::Listening, EndpointState::Closing) => true,
            (EndpointState::Listening, EndpointState::Closed) => true,
            // Connecting からの遷移
            (EndpointState::Connecting, EndpointState::Connected) => true,
            (EndpointState::Connecting, EndpointState::Closed) => true,
            // Connected からの遷移
            (EndpointState::Connected, EndpointState::Closing) => true,
            (EndpointState::Connected, EndpointState::Closed) => true,
            // Closing からの遷移
            (EndpointState::Closing, EndpointState::Closed) => true,
            // 同じ状態への遷移は許可
            (s1, s2) if s1 == s2 => true,
            _ => false,
        };

        if valid {
            self.state = new_state;
            Ok(())
        } else {
            Err(EndpointError::InvalidStateTransition)
        }
    }

    #[inline]
    pub fn recv_payload_bytes(&self) -> usize {
        self.tcp().map(|tcp| tcp.recv_payload_bytes).unwrap_or(0)
    }

    #[inline]
    pub fn send_payload_bytes(&self) -> usize {
        self.tcp().map(|tcp| tcp.send_payload_bytes).unwrap_or(0)
    }

    #[inline]
    pub fn has_recv_data(&self) -> bool {
        self.recv_payload_bytes() > 0
    }

    #[inline]
    pub fn has_send_data(&self) -> bool {
        self.send_payload_bytes() > 0
    }

    /// 受信キューからデータ取得
    #[inline]
    pub fn recv_from_buffer(&mut self, buf: &mut [u8]) -> usize {
        let Some(tcp) = self.tcp_mut() else {
            return 0;
        };

        Self::trim_empty_payloads(&mut tcp.recv_payload_queue);
        let Some(front) = tcp.recv_payload_queue.front_mut() else {
            return 0;
        };

        let len = front.copy_into(buf);
        tcp.recv_payload_bytes = tcp.recv_payload_bytes.saturating_sub(len);
        if front.is_empty() {
            tcp.recv_payload_queue.pop_front();
        }
        Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

        if len > 0 {
            // キューに空きができたので送信待ちを起こす
            if let Some(waker) = self.send_waker.take() {
                waker.wake();
            }
        }

        len
    }

    #[inline]
    pub fn recv_payload(&mut self, max_len: Option<usize>) -> Option<PacketPayload> {
        let tcp = self.tcp_mut()?;
        Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

        let payload = match max_len {
            Some(limit) => {
                let front = tcp.recv_payload_queue.front_mut()?;
                let take = limit.min(front.total_len());
                let taken = front.take_prefix(take)?;
                if front.is_empty() {
                    tcp.recv_payload_queue.pop_front();
                }
                taken
            }
            None => tcp.recv_payload_queue.pop_front()?,
        };

        tcp.recv_payload_bytes = tcp.recv_payload_bytes.saturating_sub(payload.total_len());
        Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

        if payload.total_len() > 0 {
            if let Some(waker) = self.send_waker.take() {
                waker.wake();
            }
        }

        Some(payload)
    }

    #[inline]
    pub fn send_payload(&mut self, payload: PacketPayload) -> EndpointResult<usize> {
        let available = self
            .send_buffer_limit
            .saturating_sub(self.send_payload_bytes());

        if available == 0 {
            return Err(EndpointError::BufferFull);
        }

        let queued = if payload.total_len() > available {
            payload
                .slice(0, available)
                .ok_or(EndpointError::BufferFull)?
        } else {
            payload
        };

        let len = queued.total_len();
        let tcp = self.ensure_tcp();
        tcp.send_payload_bytes = tcp.send_payload_bytes.saturating_add(len);
        tcp.send_payload_queue.push_back(queued);
        Ok(len)
    }

    #[inline]
    pub fn peek_send_payload_prefix(&self, len: usize) -> Option<PacketPayload> {
        let tcp = self.tcp()?;
        Self::queued_prefix(&tcp.send_payload_queue, len)
    }

    #[inline]
    pub fn consume_send_payload(&mut self, len: usize) -> usize {
        let Some(tcp) = self.tcp_mut() else {
            return 0;
        };
        let consumed = Self::consume_queued_prefix(&mut tcp.send_payload_queue, len);
        tcp.send_payload_bytes = tcp.send_payload_bytes.saturating_sub(consumed);
        Self::trim_empty_payloads(&mut tcp.send_payload_queue);
        consumed
    }

    #[inline]
    pub fn push_send_payload_front(&mut self, payload: PacketPayload) {
        let len = payload.total_len();
        let tcp = self.ensure_tcp();
        tcp.send_payload_bytes = tcp.send_payload_bytes.saturating_add(len);
        tcp.send_payload_queue.push_front(payload);
    }

    #[inline]
    pub fn peek_send_byte(&self) -> Option<u8> {
        let tcp = self.tcp()?;
        let payload = tcp.send_payload_queue.front()?;
        PacketPayloadView::new(payload).first_byte()
    }

    #[inline]
    pub fn clear_tcp_payload_queues(&mut self) {
        if let Some(tcp) = self.tcp_mut() {
            tcp.recv_payload_queue.clear();
            tcp.recv_payload_bytes = 0;
            tcp.send_payload_queue.clear();
            tcp.send_payload_bytes = 0;
        }
    }

    /// 受信キューにデータ追加（内部用 - カーネル/ドライバから呼ばれる）
    /// 実際にキューに追加されたバイト数を返す。
    #[inline]
    pub fn push_recv_payload(&mut self, payload: PacketPayload) -> usize {
        let available = self
            .recv_buffer_limit
            .saturating_sub(self.recv_payload_bytes());
        if available == 0 {
            return 0;
        }

        let queued = if payload.total_len() > available {
            match payload.slice(0, available) {
                Some(payload) => payload,
                None => return 0,
            }
        } else {
            payload
        };

        let len = queued.total_len();
        if len > 0 {
            let tcp = self.ensure_tcp();
            tcp.recv_payload_bytes = tcp.recv_payload_bytes.saturating_add(len);
            tcp.recv_payload_queue.push_back(queued);
            Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

            // データが到着したので受信待ちを起こす
            if let Some(waker) = self.recv_waker.take() {
                waker.wake();
            }
        }
        len
    }

    /// 接続完了通知（内部用 - TCPスタックから呼ばれる）
    #[inline]
    pub fn notify_connected(&mut self) {
        if let Some(waker) = self.connect_waker.take() {
            waker.wake();
        }
    }
}

impl Default for EndpointInner {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================
// テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    fn test_payload(data: &[u8]) -> PacketPayload {
        crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_state_transitions() {
        let mut inner = EndpointInner::new();

        // Created -> Bound
        assert!(inner.transition_to(EndpointState::Bound).is_ok());
        assert_eq!(inner.state, EndpointState::Bound);

        // Bound -> Listening
        assert!(inner.transition_to(EndpointState::Listening).is_ok());
        assert_eq!(inner.state, EndpointState::Listening);

        // Invalid: Listening -> Connected
        assert!(inner.transition_to(EndpointState::Connected).is_err());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_payload_queue_buffer() {
        let mut inner = EndpointInner::new();
        inner.ensure_tcp();

        // データ追加
        inner.push_recv_payload(test_payload(&[1, 2, 3, 4, 5]));
        assert_eq!(inner.recv_payload_bytes(), 5);

        // O(1)でのデータ取得
        let mut buf = [0u8; 3];
        let len = inner.recv_from_buffer(&mut buf);
        assert_eq!(len, 3);
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(inner.recv_payload_bytes(), 2);
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn endpoint_state_transitions_smoke() -> bool {
        let mut inner = EndpointInner::new();

        if inner.transition_to(EndpointState::Bound).is_err() || inner.state != EndpointState::Bound
        {
            return false;
        }

        if inner.transition_to(EndpointState::Listening).is_err()
            || inner.state != EndpointState::Listening
        {
            return false;
        }

        inner.transition_to(EndpointState::Connected).is_err()
    }

    pub fn payload_queue_buffer_smoke() -> bool {
        let mut inner = EndpointInner::new();
        inner.ensure_tcp();
        inner.push_recv_payload(test_payload(&[1, 2, 3, 4, 5]));
        if inner.recv_payload_bytes() != 5 {
            return false;
        }

        let mut buf = [0u8; 3];
        let len = inner.recv_from_buffer(&mut buf);

        len == 3 && buf == [1, 2, 3] && inner.recv_payload_bytes() == 2
    }
}
