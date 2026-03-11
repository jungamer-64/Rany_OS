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
use alloc::vec::Vec;

use crate::net::l4::tcp::{TcpListener as TcpListenerImpl, TcpStream};
use crate::net::l4::udp::UdpEndpoint as RawUdpSocket;
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;

use super::congestion::CongestionAlgorithm;
use super::types::{
    AcceptedConnection, EndpointAddr, EndpointError, EndpointResult, EndpointState,
};

// ============================================================================
// プロトコル固有の状態
// ============================================================================

/// TCP固有のプロトコル状態
pub struct TcpProtocolState {
    /// TCPストリーム（接続済みの場合）
    pub stream: Option<TcpStream>,
    /// TCPリスナー（リスニング中の場合）
    pub listener: Option<TcpListenerImpl>,
    /// Acceptキュー: ハンドシェイク完了済みの接続
    pub accept_queue: VecDeque<AcceptedConnection>,
    /// Acceptキューのバックログサイズ
    pub accept_backlog: usize,
    /// TCP_NODELAY (Nagleアルゴリズム無効化)
    pub nodelay: bool,
    /// Urgent data pending flag (TCP OOB data)
    pub urgent_pending: bool,
    /// 輻輳制御アルゴリズム選択（TCB作成時に使用）
    pub congestion_algorithm: Option<CongestionAlgorithm>,
}

impl TcpProtocolState {
    /// デフォルトのAcceptバックログサイズ
    pub const DEFAULT_BACKLOG: usize = 128;

    /// 新規作成
    pub fn new() -> Self {
        Self {
            stream: None,
            listener: None,
            accept_queue: VecDeque::with_capacity(Self::DEFAULT_BACKLOG),
            accept_backlog: Self::DEFAULT_BACKLOG,
            nodelay: false,
            urgent_pending: false,
            congestion_algorithm: None,
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
    pub pending_packets: VecDeque<(NetIfId, EndpointAddr, Vec<u8>)>,
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
    /// 受信バッファ（VecDeque: O(1) FIFO）
    pub recv_buffer: VecDeque<u8>,
    /// 送信バッファ（VecDeque: O(1) FIFO）
    pub send_buffer: VecDeque<u8>,
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
    /// デフォルトのAcceptバックログサイズ (後方互換)
    pub const DEFAULT_BACKLOG: usize = TcpProtocolState::DEFAULT_BACKLOG;

    /// 新規作成
    pub fn new() -> Self {
        Self {
            state: EndpointState::Created,
            local_addr: None,
            remote_addr: None,
            scope: InterfaceScope::Any,
            last_ingress_if_id: None,
            recv_buffer: VecDeque::with_capacity(Self::DEFAULT_BUFFER_SIZE),
            send_buffer: VecDeque::with_capacity(Self::DEFAULT_BUFFER_SIZE),
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

    /// プロトコル状態をリセット（close時）
    #[inline]
    pub fn clear_protocol(&mut self) {
        self.protocol = ProtocolState::Unset;
    }

    // ================================================================
    // TCP専用便利メソッド（後方互換）
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

    /// 受信バッファからデータ取得（O(1)）
    #[inline]
    pub fn recv_from_buffer(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len().min(self.recv_buffer.len());
        for (i, byte) in self.recv_buffer.drain(..len).enumerate() {
            buf[i] = byte;
        }
        // バッファに空きができたので送信待ちを起こす
        if let Some(waker) = self.send_waker.take() {
            waker.wake();
        }
        len
    }

    /// 送信バッファにデータ追加
    #[inline]
    pub fn send_to_buffer(&mut self, data: &[u8]) -> EndpointResult<usize> {
        let available = self
            .send_buffer_limit
            .saturating_sub(self.send_buffer.len());

        if available == 0 {
            return Err(EndpointError::BufferFull);
        }

        let len = data.len().min(available);
        self.send_buffer.extend(data[..len].iter().copied());
        Ok(len)
    }

    /// 受信バッファにデータ追加（内部用 - カーネル/ドライバから呼ばれる）
    /// 実際にバッファに追加されたバイト数を返す。
    #[inline]
    pub fn push_recv_data(&mut self, data: &[u8]) -> usize {
        let available = self
            .recv_buffer_limit
            .saturating_sub(self.recv_buffer.len());
        let len = data.len().min(available);
        if len > 0 {
            self.recv_buffer.extend(data[..len].iter().copied());

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

    #[cfg_attr(test, test_case)]
    pub fn test_socket_state_transitions() {
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
    pub fn test_vecdeque_buffer() {
        let mut inner = EndpointInner::new();

        // データ追加
        inner.push_recv_data(&[1, 2, 3, 4, 5]);
        assert_eq!(inner.recv_buffer.len(), 5);

        // O(1)でのデータ取得
        let mut buf = [0u8; 3];
        let len = inner.recv_from_buffer(&mut buf);
        assert_eq!(len, 3);
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(inner.recv_buffer.len(), 2);
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn socket_state_transitions_smoke() -> bool {
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

    pub fn vecdeque_buffer_smoke() -> bool {
        let mut inner = EndpointInner::new();
        inner.push_recv_data(&[1, 2, 3, 4, 5]);
        if inner.recv_buffer.len() != 5 {
            return false;
        }

        let mut buf = [0u8; 3];
        let len = inner.recv_from_buffer(&mut buf);

        len == 3 && buf == [1, 2, 3] && inner.recv_buffer.len() == 2
    }
}
