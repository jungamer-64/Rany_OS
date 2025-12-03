//! # SocketInner - 細粒度ロック用の内部状態
//!
//! ソケットの可変状態（Mutex保護対象）

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::net::tcp::{TcpStream, TcpListener as TcpListenerImpl};
use crate::net::udp::UdpSocket as RawUdpSocket;

use super::types::{SocketState, SocketError, SocketAddr, SocketResult, AcceptedConnection};

/// ソケットの可変状態（Mutex保護対象）
pub struct SocketInner {
    /// 現在の状態
    pub state: SocketState,
    /// ローカルアドレス
    pub local_addr: Option<SocketAddr>,
    /// リモートアドレス
    pub remote_addr: Option<SocketAddr>,
    /// 受信バッファ（VecDeque: O(1) FIFO）
    pub recv_buffer: VecDeque<u8>,
    /// 送信バッファ（VecDeque: O(1) FIFO）
    pub send_buffer: VecDeque<u8>,
    /// 受信バッファ上限
    pub recv_buffer_limit: usize,
    /// 送信バッファ上限
    pub send_buffer_limit: usize,
    /// TCPストリーム（接続済みの場合）
    pub tcp_stream: Option<TcpStream>,
    /// TCPリスナー（リスニング中の場合）
    pub tcp_listener: Option<TcpListenerImpl>,
    /// UDPソケット
    pub udp_socket: Option<RawUdpSocket>,
    /// 保留中のパケット（UDP用）
    pub pending_packets: VecDeque<(SocketAddr, Vec<u8>)>,
    /// Acceptキュー: ハンドシェイク完了済みの接続（Listeningソケット用）
    pub accept_queue: VecDeque<AcceptedConnection>,
    /// Acceptキューのバックログサイズ
    pub accept_backlog: usize,
    /// エラー状態
    pub last_error: Option<SocketError>,
    /// 受信待ちWaker（非同期通知用）
    pub recv_waker: Option<core::task::Waker>,
    /// 送信待ちWaker（非同期通知用）
    pub send_waker: Option<core::task::Waker>,
    /// 接続待ちWaker（非同期通知用）
    pub connect_waker: Option<core::task::Waker>,
    /// Accept待ちWaker（非同期通知用）
    pub accept_waker: Option<core::task::Waker>,
}

impl SocketInner {
    /// デフォルトバッファサイズ
    pub const DEFAULT_BUFFER_SIZE: usize = 8192;
    /// 最大バッファサイズ
    pub const MAX_BUFFER_SIZE: usize = 65536;
    /// デフォルトのAcceptバックログサイズ
    pub const DEFAULT_BACKLOG: usize = 128;
    
    /// 新規作成
    pub fn new() -> Self {
        Self {
            state: SocketState::Created,
            local_addr: None,
            remote_addr: None,
            recv_buffer: VecDeque::with_capacity(Self::DEFAULT_BUFFER_SIZE),
            send_buffer: VecDeque::with_capacity(Self::DEFAULT_BUFFER_SIZE),
            recv_buffer_limit: Self::MAX_BUFFER_SIZE,
            send_buffer_limit: Self::MAX_BUFFER_SIZE,
            tcp_stream: None,
            tcp_listener: None,
            udp_socket: None,
            pending_packets: VecDeque::with_capacity(16),
            accept_queue: VecDeque::with_capacity(Self::DEFAULT_BACKLOG),
            accept_backlog: Self::DEFAULT_BACKLOG,
            last_error: None,
            recv_waker: None,
            send_waker: None,
            connect_waker: None,
            accept_waker: None,
        }
    }
    
    /// 状態遷移（ガード付き）
    #[inline]
    pub fn transition_to(&mut self, new_state: SocketState) -> SocketResult<()> {
        let valid = match (self.state, new_state) {
            // Created からの遷移
            (SocketState::Created, SocketState::Bound) => true,
            (SocketState::Created, SocketState::Connecting) => true,
            (SocketState::Created, SocketState::Closed) => true,
            // Bound からの遷移
            (SocketState::Bound, SocketState::Listening) => true,
            (SocketState::Bound, SocketState::Connecting) => true,
            (SocketState::Bound, SocketState::Connected) => true, // UDP
            (SocketState::Bound, SocketState::Closed) => true,
            // Listening からの遷移
            (SocketState::Listening, SocketState::Closing) => true,
            (SocketState::Listening, SocketState::Closed) => true,
            // Connecting からの遷移
            (SocketState::Connecting, SocketState::Connected) => true,
            (SocketState::Connecting, SocketState::Closed) => true,
            // Connected からの遷移
            (SocketState::Connected, SocketState::Closing) => true,
            (SocketState::Connected, SocketState::Closed) => true,
            // Closing からの遷移
            (SocketState::Closing, SocketState::Closed) => true,
            // 同じ状態への遷移は許可
            (s1, s2) if s1 == s2 => true,
            _ => false,
        };
        
        if valid {
            self.state = new_state;
            Ok(())
        } else {
            Err(SocketError::InvalidStateTransition)
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
    pub fn send_to_buffer(&mut self, data: &[u8]) -> SocketResult<usize> {
        let available = self.send_buffer_limit.saturating_sub(self.send_buffer.len());
        
        if available == 0 {
            return Err(SocketError::BufferFull);
        }
        
        let len = data.len().min(available);
        self.send_buffer.extend(data[..len].iter().copied());
        Ok(len)
    }
    
    /// 受信バッファにデータ追加（内部用 - カーネル/ドライバから呼ばれる）
    #[inline]
    pub fn push_recv_data(&mut self, data: &[u8]) {
        let available = self.recv_buffer_limit.saturating_sub(self.recv_buffer.len());
        let len = data.len().min(available);
        self.recv_buffer.extend(data[..len].iter().copied());
        
        // データが到着したので受信待ちを起こす
        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
    }
    
    /// 接続完了通知（内部用 - TCPスタックから呼ばれる）
    #[inline]
    pub fn notify_connected(&mut self) {
        if let Some(waker) = self.connect_waker.take() {
            waker.wake();
        }
    }
}

impl Default for SocketInner {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================
// テスト
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_socket_state_transitions() {
        let mut inner = SocketInner::new();
        
        // Created -> Bound
        assert!(inner.transition_to(SocketState::Bound).is_ok());
        assert_eq!(inner.state, SocketState::Bound);
        
        // Bound -> Listening
        assert!(inner.transition_to(SocketState::Listening).is_ok());
        assert_eq!(inner.state, SocketState::Listening);
        
        // Invalid: Listening -> Connected
        assert!(inner.transition_to(SocketState::Connected).is_err());
    }
    
    #[test]
    fn test_vecdeque_buffer() {
        let mut inner = SocketInner::new();
        
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
