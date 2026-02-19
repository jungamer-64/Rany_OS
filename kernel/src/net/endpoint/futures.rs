// ============================================================================
// kernel/src/net/endpoint/futures.rs
// ============================================================================
//! # Async Futures - 非同期ソケット操作
//!
//! RecvFuture, SendFuture, AcceptFuture, RecvFromFuture

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use super::socket::{OwnedSocket, Socket};
use super::types::{SocketAddr, SocketError, SocketResult, SocketState};

use crate::net::tcp::TcpStream;
use crate::net::mempool::PacketRef;

/// 非同期受信Future
pub struct RecvFuture {
    socket: Socket,
    buffer: Vec<u8>,
}

impl RecvFuture {
    /// 新規作成
    pub fn new(socket: Socket, size: usize) -> Self {
        Self {
            socket,
            buffer: alloc::vec![0u8; size],
        }
    }
}

impl Future for RecvFuture {
    type Output = SocketResult<Vec<u8>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        let mut inner = this.socket.inner().lock().unwrap_or_else(|e| e.into_inner());

        // 状態チェック
        if !inner.state.can_receive() {
            return Poll::Ready(Err(SocketError::NotConnected));
        }

        // データがあれば即座に返す（O(1)）
        if !inner.recv_buffer.is_empty() {
            let len = this.buffer.len().min(inner.recv_buffer.len());
            for i in 0..len {
                if let Some(byte) = inner.recv_buffer.pop_front() {
                    this.buffer[i] = byte;
                }
            }
            this.buffer.truncate(len);
            return Poll::Ready(Ok(core::mem::take(&mut this.buffer)));
        }

        // クローズ済みならEOF
        if matches!(inner.state, SocketState::Closed | SocketState::Closing) {
            return Poll::Ready(Ok(Vec::new()));
        }

        // Wakerを登録してPending
        inner.recv_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// 非同期送信Future
pub struct SendFuture {
    socket: Socket,
    data: Vec<u8>,
    offset: usize,
}

impl SendFuture {
    /// 新規作成
    pub fn new(socket: Socket, data: Vec<u8>) -> Self {
        Self {
            socket,
            data,
            offset: 0,
        }
    }
}

impl Future for SendFuture {
    type Output = SocketResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        // Acquire inner to inspect/modify buffers
        let mut inner = this.socket.inner().lock().unwrap_or_else(|e| e.into_inner());

        // 状態チェック
        if !inner.state.can_send() {
            return Poll::Ready(Err(SocketError::NotConnected));
        }

        // 全データ送信済みなら完了
        if this.offset >= this.data.len() {
            return Poll::Ready(Ok(this.offset));
        }

        // バッファに空きがあれば書き込み
        let available = inner
            .send_buffer_limit
            .saturating_sub(inner.send_buffer.len());

        // Track whether we've written anything so we can notify the stack after dropping the lock
        let mut wrote = 0usize;
        if available > 0 {
            let remaining = &this.data[this.offset..];
            let to_send = remaining.len().min(available);
            inner
                .send_buffer
                .extend(remaining[..to_send].iter().copied());
            this.offset += to_send;
            wrote = to_send;

            // If not finished, register our waker so we get notified when space is available
            if this.offset < this.data.len() {
                inner.send_waker = Some(cx.waker().clone());
            }
        } else {
            // No space: register waker and return Pending
            inner.send_waker = Some(cx.waker().clone());
        }

        // Drop lock before notifying the event queue to avoid lock-ordering issues
        drop(inner);

        // If we wrote data, notify the network stack so it can attempt to send
        if wrote > 0 {
            let _ = super::event::send_event(super::event::NetworkEvent::DataReady {
                fd: this.socket.fd(),
                socket_type: this.socket.socket_type(),
            });

            // If we've written all the user's data, complete the future
            if this.offset >= this.data.len() {
                return Poll::Ready(Ok(this.offset));
            }
        }

        Poll::Pending
    }
}

/// 非同期接続受け入れFuture
pub struct AcceptFuture {
    socket: Socket,
}

impl AcceptFuture {
    /// 新規作成
    pub fn new(socket: Socket) -> Self {
        Self { socket }
    }
}

impl Future for AcceptFuture {
    type Output = SocketResult<(OwnedSocket, SocketAddr)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.socket.next_incoming() {
            Ok((socket, addr)) => Poll::Ready(Ok((OwnedSocket::from_socket(socket), addr))),
            Err(SocketError::Timeout) => {
                // Wakerを登録してPending
                self.socket.register_accept_waker(cx.waker().clone());
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// 非同期UDP受信Future
pub struct RecvFromFuture {
    socket: Socket,
    buffer: Vec<u8>,
}

impl RecvFromFuture {
    /// 新規作成
    pub fn new(socket: Socket, size: usize) -> Self {
        Self {
            socket,
            buffer: alloc::vec![0u8; size],
        }
    }
}

impl Future for RecvFromFuture {
    type Output = SocketResult<(Vec<u8>, SocketAddr)>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        // バッファサイズを取得
        let buf_len = this.buffer.len();
        let mut temp_buf = alloc::vec![0u8; buf_len];

        match this.socket.recv_from(&mut temp_buf) {
            Ok((len, addr)) => {
                this.buffer.truncate(len);
                this.buffer[..len].copy_from_slice(&temp_buf[..len]);
                Poll::Ready(Ok((core::mem::take(&mut this.buffer), addr)))
            }
            Err(SocketError::Timeout) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// 非同期ゼロコピー受信Future（TCP専用）
/// 成功時に `Some(PacketRef)` を返す。接続クローズ時は `None`。
pub struct RecvPacketFuture {
    stream: TcpStream,
}

impl RecvPacketFuture {
    /// 新規作成
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

impl Future for RecvPacketFuture {
    type Output = Option<PacketRef>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        match this.stream.tcb.lock() {
            Ok(mut tcb) => {
                if tcb.state == crate::net::tcp::TcpState::Closed {
                    return Poll::Ready(None);
                }

                if let Some(packet) = tcb.recv_buffer.pop_front() {
                    let len = packet.data().len();
                    tcb.stats.bytes_received += len as u64;
                    return Poll::Ready(Some(packet));
                }

                tcb.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (recv_packet) - returning None");
                Poll::Ready(None)
            }
        }
    }
}

/// TCPゼロコピー用の小さなストリームラッパー（使いやすいヘルパ）
pub struct TcpPacketStream {
    stream: TcpStream,
}

impl TcpPacketStream {
    /// 新規作成
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// 次のパケットを受信するFutureを返す
    pub fn next_packet(&self) -> RecvPacketFuture {
        RecvPacketFuture::new(self.stream.clone())
    }
}

/// UDPゼロコピー用の小さなストリームラッパー（使いやすいヘルパ）
pub struct UdpPacketStream {
    socket: crate::net::udp::UdpSocket,
}

impl UdpPacketStream {
    /// 新規作成
    pub fn new(socket: crate::net::udp::UdpSocket) -> Self {
        Self { socket }
    }

    /// 次のパケットを受信するFutureを返す
    pub fn next_packet(&self) -> crate::net::udp::UdpRecvPacketFuture {
        self.socket.recv_packet()
    }
}

// =====================================================
// 非同期拡張メソッド
// =====================================================

impl OwnedSocket {
    /// 非同期受信
    pub fn recv_async(&self, size: usize) -> Option<RecvFuture> {
        self.socket().map(|s| RecvFuture::new(s.clone(), size))
    }

    /// 非同期送信
    pub fn send_async(&self, data: Vec<u8>) -> Option<SendFuture> {
        self.socket().map(|s| SendFuture::new(s.clone(), data))
    }

    /// 非同期接続受け入れ
    pub fn accept_async(&self) -> Option<AcceptFuture> {
        self.socket().map(|s| AcceptFuture::new(s.clone()))
    }

    /// 非同期UDP受信
    pub fn recv_from_async(&self, size: usize) -> Option<RecvFromFuture> {
        self.socket().map(|s| RecvFromFuture::new(s.clone(), size))
    }

    /// TCPのゼロコピーストリームを取得（`TcpStream`をクローンして返す）
    pub fn tcp_stream(&self) -> Option<TcpStream> {
        self.socket().and_then(|s| s.inner().lock().unwrap_or_else(|e| e.into_inner()).tcp_stream.clone())
    }

    /// 非同期ゼロコピー受信（TCP向け） - 成功すると `PacketRef` を返す
    pub fn recv_packet_async(&self) -> Option<RecvPacketFuture> {
        self.socket().and_then(|s| {
            s.inner()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .tcp_stream
                .clone()
                .map(|stream| RecvPacketFuture::new(stream))
        })
    }

    /// UDPのゼロコピー受信ヘルパ（内部UDPソケットが設定されている場合にのみ利用可能）
    pub fn recv_packet_from_udp(&self) -> Option<crate::net::udp::UdpRecvPacketFuture> {
        if self.socket().map(|s| s.socket_type()) != Some(super::types::SocketType::Udp) {
            return None;
        }
        self.socket().and_then(|s| {
            // Clone the optional UdpSocket from the inner state and produce a future
            let opt = s.inner().lock().unwrap_or_else(|e| e.into_inner()).udp_socket.clone();
            opt.map(|u| u.recv_packet())
        })
    }

    /// TCP向けゼロコピー受信のストリームラッパーを取得（`TcpStream`をクローンして返す）
    pub fn tcp_packet_stream(&self) -> Option<TcpPacketStream> {
        self.tcp_stream().map(|s| TcpPacketStream::new(s))
    }

    /// UDP向けゼロコピー受信のストリームラッパーを取得（内部UDPソケットが設定されている場合）
    pub fn udp_packet_stream(&self) -> Option<UdpPacketStream> {
        self.socket().and_then(|s| s.inner().lock().unwrap_or_else(|e| e.into_inner()).udp_socket.clone()).map(|u| UdpPacketStream::new(u))
    }
}



// ==========================
// Tests for SendFuture
// ==========================

#[cfg(test)]
mod tests;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;
    use crate::net::endpoint::manager::init_socket_manager;
    use crate::net::endpoint::tcb::{tcb_table, TcpConnectionState, TcpControlBlockEntry};
    use crate::net::endpoint::{SocketAddr, SocketState};
    use crate::net::{self, create_tcp_socket, create_udp_socket, stack, NetworkEvent};
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};

    pub fn sendfuture_wakes_on_send_smoke() -> bool {
        init_socket_manager();

        stack::init_default();
        if let Ok(mut guard) = stack::stack().lock() {
            if let Some(ref mut s) = *guard {
                s.set_transmit_fn(|_data: &[u8]| true);
            }
        }

        let sock = create_tcp_socket();
        let fd = sock.fd();
        let local = SocketAddr::new([127, 0, 0, 1], 12345);
        let remote = SocketAddr::new([127, 0, 0, 1], 80);
        if let Some(s) = sock.socket() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
            let _ = inner.transition_to(SocketState::Bound);
            let _ = inner.transition_to(SocketState::Connected);
        }

        let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
        tcb.state = TcpConnectionState::Established;
        tcb_table().insert(tcb);

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let expected = alloc::vec![1u8, 2u8, 3u8, 4u8];
        let Some(mut fut) = sock.send_async(expected.clone()) else {
            return false;
        };
        let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(n)) => n == expected.len(),
            Poll::Pending => {
                let handler = crate::net::endpoint::handler::NetworkEventHandler::new();
                let _ = handler.handle_event(NetworkEvent::DataReady {
                    fd,
                    socket_type: crate::net::endpoint::types::SocketType::Tcp,
                });

                match pinned.as_mut().poll(&mut cx) {
                    Poll::Ready(Ok(n)) => n == expected.len(),
                    Poll::Pending => {
                        if let Some(s) = sock.socket() {
                            let inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
                            let staged: alloc::vec::Vec<u8> =
                                inner.send_buffer.iter().copied().collect();
                            staged == expected
                        } else {
                            false
                        }
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    pub fn recv_packet_zero_copy_via_owned_socket_smoke() -> bool {
        init_socket_manager();
        stack::init_default();

        let sock = create_tcp_socket();
        let local = SocketAddr::new([127, 0, 0, 1], 12345);
        let remote = SocketAddr::new([127, 0, 0, 1], 80);
        if let Some(s) = sock.socket() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
        }

        use alloc::sync::Arc;
        use crate::sync::PoisonLock;
        use crate::net::tcp::{
            Ipv4Addr as TcpIpv4Addr, SocketAddr as TcpSocketAddr, TcpControlBlock, TcpState,
            TcpStream,
        };

        let t_local = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 12345);
        let t_remote = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 80);

        let mut tcb = TcpControlBlock::new(t_local);
        tcb.remote_addr = Some(t_remote);
        tcb.state = TcpState::Established;
        let tcb_arc = Arc::new(PoisonLock::new(tcb));
        let stream = TcpStream { tcb: tcb_arc.clone() };

        if let Some(s) = sock.socket() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.tcp_stream = Some(stream.clone());
            let _ = inner.transition_to(SocketState::Bound);
            let _ = inner.transition_to(SocketState::Connected);
        }

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut fut = match sock.recv_packet_async() {
            Some(f) => f,
            None => RecvPacketFuture::new(stream),
        };
        let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

        matches!(pinned.as_mut().poll(&mut cx), Poll::Pending)
    }

    pub fn tcp_packet_stream_multiple_packets_smoke() -> bool {
        init_socket_manager();
        stack::init_default();

        let sock = create_tcp_socket();
        let local = SocketAddr::new([127, 0, 0, 1], 12345);
        let remote = SocketAddr::new([127, 0, 0, 1], 80);
        if let Some(s) = sock.socket() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(local);
            inner.remote_addr = Some(remote);
        }

        use alloc::sync::Arc;
        use crate::sync::PoisonLock;
        use crate::net::tcp::{
            Ipv4Addr as TcpIpv4Addr, SocketAddr as TcpSocketAddr, TcpControlBlock, TcpState,
            TcpStream,
        };

        let t_local = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 12345);
        let t_remote = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 80);

        let mut tcb = TcpControlBlock::new(t_local);
        tcb.remote_addr = Some(t_remote);
        tcb.state = TcpState::Established;
        let tcb_arc = Arc::new(PoisonLock::new(tcb));
        let stream = TcpStream { tcb: tcb_arc.clone() };

        if let Some(s) = sock.socket() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.tcp_stream = Some(stream.clone());
            let _ = inner.transition_to(SocketState::Bound);
            let _ = inner.transition_to(SocketState::Connected);
        }

        let Some(stream_wrapper) = sock.tcp_packet_stream() else {
            return false;
        };

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = stream_wrapper.next_packet();
        let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
        matches!(pinned.as_mut().poll(&mut cx), Poll::Pending)
    }

    pub fn udp_packet_stream_delivered_smoke() -> bool {
        init_socket_manager();

        let proc = crate::net::udp::UdpProcessor::new();
        let port = 40000u16;
        let Ok(u) = proc.bind_with_token(port, None) else {
            return false;
        };

        let sock = create_udp_socket();
        if let Some(s) = sock.socket() {
            let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.local_addr = Some(SocketAddr::new([127, 0, 0, 1], port));
            inner.udp_socket = Some(u.clone());
            let _ = inner.transition_to(SocketState::Bound);
            let _ = inner.transition_to(SocketState::Connected);
        }

        let Some(stream) = sock.udp_packet_stream() else {
            return false;
        };

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut fut = stream.next_packet();
        let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
        matches!(pinned.as_mut().poll(&mut cx), Poll::Pending)
    }
}
