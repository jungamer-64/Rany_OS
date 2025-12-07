//! # Async Futures - 非同期ソケット操作
//!
//! RecvFuture, SendFuture, AcceptFuture, RecvFromFuture

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use super::socket::{OwnedSocket, Socket};
use super::types::{SocketAddr, SocketError, SocketResult, SocketState};

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

        let mut inner = this.socket.inner().lock();

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

        let mut inner = this.socket.inner().lock();

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
        if available > 0 {
            let remaining = &this.data[this.offset..];
            let to_send = remaining.len().min(available);
            inner
                .send_buffer
                .extend(remaining[..to_send].iter().copied());
            this.offset += to_send;

            // 全データ送信済みなら完了
            if this.offset >= this.data.len() {
                return Poll::Ready(Ok(this.offset));
            }
        }

        // Wakerを登録してPending
        inner.send_waker = Some(cx.waker().clone());
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
        match self.socket.accept() {
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
}
