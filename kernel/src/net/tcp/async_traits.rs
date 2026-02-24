use super::*;


// ============================================================================
// AsyncRead / AsyncWrite トレイト（POSIXソケット代替）
// ============================================================================

/// 非同期読み取りトレイト
mod seq_utils;
pub use seq_utils::*;
pub trait AsyncRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, TcpError>>;
}

/// 非同期書き込みトレイト  
pub trait AsyncWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, TcpError>>;

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TcpError>>;

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TcpError>>;
}

/// TCPエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    /// 接続が閉じられた
    ConnectionClosed,
    /// 接続が拒否された
    ConnectionRefused,
    /// 接続がリセットされた
    ConnectionReset,
    /// タイムアウト
    Timeout,
    /// アドレスが使用中
    AddressInUse,
    /// バッファが満杯
    BufferFull,
    /// 無効な状態
    InvalidState,
    /// ネットワーク到達不能
    NetworkUnreachable,
}

// ============================================================================
// TcpStream - 非同期TCPストリーム
// ============================================================================

/// 非同期TCPストリーム
///
/// 【設計書】POSIXソケットAPIを模倣しない
/// connect()の代わりにdial()を使用
pub struct TcpStream {
    pub(crate) tcb: Arc<PoisonLock<TcpControlBlock>>,
}

impl TcpStream {
    /// 指定アドレスに接続（推奨API）
    ///
    /// 【設計書】POSIXのconnect()ではなく、dial()という名前を採用
    /// 指定アドレスに接続（推奨API）
    ///
    /// 【設計書】POSIXのconnect()ではなく、dial()という名前を採用
    pub async fn dial(addr: SocketAddr) -> Result<Self, TcpError> {
        // ローカルポートの割り当てとTCBの作成、初期SYNの送信は Global Stack に委譲
        let local_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED, allocate_ephemeral_port());
        
        let stream = crate::net::stack::connect_tcp(local_addr, addr)?;
        
        // 接続完了を待つ
        let tcb = stream.tcb.clone();
        ConnectFuture { tcb }.await?;

        Ok(stream)
    }


    /// ローカルアドレスを取得
    pub fn local_addr(&self) -> SocketAddr {
        match self.tcb.lock() {
            Ok(g) => g.local_addr,
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (local_addr)");
                SocketAddr::new(Ipv4Addr::UNSPECIFIED, 0)
            }
        }
    }

    /// リモートアドレスを取得
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self.tcb.lock() {
            Ok(g) => g.remote_addr,
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (peer_addr)");
                None
            }
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> TcpStats {
        match self.tcb.lock() {
            Ok(g) => g.stats.clone(),
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (stats)");
                TcpStats::default()
            }
        }
    }

    /// 読み取り用Future（コピーあり - 互換性用）
    pub fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadFuture<'a> {
        ReadFuture { stream: self, buf }
    }

    /// 【設計書 6.2】ゼロコピー読み取り
    ///
    /// バッファの所有権をアプリケーションに移動します。
    /// コピーが発生しないため、高スループットアプリケーションに推奨。
    ///
    /// # 使用例
    /// ```ignore
    /// while let Some(packet) = stream.read_zero_copy().await {
    ///     // パケットを直接処理（コピーなし）
    ///     process_packet(&packet.data());
    ///     // パケットはスコープ終了時に自動的にプールに返却
    /// }
    /// ```
    pub async fn read_zero_copy(&mut self) -> Option<PacketRef> {
        ZeroCopyReadFuture { stream: self }.await
    }

    /// 書き込み用Future（コピーあり - 互換性用）
    pub fn write<'a>(&'a mut self, buf: &'a [u8]) -> WriteFuture<'a> {
        WriteFuture { stream: self, buf }
    }

    /// 送信キューをフラッシュして実際に送信を試行する
    pub fn flush(&mut self) -> FlushFuture<'_> {
        FlushFuture { stream: self }
    }


    /// 【設計書 6.2】ゼロコピー書き込み
    ///
    /// 事前に割り当てたパケットバッファの所有権をTCPスタックに移動します。
    ///
    /// # 使用例
    /// ```ignore
    /// let mut packet = mempool::alloc_packet().unwrap();
    /// packet.data_mut()[..data.len()].copy_from_slice(data);
    /// packet.set_len(data.len());
    /// stream.write_zero_copy(packet).await?;
    /// ```
    pub async fn write_zero_copy(&mut self, packet: PacketRef) -> Result<(), TcpError> {
        ZeroCopyWriteFuture {
            stream: self,
            packet: Some(packet),
        }
        .await
    }

    /// シャットダウン
    pub async fn shutdown(&mut self) -> Result<(), TcpError> {
        ShutdownFuture { stream: self }.await
    }
}

impl Clone for TcpStream {
    fn clone(&self) -> Self {
        TcpStream { tcb: self.tcb.clone() }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, TcpError>> {
        match self.tcb.lock() {
            Ok(mut tcb) => {
                if tcb.state == TcpState::Closed {
                    return Poll::Ready(Err(TcpError::ConnectionClosed));
                }

                if let Some(packet) = tcb.recv_buffer.pop_front() {
                    let data = packet.data();
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    tcb.stats.bytes_received += len as u64;

                    // If there is remaining payload, create a new PacketRef view and requeue it at the front
                    if data.len() > len {
                        let mut rem = packet.clone_ref();
                        rem.advance(len);
                        rem.set_len(data.len() - len);
                        tcb.recv_buffer.push_front(rem);
                    }

                    Poll::Ready(Ok(len))
                } else if let Some(mut vec) = tcb.recv_queue.pop_front() {
                    let len = vec.len().min(buf.len());
                    buf[..len].copy_from_slice(&vec[..len]);
                    tcb.stats.bytes_received += len as u64;

                    if len < vec.len() {
                        // Push remainder back to the front
                        let remainder = vec.split_off(len);
                        tcb.recv_queue.push_front(remainder);
                    }

                    Poll::Ready(Ok(len))
                } else {
                    tcb.read_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in read - returning ConnectionClosed");
                Poll::Ready(Err(TcpError::ConnectionClosed))
            }
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, TcpError>> {
        match self.tcb.lock() {
            Ok(mut tcb) => {
                if tcb.state != TcpState::Established {
                    return Poll::Ready(Err(TcpError::InvalidState));
                }

                // Compute available bytes (cwnd, snd_wnd) minus outstanding and queued bytes
                let available = core::cmp::min(tcb.cwnd, tcb.snd_wnd as u32)
                    .saturating_sub(tcb.outstanding_bytes.saturating_add(tcb.send_buffer_bytes)) as usize;

                if available == 0 {
                    tcb.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }

                let len = buf.len().min(1460).min(available); // MSS制限 + available
                if len == 0 {
                    tcb.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }

                // Prefer mempool packet, but fall back to a DMA-backed packet so
                // writers don't stall forever when the packet pool is exhausted.
                if let Some(mut packet) = crate::net::mempool::alloc_packet() {
                    packet.data_mut()[..len].copy_from_slice(&buf[..len]);
                    packet.set_len(len);
                    tcb.send_buffer_bytes = tcb.send_buffer_bytes.saturating_add(len as u32);
                    tcb.send_buffer.push_back(packet);
                    tcb.stats.bytes_sent += len as u64;
                    tcb.stats.packets_sent += 1;
                    Poll::Ready(Ok(len))
                } else if let Some(mut dma_buf) =
                    crate::io::dma::TypedDmaSlice::<crate::io::dma::CpuOwned>::new(len)
                {
                    dma_buf.as_mut_slice()[..len].copy_from_slice(&buf[..len]);
                    let mut packet = crate::net::mempool::PacketRef::from_dma_slice(dma_buf);
                    packet.set_len(len);
                    tcb.send_buffer_bytes = tcb.send_buffer_bytes.saturating_add(len as u32);
                    tcb.send_buffer.push_back(packet);
                    tcb.stats.bytes_sent += len as u64;
                    tcb.stats.packets_sent += 1;
                    Poll::Ready(Ok(len))
                } else {
                    tcb.write_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in write - returning InvalidState");
                Poll::Ready(Err(TcpError::InvalidState))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), TcpError>> {
        // 送信バッファのフラッシュ
        match self.tcb.lock() {
            Ok(mut tcb) => {
                // Get current time for retransmit tracking (microseconds)
                let current_time = crate::time::precise_time_nanos() / 1000;
                
                // 送信バッファ内の全パケットを送信
                while let Some(packet) = tcb.send_buffer.pop_front() {
                    if let Some(remote) = tcb.remote_addr {
                        let data = packet.data();
                        let len = data.len();
                        // Decrement send buffer bytes now that we're attempting to send it
                        tcb.send_buffer_bytes = tcb.send_buffer_bytes.saturating_sub(len as u32);
                        let seq = tcb.snd_nxt;

                        let sent = send_data_packet(
                            tcb.local_addr,
                            remote,
                            seq,
                            tcb.rcv_nxt,
                            tcb.rcv_wnd,
                            data,
                        );

                        if sent {
                            // Queue for retransmission (PSH+ACK)
                            tcb.queue_unacked(seq, data.to_vec(), current_time, TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK);
                            tcb.last_retransmit_time = current_time;

                            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(len as u32);
                        } else {
                            // Send failed (e.g., ARP unresolved). Requeue packet at front and restore counters
                            tcb.send_buffer_bytes = tcb.send_buffer_bytes.saturating_add(len as u32);
                            tcb.send_buffer.push_front(packet);
                            break; // stop trying further sends for now
                        }
                    }
                }

                Poll::Ready(Ok(()))
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in flush - returning Ok(())");
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), TcpError>> {
        match self.tcb.lock() {
            Ok(mut tcb) => match tcb.state {
                TcpState::Established => {
                    tcb.state = TcpState::FinWait1;
                    // FIN送信
                    if let Some(remote) = tcb.remote_addr {
                        let current_time = crate::time::precise_time_nanos() / 1000;
                        let sent = send_fin_packet(tcb.local_addr, remote, tcb.snd_nxt, tcb.rcv_nxt);
                        if sent {
                            // Queue FIN as unacked (FIN consumes 1 seq)
                            let snd_nxt = tcb.snd_nxt;
                            tcb.queue_unacked(snd_nxt, Vec::new(), current_time, TcpHeader::FLAG_FIN | TcpHeader::FLAG_ACK);
                            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                            tcb.last_retransmit_time = current_time;
                        } else {
                            // Could not send now; leave in queue and rely on process_timeouts to retry
                            log::info!("[NET] FIN send failed (will retry)");
                        }
                    }
                    Poll::Ready(Ok(()))
                }
                TcpState::CloseWait => {
                    tcb.state = TcpState::LastAck;
                    // FIN送信
                    if let Some(remote) = tcb.remote_addr {
                        send_fin_packet(tcb.local_addr, remote, tcb.snd_nxt, tcb.rcv_nxt);
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                    }
                    Poll::Ready(Ok(()))
                }
                _ => Poll::Ready(Err(TcpError::InvalidState)),
            },
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (shutdown) - returning InvalidState");
                Poll::Ready(Err(TcpError::InvalidState))
            }
        }
    }
}

// ============================================================================
// TcpListener - 非同期TCPリスナー
// ============================================================================

/// 非同期TCPリスナー
///
/// 【設計書】POSIXソケットAPIを模倣しない
/// bind/listen/acceptの代わりにnew/incomingを使用
pub struct TcpListener {
    local_addr: SocketAddr,
    backlog: Arc<PoisonLock<VecDeque<TcpStream>>>,
    accept_waker: Arc<PoisonLock<Option<Waker>>>,
}

impl TcpListener {
    /// 指定アドレスで新しいリスナーを作成（推奨API）
    ///
    /// 【設計書】POSIXのbind()と同様の動作
    pub fn bind(addr: SocketAddr) -> Result<Self, TcpError> {
        crate::net::stack::bind_tcp(addr)
    }

    // Legacy constructor `TcpListener::new` removed; use `TcpListener::bind(addr)` instead.


    /// ローカルアドレスを取得
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 次の接続を非同期で取得（推奨API）
    ///
    /// 【設計書】POSIXのaccept()ではなく、Futureベースの方式を採用
    pub async fn next_connection(&self) -> Result<(TcpStream, SocketAddr), TcpError> {
        AcceptFuture { listener: self }.await
    }


    /// 新しい接続をバックログに追加（内部使用）
    pub(crate) fn push_connection(&self, stream: TcpStream, _addr: SocketAddr) {
        match self.backlog.lock() {
            Ok(mut backlog) => {
                backlog.push_back(stream);

                match self.accept_waker.lock() {
                    Ok(mut wake_opt) => {
                        if let Some(waker) = wake_opt.take() {
                            waker.wake();
                        }
                    }
                    Err(_) => log::error!("[NET] TCP Waker poisoned - cannot wake acceptor"),
                }
            }
            Err(_) => log::error!("[NET] TCP Backlog poisoned - cannot push connection"),
        }
    }
}

// ============================================================================
// Future実装
// ============================================================================

/// 接続Future
pub(crate) struct ConnectFuture {
    tcb: Arc<PoisonLock<TcpControlBlock>>,
}

impl Future for ConnectFuture {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.tcb.lock() {
            Ok(mut tcb) => match tcb.state {
                TcpState::Established => Poll::Ready(Ok(())),
                TcpState::Closed => Poll::Ready(Err(TcpError::ConnectionRefused)),
                TcpState::SynSent | TcpState::SynReceived => {
                    tcb.connect_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                _ => Poll::Ready(Err(TcpError::InvalidState)),
            },
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in connect future - returning ConnectionRefused");
                Poll::Ready(Err(TcpError::ConnectionRefused))
            }
        }
    }
}

/// Connect future with timeout support
pub(crate) struct ConnectTimeoutFuture {
    tcb: Arc<PoisonLock<TcpControlBlock>>,
    start_us: u64,
    timeout_us: u64,
}

impl Future for ConnectTimeoutFuture {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.tcb.lock() {
            Ok(mut tcb) => match tcb.state {
                TcpState::Established => Poll::Ready(Ok(())),
                TcpState::Closed => Poll::Ready(Err(TcpError::ConnectionRefused)),
                TcpState::SynSent | TcpState::SynReceived => {
                    // Register waker
                    tcb.connect_waker = Some(cx.waker().clone());

                    // Check timeout
                    let now = crate::time::precise_time_nanos() / 1000;
                    if now.saturating_sub(self.start_us) >= self.timeout_us {
                        // Timeout: treat as Timeout error and close TCB
                        tcb.state = TcpState::Closed;
                        return Poll::Ready(Err(TcpError::Timeout));
                    }

                    Poll::Pending
                }
                _ => Poll::Ready(Err(TcpError::InvalidState)),
            },
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in connect timeout future - returning ConnectionRefused");
                Poll::Ready(Err(TcpError::ConnectionRefused))
            }
        }
    }
}

impl TcpStream {
    /// Connect with a timeout in microseconds
    pub async fn dial_timeout(addr: SocketAddr, timeout_us: u64) -> Result<Self, TcpError> {
        let local_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED, allocate_ephemeral_port());
        let stream = crate::net::stack::connect_tcp(local_addr, addr)?;
        let start = crate::time::precise_time_nanos() / 1000;
        let tcb = stream.tcb.clone();
        ConnectTimeoutFuture { tcb, start_us: start, timeout_us }.await?;
        Ok(stream)
    }
}

/// 読み取りFuture
pub struct ReadFuture<'a> {
    stream: &'a mut TcpStream,
    buf: &'a mut [u8],
}

impl<'a> Future for ReadFuture<'a> {
    type Output = Result<usize, TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_read(cx, this.buf)
    }
}

/// 書き込みFuture
pub struct WriteFuture<'a> {
    stream: &'a mut TcpStream,
    buf: &'a [u8],
}

impl<'a> Future for WriteFuture<'a> {
    type Output = Result<usize, TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_write(cx, this.buf)
    }
}

/// Flush Future
pub struct FlushFuture<'a> {
    stream: &'a mut TcpStream,
}

impl<'a> Future for FlushFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_flush(cx)
    }
}

/// Accept Future
pub(crate) struct AcceptFuture<'a> {
    listener: &'a TcpListener,
}

impl<'a> Future for AcceptFuture<'a> {
    type Output = Result<(TcpStream, SocketAddr), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.listener.backlog.lock() {
            Ok(mut backlog) => {
                if let Some(stream) = backlog.pop_front() {
                    let addr = stream
                        .peer_addr()
                        .unwrap_or(SocketAddr::new(Ipv4Addr::UNSPECIFIED, 0));
                    return Poll::Ready(Ok((stream, addr)));
                }

                match self.listener.accept_waker.lock() {
                    Ok(mut wake_opt) => *wake_opt = Some(cx.waker().clone()),
                    Err(_) => log::error!("[NET] TCP Waker poisoned - cannot set waker"),
                }

                Poll::Pending
            }
            Err(_) => {
                log::error!("[NET] TCP Backlog poisoned (accept) - returning InvalidState");
                Poll::Ready(Err(TcpError::InvalidState))
            }
        }
    }
}

/// シャットダウンFuture
pub(crate) struct ShutdownFuture<'a> {
    stream: &'a mut TcpStream,
}

impl<'a> Future for ShutdownFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_shutdown(cx)
    }
}

// ============================================================================
// 【設計書 6.2】ゼロコピーFuture
// ============================================================================

/// ゼロコピー読み取りFuture
///
/// パケットバッファの所有権をそのまま返す（コピーなし）
pub(crate) struct ZeroCopyReadFuture<'a> {
    stream: &'a mut TcpStream,
}

impl<'a> Future for ZeroCopyReadFuture<'a> {
    type Output = Option<PacketRef>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.stream.tcb.lock() {
            Ok(mut tcb) => {
                if tcb.state == TcpState::Closed {
                    return Poll::Ready(None);
                }

                if let Some(packet) = tcb.recv_buffer.pop_front() {
                    let len = packet.data().len();
                    tcb.stats.bytes_received += len as u64;
                    // パケットの所有権をそのまま返す（ゼロコピー）
                    return Poll::Ready(Some(packet));
                }

                tcb.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned (zero-copy read) - returning None");
                Poll::Ready(None)
            }
        }
    }
}

/// ゼロコピー書き込みFuture
///
/// パケットバッファの所有権をTCPスタックに移動（コピーなし）
pub(crate) struct ZeroCopyWriteFuture<'a> {
    stream: &'a mut TcpStream,
    packet: Option<PacketRef>,
}

impl<'a> Future for ZeroCopyWriteFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.stream.tcb.lock() {
            Ok(mut tcb) => {
                if tcb.state != TcpState::Established {
                    return Poll::Ready(Err(TcpError::InvalidState));
                }

                // Compute available bytes
                let available = core::cmp::min(tcb.cwnd, tcb.snd_wnd as u32)
                    .saturating_sub(tcb.outstanding_bytes.saturating_add(tcb.send_buffer_bytes)) as usize;

                if !tcb.can_send() || available == 0 {
                    tcb.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }

                if let Some(packet) = this.packet.take() {
                    let len = packet.data().len();
                    if len > available {
                        // Not enough window yet
                        this.packet = Some(packet);
                        tcb.write_waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                    tcb.send_buffer_bytes = tcb.send_buffer_bytes.saturating_add(len as u32);
                    tcb.send_buffer.push_back(packet);
                    tcb.stats.bytes_sent += len as u64;
                    tcb.stats.packets_sent += 1;
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(TcpError::InvalidState))
                }
            }
            Err(_) => {
                log::error!("[NET] TCP TCB poisoned in zero-copy write - returning InvalidState");
                Poll::Ready(Err(TcpError::InvalidState))
            }
        }
    }
}

// ============================================================================
// ヘルパー関数
// ============================================================================

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

pub(crate) static NEXT_EPHEMERAL_PORT: AtomicU16 = AtomicU16::new(49152);
pub(crate) static SEQ_COUNTER: AtomicU32 = AtomicU32::new(0);

/// エフェメラルポート割り当て
pub(crate) fn allocate_ephemeral_port() -> u16 {
    let port = NEXT_EPHEMERAL_PORT.fetch_add(1, Ordering::Relaxed);
    if port >= 65535 {
        NEXT_EPHEMERAL_PORT.store(49152, Ordering::Relaxed);
    }
    port
}
