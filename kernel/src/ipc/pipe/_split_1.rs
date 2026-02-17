use super::*;


// ============================================================================
// Zero-Copy Channel - 設計書 5.3: RRef<T>によるゼロコピーIPC
// ============================================================================

use super::rref::{DomainId, RRef};

/// ゼロコピーチャンネルエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// チャンネルが閉じられている
    Disconnected,
    /// 送信側がフル
    Full,
    /// 受信側が空
    Empty,
    /// 送信側が閉じられている
    SendClosed,
    /// 受信側が閉じられている
    RecvClosed,
}

/// ゼロコピーチャンネル - RRef<T>を介したデータ転送
///
/// 設計書 5.3: データコピーなしで所有権のみ移動
pub struct ZeroCopyChannel<T> {
    /// 内部キュー
    queue: spin::Mutex<VecDeque<RRef<T>>>,
    /// 送信側が開いているか
    sender_open: AtomicBool,
    /// 受信側が開いているか
    receiver_open: AtomicBool,
    /// 送信待ちWaker
    send_wakers: spin::Mutex<VecDeque<Waker>>,
    /// 受信待ちWaker
    recv_wakers: spin::Mutex<VecDeque<Waker>>,
    /// 容量制限
    capacity: usize,
}

impl<T> ZeroCopyChannel<T> {
    /// 新しいゼロコピーチャンネルを作成
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            queue: spin::Mutex::new(VecDeque::with_capacity(capacity)),
            sender_open: AtomicBool::new(true),
            receiver_open: AtomicBool::new(true),
            send_wakers: spin::Mutex::new(VecDeque::new()),
            recv_wakers: spin::Mutex::new(VecDeque::new()),
            capacity,
        })
    }

    /// 送信（所有権を移動）
    ///
    /// データは一切コピーされない。RRefの所有権のみが移動する。
    pub fn send(&self, data: RRef<T>) -> Result<(), ChannelError> {
        if !self.receiver_open.load(Ordering::Acquire) {
            return Err(ChannelError::RecvClosed);
        }

        let mut queue = self.queue.lock();
        if queue.len() >= self.capacity {
            return Err(ChannelError::Full);
        }

        queue.push_back(data);

        // 受信待ちタスクを起床
        let mut wakers = self.recv_wakers.lock();
        if let Some(waker) = wakers.pop_front() {
            waker.wake();
        }

        Ok(())
    }

    /// 受信（所有権を取得）
    ///
    /// データは一切コピーされない。RRefの所有権のみが移動する。
    pub fn recv(&self) -> Result<RRef<T>, ChannelError> {
        if !self.sender_open.load(Ordering::Acquire) {
            let queue = self.queue.lock();
            if queue.is_empty() {
                return Err(ChannelError::Disconnected);
            }
        }

        let mut queue = self.queue.lock();
        if let Some(data) = queue.pop_front() {
            // 送信待ちタスクを起床
            let mut wakers = self.send_wakers.lock();
            if let Some(waker) = wakers.pop_front() {
                waker.wake();
            }
            Ok(data)
        } else {
            Err(ChannelError::Empty)
        }
    }

    /// 非同期送信
    pub fn poll_send(&self, data: RRef<T>, cx: &mut Context<'_>) -> Poll<Result<(), ChannelError>> {
        match self.send(data) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ChannelError::Full) => {
                let mut wakers = self.send_wakers.lock();
                wakers.push_back(cx.waker().clone());
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// 非同期受信
    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<RRef<T>, ChannelError>> {
        match self.recv() {
            Ok(data) => Poll::Ready(Ok(data)),
            Err(ChannelError::Empty) => {
                if !self.sender_open.load(Ordering::Acquire) {
                    return Poll::Ready(Err(ChannelError::Disconnected));
                }
                let mut wakers = self.recv_wakers.lock();
                wakers.push_back(cx.waker().clone());
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// 送信側をクローズ
    pub fn close_sender(&self) {
        self.sender_open.store(false, Ordering::Release);
        let mut wakers = self.recv_wakers.lock();
        while let Some(waker) = wakers.pop_front() {
            waker.wake();
        }
    }

    /// 受信側をクローズ
    pub fn close_receiver(&self) {
        self.receiver_open.store(false, Ordering::Release);
        let mut wakers = self.send_wakers.lock();
        while let Some(waker) = wakers.pop_front() {
            waker.wake();
        }
    }

    /// キューの長さ
    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    /// キューが空か
    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }
}

/// ゼロコピー送信端
pub struct ZeroCopySender<T> {
    channel: Arc<ZeroCopyChannel<T>>,
    owner: DomainId,
}

impl<T> ZeroCopySender<T> {
    /// 新しい送信端を作成
    pub fn new(channel: Arc<ZeroCopyChannel<T>>, owner: DomainId) -> Self {
        Self { channel, owner }
    }

    /// 値を送信（自動的にRRefにラップ）
    pub fn send(&self, value: T) -> Result<(), ChannelError> {
        let rref = RRef::new(self.owner, value);
        self.channel.send(rref)
    }

    /// RRefを直接送信
    pub fn send_rref(&self, rref: RRef<T>) -> Result<(), ChannelError> {
        self.channel.send(rref)
    }
}

impl<T> Drop for ZeroCopySender<T> {
    fn drop(&mut self) {
        self.channel.close_sender();
    }
}

impl<T> Clone for ZeroCopySender<T> {
    fn clone(&self) -> Self {
        Self {
            channel: self.channel.clone(),
            owner: self.owner,
        }
    }
}

/// ゼロコピー受信端
pub struct ZeroCopyReceiver<T> {
    channel: Arc<ZeroCopyChannel<T>>,
    owner: DomainId,
}

impl<T> ZeroCopyReceiver<T> {
    /// 新しい受信端を作成
    pub fn new(channel: Arc<ZeroCopyChannel<T>>, owner: DomainId) -> Self {
        Self { channel, owner }
    }

    /// RRefを受信
    pub fn recv(&self) -> Result<RRef<T>, ChannelError> {
        self.channel.recv().map(|mut rref| {
            // 所有権を受信側ドメインに移動
            rref = rref.move_to(self.owner);
            rref
        })
    }

    /// 値を受信（RRefから取り出し）
    pub fn recv_into(self) -> Result<T, ChannelError> {
        self.recv().map(|rref| rref.into_inner())
    }
}

impl<T> Drop for ZeroCopyReceiver<T> {
    fn drop(&mut self) {
        self.channel.close_receiver();
    }
}

/// ゼロコピーチャンネルのペアを作成
///
/// 設計書 5.3に準拠したゼロコピーIPC
pub fn zero_copy_channel<T>(
    capacity: usize,
    sender_domain: DomainId,
    receiver_domain: DomainId,
) -> (ZeroCopySender<T>, ZeroCopyReceiver<T>) {
    let channel = ZeroCopyChannel::new(capacity);
    let sender = ZeroCopySender::new(channel.clone(), sender_domain);
    let receiver = ZeroCopyReceiver::new(channel, receiver_domain);
    (sender, receiver)
}

#[cfg(test)]
mod tests;

