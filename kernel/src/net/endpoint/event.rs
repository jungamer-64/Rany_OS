//! # イベントシステム - プロトコルスタック連携
//!
//! NetworkEvent, NetworkEventQueue, EventWaitFuture

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use spin::Mutex;

use super::types::{SocketAddr, SocketFd, SocketType};

/// ネットワークイベント種別
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// 送信データ準備完了 - プロトコルスタックに送信を要求
    DataReady {
        fd: SocketFd,
        socket_type: SocketType,
    },
    /// 接続要求 - TCPハンドシェイク開始
    Connect {
        fd: SocketFd,
        local: SocketAddr,
        remote: SocketAddr,
    },
    /// リッスン開始
    Listen {
        fd: SocketFd,
        local: SocketAddr,
        backlog: u32,
    },
    /// ソケットクローズ
    Close { fd: SocketFd },
    /// UDP送信
    SendTo {
        fd: SocketFd,
        data: Vec<u8>,
        remote: SocketAddr,
    },
}

/// イベントキュー（ロックフリーリングバッファ）
pub struct NetworkEventQueue {
    events: Mutex<VecDeque<NetworkEvent>>,
    /// イベント待ちWaker
    waker: Mutex<Option<core::task::Waker>>,
    /// イベントあり通知フラグ
    has_events: AtomicBool,
}

impl NetworkEventQueue {
    /// キュー容量
    const CAPACITY: usize = 256;

    /// 新規作成
    pub const fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            waker: Mutex::new(None),
            has_events: AtomicBool::new(false),
        }
    }

    /// イベント送信（ソケット層から呼ばれる）
    pub fn send(&self, event: NetworkEvent) -> bool {
        let mut events = self.events.lock();
        if events.len() >= Self::CAPACITY {
            return false; // バックプレッシャー
        }
        events.push_back(event);
        self.has_events.store(true, Ordering::Release);

        // 待機中のネットワークタスクを起こす
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
        true
    }

    /// イベント受信（ネットワークタスクから呼ばれる）
    pub fn recv(&self) -> Option<NetworkEvent> {
        let mut events = self.events.lock();
        let event = events.pop_front();
        if events.is_empty() {
            self.has_events.store(false, Ordering::Release);
        }
        event
    }

    /// 全イベント取得（バッチ処理用）
    pub fn drain_all(&self) -> Vec<NetworkEvent> {
        let mut events = self.events.lock();
        self.has_events.store(false, Ordering::Release);
        events.drain(..).collect()
    }

    /// イベント待ち（非同期）
    pub fn wait_for_events(&self) -> EventWaitFuture<'_> {
        EventWaitFuture { queue: self }
    }

    /// イベントがあるか
    #[inline]
    pub fn has_events(&self) -> bool {
        self.has_events.load(Ordering::Acquire)
    }

    /// キュー内イベント数
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    /// キューが空か
    pub fn is_empty(&self) -> bool {
        !self.has_events()
    }
}

/// イベント待ちFuture
pub struct EventWaitFuture<'a> {
    queue: &'a NetworkEventQueue,
}

impl<'a> Future for EventWaitFuture<'a> {
    type Output = NetworkEvent;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // まずイベントがあるかチェック
        if let Some(event) = self.queue.recv() {
            return Poll::Ready(event);
        }

        // Wakerを登録
        *self.queue.waker.lock() = Some(cx.waker().clone());

        // 再度チェック（Waker登録中にイベントが来た可能性）
        if let Some(event) = self.queue.recv() {
            Poll::Ready(event)
        } else {
            Poll::Pending
        }
    }
}

/// グローバルイベントキュー
static NETWORK_EVENT_QUEUE: NetworkEventQueue = NetworkEventQueue::new();

/// イベントキューへの参照取得
pub fn event_queue() -> &'static NetworkEventQueue {
    &NETWORK_EVENT_QUEUE
}

/// イベント送信ヘルパー（バックプレッシャー対応）
use super::types::SocketError;

#[inline]
pub fn send_event(event: NetworkEvent) -> Result<(), SocketError> {
    if NETWORK_EVENT_QUEUE.send(event) {
        Ok(())
    } else {
        Err(SocketError::ResourceExhausted)
    }
}

/// イベント送信（エラー無視版 - 内部用）
#[inline]
pub fn send_event_ignore(event: NetworkEvent) {
    let _ = NETWORK_EVENT_QUEUE.send(event);
}
