// ============================================================================
// kernel/src/net/endpoint/event.rs
// ============================================================================
//! # イベントシステム - プロトコルスタック連携
//!
//! NetworkEvent, NetworkEventQueue, EventWaitFuture

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use crate::sync::PoisonLock;

use super::types::{EndpointAddr, EndpointFd, EndpointType};
use crate::net::datapath::mempool::PacketRef;

/// ネットワークイベント種別
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// 着信パケット - プロトコルスタックへのオフロード
    IngressPacket { packet: PacketRef },
    /// 再組立てパケット - プロトコルスタックへのオフロード
    ReassembledPacket { data: Vec<u8> },
    /// 送信データ準備完了 - プロトコルスタックに送信を要求
    DataReady {
        fd: EndpointFd,
        socket_type: EndpointType,
    },
    /// TX 資源が解放された（デバイスが送信可能になった）
    TxAvailable,
    /// 接続要求 - TCPハンドシェイク開始
    Connect {
        fd: EndpointFd,
        local: EndpointAddr,
        remote: EndpointAddr,
    },
    /// リッスン開始
    Listen {
        fd: EndpointFd,
        local: EndpointAddr,
        backlog: u32,
    },
    /// ソケットクローズ
    Close { fd: EndpointFd },
    /// UDP送信
    SendTo {
        fd: EndpointFd,
        data: Vec<u8>,
        remote: EndpointAddr,
    },
    /// TCP_NODELAY 設定
    SetNoDelay {
        fd: EndpointFd,
        nodelay: bool,
    },
    /// QoS 優先度設定
    SetPriority {
        fd: EndpointFd,
        priority: u8,
    },
    /// Raw UDP送信（ソケット非経由・スタック直接）
    RawUdpSend {
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        data: Vec<u8>,
    },
    /// Raw TCP送信（ソケット非経由・スタック直接）
    RawTcpSend {
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        segment: Vec<u8>,
    },
    /// Raw UDP IPv6送信
    RawUdpV6Send {
        src_port: u16,
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        dst_port: u16,
        data: Vec<u8>,
    },
    /// Raw TCP IPv6送信
    RawTcpV6Send {
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        segment: Vec<u8>,
    },
    /// ICMP Echo Request（非同期ping）
    IcmpEchoRequest {
        target: [u8; 4],
        sequence: u16,
    },
}

/// イベントキュー（ロックフリーリングバッファ）
pub struct NetworkEventQueue {
    events: PoisonLock<VecDeque<NetworkEvent>>,
    /// イベント待ちWaker
    waker: PoisonLock<Option<core::task::Waker>>,
    /// イベントあり通知フラグ
    has_events: AtomicBool,
}

impl NetworkEventQueue {
    /// キュー容量
    const CAPACITY: usize = 256;

    /// 新規作成
    pub const fn new() -> Self {
        Self {
            events: PoisonLock::new(VecDeque::new()),
            waker: PoisonLock::new(None),
            has_events: AtomicBool::new(false),
        }
    }

    /// イベント送信（ソケット層から呼ばれる）
    pub fn send(&self, event: NetworkEvent) -> bool {
        let Ok(mut events) = self.events.lock() else { return false; };
        if events.len() >= Self::CAPACITY {
            return false; // バックプレッシャー
        }
        events.push_back(event);
        self.has_events.store(true, Ordering::Release);

        // 待機中のネットワークタスクを起こす
        if let Ok(mut waker_guard) = self.waker.lock() {
            if let Some(waker) = waker_guard.take() {
                waker.wake();
            }
        }
        true
    }

    /// イベント受信（ネットワークタスクから呼ばれる）
    pub fn recv(&self) -> Option<NetworkEvent> {
        let Ok(mut events) = self.events.lock() else { return None; };
        let event = events.pop_front();
        if events.is_empty() {
            self.has_events.store(false, Ordering::Release);
        }
        event
    }

    /// 全イベント取得（バッチ処理用）
    pub fn drain_all(&self) -> Vec<NetworkEvent> {
        let Ok(mut events) = self.events.lock() else { return Vec::new(); };
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
        self.events.lock().map(|g| g.len()).unwrap_or(0)
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
        if let Ok(mut w) = self.queue.waker.lock() {
            *w = Some(cx.waker().clone());
        }

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
use super::types::EndpointError;

#[inline]
pub fn send_event(event: NetworkEvent) -> Result<(), EndpointError> {
    if NETWORK_EVENT_QUEUE.send(event) {
        Ok(())
    } else {
        Err(EndpointError::ResourceExhausted)
    }
}

/// イベント送信（エラー無視版 - 内部用）
#[inline]
pub fn send_event_ignore(event: NetworkEvent) {
    let _ = NETWORK_EVENT_QUEUE.send(event);
}
