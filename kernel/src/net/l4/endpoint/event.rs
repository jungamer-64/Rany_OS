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
    /// バッチ着信パケット - 複数パケットの一括通知
    /// ロック取得を1回に削減し、イベントキュー競合を低減する
    IngressBatch { packets: Vec<PacketRef> },
    /// 再組立てパケット - プロトコルスタックへのオフロード
    ReassembledPacket { data: Vec<u8> },
    /// 送信データ準備完了 - プロトコルスタックに送信を要求
    DataReady {
        fd: EndpointFd,
        endpoint_type: EndpointType,
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
        ttl: u8,
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
        ttl: u8,
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
    /// 非同期 ICMP Echo 応答通知
    IcmpEchoReply {
        source: [u8; 4],
        sequence: u16,
        rtt_us: u64,
    },
    /// 非同期TCP bind（ロック競合回避）
    AsyncTcpBind {
        local: EndpointAddr,
        /// Waker通知のための共有チャネル
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期UDP bind（ロック競合回避）
    AsyncUdpBind {
        port: u16,
        /// 結果通知用の共有スロット
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ARP解決リクエスト
    ///
    /// ARP要求を送信し、解決完了時にWakerで通知する。
    /// ISR/ポーリングコンテキストからのロック取得を回避する。
    ArpResolveRequest {
        target_ip: [u8; 4],
    },
    /// ARP解決完了通知（ARPキャッシュ更新時に発火）
    ArpResolved {
        ip: [u8; 4],
        mac: [u8; 6],
    },
    /// 非同期TCP connect（イベントキュー経由・ロック競合回避）
    AsyncTcpConnect {
        local: EndpointAddr,
        remote: EndpointAddr,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期マルチキャストグループ参加
    AsyncMulticastJoin {
        group: [u8; 4],
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期マルチキャストグループ離脱
    AsyncMulticastLeave {
        group: [u8; 4],
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期UDP unbind（イベントキュー経由・ロック競合回避）
    AsyncUnbindUdp {
        port: u16,
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期TCP unbind（イベントキュー経由・ロック競合回避）
    AsyncUnbindTcp {
        local: EndpointAddr,
        remote: EndpointAddr,
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期TCPリスナー unbind（イベントキュー経由・ロック競合回避）
    AsyncUnbindTcpListener {
        local: EndpointAddr,
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期TCP bind with token（イベントキュー経由・ロック競合回避）
    AsyncTcpBindWithToken {
        local: EndpointAddr,
        token: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期UDP bind with token（イベントキュー経由・ロック競合回避）
    AsyncUdpBindWithToken {
        port: u16,
        token: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期IPv6グローバルアドレス適用
    AsyncApplyIpv6Address {
        addr: [u8; 16],
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期タイムアウト処理リクエスト
    AsyncProcessTimeouts,
    /// インターフェース指定UDP送信（非同期版）
    RawUdpSendOn {
        if_id: u16,
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        data: Vec<u8>,
        ttl: u8,
    },
    /// インターフェース指定TCP送信（非同期版）
    RawTcpSendOn {
        if_id: u16,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        segment: Vec<u8>,
    },
    /// インターフェース指定IPv6 UDP送信（非同期版）
    RawUdpV6SendOn {
        if_id: u16,
        src_port: u16,
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        dst_port: u16,
        data: Vec<u8>,
        ttl: u8,
    },
    /// 非同期TCP connect（TcpStreamを返す完全非同期版）
    AsyncTcpConnectStream {
        local: EndpointAddr,
        remote: EndpointAddr,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<crate::net::l4::tcp::TcpStream, crate::net::l4::tcp::TcpError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期TCP bind（TcpListenerを返す完全非同期版）
    AsyncTcpBindListener {
        local: EndpointAddr,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<crate::net::l4::tcp::TcpListener, crate::net::l4::tcp::TcpError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期TCP bind with token（TcpListenerを返す完全非同期版）
    AsyncTcpBindListenerWithToken {
        local: EndpointAddr,
        token: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<crate::net::l4::tcp::TcpListener, crate::net::l4::tcp::TcpError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期UDP bind（UdpEndpointを返す完全非同期版）
    AsyncUdpBindEndpoint {
        port: u16,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<crate::net::l4::udp::UdpEndpoint>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期UDP bind with token（UdpEndpointを返す完全非同期版）
    AsyncUdpBindEndpointWithToken {
        port: u16,
        token: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<crate::net::l4::udp::UdpEndpoint>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },

    // ====================================================================
    // NAT forwarding events (bridge → event queue → handler)
    // ====================================================================

    /// NAT転送: TTL超過ICMPエラー送信（bridge RXパスから非同期オフロード）
    NatIcmpTimeExceeded {
        src_ip: [u8; 4],
        original_ip_header: Vec<u8>,
    },
    /// NAT転送: UDP転送（bridge RXパスから非同期オフロード）
    NatForwardUdp {
        if_id: u16,
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: Vec<u8>,
        ttl: u8,
    },
    /// NAT転送: TCP転送（bridge RXパスから非同期オフロード）
    NatForwardTcp {
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        segment: Vec<u8>,
        ttl: u8,
    },

    // ====================================================================
    // Async utility events (bridge/API → event queue → handler)
    // ====================================================================

    /// 非同期ICMP Echo送信（send_real_icmp_echo の非同期版）
    AsyncIcmpEcho {
        target: [u8; 4],
        sequence: u16,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<u64, ()>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ARP Probe送信（DHCPからのARPプローブ要求）
    AsyncArpProbe {
        target_ip: [u8; 4],
    },
    /// 非同期ARPキャッシュ解決チェック（DHCP衝突検出用）
    AsyncArpResolveCheck {
        target_ip: [u8; 4],
        requester_mac: [u8; 6],
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<bool>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCPリース適用
    AsyncDhcpApplyLease {
        ip: [u8; 4],
        subnet: [u8; 4],
        gateway: [u8; 4],
        dns: [u8; 4],
        hostname: Vec<u8>,
    },
    /// 非同期リンクローカルIPv6アドレス取得
    AsyncGetLinkLocal {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<[u8; 16]>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },

    // ====================================================================
    // Async config/stats query events (API layer → event queue → handler)
    // ====================================================================

    /// 非同期ネットワーク設定取得
    AsyncGetConfig {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<crate::net::api::config::NetworkConfigSnapshot>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ネットワーク統計取得
    AsyncGetStats {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<crate::net::api::config::NetworkStatsSnapshot>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ARPキャッシュ取得
    AsyncGetArpCache {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::api::connections::ArpCacheEntry>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ARPキャッシュ挿入
    AsyncArpInsert {
        ip: [u8; 4],
        mac: [u8; 6],
    },
    /// 非同期UDPエンドポイント一覧取得
    AsyncGetUdpEndpoints {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::api::connections::UdpEndpointInfo>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
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

/// バッチイベント送信（複数パケットを1回のロック取得で送信）
///
/// ロック取得を1回に削減し、高スループット受信パス向けの最適化。
/// 各パケットを個別に `send_event_ignore` するより効率的。
#[inline]
pub fn send_batch_event(packets: Vec<PacketRef>) {
    if packets.is_empty() {
        return;
    }
    if packets.len() == 1 {
        // 1パケットなら通常パスを使用（Vec のオーバーヘッド回避）
        let mut packets = packets;
        if let Some(p) = packets.pop() {
            let _ = NETWORK_EVENT_QUEUE.send(NetworkEvent::IngressPacket { packet: p });
        }
        return;
    }
    let _ = NETWORK_EVENT_QUEUE.send(NetworkEvent::IngressBatch { packets });
}
