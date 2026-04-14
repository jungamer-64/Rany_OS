// ============================================================================
// kernel/src/net/l4/endpoint/event.rs
// ============================================================================
//! # イベントシステム - プロトコルスタック連携
//!
//! NetworkEvent, NetworkEventQueue, EventWaitFuture

use crate::net::runtime::{NetRuntimeHandle, context::default_runtime_context};
use crate::sync::{MpscRingBuffer, PoisonLock, WakerQueue};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll};

use super::types::{EndpointAddr, EndpointFd, EndpointType};
use crate::net::datapath::mempool::PacketRef;
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use kernel_api::resource::net::PacketPayload;

/// ネットワークイベント種別
#[derive(Debug)]
pub enum NetworkEvent {
    /// 着信パケット - プロトコルスタックへのオフロード
    IngressPacket {
        if_id: Option<NetIfId>,
        packet: PacketRef,
    },
    /// バッチ着信パケット - 複数パケットの一括通知
    /// ロック取得を1回に削減し、イベントキュー競合を低減する
    IngressBatch {
        if_id: Option<NetIfId>,
        packets: Vec<PacketRef>,
    },
    /// 再組立てパケット - プロトコルスタックへのオフロード
    ReassembledPacket {
        if_id: Option<NetIfId>,
        payload: PacketPayload,
    },
    /// 送信データ準備完了 - プロトコルスタックに送信を要求
    DataReady {
        fd: EndpointFd,
        endpoint_type: EndpointType,
    },
    /// TX 資源が解放された（デバイスが送信可能になった）
    TxAvailable,
    /// ソケットクローズ
    Close { fd: EndpointFd },
    /// UDP送信
    SendTo {
        fd: EndpointFd,
        payload: PacketPayload,
        remote: EndpointAddr,
    },
    /// TCP_NODELAY 設定
    SetNoDelay { fd: EndpointFd, nodelay: bool },
    /// QoS 優先度設定
    SetPriority { fd: EndpointFd, priority: u8 },
    /// Raw UDP送信（ソケット非経由・スタック直接）
    ///
    /// `src_ip` が `Some` の場合、指定されたIPをソースアドレスとして使用する。
    /// `None` の場合、スタックの設定IPアドレスを使用する。
    /// DHCP DISCOVERなど、ソースIPを 0.0.0.0 にする必要がある場合に `Some([0,0,0,0])` を指定する。
    RawUdpSend {
        src_port: u16,
        src_ip: Option<[u8; 4]>,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: PacketPayload,
        ttl: u8,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// Raw TCP送信（ソケット非経由・スタック直接）
    RawTcpSend {
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        payload: PacketPayload,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// Raw UDP IPv6送信
    RawUdpV6Send {
        src_port: u16,
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        dst_port: u16,
        payload: PacketPayload,
        ttl: u8,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// Raw TCP IPv6送信
    RawTcpV6Send {
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        payload: PacketPayload,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// ICMP Echo Request（非同期ping）
    IcmpEchoRequest { target: [u8; 4], sequence: u16 },
    /// 非同期 ICMP Echo 応答通知
    IcmpEchoReply {
        source: [u8; 4],
        sequence: u16,
        rtt_us: u64,
    },
    /// 非同期ARP解決リクエスト
    ///
    /// ARP要求を送信し、解決完了時にWakerで通知する。
    /// ISR/ポーリングコンテキストからのロック取得を回避する。
    ArpResolveRequest { target_ip: [u8; 4] },
    /// 非同期NDP解決リクエスト
    ///
    /// Neighbor Solicitation を送信し、解決完了時にWakerで通知する。
    NdpResolveRequest {
        if_id: Option<u16>,
        target_ip: [u8; 16],
    },
    /// ARP解決完了通知（ARPキャッシュ更新時に発火）
    ArpResolved { ip: [u8; 4], mac: [u8; 6] },
    /// 非同期マルチキャストグループ参加
    MulticastJoin {
        group: [u8; 4],
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期マルチキャストグループ離脱
    MulticastLeave {
        group: [u8; 4],
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期タイムアウト処理リクエスト
    ProcessTimeouts,
    /// インターフェース指定UDP送信（非同期版）
    RawUdpSendOn {
        if_id: u16,
        src_port: u16,
        src_ip: Option<[u8; 4]>,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: PacketPayload,
        ttl: u8,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// インターフェース指定TCP送信（非同期版）
    RawTcpSendOn {
        if_id: u16,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        payload: PacketPayload,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// インターフェース指定IPv6 UDP送信（非同期版）
    RawUdpV6SendOn {
        if_id: u16,
        src_port: u16,
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        dst_port: u16,
        payload: PacketPayload,
        ttl: u8,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// インターフェース指定IPv6 TCP送信（非同期版）
    RawTcpV6SendOn {
        if_id: u16,
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        payload: PacketPayload,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), super::types::EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期TCP connect（TcpConnectionを返す完全非同期版）
    TcpDialConnection {
        local: EndpointAddr,
        remote: EndpointAddr,
        scope: InterfaceScope,
        result_slot: alloc::sync::Arc<
            PoisonLock<
                Option<Result<crate::net::l4::tcp::TcpConnection, crate::net::l4::tcp::TcpError>>,
            >,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期TCP bind（TcpAcceptorを返す完全非同期版）
    TcpBindAcceptor {
        local: EndpointAddr,
        scope: InterfaceScope,
        backlog: u32,
        result_slot: alloc::sync::Arc<
            PoisonLock<
                Option<Result<crate::net::l4::tcp::TcpAcceptor, crate::net::l4::tcp::TcpError>>,
            >,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    // ====================================================================
    // NAT forwarding events (bridge → event queue → handler)
    // ====================================================================
    /// NAT転送: UDP転送（bridge RXパスから非同期オフロード）
    NatForwardUdp {
        if_id: u16,
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: PacketPayload,
        ttl: u8,
    },
    /// NAT転送: TCP転送（bridge RXパスから非同期オフロード）
    NatForwardTcp {
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        payload: PacketPayload,
        ttl: u8,
    },

    // ====================================================================
    // Async utility events (bridge/API → event queue → handler)
    // ====================================================================
    /// 非同期ICMP Echo送信（send_real_icmp_echo の非同期版）
    IcmpEcho {
        target: [u8; 4],
        sequence: u16,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<u64, ()>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ARP Probe送信（DHCPからのARPプローブ要求）
    ArpProbe { target_ip: [u8; 4] },
    /// 非同期ARPキャッシュ解決チェック（DHCP衝突検出用）
    ArpResolveCheck {
        target_ip: [u8; 4],
        requester_mac: [u8; 6],
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<bool>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCPv4リース適用
    DhcpApplyLease {
        if_id: Option<u16>,
        config: crate::net::services::dhcp::DhcpV4AppliedConfig,
    },
    /// 非同期DHCPv6リース適用
    DhcpV6ApplyLease {
        if_id: Option<u16>,
        config: crate::net::services::dhcp::DhcpV6AppliedConfig,
    },
    /// 非同期リンクローカルIPv6アドレス取得
    GetLinkLocal {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<[u8; 16]>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },

    // ====================================================================
    // Async config/diagnostics/firewall query events (API → event queue)
    // ====================================================================
    /// 非同期プライマリインターフェース設定取得
    GetPrimaryInterfaceConfig {
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Option<crate::net::api::config::InterfaceConfigSnapshot>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期インターフェース設定取得
    GetInterfaceConfig {
        if_id: u16,
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Option<crate::net::api::config::InterfaceConfigSnapshot>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期インターフェース設定一覧取得
    ListInterfaceConfigs {
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Vec<crate::net::api::config::InterfaceConfigSnapshot>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期インターフェース統計取得
    GetInterfaceStats {
        if_id: u16,
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Option<crate::net::api::config::InterfaceStatsSnapshot>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期インターフェース統計一覧取得
    ListInterfaceStats {
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Vec<crate::net::api::config::InterfaceStatsSnapshot>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期インターフェース一覧取得
    ListInterfaces {
        result_slot:
            alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::api::config::InterfaceSnapshot>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ネットワーク診断スナップショット取得
    GetNetworkSnapshot {
        result_slot: alloc::sync::Arc<PoisonLock<Option<crate::net::obs::NetSnapshot>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ネットワーク最新イベント取得
    GetNetworkRecentEvents {
        limit: usize,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::obs::NetTraceEvent>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ARPキャッシュ取得
    GetArpCache {
        result_slot:
            alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::api::connections::ArpCacheEntry>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ARPキャッシュ挿入
    ArpInsert { ip: [u8; 4], mac: [u8; 6] },
    /// 非同期UDPエンドポイント一覧取得
    GetUdpEndpoints {
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Vec<crate::net::api::connections::UdpEndpointInfo>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },

    // ====================================================================
    // Async DHCP / TCP query events (complete async conversion)
    // ====================================================================
    /// 非同期DHCP状態取得
    GetDhcpState {
        if_id: Option<u16>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<crate::net::api::dhcp::DhcpRuntimeState>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCP状態一覧取得
    ListDhcpStates {
        result_slot:
            alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::api::dhcp::InterfaceDhcpState>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCPリニュー
    DhcpRenew {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCPリリース
    DhcpRelease {
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCPディスカバー
    DhcpDiscover {
        result_slot:
            alloc::sync::Arc<PoisonLock<Option<Option<crate::net::api::dhcp::DhcpOfferInfo>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCP INFORM
    DhcpInform {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCP最終拒否IP取得
    DhcpLastDeclined {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<[u8; 4]>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCP最終解放IP取得
    DhcpLastReleased {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<[u8; 4]>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期TCP接続一覧取得
    GetTcpConnections {
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Vec<crate::net::api::connections::TcpConnectionInfo>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ファイアウォール有効化
    FirewallEnable {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), &'static str>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ファイアウォール無効化
    FirewallDisable {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), &'static str>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ファイアウォール状態取得
    FirewallStatus {
        result_slot: alloc::sync::Arc<PoisonLock<Option<alloc::string::String>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ファイアウォールルール一覧取得
    FirewallListRules {
        result_slot: alloc::sync::Arc<PoisonLock<Option<alloc::string::String>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ファイアウォール統計取得
    FirewallStats {
        result_slot: alloc::sync::Arc<PoisonLock<Option<alloc::string::String>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ファイアウォールルール追加
    FirewallAddRule {
        rule: crate::net::security::firewall::FirewallRule,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<u64, alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ファイアウォールルール削除
    FirewallRemoveRule {
        id: u64,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<bool, alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ファイアウォールルール全削除
    FirewallClearRules {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期ファイアウォールデフォルトポリシー設定
    FirewallSetDefaultPolicy {
        direction: crate::net::security::firewall::FirewallDirection,
        action: crate::net::security::firewall::FirewallAction,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
}

pub(crate) struct CommandFuture<T> {
    result_slot: alloc::sync::Arc<PoisonLock<Option<T>>>,
    waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
}

impl<T> Future for CommandFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub(crate) fn poll_command_result<T>(
    result_slot: &alloc::sync::Arc<PoisonLock<Option<T>>>,
    waker: &alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    cx: &mut Context<'_>,
) -> Poll<T> {
    if let Ok(mut slot) = result_slot.lock() {
        if let Some(result) = slot.take() {
            return Poll::Ready(result);
        }
    }

    waker.register(cx.waker());

    if let Ok(mut slot) = result_slot.lock() {
        if let Some(result) = slot.take() {
            return Poll::Ready(result);
        }
    }

    Poll::Pending
}

pub(crate) fn new_command_channel<T>() -> (
    alloc::sync::Arc<PoisonLock<Option<T>>>,
    alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    CommandFuture<T>,
) {
    let result_slot = alloc::sync::Arc::new(PoisonLock::new(None));
    let waker = alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new());
    let future = CommandFuture {
        result_slot: result_slot.clone(),
        waker: waker.clone(),
    };
    (result_slot, waker, future)
}

pub(crate) fn new_detached_command_channel<T>() -> (
    alloc::sync::Arc<PoisonLock<Option<T>>>,
    alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
) {
    let (result_slot, waker, _future) = new_command_channel();
    (result_slot, waker)
}

// ============================================================================
// ロックフリー有界 MPSC イベントキュー
// ============================================================================

const NETWORK_EVENT_QUEUE_CAPACITY: usize = 256;
const NETWORK_EVENT_QUEUE_BACKING_CAPACITY: usize = NETWORK_EVENT_QUEUE_CAPACITY + 1;

/// ロックフリー有界 MPSC イベントキュー
///
/// 複数のプロデューサー（ISR, ドライバ, プロトコル層）から
/// 単一のコンシューマー（network_event_task）への
/// イベント配信をロックフリーで実現する。
///
/// ## 設計
///
/// - 固定サイズリングバッファ（実効容量 256）
/// - shared `MpscRingBuffer` による順序保証付き配信
/// - `AtomicWaker` による ISR-safe タスク起床
/// - 全操作がロック取得なしで完了（ISR コンテキストから安全に呼び出し可能）
pub struct NetworkEventQueue {
    queue: MpscRingBuffer<NetworkEvent, NETWORK_EVENT_QUEUE_BACKING_CAPACITY>,
    /// ISR-safe Waker（ロックフリー状態機械ベース）
    waker: crate::sync::atomic_waker::AtomicWaker,
    /// タスクコンテキストのプロデューサー向け空き待ち通知
    space_waiters: WakerQueue,
}

impl NetworkEventQueue {
    /// キュー容量（2のべき乗で高速なインデックス計算）
    const CAPACITY: usize = NETWORK_EVENT_QUEUE_CAPACITY;

    /// 新規作成
    pub const fn new() -> Self {
        Self {
            queue: MpscRingBuffer::new(),
            waker: crate::sync::atomic_waker::AtomicWaker::new(),
            space_waiters: WakerQueue::new(),
        }
    }

    /// イベント送信（所有権を保持したまま失敗を返す版）
    fn send_owned(&self, event: NetworkEvent) -> Result<(), NetworkEvent> {
        match self.queue.push(event) {
            Ok(()) => {
                self.waker.wake();
                Ok(())
            }
            Err(event) => Err(event),
        }
    }

    /// イベント送信（プロデューサー側 — ISR コンテキストから安全に呼び出し可能）
    ///
    /// CAS ベースでスロットを確保し、ロック取得なしでイベントを書き込む。
    /// キュー満杯時は `false` を返す（バックプレッシャー）。
    pub fn send(&self, event: NetworkEvent) -> bool {
        self.send_owned(event).is_ok()
    }

    /// イベント受信（コンシューマー側 — network_event_task 専用）
    ///
    /// 単一コンシューマー前提。ロック取得なしで次のイベントを読み出す。
    pub fn recv(&self) -> Option<NetworkEvent> {
        let event = self.queue.pop()?;
        self.space_waiters.wake_all();
        Some(event)
    }

    /// 全イベント取得（バッチ処理用）
    pub fn drain_all(&self) -> Vec<NetworkEvent> {
        let mut events = Vec::new();
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(event) = self.recv() {
            events.push(event);
        }
        events
    }

    /// イベント待ち（非同期）
    pub fn wait_for_events(&self) -> EventWaitFuture<'_> {
        EventWaitFuture { queue: self }
    }

    /// キューに空きができるまで待機する。
    pub fn wait_for_space(&self) -> QueueSpaceFuture<'_> {
        QueueSpaceFuture { queue: self }
    }

    /// イベントがあるか（高速チェック）
    #[inline]
    pub fn has_events(&self) -> bool {
        !self.queue.is_empty()
    }

    /// キュー内イベント数（概算 — 並行操作中は正確でない場合がある）
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub const fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    /// キューが空か
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub fn reset_for_tests(&self) {
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self.recv().is_some() {}
        self.waker.clear();
        self.space_waiters.clear();
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

        // AtomicWaker に Waker を登録（ロックフリー）
        self.queue.waker.register(cx.waker());

        // 再度チェック（Waker 登録中にイベントが来た可能性）
        if let Some(event) = self.queue.recv() {
            Poll::Ready(event)
        } else {
            Poll::Pending
        }
    }
}

/// キュー空き待ちFuture
pub struct QueueSpaceFuture<'a> {
    queue: &'a NetworkEventQueue,
}

impl<'a> Future for QueueSpaceFuture<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.queue.len() < self.queue.capacity() {
            return Poll::Ready(());
        }

        self.queue.space_waiters.register(cx.waker());
        if self.queue.len() < self.queue.capacity() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn runtime_context() -> &'static crate::net::runtime::NetRuntimeContext {
    default_runtime_context()
}

fn runtime_context_for(
    runtime: NetRuntimeHandle,
) -> &'static crate::net::runtime::NetRuntimeContext {
    runtime.context()
}

/// イベントキューへの参照取得
pub fn event_queue() -> &'static NetworkEventQueue {
    &runtime_context().event_queue
}

pub fn event_queue_in(runtime: NetRuntimeHandle) -> &'static NetworkEventQueue {
    &runtime_context_for(runtime).event_queue
}

pub fn mark_event_task_running() {
    mark_event_task_running_in(crate::net::runtime::default_runtime());
}

pub fn mark_event_task_running_in(runtime: NetRuntimeHandle) {
    let context = runtime_context_for(runtime);
    let was_running = context.event_task_running.swap(true, Ordering::AcqRel);
    if !was_running {
        context.event_task_ready_waiters.wake_all();
    }
}

pub fn mark_event_task_stopped() {
    mark_event_task_stopped_in(crate::net::runtime::default_runtime());
}

pub fn mark_event_task_stopped_in(runtime: NetRuntimeHandle) {
    runtime_context_for(runtime)
        .event_task_running
        .store(false, Ordering::Release);
}

pub fn event_task_running() -> bool {
    event_task_running_in(crate::net::runtime::default_runtime())
}

pub fn event_task_running_in(runtime: NetRuntimeHandle) -> bool {
    runtime_context_for(runtime)
        .event_task_running
        .load(Ordering::Acquire)
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub fn reset_event_system_for_tests() {
    reset_event_system_for_tests_in(crate::net::runtime::default_runtime());
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub fn reset_event_system_for_tests_in(runtime: NetRuntimeHandle) {
    runtime_context_for(runtime)
        .event_task_running
        .store(false, Ordering::Release);
    runtime_context_for(runtime)
        .event_task_ready_waiters
        .clear();
    event_queue_in(runtime).reset_for_tests();
}

/// イベントタスク起動待ちFuture
pub struct EventTaskReadyFuture {
    runtime: NetRuntimeHandle,
}

impl Future for EventTaskReadyFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let runtime = self.runtime;
        if event_task_running_in(runtime) {
            return Poll::Ready(());
        }

        runtime_context_for(runtime)
            .event_task_ready_waiters
            .register(cx.waker());
        if event_task_running_in(runtime) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// イベント送信ヘルパー（バックプレッシャー対応）
use super::types::EndpointError;

#[inline]
pub fn enqueue_event(event: NetworkEvent) -> Result<(), EndpointError> {
    if event_queue().send(event) {
        Ok(())
    } else {
        Err(EndpointError::ResourceExhausted)
    }
}

/// イベント送信（エラー無視版 - 内部用）
#[inline]
pub fn enqueue_event_ignore(event: NetworkEvent) {
    let _ = event_queue().send(event);
}

#[inline]
pub fn enqueue_event_in(
    runtime: NetRuntimeHandle,
    event: NetworkEvent,
) -> Result<(), EndpointError> {
    if event_queue_in(runtime).send(event) {
        Ok(())
    } else {
        Err(EndpointError::ResourceExhausted)
    }
}

#[inline]
pub fn enqueue_event_ignore_in(runtime: NetRuntimeHandle, event: NetworkEvent) {
    let _ = event_queue_in(runtime).send(event);
}

pub fn wait_for_event_task() -> EventTaskReadyFuture {
    wait_for_event_task_in(crate::net::runtime::default_runtime())
}

pub fn wait_for_event_task_in(runtime: NetRuntimeHandle) -> EventTaskReadyFuture {
    EventTaskReadyFuture { runtime }
}

/// タスクコンテキスト向け非同期イベント送信Future
pub struct SendEventFuture {
    runtime: NetRuntimeHandle,
    event: Option<NetworkEvent>,
}

impl SendEventFuture {
    pub fn new(runtime: NetRuntimeHandle, event: NetworkEvent) -> Self {
        Self {
            runtime,
            event: Some(event),
        }
    }
}

impl Future for SendEventFuture {
    type Output = Result<(), EndpointError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let runtime = this.runtime;

        if !event_task_running_in(runtime) {
            runtime_context_for(runtime)
                .event_task_ready_waiters
                .register(cx.waker());
            if !event_task_running_in(runtime) {
                return Poll::Pending;
            }
        }

        let event = this
            .event
            .take()
            .expect("send event future polled after completion");
        match event_queue_in(runtime).send_owned(event) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(event) => {
                this.event = Some(event);
                event_queue_in(runtime).space_waiters.register(cx.waker());

                let retry = this
                    .event
                    .take()
                    .expect("send event future lost pending event");
                match event_queue_in(runtime).send_owned(retry) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(event) => {
                        this.event = Some(event);
                        Poll::Pending
                    }
                }
            }
        }
    }
}

pub fn send_event(event: NetworkEvent) -> SendEventFuture {
    send_event_in(crate::net::runtime::default_runtime(), event)
}

pub fn send_event_in(runtime: NetRuntimeHandle, event: NetworkEvent) -> SendEventFuture {
    SendEventFuture::new(runtime, event)
}

/// カスタムFuture向けの遅延ディスパッチ状態
pub struct EventDispatch {
    runtime: NetRuntimeHandle,
    enqueue: Option<SendEventFuture>,
}

impl EventDispatch {
    pub fn new() -> Self {
        Self::new_in(crate::net::runtime::default_runtime())
    }

    pub const fn new_in(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
            enqueue: None,
        }
    }

    pub fn poll<F>(&mut self, cx: &mut Context<'_>, event_fn: F) -> Poll<Result<(), EndpointError>>
    where
        F: FnOnce() -> NetworkEvent,
    {
        if self.enqueue.is_none() {
            self.enqueue = Some(send_event_in(self.runtime, event_fn()));
        }

        let enqueue = self
            .enqueue
            .as_mut()
            .expect("async event dispatch missing enqueue future");
        match Pin::new(enqueue).poll(cx) {
            Poll::Ready(result) => {
                self.enqueue = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Default for EventDispatch {
    fn default() -> Self {
        Self::new()
    }
}

/// バッチイベント送信（複数パケットを1回のロック取得で送信）
///
/// ロック取得を1回に削減し、高スループット受信パス向けの最適化。
/// 各パケットを個別に `enqueue_event_ignore` するより効率的。
#[inline]
pub fn send_batch_event_on(if_id: Option<NetIfId>, packets: Vec<PacketRef>) {
    send_batch_event_on_in(crate::net::runtime::default_runtime(), if_id, packets);
}

#[inline]
pub fn send_batch_event_on_in(
    runtime: NetRuntimeHandle,
    if_id: Option<NetIfId>,
    packets: Vec<PacketRef>,
) {
    if packets.is_empty() {
        return;
    }
    if packets.len() == 1 {
        // 1パケットなら通常パスを使用（Vec のオーバーヘッド回避）
        let mut packets = packets;
        if let Some(p) = packets.pop() {
            let _ = event_queue_in(runtime).send(NetworkEvent::IngressPacket { if_id, packet: p });
        }
        return;
    }
    let _ = event_queue_in(runtime).send(NetworkEvent::IngressBatch { if_id, packets });
}

#[inline]
pub fn send_batch_event(packets: Vec<PacketRef>) {
    send_batch_event_on(None, packets);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::l4::test_support::noop_waker;
    use core::task::{Context, Poll};

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn send_event_waits_for_event_task_readiness() {
        reset_event_system_for_tests();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = send_event(NetworkEvent::TxAvailable);

        assert!(matches!(Pin::new(&mut future).poll(&mut cx), Poll::Pending));

        mark_event_task_running();
        assert!(matches!(
            Pin::new(&mut future).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            event_queue().recv(),
            Some(NetworkEvent::TxAvailable)
        ));

        reset_event_system_for_tests();
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn send_event_waits_for_queue_space() {
        reset_event_system_for_tests();
        mark_event_task_running();

        for _ in 0..NetworkEventQueue::CAPACITY {
            assert!(enqueue_event(NetworkEvent::TxAvailable).is_ok());
        }

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = send_event(NetworkEvent::TxAvailable);

        assert!(matches!(Pin::new(&mut future).poll(&mut cx), Poll::Pending));
        assert!(matches!(
            event_queue().recv(),
            Some(NetworkEvent::TxAvailable)
        ));
        assert!(matches!(
            Pin::new(&mut future).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));

        reset_event_system_for_tests();
    }
}
