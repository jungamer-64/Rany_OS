// ============================================================================
// kernel/src/net/l4/endpoint/event.rs
// ============================================================================
//! # イベントシステム - プロトコルスタック連携
//!
//! NetworkEvent, NetworkEventQueue, EventWaitFuture

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
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
    ///
    /// `src_ip` が `Some` の場合、指定されたIPをソースアドレスとして使用する。
    /// `None` の場合、スタックの設定IPアドレスを使用する。
    /// DHCP DISCOVERなど、ソースIPを 0.0.0.0 にする必要がある場合に `Some([0,0,0,0])` を指定する。
    RawUdpSend {
        src_port: u16,
        src_ip: Option<[u8; 4]>,
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
    /// NAT転送: 到達不能ICMPエラー送信（bridge RXパスから非同期オフロード）
    NatIcmpDestUnreachable {
        src_ip: [u8; 4],
        code: u8,
        next_hop_mtu: Option<u16>,
        original_packet: Vec<u8>,
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

    // ====================================================================
    // Async DHCP / TCP query events (complete async conversion)
    // ====================================================================

    /// 非同期DHCP状態取得
    AsyncGetDhcpState {
        result_slot: alloc::sync::Arc<PoisonLock<Option<crate::net::api::dhcp::DhcpRuntimeState>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCPリニュー
    AsyncDhcpRenew {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCPリリース
    AsyncDhcpRelease {
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCPディスカバー
    AsyncDhcpDiscover {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<crate::net::api::dhcp::DhcpOfferInfo>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCP最終拒否IP取得
    AsyncDhcpLastDeclined {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<[u8; 4]>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期DHCP最終解放IP取得
    AsyncDhcpLastReleased {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<[u8; 4]>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    /// 非同期TCP接続一覧取得
    AsyncGetTcpConnections {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::api::connections::TcpConnectionInfo>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
}

// ============================================================================
// ロックフリー有界 MPSC イベントキュー
// ============================================================================

/// リングバッファスロット状態
const SLOT_EMPTY: u8 = 0;
const SLOT_FULL: u8 = 1;

/// リングバッファスロット
///
/// 各スロットはアトミック状態フラグとイベントデータを保持する。
/// プロデューサーが CAS で書き込み位置を確保した後、
/// データ書き込み完了時に `state` を `FULL` に設定する。
struct EventSlot {
    /// スロット状態: EMPTY(0) または FULL(1)
    state: AtomicU8,
    /// イベントデータ（MaybeUninit で未初期化スロットを安全に表現）
    data: UnsafeCell<MaybeUninit<NetworkEvent>>,
}

// SAFETY: EventSlot は以下の理由で Send+Sync:
// - state は AtomicU8（本質的にスレッドセーフ）
// - data は状態遷移が排他的アクセスを保証:
//   - プロデューサー: CAS で書き込み位置を確保後にのみ書き込み
//   - コンシューマー: state == FULL の場合のみ読み出し、その後 EMPTY にリセット
unsafe impl Send for EventSlot {}
unsafe impl Sync for EventSlot {}

impl EventSlot {
    /// 空のスロットを作成（const fn で静的初期化対応）
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(SLOT_EMPTY),
            data: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

/// ロックフリー有界 MPSC イベントキュー
///
/// 複数のプロデューサー（ISR, ドライバ, プロトコル層）から
/// 単一のコンシューマー（network_event_task）への
/// イベント配信をロックフリーで実現する。
///
/// ## 設計
///
/// - 固定サイズリングバッファ（256スロット、2のべき乗でビットマスク高速化）
/// - CAS ベースのプロデューサー位置管理（MPSC 対応）
/// - 単一コンシューマーによる順序保証付き読み出し
/// - `AtomicWaker` による ISR-safe タスク起床
/// - 全操作がロック取得なしで完了（ISR コンテキストから安全に呼び出し可能）
///
/// ## メモリ安全性
///
/// プロデューサーは `write_pos` を CAS で確保し、排他的にスロットへ書き込む。
/// コンシューマーは `read_pos` を単独で管理し、`state == FULL` のスロットのみ読み出す。
/// スロット状態遷移（EMPTY → FULL → EMPTY）が排他的アクセスを保証する。
pub struct NetworkEventQueue {
    /// リングバッファスロット
    slots: [EventSlot; Self::CAPACITY],
    /// プロデューサー書き込み位置（単調増加、CAS で更新）
    write_pos: AtomicUsize,
    /// コンシューマー読み出し位置（単調増加、コンシューマーのみ更新）
    read_pos: AtomicUsize,
    /// ISR-safe Waker（ロックフリー状態機械ベース）
    waker: crate::sync::atomic_waker::AtomicWaker,
}

// SAFETY: NetworkEventQueue の各フィールドは Send+Sync
// - slots: EventSlot は Send+Sync（上記参照）
// - write_pos, read_pos: AtomicUsize（本質的にスレッドセーフ）
// - waker: AtomicWaker（Send+Sync 実装済み）
unsafe impl Send for NetworkEventQueue {}
unsafe impl Sync for NetworkEventQueue {}

impl NetworkEventQueue {
    /// キュー容量（2のべき乗で高速なインデックス計算）
    const CAPACITY: usize = 256;

    /// 新規作成
    pub const fn new() -> Self {
        Self {
            slots: [const { EventSlot::new() }; Self::CAPACITY],
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
            waker: crate::sync::atomic_waker::AtomicWaker::new(),
        }
    }

    /// イベント送信（プロデューサー側 — ISR コンテキストから安全に呼び出し可能）
    ///
    /// CAS ベースでスロットを確保し、ロック取得なしでイベントを書き込む。
    /// キュー満杯時は `false` を返す（バックプレッシャー）。
    pub fn send(&self, event: NetworkEvent) -> bool {
        loop {
            let write = self.write_pos.load(Ordering::Relaxed);
            let read = self.read_pos.load(Ordering::Acquire);

            // キュー満杯チェック
            if write.wrapping_sub(read) >= Self::CAPACITY {
                return false; // バックプレッシャー
            }

            // 書き込み位置を CAS で確保
            if self
                .write_pos
                .compare_exchange_weak(
                    write,
                    write.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                let idx = write & (Self::CAPACITY - 1); // ビットマスクで高速インデックス
                let slot = &self.slots[idx];

                // データ書き込み
                // SAFETY: CAS で排他的書き込み権を獲得済み。
                // 他のプロデューサーは異なるスロットに書き込む。
                unsafe {
                    (*slot.data.get()).write(event);
                }

                // スロットを FULL にマーク
                // Release: データ書き込みが先に完了することを保証
                slot.state.store(SLOT_FULL, Ordering::Release);

                // コンシューマータスクを起床（AtomicWaker — ロックフリー）
                self.waker.wake();

                return true;
            }

            // CAS 失敗 — 他のプロデューサーが先にスロットを確保。リトライ
            core::hint::spin_loop();
        }
    }

    /// イベント受信（コンシューマー側 — network_event_task 専用）
    ///
    /// 単一コンシューマー前提。ロック取得なしで次のイベントを読み出す。
    /// プロデューサーがスロットに書き込み中（CAS 成功 → state 更新前）の
    /// 場合は `None` を返し、次のポーリングで再試行する。
    pub fn recv(&self) -> Option<NetworkEvent> {
        let read = self.read_pos.load(Ordering::Relaxed);
        let idx = read & (Self::CAPACITY - 1);
        let slot = &self.slots[idx];

        // スロットにデータがあるかチェック
        // Acquire: プロデューサーのデータ書き込みを可視化
        if slot.state.load(Ordering::Acquire) != SLOT_FULL {
            return None;
        }

        // データ読み出し
        // SAFETY: 単一コンシューマーかつ state == FULL で排他的読み出し権を保持
        let event = unsafe { (*slot.data.get()).assume_init_read() };

        // スロットを EMPTY にリセット
        slot.state.store(SLOT_EMPTY, Ordering::Release);

        // 読み出し位置を進める
        self.read_pos.store(read.wrapping_add(1), Ordering::Release);

        Some(event)
    }

    /// 全イベント取得（バッチ処理用）
    pub fn drain_all(&self) -> Vec<NetworkEvent> {
        let mut events = Vec::new();
        while let Some(event) = self.recv() {
            events.push(event);
        }
        events
    }

    /// イベント待ち（非同期）
    pub fn wait_for_events(&self) -> EventWaitFuture<'_> {
        EventWaitFuture { queue: self }
    }

    /// イベントがあるか（高速チェック）
    #[inline]
    pub fn has_events(&self) -> bool {
        let read = self.read_pos.load(Ordering::Relaxed);
        let idx = read & (Self::CAPACITY - 1);
        self.slots[idx].state.load(Ordering::Acquire) == SLOT_FULL
    }

    /// キュー内イベント数（概算 — 並行操作中は正確でない場合がある）
    pub fn len(&self) -> usize {
        let write = self.write_pos.load(Ordering::Relaxed);
        let read = self.read_pos.load(Ordering::Relaxed);
        write.wrapping_sub(read)
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
