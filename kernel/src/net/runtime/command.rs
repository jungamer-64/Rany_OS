// ============================================================================
// kernel/src/net/runtime/command.rs - Runtime command bus
// ============================================================================
//! # Runtime command bus
//!
//! RuntimeCommand, RuntimeCommandQueue, CommandWaitFuture

use crate::net::runtime::{NetRuntimeHandle, context::default_runtime_context};
use crate::sync::{MpscRingBuffer, PoisonLock, WakerQueue};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll};

use crate::net::datapath::mempool::PacketRef;
use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId};
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use kernel_api::resource::net::PacketPayload;

#[derive(Debug)]
pub(crate) enum RuntimeCommand {
    Ingress(IngressCommand),
    Transport(TransportCommand),
    Control(ControlCommand),
}

#[derive(Debug)]
pub(crate) enum IngressCommand {
    Packet {
        if_id: Option<NetIfId>,
        packet: PacketRef,
    },
    Batch {
        if_id: Option<NetIfId>,
        packets: Vec<PacketRef>,
    },
    Reassembled {
        if_id: Option<NetIfId>,
        payload: PacketPayload,
    },
}

#[derive(Debug)]
pub(crate) enum TransportCommand {
    TcpDataReady {
        socket_id: SocketId,
    },
    TxAvailable,
    CloseSocket {
        socket_id: SocketId,
    },
    UdpSendTo {
        socket_id: SocketId,
        payload: PacketPayload,
        remote: EndpointAddr,
    },
    SetTcpNoDelay {
        socket_id: SocketId,
        nodelay: bool,
    },
    SetSocketPriority {
        socket_id: SocketId,
        priority: u8,
    },
    RawUdpSend {
        src_port: u16,
        src_ip: Option<[u8; 4]>,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: PacketPayload,
        ttl: u8,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    RawTcpSend {
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        payload: PacketPayload,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    RawUdpV6Send {
        src_port: u16,
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        dst_port: u16,
        payload: PacketPayload,
        ttl: u8,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    RawTcpV6Send {
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        payload: PacketPayload,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    RawUdpSendOn {
        if_id: u16,
        src_port: u16,
        src_ip: Option<[u8; 4]>,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: PacketPayload,
        ttl: u8,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    RawTcpSendOn {
        if_id: u16,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        payload: PacketPayload,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    RawUdpV6SendOn {
        if_id: u16,
        src_port: u16,
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        dst_port: u16,
        payload: PacketPayload,
        ttl: u8,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    RawTcpV6SendOn {
        if_id: u16,
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        payload: PacketPayload,
        completion_id: Option<u64>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), EndpointError>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    TcpDial {
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
    TcpBind {
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
}

#[derive(Debug)]
pub(crate) enum ControlCommand {
    IcmpEchoRequest {
        target: [u8; 4],
        sequence: u16,
    },
    IcmpEchoReply {
        source: [u8; 4],
        sequence: u16,
        rtt_us: u64,
    },
    ArpResolveRequest {
        target_ip: [u8; 4],
    },
    NdpResolveRequest {
        if_id: Option<u16>,
        target_ip: [u8; 16],
    },
    ArpResolved {
        ip: [u8; 4],
        mac: [u8; 6],
    },
    MulticastJoin {
        group: [u8; 4],
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    MulticastLeave {
        group: [u8; 4],
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    ProcessTimeouts,
    NatForwardUdp {
        if_id: u16,
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: PacketPayload,
        ttl: u8,
    },
    NatForwardTcp {
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        payload: PacketPayload,
        ttl: u8,
    },
    IcmpEcho {
        target: [u8; 4],
        sequence: u16,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<u64, ()>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    ArpProbe {
        target_ip: [u8; 4],
    },
    ArpResolveCheck {
        target_ip: [u8; 4],
        requester_mac: [u8; 6],
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<bool>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    DhcpApplyLease {
        if_id: Option<u16>,
        config: crate::net::services::dhcp::DhcpV4AppliedConfig,
    },
    DhcpV6ApplyLease {
        if_id: Option<u16>,
        config: crate::net::services::dhcp::DhcpV6AppliedConfig,
    },
    GetLinkLocal {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<[u8; 16]>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    GetPrimaryInterfaceConfig {
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Option<crate::net::api::config::InterfaceConfigSnapshot>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    GetInterfaceConfig {
        if_id: u16,
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Option<crate::net::api::config::InterfaceConfigSnapshot>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    ListInterfaceConfigs {
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Vec<crate::net::api::config::InterfaceConfigSnapshot>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    GetInterfaceStats {
        if_id: u16,
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Option<crate::net::api::config::InterfaceStatsSnapshot>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    ListInterfaceStats {
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Vec<crate::net::api::config::InterfaceStatsSnapshot>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    ListInterfaces {
        result_slot:
            alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::api::config::InterfaceSnapshot>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    GetNetworkSnapshot {
        result_slot: alloc::sync::Arc<PoisonLock<Option<crate::net::obs::NetSnapshot>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    GetNetworkRecentEvents {
        limit: usize,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::obs::NetTraceEvent>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    GetArpCache {
        result_slot:
            alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::api::connections::ArpCacheEntry>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    ArpInsert {
        ip: [u8; 4],
        mac: [u8; 6],
    },
    GetUdpEndpoints {
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Vec<crate::net::api::connections::UdpEndpointInfo>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    GetDhcpState {
        if_id: Option<u16>,
        result_slot: alloc::sync::Arc<PoisonLock<Option<crate::net::api::dhcp::DhcpRuntimeState>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    ListDhcpStates {
        result_slot:
            alloc::sync::Arc<PoisonLock<Option<Vec<crate::net::api::dhcp::InterfaceDhcpState>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    DhcpRenew {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    DhcpRelease {
        result_slot: alloc::sync::Arc<PoisonLock<Option<bool>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    DhcpDiscover {
        result_slot:
            alloc::sync::Arc<PoisonLock<Option<Option<crate::net::api::dhcp::DhcpOfferInfo>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    DhcpInform {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    DhcpLastDeclined {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<[u8; 4]>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    DhcpLastReleased {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Option<[u8; 4]>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    GetTcpConnections {
        result_slot: alloc::sync::Arc<
            PoisonLock<Option<Vec<crate::net::api::connections::TcpConnectionInfo>>>,
        >,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    FirewallEnable {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), &'static str>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    FirewallDisable {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), &'static str>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    FirewallStatus {
        result_slot: alloc::sync::Arc<PoisonLock<Option<alloc::string::String>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    FirewallListRules {
        result_slot: alloc::sync::Arc<PoisonLock<Option<alloc::string::String>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    FirewallStats {
        result_slot: alloc::sync::Arc<PoisonLock<Option<alloc::string::String>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    FirewallAddRule {
        rule: crate::net::security::firewall::FirewallRule,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<u64, alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    FirewallRemoveRule {
        id: u64,
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<bool, alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
    FirewallClearRules {
        result_slot: alloc::sync::Arc<PoisonLock<Option<Result<(), alloc::string::String>>>>,
        waker: alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>,
    },
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
/// 単一のコンシューマー（runtime_command_task）への
/// イベント配信をロックフリーで実現する。
///
/// ## 設計
///
/// - 固定サイズリングバッファ（実効容量 256）
/// - shared `MpscRingBuffer` による順序保証付き配信
/// - `AtomicWaker` による ISR-safe タスク起床
/// - 全操作がロック取得なしで完了（ISR コンテキストから安全に呼び出し可能）
pub(crate) struct RuntimeCommandQueue {
    queue: MpscRingBuffer<RuntimeCommand, NETWORK_EVENT_QUEUE_BACKING_CAPACITY>,
    /// ISR-safe Waker（ロックフリー状態機械ベース）
    waker: crate::sync::atomic_waker::AtomicWaker,
    /// タスクコンテキストのプロデューサー向け空き待ち通知
    space_waiters: WakerQueue,
}

impl RuntimeCommandQueue {
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
    fn send_owned(&self, command: RuntimeCommand) -> Result<(), RuntimeCommand> {
        match self.queue.push(command) {
            Ok(()) => {
                self.waker.wake();
                Ok(())
            }
            Err(command) => Err(command),
        }
    }

    /// イベント送信（プロデューサー側 — ISR コンテキストから安全に呼び出し可能）
    ///
    /// CAS ベースでスロットを確保し、ロック取得なしでイベントを書き込む。
    /// キュー満杯時は `false` を返す（バックプレッシャー）。
    pub(crate) fn send(&self, command: RuntimeCommand) -> bool {
        self.send_owned(command).is_ok()
    }

    /// イベント受信（コンシューマー側 — runtime_command_task 専用）
    ///
    /// 単一コンシューマー前提。ロック取得なしで次のイベントを読み出す。
    pub(crate) fn recv(&self) -> Option<RuntimeCommand> {
        let command = self.queue.pop()?;
        self.space_waiters.wake_all();
        Some(command)
    }

    /// 全イベント取得（バッチ処理用）
    pub(crate) fn drain_all(&self) -> Vec<RuntimeCommand> {
        let mut commands = Vec::new();
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(command) = self.recv() {
            commands.push(command);
        }
        commands
    }

    /// イベント待ち（非同期）
    pub(crate) fn wait_for_events(&self) -> CommandWaitFuture<'_> {
        CommandWaitFuture { queue: self }
    }

    /// キューに空きができるまで待機する。
    pub(crate) fn wait_for_space(&self) -> QueueSpaceFuture<'_> {
        QueueSpaceFuture { queue: self }
    }

    /// イベントがあるか（高速チェック）
    #[inline]
    pub(crate) fn has_events(&self) -> bool {
        !self.queue.is_empty()
    }

    /// キュー内イベント数（概算 — 並行操作中は正確でない場合がある）
    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }

    pub(crate) const fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    /// キューが空か
    pub(crate) fn is_empty(&self) -> bool {
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
pub(crate) struct CommandWaitFuture<'a> {
    queue: &'a RuntimeCommandQueue,
}

impl<'a> Future for CommandWaitFuture<'a> {
    type Output = RuntimeCommand;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // まずイベントがあるかチェック
        if let Some(command) = self.queue.recv() {
            return Poll::Ready(command);
        }

        // AtomicWaker に Waker を登録（ロックフリー）
        self.queue.waker.register(cx.waker());

        // 再度チェック（Waker 登録中にイベントが来た可能性）
        if let Some(command) = self.queue.recv() {
            Poll::Ready(command)
        } else {
            Poll::Pending
        }
    }
}

/// キュー空き待ちFuture
pub(crate) struct QueueSpaceFuture<'a> {
    queue: &'a RuntimeCommandQueue,
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
pub(crate) fn command_queue() -> &'static RuntimeCommandQueue {
    &runtime_context().command_queue
}

pub(crate) fn command_queue_in(runtime: NetRuntimeHandle) -> &'static RuntimeCommandQueue {
    &runtime_context_for(runtime).command_queue
}

pub(crate) fn mark_command_task_running() {
    mark_command_task_running_in(crate::net::runtime::default_runtime());
}

pub(crate) fn mark_command_task_running_in(runtime: NetRuntimeHandle) {
    let context = runtime_context_for(runtime);
    let was_running = context.command_task_running.swap(true, Ordering::AcqRel);
    if !was_running {
        context.command_task_ready_waiters.wake_all();
    }
}

pub(crate) fn mark_command_task_stopped() {
    mark_command_task_stopped_in(crate::net::runtime::default_runtime());
}

pub(crate) fn mark_command_task_stopped_in(runtime: NetRuntimeHandle) {
    runtime_context_for(runtime)
        .command_task_running
        .store(false, Ordering::Release);
}

pub(crate) fn command_task_running() -> bool {
    command_task_running_in(crate::net::runtime::default_runtime())
}

pub(crate) fn command_task_running_in(runtime: NetRuntimeHandle) -> bool {
    runtime_context_for(runtime)
        .command_task_running
        .load(Ordering::Acquire)
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn reset_command_system_for_tests() {
    reset_command_system_for_tests_in(crate::net::runtime::default_runtime());
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn reset_command_system_for_tests_in(runtime: NetRuntimeHandle) {
    runtime_context_for(runtime)
        .command_task_running
        .store(false, Ordering::Release);
    runtime_context_for(runtime)
        .command_task_ready_waiters
        .clear();
    command_queue_in(runtime).reset_for_tests();
}

/// イベントタスク起動待ちFuture
pub(crate) struct CommandTaskReadyFuture {
    runtime: NetRuntimeHandle,
}

impl Future for CommandTaskReadyFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let runtime = self.runtime;
        if command_task_running_in(runtime) {
            return Poll::Ready(());
        }

        runtime_context_for(runtime)
            .command_task_ready_waiters
            .register(cx.waker());
        if command_task_running_in(runtime) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// イベント送信ヘルパー（バックプレッシャー対応）
#[inline]
pub(crate) fn enqueue_command(command: RuntimeCommand) -> Result<(), EndpointError> {
    if command_queue().send(command) {
        Ok(())
    } else {
        Err(EndpointError::ResourceExhausted)
    }
}

/// イベント送信（エラー無視版 - 内部用）
#[inline]
pub(crate) fn enqueue_command_ignore(command: RuntimeCommand) {
    let _ = command_queue().send(command);
}

#[inline]
pub(crate) fn enqueue_command_in(
    runtime: NetRuntimeHandle,
    command: RuntimeCommand,
) -> Result<(), EndpointError> {
    if command_queue_in(runtime).send(command) {
        Ok(())
    } else {
        Err(EndpointError::ResourceExhausted)
    }
}

#[inline]
pub(crate) fn enqueue_command_ignore_in(runtime: NetRuntimeHandle, command: RuntimeCommand) {
    let _ = command_queue_in(runtime).send(command);
}

pub(crate) fn wait_for_command_task() -> CommandTaskReadyFuture {
    wait_for_command_task_in(crate::net::runtime::default_runtime())
}

pub(crate) fn wait_for_command_task_in(runtime: NetRuntimeHandle) -> CommandTaskReadyFuture {
    CommandTaskReadyFuture { runtime }
}

/// タスクコンテキスト向け非同期イベント送信Future
pub(crate) struct SendCommandFuture {
    runtime: NetRuntimeHandle,
    command: Option<RuntimeCommand>,
}

impl SendCommandFuture {
    pub(crate) fn new(runtime: NetRuntimeHandle, command: RuntimeCommand) -> Self {
        Self {
            runtime,
            command: Some(command),
        }
    }
}

impl Future for SendCommandFuture {
    type Output = Result<(), EndpointError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let runtime = this.runtime;

        if !command_task_running_in(runtime) {
            runtime_context_for(runtime)
                .command_task_ready_waiters
                .register(cx.waker());
            if !command_task_running_in(runtime) {
                return Poll::Pending;
            }
        }

        let command = this
            .command
            .take()
            .expect("send command future polled after completion");
        match command_queue_in(runtime).send_owned(command) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(command) => {
                this.command = Some(command);
                command_queue_in(runtime).space_waiters.register(cx.waker());

                let retry = this
                    .command
                    .take()
                    .expect("send command future lost pending command");
                match command_queue_in(runtime).send_owned(retry) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(command) => {
                        this.command = Some(command);
                        Poll::Pending
                    }
                }
            }
        }
    }
}

pub(crate) fn send_command(command: RuntimeCommand) -> SendCommandFuture {
    send_command_in(crate::net::runtime::default_runtime(), command)
}

pub(crate) fn send_command_in(
    runtime: NetRuntimeHandle,
    command: RuntimeCommand,
) -> SendCommandFuture {
    SendCommandFuture::new(runtime, command)
}

/// カスタムFuture向けの遅延ディスパッチ状態
pub(crate) struct CommandDispatch {
    runtime: NetRuntimeHandle,
    enqueue: Option<SendCommandFuture>,
}

impl CommandDispatch {
    pub(crate) fn new() -> Self {
        Self::new_in(crate::net::runtime::default_runtime())
    }

    pub(crate) const fn new_in(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
            enqueue: None,
        }
    }

    pub(crate) fn poll<F>(
        &mut self,
        cx: &mut Context<'_>,
        command_fn: F,
    ) -> Poll<Result<(), EndpointError>>
    where
        F: FnOnce() -> RuntimeCommand,
    {
        if self.enqueue.is_none() {
            self.enqueue = Some(send_command_in(self.runtime, command_fn()));
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

impl Default for CommandDispatch {
    fn default() -> Self {
        Self::new()
    }
}

/// バッチイベント送信（複数パケットを1回のロック取得で送信）
///
/// ロック取得を1回に削減し、高スループット受信パス向けの最適化。
/// 各パケットを個別に `enqueue_command_ignore` するより効率的。
#[inline]
pub(crate) fn enqueue_ingress_batch_on(if_id: Option<NetIfId>, packets: Vec<PacketRef>) {
    enqueue_ingress_batch_on_in(crate::net::runtime::default_runtime(), if_id, packets);
}

#[inline]
pub(crate) fn enqueue_ingress_batch_on_in(
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
            let _ =
                command_queue_in(runtime).send(RuntimeCommand::Ingress(IngressCommand::Packet {
                    if_id,
                    packet: p,
                }));
        }
        return;
    }
    let _ = command_queue_in(runtime).send(RuntimeCommand::Ingress(IngressCommand::Batch {
        if_id,
        packets,
    }));
}

#[inline]
pub(crate) fn enqueue_ingress_batch(packets: Vec<PacketRef>) {
    enqueue_ingress_batch_on(None, packets);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::l4::test_support::noop_waker;
    use core::task::{Context, Poll};

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn send_command_waits_for_command_task_readiness() {
        reset_command_system_for_tests();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = send_command(RuntimeCommand::Transport(TransportCommand::TxAvailable));

        assert!(matches!(Pin::new(&mut future).poll(&mut cx), Poll::Pending));

        mark_command_task_running();
        assert!(matches!(
            Pin::new(&mut future).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            command_queue().recv(),
            Some(RuntimeCommand::Transport(TransportCommand::TxAvailable))
        ));

        reset_command_system_for_tests();
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn send_command_waits_for_queue_space() {
        reset_command_system_for_tests();
        mark_command_task_running();

        for _ in 0..RuntimeCommandQueue::CAPACITY {
            assert!(
                enqueue_command(RuntimeCommand::Transport(TransportCommand::TxAvailable)).is_ok()
            );
        }

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = send_command(RuntimeCommand::Transport(TransportCommand::TxAvailable));

        assert!(matches!(Pin::new(&mut future).poll(&mut cx), Poll::Pending));
        assert!(matches!(
            command_queue().recv(),
            Some(RuntimeCommand::Transport(TransportCommand::TxAvailable))
        ));
        assert!(matches!(
            Pin::new(&mut future).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));

        reset_command_system_for_tests();
    }
}
