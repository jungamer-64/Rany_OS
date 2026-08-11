// ============================================================================
// kernel/src/net/runtime/command.rs - Runtime command bus
// ============================================================================
//! # Runtime command bus
//!
//! RuntimeCommand, RuntimeCommandQueue, CommandWaitFuture

use crate::net::runtime::NetRuntimeHandle;
use crate::sync::{MpscRingBuffer, PoisonLock, WakerQueue};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
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
        if_id: NetIfId,
        packet: PacketRef,
    },
    Reassembled {
        if_id: NetIfId,
        payload: PacketPayload,
    },
}

#[derive(Debug)]
pub(crate) enum TransportCommand {
    TcpDataReady {
        socket_id: SocketId,
    },
    CloseSocket {
        socket_id: SocketId,
    },
    UdpSendTo {
        socket_id: SocketId,
        payload: PacketPayload,
        remote: EndpointAddr,
    },
    RawSend {
        command: RawSendCommand,
        reply: CommandReplyTicket<Result<(), EndpointError>>,
    },
    TcpDial {
        local: EndpointAddr,
        remote: EndpointAddr,
        scope: InterfaceScope,
        reply: CommandReplyTicket<
            Result<crate::net::l4::tcp::TcpConnection, crate::net::l4::tcp::TcpError>,
        >,
    },
    TcpBind {
        local: EndpointAddr,
        scope: InterfaceScope,
        backlog: u32,
        reply: CommandReplyTicket<
            Result<crate::net::l4::tcp::TcpAcceptor, crate::net::l4::tcp::TcpError>,
        >,
    },
}

#[derive(Debug)]
pub(crate) enum RawSendCommand {
    Ipv4 {
        scope: InterfaceScope,
        dst: [u8; 4],
        transport: RawIpv4Transport,
        payload: PacketPayload,
        completion_id: Option<u64>,
    },
    Ipv6 {
        scope: InterfaceScope,
        dst: [u8; 16],
        transport: RawIpv6Transport,
        payload: PacketPayload,
        completion_id: Option<u64>,
    },
}

impl RawSendCommand {
    pub(crate) const fn completion_id(&self) -> Option<u64> {
        match self {
            Self::Ipv4 { completion_id, .. } | Self::Ipv6 { completion_id, .. } => *completion_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawIpv4Source {
    Auto,
    Addr([u8; 4]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawIpv4Transport {
    Udp {
        src: RawIpv4Source,
        src_port: u16,
        dst_port: u16,
        ttl: u8,
    },
    Tcp {
        src: [u8; 4],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawIpv6Transport {
    Udp {
        src: [u8; 16],
        src_port: u16,
        dst_port: u16,
        ttl: u8,
    },
    Tcp {
        src: [u8; 16],
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
    MulticastJoin {
        group: [u8; 4],
        reply: CommandReplyTicket<bool>,
    },
    MulticastLeave {
        group: [u8; 4],
        reply: CommandReplyTicket<bool>,
    },
    ProcessLocalTimeouts,
    ProcessGlobalTimeouts,
    InterfaceConfigDirty {
        revision: crate::net::runtime::manager::InterfaceConfigRevision,
    },
    ArpProbe {
        target_ip: [u8; 4],
    },
    NeighborResolvedV4 {
        if_id: Option<NetIfId>,
        ip: [u8; 4],
        mac: [u8; 6],
    },
    NeighborResolvedV6 {
        if_id: Option<NetIfId>,
        ip: [u8; 16],
        mac: [u8; 6],
    },
    DhcpApplyLease {
        if_id: Option<u16>,
        config: crate::net::services::dhcp::DhcpV4AppliedConfig,
    },
    DhcpV6ApplyLease {
        if_id: Option<u16>,
        config: crate::net::services::dhcp::DhcpV6AppliedConfig,
    },
    GetPrimaryInterfaceConfig {
        reply: CommandReplyTicket<Option<crate::net::api::config::InterfaceConfigSnapshot>>,
    },
    GetInterfaceConfig {
        if_id: u16,
        reply: CommandReplyTicket<Option<crate::net::api::config::InterfaceConfigSnapshot>>,
    },
    ListInterfaceConfigs {
        reply: CommandReplyTicket<Vec<crate::net::api::config::InterfaceConfigSnapshot>>,
    },
    GetInterfaceStats {
        if_id: u16,
        reply: CommandReplyTicket<Option<crate::net::api::config::InterfaceStatsSnapshot>>,
    },
    ListInterfaceStats {
        reply: CommandReplyTicket<Vec<crate::net::api::config::InterfaceStatsSnapshot>>,
    },
    ListInterfaces {
        reply: CommandReplyTicket<Vec<crate::net::api::config::InterfaceSnapshot>>,
    },
    GetNetworkSnapshot {
        reply: CommandReplyTicket<crate::net::obs::NetSnapshot>,
    },
    GetNetworkRecentEvents {
        limit: usize,
        reply: CommandReplyTicket<Vec<crate::net::obs::NetTraceEvent>>,
    },
    GetArpCache {
        reply: CommandReplyTicket<Vec<crate::net::api::connections::ArpCacheEntry>>,
    },
    ArpInsert {
        ip: [u8; 4],
        mac: [u8; 6],
    },
    GetUdpEndpoints {
        reply: CommandReplyTicket<Vec<crate::net::api::connections::UdpEndpointInfo>>,
    },
    GetDhcpState {
        if_id: Option<u16>,
        reply: CommandReplyTicket<crate::net::api::dhcp::DhcpRuntimeState>,
    },
    ListDhcpStates {
        reply: CommandReplyTicket<Vec<crate::net::api::dhcp::InterfaceDhcpState>>,
    },
    DhcpRenew {
        reply: CommandReplyTicket<Result<(), alloc::string::String>>,
    },
    DhcpRelease {
        reply: CommandReplyTicket<bool>,
    },
    DhcpDiscover {
        reply: CommandReplyTicket<Option<crate::net::api::dhcp::DhcpOfferInfo>>,
    },
    DhcpInform {
        reply: CommandReplyTicket<Result<(), alloc::string::String>>,
    },
    DhcpLastDeclined {
        reply: CommandReplyTicket<Option<[u8; 4]>>,
    },
    DhcpLastReleased {
        reply: CommandReplyTicket<Option<[u8; 4]>>,
    },
    GetTcpConnections {
        reply: CommandReplyTicket<Vec<crate::net::api::connections::TcpConnectionInfo>>,
    },
    FirewallEnable {
        reply: CommandReplyTicket<Result<(), &'static str>>,
    },
    FirewallDisable {
        reply: CommandReplyTicket<Result<(), &'static str>>,
    },
    FirewallStatus {
        reply: CommandReplyTicket<alloc::string::String>,
    },
    FirewallListRules {
        reply: CommandReplyTicket<alloc::string::String>,
    },
    FirewallStats {
        reply: CommandReplyTicket<alloc::string::String>,
    },
    FirewallAddRule {
        rule: crate::net::security::firewall::FirewallRule,
        reply: CommandReplyTicket<Result<u64, alloc::string::String>>,
    },
    FirewallRemoveRule {
        id: u64,
        reply: CommandReplyTicket<Result<bool, alloc::string::String>>,
    },
    FirewallClearRules {
        reply: CommandReplyTicket<Result<(), alloc::string::String>>,
    },
    FirewallSetDefaultPolicy {
        direction: crate::net::security::firewall::FirewallDirection,
        action: crate::net::security::firewall::FirewallAction,
        reply: CommandReplyTicket<Result<(), alloc::string::String>>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CommandReplyTicket<T> {
    runtime: NetRuntimeHandle,
    id: u64,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Copy for CommandReplyTicket<T> {}

impl<T> Clone for CommandReplyTicket<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> CommandReplyTicket<T> {
    const fn new(runtime: NetRuntimeHandle, id: u64) -> Self {
        Self {
            runtime,
            id,
            _marker: PhantomData,
        }
    }
}

pub(crate) enum CommandReplyValue {
    EndpointUnit(Result<(), EndpointError>),
    TcpConnection(Result<crate::net::l4::tcp::TcpConnection, crate::net::l4::tcp::TcpError>),
    TcpAcceptor(Result<crate::net::l4::tcp::TcpAcceptor, crate::net::l4::tcp::TcpError>),
    Bool(bool),
    IcmpEcho(Result<u64, ()>),
    OptionBool(Option<bool>),
    OptionIpv6(Option<[u8; 16]>),
    OptionInterfaceConfig(Option<crate::net::api::config::InterfaceConfigSnapshot>),
    InterfaceConfigs(Vec<crate::net::api::config::InterfaceConfigSnapshot>),
    OptionInterfaceStats(Option<crate::net::api::config::InterfaceStatsSnapshot>),
    InterfaceStats(Vec<crate::net::api::config::InterfaceStatsSnapshot>),
    Interfaces(Vec<crate::net::api::config::InterfaceSnapshot>),
    NetworkSnapshot(crate::net::obs::NetSnapshot),
    NetworkRecentEvents(Vec<crate::net::obs::NetTraceEvent>),
    ArpCache(Vec<crate::net::api::connections::ArpCacheEntry>),
    UdpEndpoints(Vec<crate::net::api::connections::UdpEndpointInfo>),
    DhcpState(crate::net::api::dhcp::DhcpRuntimeState),
    DhcpStates(Vec<crate::net::api::dhcp::InterfaceDhcpState>),
    StringUnit(Result<(), alloc::string::String>),
    DhcpOffer(Option<crate::net::api::dhcp::DhcpOfferInfo>),
    OptionIpv4(Option<[u8; 4]>),
    TcpConnections(Vec<crate::net::api::connections::TcpConnectionInfo>),
    StaticStrUnit(Result<(), &'static str>),
    Text(alloc::string::String),
    StringU64(Result<u64, alloc::string::String>),
    StringBool(Result<bool, alloc::string::String>),
}

impl CommandReplyValue {
    fn kind(&self) -> &'static str {
        match self {
            Self::EndpointUnit(_) => "EndpointUnit",
            Self::TcpConnection(_) => "TcpConnection",
            Self::TcpAcceptor(_) => "TcpAcceptor",
            Self::Bool(_) => "Bool",
            Self::IcmpEcho(_) => "IcmpEcho",
            Self::OptionBool(_) => "OptionBool",
            Self::OptionIpv6(_) => "OptionIpv6",
            Self::OptionInterfaceConfig(_) => "OptionInterfaceConfig",
            Self::InterfaceConfigs(_) => "InterfaceConfigs",
            Self::OptionInterfaceStats(_) => "OptionInterfaceStats",
            Self::InterfaceStats(_) => "InterfaceStats",
            Self::Interfaces(_) => "Interfaces",
            Self::NetworkSnapshot(_) => "NetworkSnapshot",
            Self::NetworkRecentEvents(_) => "NetworkRecentEvents",
            Self::ArpCache(_) => "ArpCache",
            Self::UdpEndpoints(_) => "UdpEndpoints",
            Self::DhcpState(_) => "DhcpState",
            Self::DhcpStates(_) => "DhcpStates",
            Self::StringUnit(_) => "StringUnit",
            Self::DhcpOffer(_) => "DhcpOffer",
            Self::OptionIpv4(_) => "OptionIpv4",
            Self::TcpConnections(_) => "TcpConnections",
            Self::StaticStrUnit(_) => "StaticStrUnit",
            Self::Text(_) => "Text",
            Self::StringU64(_) => "StringU64",
            Self::StringBool(_) => "StringBool",
        }
    }
}

pub(crate) trait CommandReplyPayload: Sized {
    fn into_reply_value(self) -> CommandReplyValue;
    fn take_reply_value(value: CommandReplyValue) -> Option<Self>;

    fn reply_type_name() -> &'static str {
        core::any::type_name::<Self>()
    }
}

macro_rules! command_reply_payload {
    ($ty:ty, $variant:ident) => {
        impl CommandReplyPayload for $ty {
            fn into_reply_value(self) -> CommandReplyValue {
                CommandReplyValue::$variant(self)
            }

            fn take_reply_value(value: CommandReplyValue) -> Option<Self> {
                match value {
                    CommandReplyValue::$variant(value) => Some(value),
                    _ => None,
                }
            }
        }
    };
}

command_reply_payload!(Result<(), EndpointError>, EndpointUnit);
command_reply_payload!(
    Result<crate::net::l4::tcp::TcpConnection, crate::net::l4::tcp::TcpError>,
    TcpConnection
);
command_reply_payload!(
    Result<crate::net::l4::tcp::TcpAcceptor, crate::net::l4::tcp::TcpError>,
    TcpAcceptor
);
command_reply_payload!(bool, Bool);
command_reply_payload!(Result<u64, ()>, IcmpEcho);
command_reply_payload!(Option<bool>, OptionBool);
command_reply_payload!(Option<[u8; 16]>, OptionIpv6);
command_reply_payload!(
    Option<crate::net::api::config::InterfaceConfigSnapshot>,
    OptionInterfaceConfig
);
command_reply_payload!(
    Vec<crate::net::api::config::InterfaceConfigSnapshot>,
    InterfaceConfigs
);
command_reply_payload!(
    Option<crate::net::api::config::InterfaceStatsSnapshot>,
    OptionInterfaceStats
);
command_reply_payload!(
    Vec<crate::net::api::config::InterfaceStatsSnapshot>,
    InterfaceStats
);
command_reply_payload!(Vec<crate::net::api::config::InterfaceSnapshot>, Interfaces);
command_reply_payload!(crate::net::obs::NetSnapshot, NetworkSnapshot);
command_reply_payload!(Vec<crate::net::obs::NetTraceEvent>, NetworkRecentEvents);
command_reply_payload!(Vec<crate::net::api::connections::ArpCacheEntry>, ArpCache);
command_reply_payload!(
    Vec<crate::net::api::connections::UdpEndpointInfo>,
    UdpEndpoints
);
command_reply_payload!(crate::net::api::dhcp::DhcpRuntimeState, DhcpState);
command_reply_payload!(Vec<crate::net::api::dhcp::InterfaceDhcpState>, DhcpStates);
command_reply_payload!(Result<(), alloc::string::String>, StringUnit);
command_reply_payload!(Option<crate::net::api::dhcp::DhcpOfferInfo>, DhcpOffer);
command_reply_payload!(Option<[u8; 4]>, OptionIpv4);
command_reply_payload!(
    Vec<crate::net::api::connections::TcpConnectionInfo>,
    TcpConnections
);
command_reply_payload!(Result<(), &'static str>, StaticStrUnit);
command_reply_payload!(alloc::string::String, Text);
command_reply_payload!(Result<u64, alloc::string::String>, StringU64);
command_reply_payload!(Result<bool, alloc::string::String>, StringBool);

struct CommandReplyEntry {
    value: Option<CommandReplyValue>,
    waker: crate::sync::atomic_waker::AtomicWaker,
}

impl CommandReplyEntry {
    const fn new() -> Self {
        Self {
            value: None,
            waker: crate::sync::atomic_waker::AtomicWaker::new(),
        }
    }
}

pub(crate) struct CommandReplyRegistry {
    next_id: AtomicU64,
    entries: PoisonLock<BTreeMap<u64, CommandReplyEntry>>,
}

impl CommandReplyRegistry {
    pub(crate) fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            entries: PoisonLock::new(BTreeMap::new()),
        }
    }

    fn reserve<T: CommandReplyPayload>(&self, runtime: NetRuntimeHandle) -> CommandReplyTicket<T> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, CommandReplyEntry::new());
        CommandReplyTicket::new(runtime, id)
    }

    fn poll<T: CommandReplyPayload>(
        &self,
        ticket: CommandReplyTicket<T>,
        cx: &mut Context<'_>,
    ) -> Poll<T> {
        if let Ok(mut entries) = self.entries.lock() {
            let value = entries
                .get_mut(&ticket.id)
                .and_then(|entry| entry.value.take());
            if let Some(value) = value {
                entries.remove(&ticket.id);
                return Poll::Ready(take_reply_or_type_mismatch::<T>(value));
            }

            if let Some(entry) = entries.get_mut(&ticket.id) {
                entry.waker.register(cx.waker());
            }
        }

        if let Ok(mut entries) = self.entries.lock() {
            let value = entries
                .get_mut(&ticket.id)
                .and_then(|entry| entry.value.take());
            if let Some(value) = value {
                entries.remove(&ticket.id);
                return Poll::Ready(take_reply_or_type_mismatch::<T>(value));
            }
        }

        Poll::Pending
    }

    fn complete<T: CommandReplyPayload>(&self, ticket: CommandReplyTicket<T>, value: T) {
        if let Ok(mut entries) = self.entries.lock()
            && let Some(entry) = entries.get_mut(&ticket.id)
        {
            entry.value = Some(value.into_reply_value());
            entry.waker.wake();
        }
    }

    fn unregister<T>(&self, ticket: CommandReplyTicket<T>) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(&ticket.id);
        }
    }
}

fn take_reply_or_type_mismatch<T: CommandReplyPayload>(value: CommandReplyValue) -> T {
    let received = value.kind();
    if let Some(value) = T::take_reply_value(value) {
        return value;
    }

    log::error!(
        target: "net::command",
        "[NET] command reply type mismatch: expected={} received={}",
        T::reply_type_name(),
        received
    );
    panic!(
        "command reply type mismatch: expected={} received={}",
        T::reply_type_name(),
        received
    );
}

pub(crate) struct CommandFuture<T> {
    ticket: CommandReplyTicket<T>,
}

impl<T: CommandReplyPayload> Future for CommandFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        poll_command_result(this.ticket, cx)
    }
}

impl<T> Drop for CommandFuture<T> {
    fn drop(&mut self) {
        self.ticket
            .runtime
            .context()
            .command_replies
            .unregister(self.ticket);
    }
}

pub(crate) fn poll_command_result<T: CommandReplyPayload>(
    ticket: CommandReplyTicket<T>,
    cx: &mut Context<'_>,
) -> Poll<T> {
    ticket.runtime.context().command_replies.poll(ticket, cx)
}

pub(crate) fn complete_command<T: CommandReplyPayload>(ticket: CommandReplyTicket<T>, value: T) {
    ticket
        .runtime
        .context()
        .command_replies
        .complete(ticket, value);
}

pub(crate) fn new_command_channel_in<T: CommandReplyPayload>(
    runtime: NetRuntimeHandle,
) -> (CommandReplyTicket<T>, CommandFuture<T>) {
    let ticket = runtime.context().command_replies.reserve(runtime);
    let future = CommandFuture { ticket };
    (ticket, future)
}

pub(crate) fn new_detached_command_channel_in<T: CommandReplyPayload>(
    runtime: NetRuntimeHandle,
) -> CommandReplyTicket<T> {
    runtime.context().command_replies.reserve(runtime)
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
    /// マルチコンシューマー向け ISR-safe Waker Queue
    consumer_waiters: WakerQueue,
    /// タスクコンテキストのプロデューサー向け空き待ち通知
    space_waiters: WakerQueue,
}

impl RuntimeCommandQueue {
    pub(crate) const CAPACITY: usize = NETWORK_EVENT_QUEUE_CAPACITY;

    /// 新規作成
    pub const fn new() -> Self {
        Self {
            queue: MpscRingBuffer::new(),
            consumer_waiters: WakerQueue::new(),
            space_waiters: WakerQueue::new(),
        }
    }

    /// イベント送信（所有権を保持したまま失敗を返す版）
    fn send_owned(&self, command: RuntimeCommand) -> Result<(), RuntimeCommand> {
        match self.queue.push(command) {
            Ok(()) => {
                self.consumer_waiters.wake_all();
                Ok(())
            }
            Err(command) => Err(command),
        }
    }

    /// イベント送信（ISR コンテキスト用・非同期・フェイルファスト）
    /// 既存のプッシュ操作（先行の予約コミットなど）で競合した場合はspinせず即座に破棄する
    fn try_send_owned_from_isr(&self, command: RuntimeCommand) -> Result<(), RuntimeCommand> {
        match self.queue.try_push(command) {
            Ok(()) => {
                self.consumer_waiters.wake_all_from_isr();
                Ok(())
            }
            Err(command) => Err(command),
        }
    }

    /// イベント送信（プロデューサー側 — 通常コンテキストから安全に呼び出し可能）
    ///
    /// CAS ベースでスロットを確保し、ロック取得なしでイベントを書き込む。
    /// キュー満杯時は `false` を返す（バックプレッシャー）。
    pub(crate) fn send(&self, command: RuntimeCommand) -> bool {
        self.send_owned(command).is_ok()
    }

    /// イベント送信（プロデューサー側 — ISR コンテキストから安全に呼び出し可能）
    pub(crate) fn try_send_from_isr(&self, command: RuntimeCommand) -> bool {
        self.try_send_owned_from_isr(command).is_ok()
    }

    /// イベント受信（コンシューマー側 — マルチコンシューマー安全）
    ///
    /// MPMC ロックフリーキューからアトミックに次のイベントを読み出す。
    pub(crate) fn recv(&self) -> Option<RuntimeCommand> {
        let command = self.queue.pop()?;
        self.space_waiters.wake_all();
        Some(command)
    }

    /// イベント待ち（非同期）
    pub(crate) fn wait_for_events(&self) -> CommandWaitFuture<'_> {
        CommandWaitFuture { queue: self }
    }

    #[cfg(test)]
    pub fn reset_for_tests(&self) {
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self.recv().is_some() {}
        self.consumer_waiters.clear();
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

        // Multi-consumer WakerQueue に Waker を登録
        self.queue.consumer_waiters.register(cx.waker());

        // 再度チェック（Waker 登録中にイベントが来た可能性）
        if let Some(command) = self.queue.recv() {
            Poll::Ready(command)
        } else {
            Poll::Pending
        }
    }
}

fn runtime_context_for(
    runtime: NetRuntimeHandle,
) -> &'static crate::net::runtime::NetRuntimeContext {
    runtime.context()
}

pub(crate) fn command_queue_for_core_in(
    runtime: NetRuntimeHandle,
    cpu_id: usize,
) -> &'static RuntimeCommandQueue {
    let index = cpu_id % crate::per_cpu::MAX_CPUS;
    &runtime_context_for(runtime).command_queues[index]
}

pub(crate) fn command_queue_in(runtime: NetRuntimeHandle) -> &'static RuntimeCommandQueue {
    let cpu_id = crate::cpu::try_current_id().unwrap_or(0);
    command_queue_for_core_in(runtime, cpu_id)
}

#[inline]
pub(crate) fn try_enqueue_command_in(
    runtime: NetRuntimeHandle,
    command: RuntimeCommand,
) -> Result<(), RuntimeCommand> {
    let num_cpus = crate::task::executor_slot_count().max(1);

    // Ingress パケットは flow_hash を使用して owner CPU queue へディスパッチ。
    // CPU IDは0..num_cpusの連番なので、Toeplitz hash結果の直接 modulo で
    // FlowAffinity テーブルと同一の分散を達成する（ゼロアロケーション）。
    let target_cpu = match &command {
        RuntimeCommand::Ingress(IngressCommand::Packet { packet, .. }) => {
            let flow_hash = packet.meta().flow_hash;
            (flow_hash as usize) % num_cpus
        }
        _ => crate::cpu::try_current_id().unwrap_or(0) % num_cpus,
    };

    command_queue_for_core_in(runtime, target_cpu).send_owned(command)
}

#[inline]
pub(crate) fn try_enqueue_command_from_isr_in(
    runtime: NetRuntimeHandle,
    command: RuntimeCommand,
) -> Result<(), RuntimeCommand> {
    let num_cpus = crate::task::executor_slot_count().max(1);
    let target_cpu = match &command {
        RuntimeCommand::Ingress(IngressCommand::Packet { packet, .. }) => {
            let flow_hash = packet.meta().flow_hash;
            (flow_hash as usize) % num_cpus
        }
        _ => crate::cpu::try_current_id().unwrap_or(0) % num_cpus,
    };
    command_queue_for_core_in(runtime, target_cpu).try_send_owned_from_isr(command)
}

pub(crate) fn broadcast_command_in(
    runtime: NetRuntimeHandle,
    command_factory: impl Fn() -> RuntimeCommand,
) {
    let num_cpus = crate::task::executor_slot_count().max(1);
    for cpu_id in 0..num_cpus {
        let _ = command_queue_for_core_in(runtime, cpu_id).send(command_factory());
    }
}

pub(crate) fn mark_command_task_running_in(runtime: NetRuntimeHandle) {
    let context = runtime_context_for(runtime);
    let was_running = context.command_task_running.swap(true, Ordering::AcqRel);
    if !was_running {
        context.command_task_ready_waiters.wake_all();
    }
}

pub(crate) fn command_task_running_in(runtime: NetRuntimeHandle) -> bool {
    runtime_context_for(runtime)
        .command_task_running
        .load(Ordering::Acquire)
}

#[cfg(test)]
pub(crate) fn reset_command_system_for_tests_in(runtime: NetRuntimeHandle) {
    runtime_context_for(runtime)
        .command_task_running
        .store(false, Ordering::Release);
    runtime_context_for(runtime)
        .command_task_ready_waiters
        .clear();
    command_queue_in(runtime).reset_for_tests();
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
    pub(crate) const fn new_in(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
            enqueue: None,
        }
    }

    pub(crate) const fn runtime(&self) -> NetRuntimeHandle {
        self.runtime
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::l4::test_support::noop_waker;
    use core::task::{Context, Poll};

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn send_command_waits_for_command_task_readiness() {
        let runtime = crate::net::runtime::default_runtime();
        reset_command_system_for_tests_in(runtime);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = send_command_in(
            runtime,
            RuntimeCommand::Control(ControlCommand::ProcessLocalTimeouts),
        );

        assert!(matches!(Pin::new(&mut future).poll(&mut cx), Poll::Pending));

        mark_command_task_running_in(runtime);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            command_queue_in(runtime).recv(),
            Some(RuntimeCommand::Control(
                ControlCommand::ProcessLocalTimeouts
            ))
        ));

        reset_command_system_for_tests_in(runtime);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn send_command_waits_for_queue_space() {
        let runtime = crate::net::runtime::default_runtime();
        reset_command_system_for_tests_in(runtime);
        mark_command_task_running_in(runtime);

        for _ in 0..RuntimeCommandQueue::CAPACITY {
            assert!(
                enqueue_command_in(
                    runtime,
                    RuntimeCommand::Control(ControlCommand::ProcessLocalTimeouts)
                )
                .is_ok()
            );
        }

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = send_command_in(
            runtime,
            RuntimeCommand::Control(ControlCommand::ProcessLocalTimeouts),
        );

        assert!(matches!(Pin::new(&mut future).poll(&mut cx), Poll::Pending));
        assert!(matches!(
            command_queue_in(runtime).recv(),
            Some(RuntimeCommand::Control(
                ControlCommand::ProcessLocalTimeouts
            ))
        ));
        assert!(matches!(
            Pin::new(&mut future).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));

        reset_command_system_for_tests_in(runtime);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    #[should_panic(expected = "command reply type mismatch")]
    fn command_reply_type_mismatch_is_fatal() {
        let runtime = crate::net::runtime::default_runtime();
        let registry = CommandReplyRegistry::new();
        let ticket: CommandReplyTicket<Result<(), EndpointError>> = registry.reserve(runtime);

        {
            let mut entries = registry.entries.lock().unwrap_or_else(|e| e.into_inner());
            entries
                .get_mut(&ticket.id)
                .expect("reserved reply entry")
                .value = Some(CommandReplyValue::Text(alloc::string::String::from(
                "wrong reply type",
            )));
        }

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = registry.poll(ticket, &mut cx);
    }
}
