// ============================================================================
// kernel/src/net/runtime/command.rs - Runtime command bus
// ============================================================================
//! # Runtime command bus
//!
//! RuntimeCommand, RuntimeCommandQueue, CommandWaitFuture

use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::context::{NetCpuResourceError, NetCpuResources};
use crate::sync::{MpscRingBuffer, PoisonLock, WakerQueue};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};

use crate::net::datapath::mempool::PacketRef;
use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId};
use crate::net::l4::udp::UdpPorts;
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
        ports: UdpPorts,
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
        ports: UdpPorts,
        ttl: u8,
    },
    Tcp {
        src: [u8; 16],
    },
}

fn enqueue_raw_send_in(runtime: NetRuntimeHandle, command: RawSendCommand) -> bool {
    let reply = new_detached_command_channel_in(runtime);
    try_enqueue_command_in(
        runtime,
        RuntimeCommand::Transport(TransportCommand::RawSend { command, reply }),
    )
    .is_ok()
}

pub(crate) fn enqueue_udp_v6_send_scoped_in(
    runtime: NetRuntimeHandle,
    scope: InterfaceScope,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    ports: UdpPorts,
    payload: PacketPayload,
    ttl: u8,
) -> bool {
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv6 {
            scope,
            dst: dst_ip.octets(),
            transport: RawIpv6Transport::Udp {
                src: src_ip.octets(),
                ports,
                ttl,
            },
            payload,
            completion_id: None,
        },
    )
}

pub(crate) fn enqueue_udp_send_on_with_src_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    src_ip: crate::net::l3::ipv4::Ipv4Address,
    dst_ip: crate::net::l3::ipv4::Ipv4Address,
    ports: UdpPorts,
    payload: PacketPayload,
    ttl: u8,
) -> bool {
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv4 {
            scope: InterfaceScope::Pinned(if_id),
            dst: *dst_ip.as_bytes(),
            transport: RawIpv4Transport::Udp {
                src: RawIpv4Source::Addr(*src_ip.as_bytes()),
                ports,
                ttl,
            },
            payload,
            completion_id: None,
        },
    )
}

pub(crate) fn enqueue_tcp_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    src_ip: crate::net::l3::ipv4::Ipv4Address,
    dst_ip: crate::net::l3::ipv4::Ipv4Address,
    payload: PacketPayload,
    completion_id: Option<u64>,
) -> bool {
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv4 {
            scope: InterfaceScope::Pinned(if_id),
            dst: *dst_ip.as_bytes(),
            transport: RawIpv4Transport::Tcp {
                src: *src_ip.as_bytes(),
            },
            payload,
            completion_id,
        },
    )
}

pub(crate) fn enqueue_tcp_v6_send_on_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    payload: PacketPayload,
    completion_id: Option<u64>,
) -> bool {
    enqueue_raw_send_in(
        runtime,
        RawSendCommand::Ipv6 {
            scope: InterfaceScope::Pinned(if_id),
            dst: dst_ip.octets(),
            transport: RawIpv6Transport::Tcp {
                src: src_ip.octets(),
            },
            payload,
            completion_id,
        },
    )
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
        if_id: NetIfId,
        target_ip: [u8; 4],
    },
    NdpResolveRequest {
        if_id: NetIfId,
        target_ip: [u8; 16],
    },
    MulticastJoin {
        if_id: NetIfId,
        group: [u8; 4],
        reply: CommandReplyTicket<bool>,
    },
    MulticastLeave {
        if_id: NetIfId,
        group: [u8; 4],
        reply: CommandReplyTicket<bool>,
    },
    ProcessLocalTimeouts,
    ProcessGlobalTimeouts,
    InterfaceTopologyDirty {
        revision: crate::net::runtime::manager::InterfaceTopologyRevision,
    },
    ArpProbe {
        if_id: NetIfId,
        target_ip: [u8; 4],
    },
    NeighborResolvedV4 {
        if_id: NetIfId,
        ip: [u8; 4],
        mac: [u8; 6],
    },
    NeighborResolvedV6 {
        if_id: NetIfId,
        ip: [u8; 16],
        mac: [u8; 6],
    },
    DhcpApplyLease {
        if_id: NetIfId,
        config: crate::net::services::dhcp::DhcpV4AppliedConfig,
    },
    DhcpV6ApplyLease {
        if_id: NetIfId,
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
        if_id: NetIfId,
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
    producer_state: AtomicUsize,
    /// マルチコンシューマー向け ISR-safe Waker Queue
    consumer_waiters: WakerQueue,
    /// タスクコンテキストのプロデューサー向け空き待ち通知
    space_waiters: WakerQueue,
}

const PRODUCER_ADMISSION_CLOSED: usize = 1usize << (usize::BITS - 1);
const ACTIVE_PRODUCER_MASK: usize = !PRODUCER_ADMISSION_CLOSED;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandAdmissionState {
    Open,
    Draining,
}

struct ProducerAdmission<'a> {
    state: &'a AtomicUsize,
}

impl Drop for ProducerAdmission<'_> {
    fn drop(&mut self) {
        let previous = self.state.fetch_sub(1, Ordering::AcqRel);
        assert_ne!(
            previous & ACTIVE_PRODUCER_MASK,
            0,
            "network command producer admission underflow"
        );
    }
}

impl RuntimeCommandQueue {
    pub(crate) const CAPACITY: usize = NETWORK_EVENT_QUEUE_CAPACITY;

    /// 新規作成
    pub const fn new(admission: CommandAdmissionState) -> Self {
        Self {
            queue: MpscRingBuffer::new(),
            producer_state: AtomicUsize::new(match admission {
                CommandAdmissionState::Open => 0,
                CommandAdmissionState::Draining => PRODUCER_ADMISSION_CLOSED,
            }),
            consumer_waiters: WakerQueue::new(),
            space_waiters: WakerQueue::new(),
        }
    }

    fn admit_producer(&self) -> Option<ProducerAdmission<'_>> {
        let mut state = self.producer_state.load(Ordering::Acquire);
        loop {
            if state & PRODUCER_ADMISSION_CLOSED != 0 {
                return None;
            }
            assert_ne!(
                state & ACTIVE_PRODUCER_MASK,
                ACTIVE_PRODUCER_MASK,
                "network command producer admission count exhausted"
            );
            match self.producer_state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ProducerAdmission {
                        state: &self.producer_state,
                    });
                }
                Err(observed) => state = observed,
            }
        }
    }

    fn try_admit_producer_from_isr(&self) -> Option<ProducerAdmission<'_>> {
        let state = self.producer_state.load(Ordering::Acquire);
        if state & PRODUCER_ADMISSION_CLOSED != 0
            || state & ACTIVE_PRODUCER_MASK == ACTIVE_PRODUCER_MASK
        {
            return None;
        }
        self.producer_state
            .compare_exchange(state, state + 1, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| ProducerAdmission {
                state: &self.producer_state,
            })
    }

    pub(crate) fn begin_drain(&self) {
        self.producer_state
            .fetch_or(PRODUCER_ADMISSION_CLOSED, Ordering::AcqRel);
        self.space_waiters.wake_all();
    }

    pub(crate) fn publish_online(&self) {
        self.producer_state
            .fetch_and(ACTIVE_PRODUCER_MASK, Ordering::AcqRel);
        self.space_waiters.wake_all();
    }

    pub(crate) fn is_accepting(&self) -> bool {
        self.producer_state.load(Ordering::Acquire) & PRODUCER_ADMISSION_CLOSED == 0
    }

    pub(crate) fn is_quiescent(&self) -> bool {
        let producer_state = self.producer_state.load(Ordering::Acquire);
        producer_state & ACTIVE_PRODUCER_MASK == 0 && self.queue.is_empty()
    }

    /// イベント送信（所有権を保持したまま失敗を返す版）
    fn send_owned(&self, command: RuntimeCommand) -> Result<(), RuntimeCommand> {
        let Some(_admission) = self.admit_producer() else {
            return Err(command);
        };
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
        let Some(_admission) = self.try_admit_producer_from_isr() else {
            return Err(command);
        };
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

pub(crate) fn command_resources_for_cpu_in(
    runtime: NetRuntimeHandle,
    cpu_id: crate::cpu::CpuId,
) -> Result<Arc<NetCpuResources>, NetCpuResourceError> {
    runtime_context_for(runtime).cpu_resources(cpu_id)
}

fn command_target(command: &RuntimeCommand) -> Option<crate::cpu::CpuId> {
    let cpu_runtime = crate::cpu::try_runtime()?;
    let snapshot = cpu_runtime.snapshot();
    match command {
        RuntimeCommand::Ingress(IngressCommand::Packet { packet, .. }) => {
            snapshot.online().select(u64::from(packet.meta().flow_hash))
        }
        _ => crate::cpu::CurrentCpu::acquire()
            .map(|current| current.id())
            .filter(|cpu_id| snapshot.online().contains(*cpu_id)),
    }
}

#[inline]
pub(crate) fn try_enqueue_command_in(
    runtime: NetRuntimeHandle,
    command: RuntimeCommand,
) -> Result<(), RuntimeCommand> {
    let Some(target_cpu) = command_target(&command) else {
        return Err(command);
    };
    let Ok(resources) = command_resources_for_cpu_in(runtime, target_cpu) else {
        return Err(command);
    };
    resources.command_queue.send_owned(command)
}

#[inline]
pub(crate) fn try_enqueue_command_from_isr_in(
    runtime: NetRuntimeHandle,
    command: RuntimeCommand,
) -> Result<(), RuntimeCommand> {
    let Some(target_cpu) = command_target(&command) else {
        return Err(command);
    };
    let Ok(resources) = command_resources_for_cpu_in(runtime, target_cpu) else {
        return Err(command);
    };
    resources.command_queue.try_send_owned_from_isr(command)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct CommandBroadcastReport {
    pub(crate) targets: usize,
    pub(crate) enqueued: usize,
    pub(crate) unavailable: usize,
    pub(crate) saturated: usize,
}

pub(crate) fn broadcast_command_in(
    runtime: NetRuntimeHandle,
    command_factory: impl Fn() -> RuntimeCommand,
) -> CommandBroadcastReport {
    let mut report = CommandBroadcastReport::default();
    let Some(cpu_runtime) = crate::cpu::try_runtime() else {
        return report;
    };
    let snapshot = cpu_runtime.snapshot();
    for cpu_id in snapshot.online() {
        report.targets += 1;
        let Ok(resources) = command_resources_for_cpu_in(runtime, cpu_id) else {
            report.unavailable += 1;
            continue;
        };
        if resources.command_queue.send(command_factory()) {
            report.enqueued += 1;
        } else {
            report.saturated += 1;
        }
    }
    report
}

pub(crate) fn mark_command_task_running(resources: &NetCpuResources) {
    let was_running = resources.command_task_running.swap(true, Ordering::AcqRel);
    if !was_running {
        resources.command_task_ready_waiters.wake_all();
    }
}

pub(crate) fn command_task_running(resources: &NetCpuResources) -> bool {
    resources.command_task_running.load(Ordering::Acquire)
}

/// タスクコンテキスト向け非同期イベント送信Future
pub(crate) struct SendCommandFuture {
    runtime: NetRuntimeHandle,
    command: Option<RuntimeCommand>,
    target: Option<crate::cpu::CpuId>,
}

impl SendCommandFuture {
    pub(crate) fn new(runtime: NetRuntimeHandle, command: RuntimeCommand) -> Self {
        Self {
            runtime,
            command: Some(command),
            target: None,
        }
    }
}

impl Future for SendCommandFuture {
    type Output = Result<(), EndpointError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let runtime = this.runtime;
        if this.target.is_some_and(|target| {
            !crate::cpu::snapshot().online().contains(target)
                || command_resources_for_cpu_in(runtime, target)
                    .is_ok_and(|resources| !resources.command_queue.is_accepting())
        }) {
            this.target = None;
        }
        let target = match this.target {
            Some(target) => target,
            None => {
                let Some(command) = this.command.as_ref() else {
                    return Poll::Ready(Err(EndpointError::Internal));
                };
                let Some(target) = command_target(command) else {
                    return Poll::Ready(Err(EndpointError::NetworkUnreachable));
                };
                this.target = Some(target);
                target
            }
        };
        let Ok(resources) = command_resources_for_cpu_in(runtime, target) else {
            return Poll::Ready(Err(EndpointError::Internal));
        };

        if !command_task_running(&resources) {
            resources.command_task_ready_waiters.register(cx.waker());
            if !command_task_running(&resources) {
                return Poll::Pending;
            }
        }

        let command = this
            .command
            .take()
            .expect("send command future polled after completion");
        match resources.command_queue.send_owned(command) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(command) => {
                this.command = Some(command);
                if !resources.command_queue.is_accepting() {
                    this.target = None;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                resources.command_queue.space_waiters.register(cx.waker());

                let retry = this
                    .command
                    .take()
                    .expect("send command future lost pending command");
                match resources.command_queue.send_owned(retry) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(command) => {
                        this.command = Some(command);
                        if !resources.command_queue.is_accepting() {
                            this.target = None;
                            cx.waker().wake_by_ref();
                        }
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn runtime_command_queue_returns_the_unsent_command_at_capacity() {
        let queue = RuntimeCommandQueue::new(CommandAdmissionState::Open);
        for _ in 0..RuntimeCommandQueue::CAPACITY {
            assert!(
                queue
                    .send_owned(RuntimeCommand::Control(
                        ControlCommand::ProcessLocalTimeouts
                    ))
                    .is_ok()
            );
        }

        let rejected = queue
            .send_owned(RuntimeCommand::Control(
                ControlCommand::ProcessGlobalTimeouts,
            ))
            .expect_err("bounded queue must reject one command beyond capacity");
        assert!(matches!(
            rejected,
            RuntimeCommand::Control(ControlCommand::ProcessGlobalTimeouts)
        ));
        for _ in 0..RuntimeCommandQueue::CAPACITY {
            assert!(queue.recv().is_some());
        }
        assert!(queue.recv().is_none());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn draining_command_queue_rejects_new_producers_until_reopened() {
        let queue = RuntimeCommandQueue::new(CommandAdmissionState::Open);
        let active_producer = queue.admit_producer().expect("open producer admission");
        queue.begin_drain();
        let command = RuntimeCommand::Control(ControlCommand::ProcessLocalTimeouts);
        assert!(queue.send_owned(command).is_err());
        assert!(!queue.is_quiescent());
        drop(active_producer);
        assert!(queue.is_quiescent());

        queue.publish_online();
        assert!(queue.send(RuntimeCommand::Control(
            ControlCommand::ProcessLocalTimeouts
        )));
        assert!(queue.recv().is_some());
    }
}
