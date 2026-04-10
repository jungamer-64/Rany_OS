// ============================================================================
// kernel/src/net/services/dhcp/mod.rs
// ============================================================================
//! DHCP (Dynamic Host Configuration Protocol) クライアント実装
//!
//! DHCPを使用してIPアドレス、サブネットマスク、ゲートウェイ、
//! DNSサーバーなどのネットワーク設定を自動取得する。

use crate::net::runtime::{NetRuntimeHandle, context::default_runtime_context};
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};

use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::stack::NetworkConfig;

/// DHCPクライアントポート
mod client_impl;
pub use client_impl::*;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use self::tests as qemu_v4_tests;

mod v6;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use self::v6::tests as qemu_v6_tests;
pub use v6::*;
pub const DHCP_CLIENT_PORT: u16 = 68;

const INVALID_IF_ID: u16 = u16::MAX;

struct DhcpInterfaceRuntime {
    if_id: NetIfId,
    config: NetworkConfig,
    v4: Arc<DhcpClient>,
    active: AtomicBool,
    suspended: AtomicBool,
    drive_started: AtomicBool,
}

impl DhcpInterfaceRuntime {
    fn new(if_id: NetIfId, config: NetworkConfig) -> Arc<Self> {
        Arc::new(Self {
            if_id,
            config,
            v4: Arc::new(DhcpClient::new(config.mac)),
            active: AtomicBool::new(true),
            suspended: AtomicBool::new(false),
            drive_started: AtomicBool::new(false),
        })
    }

    fn mac(&self) -> MacAddress {
        self.config.mac
    }
}

pub(crate) struct DhcpRuntimeState {
    interface_runtimes: PoisonLock<BTreeMap<NetIfId, Arc<DhcpInterfaceRuntime>>>,
    v4_dispatcher_started: AtomicBool,
    primary_if_id: AtomicU16,
    primary_v6_client: PoisonLock<Option<DhcpV6Client>>,
}

impl DhcpRuntimeState {
    pub const fn new() -> Self {
        Self {
            interface_runtimes: PoisonLock::new(BTreeMap::new()),
            v4_dispatcher_started: AtomicBool::new(false),
            primary_if_id: AtomicU16::new(INVALID_IF_ID),
            primary_v6_client: PoisonLock::new(None),
        }
    }
}

pub(crate) fn runtime_state() -> &'static DhcpRuntimeState {
    &default_runtime_context().dhcp
}

pub(crate) fn runtime_state_for(runtime: NetRuntimeHandle) -> &'static DhcpRuntimeState {
    &runtime.context().dhcp
}

pub(crate) fn primary_v6_client_lock_in(
    runtime: NetRuntimeHandle,
) -> &'static PoisonLock<Option<DhcpV6Client>> {
    &runtime_state_for(runtime).primary_v6_client
}

pub(crate) fn ensure_interface_runtime(
    if_id: NetIfId,
    config: NetworkConfig,
) -> Result<(), &'static str> {
    ensure_v4_dispatcher_task();

    let runtime = {
        let mut guard = runtime_state()
            .interface_runtimes
            .lock()
            .map_err(|_| "DHCP interface runtime lock poisoned")?;
        if let Some(existing) = guard.get(&if_id) {
            existing.active.store(true, Ordering::Release);
            existing.suspended.store(false, Ordering::Release);
            Arc::clone(existing)
        } else {
            let runtime = DhcpInterfaceRuntime::new(if_id, config);
            guard.insert(if_id, Arc::clone(&runtime));
            runtime
        }
    };

    if !runtime.drive_started.swap(true, Ordering::AcqRel) {
        crate::task::spawn_task(crate::task::Task::new(dhcp_v4_drive_task(Arc::clone(
            &runtime,
        ))));
    }

    Ok(())
}

pub(crate) fn unregister_interface_runtime(if_id: NetIfId) {
    let removed = runtime_state()
        .interface_runtimes
        .lock()
        .ok()
        .and_then(|mut guard| guard.remove(&if_id));
    if let Some(runtime) = removed {
        runtime.active.store(false, Ordering::Release);
    }
    clear_primary_interface(if_id);
}

pub(crate) fn mark_primary_interface(if_id: NetIfId) {
    runtime_state()
        .primary_if_id
        .store(if_id.0, Ordering::Release);
}

pub(crate) fn clear_primary_interface(if_id: NetIfId) {
    if runtime_state().primary_if_id.load(Ordering::Acquire) == if_id.0 {
        runtime_state()
            .primary_if_id
            .store(INVALID_IF_ID, Ordering::Release);
    }
}

fn interface_runtime(if_id: NetIfId) -> Option<Arc<DhcpInterfaceRuntime>> {
    runtime_state()
        .interface_runtimes
        .lock()
        .ok()
        .and_then(|guard| guard.get(&if_id).cloned())
}

fn interface_runtime_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<Arc<DhcpInterfaceRuntime>> {
    runtime_state_for(runtime)
        .interface_runtimes
        .lock()
        .ok()
        .and_then(|guard| guard.get(&if_id).cloned())
}

pub(crate) fn interface_v4_client(if_id: NetIfId) -> Option<Arc<DhcpClient>> {
    interface_runtime(if_id).map(|runtime| Arc::clone(&runtime.v4))
}

pub(crate) fn interface_v4_client_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<Arc<DhcpClient>> {
    interface_runtime_in(runtime, if_id).map(|runtime| Arc::clone(&runtime.v4))
}

pub(crate) fn lease_for_interface(if_id: NetIfId) -> Option<DhcpLease> {
    interface_v4_client(if_id).and_then(|client| client.lease())
}

pub(crate) fn lease_for_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<DhcpLease> {
    interface_v4_client_in(runtime, if_id).and_then(|client| client.lease())
}

pub(crate) fn has_bound_lease(if_id: NetIfId) -> bool {
    lease_for_interface(if_id).is_some()
}

pub(crate) fn has_bound_lease_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> bool {
    lease_for_interface_in(runtime, if_id).is_some()
}

pub(crate) fn release_interface(if_id: NetIfId) -> bool {
    let Some(runtime) = interface_runtime(if_id) else {
        return false;
    };
    runtime.suspended.store(true, Ordering::Release);
    runtime.v4.release_on(Some(if_id))
}

pub(crate) fn restart_interface_runtime(if_id: NetIfId) -> Result<(), &'static str> {
    ensure_v4_dispatcher_task();

    let Some(runtime) = interface_runtime(if_id) else {
        return Err("DHCP interface runtime missing");
    };

    runtime.active.store(true, Ordering::Release);
    runtime.suspended.store(false, Ordering::Release);

    if !runtime.drive_started.swap(true, Ordering::AcqRel) {
        crate::task::spawn_task(crate::task::Task::new(dhcp_v4_drive_task(Arc::clone(
            &runtime,
        ))));
    }

    runtime
        .v4
        .force_renew_or_restart(crate::task::current_tick());
    Ok(())
}

fn primary_interface_runtime() -> Option<Arc<DhcpInterfaceRuntime>> {
    let primary_if = runtime_state().primary_if_id.load(Ordering::Acquire);
    let guard = runtime_state().interface_runtimes.lock().ok()?;
    if primary_if != INVALID_IF_ID {
        if let Some(runtime) = guard.get(&NetIfId(primary_if)) {
            return Some(Arc::clone(runtime));
        }
    }
    guard
        .values()
        .find(|runtime| {
            runtime.active.load(Ordering::Acquire) && !runtime.suspended.load(Ordering::Acquire)
        })
        .cloned()
}

fn primary_interface_runtime_in(runtime: NetRuntimeHandle) -> Option<Arc<DhcpInterfaceRuntime>> {
    let state = runtime_state_for(runtime);
    let primary_if = state.primary_if_id.load(Ordering::Acquire);
    let guard = state.interface_runtimes.lock().ok()?;
    if primary_if != INVALID_IF_ID {
        if let Some(runtime) = guard.get(&NetIfId(primary_if)) {
            return Some(Arc::clone(runtime));
        }
    }
    guard
        .values()
        .find(|runtime| {
            runtime.active.load(Ordering::Acquire) && !runtime.suspended.load(Ordering::Acquire)
        })
        .cloned()
}

pub(crate) fn primary_v4_client_in(runtime: NetRuntimeHandle) -> Option<Arc<DhcpClient>> {
    primary_interface_runtime_in(runtime).map(|runtime| Arc::clone(&runtime.v4))
}

pub(crate) fn primary_interface_if_id() -> Option<NetIfId> {
    primary_interface_runtime().map(|runtime| runtime.if_id)
}

pub(crate) fn primary_interface_if_id_in(runtime: NetRuntimeHandle) -> Option<NetIfId> {
    primary_interface_runtime_in(runtime).map(|runtime| runtime.if_id)
}

fn find_runtime_for_v4_packet_in(
    runtime: NetRuntimeHandle,
    packet: &[u8],
) -> Option<Arc<DhcpInterfaceRuntime>> {
    let guard = runtime_state_for(runtime).interface_runtimes.lock().ok()?;
    for runtime in guard.values() {
        if runtime.active.load(Ordering::Acquire)
            && !runtime.suspended.load(Ordering::Acquire)
            && runtime.v4.matches_response(packet)
        {
            return Some(Arc::clone(runtime));
        }
    }
    None
}

fn find_runtime_for_v4_payload_in(
    runtime: NetRuntimeHandle,
    packet: &kernel_api::resource::net::PacketPayload,
) -> Option<Arc<DhcpInterfaceRuntime>> {
    let guard = runtime_state_for(runtime).interface_runtimes.lock().ok()?;
    for runtime in guard.values() {
        if runtime.active.load(Ordering::Acquire)
            && !runtime.suspended.load(Ordering::Acquire)
            && runtime.v4.matches_response_payload(packet)
        {
            return Some(Arc::clone(runtime));
        }
    }
    None
}

fn ensure_v4_dispatcher_task() {
    ensure_v4_dispatcher_task_in(crate::net::runtime::default_runtime());
}

fn ensure_v4_dispatcher_task_in(runtime: NetRuntimeHandle) {
    if runtime_state_for(runtime)
        .v4_dispatcher_started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        crate::task::spawn_task(crate::task::Task::new(dhcp_v4_dispatcher_task(runtime)));
    }
}

async fn dhcp_v4_drive_task(runtime: Arc<DhcpInterfaceRuntime>) {
    log::info!(
        "[NET] DHCPv4 interface task started: if{} mac={}",
        runtime.if_id.0,
        runtime.mac()
    );

    while runtime.active.load(Ordering::Acquire) {
        if runtime.suspended.load(Ordering::Acquire) {
            crate::task::sleep_ms(200).await;
            continue;
        }

        let now = crate::task::current_tick();
        if let Err(err) = runtime
            .v4
            .drive_on_interface(runtime.if_id, now, 1000)
            .await
        {
            log::warn!(
                "[NET] DHCPv4 interface drive failed: if{} err={}",
                runtime.if_id.0,
                err
            );
        }
        crate::task::sleep_ms(200).await;
    }

    runtime.drive_started.store(false, Ordering::Release);
}

async fn dhcp_v4_dispatcher_task(runtime: NetRuntimeHandle) {
    let socket = match crate::net::l4::udp::UdpEndpoint::bind_in(
        runtime,
        crate::net::types::InterfaceScope::Any,
        DHCP_CLIENT_PORT,
        None,
    ) {
        Ok(socket) => socket,
        Err(_) => {
            log::error!("[NET] DHCPv4 dispatcher failed to bind UDP port 68");
            runtime_state_for(runtime)
                .v4_dispatcher_started
                .store(false, Ordering::Release);
            return;
        }
    };

    log::info!("[NET] DHCPv4 dispatcher task started");

    loop {
        match socket.recv().await {
            Some((_if_id, _src, _ttl, packet)) => {
                let now = crate::task::current_tick();
                let process =
                    find_runtime_for_v4_payload_in(runtime, &packet).map(|interface_runtime| {
                        let result = interface_runtime.v4.process_response_payload(&packet, now);
                        (interface_runtime, result)
                    });
                let Some((interface_runtime, result)) = process else {
                    continue;
                };

                match result {
                    Ok(DhcpResponseResult::Ack(lease)) => {
                        log::info!(
                            "[NET] DHCPv4 ACK received: if{} mac={} ip={:?}",
                            interface_runtime.if_id.0,
                            interface_runtime.mac(),
                            lease.ip_address
                        );
                        let hostname_bytes = lease.hostname.clone().unwrap_or_default();
                        crate::net::l4::endpoint::event::enqueue_event_ignore_in(
                            runtime,
                            crate::net::l4::endpoint::event::NetworkEvent::DhcpApplyLease {
                                if_id: Some(interface_runtime.if_id.0),
                                ip: *lease.ip_address.as_bytes(),
                                subnet: *lease.subnet_mask.as_bytes(),
                                gateway: lease
                                    .gateway
                                    .map(|a| *a.as_bytes())
                                    .unwrap_or([0, 0, 0, 0]),
                                dns: lease
                                    .dns_servers
                                    .first()
                                    .map(|a| *a.as_bytes())
                                    .unwrap_or([0, 0, 0, 0]),
                                hostname: hostname_bytes,
                            },
                        );
                    }
                    Ok(DhcpResponseResult::Offer(lease)) => {
                        log::info!(
                            "[NET] DHCPv4 OFFER received: if{} mac={} ip={:?} server={:?}",
                            interface_runtime.if_id.0,
                            interface_runtime.mac(),
                            lease.ip_address,
                            lease.server_ip
                        );
                    }
                    Ok(DhcpResponseResult::Nak) => {
                        log::warn!(
                            "[NET] DHCPv4 NAK received: if{} mac={}",
                            interface_runtime.if_id.0,
                            interface_runtime.mac()
                        );
                    }
                    Err(err) => {
                        log::warn!(
                            "[NET] DHCPv4 response error: if{} mac={} err={}",
                            interface_runtime.if_id.0,
                            interface_runtime.mac(),
                            err
                        );
                    }
                }
            }
            None => {
                log::warn!("[NET] DHCPv4 dispatcher socket closed unexpectedly");
                runtime_state_for(runtime)
                    .v4_dispatcher_started
                    .store(false, Ordering::Release);
                break;
            }
        }
    }
}

pub fn update_runtime_mac(mac_address: MacAddress) {
    v6::update_client_v6_mac(mac_address);
}

/// DHCPサーバーポート
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCPメッセージの最大サイズ
pub const DHCP_MAX_MESSAGE_SIZE: usize = 576;

/// DHCPマジッククッキー
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// DHCPオペレーションタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpOperation {
    /// クライアント要求
    Request = 1,
    /// サーバー応答
    Reply = 2,
}

/// DHCPメッセージタイプ (オプション53)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    /// DHCPDISCOVER
    Discover = 1,
    /// DHCPOFFER
    Offer = 2,
    /// DHCPREQUEST
    Request = 3,
    /// DHCPDECLINE
    Decline = 4,
    /// DHCPACK
    Ack = 5,
    /// DHCPNAK
    Nak = 6,
    /// DHCPRELEASE
    Release = 7,
    /// DHCPINFORM
    Inform = 8,
}

impl DhcpMessageType {
    /// u8から変換
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            _ => None,
        }
    }
}

/// DHCPオプションコード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpOption {
    /// パディング
    Pad = 0,
    /// サブネットマスク
    SubnetMask = 1,
    /// ルーター (デフォルトゲートウェイ)
    Router = 3,
    /// DNSサーバー
    DnsServer = 6,
    /// ホスト名
    Hostname = 12,
    /// ドメイン名
    DomainName = 15,
    /// 要求されたIPアドレス
    RequestedIp = 50,
    /// リース時間
    LeaseTime = 51,
    /// Renewal (T1)
    RenewalTime = 58,
    /// Rebinding (T2)
    RebindingTime = 59,
    /// メッセージタイプ
    MessageType = 53,
    /// サーバー識別子
    ServerIdentifier = 54,
    /// パラメータ要求リスト
    ParameterRequestList = 55,
    /// 最大メッセージサイズ (RFC 2131)
    MaximumMessageSize = 57,
    /// クライアント識別子
    ClientIdentifier = 61,
    /// 終端
    End = 255,
}

/// DHCPヘッダ
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct DhcpHeader {
    /// オペレーション (1 = Request, 2 = Reply)
    pub op: u8,
    /// ハードウェアタイプ (1 = Ethernet)
    pub htype: u8,
    /// ハードウェアアドレス長 (6 for Ethernet)
    pub hlen: u8,
    /// ホップ数
    pub hops: u8,
    /// トランザクションID
    pub xid: [u8; 4],
    /// 経過秒数
    pub secs: [u8; 2],
    /// フラグ
    pub flags: [u8; 2],
    /// クライアントIPアドレス
    pub ciaddr: [u8; 4],
    /// 提供されたIPアドレス
    pub yiaddr: [u8; 4],
    /// サーバーIPアドレス
    pub siaddr: [u8; 4],
    /// リレーエージェントIPアドレス
    pub giaddr: [u8; 4],
    /// クライアントハードウェアアドレス (16バイト)
    pub chaddr: [u8; 16],
    /// サーバー名 (64バイト)
    pub sname: [u8; 64],
    /// ブートファイル名 (128バイト)
    pub file: [u8; 128],
}

impl DhcpHeader {
    /// ヘッダサイズ
    pub const SIZE: usize = 236;

    /// ヘッダをバイト列へシリアライズする。
    ///
    /// `DhcpHeader` はネットワークバイトオーダーの byte-array フィールドを保持しており、
    /// この関数はそのまま順序どおりに書き出す。
    pub fn encode_into(&self, dst: &mut [u8]) -> Result<(), &'static str> {
        if dst.len() < Self::SIZE {
            return Err("Buffer too small");
        }

        let mut off = 0usize;
        dst[off] = self.op;
        off += 1;
        dst[off] = self.htype;
        off += 1;
        dst[off] = self.hlen;
        off += 1;
        dst[off] = self.hops;
        off += 1;

        dst[off..off + 4].copy_from_slice(&self.xid);
        off += 4;
        dst[off..off + 2].copy_from_slice(&self.secs);
        off += 2;
        dst[off..off + 2].copy_from_slice(&self.flags);
        off += 2;
        dst[off..off + 4].copy_from_slice(&self.ciaddr);
        off += 4;
        dst[off..off + 4].copy_from_slice(&self.yiaddr);
        off += 4;
        dst[off..off + 4].copy_from_slice(&self.siaddr);
        off += 4;
        dst[off..off + 4].copy_from_slice(&self.giaddr);
        off += 4;
        dst[off..off + 16].copy_from_slice(&self.chaddr);
        off += 16;
        dst[off..off + 64].copy_from_slice(&self.sname);
        off += 64;
        dst[off..off + 128].copy_from_slice(&self.file);
        off += 128;

        debug_assert_eq!(off, Self::SIZE);
        Ok(())
    }

    pub fn decode_from(src: &[u8]) -> Option<Self> {
        if src.len() < Self::SIZE {
            return None;
        }

        let mut off = 0usize;
        let op = src[off];
        off += 1;
        let htype = src[off];
        off += 1;
        let hlen = src[off];
        off += 1;
        let hops = src[off];
        off += 1;

        let mut xid = [0u8; 4];
        xid.copy_from_slice(&src[off..off + 4]);
        off += 4;
        let mut secs = [0u8; 2];
        secs.copy_from_slice(&src[off..off + 2]);
        off += 2;
        let mut flags = [0u8; 2];
        flags.copy_from_slice(&src[off..off + 2]);
        off += 2;
        let mut ciaddr = [0u8; 4];
        ciaddr.copy_from_slice(&src[off..off + 4]);
        off += 4;
        let mut yiaddr = [0u8; 4];
        yiaddr.copy_from_slice(&src[off..off + 4]);
        off += 4;
        let mut siaddr = [0u8; 4];
        siaddr.copy_from_slice(&src[off..off + 4]);
        off += 4;
        let mut giaddr = [0u8; 4];
        giaddr.copy_from_slice(&src[off..off + 4]);
        off += 4;
        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&src[off..off + 16]);
        off += 16;
        let mut sname = [0u8; 64];
        sname.copy_from_slice(&src[off..off + 64]);
        off += 64;
        let mut file = [0u8; 128];
        file.copy_from_slice(&src[off..off + 128]);

        Some(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
        })
    }

    /// トランザクションIDを取得
    pub fn xid(&self) -> u32 {
        u32::from_be_bytes(self.xid)
    }

    /// 経過秒数を取得
    pub fn secs(&self) -> u16 {
        u16::from_be_bytes(self.secs)
    }

    /// フラグを取得
    pub fn flags(&self) -> u16 {
        u16::from_be_bytes(self.flags)
    }

    /// クライアントIPを取得
    pub fn ciaddr(&self) -> Ipv4Address {
        Ipv4Address::new(self.ciaddr)
    }

    /// 提供されたIPを取得
    pub fn yiaddr(&self) -> Ipv4Address {
        Ipv4Address::new(self.yiaddr)
    }

    /// サーバーIPを取得
    pub fn siaddr(&self) -> Ipv4Address {
        Ipv4Address::new(self.siaddr)
    }
}

// Compile-time size check: declared DHCP header size must match the packed struct size.
const _: [(); DhcpHeader::SIZE] = [(); core::mem::size_of::<DhcpHeader>()];
const _: [(); core::mem::size_of::<DhcpHeader>()] = [(); DhcpHeader::SIZE];

/// 取得したDHCP設定
#[derive(Debug, Clone)]
pub struct DhcpLease {
    /// 割り当てられたIPアドレス
    pub ip_address: Ipv4Address,
    /// サブネットマスク
    pub subnet_mask: Ipv4Address,
    /// デフォルトゲートウェイ
    pub gateway: Option<Ipv4Address>,
    /// DNSサーバー (最大3つ)
    pub dns_servers: Vec<Ipv4Address>,
    /// DHCPサーバーのIPアドレス
    pub server_ip: Ipv4Address,
    /// リース時間 (秒)
    pub lease_time: u32,
    /// Renewal time (T1)
    pub t1: u32,
    /// Rebinding time (T2)
    pub t2: u32,
    /// 取得時刻 (tick)
    pub obtained_at: u64,
    /// ホスト名
    pub hostname: Option<Vec<u8>>,
    /// ドメイン名
    pub domain_name: Option<Vec<u8>>,
}

impl DhcpLease {
    /// リースが期限切れか判定
    pub fn is_expired(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.obtained_at)) / tick_rate;
        elapsed_secs > self.lease_time as u64
    }

    /// 更新が必要か判定 (T1到達)
    pub fn needs_renewal(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.obtained_at)) / tick_rate;
        elapsed_secs >= self.t1 as u64
    }

    /// 再バインドが必要か判定 (T2到達)
    pub fn needs_rebind(&self, current_tick: u64, tick_rate: u64) -> bool {
        let elapsed_secs = (current_tick.saturating_sub(self.obtained_at)) / tick_rate;
        elapsed_secs >= self.t2 as u64
    }
}

/// DHCPクライアントの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    /// 初期状態
    Init,
    /// DISCOVER送信済み、OFFER待ち
    Selecting,
    /// REQUEST送信済み、ACK待ち
    Requesting,
    /// リース取得済み
    Bound,
    /// DHCPINFORM送信済み、ACK待ち
    Informing,
    /// 更新中
    Renewing,
    /// 再バインド中
    Rebinding,
}

/// DHCPクライアント
pub struct DhcpClient {
    runtime: NetRuntimeHandle,
    /// MACアドレス
    mac_address: MacAddress,
    /// 現在の状態
    state: PoisonLock<DhcpState>,
    /// 現在のトランザクションID
    xid: AtomicU32,
    /// 現在のリース
    lease: PoisonLock<Option<DhcpLease>>,
    /// 提案されたリース (OFFER受信後)
    offered_lease: PoisonLock<Option<DhcpLease>>,
    /// offered lease の ARP probe 送信時刻 (tick)
    offered_probe_at: AtomicU64,
    /// Last declined IP (u32 network-order, 0 when none)
    last_declined: AtomicU32,
    /// Last released IP (u32 network-order, 0 when none)
    last_released: AtomicU32,
    /// 状態遷移時刻
    state_time: AtomicU64,
    /// 再試行回数
    retry_count: AtomicU32,
}

/// DHCP応答から解析されたオプション群
struct ParsedOptions {
    message_type: Option<DhcpMessageType>,
    subnet_mask: Option<Ipv4Address>,
    router: Option<Ipv4Address>,
    dns_servers: Vec<Ipv4Address>,
    lease_time: u32,
    renewal_time: Option<u32>,
    rebinding_time: Option<u32>,
    server_id: Option<Ipv4Address>,
    hostname: Option<Vec<u8>>,
    domain_name: Option<Vec<u8>>,
}
