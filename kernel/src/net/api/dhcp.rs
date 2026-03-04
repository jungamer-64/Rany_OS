// ============================================================================
// kernel/src/net/api/dhcp.rs - DHCP操作（v4/v6）
// ============================================================================
//! DHCPv4/v6クライアントの初期化、discover/request/release/renew、状態取得。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::endpoint::tcb_table;
use crate::net::runtime::stack;
use crate::net::services::dhcp;
use crate::sync::PoisonLock;
use crate::sync::atomic_waker::AtomicWaker;

use super::config::get_network_config;

extern crate alloc;

/// DHCP runtime state snapshot for v4/v6 clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpRuntimeState {
    pub v4_state: String,
    pub v4_assigned_ip: Option<[u8; 4]>,
    pub v4_lease_remaining: Option<u32>,
    pub v4_last_declined: Option<[u8; 4]>,
    pub v4_last_released: Option<[u8; 4]>,
    pub v6_state: String,
    pub v6_assigned_ip: Option<[u8; 16]>,
    pub v6_preferred_remaining: Option<u32>,
    pub v6_valid_remaining: Option<u32>,
}

/// DHCP offer info exposed for shell/API consumers.
#[derive(Debug, Clone)]
pub struct DhcpOfferInfo {
    pub server_ip: [u8; 4],
    pub offered_ip: [u8; 4],
}

/// DHCPディスカバー（イベントキュー経由）
///
/// DHCP discover イベントを発火し、クライアントの駆動をエグゼキュータに委任する。
/// 同期的にオファー結果を返すことはできないため、
/// 応答を取得するには `dhcp_discover_async().await` を使用すること。
pub fn dhcp_discover() -> Option<DhcpOfferInfo> {
    // fire-and-forget: イベントキュー経由でDHCPクライアントを駆動
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncDhcpDiscover {
            result_slot: alloc::sync::Arc::new(crate::sync::PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
    // 同期的にオファーを返すことはできない（イベントキュー経由のため）
    None
}

/// DHCPリクエスト送信（内部的にイベントキュー経由のUDP送信を使用）
///
/// パケット構築は同期的に行うが、実際の送信は `send_udp_async()` 経由で
/// イベントキューに委任されるため、ブロッキングは発生しない。
pub fn dhcp_request(server_ip: [u8; 4], offered_ip: [u8; 4]) -> bool {
    use crate::net::services::dhcp::{
        DHCP_CLIENT_PORT, DHCP_MAGIC_COOKIE, DHCP_MAX_MESSAGE_SIZE, DHCP_SERVER_PORT,
        DhcpHeader, DhcpMessageType, DhcpOperation, DhcpOption,
    };

    let mut buf = [0u8; DHCP_MAX_MESSAGE_SIZE];
    let xid = tcb_table().get_current_tick() as u32 ^ 0xDEAD_BEEF;

    let mut header_struct = DhcpHeader {
        op: DhcpOperation::Request as u8,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: xid.to_be_bytes(),
        secs: 0u16.to_be_bytes(),
        flags: 0x8000u16.to_be_bytes(),
        ciaddr: [0; 4],
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr: [0; 16],
        sname: [0; 64],
        file: [0; 128],
    };

    // NOTE: パケット構築のためMAC取得に同期版を使用（ブートストラップ専用・短命ロック）
    if let Some(cfg) = get_network_config() {
        header_struct.chaddr[..6].copy_from_slice(&cfg.mac);
    }

    if header_struct.encode_into(&mut buf[..DhcpHeader::SIZE]).is_err() {
        return false;
    }

    let mut opts = Vec::with_capacity(64);
    opts.extend_from_slice(&DHCP_MAGIC_COOKIE);
    opts.push(DhcpOption::MessageType as u8);
    opts.push(1);
    opts.push(DhcpMessageType::Request as u8);
    opts.push(DhcpOption::RequestedIp as u8);
    opts.push(4);
    opts.extend_from_slice(&offered_ip);
    opts.push(DhcpOption::ServerIdentifier as u8);
    opts.push(4);
    opts.extend_from_slice(&server_ip);
    opts.push(DhcpOption::End as u8);

    let total_len = DhcpHeader::SIZE + opts.len();
    if total_len > buf.len() {
        return false;
    }
    buf[DhcpHeader::SIZE..DhcpHeader::SIZE + opts.len()].copy_from_slice(&opts);

    let dst = if server_ip == [0, 0, 0, 0] {
        Ipv4Address::new([255, 255, 255, 255])
    } else {
        Ipv4Address::new(server_ip)
    };
    stack::send_udp_async(DHCP_CLIENT_PORT, dst, DHCP_SERVER_PORT, &buf[..total_len], 64)
}

/// DHCPリリース（イベントキュー経由）
///
/// DHCP release イベントを発火し、リリース処理をエグゼキュータに委任する。
/// 完了を待機するには `dhcp_release_async().await` を使用すること。
pub fn dhcp_release() {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncDhcpRelease {
            result_slot: alloc::sync::Arc::new(crate::sync::PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
}

/// DHCP最終拒否IP取得（読み取り専用・短命ロック）
///
/// DHCPクライアントの最終拒否IPを読み取る。読み取り専用のため
/// ロック保持時間は最小限であり、デッドロックリスクは低い。
pub fn dhcp_last_declined() -> Option<[u8; 4]> {
    if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            return client.last_declined_ip().map(|ip| *ip.as_bytes());
        }
    }
    None
}

/// DHCP最終解放IP取得（読み取り専用・短命ロック）
///
/// DHCPクライアントの最終解放IPを読み取る。読み取り専用のため
/// ロック保持時間は最小限であり、デッドロックリスクは低い。
pub fn dhcp_last_released() -> Option<[u8; 4]> {
    if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            return client.last_released_ip().map(|ip| *ip.as_bytes());
        }
    }
    None
}

pub fn dhcp_v4_state_name(state: dhcp::DhcpState) -> &'static str {
    match state {
        dhcp::DhcpState::Init => "Init",
        dhcp::DhcpState::Selecting => "Selecting",
        dhcp::DhcpState::Requesting => "Requesting",
        dhcp::DhcpState::Bound => "Bound",
        dhcp::DhcpState::Renewing => "Renewing",
        dhcp::DhcpState::Rebinding => "Rebinding",
    }
}

pub fn dhcp_v6_state_name(state: dhcp::DhcpV6State) -> &'static str {
    match state {
        dhcp::DhcpV6State::Init => "Init",
        dhcp::DhcpV6State::SolicitSent => "SolicitSent",
        dhcp::DhcpV6State::Requesting => "Requesting",
        dhcp::DhcpV6State::Bound => "Bound",
        dhcp::DhcpV6State::Renewing => "Renewing",
        dhcp::DhcpV6State::Rebinding => "Rebinding",
    }
}

pub fn lease_remaining_secs(total: u32, obtained_at: u64, now: u64, tick_rate: u64) -> u32 {
    let elapsed = (now.saturating_sub(obtained_at)) / tick_rate;
    total.saturating_sub(core::cmp::min(elapsed, u32::MAX as u64) as u32)
}

/// DHCP/mDNS/DNS ランタイム初期化
///
/// エグゼキュータ起動前の初期化処理のため、同期版スタックアクセスを使用。
/// この関数は一度だけ呼ばれるブートストラップ処理であり、
/// 同期ロック取得は許容される。
pub fn init_dhcp_runtime() -> Result<(), String> {
    let mac = match stack::stack().lock() {
        Ok(guard) => match guard.as_ref() {
            Some(stack_guard) => stack_guard.config().mac,
            None => return Err(String::from("Network stack is not initialized")),
        },
        Err(_) => return Err(String::from("Network stack lock poisoned")),
    };

    dhcp::init(mac);
    dhcp::init_v6(mac);

    let (hostname, ip, dns_servers) = match stack::stack().lock() {
        Ok(guard) => match guard.as_ref() {
            Some(stack_guard) => {
                let cfg = stack_guard.config();
                let dns = if let Some(d) = cfg.ipv4.dns { vec![d] } else { vec![] };
                (String::from("ranyos"), cfg.ipv4.address, dns)
            }
            None => (String::from("ranyos"), Ipv4Address::new([0, 0, 0, 0]), vec![]),
        },
        Err(_) => (String::from("ranyos"), Ipv4Address::new([0, 0, 0, 0]), vec![]),
    };
    crate::net::services::mdns::init(hostname, ip);

    // DNS 初期化
    crate::net::services::dns::init(1000);
    if !dns_servers.is_empty() {
        if let Ok(guard) = crate::net::services::dns::client().lock() {
            if let Some(ref client) = *guard {
                client.set_ipv4_servers(dns_servers);
            }
        }
    }

    // Spawn DHCPv4 client task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
            if let Some(client) = &*guard {
                let _ = client.run().await;
            }
        }
    }));

    // Spawn DHCPv6 client task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        if let Ok(guard) = dhcp::DHCPV6_CLIENT.lock() {
            if let Some(client6) = &*guard {
                let _ = client6.run().await;
            }
        }
    }));

    // Spawn mDNS service task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        if let Ok(mut guard) = crate::net::services::mdns::service().lock() {
            if let Some(ref mut service) = *guard {
                let _ = service.run().await;
            }
        }
    }));

    // Spawn DNS client task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        if let Ok(guard) = crate::net::services::dns::client().lock() {
            if let Some(ref client) = *guard {
                let _ = client.run().await;
            }
        }
    }));

    Ok(())
}

/// DHCP状態取得（読み取り専用・短命ロック）
///
/// DHCPv4/v6クライアントの現在の状態をスナップショットとして取得する。
/// 読み取り専用のためロック保持時間は最小限。
pub fn dhcp_state() -> DhcpRuntimeState {
    let now = tcb_table().get_current_tick();
    let tick_rate = 1000u64;

    let mut out = DhcpRuntimeState {
        v4_state: String::from("Init"),
        v4_assigned_ip: None,
        v4_lease_remaining: None,
        v4_last_declined: None,
        v4_last_released: None,
        v6_state: String::from("Init"),
        v6_assigned_ip: None,
        v6_preferred_remaining: None,
        v6_valid_remaining: None,
    };

    match dhcp::DHCP_CLIENT.lock() {
        Ok(guard) => {
            if let Some(ref client) = *guard {
                out.v4_state = String::from(dhcp_v4_state_name(client.state()));
                if let Some(lease) = client.lease() {
                    out.v4_assigned_ip = Some(*lease.ip_address.as_bytes());
                    out.v4_lease_remaining = Some(lease_remaining_secs(
                        lease.lease_time,
                        lease.obtained_at,
                        now,
                        tick_rate,
                    ));
                }
                out.v4_last_declined = client.last_declined_ip().map(|ip| *ip.as_bytes());
                out.v4_last_released = client.last_released_ip().map(|ip| *ip.as_bytes());
            }
        }
        Err(_) => out.v4_state = String::from("Poisoned"),
    }

    match dhcp::DHCPV6_CLIENT.lock() {
        Ok(guard6) => {
            if let Some(ref client6) = *guard6 {
                out.v6_state = String::from(dhcp_v6_state_name(client6.state()));
                if let Some(lease6) = client6.lease() {
                    out.v6_assigned_ip = Some(*lease6.addr.as_bytes());
                    out.v6_preferred_remaining = Some(lease_remaining_secs(
                        lease6.preferred_lifetime,
                        lease6.obtained_at,
                        now,
                        tick_rate,
                    ));
                    out.v6_valid_remaining = Some(lease_remaining_secs(
                        lease6.valid_lifetime,
                        lease6.obtained_at,
                        now,
                        tick_rate,
                    ));
                }
            }
        }
        Err(_) => out.v6_state = String::from("Poisoned"),
    }

    out
}

/// DHCPリニュー（イベントキュー経由）
///
/// DHCP renew イベントを発火し、リニュー処理をエグゼキュータに委任する。
/// 完了を待機するには `dhcp_renew_async().await` を使用すること。
pub fn dhcp_renew() -> Result<(), String> {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncDhcpRenew {
            result_slot: alloc::sync::Arc::new(crate::sync::PoisonLock::new(None)),
            waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
        },
    );
    Ok(())
}

// NOTE: 旧同期dhcp_renewは削除済み（イベントキュー経由に移行）
// handler.rs の AsyncDhcpRenew イベントハンドラで処理される

// ============================================================================
// 非同期API（推奨）
// ============================================================================

/// 非同期DHCP状態取得Future
pub struct DhcpStateFuture {
    result_slot: Arc<PoisonLock<Option<DhcpRuntimeState>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpStateFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for DhcpStateFuture {
    type Output = DhcpRuntimeState;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncGetDhcpState {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        if let Ok(slot) = this.result_slot.lock() {
            if let Some(state) = slot.as_ref() {
                return Poll::Ready(state.clone());
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期DHCP状態取得（推奨API）
///
/// イベントキュー経由でDHCPクライアントにアクセスし、同期ロックを回避する。
///
/// # 使用例
/// ```ignore
/// let state = dhcp_state_async().await;
/// ```
pub fn dhcp_state_async() -> DhcpStateFuture {
    DhcpStateFuture::new()
}

/// 非同期DHCPリニューFuture
pub struct DhcpRenewFuture {
    result_slot: Arc<PoisonLock<Option<Result<(), String>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpRenewFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for DhcpRenewFuture {
    type Output = Result<(), String>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncDhcpRenew {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        if let Ok(slot) = this.result_slot.lock() {
            if let Some(result) = slot.as_ref() {
                return Poll::Ready(result.clone());
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期DHCPリニュー（推奨API）
///
/// # 使用例
/// ```ignore
/// let result = dhcp_renew_async().await;
/// ```
pub fn dhcp_renew_async() -> DhcpRenewFuture {
    DhcpRenewFuture::new()
}

/// 非同期DHCPリリースFuture
pub struct DhcpReleaseFuture {
    result_slot: Arc<PoisonLock<Option<bool>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpReleaseFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for DhcpReleaseFuture {
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncDhcpRelease {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        if let Ok(slot) = this.result_slot.lock() {
            if let Some(result) = slot.as_ref() {
                return Poll::Ready(*result);
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期DHCPリリース（推奨API）
///
/// # 使用例
/// ```ignore
/// let released = dhcp_release_async().await;
/// ```
pub fn dhcp_release_async() -> DhcpReleaseFuture {
    DhcpReleaseFuture::new()
}

/// 非同期DHCPディスカバーFuture
pub struct DhcpDiscoverFuture {
    result_slot: Arc<PoisonLock<Option<Option<DhcpOfferInfo>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpDiscoverFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for DhcpDiscoverFuture {
    type Output = Option<DhcpOfferInfo>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncDhcpDiscover {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        if let Ok(slot) = this.result_slot.lock() {
            if let Some(result) = slot.as_ref() {
                return Poll::Ready(result.clone());
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期DHCPディスカバー（推奨API）
///
/// # 使用例
/// ```ignore
/// let offer = dhcp_discover_async().await;
/// ```
pub fn dhcp_discover_async() -> DhcpDiscoverFuture {
    DhcpDiscoverFuture::new()
}

/// 非同期DHCP最終拒否IP取得Future
pub struct DhcpLastDeclinedFuture {
    result_slot: Arc<PoisonLock<Option<Option<[u8; 4]>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpLastDeclinedFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for DhcpLastDeclinedFuture {
    type Output = Option<[u8; 4]>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncDhcpLastDeclined {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        if let Ok(slot) = this.result_slot.lock() {
            if let Some(result) = slot.as_ref() {
                return Poll::Ready(*result);
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期DHCP最終拒否IP取得（推奨API）
pub fn dhcp_last_declined_async() -> DhcpLastDeclinedFuture {
    DhcpLastDeclinedFuture::new()
}

/// 非同期DHCP最終解放IP取得Future
pub struct DhcpLastReleasedFuture {
    result_slot: Arc<PoisonLock<Option<Option<[u8; 4]>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpLastReleasedFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for DhcpLastReleasedFuture {
    type Output = Option<[u8; 4]>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncDhcpLastReleased {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        if let Ok(slot) = this.result_slot.lock() {
            if let Some(result) = slot.as_ref() {
                return Poll::Ready(*result);
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期DHCP最終解放IP取得（推奨API）
pub fn dhcp_last_released_async() -> DhcpLastReleasedFuture {
    DhcpLastReleasedFuture::new()
}
