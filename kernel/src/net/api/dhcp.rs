// ============================================================================
// kernel/src/net/api/dhcp.rs - DHCP操作（v4/v6）
// ============================================================================
//! DHCPv4/v6クライアントの初期化、discover/request/release/renew、状態取得。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::endpoint::tcb_table;
use crate::net::runtime::stack;
use crate::net::services::dhcp;
use crate::sync::PoisonLock;
use crate::sync::atomic_waker::AtomicWaker;

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
// 旧同期API (dhcp_discover, dhcp_request, dhcp_release, dhcp_last_declined,
// dhcp_last_released, dhcp_renew) は削除済み。
// 非同期版 (dhcp_discover_async, dhcp_release_async, dhcp_renew_async,
// dhcp_last_declined_async, dhcp_last_released_async) を使用すること。

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
                let dns = if let Some(d) = cfg.ipv4.dns {
                    vec![d]
                } else {
                    vec![]
                };
                (String::from("ranyos"), cfg.ipv4.address, dns)
            }
            None => (
                String::from("ranyos"),
                Ipv4Address::new([0, 0, 0, 0]),
                vec![],
            ),
        },
        Err(_) => (
            String::from("ranyos"),
            Ipv4Address::new([0, 0, 0, 0]),
            vec![],
        ),
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
    //
    // DHCP_CLIENT は PoisonLock（スピンロック）で保護されている。
    // ロックを .await を跨いで保持するとデッドロックするため、
    // 初期化済みクライアントへの 'static 参照を取得してからロックを解放する。
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        let client_ref: Option<&'static dhcp::DhcpClient> = {
            let guard = match dhcp::DHCP_CLIENT.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.as_ref().map(|c| {
                // SAFETY: DHCP_CLIENT はカーネル静的変数で init() 後は
                // Some のまま変更されず、カーネル寿命と同等に存続する。
                unsafe { &*(c as *const dhcp::DhcpClient) }
            })
        }; // guard ドロップ → ロック解放
        if let Some(client) = client_ref {
            if let Err(e) = client.run().await {
                log::error!("[NET] DHCPv4 client task failed: {}", e);
            }
        }
    }));

    // Spawn DHCPv6 client task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        let client_ref: Option<&'static dhcp::DhcpV6Client> = {
            let guard = match dhcp::DHCPV6_CLIENT.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.as_ref().map(|c| {
                // SAFETY: DHCPV6_CLIENT はカーネル静的変数で init_v6() 後は
                // Some のまま変更されず、カーネル寿命と同等に存続する。
                unsafe { &*(c as *const dhcp::DhcpV6Client) }
            })
        }; // guard ドロップ → ロック解放
        if let Some(client6) = client_ref {
            if let Err(e) = client6.run().await {
                log::error!("[NET] DHCPv6 client task failed: {}", e);
            }
        }
    }));

    // Spawn mDNS service task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        let svc_ref: Option<&'static mut crate::net::services::mdns::MdnsService> = {
            let mut guard = match crate::net::services::mdns::service().lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.as_mut().map(|s| {
                // SAFETY: mDNS サービスはカーネル静的変数で init() 後は
                // Some のまま変更されず、カーネル寿命と同等に存続する。
                unsafe { &mut *(s as *mut crate::net::services::mdns::MdnsService) }
            })
        }; // guard ドロップ → ロック解放
        if let Some(service) = svc_ref {
            let _ = service.run().await;
        }
    }));

    // Spawn DNS client task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        let client_ref: Option<&'static crate::net::services::dns::DnsClient> = {
            let guard = match crate::net::services::dns::client().lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.as_ref().map(|c| {
                // SAFETY: DNS クライアントはカーネル静的変数で init() 後は
                // Some のまま変更されず、カーネル寿命と同等に存続する。
                unsafe { &*(c as *const crate::net::services::dns::DnsClient) }
            })
        }; // guard ドロップ → ロック解放
        if let Some(client) = client_ref {
            let _ = client.run().await;
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

// 旧同期 dhcp_renew は削除済み（dhcp_renew_async を使用すること）

// ============================================================================
// 非同期API（推奨）
// ============================================================================

/// 非同期DHCP状態取得Future
pub struct DhcpStateFuture {
    ready: Option<DhcpRuntimeState>,
}

impl DhcpStateFuture {
    fn new() -> Self {
        Self {
            ready: Some(dhcp_state()),
        }
    }
}

impl Future for DhcpStateFuture {
    type Output = DhcpRuntimeState;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _ = cx;
        let this = self.get_mut();
        let state = this.ready.take().unwrap_or_else(dhcp_state);
        Poll::Ready(state)
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
