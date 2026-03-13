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

use crate::net::l4::endpoint::tcb_table;
use crate::net::runtime::manager::{self, NetIfId};
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

/// DHCP snapshot tagged with the owning interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDhcpState {
    pub if_id: u16,
    pub state: DhcpRuntimeState,
}

/// DHCPディスカバー（イベントキュー経由）
///
// 旧同期API (dhcp_discover, dhcp_request, dhcp_release, dhcp_last_declined,
// dhcp_last_released, dhcp_renew) は削除済み。
// 非同期版 (dhcp_discover, dhcp_release, dhcp_renew,
// dhcp_last_declined, dhcp_last_released) を使用すること。

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
    let bootstrap_config = manager::list_interfaces()
        .ok()
        .unwrap_or_default()
        .into_iter()
        .find_map(|iface| iface.config)
        .or_else(|| match stack::stack().lock() {
            Ok(guard) => guard.as_ref().map(|stack_guard| stack_guard.config()),
            Err(_) => None,
        })
        .ok_or_else(|| String::from("Network stack is not initialized"))?;

    let mac = bootstrap_config.mac;
    let ipv6_enabled = bootstrap_config.ipv6.is_some();

    dhcp::init(mac);
    if ipv6_enabled {
        dhcp::init_v6(mac);
    } else {
        log::info!("[NET] DHCPv6 runtime disabled: IPv6 is not configured");
    }

    let dns_servers = if let Some(d) = bootstrap_config.ipv4.dns {
        vec![d]
    } else {
        vec![]
    };
    let hostname = String::from("ranyos");
    let ip = bootstrap_config.ipv4.address;
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

    // DHCPv4 itself is now driven by the per-interface runtime registry.
    // Keep the legacy singleton initialized as a compatibility view, but do not
    // spawn its dedicated socket task here because the shared dispatcher owns
    // UDP port 68.

    if ipv6_enabled {
        // Spawn DHCPv6 client task only when IPv6 is configured for the active stack.
        crate::task::spawn_task(crate::task::Task::new(async move {
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
    }

    // Spawn mDNS service task
    crate::task::spawn_task(crate::task::Task::new(async move {
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
    crate::task::spawn_task(crate::task::Task::new(async move {
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

fn snapshot_for_interface(if_id: NetIfId) -> DhcpRuntimeState {
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

    if let Some(client) = dhcp::interface_v4_client(if_id) {
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

    if crate::net::runtime::device::primary_if() == Some(if_id) {
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
    }

    out
}

pub(crate) fn get_dhcp_state_sync(if_id: NetIfId) -> DhcpRuntimeState {
    snapshot_for_interface(if_id)
}

pub(crate) fn list_dhcp_states_sync() -> alloc::vec::Vec<InterfaceDhcpState> {
    manager::list_interfaces()
        .unwrap_or_default()
        .into_iter()
        .map(|iface| InterfaceDhcpState {
            if_id: iface.if_id.0,
            state: snapshot_for_interface(iface.if_id),
        })
        .collect()
}

/// DHCP状態取得（読み取り専用・短命ロック）
///
/// DHCPv4/v6クライアントの現在の状態をスナップショットとして取得する。
/// 読み取り専用のためロック保持時間は最小限。
pub(crate) fn dhcp_state_sync() -> DhcpRuntimeState {
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

    if let Some(client) = dhcp::primary_v4_client() {
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
    } else {
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

// 旧同期 dhcp_renew は削除済み（dhcp_renew を使用すること）

/// 非同期DHCP状態取得（推奨API）
///
/// イベントキュー経由でDHCPクライアントにアクセスし、同期ロックを回避する。
pub async fn get_dhcp_state(if_id: NetIfId) -> DhcpRuntimeState {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<DhcpRuntimeState>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::GetDhcpState {
        if_id: Some(if_id.0),
        result_slot,
        waker,
    };
    let _ = crate::net::l4::endpoint::event::send_event(event).await;
    command_future.await
}

pub async fn list_dhcp_states() -> alloc::vec::Vec<InterfaceDhcpState> {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<alloc::vec::Vec<InterfaceDhcpState>>();
    let event =
        crate::net::l4::endpoint::event::NetworkEvent::ListDhcpStates { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event(event).await;
    command_future.await
}

pub async fn dhcp_state() -> DhcpRuntimeState {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<DhcpRuntimeState>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::GetDhcpState {
        if_id: None,
        result_slot,
        waker,
    };
    let _ = crate::net::l4::endpoint::event::send_event(event).await;
    command_future.await
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
            let mut enqueue = crate::net::l4::endpoint::event::send_event(
                crate::net::l4::endpoint::event::NetworkEvent::DhcpRenew {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(String::from("network event dispatch failed")));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        stack::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

/// 非同期DHCPリニュー（推奨API）
///
/// # 使用例
/// ```ignore
/// let result = dhcp_renew().await;
/// ```
pub fn dhcp_renew() -> DhcpRenewFuture {
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
            let mut enqueue = crate::net::l4::endpoint::event::send_event(
                crate::net::l4::endpoint::event::NetworkEvent::DhcpRelease {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(false),
                Poll::Pending => return Poll::Pending,
            }
        }

        stack::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

/// 非同期DHCPリリース（推奨API）
///
/// # 使用例
/// ```ignore
/// let released = dhcp_release().await;
/// ```
pub fn dhcp_release() -> DhcpReleaseFuture {
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
            let mut enqueue = crate::net::l4::endpoint::event::send_event(
                crate::net::l4::endpoint::event::NetworkEvent::DhcpDiscover {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }

        stack::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

/// 非同期DHCPディスカバー（推奨API）
///
/// # 使用例
/// ```ignore
/// let offer = dhcp_discover().await;
/// ```
pub fn dhcp_discover() -> DhcpDiscoverFuture {
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
            let mut enqueue = crate::net::l4::endpoint::event::send_event(
                crate::net::l4::endpoint::event::NetworkEvent::DhcpLastDeclined {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }

        stack::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

/// 非同期DHCP最終拒否IP取得（推奨API）
pub fn dhcp_last_declined() -> DhcpLastDeclinedFuture {
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
            let mut enqueue = crate::net::l4::endpoint::event::send_event(
                crate::net::l4::endpoint::event::NetworkEvent::DhcpLastReleased {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }

        stack::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

/// 非同期DHCP最終解放IP取得（推奨API）
pub fn dhcp_last_released() -> DhcpLastReleasedFuture {
    DhcpLastReleasedFuture::new()
}

#[cfg(test)]
mod tests {
    #[test]
    fn dhcp_state_completes_with_event_task() {
        let state = {
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output = super::dhcp_state().await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::l4::endpoint::tcp_rx::network_event_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            output.expect("dhcp_state test timed out")
        };
        assert!(!state.v4_state.is_empty());
    }
}
