// ============================================================================
// kernel/src/net/api/dhcp.rs - DHCP操作（v4/v6）
// ============================================================================
//! DHCPv4/v6クライアントの初期化、discover/request/release/renew、状態取得。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use crate::net::l4::tcp::tcb_table;
use crate::net::runtime::manager::{self, NetIfId};
use crate::net::runtime::stack;
use crate::net::runtime::{NetRuntimeHandle, default_runtime};
use crate::net::services::dhcp;
use crate::sync::PoisonLock;
use crate::sync::atomic_waker::AtomicWaker;

extern crate alloc;

static NET_BACKGROUND_TASKS_STARTED: AtomicBool = AtomicBool::new(false);

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

pub fn dhcp_v4_state_name(state: dhcp::DhcpState) -> &'static str {
    match state {
        dhcp::DhcpState::Init => "Init",
        dhcp::DhcpState::Selecting => "Selecting",
        dhcp::DhcpState::Requesting => "Requesting",
        dhcp::DhcpState::Bound => "Bound",
        dhcp::DhcpState::Informing => "Informing",
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
    let runtime = default_runtime();
    let interfaces = manager::list_interfaces_in(runtime)
        .ok()
        .unwrap_or_default();
    let bootstrap_config = interfaces
        .iter()
        .find_map(|iface| iface.config)
        .or_else(|| match stack::stack_in(runtime).lock() {
            Ok(guard) => guard.as_ref().map(|stack_guard| stack_guard.config()),
            Err(_) => None,
        })
        .ok_or_else(|| String::from("Network stack is not initialized"))?;

    let ipv6_enabled = bootstrap_config.ipv6.is_some();

    for iface in interfaces {
        let Some(config) = iface.config else {
            continue;
        };
        if let Err(err) = dhcp::ensure_interface_runtime(iface.if_id, config) {
            log::warn!(
                "[NET] DHCPv4 interface runtime init failed: if{} err={}",
                iface.if_id.0,
                err
            );
        }
    }

    if ipv6_enabled {
        log::info!("[NET] DHCPv6 enabled via multi-interface system");
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
    crate::net::services::mdns::init_in(runtime, hostname, ip);

    // DNS 初期化
    crate::net::services::dns::init(1000);
    if !dns_servers.is_empty() {
        crate::net::services::dns::set_ipv4_servers(&dns_servers);
    }

    // DHCPv4 is driven by the per-interface runtime registry; bootstrap only
    // ensures interface runtimes exist for already-registered interfaces.

    log::info!(
        "[NET][boot] DHCP runtime initialized; background network service tasks deferred until runtime spawn"
    );

    Ok(())
}

pub(crate) fn start_background_service_tasks() {
    let runtime = default_runtime();
    let has_dhcpv6 = dhcp::primary_v6_client_in(runtime).is_some();
    let has_mdns = crate::net::services::mdns::service_in(runtime)
        .lock()
        .ok()
        .is_some_and(|guard| guard.is_some());
    let has_dns = crate::net::services::dns::cloned_client().is_some();

    if !has_dhcpv6 && !has_mdns && !has_dns {
        log::info!("[NET][boot] network service tasks not started: runtime services unavailable");
        return;
    }

    if NET_BACKGROUND_TASKS_STARTED.swap(true, Ordering::AcqRel) {
        log::info!("[NET][boot] network service tasks already started; skipping");
        return;
    }

    // DHCPv6 tasks are now spawned in dhcp::ensure_interface_runtime()
    // which is called from init_dhcp_runtime().
    if has_dhcpv6 {
        log::info!("[NET][boot] DHCPv6 multi-interface tasks already scheduled");
    }

    if has_mdns {
        log::info!("[NET][boot] scheduling mDNS service task on bootstrap CPU0");
        crate::task::spawn_on_cpu_with_priority(0, crate::task::Priority::Normal, async move {
            log::info!(
                "[NET][boot] mDNS service task running on CPU {}",
                crate::cpu::try_current_id().unwrap_or(0)
            );
            let svc_ref: Option<&'static mut crate::net::services::mdns::MdnsService> = {
                let mut guard = match crate::net::services::mdns::service_in(runtime).lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                guard
                    .as_mut()
                    .map(|s| unsafe { &mut *(s as *mut crate::net::services::mdns::MdnsService) })
            };
            if let Some(service) = svc_ref {
                let _ = service.run().await;
            }
        });
    }

    if has_dns {
        log::info!("[NET][boot] scheduling DNS client task on bootstrap CPU0");
        crate::task::spawn_on_cpu_with_priority(0, crate::task::Priority::Normal, async move {
            log::info!(
                "[NET][boot] DNS client task running on CPU {}",
                crate::cpu::try_current_id().unwrap_or(0)
            );
            let client = crate::net::services::dns::cloned_client();
            if let Some(client) = client {
                let _ = client.run().await;
            }
        });
    }
}

fn snapshot_for_interface_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> DhcpRuntimeState {
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

    if let Some(client) = dhcp::interface_v4_client_in(runtime, if_id) {
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

    if crate::net::runtime::device::primary_if_in(runtime) == Some(if_id) {
        if let Some(client6) = dhcp::primary_v6_client_in(runtime) {
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

    out
}

pub(crate) fn get_dhcp_state_snapshot_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> DhcpRuntimeState {
    snapshot_for_interface_in(runtime, if_id)
}

pub(crate) fn list_dhcp_states_snapshot_in(
    runtime: NetRuntimeHandle,
) -> alloc::vec::Vec<InterfaceDhcpState> {
    manager::list_interfaces_in(runtime)
        .unwrap_or_default()
        .into_iter()
        .map(|iface| InterfaceDhcpState {
            if_id: iface.if_id.0,
            state: snapshot_for_interface_in(runtime, iface.if_id),
        })
        .collect()
}

pub(crate) fn dhcp_state_snapshot_in(runtime: NetRuntimeHandle) -> DhcpRuntimeState {
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

    if let Some(client) = dhcp::primary_v4_client_in(runtime) {
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

    if let Some(client6) = dhcp::primary_v6_client_in(runtime) {
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

    out
}

pub async fn get_dhcp_state_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> DhcpRuntimeState {
    let (result_slot, waker, command_future) =
        crate::net::runtime::command::new_command_channel::<DhcpRuntimeState>();
    let event = crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::GetDhcpState {
        if_id: Some(if_id.0),
        result_slot,
        waker,
    });
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn list_dhcp_states_in(runtime: NetRuntimeHandle) -> alloc::vec::Vec<InterfaceDhcpState> {
    let (result_slot, waker, command_future) = crate::net::runtime::command::new_command_channel::<
        alloc::vec::Vec<InterfaceDhcpState>,
    >();
    let event =
        crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::ListDhcpStates { result_slot, waker });
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn dhcp_state_in(runtime: NetRuntimeHandle) -> DhcpRuntimeState {
    let (result_slot, waker, command_future) =
        crate::net::runtime::command::new_command_channel::<DhcpRuntimeState>();
    let event = crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::GetDhcpState {
        if_id: None,
        result_slot,
        waker,
    });
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

/// 非同期DHCPリニューFuture
pub struct DhcpRenewFuture {
    runtime: NetRuntimeHandle,
    result_slot: Arc<PoisonLock<Option<Result<(), String>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpRenewFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
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
            let mut enqueue = crate::net::runtime::command::send_command_in(
                this.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpRenew {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                }),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(String::from("network event dispatch failed")));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::command::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub fn dhcp_renew_in(runtime: NetRuntimeHandle) -> DhcpRenewFuture {
    DhcpRenewFuture::new(runtime)
}

/// 非同期DHCPリリースFuture
pub struct DhcpReleaseFuture {
    runtime: NetRuntimeHandle,
    result_slot: Arc<PoisonLock<Option<bool>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpReleaseFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
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
            let mut enqueue = crate::net::runtime::command::send_command_in(
                this.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpRelease {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                }),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(false),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::command::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub fn dhcp_release_in(runtime: NetRuntimeHandle) -> DhcpReleaseFuture {
    DhcpReleaseFuture::new(runtime)
}

/// 非同期DHCPディスカバーFuture
pub struct DhcpDiscoverFuture {
    runtime: NetRuntimeHandle,
    result_slot: Arc<PoisonLock<Option<Option<DhcpOfferInfo>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpDiscoverFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
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
            let mut enqueue = crate::net::runtime::command::send_command_in(
                this.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpDiscover {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                }),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::command::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub fn dhcp_discover_in(runtime: NetRuntimeHandle) -> DhcpDiscoverFuture {
    DhcpDiscoverFuture::new(runtime)
}

/// 非同期DHCP INFORM Future
pub struct DhcpInformFuture {
    runtime: NetRuntimeHandle,
    result_slot: Arc<PoisonLock<Option<Result<(), String>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpInformFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for DhcpInformFuture {
    type Output = Result<(), String>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            let mut enqueue = crate::net::runtime::command::send_command_in(
                this.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpInform {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                }),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(String::from("network event dispatch failed")));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::command::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub fn dhcp_inform_in(runtime: NetRuntimeHandle) -> DhcpInformFuture {
    DhcpInformFuture::new(runtime)
}

/// 非同期DHCP最終拒否IP取得Future
pub struct DhcpLastDeclinedFuture {
    runtime: NetRuntimeHandle,
    result_slot: Arc<PoisonLock<Option<Option<[u8; 4]>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpLastDeclinedFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
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
            let mut enqueue = crate::net::runtime::command::send_command_in(
                this.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpLastDeclined {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                }),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::command::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub fn dhcp_last_declined_in(runtime: NetRuntimeHandle) -> DhcpLastDeclinedFuture {
    DhcpLastDeclinedFuture::new(runtime)
}

/// 非同期DHCP最終解放IP取得Future
pub struct DhcpLastReleasedFuture {
    runtime: NetRuntimeHandle,
    result_slot: Arc<PoisonLock<Option<Option<[u8; 4]>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl DhcpLastReleasedFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
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
            let mut enqueue = crate::net::runtime::command::send_command_in(
                this.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::DhcpLastReleased {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                }),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::command::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub fn dhcp_last_released_in(runtime: NetRuntimeHandle) -> DhcpLastReleasedFuture {
    DhcpLastReleasedFuture::new(runtime)
}

#[cfg(test)]
mod tests {
    use crate::net::runtime::{create_runtime, default_runtime, reset_runtime_registry_for_tests};
    use core::future::Future;

    fn run_with_event_task_in<F>(
        runtime: crate::net::runtime::NetRuntimeHandle,
        future: F,
    ) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        crate::net::runtime::command::reset_command_system_for_tests_in(runtime);

        let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
        let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let mut executor = crate::task::TestExecutor::new();

        let result_slot_clone = result_slot.clone();
        let completed_clone = completed.clone();
        executor.spawn(crate::task::Task::new(async move {
            let output = future.await;
            let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(output);
            completed_clone.store(true, core::sync::atomic::Ordering::Release);
        }));
        executor.spawn(crate::task::Task::new(async move {
            crate::net::runtime::command_loop::runtime_command_task_in(runtime).await;
        }));

        let mut output = None;
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if completed.load(core::sync::atomic::Ordering::Acquire) {
                output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                break;
            }
        }

        crate::net::runtime::command::reset_command_system_for_tests_in(runtime);
        output.expect("dhcp api test future timed out")
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn dhcp_state_completes_with_event_task() {
        let state = {
            crate::net::runtime::command::reset_command_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output = super::dhcp_state_in(default_runtime()).await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::runtime::command_loop::runtime_command_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::runtime::command::reset_command_system_for_tests();
            output.expect("dhcp_state test timed out")
        };
        assert!(!state.v4_state.is_empty());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn list_dhcp_states_uses_runtime_local_manager() {
        reset_runtime_registry_for_tests();

        let runtime_a = default_runtime();
        let runtime_b = create_runtime();

        manager::init_network_manager_in(runtime_a);
        manager::init_network_manager_in(runtime_b);

        manager::register_interface_in(runtime_a, "dhcp-a0").expect("runtime a interface");
        let if_b0 =
            manager::register_interface_in(runtime_b, "dhcp-b0").expect("runtime b interface");

        let states = run_with_event_task_in(runtime_b, super::list_dhcp_states_in(runtime_b));

        assert_eq!(states.len(), 1);
        assert_eq!(states[0].if_id, if_b0.0);
    }
}
