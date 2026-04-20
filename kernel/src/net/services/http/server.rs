// ============================================================================
// kernel/src/net/services/http/server.rs - サービス / HTTP / サーバ
// ============================================================================

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll};

use crate::net::l4::tcp::{EndpointAddr, TcpAcceptor, TcpError};
use crate::sync::atomic_waker::AtomicWaker;
use crate::task::{self, Task, TimeoutResult};
use kernel_api::service::netdev::NetDriverEvent;

mod connection;
mod index_html;
mod router;

static HOST_HTTP_SERVICE_STARTED: AtomicBool = AtomicBool::new(false);
static HTTP_POLLER_SIGNAL_WAKER: AtomicWaker = AtomicWaker::new();
static HTTP_POLLER_SIGNAL_SEQ: AtomicU64 = AtomicU64::new(1);

/// アクティブな同時接続数を追跡
pub(super) static ACTIVE_CONNECTIONS: AtomicU32 = AtomicU32::new(0);
pub(super) static TOTAL_REQUESTS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub(super) static BYTES_RX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub(super) static BYTES_TX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 同時接続数の上限
const MAX_CONCURRENT_CONNECTIONS: u32 = 16;
const HOST_HTTP_READY_POLL_MS: u64 = 100;
const HOST_HTTP_RETRY_BASE_MS: u64 = 100;
const HOST_HTTP_RETRY_MAX_MS: u64 = 5_000;
// 100ms << 6 = 6400ms となり、HOST_HTTP_RETRY_MAX_MS(5000ms) にクランプされる。
const HOST_HTTP_BACKOFF_CAP_SHIFT: u32 = 6;
const HOST_HTTP_IDLE_WAIT_BASE_MS: u32 = 5;
const HOST_HTTP_IDLE_WAIT_MAX_MS: u32 = 50;
pub(super) const HOST_HTTP_CONNECTION_TIMEOUT_MS: u64 = 10_000;
pub(super) const HOST_HTTP_READ_TRIES: usize = 20;
pub(super) const HOST_HTTP_READ_TIMEOUT_MS: u64 = 100;
const HOST_HTTP_MAX_READ_WAIT_MS: u64 = HOST_HTTP_READ_TRIES as u64 * HOST_HTTP_READ_TIMEOUT_MS;
// Invariant: リクエスト読み取りの最大待機時間は接続寿命を超えないこと。
const _HOST_HTTP_READ_BUDGET_GUARD: [(); 1] =
    [(); (HOST_HTTP_MAX_READ_WAIT_MS <= HOST_HTTP_CONNECTION_TIMEOUT_MS) as usize];
// deadline 判定コストを抑えるため、読み取り試行ごとではなく N 回ごとにチェックする。
// READ_TIMEOUT_MS(100ms) * STRIDE(2) = 最長 200ms の判定遅延を許容する代わりに、
// 高頻度 current_tick() 呼び出しを抑制する。
pub(super) const HOST_HTTP_READ_DEADLINE_CHECK_STRIDE: usize = 2;

struct HttpPollerSignalFuture {
    observed_seq: u64,
}

impl Future for HttpPollerSignalFuture {
    type Output = u64;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let current = HTTP_POLLER_SIGNAL_SEQ.load(Ordering::Acquire);
        if current != self.observed_seq {
            return Poll::Ready(current);
        }

        HTTP_POLLER_SIGNAL_WAKER.register(cx.waker());

        let current = HTTP_POLLER_SIGNAL_SEQ.load(Ordering::Acquire);
        if current != self.observed_seq {
            Poll::Ready(current)
        } else {
            Poll::Pending
        }
    }
}

fn current_http_poller_signal_seq() -> u64 {
    HTTP_POLLER_SIGNAL_SEQ.load(Ordering::Acquire)
}

fn notify_http_poller_signal() {
    HTTP_POLLER_SIGNAL_SEQ.fetch_add(1, Ordering::AcqRel);
    HTTP_POLLER_SIGNAL_WAKER.wake();
}

const fn host_http_idle_wait_ms(consecutive_idle: u32) -> u64 {
    let expanded = HOST_HTTP_IDLE_WAIT_BASE_MS.saturating_add(consecutive_idle);
    if expanded > HOST_HTTP_IDLE_WAIT_MAX_MS {
        HOST_HTTP_IDLE_WAIT_MAX_MS as u64
    } else {
        expanded as u64
    }
}

fn enqueue_runtime_poll_events() -> usize {
    let runtime = crate::net::runtime::default_runtime();
    let mut queued = 0usize;

    for port_id in crate::net::runtime::device::list_port_ids_in(runtime) {
        if crate::net::runtime::device::enqueue_event(port_id, NetDriverEvent::Poll) {
            queued = queued.saturating_add(1);
        }
    }

    queued
}

async fn wait_http_poller_signal_or_timeout(observed_seq: &mut u64, timeout_ms: u64) -> bool {
    match task::with_timeout(
        HttpPollerSignalFuture {
            observed_seq: *observed_seq,
        },
        timeout_ms,
    )
    .await
    {
        TimeoutResult::Completed(next_seq) => {
            *observed_seq = next_seq;
            true
        }
        TimeoutResult::TimedOut => false,
    }
}

#[derive(Debug, Clone, Copy)]
enum ServiceRestartCause {
    Bind(TcpError),
    NextConnection(TcpError),
}

pub fn start_once() {
    if HOST_HTTP_SERVICE_STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        log::info!("[HOST-HTTP] service already started, skipping");
        return;
    }

    // spawn_on_cpu_with_priority は TaskId を常に返す設計で、失敗パスを公開しない。
    // そのため started フラグは spawn 前に確定し、二重起動を防ぐ。
    log::info!("[HOST-HTTP] scheduling host HTTP service on 0.0.0.0:80");
    crate::task::spawn_on_cpu_with_priority(0, crate::task::Priority::Normal, async {
        log::info!(
            "[HOST-HTTP] net poller running on CPU {}",
            crate::cpu::try_current_id().unwrap_or(0)
        );
        run_net_poller().await;
    });
    crate::task::spawn_on_cpu_with_priority(0, crate::task::Priority::Normal, async {
        log::info!(
            "[HOST-HTTP] supervisor running on CPU {}",
            crate::cpu::try_current_id().unwrap_or(0)
        );
        run_service_supervisor().await;
    });
}

/// 【設計書準拠】適応的ポーリングをHTTPサービスに適用
///
/// 低負荷時は10msスリープで省電力、高負荷時は1msに短縮して
/// レスポンスレイテンシを低減する。
///
/// VirtIO-Net割り込み処理はISR + runtime_command_task で非同期に
/// 駆動されるため、ここでは yield / sleep でExecutorに制御を渡すのみ。
async fn run_net_poller() {
    let mut consecutive_idle: u32 = 0;
    let mut observed_signal_seq = current_http_poller_signal_seq();
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        // ISR + runtime_command_task が非同期にパケット処理を行うため、
        // ここでは Executor へ制御を返しつつ、HTTP接続イベント通知を待機する。
        // Poll event は non-ISR の文脈で device event queue に投入する。
        task::yield_now().await;

        let active = ACTIVE_CONNECTIONS.load(Ordering::Acquire);
        let wait_ms = if active > 0 {
            consecutive_idle = 0;
            1
        } else {
            consecutive_idle = consecutive_idle.saturating_add(1);
            // アイドル回数に応じて待機間隔を拡大（最大50ms）。
            host_http_idle_wait_ms(consecutive_idle)
        };

        if wait_http_poller_signal_or_timeout(&mut observed_signal_seq, wait_ms).await {
            consecutive_idle = 0;
        }

        // active 接続時は高頻度で、idle 時も最大待機に達したサイクルで Poll を投入する。
        // Queue が埋まっている場合 enqueue_event は false を返すため、ここでは best-effort とする。
        if active > 0 || wait_ms >= HOST_HTTP_IDLE_WAIT_MAX_MS as u64 {
            let _ = enqueue_runtime_poll_events();
        }
    }
}

/// 【async-first 設計】接続を並行処理するHTTPサービスメインループ
///
/// 各接続をspawn_globalで独立タスクとして起動し、
/// acceptループがブロックされないようにする。
const fn http_supervisor_backoff_ms(consecutive_failures: u32) -> u64 {
    let shift = if consecutive_failures > HOST_HTTP_BACKOFF_CAP_SHIFT {
        HOST_HTTP_BACKOFF_CAP_SHIFT
    } else {
        consecutive_failures
    };
    let delay = HOST_HTTP_RETRY_BASE_MS << shift;
    if delay > HOST_HTTP_RETRY_MAX_MS {
        HOST_HTTP_RETRY_MAX_MS
    } else {
        delay
    }
}

fn should_log_http_restart_warning(consecutive_failures: u32) -> bool {
    consecutive_failures < 4 || consecutive_failures.is_power_of_two()
}

fn http_config_usable(config: &crate::net::api::config::InterfaceConfigSnapshot) -> bool {
    config.ip != [0, 0, 0, 0] && config.mac != [0, 0, 0, 0, 0, 0]
}

fn http_network_ready() -> bool {
    if !crate::net::runtime::bridge::get_stack_glue_stats().initialized {
        return false;
    }

    crate::net::api::config::primary_interface_config_from_runtime_in(
        crate::net::runtime::default_runtime(),
    )
    .as_ref()
    .is_some_and(http_config_usable)
}

async fn wait_for_http_network_ready() {
    let mut logged_wait = false;
    loop {
        if http_network_ready() {
            return;
        }

        if !logged_wait {
            log::info!("[HOST-HTTP] waiting for usable network configuration before binding");
            logged_wait = true;
        }

        task::sleep_ms(HOST_HTTP_READY_POLL_MS).await;
    }
}

fn log_http_restart(cause: ServiceRestartCause, consecutive_failures: u32, backoff_ms: u64) {
    if !should_log_http_restart_warning(consecutive_failures) {
        return;
    }

    match cause {
        ServiceRestartCause::Bind(err) => {
            log::warn!(
                "[HOST-HTTP] bind failed on port 80: {:?} (restart #{}, backoff={}ms)",
                err,
                consecutive_failures + 1,
                backoff_ms
            );
        }
        ServiceRestartCause::NextConnection(err) => {
            log::warn!(
                "[HOST-HTTP] next_connection error: {:?} (rebind #{}, backoff={}ms)",
                err,
                consecutive_failures + 1,
                backoff_ms
            );
        }
    }
}

async fn bind_http_acceptor() -> Result<TcpAcceptor, TcpError> {
    TcpAcceptor::bind_in(
        crate::net::runtime::default_runtime(),
        EndpointAddr::new([0, 0, 0, 0], 80),
    )
    .await
}

async fn run_service_supervisor() {
    let mut consecutive_failures = 0u32;

    loop {
        wait_for_http_network_ready().await;

        let acceptor = match bind_http_acceptor().await {
            Ok(acceptor) => {
                if consecutive_failures > 0 {
                    log::info!(
                        "[HOST-HTTP] acceptor recovered after {} restart attempt(s)",
                        consecutive_failures
                    );
                }
                consecutive_failures = 0;
                log::info!("[HOST-HTTP] accepting connections on 0.0.0.0:80");
                acceptor
            }
            Err(err) => {
                let backoff_ms = http_supervisor_backoff_ms(consecutive_failures);
                log_http_restart(
                    ServiceRestartCause::Bind(err),
                    consecutive_failures,
                    backoff_ms,
                );
                consecutive_failures = consecutive_failures.saturating_add(1);
                task::sleep_ms(backoff_ms).await;
                continue;
            }
        };

        if let Err(err) = run_service(acceptor).await {
            let backoff_ms = http_supervisor_backoff_ms(consecutive_failures);
            log_http_restart(
                ServiceRestartCause::NextConnection(err),
                consecutive_failures,
                backoff_ms,
            );
            consecutive_failures = consecutive_failures.saturating_add(1);
            task::sleep_ms(backoff_ms).await;
        }
    }
}

async fn run_service(acceptor: TcpAcceptor) -> Result<(), TcpError> {
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        match task::with_timeout(acceptor.next_connection(), 500).await {
            TimeoutResult::TimedOut => {
                task::yield_now().await;
            }
            TimeoutResult::Completed(Ok((client, peer))) => {
                let Some(active_after) = try_acquire_connection_slot() else {
                    log::warn!(
                        "[HOST-HTTP] connection limit reached ({}), rejecting {:?}",
                        ACTIVE_CONNECTIONS.load(Ordering::Acquire),
                        peer
                    );
                    // 接続を閉じて次を受け付ける
                    let mut rejected = client;
                    let _ = rejected.close();
                    continue;
                };

                log::info!(
                    "[HOST-HTTP] accepted connection from {:?} (active: {})",
                    peer,
                    active_after
                );

                // 【設計書準拠】各接続を独立タスクとしてspawn（並行処理）
                crate::task::spawn_task(Task::new(async move {
                    connection::handle_client(client).await;
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
                    notify_http_poller_signal();
                }));

                notify_http_poller_signal();
            }
            TimeoutResult::Completed(Err(err)) => {
                return Err(err);
            }
        }
    }
}

fn try_acquire_connection_slot() -> Option<u32> {
    loop {
        let current = ACTIVE_CONNECTIONS.load(Ordering::Acquire);
        if current >= MAX_CONCURRENT_CONNECTIONS {
            return None;
        }

        let next = current.checked_add(1)?;
        if ACTIVE_CONNECTIONS
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(next);
        }

        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::{http_config_usable, http_supervisor_backoff_ms, should_log_http_restart_warning};

    #[test]
    fn http_backoff_is_exponential_and_capped() {
        assert_eq!(http_supervisor_backoff_ms(0), 100);
        assert_eq!(http_supervisor_backoff_ms(1), 200);
        assert_eq!(http_supervisor_backoff_ms(3), 800);
        assert_eq!(http_supervisor_backoff_ms(5), 3_200);
        assert_eq!(http_supervisor_backoff_ms(6), 5_000);
        assert_eq!(http_supervisor_backoff_ms(7), 5_000);
        assert_eq!(http_supervisor_backoff_ms(8), 5_000);
    }

    #[test]
    fn http_restart_logging_is_rate_limited() {
        assert!(should_log_http_restart_warning(0));
        assert!(should_log_http_restart_warning(1));
        assert!(should_log_http_restart_warning(3));
        assert!(!should_log_http_restart_warning(5));
        assert!(should_log_http_restart_warning(8));
    }

    #[test]
    fn http_config_requires_nonzero_ip_and_mac() {
        let unusable = crate::net::api::config::InterfaceConfigSnapshot {
            if_id: 0,
            name: alloc::string::String::from("eth0"),
            admin_up: true,
            virtio_index: Some(0),
            ip: [0, 0, 0, 0],
            netmask: [0, 0, 0, 0],
            gateway: [0, 0, 0, 0],
            mac: [0, 0, 0, 0, 0, 0],
        };
        let usable = crate::net::api::config::InterfaceConfigSnapshot {
            if_id: 0,
            name: alloc::string::String::from("eth0"),
            admin_up: true,
            virtio_index: Some(0),
            ip: [192, 168, 1, 10],
            netmask: [255, 255, 255, 0],
            gateway: [192, 168, 1, 1],
            mac: [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01],
        };

        assert!(!http_config_usable(&unusable));
        assert!(http_config_usable(&usable));
    }

    #[test]
    fn http_poller_signal_sequence_advances_on_notify() {
        let before = current_http_poller_signal_seq();
        notify_http_poller_signal();
        let after = current_http_poller_signal_seq();
        assert!(after > before);
    }

    #[test]
    fn http_idle_wait_scales_and_is_capped() {
        assert_eq!(host_http_idle_wait_ms(0), 5);
        assert_eq!(host_http_idle_wait_ms(1), 6);
        assert_eq!(host_http_idle_wait_ms(10), 15);
        assert_eq!(host_http_idle_wait_ms(45), 50);
        assert_eq!(host_http_idle_wait_ms(10_000), 50);
    }
}
