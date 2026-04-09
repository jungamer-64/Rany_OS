use alloc::string::{String, ToString};
use alloc::{format, vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::net::l4::tcp::{EndpointAddr, TcpAcceptor, TcpConnection, TcpError};
use crate::net::payload::{PacketPayloadBuilder, PayloadSpan};
use crate::task::{self, Task, TimeoutResult};
use kernel_api::resource::net::PacketPayload;

static HOST_HTTP_SERVICE_STARTED: AtomicBool = AtomicBool::new(false);

/// アクティブな同時接続数を追跡
static ACTIVE_CONNECTIONS: AtomicU32 = AtomicU32::new(0);
static TOTAL_REQUESTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BYTES_RX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BYTES_TX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 同時接続数の上限
const MAX_CONCURRENT_CONNECTIONS: u32 = 16;
const HOST_HTTP_READY_POLL_MS: u64 = 100;
const HOST_HTTP_RETRY_BASE_MS: u64 = 100;
const HOST_HTTP_RETRY_MAX_MS: u64 = 5_000;
// 100ms << 6 = 6400ms となり、HOST_HTTP_RETRY_MAX_MS(5000ms) にクランプされる。
const HOST_HTTP_BACKOFF_CAP_SHIFT: u32 = 6;
const HOST_HTTP_CONNECTION_TIMEOUT_MS: u64 = 10_000;
const HOST_HTTP_READ_TRIES: usize = 20;
const HOST_HTTP_READ_TIMEOUT_MS: u64 = 100;
const HOST_HTTP_MAX_READ_WAIT_MS: u64 = HOST_HTTP_READ_TRIES as u64 * HOST_HTTP_READ_TIMEOUT_MS;
// Invariant: リクエスト読み取りの最大待機時間は接続寿命を超えないこと。
const _HOST_HTTP_READ_BUDGET_GUARD: [(); 1] =
    [(); (HOST_HTTP_MAX_READ_WAIT_MS <= HOST_HTTP_CONNECTION_TIMEOUT_MS) as usize];
// deadline 判定コストを抑えるため、読み取り試行ごとではなく N 回ごとにチェックする。
// READ_TIMEOUT_MS(100ms) * STRIDE(2) = 最長 200ms の判定遅延を許容する代わりに、
// 高頻度 current_tick() 呼び出しを抑制する。
const HOST_HTTP_READ_DEADLINE_CHECK_STRIDE: usize = 2;

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
/// VirtIO-Net割り込み処理はISR + network_event_task で非同期に
/// 駆動されるため、ここでは yield / sleep でExecutorに制御を渡すのみ。
async fn run_net_poller() {
    let mut consecutive_idle: u32 = 0;
    // TODO(net/http, issue: runtime-poller-hook):
    // runtime device poll hook が入ったらここで実ポーリングを統合する。
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        // ISR + network_event_taskが非同期にパケット処理を行うため
        // 直接ドライバポーリング helper を呼ばず yield で Executor に委ねる
        task::yield_now().await;

        let active = ACTIVE_CONNECTIONS.load(Ordering::Acquire);
        if active > 0 {
            // アクティブ接続あり: 高頻度ポーリング
            consecutive_idle = 0;
            task::sleep_ms(1).await;
        } else {
            consecutive_idle = consecutive_idle.saturating_add(1);
            // アイドル回数に応じてポーリング間隔を拡大（最大50ms）
            let sleep_ms = core::cmp::min(5 + consecutive_idle, 50) as u64;
            task::sleep_ms(sleep_ms).await;
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
                    handle_client(client).await;
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
                }));
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

fn keep_alive_for_request(request: &super::types::HttpRequestView) -> bool {
    let default_keep_alive = request.version == super::types::HttpVersion::Http1_1;

    match request.connection_directive() {
        Some(super::types::ConnectionDirective::Close) => false,
        Some(super::types::ConnectionDirective::KeepAlive) => true,
        None => default_keep_alive,
    }
}

fn build_service_unavailable_response_or_log() -> Option<PacketPayload> {
    build_json_response_or_log(
        "503 Service Unavailable",
        "{\"status\":\"service_unavailable\"}",
        false,
        "service_unavailable",
    )
}

fn build_bad_request_response_or_log() -> Option<PacketPayload> {
    build_json_response_or_log(
        "400 Bad Request",
        "{\"status\":\"bad_request\"}",
        false,
        "bad_request",
    )
}

fn build_timeout_response_or_log() -> Option<PacketPayload> {
    build_json_response_or_log(
        "408 Request Timeout",
        "{\"status\":\"timeout\"}",
        false,
        "timeout",
    )
}

const fn connection_deadline_tick(start_tick_ms: u64) -> u64 {
    // current_tick() はミリ秒単位の単調増加 tick を返す想定。
    // saturating_add を使い、理論上のオーバーフロー時も安全側（期限到達扱い）に倒す。
    start_tick_ms.saturating_add(HOST_HTTP_CONNECTION_TIMEOUT_MS)
}

const fn connection_deadline_reached_at(now_tick_ms: u64, deadline_tick_ms: u64) -> bool {
    // tick は単調増加前提のため単純比較で判定する。
    now_tick_ms >= deadline_tick_ms
}

enum RequestResponse {
    Respond {
        payload: PacketPayload,
        keep_alive: bool,
    },
    // 通常レスポンスと 503 fallback の両方の構築に失敗したため、
    // 書き込みを行わず接続を終了すべき状態。
    Close,
}

fn build_request_response_or_fallback(request: &super::types::HttpRequestView) -> RequestResponse {
    let keep_alive = keep_alive_for_request(request);

    match build_response_for_request(request, keep_alive) {
        Ok(payload) => RequestResponse::Respond {
            payload,
            keep_alive,
        },
        Err(err) => {
            log::error!("[HOST-HTTP] response build failed: {:?}", err);
            match build_service_unavailable_response_or_log() {
                Some(payload) => RequestResponse::Respond {
                    payload,
                    keep_alive: false,
                },
                None => {
                    log::error!(
                        "[HOST-HTTP] failed to build 503 fallback response; closing connection"
                    );
                    RequestResponse::Close
                }
            }
        }
    }
}

async fn handle_client(mut client: TcpConnection) {
    let mut parser = super::parser::HttpParser::new();
    let connection_started_tick_ms = crate::task::current_tick();
    let connection_deadline_tick_ms = connection_deadline_tick(connection_started_tick_ms);

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        let mut response_payload: Option<PacketPayload> = None;
        let mut keep_alive = false;

        // ループ先頭の判定は「読み取りに入る前」の早期打ち切り用。
        // これにより、既に接続寿命を超えたソケットへ追加処理を行わない。
        let now_tick_ms = crate::task::current_tick();
        if connection_deadline_reached_at(now_tick_ms, connection_deadline_tick_ms) {
            log::warn!(
                "[HOST-HTTP] connection lifetime exceeded {}ms, closing",
                HOST_HTTP_CONNECTION_TIMEOUT_MS
            );
            keep_alive = false;
            response_payload = build_timeout_response_or_log();
            if response_payload.is_none() {
                break;
            }
        }

        // まずバッファ内のデータだけでパースできるか試す（パイプライン処理対応）
        if response_payload.is_none() {
            match parser.try_parse_request() {
                Ok(Some(request)) => {
                    let response = build_request_response_or_fallback(&request);
                    match response {
                        RequestResponse::Respond {
                            payload,
                            keep_alive: next_keep_alive,
                        } => {
                            keep_alive = next_keep_alive;
                            response_payload = Some(payload);
                        }
                        RequestResponse::Close => {
                            break;
                        }
                    }
                }
                Ok(None) => {} // データ不足
                Err(err) => {
                    log::warn!("[HOST-HTTP] parse error: {:?}", err);
                    response_payload = build_bad_request_response_or_log();
                    if response_payload.is_none() {
                        break;
                    }
                }
            }
        }

        // バッファ内のデータだけでリクエストが完成しなかった場合のみ、ソケットから読み込みを行う
        if response_payload.is_none() {
            let mut read_success = false;
            let mut abort_connection = false;

            for attempt in 0..HOST_HTTP_READ_TRIES {
                // こちらは「読み取り待機中」に寿命超過を検出するための判定。
                // ループ先頭判定だけだと、recv 待ちが続く間に期限超過を見逃すため、
                // stride 間隔で再確認する。
                if attempt % HOST_HTTP_READ_DEADLINE_CHECK_STRIDE == 0 {
                    let read_now_tick_ms = crate::task::current_tick();
                    if connection_deadline_reached_at(read_now_tick_ms, connection_deadline_tick_ms)
                    {
                        log::warn!(
                            "[HOST-HTTP] request read deadline exceeded {}ms, closing",
                            HOST_HTTP_CONNECTION_TIMEOUT_MS
                        );
                        keep_alive = false;
                        response_payload = build_timeout_response_or_log();
                        if response_payload.is_none() {
                            abort_connection = true;
                        }
                        break;
                    }
                }

                match task::with_timeout(client.recv_payload(), HOST_HTTP_READ_TIMEOUT_MS).await {
                    TimeoutResult::TimedOut => {
                        task::yield_now().await;
                    }
                    TimeoutResult::Completed(None) => {
                        break;
                    }
                    TimeoutResult::Completed(Some(payload)) => {
                        let len = payload.total_len();
                        if len == 0 {
                            break;
                        }
                        read_success = true;
                        BYTES_RX.fetch_add(len as u64, Ordering::Relaxed);
                        parser.push_payload(payload);
                        match parser.try_parse_request() {
                            Ok(Some(request)) => {
                                let response = build_request_response_or_fallback(&request);
                                match response {
                                    RequestResponse::Respond {
                                        payload,
                                        keep_alive: next_keep_alive,
                                    } => {
                                        keep_alive = next_keep_alive;
                                        response_payload = Some(payload);
                                    }
                                    RequestResponse::Close => {
                                        abort_connection = true;
                                    }
                                }
                                break;
                            }
                            Ok(None) => {
                                // Continue reading
                            }
                            Err(err) => {
                                log::warn!("[HOST-HTTP] parse error: {:?}", err);
                                response_payload = build_bad_request_response_or_log();
                                if response_payload.is_none() {
                                    abort_connection = true;
                                }
                                break;
                            }
                        }
                    }
                }
            }

            if abort_connection {
                break;
            }

            if !read_success && response_payload.is_none() {
                // クライアントが正常に接続を閉じた場合
                break;
            }
        }

        let Some(response) = response_payload.or_else(|| {
            log::warn!("[HOST-HTTP] request read timeout or client closed connection early");
            build_timeout_response_or_log()
        }) else {
            break;
        };

        log::info!(
            "[HOST-HTTP] preparing response: {} bytes",
            response.total_len()
        );

        if let Err(err) = write_response(&mut client, response).await {
            log::warn!("[HOST-HTTP] send error: {}", err);
            break;
        }

        if !keep_alive {
            break;
        }
    }

    let _ = client.close();
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
}

async fn write_response(
    client: &mut TcpConnection,
    response: PacketPayload,
) -> Result<(), &'static str> {
    let total_len = response.total_len();
    client
        .send_payload(response)
        .await
        .map_err(|_| "socket write error")?;
    client.drain_tx().await.map_err(|_| "socket drain error")?;
    BYTES_TX.fetch_add(total_len as u64, Ordering::Relaxed);
    Ok(())
}

fn aggregate_port_runtime_stats() -> (usize, u64, u64, u64, u64) {
    let keys = crate::net::runtime::device::list_port_keys_in(
        crate::net::runtime::default_runtime(),
        None,
    );
    let mut rx_packets = 0u64;
    let mut tx_packets = 0u64;
    let mut tx_errors = 0u64;
    let mut rx_errors = 0u64;

    for key in &keys {
        if let Some(stats) = crate::net::runtime::device::port_stats(*key) {
            rx_packets = rx_packets.saturating_add(stats.rx_packets);
            tx_packets = tx_packets.saturating_add(stats.tx_packets);
            tx_errors = tx_errors.saturating_add(stats.tx_errors);
            rx_errors = rx_errors.saturating_add(stats.rx_errors);
        }
    }

    (keys.len(), rx_packets, tx_packets, tx_errors, rx_errors)
}

fn build_health_response(keep_alive: bool) -> Result<PacketPayload, HttpResponseBuildError> {
    let (ports, rx_packets, tx_packets, tx_errors, rx_errors) = aggregate_port_runtime_stats();
    let body = format!(
        "{{\"status\":\"ok\",\"port_runtime\":{},\"ports\":{},\"rx\":{},\"tx\":{},\"tx_errors\":{},\"rx_errors\":{}}}",
        if crate::net::runtime::device::is_initialized() {
            "true"
        } else {
            "false"
        },
        ports,
        rx_packets,
        tx_packets,
        tx_errors,
        rx_errors
    );
    build_json_response("200 OK", &body, keep_alive)
}

fn build_response_for_request(
    request: &super::types::HttpRequestView,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);

    if request.method == super::types::HttpMethod::Get {
        return build_get_response(request, keep_alive);
    }

    if request.method == super::types::HttpMethod::Post && request.uri_eq("/echo") {
        return build_echo_response(request, keep_alive);
    }

    build_json_response("404 Not Found", "{\"status\":\"not_found\"}", keep_alive)
}

fn build_get_response(
    request: &super::types::HttpRequestView,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    if request.uri_eq("/") {
        return build_index_response(keep_alive);
    }
    if request.uri_eq("/health") {
        return build_health_response(keep_alive);
    }
    if request.uri_eq("/stats") {
        return build_stats_response(keep_alive);
    }
    if request.uri_eq("/info") {
        return build_info_response(keep_alive);
    }
    if request.uri_eq("/logs") {
        return build_log_response(keep_alive);
    }
    if request.uri_eq("/executors") {
        return build_executor_stats_response(keep_alive);
    }
    if request.uri_eq("/memory") {
        return build_memory_info_response(keep_alive);
    }

    build_json_response("404 Not Found", "{\"status\":\"not_found\"}", keep_alive)
}

fn build_echo_response(
    request: &super::types::HttpRequestView,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    if let Some(body) = request.body_payload() {
        build_payload_response(
            "200 OK",
            HeaderValue::PayloadOrDefault(request.content_type()),
            body,
            keep_alive,
            &[],
        )
    } else {
        build_json_response(
            "400 Bad Request",
            "{\"status\":\"missing_body\"}",
            keep_alive,
        )
    }
}

fn build_index_response(keep_alive: bool) -> Result<PacketPayload, HttpResponseBuildError> {
    let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>ExoRust Kernel</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; }
        .stats { background: #16213e; padding: 20px; border-radius: 8px; }
        .stat { margin: 10px 0; }
        a { color: #0f4c75; }
    </style>
</head>
<body>
    <h1>🦀 ExoRust Kernel HTTP Server</h1>
    <p>Welcome to the ExoRust zero-copy HTTP server!</p>
    
    <h2>Architecture Highlights</h2>
    <ul>
        <li><strong>Single Address Space (SAS)</strong> - No TLB flushes</li>
        <li><strong>Single Privilege Level (SPL)</strong> - Syscalls are function calls</li>
        <li><strong>Zero-Copy I/O</strong> - Data flows without copying</li>
        <li><strong>Async-First Design</strong> - Cooperative multitasking</li>
    </ul>
    
    <h2>Endpoints</h2>
    <ul>
        <li><a href="/">/</a> - This page</li>
        <li><a href="/stats">/stats</a> - Server statistics</li>
        <li><a href="/info">/info</a> - System information</li>
        <li><a href="/health">/health</a> - Health check</li>
        <li><a href="/memory">/memory</a> - Detailed memory information</li>
        <li><a href="/executors">/executors</a> - Per-core scheduler statistics</li>
        <li><a href="/logs">/logs</a> - Kernel log viewer</li>
        <li><a href="/echo">/echo</a> - POST Echo API</li>
    </ul>
    
    <p><em>Running on ExoRust v0.3.0</em></p>
</body>
</html>"#;
    build_html_response("200 OK", html, keep_alive)
}

fn build_log_response(keep_alive: bool) -> Result<PacketPayload, HttpResponseBuildError> {
    let len = crate::io::log::get_log_len();
    // 16KB までのログを返却
    let max_len = core::cmp::min(len, 16 * 1024);
    let is_truncated = len > max_len;
    let mut buf = vec![0u8; max_len];
    let actual = crate::io::log::peek_global_log(&mut buf);

    // Valid UTF-8 な部分のみを返却
    let logs = match core::str::from_utf8(&buf[..actual]) {
        Ok(s) => s,
        Err(e) => {
            let valid_len = e.valid_up_to();
            core::str::from_utf8(&buf[..valid_len]).unwrap_or("[INVALID LOG DATA]")
        }
    };

    let truncation_header = if is_truncated {
        [("X-Log-Truncated", "true")]
    } else {
        [("X-Log-Truncated", "false")]
    };

    build_custom_response_with_headers(
        "200 OK",
        "text/plain; charset=utf-8",
        logs,
        keep_alive,
        &truncation_header,
    )
}

fn build_executor_stats_response(
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    let manager = crate::task::executor_manager();
    let all_stats = manager.all_stats();

    let mut json = alloc::string::String::from("[\n");
    for (i, stats) in all_stats.iter().enumerate() {
        if i > 0 {
            json.push_str(",\n");
        }
        json.push_str(&format!(
            r#"  {{
    "core_id": {},
    "tasks_executed": {},
    "tasks_stolen": {},
    "tasks_stolen_from": {},
    "queue_length": {},
    "running_count": {}
  }}"#,
            stats.core_id,
            stats.tasks_executed,
            stats.tasks_stolen,
            stats.tasks_stolen_from,
            stats.queue_length,
            stats.running_count
        ));
    }
    json.push_str("\n]");

    build_json_response("200 OK", &json, keep_alive)
}

fn build_memory_info_response(keep_alive: bool) -> Result<PacketPayload, HttpResponseBuildError> {
    let stats = crate::mm::phys::buddy_allocator::buddy_allocator_stats();
    let total_kb = (stats.total_frames as u64) * 4;
    let free_kb = (stats.free_frames as u64) * 4;
    let used_kb = total_kb.saturating_sub(free_kb);

    let (heap_used, heap_free) = crate::heap::heap_stats();

    let mut json = format!(
        r#"{{
    "physical_memory": {{
        "total_kb": {},
        "free_kb": {},
        "used_kb": {},
        "split_count": {},
        "coalesce_count": {}
    }},
    "heap": {{
        "used_bytes": {},
        "free_bytes": {}
    }},
    "order_stats": ["#,
        total_kb, free_kb, used_kb, stats.split_count, stats.coalesce_count, heap_used, heap_free
    );

    for (i, (blocks, frames)) in stats.order_stats.iter().enumerate() {
        if i > 0 {
            json.push_str(", ");
        }
        json.push_str(&format!(
            r#"{{"order": {}, "blocks": {}, "frames": {}}}"#,
            i, blocks, frames
        ));
    }
    json.push_str("]}\n");

    build_json_response("200 OK", &json, keep_alive)
}

fn build_stats_response(keep_alive: bool) -> Result<PacketPayload, HttpResponseBuildError> {
    let requests = TOTAL_REQUESTS.load(Ordering::Relaxed);
    let bytes_rx = BYTES_RX.load(Ordering::Relaxed);
    let bytes_tx = BYTES_TX.load(Ordering::Relaxed);
    let connections = ACTIVE_CONNECTIONS.load(Ordering::Acquire);

    let (heap_used, heap_free) = crate::heap::heap_stats();
    let timer_ticks = crate::interrupts::get_timer_ticks();

    let json = format!(
        r#"{{
    "server": "ExoRust HTTP",
    "version": "0.3.0",
    "stats": {{
        "requests": {},
        "bytes_received": {},
        "bytes_sent": {},
        "active_connections": {}
    }},
    "system": {{
        "heap_used": {},
        "heap_free": {},
        "timer_ticks": {}
    }}
}}"#,
        requests, bytes_rx, bytes_tx, connections, heap_used, heap_free, timer_ticks
    );

    build_json_response("200 OK", &json, keep_alive)
}

fn build_info_response(keep_alive: bool) -> Result<PacketPayload, HttpResponseBuildError> {
    let domain_stats = crate::domain::get_domain_stats();
    let sas_stats = crate::sas::stats();
    let spectre = crate::security::spectre::status_summary();

    let json = format!(
        r#"{{
    "kernel": {{
        "name": "ExoRust",
        "version": "0.3.0",
        "architecture": "x86_64",
        "design": "Single Address Space + Single Privilege Level"
    }},
    "domains": {{
        "total": {},
        "running": {},
        "stopped": {}
    }},
    "sas": {{
        "regions": {},
        "objects": {},
        "domains": {}
    }},
    "security": {{
        "ibrs": {},
        "stibp": {},
        "ssbd": {},
        "retpoline": {}
    }}
}}"#,
        domain_stats.total,
        domain_stats.running,
        domain_stats.stopped,
        sas_stats.total_regions,
        sas_stats.total_objects,
        sas_stats.domains,
        spectre.ibrs_enabled,
        spectre.stibp_enabled,
        spectre.ssbd_enabled,
        spectre.using_retpoline
    );

    build_json_response("200 OK", &json, keep_alive)
}

fn build_json_response(
    status: &str,
    body: &str,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    build_custom_response(status, "application/json", body, keep_alive)
}

fn build_html_response(
    status: &str,
    body: &str,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    build_custom_response(status, "text/html; charset=utf-8", body, keep_alive)
}

enum HeaderValue {
    Text(String),
    PayloadOrDefault(Option<PayloadSpan>),
}

#[derive(Debug, Clone, Copy)]
enum HttpResponseBuildError {
    AllocationFailed,
    InvalidPayloadSpan,
}

fn push_builder_str(
    builder: &mut PacketPayloadBuilder,
    value: &str,
) -> Result<(), HttpResponseBuildError> {
    builder
        .push_str(value)
        .ok_or(HttpResponseBuildError::AllocationFailed)
}

fn build_json_response_or_log(
    status: &str,
    body: &str,
    keep_alive: bool,
    context: &str,
) -> Option<PacketPayload> {
    match build_json_response(status, body, keep_alive) {
        Ok(payload) => Some(payload),
        Err(err) => {
            log::error!(
                "[HOST-HTTP] failed to build {} fallback response: {:?}",
                context,
                err
            );
            None
        }
    }
}

fn body_payload_from_bytes(body: &[u8]) -> Result<PacketPayload, HttpResponseBuildError> {
    let mut builder = PacketPayloadBuilder::new();
    builder
        .push_bytes(body)
        .ok_or(HttpResponseBuildError::AllocationFailed)?;
    Ok(builder.build())
}

fn write_content_type_header(
    builder: &mut PacketPayloadBuilder,
    content_type: HeaderValue,
) -> Result<(), HttpResponseBuildError> {
    push_builder_str(builder, "Content-Type: ")?;
    match content_type {
        HeaderValue::Text(value) => {
            push_builder_str(builder, &value)?;
        }
        HeaderValue::PayloadOrDefault(Some(value)) => {
            let payload = value
                .to_payload()
                .ok_or(HttpResponseBuildError::InvalidPayloadSpan)?;
            builder.push_payload(payload);
        }
        HeaderValue::PayloadOrDefault(None) => {
            push_builder_str(builder, "application/octet-stream")?;
        }
    }
    Ok(())
}

fn write_additional_headers(
    builder: &mut PacketPayloadBuilder,
    additional_headers: &[(&str, &str)],
) -> Result<(), HttpResponseBuildError> {
    for (name, value) in additional_headers {
        push_builder_str(builder, name)?;
        push_builder_str(builder, ": ")?;
        push_builder_str(builder, value)?;
        push_builder_str(builder, "\r\n")?;
    }
    Ok(())
}

fn build_payload_response(
    status: &str,
    content_type: HeaderValue,
    body: PacketPayload,
    keep_alive: bool,
    additional_headers: &[(&str, &str)],
) -> Result<PacketPayload, HttpResponseBuildError> {
    let connection_header = if keep_alive { "keep-alive" } else { "close" };
    let mut builder = PacketPayloadBuilder::new();
    push_builder_str(&mut builder, "HTTP/1.1 ")?;
    push_builder_str(&mut builder, status)?;
    push_builder_str(&mut builder, "\r\n")?;
    write_content_type_header(&mut builder, content_type)?;
    push_builder_str(&mut builder, "\r\n")?;
    write_additional_headers(&mut builder, additional_headers)?;
    push_builder_str(&mut builder, "Connection: ")?;
    push_builder_str(&mut builder, connection_header)?;
    push_builder_str(&mut builder, "\r\n")?;
    push_builder_str(&mut builder, "Content-Length: ")?;
    push_builder_str(&mut builder, &format!("{}", body.total_len()))?;
    push_builder_str(&mut builder, "\r\n\r\n")?;
    builder.push_payload(body);
    Ok(builder.build())
}

fn build_custom_response(
    status: &str,
    content_type: &str,
    body: &str,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    build_custom_response_with_headers(status, content_type, body, keep_alive, &[])
}

fn build_custom_response_with_headers(
    status: &str,
    content_type: &str,
    body: &str,
    keep_alive: bool,
    additional_headers: &[(&str, &str)],
) -> Result<PacketPayload, HttpResponseBuildError> {
    build_payload_response(
        status,
        HeaderValue::Text(content_type.to_string()),
        body_payload_from_bytes(body.as_bytes())?,
        keep_alive,
        additional_headers,
    )
}
