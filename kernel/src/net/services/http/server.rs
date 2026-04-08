use alloc::{format, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::net::l4::tcp::{EndpointAddr, TcpError, TcpListener, TcpStream};
use crate::task::{self, Task, TimeoutResult};

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

#[derive(Debug, Clone, Copy)]
enum ServiceRestartCause {
    Listen(TcpError),
    Accept(TcpError),
}

pub fn start_once() {
    if HOST_HTTP_SERVICE_STARTED.swap(true, Ordering::AcqRel) {
        log::info!("[HOST-HTTP] service already started, skipping");
        return;
    }

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
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        // ISR + network_event_taskが非同期にパケット処理を行うため
        // 直接ドライバポーリング helper を呼ばず yield で Executor に委ねる
        task::yield_now().await;

        let active = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
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
    let shift = if consecutive_failures > 5 {
        5
    } else {
        consecutive_failures
    };
    let delay = match HOST_HTTP_RETRY_BASE_MS.checked_shl(shift) {
        Some(delay) => delay,
        None => HOST_HTTP_RETRY_MAX_MS,
    };
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

    crate::net::runtime::bridge::primary_interface_config()
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
        ServiceRestartCause::Listen(err) => {
            log::warn!(
                "[HOST-HTTP] listen_on failed on port 80: {:?} (restart #{}, backoff={}ms)",
                err,
                consecutive_failures + 1,
                backoff_ms
            );
        }
        ServiceRestartCause::Accept(err) => {
            log::warn!(
                "[HOST-HTTP] accept error: {:?} (rebind #{}, backoff={}ms)",
                err,
                consecutive_failures + 1,
                backoff_ms
            );
        }
    }
}

async fn bind_http_listener() -> Result<TcpListener, TcpError> {
    TcpListener::listen_on(EndpointAddr::new([0, 0, 0, 0], 80)).await
}

async fn run_service_supervisor() {
    let mut consecutive_failures = 0u32;

    loop {
        wait_for_http_network_ready().await;

        let listener = match bind_http_listener().await {
            Ok(listener) => {
                if consecutive_failures > 0 {
                    log::info!(
                        "[HOST-HTTP] listener recovered after {} restart attempt(s)",
                        consecutive_failures
                    );
                }
                consecutive_failures = 0;
                log::info!("[HOST-HTTP] listening on 0.0.0.0:80");
                listener
            }
            Err(err) => {
                let backoff_ms = http_supervisor_backoff_ms(consecutive_failures);
                log_http_restart(
                    ServiceRestartCause::Listen(err),
                    consecutive_failures,
                    backoff_ms,
                );
                consecutive_failures = consecutive_failures.saturating_add(1);
                task::sleep_ms(backoff_ms).await;
                continue;
            }
        };

        if let Err(err) = run_service(listener).await {
            let backoff_ms = http_supervisor_backoff_ms(consecutive_failures);
            log_http_restart(
                ServiceRestartCause::Accept(err),
                consecutive_failures,
                backoff_ms,
            );
            consecutive_failures = consecutive_failures.saturating_add(1);
            task::sleep_ms(backoff_ms).await;
        }
    }
}

async fn run_service(listener: TcpListener) -> Result<(), TcpError> {
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        match task::with_timeout(listener.next_connection(), 500).await {
            TimeoutResult::TimedOut => {
                task::yield_now().await;
            }
            TimeoutResult::Completed(Ok((client, peer))) => {
                let active = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
                if active >= MAX_CONCURRENT_CONNECTIONS {
                    log::warn!(
                        "[HOST-HTTP] connection limit reached ({}), rejecting {:?}",
                        active,
                        peer
                    );
                    // 接続を閉じて次を受け付ける
                    let mut rejected = client;
                    let _ = rejected.shutdown().await;
                    continue;
                }

                log::info!(
                    "[HOST-HTTP] accepted connection from {:?} (active: {})",
                    peer,
                    active + 1
                );

                // 【設計書準拠】各接続を独立タスクとしてspawn（並行処理）
                crate::task::spawn_task(Task::new(async move {
                    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                    handle_client(client).await;
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                }));
            }
            TimeoutResult::Completed(Err(err)) => {
                return Err(err);
            }
        }
    }
}

async fn handle_client(mut client: TcpStream) {
    let mut parser = super::parser::HttpParser::new();

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        let mut response_bytes = None;
        let mut keep_alive = false;

        // まずバッファ内のデータだけでパースできるか試す（パイプライン処理対応）
        match parser.try_parse_request() {
            Ok(Some(request)) => {
                let req_keep_alive = request
                    .get_header("Connection")
                    .map(|v| v.eq_ignore_ascii_case("keep-alive"))
                    .unwrap_or(false);
                let default_keep_alive = request.version == super::types::HttpVersion::Http1_1;
                let conn_close = request
                    .get_header("Connection")
                    .map(|v| v.eq_ignore_ascii_case("close"))
                    .unwrap_or(false);
                keep_alive = (req_keep_alive || default_keep_alive) && !conn_close;

                response_bytes = Some(build_response_for_request(&request, keep_alive));
            }
            Ok(None) => {} // データ不足
            Err(err) => {
                log::warn!("[HOST-HTTP] parse error: {:?}", err);
                response_bytes = Some(build_json_response(
                    "400 Bad Request",
                    "{\"status\":\"bad_request\"}",
                    false,
                ));
            }
        }

        // バッファ内のデータだけでリクエストが完成しなかった場合のみ、ソケットから読み込みを行う
        if response_bytes.is_none() {
            const READ_TRIES: usize = 20;
            const READ_TIMEOUT_MS: u64 = 100;

            let mut buffer = [0u8; 2048];
            let mut read_success = false;

            for _ in 0..READ_TRIES {
                match task::with_timeout(client.read(&mut buffer), READ_TIMEOUT_MS).await {
                    TimeoutResult::TimedOut => {
                        task::yield_now().await;
                    }
                    TimeoutResult::Completed(Err(_)) => {
                        log::warn!("[HOST-HTTP] read error");
                        response_bytes = Some(build_json_response(
                            "500 Internal Server Error",
                            "{\"status\":\"error\"}",
                            false,
                        ));
                        break;
                    }
                    TimeoutResult::Completed(Ok(0)) => {
                        break;
                    }
                    TimeoutResult::Completed(Ok(len)) => {
                        read_success = true;
                        BYTES_RX.fetch_add(len as u64, Ordering::Relaxed);
                        parser.push_data(&buffer[..len]);
                        match parser.try_parse_request() {
                            Ok(Some(request)) => {
                                let req_keep_alive = request
                                    .get_header("Connection")
                                    .map(|v| v.eq_ignore_ascii_case("keep-alive"))
                                    .unwrap_or(false);
                                let default_keep_alive =
                                    request.version == super::types::HttpVersion::Http1_1;
                                let conn_close = request
                                    .get_header("Connection")
                                    .map(|v| v.eq_ignore_ascii_case("close"))
                                    .unwrap_or(false);
                                keep_alive = (req_keep_alive || default_keep_alive) && !conn_close;

                                response_bytes =
                                    Some(build_response_for_request(&request, keep_alive));
                                break;
                            }
                            Ok(None) => {
                                // Continue reading
                            }
                            Err(err) => {
                                log::warn!("[HOST-HTTP] parse error: {:?}", err);
                                response_bytes = Some(build_json_response(
                                    "400 Bad Request",
                                    "{\"status\":\"bad_request\"}",
                                    false,
                                ));
                                break;
                            }
                        }
                    }
                }
            }

            if !read_success && response_bytes.is_none() {
                // クライアントが正常に接続を閉じた場合
                break;
            }
        }

        let response = response_bytes.unwrap_or_else(|| {
            log::warn!("[HOST-HTTP] request read timeout or client closed connection early");
            build_json_response("408 Request Timeout", "{\"status\":\"timeout\"}", false)
        });

        log::info!("[HOST-HTTP] preparing response: {} bytes", response.len());

        if let Err(err) = write_response(&mut client, response.as_slice()).await {
            log::warn!("[HOST-HTTP] send error: {}", err);
            break;
        }

        if !keep_alive {
            break;
        }
    }

    let _ = client.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::{http_config_usable, http_supervisor_backoff_ms, should_log_http_restart_warning};

    #[test]
    fn http_backoff_is_exponential_and_capped() {
        assert_eq!(http_supervisor_backoff_ms(0), 100);
        assert_eq!(http_supervisor_backoff_ms(1), 200);
        assert_eq!(http_supervisor_backoff_ms(3), 800);
        assert_eq!(http_supervisor_backoff_ms(8), 3_200);
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

async fn write_response(client: &mut TcpStream, response: &[u8]) -> Result<(), &'static str> {
    const IO_TIMEOUT_MS: u64 = 200;
    const MAX_TIMEOUT_RETRIES: usize = 25;

    let mut sent = 0usize;
    let mut write_timeouts = 0usize;
    while sent < response.len() {
        log::info!(
            "[HOST-HTTP] write attempt: offset={} remaining={}",
            sent,
            response.len().saturating_sub(sent)
        );
        match task::with_timeout(client.write(&response[sent..]), IO_TIMEOUT_MS).await {
            TimeoutResult::TimedOut => {
                write_timeouts = write_timeouts.saturating_add(1);
                if write_timeouts >= MAX_TIMEOUT_RETRIES {
                    return Err("socket write timeout");
                }
                task::yield_now().await;
                continue;
            }
            TimeoutResult::Completed(Err(_)) => return Err("socket write error"),
            TimeoutResult::Completed(Ok(0)) => return Err("socket closed while sending"),
            TimeoutResult::Completed(Ok(written)) => {
                write_timeouts = 0;
                log::info!("[HOST-HTTP] wrote {} bytes", written);
                sent += written;
                BYTES_TX.fetch_add(written as u64, Ordering::Relaxed);
                // yieldでExecutorに制御を渡し、ISR駆動のVirtIO処理を促進
                task::yield_now().await;
            }
        }
    }

    log::info!("[HOST-HTTP] flushing response");
    let mut flush_timeouts = 0usize;
    loop {
        match task::with_timeout(client.flush(), IO_TIMEOUT_MS).await {
            TimeoutResult::TimedOut => {
                flush_timeouts = flush_timeouts.saturating_add(1);
                if flush_timeouts >= MAX_TIMEOUT_RETRIES {
                    return Err("socket flush timeout");
                }
                task::yield_now().await;
            }
            TimeoutResult::Completed(Err(_)) => return Err("socket flush error"),
            TimeoutResult::Completed(Ok(())) => {
                log::info!("[HOST-HTTP] flush complete");
                return Ok(());
            }
        }
    }
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

fn build_health_response(keep_alive: bool) -> Vec<u8> {
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

fn build_response_for_request(request: &super::types::HttpRequest, keep_alive: bool) -> Vec<u8> {
    TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);

    if request.method == super::types::HttpMethod::Get {
        match request.uri.as_str() {
            "/" => return build_index_response(keep_alive),
            "/health" => return build_health_response(keep_alive),
            "/stats" => return build_stats_response(keep_alive),
            "/info" => return build_info_response(keep_alive),
            "/logs" => return build_log_response(keep_alive),
            "/executors" => return build_executor_stats_response(keep_alive),
            "/memory" => return build_memory_info_response(keep_alive),
            _ => {}
        }
    } else if request.method == super::types::HttpMethod::Post {
        if request.uri.as_str() == "/echo" {
            return build_echo_response(request, keep_alive);
        }
    }

    build_json_response("404 Not Found", "{\"status\":\"not_found\"}", keep_alive)
}

fn build_echo_response(request: &super::types::HttpRequest, keep_alive: bool) -> Vec<u8> {
    if let Some(body) = &request.body {
        let content_type = request
            .get_header("Content-Type")
            .unwrap_or("application/json");
        let body_str = core::str::from_utf8(body).unwrap_or("{\"error\": \"invalid utf-8\"}");
        build_custom_response("200 OK", content_type, body_str, keep_alive)
    } else {
        build_json_response(
            "400 Bad Request",
            "{\"status\":\"missing_body\"}",
            keep_alive,
        )
    }
}

fn build_index_response(keep_alive: bool) -> Vec<u8> {
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

fn build_log_response(keep_alive: bool) -> Vec<u8> {
    let len = crate::io::log::get_log_len();
    // 16KB までのログを返却
    let max_len = core::cmp::min(len, 16 * 1024);
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

    build_custom_response("200 OK", "text/plain; charset=utf-8", logs, keep_alive)
}

fn build_executor_stats_response(keep_alive: bool) -> Vec<u8> {
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

fn build_memory_info_response(keep_alive: bool) -> Vec<u8> {
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

fn build_stats_response(keep_alive: bool) -> Vec<u8> {
    let requests = TOTAL_REQUESTS.load(Ordering::Relaxed);
    let bytes_rx = BYTES_RX.load(Ordering::Relaxed);
    let bytes_tx = BYTES_TX.load(Ordering::Relaxed);
    let connections = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);

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

fn build_info_response(keep_alive: bool) -> Vec<u8> {
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

fn build_json_response(status: &str, body: &str, keep_alive: bool) -> Vec<u8> {
    build_custom_response(status, "application/json", body, keep_alive)
}

fn build_html_response(status: &str, body: &str, keep_alive: bool) -> Vec<u8> {
    build_custom_response(status, "text/html; charset=utf-8", body, keep_alive)
}

fn build_custom_response(
    status: &str,
    content_type: &str,
    body: &str,
    keep_alive: bool,
) -> Vec<u8> {
    let connection_header = if keep_alive { "keep-alive" } else { "close" };
    let mut parts = status.splitn(2, ' ');
    let status_code: u16 = parts.next().unwrap_or("200").parse().unwrap_or(200);
    let reason_phrase = parts.next().unwrap_or("");

    super::types::HttpResponse::new(status_code, reason_phrase)
        .header("Content-Type", content_type)
        .header("Connection", connection_header)
        .body(body.as_bytes().to_vec())
        .to_bytes()
}
