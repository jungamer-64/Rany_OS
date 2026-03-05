use alloc::{format, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::net::l4::tcp::{EndpointAddr, TcpListener, TcpStream};
use crate::task::{self, Task, TimeoutResult};

static HOST_HTTP_SERVICE_STARTED: AtomicBool = AtomicBool::new(false);

/// アクティブな同時接続数を追跡
static ACTIVE_CONNECTIONS: AtomicU32 = AtomicU32::new(0);
static TOTAL_REQUESTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BYTES_RX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BYTES_TX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 同時接続数の上限
const MAX_CONCURRENT_CONNECTIONS: u32 = 16;

pub fn start_once(executor: &mut task::Executor) {
    if HOST_HTTP_SERVICE_STARTED.swap(true, Ordering::AcqRel) {
        log::info!("[HOST-HTTP] service already started, skipping");
        return;
    }

    log::info!("[HOST-HTTP] scheduling host HTTP service on 0.0.0.0:80");
    executor.spawn(Task::new(async {
        run_net_poller().await;
    }));
    executor.spawn(Task::new(async {
        run_service().await;
    }));
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
    loop {
        // ISR + network_event_taskが非同期にパケット処理を行うため
        // 直接handle_all_virtio_net_interrupts()を呼ばずyieldで委ねる
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
async fn run_service() {
    let listener = match TcpListener::bind(EndpointAddr::new([0, 0, 0, 0], 80)).await {
        Ok(listener) => {
            log::info!("[HOST-HTTP] listening on 0.0.0.0:80");
            listener
        }
        Err(err) => {
            log::warn!("[HOST-HTTP] bind/listen failed on port 80: {:?}", err);
            return;
        }
    };

    loop {
        match task::with_timeout(listener.next_connection(), 500).await {
            TimeoutResult::TimedOut => {
                task::yield_now().await;
            }
            TimeoutResult::Completed(Ok((client, peer))) => {
                let active = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
                if active >= MAX_CONCURRENT_CONNECTIONS {
                    log::warn!("[HOST-HTTP] connection limit reached ({}), rejecting {:?}", active, peer);
                    // 接続を閉じて次を受け付ける
                    let mut rejected = client;
                    let _ = rejected.shutdown().await;
                    continue;
                }

                log::info!("[HOST-HTTP] accepted connection from {:?} (active: {})", peer, active + 1);

                // 【設計書準拠】各接続を独立タスクとしてspawn（並行処理）
                crate::task::Executor::spawn_global(Task::new(async move {
                    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                    handle_client(client).await;
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                }));
            }
            TimeoutResult::Completed(Err(err)) => {
                log::warn!("[HOST-HTTP] accept error: {:?}", err);
                task::sleep_ms(20).await;
            }
        }
    }
}

async fn handle_client(mut client: TcpStream) {
    let mut parser = super::parser::HttpParser::new();

    loop {
        let mut response_bytes = None;
        let mut keep_alive = false;

        // まずバッファ内のデータだけでパースできるか試す（パイプライン処理対応）
        match parser.try_parse_request() {
            Ok(Some(request)) => {
                let req_keep_alive = request.get_header("Connection").map(|v| v.eq_ignore_ascii_case("keep-alive")).unwrap_or(false);
                let default_keep_alive = request.version == super::types::HttpVersion::Http1_1;
                let conn_close = request.get_header("Connection").map(|v| v.eq_ignore_ascii_case("close")).unwrap_or(false);
                keep_alive = (req_keep_alive || default_keep_alive) && !conn_close;
                
                response_bytes = Some(build_response_for_request(&request, keep_alive));
            }
            Ok(None) => {} // データ不足
            Err(err) => {
                log::warn!("[HOST-HTTP] parse error: {:?}", err);
                response_bytes = Some(build_json_response("400 Bad Request", "{\"status\":\"bad_request\"}", false));
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
                        response_bytes = Some(build_json_response("500 Internal Server Error", "{\"status\":\"error\"}", false));
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
                                let req_keep_alive = request.get_header("Connection").map(|v| v.eq_ignore_ascii_case("keep-alive")).unwrap_or(false);
                                let default_keep_alive = request.version == super::types::HttpVersion::Http1_1;
                                let conn_close = request.get_header("Connection").map(|v| v.eq_ignore_ascii_case("close")).unwrap_or(false);
                                keep_alive = (req_keep_alive || default_keep_alive) && !conn_close;
                                
                                response_bytes = Some(build_response_for_request(&request, keep_alive));
                                break;
                            }
                            Ok(None) => {
                                // Continue reading
                            }
                            Err(err) => {
                                log::warn!("[HOST-HTTP] parse error: {:?}", err);
                                response_bytes = Some(build_json_response("400 Bad Request", "{\"status\":\"bad_request\"}", false));
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

fn build_health_response(keep_alive: bool) -> Vec<u8> {
    let bridge = crate::net::runtime::bridge::is_initialized();
    let stats = crate::net::runtime::bridge::get_bridge_stats();
    let body = format!(
        "{{\"status\":\"ok\",\"bridge\":{},\"rx\":{},\"tx\":{}}}",
        if bridge { "true" } else { "false" },
        stats.rx_packets,
        stats.tx_packets
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
        let content_type = request.get_header("Content-Type").unwrap_or("application/json");
        let body_str = core::str::from_utf8(body).unwrap_or("{\"error\": \"invalid utf-8\"}");
        build_custom_response("200 OK", content_type, body_str, keep_alive)
    } else {
        build_json_response("400 Bad Request", "{\"status\":\"missing_body\"}", keep_alive)
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
        <li><a href="/health">/health</a> - Health check</li>
        <li><a href="/info">/info</a> - System information</li>
        <li><a href="/echo">/echo</a> - POST Echo API</li>
    </ul>
    
    <p><em>Running on ExoRust v0.3.0</em></p>
</body>
</html>"#;
    build_html_response("200 OK", html, keep_alive)
}

fn build_stats_response(keep_alive: bool) -> Vec<u8> {
    let requests = TOTAL_REQUESTS.load(Ordering::Relaxed);
    let bytes_rx = BYTES_RX.load(Ordering::Relaxed);
    let bytes_tx = BYTES_TX.load(Ordering::Relaxed);
    let connections = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
    
    let (heap_used, heap_free) = crate::memory::heap_stats();
    let timer_ticks = crate::interrupts::get_timer_ticks();
    
    let json = format!(r#"{{
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
}}"#, requests, bytes_rx, bytes_tx, connections, heap_used, heap_free, timer_ticks);
    
    build_json_response("200 OK", &json, keep_alive)
}

fn build_info_response(keep_alive: bool) -> Vec<u8> {
    let domain_stats = crate::domain_system::get_domain_stats();
    let sas_stats = crate::sas::stats();
    let spectre = crate::security::spectre::status_summary();
    
    let json = format!(r#"{{
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
        domain_stats.total, domain_stats.running, domain_stats.stopped,
        sas_stats.total_regions, sas_stats.total_objects, sas_stats.domains,
        spectre.ibrs_enabled, spectre.stibp_enabled, spectre.ssbd_enabled, spectre.using_retpoline
    );
    
    build_json_response("200 OK", &json, keep_alive)
}

fn build_json_response(status: &str, body: &str, keep_alive: bool) -> Vec<u8> {
    build_custom_response(status, "application/json", body, keep_alive)
}

fn build_html_response(status: &str, body: &str, keep_alive: bool) -> Vec<u8> {
    build_custom_response(status, "text/html; charset=utf-8", body, keep_alive)
}

fn build_custom_response(status: &str, content_type: &str, body: &str, keep_alive: bool) -> Vec<u8> {
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
