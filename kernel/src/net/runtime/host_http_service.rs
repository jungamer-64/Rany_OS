use alloc::{format, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::net::l4::tcp::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use crate::task::{self, Task, TimeoutResult};

static HOST_HTTP_SERVICE_STARTED: AtomicBool = AtomicBool::new(false);

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

async fn run_net_poller() {
    loop {
        crate::io::virtio::handle_all_virtio_net_interrupts();
        task::sleep_ms(1).await;
    }
}

async fn run_service() {
    let listener = match TcpListener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED, 80)) {
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
                log::info!("[HOST-HTTP] accepted connection from {:?}", peer);
                handle_client(client).await;
            }
            TimeoutResult::Completed(Err(err)) => {
                log::warn!("[HOST-HTTP] accept error: {:?}", err);
                task::sleep_ms(20).await;
            }
        }
    }
}

async fn handle_client(mut client: TcpStream) {
    let response = match read_request_with_timeout(&mut client).await {
        Ok(request) => build_response_for_request(&request),
        Err(err) => {
            log::warn!("[HOST-HTTP] read request failed: {}", err);
            build_json_response("400 Bad Request", "{\"status\":\"bad_request\"}")
        }
    };
    log::info!("[HOST-HTTP] preparing response: {} bytes", response.len());
    log::info!("[HOST-HTTP] connection established, preparing response...");

    if let Err(err) = write_response(&mut client, response.as_slice()).await {
        log::warn!("[HOST-HTTP] send error: {}", err);
    }

    let _ = client.shutdown().await;
}

async fn read_request_with_timeout(client: &mut TcpStream) -> Result<Vec<u8>, &'static str> {
    const READ_TRIES: usize = 20;
    const READ_TIMEOUT_MS: u64 = 100;

    let mut buffer = [0u8; 2048];
    for _ in 0..READ_TRIES {
        match task::with_timeout(client.read(&mut buffer), READ_TIMEOUT_MS).await {
            TimeoutResult::TimedOut => {
                crate::io::virtio::handle_all_virtio_net_interrupts();
                task::yield_now().await;
            }
            TimeoutResult::Completed(Err(_)) => return Err("socket recv error"),
            TimeoutResult::Completed(Ok(0)) => return Err("peer closed connection"),
            TimeoutResult::Completed(Ok(len)) => return Ok(buffer[..len].to_vec()),
        }
    }

    Err("request read timeout")
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
                crate::io::virtio::handle_all_virtio_net_interrupts();
                task::yield_now().await;
                continue;
            }
            TimeoutResult::Completed(Err(_)) => return Err("socket write error"),
            TimeoutResult::Completed(Ok(0)) => return Err("socket closed while sending"),
            TimeoutResult::Completed(Ok(written)) => {
                write_timeouts = 0;
                log::info!("[HOST-HTTP] wrote {} bytes", written);
                sent += written;
                crate::io::virtio::handle_all_virtio_net_interrupts();
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
                crate::io::virtio::handle_all_virtio_net_interrupts();
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

fn build_health_response() -> Vec<u8> {
    let bridge = crate::net::runtime::bridge::is_initialized();
    let stats = crate::net::runtime::bridge::get_bridge_stats();
    let body = format!(
        "{{\"status\":\"ok\",\"bridge\":{},\"rx\":{},\"tx\":{}}}",
        if bridge { "true" } else { "false" },
        stats.rx_packets,
        stats.tx_packets
    );
    build_json_response("200 OK", &body)
}

fn build_response_for_request(request: &[u8]) -> Vec<u8> {
    let request_line = core::str::from_utf8(request)
        .ok()
        .and_then(|text| text.lines().next())
        .unwrap_or("");

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method == "GET" && path == "/health" {
        return build_health_response();
    }

    build_json_response("404 Not Found", "{\"status\":\"not_found\"}")
}

fn build_json_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        status = status,
        len = body.len(),
        body = body
    )
    .into_bytes()
}
