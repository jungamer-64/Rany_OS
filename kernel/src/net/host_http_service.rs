use alloc::{format, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use crate::task::{self, Task, TimeoutResult};

static HOST_HTTP_SERVICE_STARTED: AtomicBool = AtomicBool::new(false);

pub fn start_once(executor: &mut task::Executor) {
    if HOST_HTTP_SERVICE_STARTED.swap(true, Ordering::AcqRel) {
        log::info!("[HOST-HTTP] service already started, skipping");
        return;
    }

    log::info!("[HOST-HTTP] scheduling host HTTP service on 0.0.0.0:80");
    executor.spawn(Task::new(async {
        run_service().await;
    }));
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
    let request = match read_request_with_timeout(&mut client).await {
        Ok(data) => data,
        Err(err) => {
            log::warn!("[HOST-HTTP] read request failed: {}", err);
            return;
        }
    };

    let response = build_response_for_request(&request);

    match task::with_timeout(client.write(response.as_slice()), 300).await {
        TimeoutResult::TimedOut => {
            log::warn!("[HOST-HTTP] send timeout");
        }
        TimeoutResult::Completed(Ok(_)) => {}
        TimeoutResult::Completed(Err(err)) => {
            log::warn!("[HOST-HTTP] send error: {:?}", err);
        }
    }

    let _ = task::with_timeout(client.shutdown(), 100).await;
}

async fn read_request_with_timeout(client: &mut TcpStream) -> Result<Vec<u8>, &'static str> {
    const READ_TRIES: usize = 20;
    let mut buffer = [0u8; 2048];

    for _ in 0..READ_TRIES {
        match task::with_timeout(client.read(&mut buffer), 100).await {
            TimeoutResult::TimedOut => {
                task::yield_now().await;
            }
            TimeoutResult::Completed(Ok(len)) => {
                if len == 0 {
                    return Err("peer closed connection");
                }
                return Ok(buffer[..len].to_vec());
            }
            TimeoutResult::Completed(Err(_)) => {
                return Err("socket recv error");
            }
        }
    }

    Err("request read timeout")
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
        let bridge = crate::net::driver_bridge::is_initialized();
        let stats = crate::net::get_bridge_stats();
        let body = format!(
            "{{\"status\":\"ok\",\"bridge\":{},\"rx\":{},\"tx\":{}}}",
            if bridge { "true" } else { "false" },
            stats.rx_packets,
            stats.tx_packets
        );
        return build_json_response("200 OK", &body);
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
