// ============================================================================
// kernel/src/net/services/http/server/router.rs - サービス / HTTP / サーバ / router
// ============================================================================

use alloc::string::String;
use alloc::{format, vec::Vec};
use core::sync::atomic::Ordering;

use crate::net::payload::GeneratedPacketWriter;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::services::http::types::{
    ConnectionDirective, HttpHeaderName, HttpHeaderValue, HttpInboundRequest, HttpMethod,
    HttpResponse, HttpStatusCode, HttpVersion,
};
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

use super::index_html;

pub(super) enum RequestResponse {
    Respond {
        payload: PacketPayload,
        keep_alive: bool,
    },
    // 通常レスポンスと 503 fallback の両方の構築に失敗したため、
    // 書き込みを行わず接続を終了すべき状態。
    Close,
}

fn keep_alive_for_request(request: &HttpInboundRequest) -> bool {
    let default_keep_alive = request.version == HttpVersion::Http1_1;

    match request.connection_directive() {
        Some(ConnectionDirective::Close) => false,
        Some(ConnectionDirective::KeepAlive) => true,
        None => default_keep_alive,
    }
}

fn build_json_response_or_log(
    status: HttpStatusCode,
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

pub(super) fn build_service_unavailable_response_or_log() -> Option<PacketPayload> {
    build_json_response_or_log(
        HttpStatusCode::SERVICE_UNAVAILABLE,
        "{\"status\":\"service_unavailable\"}",
        false,
        "service_unavailable",
    )
}

pub(super) fn build_bad_request_response_or_log() -> Option<PacketPayload> {
    build_json_response_or_log(
        HttpStatusCode::BAD_REQUEST,
        "{\"status\":\"bad_request\"}",
        false,
        "bad_request",
    )
}

pub(super) fn build_timeout_response_or_log() -> Option<PacketPayload> {
    build_json_response_or_log(
        HttpStatusCode::REQUEST_TIMEOUT,
        "{\"status\":\"timeout\"}",
        false,
        "timeout",
    )
}

pub(super) fn build_request_response_or_fallback(
    runtime: NetRuntimeHandle,
    request: HttpInboundRequest,
) -> RequestResponse {
    let keep_alive = keep_alive_for_request(&request);

    match build_response_for_request(runtime, request, keep_alive) {
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

fn aggregate_port_runtime_stats_in(runtime: NetRuntimeHandle) -> (usize, u64, u64, u64, u64) {
    let port_ids = crate::net::runtime::device::list_port_ids_in(runtime);
    let mut rx_packets = 0u64;
    let mut tx_packets = 0u64;
    let mut tx_errors = 0u64;
    let mut rx_errors = 0u64;

    for port_id in &port_ids {
        if let Some(stats) = crate::net::runtime::device::port_stats_in(runtime, *port_id) {
            rx_packets = rx_packets.saturating_add(stats.rx_packets);
            tx_packets = tx_packets.saturating_add(stats.tx_packets);
            tx_errors = tx_errors.saturating_add(stats.tx_errors);
            rx_errors = rx_errors.saturating_add(stats.rx_errors);
        }
    }

    (port_ids.len(), rx_packets, tx_packets, tx_errors, rx_errors)
}

fn build_health_response_in(
    runtime: NetRuntimeHandle,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    let (ports, rx_packets, tx_packets, tx_errors, rx_errors) =
        aggregate_port_runtime_stats_in(runtime);
    let body = format!(
        "{{\"status\":\"ok\",\"port_runtime\":{},\"ports\":{},\"rx\":{},\"tx\":{},\"tx_errors\":{},\"rx_errors\":{}}}",
        if crate::net::runtime::device::is_initialized_in(runtime) {
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
    build_json_response(HttpStatusCode::OK, &body, keep_alive)
}

fn build_response_for_request(
    runtime: NetRuntimeHandle,
    request: HttpInboundRequest,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    super::http_runtime_in(runtime)
        .total_requests
        .fetch_add(1, Ordering::Relaxed);

    if request.method == HttpMethod::Get {
        return build_get_response(runtime, &request, keep_alive);
    }

    if request.method == HttpMethod::Post && request.uri_eq("/echo") {
        return build_echo_response(request, keep_alive);
    }

    build_json_response(
        HttpStatusCode::NOT_FOUND,
        "{\"status\":\"not_found\"}",
        keep_alive,
    )
}

fn build_get_response(
    runtime: NetRuntimeHandle,
    request: &HttpInboundRequest,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    if request.uri_eq("/") {
        return build_index_response(keep_alive);
    }
    if request.uri_eq("/health") {
        return build_health_response_in(runtime, keep_alive);
    }
    if request.uri_eq("/stats") {
        return build_stats_response(runtime, keep_alive);
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

    build_json_response(
        HttpStatusCode::NOT_FOUND,
        "{\"status\":\"not_found\"}",
        keep_alive,
    )
}

fn build_echo_response(
    request: HttpInboundRequest,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    if let Some(body) = request.into_body_payload() {
        build_payload_response(
            HttpStatusCode::OK,
            "application/octet-stream",
            body,
            keep_alive,
            &[],
        )
    } else {
        build_json_response(
            HttpStatusCode::BAD_REQUEST,
            "{\"status\":\"missing_body\"}",
            keep_alive,
        )
    }
}

fn build_index_response(keep_alive: bool) -> Result<PacketPayload, HttpResponseBuildError> {
    build_html_response(HttpStatusCode::OK, index_html::INDEX_HTML, keep_alive)
}

fn build_log_response(keep_alive: bool) -> Result<PacketPayload, HttpResponseBuildError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(crate::io::log::HISTORY_BYTES)
        .map_err(|_| HttpResponseBuildError::AllocationFailed)?;
    bytes.resize(crate::io::log::HISTORY_BYTES, 0);
    let snapshot = crate::io::log::snapshot(&mut bytes);
    let truncated = if snapshot.truncated { "true" } else { "false" };
    build_custom_response_with_headers(
        HttpStatusCode::OK,
        "text/plain; charset=utf-8",
        snapshot.text,
        keep_alive,
        &[("X-Log-Truncated", truncated)],
    )
}

fn build_executor_stats_response(
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    let Some(snapshot) = crate::task::scheduler_snapshot() else {
        return build_json_response(HttpStatusCode::SERVICE_UNAVAILABLE, "[]", keep_alive);
    };

    let mut json = String::from("[\n");
    for (i, queue) in snapshot.run_queues.iter().enumerate() {
        if i > 0 {
            json.push_str(",\n");
        }
        json.push_str(&format!(
            r#"  {{
    "cpu_id": {},
    "ready_tasks": {},
    "scheduler_task_count": {},
    "scheduler_poll_count": {}
  }}"#,
            queue.cpu, queue.ready_tasks, snapshot.task_count, snapshot.poll_count
        ));
    }
    json.push_str("\n]");

    build_json_response(HttpStatusCode::OK, &json, keep_alive)
}

fn build_memory_info_response(keep_alive: bool) -> Result<PacketPayload, HttpResponseBuildError> {
    let (free_frames, total_frames) = crate::mm::phys::frame_allocator::frame_allocator_stats();
    let total_kb = total_frames as u64 * 4;
    let free_kb = free_frames * 4;
    let used_kb = total_kb.saturating_sub(free_kb);
    let (heap_used, heap_free) = crate::heap::heap_stats();
    let json = format!(
        r#"{{
    "physical_memory": {{ "total_kb": {}, "free_kb": {}, "used_kb": {} }},
    "heap": {{ "used_bytes": {}, "free_bytes": {} }}
}}
"#,
        total_kb, free_kb, used_kb, heap_used, heap_free
    );
    build_json_response(HttpStatusCode::OK, &json, keep_alive)
}

fn build_stats_response(
    runtime: NetRuntimeHandle,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    let state = super::http_runtime_in(runtime);
    let requests = state.total_requests.load(Ordering::Relaxed);
    let bytes_rx = state.bytes_rx.load(Ordering::Relaxed);
    let bytes_tx = state.bytes_tx.load(Ordering::Relaxed);
    let connections = state.active_connections.load(Ordering::Acquire);

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

    build_json_response(HttpStatusCode::OK, &json, keep_alive)
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

    build_json_response(HttpStatusCode::OK, &json, keep_alive)
}

fn build_json_response(
    status: HttpStatusCode,
    body: &str,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    build_custom_response(status, "application/json", body, keep_alive)
}

fn build_html_response(
    status: HttpStatusCode,
    body: &str,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    build_custom_response(status, "text/html; charset=utf-8", body, keep_alive)
}

#[derive(Debug, Clone, Copy)]
enum HttpResponseBuildError {
    AllocationFailed,
    InvalidHeader,
}

fn build_payload_response(
    status: HttpStatusCode,
    content_type: &'static str,
    body: PacketPayload,
    keep_alive: bool,
    additional_headers: &[(&str, &str)],
) -> Result<PacketPayload, HttpResponseBuildError> {
    let connection = if keep_alive {
        ConnectionDirective::KeepAlive
    } else {
        ConnectionDirective::Close
    };
    let mut response = HttpResponse::new(status, status.reason_phrase()).header_typed(
        HttpHeaderName::ContentType,
        HttpHeaderValue::from_static(content_type),
    );
    for (name, value) in additional_headers {
        response = response
            .header(name, value)
            .ok_or(HttpResponseBuildError::InvalidHeader)?;
    }
    response
        .header_typed(
            HttpHeaderName::Connection,
            HttpHeaderValue::from_static(connection.as_header_value()),
        )
        .body_payload(body)
        .ok_or(HttpResponseBuildError::AllocationFailed)?
        .into_payload()
        .ok_or(HttpResponseBuildError::AllocationFailed)
}

fn build_custom_response_with_headers(
    status: HttpStatusCode,
    content_type: &'static str,
    body: &str,
    keep_alive: bool,
    additional_headers: &[(&str, &str)],
) -> Result<PacketPayload, HttpResponseBuildError> {
    let mut writer = GeneratedPacketWriter::new(body.len(), DEFAULT_PACKET_HEADROOM)
        .ok_or(HttpResponseBuildError::AllocationFailed)?;
    writer
        .write_generated_bytes(body.as_bytes())
        .ok_or(HttpResponseBuildError::AllocationFailed)?;
    build_payload_response(
        status,
        content_type,
        writer
            .finish()
            .ok_or(HttpResponseBuildError::AllocationFailed)?,
        keep_alive,
        additional_headers,
    )
}

fn build_custom_response(
    status: HttpStatusCode,
    content_type: &'static str,
    body: &str,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    build_custom_response_with_headers(status, content_type, body, keep_alive, &[])
}
