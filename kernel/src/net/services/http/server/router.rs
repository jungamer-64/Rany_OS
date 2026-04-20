// ============================================================================
// kernel/src/net/services/http/server/router.rs - サービス / HTTP / サーバ / router
// ============================================================================

use alloc::string::{String, ToString};
use alloc::{format, vec};
use core::sync::atomic::Ordering;

use crate::net::payload::{PacketPayloadBuilder, PayloadSpanRef};
use crate::net::services::http::types::{
    ConnectionDirective, HttpInboundRequest, HttpMethod, HttpVersion,
};
use kernel_api::resource::net::PacketPayload;

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

pub(super) fn build_service_unavailable_response_or_log() -> Option<PacketPayload> {
    build_json_response_or_log(
        "503 Service Unavailable",
        "{\"status\":\"service_unavailable\"}",
        false,
        "service_unavailable",
    )
}

pub(super) fn build_bad_request_response_or_log() -> Option<PacketPayload> {
    build_json_response_or_log(
        "400 Bad Request",
        "{\"status\":\"bad_request\"}",
        false,
        "bad_request",
    )
}

pub(super) fn build_timeout_response_or_log() -> Option<PacketPayload> {
    build_json_response_or_log(
        "408 Request Timeout",
        "{\"status\":\"timeout\"}",
        false,
        "timeout",
    )
}

pub(super) fn build_request_response_or_fallback(request: &HttpInboundRequest) -> RequestResponse {
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

fn aggregate_port_runtime_stats() -> (usize, u64, u64, u64, u64) {
    let port_ids =
        crate::net::runtime::device::list_port_ids_in(crate::net::runtime::default_runtime());
    let mut rx_packets = 0u64;
    let mut tx_packets = 0u64;
    let mut tx_errors = 0u64;
    let mut rx_errors = 0u64;

    for port_id in &port_ids {
        if let Some(stats) = crate::net::runtime::device::port_stats(*port_id) {
            rx_packets = rx_packets.saturating_add(stats.rx_packets);
            tx_packets = tx_packets.saturating_add(stats.tx_packets);
            tx_errors = tx_errors.saturating_add(stats.tx_errors);
            rx_errors = rx_errors.saturating_add(stats.rx_errors);
        }
    }

    (port_ids.len(), rx_packets, tx_packets, tx_errors, rx_errors)
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
    request: &HttpInboundRequest,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    super::TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);

    if request.method == HttpMethod::Get {
        return build_get_response(request, keep_alive);
    }

    if request.method == HttpMethod::Post && request.uri_eq("/echo") {
        return build_echo_response(request, keep_alive);
    }

    build_json_response("404 Not Found", "{\"status\":\"not_found\"}", keep_alive)
}

fn build_get_response(
    request: &HttpInboundRequest,
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
    request: &HttpInboundRequest,
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
    build_html_response("200 OK", index_html::INDEX_HTML, keep_alive)
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

    let mut json = String::from("[\n");
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
    let requests = super::TOTAL_REQUESTS.load(Ordering::Relaxed);
    let bytes_rx = super::BYTES_RX.load(Ordering::Relaxed);
    let bytes_tx = super::BYTES_TX.load(Ordering::Relaxed);
    let connections = super::ACTIVE_CONNECTIONS.load(Ordering::Acquire);

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

enum HeaderValue<'a> {
    Text(String),
    PayloadOrDefault(Option<PayloadSpanRef<'a>>),
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

fn write_content_type_header(
    builder: &mut PacketPayloadBuilder,
    content_type: HeaderValue<'_>,
) -> Result<(), HttpResponseBuildError> {
    push_builder_str(builder, "Content-Type: ")?;
    match content_type {
        HeaderValue::Text(value) => push_builder_str(builder, &value)?,
        HeaderValue::PayloadOrDefault(Some(value)) => {
            builder
                .push_span_ref(value)
                .ok_or(HttpResponseBuildError::InvalidPayloadSpan)?;
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

const fn connection_header_value(keep_alive: bool) -> &'static str {
    if keep_alive { "keep-alive" } else { "close" }
}

fn write_status_line(
    builder: &mut PacketPayloadBuilder,
    status: &str,
) -> Result<(), HttpResponseBuildError> {
    push_builder_str(builder, "HTTP/1.1 ")?;
    push_builder_str(builder, status)?;
    push_builder_str(builder, "\r\n")
}

fn write_connection_header(
    builder: &mut PacketPayloadBuilder,
    keep_alive: bool,
) -> Result<(), HttpResponseBuildError> {
    push_builder_str(builder, "Connection: ")?;
    push_builder_str(builder, connection_header_value(keep_alive))?;
    push_builder_str(builder, "\r\n")
}

fn write_content_length_header(
    builder: &mut PacketPayloadBuilder,
    body_len: usize,
) -> Result<(), HttpResponseBuildError> {
    push_builder_str(builder, "Content-Length: ")?;
    push_builder_str(builder, &format!("{}", body_len))?;
    push_builder_str(builder, "\r\n\r\n")
}

fn build_payload_response(
    status: &str,
    content_type: HeaderValue<'_>,
    body: PacketPayload,
    keep_alive: bool,
    additional_headers: &[(&str, &str)],
) -> Result<PacketPayload, HttpResponseBuildError> {
    let mut builder = PacketPayloadBuilder::new();
    write_status_line(&mut builder, status)?;
    write_content_type_header(&mut builder, content_type)?;
    push_builder_str(&mut builder, "\r\n")?;
    write_additional_headers(&mut builder, additional_headers)?;
    write_connection_header(&mut builder, keep_alive)?;
    write_content_length_header(&mut builder, body.total_len())?;
    builder.push_payload(body);
    Ok(builder.build())
}

fn build_custom_response_with_headers(
    status: &str,
    content_type: &str,
    body: &str,
    keep_alive: bool,
    additional_headers: &[(&str, &str)],
) -> Result<PacketPayload, HttpResponseBuildError> {
    let mut body_builder = PacketPayloadBuilder::new();
    push_builder_str(&mut body_builder, body)?;
    build_payload_response(
        status,
        HeaderValue::Text(content_type.to_string()),
        body_builder.build(),
        keep_alive,
        additional_headers,
    )
}

fn build_custom_response(
    status: &str,
    content_type: &str,
    body: &str,
    keep_alive: bool,
) -> Result<PacketPayload, HttpResponseBuildError> {
    build_custom_response_with_headers(status, content_type, body, keep_alive, &[])
}
