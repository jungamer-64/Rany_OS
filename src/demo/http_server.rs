// ============================================================================
// src/demo/http_server.rs - Simple HTTP Server Demo
// Demonstrates zero-copy network I/O in ExoRust
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

use crate::demo::DemoResult;
use crate::net::ipv4::Ipv4Address;

/// HTTP server statistics
pub struct HttpStats {
    /// Total requests received
    pub requests: AtomicU64,
    /// Total bytes received
    pub bytes_rx: AtomicU64,
    /// Total bytes sent
    pub bytes_tx: AtomicU64,
    /// Active connections
    pub connections: AtomicU64,
}

impl HttpStats {
    pub const fn new() -> Self {
        HttpStats {
            requests: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
            connections: AtomicU64::new(0),
        }
    }
}

/// Global server stats
static STATS: HttpStats = HttpStats::new();

/// Server running flag
static RUNNING: AtomicBool = AtomicBool::new(false);

/// HTTP response codes
#[derive(Debug, Clone, Copy)]
pub enum HttpStatus {
    Ok = 200,
    NotFound = 404,
    InternalError = 500,
}

impl HttpStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpStatus::Ok => "200 OK",
            HttpStatus::NotFound => "404 Not Found",
            HttpStatus::InternalError => "500 Internal Server Error",
        }
    }
}

/// HTTP request
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub version: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body: &'a [u8],
}

impl<'a> HttpRequest<'a> {
    /// Parse HTTP request from bytes (zero-copy where possible)
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let text = core::str::from_utf8(data).ok()?;
        
        // Find end of request line
        let mut lines = text.lines();
        let request_line = lines.next()?;
        
        // Parse request line: "GET /path HTTP/1.1"
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?;
        let path = parts.next()?;
        let version = parts.next()?;
        
        // Parse headers
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                headers.push((name, value));
            }
        }
        
        Some(HttpRequest {
            method,
            path,
            version,
            headers,
            body: &[],
        })
    }
    
    /// Get header value
    pub fn header(&self, name: &str) -> Option<&'a str> {
        for (key, value) in &self.headers {
            if key.eq_ignore_ascii_case(name) {
                return Some(*value);
            }
        }
        None
    }
}

/// HTTP response builder
pub struct HttpResponse {
    status: HttpStatus,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: HttpStatus) -> Self {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
    
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((String::from(name), String::from(value)));
        self
    }
    
    pub fn body(mut self, data: &[u8]) -> Self {
        self.body = data.to_vec();
        self
    }
    
    pub fn body_str(mut self, text: &str) -> Self {
        self.body = text.as_bytes().to_vec();
        self
    }
    
    /// Build HTTP response bytes
    pub fn build(&self) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {}\r\n",
            self.status.as_str()
        );
        
        // Add Content-Length
        response.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        
        // Add custom headers
        for (name, value) in &self.headers {
            response.push_str(&format!("{}: {}\r\n", name, value));
        }
        
        // Add server header
        response.push_str("Server: ExoRust/0.2.0\r\n");
        response.push_str("Connection: close\r\n");
        response.push_str("\r\n");
        
        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

/// Route handler type
type RouteHandler = fn(&HttpRequest) -> HttpResponse;

/// HTTP router
pub struct Router {
    routes: Vec<(&'static str, &'static str, RouteHandler)>,
}

impl Router {
    pub fn new() -> Self {
        Router { routes: Vec::new() }
    }
    
    pub fn get(mut self, path: &'static str, handler: RouteHandler) -> Self {
        self.routes.push(("GET", path, handler));
        self
    }
    
    pub fn post(mut self, path: &'static str, handler: RouteHandler) -> Self {
        self.routes.push(("POST", path, handler));
        self
    }
    
    pub fn route(&self, request: &HttpRequest) -> HttpResponse {
        for (method, path, handler) in &self.routes {
            if request.method == *method && request.path == *path {
                return handler(request);
            }
        }
        
        // 404 Not Found
        HttpResponse::new(HttpStatus::NotFound)
            .header("Content-Type", "text/html")
            .body_str("<html><body><h1>404 Not Found</h1></body></html>")
    }
}

/// Default routes
fn route_index(_req: &HttpRequest) -> HttpResponse {
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
    <p>Welcome to the ExoRust zero-copy HTTP server demonstration!</p>
    
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
    </ul>
    
    <p><em>Running on ExoRust v0.2.0</em></p>
</body>
</html>"#;
    
    HttpResponse::new(HttpStatus::Ok)
        .header("Content-Type", "text/html; charset=utf-8")
        .body_str(html)
}

fn route_stats(_req: &HttpRequest) -> HttpResponse {
    let requests = STATS.requests.load(Ordering::Relaxed);
    let bytes_rx = STATS.bytes_rx.load(Ordering::Relaxed);
    let bytes_tx = STATS.bytes_tx.load(Ordering::Relaxed);
    let connections = STATS.connections.load(Ordering::Relaxed);
    
    let (heap_used, heap_free) = crate::memory::heap_stats();
    let timer_ticks = crate::interrupts::get_timer_ticks();
    
    let json = format!(r#"{{
    "server": "ExoRust HTTP",
    "version": "0.2.0",
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
    
    HttpResponse::new(HttpStatus::Ok)
        .header("Content-Type", "application/json")
        .body_str(&json)
}

fn route_health(_req: &HttpRequest) -> HttpResponse {
    HttpResponse::new(HttpStatus::Ok)
        .header("Content-Type", "application/json")
        .body_str(r#"{"status":"healthy","kernel":"ExoRust"}"#)
}

fn route_info(_req: &HttpRequest) -> HttpResponse {
    let domain_stats = crate::domain_system::get_domain_stats();
    let sas_stats = crate::sas::stats();
    let spectre = crate::spectre::status_summary();
    
    let json = format!(r#"{{
    "kernel": {{
        "name": "ExoRust",
        "version": "0.2.0",
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
    
    HttpResponse::new(HttpStatus::Ok)
        .header("Content-Type", "application/json")
        .body_str(&json)
}

/// Create default router
fn create_router() -> Router {
    Router::new()
        .get("/", route_index)
        .get("/stats", route_stats)
        .get("/health", route_health)
        .get("/info", route_info)
}

/// Handle connection
fn handle_connection(data: &[u8], router: &Router) -> Vec<u8> {
    STATS.bytes_rx.fetch_add(data.len() as u64, Ordering::Relaxed);
    STATS.requests.fetch_add(1, Ordering::Relaxed);
    
    let response = match HttpRequest::parse(data) {
        Some(request) => router.route(&request),
        None => HttpResponse::new(HttpStatus::InternalError)
            .body_str("Invalid HTTP request"),
    };
    
    let bytes = response.build();
    STATS.bytes_tx.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    bytes
}

/// Run HTTP server demo
pub fn run() -> DemoResult {
    crate::log!("\n");
    crate::log!("================================================================================\n");
    crate::log!("                    ExoRust HTTP Server Demo\n");
    crate::log!("================================================================================\n\n");
    
    let router = create_router();
    
    RUNNING.store(true, Ordering::SeqCst);
    
    crate::log!("[HTTP] Server initialized\n");
    crate::log!("[HTTP] Routes registered:\n");
    crate::log!("       GET /        - Welcome page\n");
    crate::log!("       GET /stats   - Server statistics\n");
    crate::log!("       GET /health  - Health check\n");
    crate::log!("       GET /info    - System information\n\n");
    
    // Simulate some test requests
    crate::log!("[HTTP] Running test requests...\n\n");
    
    // Test 1: Index page
    let request1 = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let response1 = handle_connection(request1, &router);
    crate::log!("[HTTP] GET / - Response: {} bytes\n", response1.len());
    
    // Test 2: Stats endpoint
    let request2 = b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let response2 = handle_connection(request2, &router);
    crate::log!("[HTTP] GET /stats - Response: {} bytes\n", response2.len());
    
    // Show stats JSON
    if let Ok(body) = core::str::from_utf8(&response2) {
        if let Some(json_start) = body.find('{') {
            crate::log!("[HTTP] Stats response:\n{}\n", &body[json_start..]);
        }
    }
    
    // Test 3: Health check
    let request3 = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let response3 = handle_connection(request3, &router);
    crate::log!("[HTTP] GET /health - Response: {} bytes\n", response3.len());
    
    // Test 4: 404
    let request4 = b"GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let response4 = handle_connection(request4, &router);
    crate::log!("[HTTP] GET /nonexistent - Response: {} bytes (404)\n", response4.len());
    
    // Print final stats
    crate::log!("\n[HTTP] Final Statistics:\n");
    crate::log!("       Requests: {}\n", STATS.requests.load(Ordering::Relaxed));
    crate::log!("       Bytes RX: {}\n", STATS.bytes_rx.load(Ordering::Relaxed));
    crate::log!("       Bytes TX: {}\n", STATS.bytes_tx.load(Ordering::Relaxed));
    
    RUNNING.store(false, Ordering::SeqCst);
    
    crate::log!("\n[HTTP] Server demo completed successfully\n");
    crate::log!("================================================================================\n\n");
    
    DemoResult::Success
}

/// Get server statistics
pub fn stats() -> (u64, u64, u64, u64) {
    (
        STATS.requests.load(Ordering::Relaxed),
        STATS.bytes_rx.load(Ordering::Relaxed),
        STATS.bytes_tx.load(Ordering::Relaxed),
        STATS.connections.load(Ordering::Relaxed),
    )
}

/// Check if server is running
pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}
