// ============================================================================
// src/demo/echo_server.rs - TCP Echo Server Demo
// Demonstrates async I/O and zero-copy networking
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

use crate::demo::DemoResult;
use crate::net::endpoint::{
    SocketAddr, SocketError, OwnedSocket,
    create_tcp_server,
};

/// Echo server statistics
pub struct EchoStats {
    /// Total connections
    pub connections: AtomicU64,
    /// Total bytes echoed
    pub bytes_echoed: AtomicU64,
    /// Errors
    pub errors: AtomicU64,
    /// Active connections
    pub active_connections: AtomicU64,
}

impl EchoStats {
    pub const fn new() -> Self {
        EchoStats {
            connections: AtomicU64::new(0),
            bytes_echoed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
        }
    }
    
    /// Record new connection
    pub fn on_connect(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record connection close
    pub fn on_disconnect(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
    
    /// Record bytes echoed
    pub fn on_echo(&self, bytes: usize) {
        self.bytes_echoed.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    
    /// Record error
    pub fn on_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
}

static STATS: EchoStats = EchoStats::new();
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Echo server configuration
pub struct EchoConfig {
    /// Port to listen on
    pub port: u16,
    /// Maximum message size
    pub max_message_size: usize,
    /// Echo prefix
    pub prefix: Option<String>,
    /// Backlog size for listen()
    pub backlog: u32,
}

impl Default for EchoConfig {
    fn default() -> Self {
        EchoConfig {
            port: 7777,
            max_message_size: 65536,
            prefix: None,
            backlog: 128,
        }
    }
}

// ============================================================================
// Real Async TCP Echo Server using endpoint module
// ============================================================================

/// Run the real async TCP echo server
/// This uses the actual network stack with OwnedSocket and async/await
pub async fn run_echo_server() {
    run_echo_server_on_port(8080).await
}

/// Run the async TCP echo server on specified port
pub async fn run_echo_server_on_port(port: u16) {
    let addr = SocketAddr::new([0, 0, 0, 0], port); // 0.0.0.0:port

    // 1. Create server socket (Bind + Listen)
    let server = match create_tcp_server(addr, 128) {
        Ok(s) => s,
        Err(e) => {
            crate::serial_println!("Echo Server: Failed to bind on port {}: {:?}", port, e);
            STATS.on_error();
            return;
        }
    };

    RUNNING.store(true, Ordering::SeqCst);
    crate::serial_println!("Echo Server: Listening on 0.0.0.0:{}", port);

    // Accept loop
    loop {
        if !RUNNING.load(Ordering::SeqCst) {
            crate::serial_println!("Echo Server: Shutdown requested");
            break;
        }

        // 2. Accept connections (Async)
        if let Some(accept_future) = server.accept_async() {
            match accept_future.await {
                Ok((client_socket, client_addr)) => {
                    STATS.on_connect();
                    crate::serial_println!(
                        "Echo Server: New connection from {:?}:{} (total: {})",
                        client_addr.ip,
                        client_addr.port,
                        STATS.connections.load(Ordering::Relaxed)
                    );

                    // 3. Spawn client handler task
                    // Note: In a real implementation, this would use the task scheduler
                    // For now, we handle inline (single-threaded)
                    handle_echo_client(client_socket).await;
                }
                Err(SocketError::Timeout) => {
                    // No pending connections, yield and try again
                    // In real async runtime, this would be handled by the Future
                    continue;
                }
                Err(e) => {
                    crate::serial_println!("Echo Server: Accept error: {:?}", e);
                    STATS.on_error();
                }
            }
        }
    }

    RUNNING.store(false, Ordering::SeqCst);
    crate::serial_println!("Echo Server: Stopped");
}

/// Handle a single echo client connection
async fn handle_echo_client(socket: OwnedSocket) {
    let client_fd = socket.fd();
    crate::serial_println!("Echo Client {}: Handler started", client_fd.raw());

    loop {
        // 4. Receive data (Async)
        let recv_future = match socket.recv_async(1024) {
            Some(f) => f,
            None => {
                crate::serial_println!("Echo Client {}: Socket error", client_fd.raw());
                STATS.on_error();
                break;
            }
        };

        match recv_future.await {
            Ok(data) => {
                if data.is_empty() {
                    // EOF - connection closed by peer
                    crate::serial_println!("Echo Client {}: Connection closed by peer", client_fd.raw());
                    break;
                }

                let len = data.len();
                crate::serial_println!(
                    "Echo Client {}: Received {} bytes",
                    client_fd.raw(),
                    len
                );

                // 5. Send data back (Echo)
                if let Some(send_future) = socket.send_async(data) {
                    match send_future.await {
                        Ok(sent) => {
                            STATS.on_echo(sent);
                            crate::serial_println!(
                                "Echo Client {}: Echoed {} bytes",
                                client_fd.raw(),
                                sent
                            );
                        }
                        Err(e) => {
                            crate::serial_println!(
                                "Echo Client {}: Send error: {:?}",
                                client_fd.raw(),
                                e
                            );
                            STATS.on_error();
                            break;
                        }
                    }
                }
            }
            Err(SocketError::Timeout) => {
                // No data available, continue waiting
                continue;
            }
            Err(e) => {
                crate::serial_println!("Echo Client {}: Recv error: {:?}", client_fd.raw(), e);
                STATS.on_error();
                break;
            }
        }
    }

    STATS.on_disconnect();
    crate::serial_println!(
        "Echo Client {}: Handler finished (active: {})",
        client_fd.raw(),
        STATS.active_connections.load(Ordering::Relaxed)
    );
    // OwnedSocket is dropped here, automatically sending FIN and closing
}

/// Stop the echo server
pub fn stop_server() {
    RUNNING.store(false, Ordering::SeqCst);
}

/// Check if server is running
pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// Get echo server statistics
pub fn stats() -> (u64, u64, u64, u64) {
    (
        STATS.connections.load(Ordering::Relaxed),
        STATS.bytes_echoed.load(Ordering::Relaxed),
        STATS.errors.load(Ordering::Relaxed),
        STATS.active_connections.load(Ordering::Relaxed),
    )
}

/// Print server statistics
pub fn print_stats() {
    let (conns, bytes, errors, active) = stats();
    crate::serial_println!("Echo Server Statistics:");
    crate::serial_println!("  Total connections: {}", conns);
    crate::serial_println!("  Active connections: {}", active);
    crate::serial_println!("  Bytes echoed: {}", bytes);
    crate::serial_println!("  Errors: {}", errors);
}

// ============================================================================
// Legacy Simulation Code (for testing without network hardware)
// ============================================================================

/// Simulated echo connection (for demo/testing purposes)
pub struct EchoConnection {
    id: u64,
    remote: String,
    bytes_in: u64,
    bytes_out: u64,
}

impl EchoConnection {
    pub fn new(id: u64, remote: &str) -> Self {
        STATS.on_connect();
        
        EchoConnection {
            id,
            remote: String::from(remote),
            bytes_in: 0,
            bytes_out: 0,
        }
    }
    
    /// Echo data back
    pub fn echo(&mut self, data: &[u8], prefix: Option<&str>) -> Vec<u8> {
        self.bytes_in += data.len() as u64;
        
        let response = if let Some(p) = prefix {
            let mut resp = p.as_bytes().to_vec();
            resp.extend_from_slice(data);
            resp
        } else {
            data.to_vec()
        };
        
        self.bytes_out += response.len() as u64;
        STATS.on_echo(response.len());
        
        response
    }
    
    pub fn close(self) {
        STATS.on_disconnect();
        crate::log!("[ECHO] Connection {} closed (in={}, out={})\n", 
            self.id, self.bytes_in, self.bytes_out);
    }
}

/// Run echo server demo (simulation mode)
pub fn run() -> DemoResult {
    crate::log!("\n");
    crate::log!("================================================================================\n");
    crate::log!("                    ExoRust TCP Echo Server Demo\n");
    crate::log!("================================================================================\n\n");
    
    let config = EchoConfig {
        port: 7777,
        max_message_size: 4096,
        prefix: Some(String::from("[ECHO] ")),
        backlog: 128,
    };
    
    RUNNING.store(true, Ordering::SeqCst);
    
    crate::log!("[ECHO] Server initialized on port {}\n", config.port);
    crate::log!("[ECHO] Max message size: {} bytes\n", config.max_message_size);
    crate::log!("[ECHO] Backlog: {} connections\n", config.backlog);
    if let Some(ref prefix) = config.prefix {
        crate::log!("[ECHO] Response prefix: '{}'\n", prefix);
    }
    crate::log!("\n");
    
    // Simulate connections and echo operations
    crate::log!("[ECHO] Simulating echo connections...\n\n");
    
    // Connection 1
    let mut conn1 = EchoConnection::new(1, "192.168.1.100:54321");
    crate::log!("[ECHO] Connection 1 from {}\n", conn1.remote);
    
    let msg1 = b"Hello, ExoRust!";
    let response1 = conn1.echo(msg1, config.prefix.as_deref());
    crate::log!("[ECHO] Received: '{}'\n", core::str::from_utf8(msg1).unwrap());
    crate::log!("[ECHO] Sent: '{}'\n", core::str::from_utf8(&response1).unwrap_or("<binary>"));
    
    // Connection 2
    let mut conn2 = EchoConnection::new(2, "10.0.0.50:12345");
    crate::log!("\n[ECHO] Connection 2 from {}\n", conn2.remote);
    
    let msg2 = b"Testing zero-copy networking";
    let response2 = conn2.echo(msg2, config.prefix.as_deref());
    crate::log!("[ECHO] Received: '{}'\n", core::str::from_utf8(msg2).unwrap());
    crate::log!("[ECHO] Sent: '{}'\n", core::str::from_utf8(&response2).unwrap_or("<binary>"));
    
    // Multiple messages on connection 1
    crate::log!("\n[ECHO] Multiple messages on connection 1:\n");
    for i in 0..5 {
        let msg = alloc::format!("Message {}", i);
        let response = conn1.echo(msg.as_bytes(), config.prefix.as_deref());
        crate::log!("  [{}] Echo: {}\n", i, core::str::from_utf8(&response).unwrap_or("<binary>"));
    }
    
    // Binary data test
    crate::log!("\n[ECHO] Binary data test:\n");
    let binary_data: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                  0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let response_binary = conn2.echo(&binary_data, None);
    crate::log!("[ECHO] Sent {} bytes of binary data\n", binary_data.len());
    crate::log!("[ECHO] Received {} bytes back\n", response_binary.len());
    
    if response_binary == binary_data {
        crate::log!("[ECHO] Binary data integrity verified ✓\n");
    } else {
        crate::log!("[ECHO] WARNING: Binary data mismatch!\n");
    }
    
    // Close connections
    conn1.close();
    conn2.close();
    
    // Print statistics
    let (conns, bytes, errors, active) = stats();
    crate::log!("\n[ECHO] Server Statistics:\n");
    crate::log!("       Total connections: {}\n", conns);
    crate::log!("       Active connections: {}\n", active);
    crate::log!("       Bytes echoed: {}\n", bytes);
    crate::log!("       Errors: {}\n", errors);
    
    RUNNING.store(false, Ordering::SeqCst);
    
    crate::log!("\n[ECHO] Echo server demo completed successfully\n");
    crate::log!("================================================================================\n\n");
    
    DemoResult::Success
}
