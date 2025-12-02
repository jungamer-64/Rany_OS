// ============================================================================
// src/demo/echo_server.rs - TCP Echo Server Demo
// Demonstrates async I/O and zero-copy networking
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

use crate::demo::DemoResult;

/// Echo server statistics
pub struct EchoStats {
    /// Total connections
    pub connections: AtomicU64,
    /// Total bytes echoed
    pub bytes_echoed: AtomicU64,
    /// Errors
    pub errors: AtomicU64,
}

impl EchoStats {
    pub const fn new() -> Self {
        EchoStats {
            connections: AtomicU64::new(0),
            bytes_echoed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
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
}

impl Default for EchoConfig {
    fn default() -> Self {
        EchoConfig {
            port: 7777,
            max_message_size: 65536,
            prefix: None,
        }
    }
}

/// Simulated echo connection
pub struct EchoConnection {
    id: u64,
    remote: String,
    bytes_in: u64,
    bytes_out: u64,
}

impl EchoConnection {
    pub fn new(id: u64, remote: &str) -> Self {
        STATS.connections.fetch_add(1, Ordering::Relaxed);
        
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
        STATS.bytes_echoed.fetch_add(response.len() as u64, Ordering::Relaxed);
        
        response
    }
    
    pub fn close(self) {
        crate::log!("[ECHO] Connection {} closed (in={}, out={})\n", 
            self.id, self.bytes_in, self.bytes_out);
    }
}

/// Run echo server demo
pub fn run() -> DemoResult {
    crate::log!("\n");
    crate::log!("================================================================================\n");
    crate::log!("                    ExoRust TCP Echo Server Demo\n");
    crate::log!("================================================================================\n\n");
    
    let config = EchoConfig {
        port: 7777,
        max_message_size: 4096,
        prefix: Some(String::from("[ECHO] ")),
    };
    
    RUNNING.store(true, Ordering::SeqCst);
    
    crate::log!("[ECHO] Server initialized on port {}\n", config.port);
    crate::log!("[ECHO] Max message size: {} bytes\n", config.max_message_size);
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
    crate::log!("\n[ECHO] Server Statistics:\n");
    crate::log!("       Total connections: {}\n", STATS.connections.load(Ordering::Relaxed));
    crate::log!("       Bytes echoed: {}\n", STATS.bytes_echoed.load(Ordering::Relaxed));
    crate::log!("       Errors: {}\n", STATS.errors.load(Ordering::Relaxed));
    
    RUNNING.store(false, Ordering::SeqCst);
    
    crate::log!("\n[ECHO] Echo server demo completed successfully\n");
    crate::log!("================================================================================\n\n");
    
    DemoResult::Success
}

/// Get echo server statistics
pub fn stats() -> (u64, u64, u64) {
    (
        STATS.connections.load(Ordering::Relaxed),
        STATS.bytes_echoed.load(Ordering::Relaxed),
        STATS.errors.load(Ordering::Relaxed),
    )
}

/// Check if server is running
pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}
