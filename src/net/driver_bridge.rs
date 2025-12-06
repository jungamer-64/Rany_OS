// ============================================================================
// src/net/driver_bridge.rs - VirtIO-Net <-> NetworkStack Bridge
// ============================================================================
//!
//! VirtIO-NetドライバとNetworkStackを接続するブリッジモジュール。
//! 送信コールバック設定と受信パケット処理を統合します。

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use crate::io::virtio::{with_virtio_net, VirtioNetDevice, VirtioNetHeader};
use super::stack::{self, NetworkStack, NetworkConfig};
use super::ethernet::MacAddress;
use super::ipv4::{Ipv4Address, Ipv4Config};
use alloc::vec::Vec;
use spin::Mutex;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

extern crate alloc;

// ============================================================================
// Bridge State
// ============================================================================

/// Bridge initialization state
static BRIDGE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Packet transmission counter
static TX_PACKETS: AtomicU64 = AtomicU64::new(0);

/// Packet reception counter  
static RX_PACKETS: AtomicU64 = AtomicU64::new(0);

/// Receive buffer for processing
static RX_BUFFER: Mutex<[u8; 2048]> = Mutex::new([0u8; 2048]);

// ============================================================================
// Transmit Bridge
// ============================================================================

/// Transmit callback for NetworkStack
/// This is called when NetworkStack needs to send a packet
fn virtio_transmit(data: &[u8]) -> bool {
    // VirtIO-Netデバイスが利用可能か確認
    let result = with_virtio_net(|device| {
        // 簡単な同期送信を試みる
        // 実際にはsend_asyncを使用するが、ここではシンプルな実装
        transmit_packet(device, data)
    });
    
    match result {
        Some(Ok(())) => {
            TX_PACKETS.fetch_add(1, Ordering::Relaxed);
            true
        }
        Some(Err(_)) => {
            crate::serial_println!("[NET BRIDGE] Transmit error");
            false
        }
        None => {
            // VirtIO-Netが初期化されていない場合はデバッグ出力
            #[cfg(debug_assertions)]
            crate::serial_println!("[NET BRIDGE] VirtIO-Net not initialized");
            false
        }
    }
}

/// Low-level packet transmission via VirtIO-Net
fn transmit_packet(device: &VirtioNetDevice, data: &[u8]) -> Result<(), &'static str> {
    // VirtIO-Netヘッダを先頭に追加
    let mut tx_buffer = alloc::vec![0u8; VirtioNetHeader::SIZE + data.len()];
    
    // ヘッダ（デフォルト値でOK）
    let header = VirtioNetHeader::new_tx();
    let header_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &header as *const _ as *const u8,
            VirtioNetHeader::SIZE
        )
    };
    tx_buffer[..VirtioNetHeader::SIZE].copy_from_slice(header_bytes);
    tx_buffer[VirtioNetHeader::SIZE..].copy_from_slice(data);
    
    // 同期送信（実際はasyncが好ましい）
    // 現在の実装ではTXキューに直接追加
    // TODO: 非同期送信の完全実装
    
    let _ = device; // 現在は未使用（キュー操作が必要）
    
    // デバッグ用：パケット送信ログ
    #[cfg(debug_assertions)]
    if data.len() >= 14 {
        crate::serial_println!(
            "[NET TX] {} bytes, dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            data.len(),
            data[0], data[1], data[2], data[3], data[4], data[5]
        );
    }
    
    Ok(())
}

// ============================================================================
// Receive Bridge
// ============================================================================

/// Process a received packet from VirtIO-Net
/// Call this from the interrupt handler or polling loop
pub fn process_received_packet(data: &[u8]) {
    // VirtIO-Netヘッダをスキップ
    if data.len() <= VirtioNetHeader::SIZE {
        return;
    }
    
    let ethernet_data = &data[VirtioNetHeader::SIZE..];
    
    RX_PACKETS.fetch_add(1, Ordering::Relaxed);
    
    // NetworkStackに渡す
    stack::receive(ethernet_data);
    
    #[cfg(debug_assertions)]
    if ethernet_data.len() >= 14 {
        crate::serial_println!(
            "[NET RX] {} bytes, src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            ethernet_data.len(),
            ethernet_data[6], ethernet_data[7], ethernet_data[8],
            ethernet_data[9], ethernet_data[10], ethernet_data[11]
        );
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the network bridge
/// Connects VirtIO-Net driver to NetworkStack
pub fn init_bridge() -> Result<(), &'static str> {
    if BRIDGE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(()); // Already initialized
    }
    
    crate::serial_println!("[NET BRIDGE] Initializing VirtIO-Net <-> NetworkStack bridge...");
    
    // Get MAC address from VirtIO-Net if available
    let mac = with_virtio_net(|device| {
        let mac_bytes = device.mac_address();
        MacAddress::from_octets(
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5]
        )
    }).unwrap_or_else(|| {
        // Default MAC for QEMU user mode networking
        MacAddress::from_octets(0x52, 0x54, 0x00, 0x12, 0x34, 0x56)
    });
    
    // Initialize NetworkStack with configuration
    let config = NetworkConfig {
        mac,
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 2, 15]),  // QEMU default
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::new([10, 0, 2, 2]),  // QEMU gateway
            dns: Some(Ipv4Address::new([10, 0, 2, 3])),
        },
        icmp_echo_enabled: true,
    };
    
    // Initialize the stack
    stack::init(config);
    
    // Set transmit callback
    if let Some(ref stack) = *stack::stack().lock() {
        stack.set_transmit_fn(virtio_transmit);
    }
    
    crate::serial_println!("[NET BRIDGE] Bridge initialized");
    crate::serial_println!("  MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.as_bytes()[0], mac.as_bytes()[1], mac.as_bytes()[2],
        mac.as_bytes()[3], mac.as_bytes()[4], mac.as_bytes()[5]);
    crate::serial_println!("  IP: 10.0.2.15");
    
    Ok(())
}

/// Check if bridge is initialized
pub fn is_initialized() -> bool {
    BRIDGE_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// Shell API Integration
// ============================================================================

/// Get bridge statistics
pub fn get_bridge_stats() -> BridgeStats {
    BridgeStats {
        tx_packets: TX_PACKETS.load(Ordering::Relaxed),
        rx_packets: RX_PACKETS.load(Ordering::Relaxed),
        initialized: BRIDGE_INITIALIZED.load(Ordering::Acquire),
    }
}

/// Bridge statistics
#[derive(Debug, Clone, Copy)]
pub struct BridgeStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub initialized: bool,
}

/// Get real network configuration from NetworkStack
pub fn get_real_config() -> Option<super::NetworkConfigSnapshot> {
    let stack_guard = stack::stack().lock();
    let stack = stack_guard.as_ref()?;
    
    let config = stack.config();
    
    Some(super::NetworkConfigSnapshot {
        ip: *config.ipv4.address.as_bytes(),
        netmask: *config.ipv4.subnet_mask.as_bytes(),
        gateway: *config.ipv4.gateway.as_bytes(),
        mac: *config.mac.as_bytes(),
    })
}

/// Get real network statistics from NetworkStack
pub fn get_real_stats() -> Option<super::NetworkStatsSnapshot> {
    let stack_guard = stack::stack().lock();
    let stack = stack_guard.as_ref()?;
    
    let stats = stack.stats();
    
    Some(super::NetworkStatsSnapshot {
        rx_packets: stats.rx_packets.load(Ordering::Relaxed),
        tx_packets: stats.tx_packets.load(Ordering::Relaxed),
        rx_bytes: stats.rx_bytes.load(Ordering::Relaxed),
        tx_bytes: stats.tx_bytes.load(Ordering::Relaxed),
        rx_errors: stats.rx_errors.load(Ordering::Relaxed),
        rx_dropped: stats.rx_dropped.load(Ordering::Relaxed),
    })
}

/// Send ICMP echo via real NetworkStack
pub fn send_real_icmp_echo(target: [u8; 4], seq: u16) -> Result<u64, &'static str> {
    let stack_guard = stack::stack().lock();
    let stack = stack_guard.as_ref().ok_or("Network stack not initialized")?;
    
    let target_ip = Ipv4Address::new(target);
    
    stack.send_icmp_echo_request(target_ip, seq)
        .map_err(|_| "Failed to send ICMP echo request")
}

/// Get ARP cache entries from real NetworkStack
pub fn get_real_arp_cache() -> Vec<super::ArpCacheEntry> {
    let stack_guard = stack::stack().lock();
    let stack = match stack_guard.as_ref() {
        Some(s) => s,
        None => return Vec::new(),
    };
    
    let arp_cache = stack.arp_cache();
    let mut entries = Vec::new();
    
    for (ip, mac) in arp_cache {
        entries.push(super::ArpCacheEntry {
            ip: *ip.as_bytes(),
            mac: *mac.as_bytes(),
            complete: true,
        });
    }
    
    entries
}
