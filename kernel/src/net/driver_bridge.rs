// ============================================================================
// src/net/driver_bridge.rs - VirtIO-Net <-> NetworkStack Bridge
// ============================================================================
//!
//! VirtIO-NetドライバとNetworkStackを接続するブリッジモジュール。
//! 送信コールバック設定と受信パケット処理を統合します。

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use super::ethernet::MacAddress;
use super::ipv4::{Ipv4Address, Ipv4Config};
use super::stack::{self, NetworkConfig, NetworkStack};
use crate::io::virtio::{VirtioNetDevice, VirtioNetHeader, with_virtio_net};
use crate::sync::PoisonLock;
use alloc::vec::Vec;
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
static RX_BUFFER: PoisonLock<[u8; 2048]> = PoisonLock::new([0u8; 2048]);

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
    let header_bytes: &[u8] = &crate::util::struct_as_bytes(&header)[..VirtioNetHeader::SIZE];
    tx_buffer[..VirtioNetHeader::SIZE].copy_from_slice(header_bytes);
    tx_buffer[VirtioNetHeader::SIZE..].copy_from_slice(data);

    // 非同期送信Futureを作成
    // Note: 完全な非同期実行にはasync executorとの統合が必要
    // 現時点ではFutureを作成し、送信リクエストをキューに登録する
    // 実際の送信完了はデバイスの割り込み処理で確認される
    let _send_future = device.send_async(&tx_buffer);

    // send_asyncはFutureを返すが、内部でVirtQueueにディスクリプタを追加し
    // デバイスに通知を送る
    // ここではfire-and-forgetパターンで送信リクエストのみ発行

    // デバッグ用：パケット送信ログ
    #[cfg(debug_assertions)]
    if data.len() >= 14 {
        crate::serial_println!(
            "[NET TX] {} bytes queued, dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            data.len(),
            data[0],
            data[1],
            data[2],
            data[3],
            data[4],
            data[5]
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
            ethernet_data[6],
            ethernet_data[7],
            ethernet_data[8],
            ethernet_data[9],
            ethernet_data[10],
            ethernet_data[11]
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
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        )
    })
    .unwrap_or_else(|| {
        // Default MAC for QEMU user mode networking
        MacAddress::from_octets(0x52, 0x54, 0x00, 0x12, 0x34, 0x56)
    });

    // Initialize NetworkStack with configuration
    let config = NetworkConfig {
        mac,
        ipv4: Ipv4Config {
            address: Ipv4Address::new([10, 0, 2, 15]), // QEMU default
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::new([10, 0, 2, 2]), // QEMU gateway
            dns: Some(Ipv4Address::new([10, 0, 2, 3])),
        },
        icmp_echo_enabled: true,
    };

    // Initialize the stack
    stack::init(config);

    // Set transmit callback
    match stack::stack().lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.set_transmit_fn(virtio_transmit);
            }
        }
        Err(_) => log::error!("[NET BRIDGE] Stack poisoned - transmit fn not set"),
    }

    crate::serial_println!("[NET BRIDGE] Bridge initialized");
    crate::serial_println!(
        "  MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.as_bytes()[0],
        mac.as_bytes()[1],
        mac.as_bytes()[2],
        mac.as_bytes()[3],
        mac.as_bytes()[4],
        mac.as_bytes()[5]
    );
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
    match stack::stack().lock() {
        Ok(guard) => {
            let stack = match guard.as_ref() {
                Some(s) => s,
                None => return None,
            };

            let config = stack.config();

            Some(super::NetworkConfigSnapshot {
                ip: *config.ipv4.address.as_bytes(),
                netmask: *config.ipv4.subnet_mask.as_bytes(),
                gateway: *config.ipv4.gateway.as_bytes(),
                mac: *config.mac.as_bytes(),
            })
        }
        Err(_) => {
            log::error!("[NET BRIDGE] Stack poisoned (get_real_config)");
            None
        }
    }
}

/// Get real network statistics from NetworkStack
pub fn get_real_stats() -> Option<super::NetworkStatsSnapshot> {
    match stack::stack().lock() {
        Ok(guard) => {
            let stack = match guard.as_ref() {
                Some(s) => s,
                None => return Vec::new(),
            };

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
        Err(_) => {
            log::error!("[NET BRIDGE] Stack poisoned (get_real_stats)");
            None
        }
    }
}

/// Send ICMP echo via real NetworkStack
pub fn send_real_icmp_echo(target: [u8; 4], seq: u16) -> Result<u64, &'static str> {
    match stack::stack().lock() {
        Ok(mut guard) => match guard.as_mut() {
            Some(stack) => {
                let target_ip = Ipv4Address::new(target);
                stack
                    .send_icmp_echo_request(target_ip, seq)
                    .map_err(|_| "Failed to send ICMP echo request")
            }
            None => Err("Network stack not initialized"),
        },
        Err(_) => {
            log::error!("[NET BRIDGE] Stack poisoned (send_real_icmp_echo)");
            Err("Network stack not initialized")
        }
    }
}

/// Get ARP cache entries from real NetworkStack
pub fn get_real_arp_cache() -> Vec<super::ArpCacheEntry> {
    match stack::stack().lock() {
        Ok(guard) => match guard.as_ref() {
            Some(stack) => {
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
            None => Vec::new(),
        },
        Err(_) => {
            log::error!("[NET BRIDGE] Stack poisoned (get_real_arp_cache)");
            Vec::new()
        }
    } Vec::new()
        }
    }
}
