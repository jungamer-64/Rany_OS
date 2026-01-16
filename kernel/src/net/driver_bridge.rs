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
use super::optimization::{BatchConfig, BatchProcessor};
use super::stack::{self, NetworkConfig, NetworkStack};
use crate::io::virtio::{VirtioNetDevice, with_virtio_net};
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

/// Batch Processor for RX
static BATCH_PROCESSOR: BatchProcessor = BatchProcessor::new(BatchConfig {
    max_batch_size: 64,
    max_delay_us: 50,
    min_pps_threshold: 1000,
    adaptive_batching: true,
});

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
            log::info!("[NET BRIDGE] Transmit error");
            false
        }
        None => {
            // VirtIO-Netが初期化されていない場合はデバッグ出力
            #[cfg(debug_assertions)]
            log::info!("[NET BRIDGE] VirtIO-Net not initialized");
            false
        }
    }
}

/// Low-level packet transmission via VirtIO-Net
fn transmit_packet(device: &VirtioNetDevice, data: &[u8]) -> Result<(), &'static str> {
    // Synchronously submit the packet using a DMA buffer so that the descriptor
    // is added and the device is notified immediately. The DMA buffer is
    // retained in the device's tx_inflight map and freed when the TX completion
    // is processed in the interrupt handler.
    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] transmit_packet called len={}\n", data.len()));

    match device.submit_tx(data) {
        Ok(()) => {
            if data.len() >= 14 {
                log::info!(
                    "[NET-TX] {} bytes queued, dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    data.len(),
                    data[0],
                    data[1],
                    data[2],
                    data[3],
                    data[4],
                    data[5]
                );
            } else {
                log::info!("[NET-TX] {} bytes queued", data.len());
            }
            Ok(())
        }
        Err(_) => {
            log::info!("[NET-TX] submit failed");
            Err("Failed to submit TX")
        },
    }
}

// ============================================================================
// Receive Bridge
// ============================================================================

/// Process a received payload from VirtIO-Net (compatibility wrapper)
/// Call this from older interrupt handlers or polling loops.
/// This delegates to the zero-copy path by allocating a PacketRef and handing it off.
// Compatibility wrapper `process_received_packet` has been removed.
// Use `process_received_packet_zero_copy` directly instead.


/// Process a completed RX buffer without copying: use the provided PacketRef (zero-copy)
pub fn process_received_packet_zero_copy(mut packet: crate::net::PacketRef, header_size: usize, payload_len: usize) {
    RX_PACKETS.fetch_add(1, Ordering::Relaxed);

    // Ensure view length covers header + payload
    packet.set_len(header_size + payload_len);

    // Skip the virtio header so the PacketRef points at the Ethernet frame
    if header_size > 0 {
        packet.advance(header_size);
    }

    // Enqueue to batch processor (zero-copy)
    if let Some(batch) = BATCH_PROCESSOR.enqueue(packet) {
        stack::receive_batch(batch);
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

    log::info!("[NET BRIDGE] Initializing VirtIO-Net <-> NetworkStack bridge...");

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

    log::info!("[NET BRIDGE] Bridge initialized");
    log::info!(
        "  MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.as_bytes()[0],
        mac.as_bytes()[1],
        mac.as_bytes()[2],
        mac.as_bytes()[3],
        mac.as_bytes()[4],
        mac.as_bytes()[5]
    );
    log::info!("  IP: 10.0.2.15");

    Ok(())
}

/// Check if bridge is initialized
pub fn is_initialized() -> bool {
    BRIDGE_INITIALIZED.load(Ordering::Acquire)
}

/// Check and flush batched packets if timeout occurred
/// Should be called periodically (e.g. from timer interrupt)
pub fn check_batch_timeout(current_tsc: u64, tsc_freq: u64) {
    if let Some(batch) = BATCH_PROCESSOR.check_timeout(current_tsc, tsc_freq) {
        stack::receive_batch(batch);
    }
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{mempool, stack};
    use crate::net::ipv4::{Ipv4PacketMut, Ipv4Address, IpProtocol};
    use crate::net::tcp::{TcpControlBlock, TcpState, SocketAddr as TcpSocketAddr, Ipv4Addr as TcpIpv4Addr};
    use alloc::vec::Vec;

    #[test_case]
    fn test_zero_copy_via_bridge() {
        // Initialize mempool and stack
        let _ = mempool::init_net_mempool(4);

        // Configure stack to use 127.0.0.1 for tests
        let mut config = super::NetworkConfig::default();
        config.ipv4.address = Ipv4Address::new([127, 0, 0, 1]);
        stack::init(config);

        // Prepare a TCB and register it in the global stack
        let local = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 1000);
        let remote = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 2000);

        let mut tcb = TcpControlBlock::new(local);
        tcb.remote_addr = Some(remote);
        tcb.state = TcpState::Established;
        tcb.rcv_nxt = 1;
        let tcb_arc = alloc::sync::Arc::new(PoisonLock::new(tcb));

        // Insert into stack's tcp connections
        match stack::stack().lock() {
            Ok(mut guard) => {
                if let Some(ref mut s) = *guard {
                    s.tcp.connections.insert((local, remote), tcb_arc.clone());
                }
            }
            Err(_) => panic!("Stack poisoned"),
        }

        // Build packet: virtio header + ethernet + IPv4 + TCP + payload
        let header_size = crate::io::virtio::net::VirtioNetHeader::SIZE;
        let payload = b"hello";
        let tcp_len = 20 + payload.len();
        let ip_total_len = 20 + tcp_len; // IP header + TCP + payload
        let eth_total_len = 14 + ip_total_len; // Ethernet frame length

        // Allocate packet buffer
        let mut packet = mempool::alloc_packet().expect("alloc packet");
        let buf = packet.data_mut();

        // Ensure buffer large enough
        let needed = header_size + eth_total_len;
        assert!(buf.len() >= needed, "Packet buffer too small for test");

        // Virtio header (zero)
        for i in 0..header_size { buf[i] = 0; }

        // Ethernet header
        let eth_off = header_size;
        buf[eth_off..eth_off + 6].copy_from_slice(&[0xff; 6]); // dst
        buf[eth_off + 6..eth_off + 12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
        buf[eth_off + 12..eth_off + 14].copy_from_slice(&[0x08, 0x00]); // EtherType = IPv4

        // IPv4 header
        let ip_off = eth_off + 14;
        let mut ipv4_mut = Ipv4PacketMut::new(&mut buf[ip_off..ip_off + 20]).expect("ipv4 mut");
        ipv4_mut
            .init_header()
            .set_source(Ipv4Address::new([127, 0, 0, 1]))
            .set_destination(Ipv4Address::new([127, 0, 0, 1]))
            .set_protocol(IpProtocol::Tcp)
            .set_identification(1);
        // Write TCP header and payload into IP payload
        let tcp_off = ip_off + 20;
        // Src port 2000, dst port 1000
        buf[tcp_off..tcp_off + 2].copy_from_slice(&2000u16.to_be_bytes());
        buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&1000u16.to_be_bytes());
        // Seq = 1
        buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&1u32.to_be_bytes());
        // Ack = 0
        buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&0u32.to_be_bytes());
        // Data offset = 5 (20 bytes), flags = 0
        let data_off_flags = ((5u16 << 12) | 0u16).to_be_bytes();
        buf[tcp_off + 12..tcp_off + 14].copy_from_slice(&data_off_flags);
        // Window
        buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&65535u16.to_be_bytes());
        // Payload
        buf[tcp_off + 20..tcp_off + 20 + payload.len()].copy_from_slice(payload);

        // Finalize IP header (set total length and checksum)
        ipv4_mut.finalize(tcp_len);

        // Set packet length (virtio header + ethernet frame)
        packet.set_len(header_size + eth_total_len);

        // Call bridge zero-copy entry
        process_received_packet_zero_copy(packet, header_size, eth_total_len);

        // Force a batch timeout to flush the packet into the stack
        check_batch_timeout(100_000, 1);

        // Now verify TCB received the payload zero-copy
        if let Ok(mut guard) = tcb_arc.lock() {
            assert!(!guard.recv_buffer.is_empty());
            let first = guard.recv_buffer.front().unwrap();
            assert_eq!(first.data(), payload);
        } else {
            panic!("TCB lock poisoned in test");
        }
    }
}

/// Get real network statistics from NetworkStack
pub fn get_real_stats() -> Option<super::NetworkStatsSnapshot> {
    match stack::stack().lock() {
        Ok(guard) => {
            let stack = match guard.as_ref() {
                Some(s) => s,
                None => return None,
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
    }
}
