// ============================================================================
// kernel/src/net/api/config.rs - ネットワーク設定・統計の取得
// ============================================================================
//! ネットワーク設定スナップショットと統計情報の取得。
//!
//! `NetworkStack` からIPアドレス、MAC、サブネットマスク、ゲートウェイ、
//! パケットカウンタなどを安全に読み取る関数を提供する。

use core::sync::atomic::Ordering;
use crate::net::runtime::stack;
use crate::sync::PoisonLock;

/// Network configuration snapshot for shell commands.
#[derive(Debug, Clone)]
pub struct NetworkConfigSnapshot {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub mac: [u8; 6],
}

/// Network statistics snapshot for shell commands.
#[derive(Debug, Clone, Copy)]
pub struct NetworkStatsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
}

// Fallback stats used if stack access fails.
static NETWORK_STATS: PoisonLock<NetworkStatsSnapshot> = PoisonLock::new(NetworkStatsSnapshot {
    rx_packets: 0,
    tx_packets: 0,
    rx_bytes: 0,
    tx_bytes: 0,
    rx_errors: 0,
    rx_dropped: 0,
});

pub fn get_network_config() -> Option<NetworkConfigSnapshot> {
    match stack::stack().lock() {
        Ok(guard) => guard.as_ref().map(|stack_guard| {
            let cfg = stack_guard.config();
            NetworkConfigSnapshot {
                ip: *cfg.ipv4.address.as_bytes(),
                netmask: *cfg.ipv4.subnet_mask.as_bytes(),
                gateway: *cfg.ipv4.gateway.as_bytes(),
                mac: *cfg.mac.as_bytes(),
            }
        }),
        Err(_) => {
            log::error!("[NET] Stack lock poisoned (get_network_config)");
            None
        }
    }
}

pub fn get_network_stats() -> Option<NetworkStatsSnapshot> {
    match stack::stack().lock() {
        Ok(guard) => {
            if let Some(stack_guard) = guard.as_ref() {
                let stats = stack_guard.stats();
                return Some(NetworkStatsSnapshot {
                    rx_packets: stats.rx_packets.load(Ordering::Relaxed),
                    tx_packets: stats.tx_packets.load(Ordering::Relaxed),
                    rx_bytes: stats.rx_bytes.load(Ordering::Relaxed),
                    tx_bytes: stats.tx_bytes.load(Ordering::Relaxed),
                    rx_errors: stats.rx_errors.load(Ordering::Relaxed),
                    rx_dropped: stats.rx_dropped.load(Ordering::Relaxed),
                });
            }
        }
        Err(_) => {
            log::error!("[NET] Stack lock poisoned (get_network_stats)");
            return None;
        }
    }

    let stats = match NETWORK_STATS.lock() {
        Ok(guard) => *guard,
        Err(_) => NetworkStatsSnapshot {
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_errors: 0,
            rx_dropped: 0,
        },
    };
    Some(stats)
}
