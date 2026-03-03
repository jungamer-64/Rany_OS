// ============================================================================
// kernel/src/net/api/config.rs - ネットワーク設定・統計の取得
// ============================================================================
//! ネットワーク設定スナップショットと統計情報の取得。
//!
//! `NetworkStack` からIPアドレス、MAC、サブネットマスク、ゲートウェイ、
//! パケットカウンタなどを安全に読み取る関数を提供する。
//!
//! ## 非同期API（推奨）
//! `get_network_config_async()` / `get_network_stats_async()` は
//! イベントキュー経由でスタックにアクセスし、同期ロックを回避する。

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll};
use alloc::sync::Arc;
use crate::net::runtime::stack;
use crate::sync::PoisonLock;
use crate::sync::atomic_waker::AtomicWaker;

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

/// 同期ネットワーク設定取得（非推奨：get_network_config_async を使用してください）
///
/// `stack().lock()` で同期ロックを取得するため、asyncコンテキストでの
/// 使用はデッドロックリスクがある。
#[deprecated(note = "use get_network_config_async() instead")]
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

/// 同期ネットワーク統計取得（非推奨：get_network_stats_async を使用してください）
#[deprecated(note = "use get_network_stats_async() instead")]
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

// ============================================================================
// 非同期API（推奨）
// ============================================================================

/// 非同期ネットワーク設定取得Future
///
/// イベントキュー経由でスタックにアクセスし、同期ロックを回避する。
pub struct GetConfigFuture {
    result_slot: Arc<PoisonLock<Option<Option<NetworkConfigSnapshot>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl GetConfigFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for GetConfigFuture {
    type Output = Option<NetworkConfigSnapshot>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            // イベントキュー経由でconfig取得を要求
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncGetConfig {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        // 結果をチェック
        if let Ok(slot) = this.result_slot.lock() {
            if let Some(result) = slot.as_ref() {
                return Poll::Ready(result.clone());
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期ネットワーク設定取得（推奨API）
///
/// イベントキュー経由でスタックにアクセスするため、
/// 同期ロック取得を完全に回避する。
///
/// # 使用例
/// ```ignore
/// let config = get_network_config_async().await;
/// ```
pub fn get_network_config_async() -> GetConfigFuture {
    GetConfigFuture::new()
}

/// 非同期ネットワーク統計取得Future
pub struct GetStatsFuture {
    result_slot: Arc<PoisonLock<Option<Option<NetworkStatsSnapshot>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl GetStatsFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for GetStatsFuture {
    type Output = Option<NetworkStatsSnapshot>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncGetStats {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        if let Ok(slot) = this.result_slot.lock() {
            if let Some(result) = slot.as_ref() {
                return Poll::Ready(result.clone());
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期ネットワーク統計取得（推奨API）
///
/// # 使用例
/// ```ignore
/// let stats = get_network_stats_async().await;
/// ```
pub fn get_network_stats_async() -> GetStatsFuture {
    GetStatsFuture::new()
}
