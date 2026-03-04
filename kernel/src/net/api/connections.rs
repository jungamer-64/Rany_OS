// ============================================================================
// kernel/src/net/api/connections.rs - TCP/UDP接続情報・ARP操作
// ============================================================================
//! TCP接続一覧、UDPソケット一覧、ARPキャッシュの取得・操作。

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::endpoint::{TcpConnectionState, tcb_table};
use crate::net::runtime::stack;

extern crate alloc;

/// TCP connection info for netstat.
#[derive(Debug, Clone)]
pub struct TcpConnectionInfo {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
}

/// UDP socket info for netstat.
#[derive(Debug, Clone)]
pub struct UdpEndpointInfo {
    pub local_addr: String,
    pub remote_addr: String,
}

/// ARP cache entry.
#[derive(Debug, Clone)]
pub struct ArpCacheEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub complete: bool,
}

/// TCP接続一覧取得（読み取り専用・tcb_table参照）
///
/// `tcb_table()` から接続スナップショットを取得する。ネットワークスタックロックは使用しない。
pub fn get_tcp_connections() -> Option<Vec<TcpConnectionInfo>> {
    let snapshots = tcb_table().list_connections();
    if snapshots.is_empty() {
        return None;
    }

    let connections = snapshots
        .into_iter()
        .map(|snap| {
            let state = match snap.state {
                TcpConnectionState::Closed => "CLOSED",
                TcpConnectionState::Listen => "LISTEN",
                TcpConnectionState::SynSent => "SYN_SENT",
                TcpConnectionState::SynReceived => "SYN_RCVD",
                TcpConnectionState::Established => "ESTABLISHED",
                TcpConnectionState::FinWait1 => "FIN_WAIT1",
                TcpConnectionState::FinWait2 => "FIN_WAIT2",
                TcpConnectionState::CloseWait => "CLOSE_WAIT",
                TcpConnectionState::Closing => "CLOSING",
                TcpConnectionState::LastAck => "LAST_ACK",
                TcpConnectionState::TimeWait => "TIME_WAIT",
            };
            TcpConnectionInfo {
                local_addr: format!("{}", snap.local),
                remote_addr: format!("{}", snap.remote),
                state: String::from(state),
            }
        })
        .collect();

    Some(connections)
}

/// UDPエンドポイント一覧取得（読み取り専用・短命ロック）
///
/// ネットワークスタックロックを短時間取得し、UDPエンドポイント情報をスナップショットする。
///
/// # 非推奨
/// asyncコンテキストでは [`get_udp_endpoints_async()`] を使用すること。
#[deprecated(note = "Use get_udp_endpoints_async() for async contexts. Sync version acquires NETWORK_STACK lock.")]
pub fn get_udp_endpoints() -> Option<Vec<UdpEndpointInfo>> {
    match stack::stack().lock() {
        Ok(guard) => {
            if let Some(ref stack_guard) = guard.as_ref() {
                let snapshots = stack_guard.list_udp_endpoints();
                if snapshots.is_empty() {
                    return None;
                }
                return Some(
                    snapshots
                        .into_iter()
                        .map(|snap| UdpEndpointInfo {
                            local_addr: format!("*:{}", snap.local_port),
                            remote_addr: String::from("*:*"),
                        })
                        .collect(),
                );
            }
        }
        Err(_) => {
            log::error!("[NET] Stack lock poisoned (get_udp_endpoints)");
        }
    }
    None
}

/// ARPキャッシュ取得（読み取り専用・短命ロック）
///
/// ネットワークスタックロックを短時間取得し、ARPエントリをスナップショットする。
///
/// # 非推奨
/// asyncコンテキストでは [`get_arp_cache_async()`] を使用すること。
#[deprecated(note = "Use get_arp_cache_async() for async contexts. Sync version acquires NETWORK_STACK lock.")]
pub fn get_arp_cache() -> Option<Vec<ArpCacheEntry>> {
    match stack::stack().lock() {
        Ok(guard) => {
            if let Some(stack_guard) = guard.as_ref() {
                let arp_entries = stack_guard.arp_cache();
                let entries: Vec<ArpCacheEntry> = arp_entries
                    .iter()
                    .map(|(ip, mac)| ArpCacheEntry {
                        ip: *ip.as_bytes(),
                        mac: *mac.as_bytes(),
                        complete: true,
                    })
                    .collect();
                if !entries.is_empty() {
                    return Some(entries);
                }
            }
        }
        Err(_) => log::error!("[NET] Stack lock poisoned (get_arp_cache) - returning demo output"),
    }
    None
}

/// ARPキャッシュ挿入（短命ロック）
///
/// ネットワークスタックロックを短時間取得し、ARPエントリを挿入する。
///
/// # 非推奨
/// asyncコンテキストでは [`arp_cache_insert_async()`] を使用すること。
#[deprecated(note = "Use arp_cache_insert_async() for async contexts. Sync version acquires NETWORK_STACK lock.")]
pub fn arp_cache_insert(ip: Ipv4Address, mac: MacAddress) -> bool {
    if let Ok(mut guard) = stack::stack().lock() {
        if let Some(stack_ref) = guard.as_mut() {
            let now = crate::time::get_uptime_ms();
            stack_ref.arp_cache_insert(ip, mac, now);
            return true;
        }
    }
    false
}

// ============================================================================
// 非同期API（推奨）
// ============================================================================

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use alloc::sync::Arc;
use crate::sync::PoisonLock;
use crate::sync::atomic_waker::AtomicWaker;

/// 非同期ARPキャッシュ取得Future
pub struct GetArpCacheFuture {
    result_slot: Arc<PoisonLock<Option<Vec<ArpCacheEntry>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl GetArpCacheFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for GetArpCacheFuture {
    type Output = Vec<ArpCacheEntry>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncGetArpCache {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        if let Ok(slot) = this.result_slot.lock() {
            if let Some(entries) = slot.as_ref() {
                return Poll::Ready(entries.clone());
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期ARPキャッシュ取得（推奨API）
///
/// イベントキュー経由でスタックにアクセスするため、
/// 同期ロック取得を完全に回避する。
///
/// # 使用例
/// ```ignore
/// let entries = get_arp_cache_async().await;
/// ```
pub fn get_arp_cache_async() -> GetArpCacheFuture {
    GetArpCacheFuture::new()
}

/// 非同期ARPキャッシュ挿入（推奨API）
///
/// イベントキュー経由でスタックにARP挿入イベントを送出する。
pub fn arp_cache_insert_async(ip: Ipv4Address, mac: MacAddress) {
    crate::net::l4::endpoint::event::send_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::AsyncArpInsert {
            ip: *ip.as_bytes(),
            mac: *mac.as_bytes(),
        },
    );
}

/// 非同期UDPエンドポイント一覧取得Future
pub struct GetUdpEndpointsFuture {
    result_slot: Arc<PoisonLock<Option<Vec<UdpEndpointInfo>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl GetUdpEndpointsFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for GetUdpEndpointsFuture {
    type Output = Vec<UdpEndpointInfo>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncGetUdpEndpoints {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        if let Ok(slot) = this.result_slot.lock() {
            if let Some(endpoints) = slot.as_ref() {
                return Poll::Ready(endpoints.clone());
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期UDPエンドポイント一覧取得（推奨API）
pub fn get_udp_endpoints_async() -> GetUdpEndpointsFuture {
    GetUdpEndpointsFuture::new()
}

/// 非同期TCP接続一覧取得Future
pub struct GetTcpConnectionsFuture {
    result_slot: Arc<PoisonLock<Option<Vec<TcpConnectionInfo>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl GetTcpConnectionsFuture {
    fn new() -> Self {
        Self {
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for GetTcpConnectionsFuture {
    type Output = Vec<TcpConnectionInfo>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.sent {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::AsyncGetTcpConnections {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            this.waker.register(cx.waker());
            this.sent = true;
            return Poll::Pending;
        }

        if let Ok(slot) = this.result_slot.lock() {
            if let Some(connections) = slot.as_ref() {
                return Poll::Ready(connections.clone());
            }
        }

        this.waker.register(cx.waker());
        Poll::Pending
    }
}

/// 非同期TCP接続一覧取得（推奨API）
///
/// # 使用例
/// ```ignore
/// let connections = get_tcp_connections_async().await;
/// ```
pub fn get_tcp_connections_async() -> GetTcpConnectionsFuture {
    GetTcpConnectionsFuture::new()
}
