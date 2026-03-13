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
pub fn get_tcp_connections_sync() -> Option<Vec<TcpConnectionInfo>> {
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

// ============================================================================
// 非同期API（推奨）
// ============================================================================

use crate::sync::PoisonLock;
use crate::sync::atomic_waker::AtomicWaker;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

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
            let mut enqueue = crate::net::l4::endpoint::event::send_event(
                crate::net::l4::endpoint::event::NetworkEvent::GetArpCache {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(Vec::new()),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::stack::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

/// 非同期ARPキャッシュ取得（推奨API）
///
/// イベントキュー経由でスタックにアクセスするため、
/// 同期ロック取得を完全に回避する。
///
/// # 使用例
/// ```ignore
/// let entries = get_arp_cache().await;
/// ```
pub fn get_arp_cache() -> GetArpCacheFuture {
    GetArpCacheFuture::new()
}

/// 非同期ARPキャッシュ挿入（推奨API）
///
/// イベントキュー経由でスタックにARP挿入イベントを送出する。
pub fn enqueue_arp_cache_insert(ip: Ipv4Address, mac: MacAddress) {
    crate::net::l4::endpoint::event::enqueue_event_ignore(
        crate::net::l4::endpoint::event::NetworkEvent::ArpInsert {
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
            let mut enqueue = crate::net::l4::endpoint::event::send_event(
                crate::net::l4::endpoint::event::NetworkEvent::GetUdpEndpoints {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(Vec::new()),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::stack::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

/// 非同期UDPエンドポイント一覧取得（推奨API）
pub fn get_udp_endpoints() -> GetUdpEndpointsFuture {
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
            let mut enqueue = crate::net::l4::endpoint::event::send_event(
                crate::net::l4::endpoint::event::NetworkEvent::GetTcpConnections {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                },
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(Vec::new()),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::stack::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

/// 非同期TCP接続一覧取得（推奨API）
///
/// # 使用例
/// ```ignore
/// let connections = get_tcp_connections().await;
/// ```
pub fn get_tcp_connections() -> GetTcpConnectionsFuture {
    GetTcpConnectionsFuture::new()
}

#[cfg(test)]
mod tests {
    #[test]
    fn connection_queries_complete_with_event_task() {
        let tcp = {
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output = super::get_tcp_connections().await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::l4::endpoint::tcp_rx::network_event_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            output.expect("get_tcp_connections test timed out")
        };
        let udp = {
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output = super::get_udp_endpoints().await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::l4::endpoint::tcp_rx::network_event_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            output.expect("get_udp_endpoints test timed out")
        };
        let arp = {
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output = super::get_arp_cache().await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::l4::endpoint::tcp_rx::network_event_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            output.expect("get_arp_cache test timed out")
        };

        assert!(tcp.is_empty());
        assert!(udp.is_empty());
        assert!(arp.is_empty());
    }
}
