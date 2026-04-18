// ============================================================================
// kernel/src/net/api/connections.rs - TCP/UDP接続情報・ARP操作
// ============================================================================
//! TCP接続一覧、UDPソケット一覧、ARPキャッシュの取得・操作。

use alloc::string::String;
use alloc::vec::Vec;

use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::runtime::NetRuntimeHandle;

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
    runtime: NetRuntimeHandle,
    result_slot: Arc<PoisonLock<Option<Vec<ArpCacheEntry>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl GetArpCacheFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for GetArpCacheFuture {
    type Output = Vec<ArpCacheEntry>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.sent {
            let mut enqueue = crate::net::runtime::command::send_command_in(
                this.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::GetArpCache {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                }),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(Vec::new()),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::command::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub fn get_arp_cache_in(runtime: NetRuntimeHandle) -> GetArpCacheFuture {
    GetArpCacheFuture::new(runtime)
}

pub fn enqueue_arp_cache_insert_in(runtime: NetRuntimeHandle, ip: Ipv4Address, mac: MacAddress) {
    crate::net::runtime::command::enqueue_command_ignore_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::ArpInsert {
            ip: *ip.as_bytes(),
            mac: *mac.as_bytes(),
        }),
    );
}

/// 非同期UDPエンドポイント一覧取得Future
pub struct GetUdpEndpointsFuture {
    runtime: NetRuntimeHandle,
    result_slot: Arc<PoisonLock<Option<Vec<UdpEndpointInfo>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl GetUdpEndpointsFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for GetUdpEndpointsFuture {
    type Output = Vec<UdpEndpointInfo>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.sent {
            let mut enqueue = crate::net::runtime::command::send_command_in(
                this.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::GetUdpEndpoints {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                }),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(Vec::new()),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::command::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub fn get_udp_endpoints_in(runtime: NetRuntimeHandle) -> GetUdpEndpointsFuture {
    GetUdpEndpointsFuture::new(runtime)
}

/// 非同期TCP接続一覧取得Future
pub struct GetTcpConnectionsFuture {
    runtime: NetRuntimeHandle,
    result_slot: Arc<PoisonLock<Option<Vec<TcpConnectionInfo>>>>,
    waker: Arc<AtomicWaker>,
    sent: bool,
}

impl GetTcpConnectionsFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
            result_slot: Arc::new(PoisonLock::new(None)),
            waker: Arc::new(AtomicWaker::new()),
            sent: false,
        }
    }
}

impl Future for GetTcpConnectionsFuture {
    type Output = Vec<TcpConnectionInfo>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.sent {
            let mut enqueue = crate::net::runtime::command::send_command_in(
                this.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::GetTcpConnections {
                    result_slot: this.result_slot.clone(),
                    waker: this.waker.clone(),
                }),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(Vec::new()),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::command::poll_command_result(&this.result_slot, &this.waker, cx)
    }
}

pub fn get_tcp_connections_in(runtime: NetRuntimeHandle) -> GetTcpConnectionsFuture {
    GetTcpConnectionsFuture::new(runtime)
}

#[cfg(test)]
mod tests {
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn connection_queries_complete_with_event_task() {
        let tcp = {
            crate::net::runtime::command::reset_command_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output =
                    super::get_tcp_connections_in(crate::net::runtime::default_runtime()).await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::runtime::command_loop::runtime_command_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::runtime::command::reset_command_system_for_tests();
            output.expect("get_tcp_connections test timed out")
        };
        let udp = {
            crate::net::runtime::command::reset_command_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output =
                    super::get_udp_endpoints_in(crate::net::runtime::default_runtime()).await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::runtime::command_loop::runtime_command_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::runtime::command::reset_command_system_for_tests();
            output.expect("get_udp_endpoints test timed out")
        };
        let arp = {
            crate::net::runtime::command::reset_command_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output = super::get_arp_cache_in(crate::net::runtime::default_runtime()).await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::runtime::command_loop::runtime_command_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::runtime::command::reset_command_system_for_tests();
            output.expect("get_arp_cache test timed out")
        };

        assert!(tcp.is_empty());
        assert!(udp.is_empty());
        assert!(arp.is_empty());
    }
}
