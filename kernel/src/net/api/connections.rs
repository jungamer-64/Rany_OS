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
#[derive(Debug)]
pub struct TcpConnectionInfo {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
}

/// UDP socket info for netstat.
#[derive(Debug)]
pub struct UdpEndpointInfo {
    pub local_addr: String,
    pub remote_addr: String,
}

/// ARP cache entry.
#[derive(Debug)]
pub struct ArpCacheEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub complete: bool,
}

// ============================================================================
// 非同期API（推奨）
// ============================================================================

use crate::net::runtime::command::{CommandFuture, CommandReplyTicket, new_command_channel_in};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// 非同期ARPキャッシュ取得Future
pub struct GetArpCacheFuture {
    runtime: NetRuntimeHandle,
    reply: CommandReplyTicket<Vec<ArpCacheEntry>>,
    command_future: CommandFuture<Vec<ArpCacheEntry>>,
    sent: bool,
}

impl GetArpCacheFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        let (reply, command_future) = new_command_channel_in(runtime);
        Self {
            runtime,
            reply,
            command_future,
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
                crate::net::runtime::command::RuntimeCommand::Control(
                    crate::net::runtime::command::ControlCommand::GetArpCache { reply: this.reply },
                ),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(Vec::new()),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut this.command_future).poll(cx)
    }
}

pub fn get_arp_cache_in(runtime: NetRuntimeHandle) -> GetArpCacheFuture {
    GetArpCacheFuture::new(runtime)
}

pub fn enqueue_arp_cache_insert_in(runtime: NetRuntimeHandle, ip: Ipv4Address, mac: MacAddress) {
    crate::net::runtime::command::enqueue_command_ignore_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Control(
            crate::net::runtime::command::ControlCommand::ArpInsert {
                ip: *ip.as_bytes(),
                mac: *mac.as_bytes(),
            },
        ),
    );
}

/// 非同期UDPエンドポイント一覧取得Future
pub struct GetUdpEndpointsFuture {
    runtime: NetRuntimeHandle,
    reply: CommandReplyTicket<Vec<UdpEndpointInfo>>,
    command_future: CommandFuture<Vec<UdpEndpointInfo>>,
    sent: bool,
}

impl GetUdpEndpointsFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        let (reply, command_future) = new_command_channel_in(runtime);
        Self {
            runtime,
            reply,
            command_future,
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
                crate::net::runtime::command::RuntimeCommand::Control(
                    crate::net::runtime::command::ControlCommand::GetUdpEndpoints {
                        reply: this.reply,
                    },
                ),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(Vec::new()),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut this.command_future).poll(cx)
    }
}

pub fn get_udp_endpoints_in(runtime: NetRuntimeHandle) -> GetUdpEndpointsFuture {
    GetUdpEndpointsFuture::new(runtime)
}

/// 非同期TCP接続一覧取得Future
pub struct GetTcpConnectionsFuture {
    runtime: NetRuntimeHandle,
    reply: CommandReplyTicket<Vec<TcpConnectionInfo>>,
    command_future: CommandFuture<Vec<TcpConnectionInfo>>,
    sent: bool,
}

impl GetTcpConnectionsFuture {
    fn new(runtime: NetRuntimeHandle) -> Self {
        let (reply, command_future) = new_command_channel_in(runtime);
        Self {
            runtime,
            reply,
            command_future,
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
                crate::net::runtime::command::RuntimeCommand::Control(
                    crate::net::runtime::command::ControlCommand::GetTcpConnections {
                        reply: this.reply,
                    },
                ),
            );
            match core::future::Future::poll(core::pin::Pin::new(&mut enqueue), cx) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(_)) => return Poll::Ready(Vec::new()),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut this.command_future).poll(cx)
    }
}

pub fn get_tcp_connections_in(runtime: NetRuntimeHandle) -> GetTcpConnectionsFuture {
    GetTcpConnectionsFuture::new(runtime)
}

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::task::{Context, Poll};

    fn run_with_event_task<F>(future: F) -> F::Output
    where
        F: Future,
    {
        crate::net::runtime::command::reset_command_system_for_tests();
        let mut executor = crate::task::TestExecutor::new();
        executor.spawn(crate::task::Task::new(async {
            crate::net::runtime::command_loop::runtime_command_task().await;
        }));

        let waker = crate::net::l4::test_support::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if let Poll::Ready(output) = Future::poll(future.as_mut(), &mut cx) {
                crate::net::runtime::command::reset_command_system_for_tests();
                return output;
            }
        }

        crate::net::runtime::command::reset_command_system_for_tests();
        panic!("connection query test timed out")
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn connection_queries_complete_with_event_task() {
        let tcp = run_with_event_task(super::get_tcp_connections_in(
            crate::net::runtime::default_runtime(),
        ));
        let udp = run_with_event_task(super::get_udp_endpoints_in(
            crate::net::runtime::default_runtime(),
        ));
        let arp = run_with_event_task(super::get_arp_cache_in(
            crate::net::runtime::default_runtime(),
        ));

        assert!(tcp.is_empty());
        assert!(udp.is_empty());
        assert!(arp.is_empty());
    }
}
