// ============================================================================
// kernel/src/net/api/icmp.rs - ICMP Echo (ping) 操作
// ============================================================================
//! ICMP Echoリクエストの送信（同期・非同期）。

extern crate alloc;

use crate::net::l4::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::CommandDispatch;
pub use crate::net::runtime::icmp::IcmpEchoResult;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

// Removed: `send_icmp_echo()` — deprecated, use `enqueue_icmp_echo_in()` or `ping_in()` instead.

/// 非同期ICMP Echo送信（fire-and-forget）
///
/// ICMP Echoリクエストをイベントキュー経由で送信する。
/// エグゼキュータが起動しているasyncコンテキストから呼び出す。
/// 応答を待機するには `ping_in(runtime, ...)` または `IcmpEchoFuture` を使用すること。
pub fn enqueue_icmp_echo_in(runtime: NetRuntimeHandle, target: [u8; 4], seq: u16) -> bool {
    let _ = crate::net::runtime::command::try_enqueue_command_in(
        runtime,
        crate::net::runtime::command::RuntimeCommand::Control(
            crate::net::runtime::command::ControlCommand::IcmpEchoRequest {
                target,
                sequence: seq,
            },
        ),
    );
    true
}

pub(crate) fn notify_icmp_echo_reply_in(
    runtime: NetRuntimeHandle,
    source: [u8; 4],
    sequence: u16,
    rtt_us: u64,
) {
    crate::net::runtime::icmp::icmp_runtime_in(runtime).notify_echo_reply(source, sequence, rtt_us);
}

pub(crate) fn cleanup_icmp_echo_waiters_in(runtime: NetRuntimeHandle) {
    crate::net::runtime::icmp::icmp_runtime_in(runtime).cleanup_echo_waiters();
}

pub struct IcmpEchoFuture {
    target: [u8; 4],
    sequence: u16,
    registered: bool,
    sent: bool,
    timeout_us: u64,
    dispatch: CommandDispatch,
}

impl IcmpEchoFuture {
    pub fn new_in(runtime: NetRuntimeHandle, target: [u8; 4], sequence: u16) -> Self {
        Self {
            target,
            sequence,
            registered: false,
            sent: false,
            timeout_us: 5_000_000,
            dispatch: CommandDispatch::new_in(runtime),
        }
    }

    pub fn with_timeout_in(
        runtime: NetRuntimeHandle,
        target: [u8; 4],
        sequence: u16,
        timeout_us: u64,
    ) -> Self {
        Self {
            target,
            sequence,
            registered: false,
            sent: false,
            timeout_us,
            dispatch: CommandDispatch::new_in(runtime),
        }
    }
}

impl Future for IcmpEchoFuture {
    type Output = Result<IcmpEchoResult, EndpointError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.registered {
            if let Err(err) = crate::net::runtime::icmp::icmp_runtime_in(this.dispatch.runtime())
                .register_echo_waiter(this.target, this.sequence, this.timeout_us)
            {
                return Poll::Ready(Err(err));
            }
            this.registered = true;
        }

        if !this.sent {
            match this.dispatch.poll(cx, || {
                crate::net::runtime::command::RuntimeCommand::Control(
                    crate::net::runtime::command::ControlCommand::IcmpEchoRequest {
                        target: this.target,
                        sequence: this.sequence,
                    },
                )
            }) {
                Poll::Ready(Ok(())) => this.sent = true,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        crate::net::runtime::icmp::icmp_runtime_in(this.dispatch.runtime()).poll_echo_result(
            this.target,
            this.sequence,
            cx.waker(),
        )
    }
}

/// 非同期ICMP Echo（推奨API）
///
/// ICMP Echo Requestを送信し、応答をFutureで待機する。
/// 完全にイベントキュー経由で動作し、同期ロックを一切取得しない。
///
/// # 使用例
/// ```ignore
/// let result = ping_in(runtime, [8, 8, 8, 8], 1).await;
/// match result {
///     Ok(echo) => log::info!("RTT: {} us", echo.rtt_us),
///     Err(e) => log::warn!("ping failed: {:?}", e),
/// }
/// ```
pub fn ping_in(runtime: NetRuntimeHandle, target: [u8; 4], seq: u16) -> IcmpEchoFuture {
    IcmpEchoFuture::new_in(runtime, target, seq)
}

/// カスタムタイムアウト付き非同期ICMP Echo
pub fn ping_with_timeout_in(
    runtime: NetRuntimeHandle,
    target: [u8; 4],
    seq: u16,
    timeout_us: u64,
) -> IcmpEchoFuture {
    IcmpEchoFuture::with_timeout_in(runtime, target, seq, timeout_us)
}
