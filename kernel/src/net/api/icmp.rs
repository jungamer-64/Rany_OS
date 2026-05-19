// ============================================================================
// kernel/src/net/api/icmp.rs - ICMP Echo (ping) 操作
// ============================================================================
//! ICMP Echoリクエストの送信（同期・非同期）。

extern crate alloc;

use crate::net::l4::types::EndpointError;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::CommandDispatch;
use crate::sync::{AtomicWaker, PoisonLock};
use alloc::collections::BTreeMap;
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
    crate::net::runtime::command::enqueue_command_ignore_in(
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

/// ICMP Echo 応答の結果
#[derive(Debug, Clone, Copy)]
pub struct IcmpEchoResult {
    pub source: [u8; 4],
    pub sequence: u16,
    pub rtt_us: u64,
}

struct PingWaiter {
    waker: AtomicWaker,
    result: Option<IcmpEchoResult>,
    start_tick: u64,
    timeout_us: u64,
}

struct IcmpEchoRegistry {
    waiters: BTreeMap<(u32, u16), PingWaiter>,
}

impl IcmpEchoRegistry {
    const fn new() -> Self {
        Self {
            waiters: BTreeMap::new(),
        }
    }

    fn register(&mut self, target: [u8; 4], sequence: u16, timeout_us: u64) {
        let key = (u32::from_be_bytes(target), sequence);
        let now = crate::task::current_tick();
        self.waiters.insert(
            key,
            PingWaiter {
                waker: AtomicWaker::new(),
                result: None,
                start_tick: now,
                timeout_us,
            },
        );
    }

    fn set_waker(&mut self, target: [u8; 4], sequence: u16, waker: &core::task::Waker) {
        let key = (u32::from_be_bytes(target), sequence);
        if let Some(entry) = self.waiters.get_mut(&key) {
            entry.waker.register(waker);
        }
    }

    fn notify_reply(&mut self, source: [u8; 4], sequence: u16, rtt_us: u64) {
        let key = (u32::from_be_bytes(source), sequence);
        if let Some(entry) = self.waiters.get_mut(&key) {
            entry.result = Some(IcmpEchoResult {
                source,
                sequence,
                rtt_us,
            });
            entry.waker.wake();
        }
    }

    fn poll_result(
        &mut self,
        target: [u8; 4],
        sequence: u16,
    ) -> Poll<Result<IcmpEchoResult, EndpointError>> {
        let key = (u32::from_be_bytes(target), sequence);
        if let Some(entry) = self.waiters.get(&key) {
            if let Some(result) = entry.result {
                self.waiters.remove(&key);
                return Poll::Ready(Ok(result));
            }
            let now = crate::task::current_tick();
            let elapsed = now.saturating_sub(entry.start_tick);
            if elapsed > entry.timeout_us {
                self.waiters.remove(&key);
                return Poll::Ready(Err(EndpointError::Timeout));
            }
            Poll::Pending
        } else {
            Poll::Ready(Err(EndpointError::NotFound))
        }
    }

    fn cleanup_expired(&mut self) {
        let now = crate::task::current_tick();
        self.waiters.retain(|_, entry| {
            let elapsed = now.saturating_sub(entry.start_tick);
            elapsed <= entry.timeout_us
        });
    }
}

static ICMP_ECHO_REGISTRY: PoisonLock<IcmpEchoRegistry> = PoisonLock::new(IcmpEchoRegistry::new());

pub(crate) fn notify_icmp_echo_reply(source: [u8; 4], sequence: u16, rtt_us: u64) {
    if let Ok(mut registry) = ICMP_ECHO_REGISTRY.lock() {
        registry.notify_reply(source, sequence, rtt_us);
    }
}

pub(crate) fn cleanup_icmp_echo_waiters() {
    if let Ok(mut registry) = ICMP_ECHO_REGISTRY.lock() {
        registry.cleanup_expired();
    }
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
            if let Ok(mut registry) = ICMP_ECHO_REGISTRY.lock() {
                registry.register(this.target, this.sequence, this.timeout_us);
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

        if let Ok(mut registry) = ICMP_ECHO_REGISTRY.lock() {
            registry.set_waker(this.target, this.sequence, cx.waker());
            registry.poll_result(this.target, this.sequence)
        } else {
            Poll::Ready(Err(EndpointError::Internal))
        }
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
