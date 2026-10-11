// ============================================================================
// kernel/src/net/l2/arp/resolve_future.rs - 非同期ARP解決Future
// ============================================================================
//! # 非同期ARP解決Future
//!
//! ARP要求を送信し、解決完了をWakerベースで待機する。
//! ISR/ポーリングコンテキストからの呼び出しを回避し、
//! イベントキュー経由で安全にARP解決を行う。
//!
//! 完全非同期設計: NETWORK_STACKロックを一切使用せず、
//! ArpResolveRequestイベント経由でキャッシュ確認・ARP要求送信を行う。

// Building block: ARP resolve timeout constants retained for future async ARP

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use super::{Ipv4Address, MacAddress};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::try_enqueue_command_in;
use crate::net::runtime::manager::NetIfId;

pub struct ArpResolveFuture {
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    target_ip: Ipv4Address,
    /// 待機者ID（登録済みの場合）
    waiter_id: Option<u64>,
    /// ARP要求送信済みフラグ
    request_sent: bool,
    /// ポーリング回数（タイムアウト検出用）
    poll_count: u32,
}

impl ArpResolveFuture {
    /// 新規作成
    pub fn new_in(runtime: NetRuntimeHandle, if_id: NetIfId, target_ip: Ipv4Address) -> Self {
        Self {
            runtime,
            if_id,
            target_ip,
            waiter_id: None,
            request_sent: false,
            poll_count: 0,
        }
    }
}

/// ARP解決エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpResolveError {
    /// タイムアウト
    Timeout,
    /// リソース不足
    ResourceExhausted,
    /// スタック未初期化
    NotInitialized,
}

impl Future for ArpResolveFuture {
    type Output = Result<MacAddress, ArpResolveError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let ip_bytes = *self.target_ip.as_bytes();

        // ブロードキャストは即座に返す
        if self.target_ip.is_broadcast() {
            return Poll::Ready(Ok(MacAddress::BROADCAST));
        }

        if self.target_ip.is_multicast() {
            let ip = self.target_ip.as_bytes();
            let mac = MacAddress::new([0x01, 0x00, 0x5e, ip[1] & 0x7f, ip[2], ip[3]]);
            return Poll::Ready(Ok(mac));
        }

        // 初回ポーリング時にウェイター登録
        if self.waiter_id.is_none() {
            self.waiter_id = register_arp_waiter(self.runtime, self.if_id, ip_bytes, cx.waker());
            if self.waiter_id.is_none() {
                return Poll::Ready(Err(ArpResolveError::ResourceExhausted));
            }
        }

        // ウェイター登録済みの結果を確認
        if let Some(waiter_id) = self.waiter_id {
            if let Some(mac) = poll_arp_result(self.runtime, waiter_id) {
                let _ = remove_arp_waiter(self.runtime, waiter_id);
                self.waiter_id = None;
                return Poll::Ready(Ok(mac));
            }

            // Future側のWakerを最新化。待機者が消えていればタイムアウト扱い。
            if !update_arp_waiter_waker(self.runtime, waiter_id, cx.waker()) {
                self.waiter_id = None;
                return Poll::Ready(Err(ArpResolveError::Timeout));
            }
        }

        // タイムアウトチェック（約50回ポーリング × 100ms sleep = 5秒）
        self.poll_count += 1;
        if self.poll_count > 50 {
            if let Some(waiter_id) = self.waiter_id.take() {
                let _ = remove_arp_waiter(self.runtime, waiter_id);
            }
            return Poll::Ready(Err(ArpResolveError::Timeout));
        }

        // ARP要求をイベントキュー経由で送信（初回のみ、または再送）
        // ArpResolveRequestハンドラ内でキャッシュヒット時は即座にnotify_arp_resolved_in()が呼ばれる
        if !self.request_sent || self.poll_count % 10 == 0 {
            let _ = try_enqueue_command_in(
                self.runtime,
                crate::net::runtime::command::RuntimeCommand::Control(
                    crate::net::runtime::command::ControlCommand::ArpResolveRequest {
                        if_id: self.if_id,
                        target_ip: ip_bytes,
                    },
                ),
            );
            self.request_sent = true;
        }

        Poll::Pending
    }
}

impl Drop for ArpResolveFuture {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id.take() {
            let _ = remove_arp_waiter(self.runtime, waiter_id);
        }
    }
}

/// 非同期ARP解決ヘルパー関数
///
/// `ArpResolveFuture` のショートカット。
pub async fn resolve_mac_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    target_ip: Ipv4Address,
) -> Result<MacAddress, ArpResolveError> {
    ArpResolveFuture::new_in(runtime, if_id, target_ip).await
}

/// 期限切れのARP待機エントリをクリーンアップ
///
/// タイマータスクから定期的に呼び出す。
pub fn cleanup_arp_waiters_in(runtime: NetRuntimeHandle) {
    let now_ms = current_time_ms();
    if let Ok(mut waiters) = arp_waiters_in(runtime).waiters.lock() {
        for waiter in waiters.iter() {
            let age_base = waiter.completed_at_ms.unwrap_or(waiter.created_at_ms);
            let expired = now_ms.saturating_sub(age_base) > ARP_RESOLVE_TIMEOUT_MS;

            // 未解決のまま期限切れになった待機者は起床させ、
            // 次回poll時にTimeoutへ遷移させる。
            if expired && waiter.result.is_none() {
                waiter.waker.wake();
            }
        }

        // 完了済み/未完了を問わず、長期間放置された待機者を回収。
        waiters.retain(|waiter| {
            let age_base = waiter.completed_at_ms.unwrap_or(waiter.created_at_ms);
            now_ms.saturating_sub(age_base) <= ARP_RESOLVE_TIMEOUT_MS
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::task::{Context, RawWaker, RawWakerVTable, Waker};

    fn noop_waker() -> Waker {
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}

        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);

        // SAFETY: no-op vtable with null data pointer is valid for a no-op waker.
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn arp_waiter_notify_wakes_all_waiters_for_same_ip() {
        let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
        reset_arp_waiters_for_tests(runtime);

        let ip = [10, 0, 0, 42];
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];
        let if_id = NetIfId(1);

        let waiter_a = register_arp_waiter(runtime, if_id, ip, &noop_waker())
            .expect("failed to register waiter A");
        let waiter_b = register_arp_waiter(runtime, if_id, ip, &noop_waker())
            .expect("failed to register waiter B");

        notify_arp_resolved_in(runtime, if_id, ip, mac);

        assert_eq!(
            poll_arp_result(runtime, waiter_a),
            Some(MacAddress::new(mac))
        );
        assert_eq!(
            poll_arp_result(runtime, waiter_b),
            Some(MacAddress::new(mac))
        );

        let _ = remove_arp_waiter(runtime, waiter_a);
        let _ = remove_arp_waiter(runtime, waiter_b);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn arp_resolve_future_returns_ready_after_resolution_notification() {
        let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
        reset_arp_waiters_for_tests(runtime);

        let ip = [192, 168, 1, 77];
        let target_ip = Ipv4Address::new(ip);
        let resolved_mac = MacAddress::from_octets(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
        let if_id = NetIfId(2);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = ArpResolveFuture::new_in(runtime, if_id, target_ip);
        fut.request_sent = true;

        assert!(matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending));

        notify_arp_resolved_in(runtime, if_id, ip, *resolved_mac.as_bytes());

        let poll = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(mac)) if mac == resolved_mac));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn arp_resolve_future_timeout_removes_registered_waiter() {
        let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
        reset_arp_waiters_for_tests(runtime);

        let ip = [172, 16, 0, 9];
        let if_id = NetIfId(3);
        let waiter_id = register_arp_waiter(runtime, if_id, ip, &noop_waker())
            .expect("failed to register waiter");
        assert!(waiter_exists(runtime, waiter_id));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = ArpResolveFuture::new_in(runtime, if_id, Ipv4Address::new(ip));
        fut.request_sent = true;
        fut.waiter_id = Some(waiter_id);
        fut.poll_count = 50;

        let poll = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(poll, Poll::Ready(Err(ArpResolveError::Timeout))));
        assert!(!waiter_exists(runtime, waiter_id));
    }
}
