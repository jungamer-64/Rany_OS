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

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use super::{Ipv4Address, MacAddress};
use crate::sync::{AtomicWaker, PoisonLock};

// ============================================================================
// ARP Resolve Waiter Registry
// ============================================================================

/// ARP解決待ちエントリ
struct ArpWaiter {
    /// 待機ID
    id: u64,
    /// 解決対象IPアドレス
    ip: [u8; 4],
    /// 結果格納スロット（解決成功時にMACアドレスが書き込まれる）
    result: Option<MacAddress>,
    /// 通知用Waker
    waker: AtomicWaker,
    /// 登録時刻
    created_at_ms: u64,
    /// 解決完了時刻（未完了時はNone）
    completed_at_ms: Option<u64>,
}

/// ARP解決待ちレジストリ（グローバル）
///
/// 同時に待機できるARP解決リクエスト数の上限。
const ARP_WAITER_CAPACITY: usize = 32;

/// タイムアウト（ミリ秒）
const ARP_RESOLVE_TIMEOUT_MS: u64 = 5_000;

#[inline]
fn current_time_ms() -> u64 {
    crate::time::get_uptime_ms()
}

#[cfg(any(test, feature = "qemu-test-export"))]
fn reset_arp_waiters_for_tests() {
    if let Ok(mut waiters) = ARP_WAITERS.lock() {
        waiters.clear();
    }
    ARP_WAITER_NEXT_ID.store(1, Ordering::Relaxed);
}

/// ARP解決完了を通知する（ARPキャッシュ更新時にイベントハンドラから呼ばれる）
///
/// 該当IPの全待機者にMACアドレスを通知してWakerを起こす。
pub fn notify_arp_resolved(ip: [u8; 4], mac: [u8; 6]) {
    let now_ms = current_time_ms();
    let resolved_mac = MacAddress::new(mac);
    let Ok(mut waiters) = ARP_WAITERS.lock() else {
        return;
    };

    for waiter in waiters.iter_mut() {
        if waiter.ip == ip && waiter.result.is_none() {
            waiter.result = Some(resolved_mac);
            waiter.completed_at_ms = Some(now_ms);
            waiter.waker.wake();
        }
    }
}

/// ARP解決待ちを登録し、ウェイターIDを返す
fn register_arp_waiter(ip: [u8; 4], waker: &Waker) -> Option<u64> {
    let Ok(mut waiters) = ARP_WAITERS.lock() else {
        return None;
    };

    if waiters.len() >= ARP_WAITER_CAPACITY {
        return None;
    }

    let waiter_id = ARP_WAITER_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let waiter = ArpWaiter {
        id: waiter_id,
        ip,
        result: None,
        waker: AtomicWaker::new(),
        created_at_ms: current_time_ms(),
        completed_at_ms: None,
    };
    waiter.waker.register(waker);
    waiters.push(waiter);
    Some(waiter_id)
}

/// 登録済み待機者のWakerを更新する。
///
/// `true`: 待機者が存在し更新できた
/// `false`: 待機者が見つからない（タイムアウト回収などで削除済み）
fn update_arp_waiter_waker(waiter_id: u64, waker: &Waker) -> bool {
    let Ok(mut waiters) = ARP_WAITERS.lock() else {
        return false;
    };

    if let Some(waiter) = waiters.iter_mut().find(|w| w.id == waiter_id) {
        waiter.waker.register(waker);
        return true;
    }

    false
}

/// 待機IDに紐づくARP解決結果を取得（ポーリング用）
fn poll_arp_result(waiter_id: u64) -> Option<MacAddress> {
    let Ok(waiters) = ARP_WAITERS.lock() else {
        return None;
    };

    for waiter in waiters.iter() {
        if waiter.id == waiter_id {
            return waiter.result;
        }
    }

    None
}

/// 待機IDに紐づくエントリを削除する
fn remove_arp_waiter(waiter_id: u64) -> bool {
    let Ok(mut waiters) = ARP_WAITERS.lock() else {
        return false;
    };

    let before = waiters.len();
    waiters.retain(|w| w.id != waiter_id);
    waiters.len() != before
}

#[cfg(any(test, feature = "qemu-test-export"))]
fn waiter_exists(waiter_id: u64) -> bool {
    let Ok(waiters) = ARP_WAITERS.lock() else {
        return false;
    };

    waiters.iter().any(|w| w.id == waiter_id)
}

// ============================================================================
// ArpResolveFuture
// ============================================================================

/// 非同期ARP解決Future
///
/// 指定IPアドレスのMAC解決を非同期で行う。
/// まずキャッシュを確認し、キャッシュヒットなら即座に返す。
/// キャッシュミス時はARP要求をイベントキュー経由で送信し、
/// 解決完了をWakerで待機する。
///
/// # 使用例
/// ```ignore
/// let mac = ArpResolveFuture::new(target_ip).await;
/// match mac {
///     Ok(mac) => log::info!("Resolved: {}", mac),
///     Err(e) => log::warn!("ARP resolve failed: {}", e),
/// }
/// ```
pub struct ArpResolveFuture {
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
    pub fn new(target_ip: Ipv4Address) -> Self {
        Self {
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

        // 初回ポーリング時にウェイター登録
        if self.waiter_id.is_none() {
            self.waiter_id = register_arp_waiter(ip_bytes, cx.waker());
            if self.waiter_id.is_none() {
                return Poll::Ready(Err(ArpResolveError::ResourceExhausted));
            }
        }

        // ウェイター登録済みの結果を確認
        if let Some(waiter_id) = self.waiter_id {
            if let Some(mac) = poll_arp_result(waiter_id) {
                let _ = remove_arp_waiter(waiter_id);
                self.waiter_id = None;
                return Poll::Ready(Ok(mac));
            }

            // Future側のWakerを最新化。待機者が消えていればタイムアウト扱い。
            if !update_arp_waiter_waker(waiter_id, cx.waker()) {
                self.waiter_id = None;
                return Poll::Ready(Err(ArpResolveError::Timeout));
            }
        }

        // タイムアウトチェック（約50回ポーリング × 100ms sleep = 5秒）
        self.poll_count += 1;
        if self.poll_count > 50 {
            if let Some(waiter_id) = self.waiter_id.take() {
                let _ = remove_arp_waiter(waiter_id);
            }
            return Poll::Ready(Err(ArpResolveError::Timeout));
        }

        // ARP要求をイベントキュー経由で送信（初回のみ、または再送）
        // ArpResolveRequestハンドラ内でキャッシュヒット時は即座にnotify_arp_resolved()が呼ばれる
        if !self.request_sent || self.poll_count % 10 == 0 {
            crate::net::runtime::command::enqueue_command_ignore(
                crate::net::runtime::command::RuntimeCommand::Control(crate::net::runtime::command::ControlCommand::ArpResolveRequest {
                    target_ip: ip_bytes,
                }),
            );
            self.request_sent = true;
        }

        Poll::Pending
    }
}

impl Drop for ArpResolveFuture {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id.take() {
            let _ = remove_arp_waiter(waiter_id);
        }
    }
}

/// 非同期ARP解決ヘルパー関数
///
/// `ArpResolveFuture` のショートカット。
pub async fn resolve_mac(target_ip: Ipv4Address) -> Result<MacAddress, ArpResolveError> {
    ArpResolveFuture::new(target_ip).await
}

/// 期限切れのARP待機エントリをクリーンアップ
///
/// タイマータスクから定期的に呼び出す。
pub fn cleanup_arp_waiters() {
    let now_ms = current_time_ms();
    if let Ok(mut waiters) = ARP_WAITERS.lock() {
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

#[cfg(any(test, feature = "qemu-test-export"))]
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

    #[cfg_attr(test, test_case)]
    fn arp_waiter_notify_wakes_all_waiters_for_same_ip() {
        reset_arp_waiters_for_tests();

        let ip = [10, 0, 0, 42];
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

        let waiter_a = register_arp_waiter(ip, noop_waker()).expect("failed to register waiter A");
        let waiter_b = register_arp_waiter(ip, noop_waker()).expect("failed to register waiter B");

        notify_arp_resolved(ip, mac);

        assert_eq!(poll_arp_result(waiter_a), Some(MacAddress::new(mac)));
        assert_eq!(poll_arp_result(waiter_b), Some(MacAddress::new(mac)));

        let _ = remove_arp_waiter(waiter_a);
        let _ = remove_arp_waiter(waiter_b);
    }

    #[cfg_attr(test, test_case)]
    fn arp_resolve_future_returns_ready_after_resolution_notification() {
        reset_arp_waiters_for_tests();

        let ip = [192, 168, 1, 77];
        let target_ip = Ipv4Address::new(ip);
        let resolved_mac = MacAddress::from_octets(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = ArpResolveFuture::new(target_ip);
        fut.request_sent = true;

        assert!(matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending));

        notify_arp_resolved(ip, *resolved_mac.as_bytes());

        let poll = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(mac)) if mac == resolved_mac));
    }

    #[cfg_attr(test, test_case)]
    fn arp_resolve_future_timeout_removes_registered_waiter() {
        reset_arp_waiters_for_tests();

        let ip = [172, 16, 0, 9];
        let waiter_id = register_arp_waiter(ip, noop_waker()).expect("failed to register waiter");
        assert!(waiter_exists(waiter_id));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = ArpResolveFuture::new(Ipv4Address::new(ip));
        fut.request_sent = true;
        fut.waiter_id = Some(waiter_id);
        fut.poll_count = 50;

        let poll = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(poll, Poll::Ready(Err(ArpResolveError::Timeout))));
        assert!(!waiter_exists(waiter_id));
    }
}
