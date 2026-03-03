// ============================================================================
// kernel/src/net/l2/arp/resolve_future.rs
// ============================================================================
//! # 非同期ARP解決Future
//!
//! ARP要求を送信し、解決完了をWakerベースで待機する。
//! ISR/ポーリングコンテキストからの呼び出しを回避し、
//! イベントキュー経由で安全にARP解決を行う。

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use super::{MacAddress, Ipv4Address};
use crate::sync::PoisonLock;

// ============================================================================
// ARP Resolve Waiter Registry
// ============================================================================

/// ARP解決待ちエントリ
struct ArpWaiter {
    /// 解決対象IPアドレス
    ip: [u8; 4],
    /// 結果格納スロット（解決成功時にMACアドレスが書き込まれる）
    result: Option<MacAddress>,
    /// 通知用Waker
    waker: Option<Waker>,
    /// 有効フラグ（解決完了後にfalse）
    active: bool,
}

/// ARP解決待ちレジストリ（グローバル）
///
/// 同時に待機できるARP解決リクエスト数の上限。
const ARP_WAITER_CAPACITY: usize = 32;

/// タイムアウト（ミリ秒）
const ARP_RESOLVE_TIMEOUT_MS: u64 = 5_000;

static ARP_WAITERS: PoisonLock<Vec<ArpWaiter>> = PoisonLock::new(Vec::new());

/// ARP解決完了を通知する（ARPキャッシュ更新時にイベントハンドラから呼ばれる）
///
/// 該当IPの全待機者にMACアドレスを通知してWakerを起こす。
pub fn notify_arp_resolved(ip: [u8; 4], mac: [u8; 6]) {
    let resolved_mac = MacAddress::new(mac);
    let Ok(mut waiters) = ARP_WAITERS.lock() else {
        return;
    };

    for waiter in waiters.iter_mut() {
        if waiter.active && waiter.ip == ip {
            waiter.result = Some(resolved_mac);
            waiter.active = false;
            if let Some(waker) = waiter.waker.take() {
                waker.wake();
            }
        }
    }

    // 完了済みエントリを除去
    waiters.retain(|w| w.active);
}

/// ARP解決待ちを登録し、ウェイターIDを返す
fn register_arp_waiter(ip: [u8; 4], waker: Waker) -> Option<usize> {
    let Ok(mut waiters) = ARP_WAITERS.lock() else {
        return None;
    };

    // 既に同じIPに対する待機が存在する場合はWakerを更新
    for (idx, waiter) in waiters.iter_mut().enumerate() {
        if waiter.active && waiter.ip == ip {
            waiter.waker = Some(waker);
            return Some(idx);
        }
    }

    if waiters.len() >= ARP_WAITER_CAPACITY {
        return None;
    }

    let idx = waiters.len();
    waiters.push(ArpWaiter {
        ip,
        result: None,
        waker: Some(waker),
        active: true,
    });
    Some(idx)
}

/// ARP解決結果を取得（ポーリング用）
fn poll_arp_result(ip: [u8; 4]) -> Option<MacAddress> {
    let Ok(waiters) = ARP_WAITERS.lock() else {
        return None;
    };

    for waiter in waiters.iter() {
        if waiter.ip == ip && !waiter.active {
            return waiter.result;
        }
    }

    None
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

        // まずキャッシュを確認（イベントキューを経由しない高速パス）
        if let Ok(stack_guard) = crate::net::runtime::stack::NETWORK_STACK.lock() {
            if let Some(ref stack) = *stack_guard {
                let current_time = stack.current_time();
                if let Some(mac) = stack.arp.resolve(self.target_ip, current_time) {
                    return Poll::Ready(Ok(mac));
                }
            } else {
                return Poll::Ready(Err(ArpResolveError::NotInitialized));
            }
        }

        // ウェイター登録済みの結果を確認
        if let Some(mac) = poll_arp_result(ip_bytes) {
            return Poll::Ready(Ok(mac));
        }

        // タイムアウトチェック（約50回ポーリング × 100ms sleep = 5秒）
        self.poll_count += 1;
        if self.poll_count > 50 {
            return Poll::Ready(Err(ArpResolveError::Timeout));
        }

        // ARP要求をイベントキュー経由で送信（初回のみ、または再送）
        if !self.request_sent || self.poll_count % 10 == 0 {
            crate::net::l4::endpoint::event::send_event_ignore(
                crate::net::l4::endpoint::event::NetworkEvent::ArpResolveRequest {
                    target_ip: ip_bytes,
                },
            );
            self.request_sent = true;
        }

        // ウェイター登録
        if register_arp_waiter(ip_bytes, cx.waker().clone()).is_none() {
            return Poll::Ready(Err(ArpResolveError::ResourceExhausted));
        }

        Poll::Pending
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
    if let Ok(mut waiters) = ARP_WAITERS.lock() {
        for waiter in waiters.iter_mut() {
            if waiter.active {
                // アクティブな待機者にWakeを送って再ポーリングさせる
                // （Future側でpoll_countによるタイムアウトを検出）
                if let Some(waker) = waiter.waker.take() {
                    waker.wake();
                }
            }
        }
        waiters.retain(|w| w.active);
    }
}
