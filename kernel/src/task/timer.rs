// ============================================================================
// src/task/timer.rs - Timer-based async sleep implementation
// 設計書 4.2: Interrupt-Waker Bridge の実装例
// 
// 【重要】2段階Wake方式:
// ISRから直接waker.wake()を呼ばず、保留リストに追加のみ。
// 実際のwake()はExecutorのイベントループで行う。
// ============================================================================
#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

/// グローバルなタイマーティック（1ms単位）
static TICKS: AtomicU64 = AtomicU64::new(0);

/// スリープ中のタスクのレジストリ
static SLEEP_REGISTRY: Mutex<BTreeMap<u64, Waker>> = Mutex::new(BTreeMap::new());

/// 【2段階Wake方式】保留中のWakerリスト
/// ISRはここに追加のみ、実際のwake()はprocess_pending_timer_wakers()で行う
static PENDING_TIMER_WAKERS: Mutex<Vec<Waker>> = Mutex::new(Vec::new());

/// タイマー割り込みハンドラから呼ばれる
/// 
/// 【設計書 4.2】2段階Wake方式:
/// ISRコンテキストでは直接wake()を呼ばず、保留リストに追加のみ
pub fn handle_timer_interrupt() {
    let current_tick = TICKS.fetch_add(1, Ordering::SeqCst) + 1;

    // 起床すべきタスクを探して保留リストに追加
    // 【重要】ISRコンテキストではwake()を呼ばない
    if let Some(mut registry) = SLEEP_REGISTRY.try_lock() {
        let wake_keys: Vec<u64> =
            registry.range(..=current_tick).map(|(k, _)| *k).collect();

        if !wake_keys.is_empty() {
            if let Some(mut pending) = PENDING_TIMER_WAKERS.try_lock() {
                for key in wake_keys {
                    if let Some(waker) = registry.remove(&key) {
                        // 【重要】wake()を呼ばず、保留リストに追加のみ
                        pending.push(waker);
                    }
                }
            }
        }
    }
}

/// 保留中のタイマーWakerを処理（Executorから呼び出す）
/// 
/// 【設計書 4.2】2段階Wake方式: 非ISRコンテキストで呼び出す
/// process_interrupt_events()の後に呼び出すべき
pub fn process_pending_timer_wakers() {
    // 保留リストを取得してクリア
    let wakers: Vec<Waker> = {
        let mut pending = PENDING_TIMER_WAKERS.lock();
        core::mem::take(&mut *pending)
    };
    
    // 非ISRコンテキストなので安全にwake()を呼び出す
    for waker in wakers {
        waker.wake();
    }
}

/// 保留中のタイマーWaker数を取得
pub fn pending_timer_waker_count() -> usize {
    PENDING_TIMER_WAKERS.lock().len()
}

/// 現在のティック数を取得
pub fn current_tick() -> u64 {
    TICKS.load(Ordering::SeqCst)
}

/// 指定ミリ秒スリープする非同期関数
pub async fn sleep_ms(duration_ms: u64) {
    SleepFuture::new(duration_ms).await;
}

/// スリープ用のFuture
struct SleepFuture {
    wake_tick: u64,
    registered: bool,
}

impl SleepFuture {
    fn new(duration_ms: u64) -> Self {
        let wake_tick = current_tick() + duration_ms;
        Self {
            wake_tick,
            registered: false,
        }
    }
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let current = current_tick();

        if current >= self.wake_tick {
            // スリープ期間が終了
            return Poll::Ready(());
        }

        // Wakerを登録（初回のみ）
        if !self.registered {
            SLEEP_REGISTRY
                .lock()
                .insert(self.wake_tick, cx.waker().clone());
            self.registered = true;
        }

        Poll::Pending
    }
}

impl Drop for SleepFuture {
    fn drop(&mut self) {
        // タスクがキャンセルされた場合、レジストリから削除
        if self.registered {
            SLEEP_REGISTRY.lock().remove(&self.wake_tick);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep_future() {
        // テストは割り込み環境が必要なため、統合テストで実施
    }
}
