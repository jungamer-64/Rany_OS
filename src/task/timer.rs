// ============================================================================
// src/task/timer.rs - Timer-based async sleep implementation
// 設計書 4.2: Interrupt-Waker Bridge の実装例
// ============================================================================
#![allow(dead_code)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::collections::BTreeMap;
use spin::Mutex;

/// グローバルなタイマーティック（1ms単位）
static TICKS: AtomicU64 = AtomicU64::new(0);

/// スリープ中のタスクのレジストリ
static SLEEP_REGISTRY: Mutex<BTreeMap<u64, core::task::Waker>> = Mutex::new(BTreeMap::new());

/// タイマー割り込みハンドラから呼ばれる
/// 設計書 4.2 ステップ3: Wakeの発行
pub fn handle_timer_interrupt() {
    let current_tick = TICKS.fetch_add(1, Ordering::SeqCst) + 1;
    
    // 起床すべきタスクを探してWakerを起動
    let mut registry = SLEEP_REGISTRY.lock();
    let wake_keys: alloc::vec::Vec<u64> = registry
        .range(..=current_tick)
        .map(|(k, _)| *k)
        .collect();
    
    for key in wake_keys {
        if let Some(waker) = registry.remove(&key) {
            waker.wake();
        }
    }
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
            SLEEP_REGISTRY.lock().insert(self.wake_tick, cx.waker().clone());
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
