// ============================================================================
// src/task/timer.rs - Timer-based async sleep implementation
// 設計書 4.2: Interrupt-Waker Bridge の実装例
//
// 【重要】2段階Wake方式:
// ISRから直接waker.wake()を呼ばず、保留リストに追加のみ。
// 実際のwake()はExecutorのイベントループで行う。
//
// 【改良】ロックフリー化:
// - PENDING_TIMER_WAKERS: ロックフリーリングバッファに変更
// - SLEEP_REGISTRY: シャード化されたレジストリに変更
// ============================================================================
#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

/// グローバルなタイマーティック（1ms単位）
static TICKS: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Sharded Sleep Registry
// ============================================================================

/// シャード数（2のべき乗）
const SHARD_COUNT: usize = 16;
const SHARD_MASK: usize = SHARD_COUNT - 1;

/// シャード化されたスリープレジストリ
/// 
/// ティック値でシャーディングすることで、ISRでのロック競合を減らす
struct ShardedSleepRegistry {
    shards: [Mutex<BTreeMap<u64, Waker>>; SHARD_COUNT],
}

impl ShardedSleepRegistry {
    const fn new() -> Self {
        const EMPTY_SHARD: Mutex<BTreeMap<u64, Waker>> = Mutex::new(BTreeMap::new());
        Self {
            shards: [EMPTY_SHARD; SHARD_COUNT],
        }
    }

    /// ティック値からシャードインデックスを計算
    #[inline]
    fn shard_index(tick: u64) -> usize {
        (tick as usize) & SHARD_MASK
    }

    /// Wakerを登録
    fn insert(&self, tick: u64, waker: Waker) {
        let idx = Self::shard_index(tick);
        self.shards[idx].lock().insert(tick, waker);
    }

    /// Wakerを削除
    fn remove(&self, tick: u64) -> Option<Waker> {
        let idx = Self::shard_index(tick);
        self.shards[idx].lock().remove(&tick)
    }

    /// 指定ティック以下のすべてのWakerを収集して削除
    /// ISRから呼ばれるため、try_lockを使用
    fn drain_expired(&self, current_tick: u64, out: &mut Vec<Waker>) {
        for shard in &self.shards {
            if let Some(mut guard) = shard.try_lock() {
                // この時点でcurrent_tick以下のキーを収集
                let expired_keys: Vec<u64> = guard
                    .range(..=current_tick)
                    .map(|(k, _)| *k)
                    .collect();
                
                for key in expired_keys {
                    if let Some(waker) = guard.remove(&key) {
                        out.push(waker);
                    }
                }
            }
            // try_lockに失敗したシャードは次回のISRで処理
        }
    }
}

static SLEEP_REGISTRY: ShardedSleepRegistry = ShardedSleepRegistry::new();

// ============================================================================
// Lock-Free Pending Wakers Queue
// ============================================================================

/// ロックフリーのペンディングWakerキューサイズ
const PENDING_QUEUE_SIZE: usize = 512;
const PENDING_QUEUE_MASK: usize = PENDING_QUEUE_SIZE - 1;

/// ロックフリーのペンディングWakerキュー
/// 
/// MPSCキュー: ISR（複数コア）がプロデューサ、Executorがコンシューマ
#[repr(C, align(64))]
struct LockFreePendingWakers {
    /// プロデューサーのヘッド（ISRが書き込む位置）
    head: AtomicUsize,
    /// コンシューマーのテール（Executorが読む位置）
    tail: AtomicUsize,
    /// Wakerの循環バッファ（AtomicPtrとして格納）
    buffer: [AtomicUsize; PENDING_QUEUE_SIZE],
    /// 統計: 追加成功
    enqueued: AtomicUsize,
    /// 統計: 追加失敗（キュー満杯）
    dropped: AtomicUsize,
}

impl LockFreePendingWakers {
    const fn new() -> Self {
        const ZERO: AtomicUsize = AtomicUsize::new(0);
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buffer: [ZERO; PENDING_QUEUE_SIZE],
            enqueued: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    /// ISRからWakerをエンキュー（ロックフリー）
    /// 
    /// Wakerはヒープにボックス化してポインタとして格納
    fn enqueue(&self, waker: Waker) -> bool {
        // Box化してリーク（後でコンシューマが回収）
        let boxed = alloc::boxed::Box::new(waker);
        let ptr = alloc::boxed::Box::into_raw(boxed) as usize;

        loop {
            let head = self.head.load(Ordering::Acquire);
            let tail = self.tail.load(Ordering::Acquire);

            // キューが満杯かチェック
            if head.wrapping_sub(tail) >= PENDING_QUEUE_SIZE {
                // 満杯: Boxを解放して失敗を報告
                unsafe {
                    let _ = alloc::boxed::Box::from_raw(ptr as *mut Waker);
                }
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            }

            let idx = head & PENDING_QUEUE_MASK;

            // CASでスロットを確保
            match self.head.compare_exchange_weak(
                head,
                head.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // 成功: Wakerポインタを格納
                    self.buffer[idx].store(ptr, Ordering::Release);
                    self.enqueued.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(_) => {
                    // 競合: リトライ
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// ExecutorがすべてのWakerをデキュー
    fn drain(&self) -> Vec<Waker> {
        let mut wakers = Vec::new();

        loop {
            let tail = self.tail.load(Ordering::Acquire);
            let head = self.head.load(Ordering::Acquire);

            if tail == head {
                // キューが空
                break;
            }

            let idx = tail & PENDING_QUEUE_MASK;

            // テールを進める
            match self.tail.compare_exchange_weak(
                tail,
                tail.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // 成功: Wakerを取り出す
                    let ptr = self.buffer[idx].swap(0, Ordering::Acquire);
                    if ptr != 0 {
                        // SAFETY: enqueue()でBox化したポインタを回収
                        let waker = unsafe { *alloc::boxed::Box::from_raw(ptr as *mut Waker) };
                        wakers.push(waker);
                    }
                }
                Err(_) => {
                    // 競合（別のコンシューマ）: リトライ
                    core::hint::spin_loop();
                }
            }
        }

        wakers
    }

    /// 統計を取得
    fn stats(&self) -> (usize, usize) {
        (
            self.enqueued.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    /// 現在のキューサイズ（おおよそ）
    fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }
}

static PENDING_TIMER_WAKERS: LockFreePendingWakers = LockFreePendingWakers::new();

// ============================================================================
// Public API
// ============================================================================

/// タイマー割り込みハンドラから呼ばれる
///
/// 【設計書 4.2】2段階Wake方式:
/// ISRコンテキストでは直接wake()を呼ばず、ロックフリーキューに追加
pub fn handle_timer_interrupt() {
    let current_tick = TICKS.fetch_add(1, Ordering::SeqCst) + 1;

    // スリープレジストリから期限切れのWakerを収集
    // 【改良】シャーディングにより競合を低減
    let mut expired = Vec::new();
    SLEEP_REGISTRY.drain_expired(current_tick, &mut expired);

    // 【改良】ロックフリーキューにエンキュー
    for waker in expired {
        let _ = PENDING_TIMER_WAKERS.enqueue(waker);
    }
}

/// 保留中のタイマーWakerを処理（Executorから呼び出す）
///
/// 【設計書 4.2】2段階Wake方式: 非ISRコンテキストで呼び出す
/// process_interrupt_events()の後に呼び出すべき
pub fn process_pending_timer_wakers() {
    // 【改良】ロックフリーでドレイン
    let wakers = PENDING_TIMER_WAKERS.drain();

    // 非ISRコンテキストなので安全にwake()を呼び出す
    for waker in wakers {
        waker.wake();
    }
}

/// 保留中のタイマーWaker数を取得（おおよそ）
pub fn pending_timer_waker_count() -> usize {
    PENDING_TIMER_WAKERS.len()
}

/// ペンディングキューの統計を取得 (enqueued, dropped)
pub fn pending_waker_stats() -> (usize, usize) {
    PENDING_TIMER_WAKERS.stats()
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
            SLEEP_REGISTRY.insert(self.wake_tick, cx.waker().clone());
            self.registered = true;
        }

        Poll::Pending
    }
}

impl Drop for SleepFuture {
    fn drop(&mut self) {
        // タスクがキャンセルされた場合、レジストリから削除
        if self.registered {
            let _ = SLEEP_REGISTRY.remove(self.wake_tick);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_sleep_future() {
        // テストは割り込み環境が必要なため、統合テストで実施
    }

    #[test_case]
    fn test_sharded_registry() {
        // シャードインデックスのテスト
        assert_eq!(ShardedSleepRegistry::shard_index(0), 0);
        assert_eq!(ShardedSleepRegistry::shard_index(16), 0);
        assert_eq!(ShardedSleepRegistry::shard_index(1), 1);
        assert_eq!(ShardedSleepRegistry::shard_index(15), 15);
    }
}
