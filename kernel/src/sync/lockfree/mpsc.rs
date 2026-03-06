// ============================================================================
// src/sync/lockfree/mpsc.rs - MPSC (Multi-Producer Single-Consumer) リングバッファ
// 複数コアから単一コアへのメッセージ送信用
// ============================================================================

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::CacheLinePadded;
use super::backoff::Backoff;

/// ロックフリーMPSC リングバッファ
///
/// 複数のプロデューサーが同時にプッシュ可能
/// CAS操作を使用して競合を解決
#[repr(C, align(64))]
pub struct MpscRingBuffer<T, const N: usize> {
    /// 予約済みの書き込み位置
    pub(crate) head: CacheLinePadded<AtomicUsize>,
    /// コミット済みの書き込み位置
    committed: CacheLinePadded<AtomicUsize>,
    /// 読み取り位置
    pub(crate) tail: CacheLinePadded<AtomicUsize>,
    /// バッファ
    buffer: CacheLinePadded<UnsafeCell<[MaybeUninit<T>; N]>>,
}

unsafe impl<T: Send, const N: usize> Send for MpscRingBuffer<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for MpscRingBuffer<T, N> {}

impl<T, const N: usize> MpscRingBuffer<T, N> {
    pub const fn new() -> Self {
        assert!(N >= 2, "Ring buffer must have at least 2 slots");

        Self {
            head: CacheLinePadded::new(AtomicUsize::new(0)),
            committed: CacheLinePadded::new(AtomicUsize::new(0)),
            tail: CacheLinePadded::new(AtomicUsize::new(0)),
            buffer: CacheLinePadded::new(UnsafeCell::new(unsafe {
                MaybeUninit::uninit().assume_init()
            })),
        }
    }

    #[inline]
    pub const fn capacity(&self) -> usize {
        N - 1
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.committed.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }

    /// 現在の要素数を取得
    #[inline]
    pub fn len(&self) -> usize {
        let committed = self.committed.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        committed.wrapping_sub(tail) % N
    }

    /// 要素をプッシュ（複数プロデューサー対応）
    ///
    /// CASループでスロットを予約してから書き込む
    /// 指数バックオフを使用して競合を緩和
    #[inline]
    pub fn push(&self, value: T) -> Result<(), T> {
        let mut backoff = Backoff::new();

        loop {
            let head = self.head.load(Ordering::Relaxed);
            let next_head = (head + 1) % N;

            // 満杯チェック
            if next_head == self.tail.load(Ordering::Acquire) {
                return Err(value);
            }

            // CASでスロットを予約
            match self.head.compare_exchange_weak(
                head,
                next_head,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // 予約成功、書き込み
                    unsafe {
                        let slot = &mut (*self.buffer.value.get())[head];
                        slot.write(value);
                    }

                    // コミットを待機（順序保証）
                    // 前のスロットがコミットされるまで待つ
                    let mut commit_backoff = Backoff::new();
                    while self.committed.load(Ordering::Acquire) != head {
                        commit_backoff.snooze();
                    }

                    // コミット
                    self.committed.store(next_head, Ordering::Release);

                    return Ok(());
                }
                Err(_) => {
                    // 競合、バックオフしてリトライ
                    backoff.spin();
                }
            }
        }
    }

    /// 要素をポップ（単一コンシューマー）
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);

        // コミット済みまでのデータのみ読める
        if tail == self.committed.load(Ordering::Acquire) {
            return None;
        }

        let value = unsafe {
            let slot = &(*self.buffer.value.get())[tail];
            slot.assume_init_read()
        };

        let next_tail = (tail + 1) % N;
        self.tail.store(next_tail, Ordering::Release);

        Some(value)
    }
}

impl<T, const N: usize> Default for MpscRingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for MpscRingBuffer<T, N> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}
