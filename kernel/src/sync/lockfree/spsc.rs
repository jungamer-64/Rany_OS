// ============================================================================
// src/sync/lockfree/spsc.rs - SPSC (Single-Producer Single-Consumer) リングバッファ
// 設計書 4.3: コア間通信が必要な場合は、ロックフリーなリングバッファを
// 用いたメッセージパッシングを行う
// ============================================================================

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::CacheLinePadded;

/// ロックフリーSPSC (Single-Producer Single-Consumer) リングバッファ
///
/// 設計書 4.3: コア間通信が必要な場合は、ロックフリーなリングバッファを
/// 用いたメッセージパッシングを行う
///
/// # 特徴
/// - 単一プロデューサー・単一コンシューマー
/// - ロックフリー（CASベース）
/// - キャッシュライン最適化
/// - ゼロコピー（可能な場合）
#[repr(C, align(64))]
pub struct SpscRingBuffer<T, const N: usize> {
    /// 書き込みインデックス（プロデューサー所有）
    head: CacheLinePadded<AtomicUsize>,
    /// 読み取りインデックス（コンシューマー所有）
    tail: CacheLinePadded<AtomicUsize>,
    /// バッファ（キャッシュライン境界にアラインメント）
    buffer: CacheLinePadded<UnsafeCell<[MaybeUninit<T>; N]>>,
}

// SAFETY: SpscRingBufferはSend/Sync安全
// - headはプロデューサーのみが書き込み
// - tailはコンシューマーのみが書き込み
// - バッファはatomicインデックスで保護
unsafe impl<T: Send, const N: usize> Send for SpscRingBuffer<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for SpscRingBuffer<T, N> {}

impl<T, const N: usize> SpscRingBuffer<T, N> {
    /// 新しいリングバッファを作成
    ///
    /// # Panics
    /// Nが2以上でない場合パニック
    pub const fn new() -> Self {
        assert!(N >= 2, "Ring buffer must have at least 2 slots");

        Self {
            head: CacheLinePadded::new(AtomicUsize::new(0)),
            tail: CacheLinePadded::new(AtomicUsize::new(0)),
            buffer: CacheLinePadded::new(UnsafeCell::new(unsafe {
                MaybeUninit::uninit().assume_init()
            })),
        }
    }

    /// キャパシティを取得（実際に使用可能なスロット数はN-1）
    #[inline]
    pub const fn capacity(&self) -> usize {
        N - 1
    }

    /// 現在の要素数を取得
    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail) % N
    }

    /// バッファが空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head == tail
    }

    /// バッファが満杯かどうか
    #[inline]
    pub fn is_full(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        (head.wrapping_add(1)) % N == tail
    }

    /// 要素をプッシュ（プロデューサー側）
    ///
    /// # Returns
    /// - `Ok(())` - 成功
    /// - `Err(value)` - バッファが満杯で失敗（値を返却）
    #[inline]
    pub fn push(&self, value: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Relaxed);
        let next_head = (head + 1) % N;

        // 満杯チェック
        if next_head == self.tail.load(Ordering::Acquire) {
            return Err(value);
        }

        // バッファに書き込み
        unsafe {
            let slot = &mut (*self.buffer.value.get())[head];
            slot.write(value);
        }

        // headを更新（Releaseでコンシューマーに可視化）
        self.head.store(next_head, Ordering::Release);

        Ok(())
    }

    /// 要素をポップ（コンシューマー側）
    ///
    /// # Returns
    /// - `Some(value)` - 成功
    /// - `None` - バッファが空
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);

        // 空チェック（Acquireでプロデューサーの書き込みを可視化）
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }

        // バッファから読み取り
        let value = unsafe {
            let slot = &(*self.buffer.value.get())[tail];
            slot.assume_init_read()
        };

        // tailを更新
        let next_tail = (tail + 1) % N;
        self.tail.store(next_tail, Ordering::Release);

        Some(value)
    }

    /// 要素を覗き見（コンシューマー側、削除しない）
    #[inline]
    pub fn peek(&self) -> Option<&T> {
        let tail = self.tail.load(Ordering::Relaxed);

        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }

        unsafe {
            let slot = &(*self.buffer.value.get())[tail];
            Some(slot.assume_init_ref())
        }
    }
}

impl<T, const N: usize> Default for SpscRingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for SpscRingBuffer<T, N> {
    fn drop(&mut self) {
        // 残っている要素をドロップ
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self.pop().is_some() {}
    }
}
