// ============================================================================
// src/sync/lockfree/mpmc.rs - MPMC (Multi-Producer Multi-Consumer) リングバッファ
// 汎用的なコア間通信用
// ============================================================================

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use super::CacheLinePadded;
use super::backoff::Backoff;

/// スロットの状態
const SLOT_EMPTY: u32 = 0;
const SLOT_WRITING: u32 = 1;
const SLOT_READY: u32 = 2;
const SLOT_READING: u32 = 3;

/// MPMCスロット
///
/// 各スロットは独立した状態を持ち、複数のプロデューサーとコンシューマーが
/// 同時に異なるスロットにアクセス可能
#[repr(C, align(64))]
struct MpmcSlot<T> {
    /// スロットの状態
    state: AtomicU32,
    /// シーケンス番号（ABAプロブレム対策）
    sequence: AtomicUsize,
    /// データ
    data: UnsafeCell<MaybeUninit<T>>,
}

impl<T> MpmcSlot<T> {
    const fn new(seq: usize) -> Self {
        Self {
            state: AtomicU32::new(SLOT_EMPTY),
            sequence: AtomicUsize::new(seq),
            data: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

/// ロックフリーMPMC (Multi-Producer Multi-Consumer) リングバッファ
///
/// 複数のプロデューサーと複数のコンシューマーが同時に操作可能
/// 各スロットに独立した状態を持ち、競合を最小化
///
/// # 特徴
/// - 複数プロデューサー・複数コンシューマー
/// - スロットレベルのロックフリー操作
/// - ABAプロブレム対策（シーケンス番号）
/// - 指数バックオフによる競合緩和
#[repr(C, align(64))]
pub struct MpmcRingBuffer<T, const N: usize> {
    /// 書き込み位置
    head: CacheLinePadded<AtomicUsize>,
    /// 読み取り位置
    tail: CacheLinePadded<AtomicUsize>,
    /// スロット配列
    slots: [MpmcSlot<T>; N],
}

// SAFETY: MPMCRingBufferはSend/Sync安全
// - 各スロットは独立した状態を持つ
// - CAS操作で競合を解決
unsafe impl<T: Send, const N: usize> Send for MpmcRingBuffer<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for MpmcRingBuffer<T, N> {}

impl<T, const N: usize> MpmcRingBuffer<T, N> {
    const fn init_slots() -> [MpmcSlot<T>; N] {
        let mut slots: [MaybeUninit<MpmcSlot<T>>; N] = [const { MaybeUninit::uninit() }; N];
        let mut i = 0;
        while i < N {
            slots[i] = MaybeUninit::new(MpmcSlot::new(i));
            i += 1;
        }

        // SAFETY: Every element in `slots` is initialized exactly once above.
        unsafe {
            core::mem::transmute_copy::<[MaybeUninit<MpmcSlot<T>>; N], [MpmcSlot<T>; N]>(&slots)
        }
    }

    /// 新しいMPMCリングバッファを作成
    ///
    /// # Panics
    /// Nが2以上でない場合パニック
    pub const fn new() -> Self {
        assert!(N >= 2, "Ring buffer must have at least 2 slots");

        Self {
            head: CacheLinePadded::new(AtomicUsize::new(0)),
            tail: CacheLinePadded::new(AtomicUsize::new(0)),
            slots: Self::init_slots(),
        }
    }

    /// キャパシティを取得
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// 現在の要素数を推定
    ///
    /// 注意: この値は概算であり、同時アクセス中は正確でない場合があります
    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    /// バッファが空かどうかを推定
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 要素をプッシュ（複数プロデューサー対応）
    ///
    /// # Returns
    /// - `Ok(())` - 成功
    /// - `Err(value)` - バッファが満杯で失敗（値を返却）
    pub fn push(&self, value: T) -> Result<(), T> {
        let mut backoff = Backoff::new();

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            let head = self.head.load(Ordering::Relaxed);
            let tail = self.tail.load(Ordering::Acquire);

            // 満杯チェック
            if head.wrapping_sub(tail) >= N {
                if backoff.is_completed() {
                    return Err(value);
                }
                backoff.spin();
                continue;
            }

            let index = head % N;
            let slot = &self.slots[index];
            let seq = slot.sequence.load(Ordering::Acquire);

            // スロットが書き込み可能かチェック
            if seq == head {
                // headを予約
                match self.head.compare_exchange_weak(
                    head,
                    head.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // 書き込み
                        unsafe {
                            (*slot.data.get()).write(value);
                        }

                        // シーケンス番号を更新（読み取り可能に）
                        slot.sequence.store(head.wrapping_add(1), Ordering::Release);

                        return Ok(());
                    }
                    Err(_) => {
                        // 競合、バックオフしてリトライ
                        backoff.snooze();
                    }
                }
            } else if seq < head {
                // スロットがまだ準備できていない（コンシューマー遅れ）
                backoff.spin();
            } else {
                // 他のプロデューサーが先に予約した
                backoff.snooze();
            }
        }
    }

    /// 要素をポップ（複数コンシューマー対応）
    ///
    /// # Returns
    /// - `Some(value)` - 成功
    /// - `None` - バッファが空
    pub fn pop(&self) -> Option<T> {
        let mut backoff = Backoff::new();

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            let tail = self.tail.load(Ordering::Relaxed);
            let head = self.head.load(Ordering::Acquire);

            // 空チェック
            if tail == head {
                return None;
            }

            let index = tail % N;
            let slot = &self.slots[index];
            let seq = slot.sequence.load(Ordering::Acquire);
            let expected_seq = tail.wrapping_add(1);

            // スロットが読み取り可能かチェック
            if seq == expected_seq {
                // tailを予約
                match self.tail.compare_exchange_weak(
                    tail,
                    tail.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // 読み取り
                        let value = unsafe { (*slot.data.get()).assume_init_read() };

                        // シーケンス番号を更新（書き込み可能に）
                        slot.sequence.store(tail.wrapping_add(N), Ordering::Release);

                        return Some(value);
                    }
                    Err(_) => {
                        // 競合、バックオフしてリトライ
                        backoff.snooze();
                    }
                }
            } else if seq < expected_seq {
                // データがまだ書き込まれていない
                if tail == self.tail.load(Ordering::Relaxed) {
                    // tailが変わっていないので、本当に空
                    if backoff.is_completed() {
                        return None;
                    }
                    backoff.spin();
                }
            } else {
                // 他のコンシューマーが先に読み取った
                backoff.snooze();
            }
        }
    }

    /// 非ブロッキングでプッシュを試行
    #[inline]
    pub fn try_push(&self, value: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        // 満杯チェック
        if head.wrapping_sub(tail) >= N {
            return Err(value);
        }

        let index = head % N;
        let slot = &self.slots[index];
        let seq = slot.sequence.load(Ordering::Acquire);

        if seq != head {
            return Err(value);
        }

        // headを予約
        if self
            .head
            .compare_exchange(
                head,
                head.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return Err(value);
        }

        // 書き込み
        unsafe {
            (*slot.data.get()).write(value);
        }

        // シーケンス番号を更新
        slot.sequence.store(head.wrapping_add(1), Ordering::Release);

        Ok(())
    }

    /// 非ブロッキングでポップを試行
    #[inline]
    pub fn try_pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        // 空チェック
        if tail == head {
            return None;
        }

        let index = tail % N;
        let slot = &self.slots[index];
        let seq = slot.sequence.load(Ordering::Acquire);
        let expected_seq = tail.wrapping_add(1);

        if seq != expected_seq {
            return None;
        }

        // tailを予約
        if self
            .tail
            .compare_exchange(
                tail,
                tail.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return None;
        }

        // 読み取り
        let value = unsafe { (*slot.data.get()).assume_init_read() };

        // シーケンス番号を更新
        slot.sequence.store(tail.wrapping_add(N), Ordering::Release);

        Some(value)
    }
}

impl<T, const N: usize> Default for MpmcRingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> core::fmt::Debug for MpmcRingBuffer<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MpmcRingBuffer")
            .field("capacity", &N)
            .field("len", &self.len())
            .finish()
    }
}

impl<T, const N: usize> Drop for MpmcRingBuffer<T, N> {
    fn drop(&mut self) {
        // 残っている要素をドロップ
        while self.pop().is_some() {}
    }
}

// ============================================================================
// QEMU smoke tests
// ============================================================================

#[cfg(feature = "qemu-test-export")]
#[path = "qemu_tests.rs"]
pub mod qemu_tests;
