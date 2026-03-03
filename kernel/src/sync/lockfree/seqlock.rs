// ============================================================================
// src/sync/lockfree/seqlock.rs - Seqlock (Reader-Writer Lock Optimization)
// 読み取りが多い場合に最適化されたロック
// ============================================================================

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Seqlock - 読み取り優先のロック
///
/// 書き込みはロックを取得、読み取りはシーケンス番号で整合性を検証
/// 読み取りが非常に多く、書き込みが少ない場合に最適
pub struct Seqlock<T> {
    sequence: AtomicUsize,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Seqlock<T> {}
unsafe impl<T: Send + Sync> Sync for Seqlock<T> {}

impl<T: Copy> Seqlock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            sequence: AtomicUsize::new(0),
            data: UnsafeCell::new(value),
        }
    }

    /// 読み取り（ロックフリー、整合性検証付き）
    pub fn read(&self) -> T {
        loop {
            let seq1 = self.sequence.load(Ordering::Acquire);

            // 奇数の場合は書き込み中なのでリトライ
            if seq1 & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }

            // データを読み取り
            let value = unsafe { *self.data.get() };

            // シーケンス番号が変わっていないか確認
            core::sync::atomic::fence(Ordering::Acquire);
            let seq2 = self.sequence.load(Ordering::Relaxed);

            if seq1 == seq2 {
                return value;
            }

            // 書き込みが発生したのでリトライ
            core::hint::spin_loop();
        }
    }

    /// 書き込み（排他ロック）
    pub fn write(&self, value: T) {
        // シーケンス番号をインクリメント（奇数に）
        let _seq = self.sequence.fetch_add(1, Ordering::Acquire);

        // データを書き込み
        unsafe {
            *self.data.get() = value;
        }

        // シーケンス番号をインクリメント（偶数に）
        self.sequence.fetch_add(1, Ordering::Release);
    }

    /// 書き込みガードを取得
    pub fn write_guard(&self) -> SeqlockWriteGuard<'_, T> {
        // シーケンス番号をインクリメント（奇数に）
        self.sequence.fetch_add(1, Ordering::Acquire);

        SeqlockWriteGuard { lock: self }
    }
}

/// Seqlock 書き込みガード
pub struct SeqlockWriteGuard<'a, T> {
    lock: &'a Seqlock<T>,
}

impl<'a, T> core::ops::Deref for SeqlockWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for SeqlockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SeqlockWriteGuard<'a, T> {
    fn drop(&mut self) {
        // シーケンス番号をインクリメント（偶数に）
        self.lock.sequence.fetch_add(1, Ordering::Release);
    }
}
