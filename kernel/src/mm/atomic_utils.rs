// ============================================================================
// mm/atomic_utils.rs - アトミック操作ユーティリティ
// ============================================================================
//
// このモジュールは、no_std環境で使用可能なアトミックラッパー型を提供します。
//
// ## 背景
// - `core::sync::atomic`は全プラットフォームで`AtomicU8`/`AtomicU16`を保証しない
// - `AtomicUsize`をベースにしたラッパーで互換性を確保
//
// ## 使用箇所
// - `RemoteFreeRing`: Vyukov MPSCキューのエントリ管理
// - 将来的な`Magazine`のアトミック操作
//
// ## 移行元
// - iova_bitmap.rs:1770-1860 (IOVA_MM_MIGRATION_PLAN Phase 0.2)
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicUsize, Ordering};

// ============================================================================
// AtomicU8: 8ビットアトミック操作
// ============================================================================

/// Atomic u8 wrapper
///
/// `core::sync::atomic`は全プラットフォームで`AtomicU8`を保証しないため、
/// `AtomicUsize`をベースにしたラッパーを提供する。
///
/// # 使用例
///
/// ```rust
/// use crate::mm::atomic_utils::AtomicU8;
/// use core::sync::atomic::Ordering;
///
/// let counter = AtomicU8::new(0);
/// counter.store(42, Ordering::Release);
/// assert_eq!(counter.load(Ordering::Acquire), 42);
/// ```
#[repr(transparent)]
pub struct AtomicU8(AtomicUsize);

impl AtomicU8 {
    /// 新しいAtomicU8を作成
    #[inline]
    pub const fn new(v: u8) -> Self {
        Self(AtomicUsize::new(v as usize))
    }

    /// 値を格納
    #[inline]
    pub fn store(&self, v: u8, order: Ordering) {
        self.0.store(v as usize, order);
    }

    /// 値を読み込み
    #[inline]
    pub fn load(&self, order: Ordering) -> u8 {
        self.0.load(order) as u8
    }

    /// アトミックにAND演算を行い、以前の値を返す
    ///
    /// CASループを使用（AtomicUsizeの操作は全ビットに影響するため）
    #[inline]
    pub fn fetch_and(&self, val: u8, order: Ordering) -> u8 {
        loop {
            let current = self.0.load(Ordering::Acquire);
            let new_val = (current as u8) & val;
            if self
                .0
                .compare_exchange_weak(current, new_val as usize, order, Ordering::Relaxed)
                .is_ok()
            {
                return current as u8;
            }
            core::hint::spin_loop();
        }
    }

    /// アトミックにOR演算を行い、以前の値を返す
    ///
    /// CASループを使用（AtomicUsizeの操作は全ビットに影響するため）
    #[inline]
    pub fn fetch_or(&self, val: u8, order: Ordering) -> u8 {
        loop {
            let current = self.0.load(Ordering::Acquire);
            let new_val = (current as u8) | val;
            if self
                .0
                .compare_exchange_weak(current, new_val as usize, order, Ordering::Relaxed)
                .is_ok()
            {
                return current as u8;
            }
            core::hint::spin_loop();
        }
    }

    /// アトミックにXOR演算を行い、以前の値を返す
    #[inline]
    pub fn fetch_xor(&self, val: u8, order: Ordering) -> u8 {
        loop {
            let current = self.0.load(Ordering::Acquire);
            let new_val = (current as u8) ^ val;
            if self
                .0
                .compare_exchange_weak(current, new_val as usize, order, Ordering::Relaxed)
                .is_ok()
            {
                return current as u8;
            }
            core::hint::spin_loop();
        }
    }

    /// アトミックに加算を行い、以前の値を返す
    #[inline]
    pub fn fetch_add(&self, val: u8, order: Ordering) -> u8 {
        loop {
            let current = self.0.load(Ordering::Acquire);
            let new_val = (current as u8).wrapping_add(val);
            if self
                .0
                .compare_exchange_weak(current, new_val as usize, order, Ordering::Relaxed)
                .is_ok()
            {
                return current as u8;
            }
            core::hint::spin_loop();
        }
    }

    /// アトミックに減算を行い、以前の値を返す
    #[inline]
    pub fn fetch_sub(&self, val: u8, order: Ordering) -> u8 {
        loop {
            let current = self.0.load(Ordering::Acquire);
            let new_val = (current as u8).wrapping_sub(val);
            if self
                .0
                .compare_exchange_weak(current, new_val as usize, order, Ordering::Relaxed)
                .is_ok()
            {
                return current as u8;
            }
            core::hint::spin_loop();
        }
    }

    /// Compare-and-swap操作
    #[inline]
    pub fn compare_exchange(
        &self,
        current: u8,
        new: u8,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u8, u8> {
        self.0
            .compare_exchange(current as usize, new as usize, success, failure)
            .map(|v| v as u8)
            .map_err(|v| v as u8)
    }

    /// Compare-and-swap操作（weak版）
    #[inline]
    pub fn compare_exchange_weak(
        &self,
        current: u8,
        new: u8,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u8, u8> {
        self.0
            .compare_exchange_weak(current as usize, new as usize, success, failure)
            .map(|v| v as u8)
            .map_err(|v| v as u8)
    }

    /// 値をスワップして以前の値を返す
    #[inline]
    pub fn swap(&self, val: u8, order: Ordering) -> u8 {
        self.0.swap(val as usize, order) as u8
    }
}

impl Default for AtomicU8 {
    fn default() -> Self {
        Self::new(0)
    }
}

impl core::fmt::Debug for AtomicU8 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AtomicU8")
            .field(&self.load(Ordering::SeqCst))
            .finish()
    }
}

// ============================================================================
// AtomicU16: 16ビットアトミック操作
// ============================================================================

/// Atomic u16 wrapper
///
/// `core::sync::atomic`は全プラットフォームで`AtomicU16`を保証しないため、
/// `AtomicUsize`をベースにしたラッパーを提供する。
///
/// # 使用例
///
/// ```rust
/// use crate::mm::atomic_utils::AtomicU16;
/// use core::sync::atomic::Ordering;
///
/// let counter = AtomicU16::new(0);
/// counter.store(1000, Ordering::Release);
/// assert_eq!(counter.load(Ordering::Acquire), 1000);
/// ```
#[repr(transparent)]
pub struct AtomicU16(AtomicUsize);

impl AtomicU16 {
    /// 新しいAtomicU16を作成
    #[inline]
    pub const fn new(v: u16) -> Self {
        Self(AtomicUsize::new(v as usize))
    }

    /// 値を格納
    #[inline]
    pub fn store(&self, v: u16, order: Ordering) {
        self.0.store(v as usize, order);
    }

    /// 値を読み込み
    #[inline]
    pub fn load(&self, order: Ordering) -> u16 {
        self.0.load(order) as u16
    }

    /// アトミックに加算を行い、以前の値を返す
    #[inline]
    pub fn fetch_add(&self, val: u16, order: Ordering) -> u16 {
        loop {
            let current = self.0.load(Ordering::Acquire);
            let new_val = (current as u16).wrapping_add(val);
            if self
                .0
                .compare_exchange_weak(current, new_val as usize, order, Ordering::Relaxed)
                .is_ok()
            {
                return current as u16;
            }
            core::hint::spin_loop();
        }
    }

    /// アトミックに減算を行い、以前の値を返す
    #[inline]
    pub fn fetch_sub(&self, val: u16, order: Ordering) -> u16 {
        loop {
            let current = self.0.load(Ordering::Acquire);
            let new_val = (current as u16).wrapping_sub(val);
            if self
                .0
                .compare_exchange_weak(current, new_val as usize, order, Ordering::Relaxed)
                .is_ok()
            {
                return current as u16;
            }
            core::hint::spin_loop();
        }
    }

    /// Compare-and-swap操作
    #[inline]
    pub fn compare_exchange(
        &self,
        current: u16,
        new: u16,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u16, u16> {
        self.0
            .compare_exchange(current as usize, new as usize, success, failure)
            .map(|v| v as u16)
            .map_err(|v| v as u16)
    }

    /// Compare-and-swap操作（weak版）
    #[inline]
    pub fn compare_exchange_weak(
        &self,
        current: u16,
        new: u16,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u16, u16> {
        self.0
            .compare_exchange_weak(current as usize, new as usize, success, failure)
            .map(|v| v as u16)
            .map_err(|v| v as u16)
    }

    /// 値をスワップして以前の値を返す
    #[inline]
    pub fn swap(&self, val: u16, order: Ordering) -> u16 {
        self.0.swap(val as usize, order) as u16
    }
}

impl Default for AtomicU16 {
    fn default() -> Self {
        Self::new(0)
    }
}

impl core::fmt::Debug for AtomicU16 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AtomicU16")
            .field(&self.load(Ordering::SeqCst))
            .finish()
    }
}


// ============================================================================
// QEMU Smoke Tests (wave10)
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;
    use core::sync::atomic::Ordering;

    pub fn atomic_u8_basic_smoke() -> bool {
        let a = AtomicU8::new(42);
        let ok1 = a.load(Ordering::SeqCst) == 42;
        a.store(100, Ordering::SeqCst);
        ok1 && a.load(Ordering::SeqCst) == 100
    }

    pub fn atomic_u8_fetch_and_smoke() -> bool {
        let a = AtomicU8::new(0b11110000);
        let prev = a.fetch_and(0b10101010, Ordering::SeqCst);
        prev == 0b11110000 && a.load(Ordering::SeqCst) == 0b10100000
    }

    pub fn atomic_u8_fetch_or_smoke() -> bool {
        let a = AtomicU8::new(0b11110000);
        let prev = a.fetch_or(0b00001111, Ordering::SeqCst);
        prev == 0b11110000 && a.load(Ordering::SeqCst) == 0b11111111
    }

    pub fn atomic_u8_fetch_add_smoke() -> bool {
        let a = AtomicU8::new(100);
        let prev = a.fetch_add(50, Ordering::SeqCst);
        prev == 100 && a.load(Ordering::SeqCst) == 150
    }

    pub fn atomic_u8_wrapping_smoke() -> bool {
        let a = AtomicU8::new(250);
        let prev = a.fetch_add(10, Ordering::SeqCst);
        prev == 250 && a.load(Ordering::SeqCst) == 4
    }

    pub fn atomic_u16_basic_smoke() -> bool {
        let a = AtomicU16::new(1000);
        let ok1 = a.load(Ordering::SeqCst) == 1000;
        a.store(50000, Ordering::SeqCst);
        ok1 && a.load(Ordering::SeqCst) == 50000
    }

    pub fn atomic_u16_fetch_add_smoke() -> bool {
        let a = AtomicU16::new(10000);
        let prev = a.fetch_add(5000, Ordering::SeqCst);
        prev == 10000 && a.load(Ordering::SeqCst) == 15000
    }

    pub fn atomic_u16_wrapping_smoke() -> bool {
        let a = AtomicU16::new(65530);
        let prev = a.fetch_add(10, Ordering::SeqCst);
        prev == 65530 && a.load(Ordering::SeqCst) == 4
    }

    pub fn compare_exchange_smoke() -> bool {
        let a = AtomicU8::new(10);
        let ok1 = a.compare_exchange(10, 20, Ordering::SeqCst, Ordering::SeqCst) == Ok(10);
        let ok2 = a.load(Ordering::SeqCst) == 20;
        let ok3 = a.compare_exchange(10, 30, Ordering::SeqCst, Ordering::SeqCst) == Err(20);
        let ok4 = a.load(Ordering::SeqCst) == 20;
        ok1 && ok2 && ok3 && ok4
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_atomic_u8_basic() {
        let a = AtomicU8::new(42);
        assert_eq!(a.load(Ordering::SeqCst), 42);

        a.store(100, Ordering::SeqCst);
        assert_eq!(a.load(Ordering::SeqCst), 100);
    }

    #[test_case]
    fn test_atomic_u8_fetch_and() {
        let a = AtomicU8::new(0b11110000);
        let prev = a.fetch_and(0b10101010, Ordering::SeqCst);
        assert_eq!(prev, 0b11110000);
        assert_eq!(a.load(Ordering::SeqCst), 0b10100000);
    }

    #[test_case]
    fn test_atomic_u8_fetch_or() {
        let a = AtomicU8::new(0b11110000);
        let prev = a.fetch_or(0b00001111, Ordering::SeqCst);
        assert_eq!(prev, 0b11110000);
        assert_eq!(a.load(Ordering::SeqCst), 0b11111111);
    }

    #[test_case]
    fn test_atomic_u8_fetch_add() {
        let a = AtomicU8::new(100);
        let prev = a.fetch_add(50, Ordering::SeqCst);
        assert_eq!(prev, 100);
        assert_eq!(a.load(Ordering::SeqCst), 150);
    }

    #[test_case]
    fn test_atomic_u8_wrapping() {
        let a = AtomicU8::new(250);
        let prev = a.fetch_add(10, Ordering::SeqCst);
        assert_eq!(prev, 250);
        assert_eq!(a.load(Ordering::SeqCst), 4); // 250 + 10 = 260 → wraps to 4
    }

    #[test_case]
    fn test_atomic_u16_basic() {
        let a = AtomicU16::new(1000);
        assert_eq!(a.load(Ordering::SeqCst), 1000);

        a.store(50000, Ordering::SeqCst);
        assert_eq!(a.load(Ordering::SeqCst), 50000);
    }

    #[test_case]
    fn test_atomic_u16_fetch_add() {
        let a = AtomicU16::new(10000);
        let prev = a.fetch_add(5000, Ordering::SeqCst);
        assert_eq!(prev, 10000);
        assert_eq!(a.load(Ordering::SeqCst), 15000);
    }

    #[test_case]
    fn test_atomic_u16_wrapping() {
        let a = AtomicU16::new(65530);
        let prev = a.fetch_add(10, Ordering::SeqCst);
        assert_eq!(prev, 65530);
        assert_eq!(a.load(Ordering::SeqCst), 4); // 65530 + 10 = 65540 → wraps to 4
    }

    #[test_case]
    fn test_compare_exchange() {
        let a = AtomicU8::new(10);
        
        // 成功ケース
        let result = a.compare_exchange(10, 20, Ordering::SeqCst, Ordering::SeqCst);
        assert_eq!(result, Ok(10));
        assert_eq!(a.load(Ordering::SeqCst), 20);
        
        // 失敗ケース
        let result = a.compare_exchange(10, 30, Ordering::SeqCst, Ordering::SeqCst);
        assert_eq!(result, Err(20));
        assert_eq!(a.load(Ordering::SeqCst), 20);
    }
}

