// ============================================================================
// src/sync/irq_mutex.rs - 割り込み禁止Mutex
// 
// 問題: spin::Mutex はロック中でも割り込みを許可する
// → 割り込みハンドラが同じMutexをロックしようとするとデッドロック
//
// 解決: ロック取得時に cli (Clear Interrupt Flag) で割り込み禁止
//       ロック解放時に sti (Set Interrupt Flag) で割り込み許可
//
// 参考: Linux の spin_lock_irqsave / spin_unlock_irqrestore
// ============================================================================
#![allow(dead_code)]

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// 割り込みフラグ (RFLAGS.IF) を保存して割り込みを禁止
/// 
/// # Returns
/// 元の割り込み有効状態 (true = 有効だった)
#[inline]
fn save_and_disable_interrupts() -> bool {
    let rflags: u64;
    
    unsafe {
        // RFLAGS を読み取り
        asm!(
            "pushfq",
            "pop {0}",
            out(reg) rflags,
            options(nomem, preserves_flags)
        );
        
        // 割り込み禁止 (cli)
        asm!("cli", options(nomem, nostack));
    }
    
    // IF ビット (bit 9) が立っていたら割り込み有効だった
    (rflags & (1 << 9)) != 0
}

/// 割り込みを復元（元々有効だった場合のみ有効化）
#[inline]
fn restore_interrupts(was_enabled: bool) {
    if was_enabled {
        unsafe {
            // 割り込み許可 (sti)
            asm!("sti", options(nomem, nostack));
        }
    }
}

/// 割り込み禁止Mutex
/// 
/// ロック取得時に自動的に割り込みを禁止し、
/// ロック解放時に元の状態に復元する。
/// 
/// # Usage
/// ```ignore
/// static DATA: IrqMutex<u64> = IrqMutex::new(0);
/// 
/// fn example() {
///     let mut guard = DATA.lock();
///     *guard += 1;
///     // guard がドロップされると割り込みが復元される
/// }
/// ```
/// 
/// # 割り込みハンドラからの使用
/// 割り込みハンドラ内でこのMutexをロックしても、
/// 既に割り込みが禁止されているため、デッドロックしない。
pub struct IrqMutex<T: ?Sized> {
    /// スピンロック本体
    locked: AtomicBool,
    /// 保護されるデータ
    data: UnsafeCell<T>,
}

// SAFETY: IrqMutex は排他的アクセスを保証する
unsafe impl<T: ?Sized + Send> Sync for IrqMutex<T> {}
unsafe impl<T: ?Sized + Send> Send for IrqMutex<T> {}

impl<T> IrqMutex<T> {
    /// 新しい IrqMutex を作成
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }
    
    /// ロックを取得
    /// 
    /// 割り込みを禁止してからスピンロックを取得する。
    /// ガードがドロップされると自動的に割り込みが復元される。
    pub fn lock(&self) -> IrqMutexGuard<'_, T> {
        // 1. 割り込みを禁止（現在の状態を保存）
        let irq_was_enabled = save_and_disable_interrupts();
        
        // 2. スピンロックを取得
        while self.locked.compare_exchange_weak(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_err() {
            // スピン中にCPUに休憩を与える (電力効率)
            core::hint::spin_loop();
        }
        
        IrqMutexGuard {
            lock: self,
            irq_was_enabled,
        }
    }
    
    /// ロックを試行（失敗したら即座に返る）
    pub fn try_lock(&self) -> Option<IrqMutexGuard<'_, T>> {
        // 1. 割り込みを禁止
        let irq_was_enabled = save_and_disable_interrupts();
        
        // 2. ロック試行
        if self.locked.compare_exchange(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_ok() {
            Some(IrqMutexGuard {
                lock: self,
                irq_was_enabled,
            })
        } else {
            // ロック失敗 → 割り込みを復元
            restore_interrupts(irq_was_enabled);
            None
        }
    }
    
    /// ロック状態を確認（デバッグ用）
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

/// IrqMutex のガード
/// 
/// ドロップ時にロックを解放し、割り込み状態を復元する。
pub struct IrqMutexGuard<'a, T: ?Sized> {
    lock: &'a IrqMutex<T>,
    irq_was_enabled: bool,
}

impl<T: ?Sized> Deref for IrqMutexGuard<'_, T> {
    type Target = T;
    
    fn deref(&self) -> &T {
        // SAFETY: ロックを保持しているので安全にアクセス可能
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for IrqMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: ロックを保持しているので安全にアクセス可能
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for IrqMutexGuard<'_, T> {
    fn drop(&mut self) {
        // 1. スピンロックを解放
        self.lock.locked.store(false, Ordering::Release);
        
        // 2. 割り込み状態を復元
        restore_interrupts(self.irq_was_enabled);
    }
}

// ============================================================================
// 特殊なケース用のユーティリティ
// ============================================================================

/// 割り込みを禁止した状態で処理を実行
/// 
/// ロックは不要だが、割り込みを一時的に禁止したい場合に使用。
/// 例: 複数のI/Oポートへのアトミックなアクセス
pub fn with_interrupts_disabled<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let was_enabled = save_and_disable_interrupts();
    let result = f();
    restore_interrupts(was_enabled);
    result
}

/// 現在割り込みが有効かどうかを確認
pub fn interrupts_enabled() -> bool {
    let rflags: u64;
    
    unsafe {
        asm!(
            "pushfq",
            "pop {0}",
            out(reg) rflags,
            options(nomem, preserves_flags)
        );
    }
    
    (rflags & (1 << 9)) != 0
}

/// 割り込みを強制的に有効化
/// 
/// # Safety
/// 割り込みハンドラが正しく設定されている必要がある
pub unsafe fn enable_interrupts() {
    unsafe { asm!("sti", options(nomem, nostack)); }
}

/// 割り込みを強制的に無効化
pub fn disable_interrupts() {
    unsafe { asm!("cli", options(nomem, nostack)); }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_irq_mutex_basic() {
        let mutex = IrqMutex::new(42u64);
        
        {
            let mut guard = mutex.lock();
            assert_eq!(*guard, 42);
            *guard = 100;
        }
        
        {
            let guard = mutex.lock();
            assert_eq!(*guard, 100);
        }
    }
    
    #[test]
    fn test_try_lock() {
        let mutex = IrqMutex::new(0u64);
        
        let guard = mutex.lock();
        assert!(mutex.try_lock().is_none()); // 既にロック中
        drop(guard);
        
        assert!(mutex.try_lock().is_some()); // 解放後は取得可能
    }
}
