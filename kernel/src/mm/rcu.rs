// SPDX-License-Identifier: MIT
// ExoRust Kernel - RCU (Read-Copy-Update) synchronization primitive
//
// RCUは読み取り側が非常に軽量で、書き込み側が遅延解放を待つ同期プリミティブ。
// VMAの検索、ルーティングテーブルの参照など、読み取り優位なデータ構造に最適。
#![allow(dead_code)]

use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::collections::VecDeque;
use alloc::boxed::Box;
use alloc::vec::Vec;
use spin::Mutex;
use crate::mm::per_cpu;

/// RCUのグレース期間を追跡するためのエポックカウンタ
///
/// 全CPUが少なくとも1回のコンテキストスイッチを行うと、
/// その時点で保持されていた全ての参照が解放されたと見なせる
static RCU_GLOBAL_EPOCH: AtomicUsize = AtomicUsize::new(0);



/// RCUコンテキストスイッチカウンタ（グレース期間検出用）
static RCU_CONTEXT_SWITCHES: AtomicUsize = AtomicUsize::new(0);

/// グレース期間終了に必要なコンテキストスイッチ数
/// 保守的に2回とする（全CPUが少なくとも1回は切り替わる）
pub const RCU_GRACE_PERIOD_SWITCHES: usize = 2;

// ============================================================================
// RCU Read-side API
// ============================================================================

/// RCU読み取りセクションのガード
///
/// このガードが生存している間、RCU保護されたデータの参照は有効
pub struct RcuReadGuard {
    _marker: core::marker::PhantomData<*const ()>,
}

impl RcuReadGuard {
    /// 新しいRCU読み取りガードを作成
    fn new() -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }
}

impl Drop for RcuReadGuard {
    fn drop(&mut self) {
        rcu_read_unlock_internal();
    }
}

/// RCU読み取りセクションを開始
///
/// このセクション内では、RCU保護されたポインタは安全にderefできる
/// 非常に軽量（メモリバリアのみ）
///
/// # Returns
/// RcuReadGuard - スコープを抜けると自動的にunlock
#[inline]
pub fn rcu_read_lock() -> RcuReadGuard {
    // 読み取り開始を記録（compiler fence のみ、実際のロックなし）
    core::sync::atomic::compiler_fence(Ordering::Acquire);
    
    // Increment local read depth
    unsafe {
        let gs_base = per_cpu::read_gs_base();
        if gs_base != 0 {
            let pcp = &*(gs_base as *const per_cpu::PerCpuData);
            pcp.rcu_state.read_depth.fetch_add(1, Ordering::Relaxed);
        } else {
             // Fallback for non-SMP/init
             // Using interrupts disabled can be a fallback? 
             // Or just do nothing and rely on non-preemption if early?
        }
    }
    
    RcuReadGuard::new()
}

/// RCU読み取りセクションを終了（内部用）
#[inline]
fn rcu_read_unlock_internal() {
    unsafe {
        let gs_base = per_cpu::read_gs_base();
        if gs_base != 0 {
            let pcp = &*(gs_base as *const per_cpu::PerCpuData);
            pcp.rcu_state.read_depth.fetch_sub(1, Ordering::Relaxed);
        }
    }
    core::sync::atomic::compiler_fence(Ordering::Release);
}

/// 現在RCU読み取りセクション内かどうか
#[inline]
pub fn rcu_read_active() -> bool {
    unsafe {
        let gs_base = per_cpu::read_gs_base();
        if gs_base != 0 {
            let pcp = &*(gs_base as *const per_cpu::PerCpuData);
            pcp.rcu_state.read_depth.load(Ordering::Relaxed) > 0
        } else {
            false
        }
    }
}

// ============================================================================
// RCU Write-side / Grace Period API
// ============================================================================

/// 現在のRCUエポックを取得
#[inline]
pub fn rcu_current_epoch() -> usize {
    RCU_GLOBAL_EPOCH.load(Ordering::Acquire)
}

/// RCUエポックを進める（コンテキストスイッチ時に呼ぶ）
#[inline]
pub fn rcu_advance_epoch() {
    RCU_GLOBAL_EPOCH.fetch_add(1, Ordering::Release);
}

/// コンテキストスイッチをRCUに通知
///
/// スケジューラのコンテキストスイッチ処理から呼び出す
#[inline]
pub fn rcu_note_context_switch() {
    unsafe {
        let gs = per_cpu::read_gs_base();
        if gs != 0 {
            let pcp = &*(gs as *const per_cpu::PerCpuData);
            // Only report QS if not in a read section
            if pcp.rcu_state.read_depth.load(Ordering::Relaxed) == 0 {
                 pcp.rcu_state.qs_count.fetch_add(1, Ordering::Release);
            }
        }
    }
    // Also update global for compatibility if needed, but we rely on local now.
    // RCU_CONTEXT_SWITCHES.fetch_add(1, Ordering::Release);
}

/// 現在のコンテキストスイッチカウントを取得
#[inline]
pub fn rcu_context_switch_count() -> usize {
    RCU_CONTEXT_SWITCHES.load(Ordering::Acquire)
}

/// 同期的にグレース期間の終了を待つ
///
/// 呼び出し時点で存在した全てのRCU読み取りセクションが終了するまでブロック
///
/// # Warning
/// これはビジーウェイトなので、割り込みコンテキストでは使用しないこと
/// 同期的にグレース期間の終了を待つ
///
/// 呼び出し時点で存在した全てのRCU読み取りセクションが終了するまでブロック
///
/// # Warning
/// これはビジーウェイトなので、割り込みコンテキストでは使用しないこと
pub fn synchronize_rcu() {
    // 1. Snapshot QS counts for all online CPUs
    let mut snapshots = Vec::new();
    for i in 0..per_cpu::MAX_CPUS {
        if per_cpu::is_cpu_online(i) {
             unsafe {
                 let pcp = per_cpu::get_per_cpu_data(i);
                 snapshots.push((i, pcp.rcu_state.qs_count.load(Ordering::Acquire)));
             }
        }
    }

    // 2. Wait for each active CPU to pass through a quiescent state
    // (switch context or go offline)
    for (cpu_id, snap_val) in snapshots {
        loop {
            if !per_cpu::is_cpu_online(cpu_id) {
                // CPU went offline -> Quiescent State
                break;
            }
            unsafe {
                let pcp = per_cpu::get_per_cpu_data(cpu_id);
                let current_val = pcp.rcu_state.qs_count.load(Ordering::Acquire);
                if current_val != snap_val {
                    break;
                }
            }
            core::hint::spin_loop();
        }
    }

    // 3. Advance epoch to release callbacks
    rcu_advance_epoch();
}

// ============================================================================
// Deferred Callback (call_rcu) API
// ============================================================================

/// RCUコールバック関数の型
pub type RcuCallback = fn(*mut u8);

/// 遅延解放用のコールバックエントリ
#[derive(Debug)]
pub struct RcuCallbackEntry {
    /// 解放対象のポインタ
    ptr: *mut u8,
    /// コールバック関数
    callback: RcuCallback,
    /// 登録時のエポック
    epoch: usize,
}

// Safety: ポインタはBox::into_raw()で作られ、グレース期間後に解放される
unsafe impl Send for RcuCallbackEntry {}

/// 遅延コールバックキュー（簡易実装: グローバル1つ）
/// 本格実装ではPer-CPUキューを使用する
static RCU_CALLBACK_QUEUE: spin::Mutex<VecDeque<RcuCallbackEntry>> =
    spin::Mutex::new(VecDeque::new());

/// グレース期間後にコールバックを呼び出す（非同期版synchronize_rcu）
///
/// # Arguments
/// * `ptr` - 解放対象のポインタ
/// * `callback` - グレース期間後に呼び出されるコールバック
///
/// # Example
/// ```ignore
/// fn free_old_vma(ptr: *mut u8) {
///     unsafe { drop(Box::from_raw(ptr as *mut VmArea)); }
/// }
///
/// call_rcu(old_vma as *mut u8, free_old_vma);
/// ```
/// グレース期間後にコールバックを呼び出す（非同期版synchronize_rcu）
///
/// # Arguments
/// * `ptr` - 解放対象のポインタ
/// * `callback` - グレース期間後に呼び出されるコールバック
pub fn call_rcu(ptr: *mut u8, callback: RcuCallback) {
    let entry = RcuCallbackEntry {
        ptr,
        callback,
        epoch: rcu_current_epoch(),
    };

    // Try per-CPU queue first
    unsafe {
        let gs_base = per_cpu::read_gs_base();
        if gs_base != 0 {
            let pcp = &*(gs_base as *const per_cpu::PerCpuData);
            pcp.rcu_state.batch_queue.lock().push_back(entry);
        } else {
            // Fallback for early boot / non-PerCPU context (should be rare)
            // Just leak or use a temporary global? 
            // For now, panic/warn or use static fallback.
            // Using the static fallback defined previously (if kept) or simple static.
            RCU_CALLBACK_QUEUE.lock().push_back(entry);
        }
    }
}

/// 期限切れのRCUコールバックを処理 (Per-CPU)
///
/// 定期的に呼び出す（スケジューラのアイドルループやタイマー割り込みから）
pub fn rcu_process_callbacks() {
    let current_epoch = rcu_current_epoch();
    
    unsafe {
        let gs_base = per_cpu::read_gs_base();
        if gs_base == 0 { return; }
        let pcp = &*(gs_base as *const per_cpu::PerCpuData);
        let mut queue = pcp.rcu_state.batch_queue.lock();

        // グレース期間が経過したコールバックを処理
        while let Some(entry) = queue.front() {
            // エポックが2以上離れていればグレース期間経過
            if current_epoch.wrapping_sub(entry.epoch) >= 2 {
                let entry = queue.pop_front().unwrap();
                drop(queue); // ロックを解放してからコールバック実行

                // コールバック呼び出し
                (entry.callback)(entry.ptr);

                // ロック再取得
                queue = pcp.rcu_state.batch_queue.lock();
            } else {
                break;
            }
        }
    }
}

/// ペンディング中のRCUコールバック数を取得 (Current CPU)
pub fn rcu_pending_callbacks() -> usize {
    unsafe {
        let gs_base = per_cpu::read_gs_base();
        if gs_base != 0 {
            let pcp = &*(gs_base as *const per_cpu::PerCpuData);
            pcp.rcu_state.batch_queue.lock().len()
        } else {
            RCU_CALLBACK_QUEUE.lock().len()
        }
    }
}

// ============================================================================
// RCU-protected pointer wrapper
// ============================================================================

/// RCU保護されたポインタ
///
/// 読み取り側: rcu_read_lock()のガード内で安全にderef
/// 書き込み側: 新しい値を公開後、古い値をcall_rcu()で解放
pub struct RcuPtr<T> {
    ptr: AtomicUsize,
    _marker: core::marker::PhantomData<*mut T>,
}

impl<T> RcuPtr<T> {
    /// 新しいRcuPtrを作成
    pub fn new(value: Box<T>) -> Self {
        Self {
            ptr: AtomicUsize::new(Box::into_raw(value) as usize),
            _marker: core::marker::PhantomData,
        }
    }

    /// nullポインタで初期化
    pub const fn null() -> Self {
        Self {
            ptr: AtomicUsize::new(0),
            _marker: core::marker::PhantomData,
        }
    }

    /// RCU読み取りセクション内でポインタを取得
    ///
    /// # Safety
    /// rcu_read_lock()のガードが生存している間のみ有効
    #[inline]
    pub unsafe fn load(&self, _guard: &RcuReadGuard) -> *const T {
        self.ptr.load(Ordering::Acquire) as *const T
    }

    /// 新しい値を公開（古い値を返す）
    ///
    /// 戻り値は呼び出し側がcall_rcu()等で適切に解放する責任がある
    pub fn swap(&self, new_value: Box<T>) -> *mut T {
        let new_ptr = Box::into_raw(new_value) as usize;
        let old_ptr = self.ptr.swap(new_ptr, Ordering::AcqRel);
        old_ptr as *mut T
    }

    /// 現在の生ポインタを取得（デバッグ用）
    pub fn as_ptr(&self) -> *const T {
        self.ptr.load(Ordering::Acquire) as *const T
    }
}

// Safety: RcuPtrはAtomicで保護されており、スレッド間で共有可能
unsafe impl<T: Send> Send for RcuPtr<T> {}
unsafe impl<T: Sync> Sync for RcuPtr<T> {}

// ============================================================================
// Per-CPU RCU state (simplified version)
// ============================================================================

/// Per-CPU RCU状態
///
/// 本格実装ではPer-CPU変数として配置する
#[derive(Debug)]
pub struct PerCpuRcuState {
    /// このCPUがquiescent state（静止状態）に入った回数
    pub qs_count: AtomicUsize,
    /// 最後に報告したグレース期間番号
    pub last_gp: AtomicUsize,
    /// このCPUでの読み取りセクションネスト深度
    pub read_depth: AtomicUsize,
    /// Callbacks buffered on this CPU (to be moved to global/batch list)
    pub batch_queue: Mutex<VecDeque<RcuCallbackEntry>>,
}

impl PerCpuRcuState {
    /// 新しいPer-CPU RCU状態を作成
    pub const fn new() -> Self {
        Self {
            qs_count: AtomicUsize::new(0),
            last_gp: AtomicUsize::new(0),
            read_depth: AtomicUsize::new(0),
            batch_queue: Mutex::new(VecDeque::new()),
        }
    }

    /// Quiescent stateを報告
    ///
    /// コンテキストスイッチ時やアイドル時に呼び出す
    pub fn report_qs(&self) {
        self.qs_count.fetch_add(1, Ordering::Release);
    }

    /// 読み取りセクション開始
    pub fn enter_read_section(&self) {
        self.read_depth.fetch_add(1, Ordering::Acquire);
    }

    /// 読み取りセクション終了
    pub fn exit_read_section(&self) {
        self.read_depth.fetch_sub(1, Ordering::Release);
    }

    /// 現在読み取りセクション内かどうか
    pub fn in_read_section(&self) -> bool {
        self.read_depth.load(Ordering::Acquire) > 0
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// RCUサブシステムの統計情報
#[derive(Debug, Clone, Copy)]
pub struct RcuStats {
    /// 現在のグローバルエポック
    pub current_epoch: usize,
    /// コンテキストスイッチ総数
    pub context_switches: usize,
    /// ペンディングコールバック数
    pub pending_callbacks: usize,
}

/// RCU統計を取得
pub fn rcu_stats() -> RcuStats {
    RcuStats {
        current_epoch: rcu_current_epoch(),
        context_switches: rcu_context_switch_count(),
        pending_callbacks: rcu_pending_callbacks(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_rcu_read_guard() {
        {
            let _guard = rcu_read_lock();
            assert!(rcu_read_active());
        }
        // ガードがdropされたので非アクティブ
        assert!(!rcu_read_active());
    }

    #[test_case]
    fn test_rcu_epoch() {
        let epoch1 = rcu_current_epoch();
        rcu_advance_epoch();
        let epoch2 = rcu_current_epoch();
        assert_eq!(epoch2, epoch1 + 1);
    }

    #[test_case]
    fn test_per_cpu_rcu_state() {
        let state = PerCpuRcuState::new();

        assert!(!state.in_read_section());

        state.enter_read_section();
        assert!(state.in_read_section());

        state.exit_read_section();
        assert!(!state.in_read_section());
    }
}

