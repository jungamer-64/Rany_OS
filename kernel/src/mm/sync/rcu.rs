// SPDX-License-Identifier: MIT
// ExoRust Kernel - RCU (Read-Copy-Update) synchronization primitive
//
// RCUは読み取り側が非常に軽量で、書き込み側が遅延解放を待つ同期プリミティブ。
// VMAの検索、ルーティングテーブルの参照など、読み取り優位なデータ構造に最適。
use crate::cpu::CurrentCpu;
use crate::sync::IrqPoisonLock;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

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
    current: CurrentCpu,
}

impl RcuReadGuard {
    /// 新しいRCU読み取りガードを作成
    fn new(current: CurrentCpu) -> Self {
        Self { current }
    }
}

impl Drop for RcuReadGuard {
    fn drop(&mut self) {
        self.current.exit_rcu_read();
        core::sync::atomic::compiler_fence(Ordering::Release);
    }
}

/// RCU読み取りセクションを開始
///
/// このセクション内では、RCU保護されたポインタは安全にderefできる
/// 非常に軽量（メモリバリアのみ）
///
/// # Returns
/// RcuReadGuard - スコープを抜けると自動的にunlock
///
/// # Panics
/// Panics if CPU-local state is not installed on the executing CPU.
#[inline]
pub fn rcu_read_lock() -> RcuReadGuard {
    // 読み取り開始を記録（compiler fence のみ、実際のロックなし）
    core::sync::atomic::compiler_fence(Ordering::Acquire);

    let current = CurrentCpu::acquire()
        .unwrap_or_else(|| panic!("RCU read-side section entered without CPU-local state"));
    current.enter_rcu_read();
    RcuReadGuard::new(current)
}

/// 現在RCU読み取りセクション内かどうか
///
/// # Panics
/// Panics if CPU-local state is not installed on the executing CPU.
#[inline]
pub fn rcu_read_active() -> bool {
    CurrentCpu::acquire()
        .unwrap_or_else(|| panic!("RCU read state queried without CPU-local state"))
        .rcu_read_active()
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
    let Some(current) = CurrentCpu::acquire() else {
        return;
    };
    if current.note_rcu_quiescent() {
        RCU_CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn quiesce_current_cpu_for_offline() {
    let current = CurrentCpu::acquire()
        .unwrap_or_else(|| panic!("RCU CPU quiescence requires CPU-local state"));
    assert!(
        !current.rcu_read_active(),
        "CPU cannot park inside an RCU read-side section"
    );
    assert!(
        current.note_rcu_quiescent(),
        "CPU failed to publish its final RCU quiescent state"
    );
    RCU_CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
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
///
/// # Panics
/// Panics if the calling CPU is itself inside an RCU read-side section, if an
/// online CPU has no CPU-local state, or if a quiescence wake IPI cannot be
/// delivered.
pub fn synchronize_rcu() {
    let topology = crate::cpu::snapshot();
    let runtime = crate::cpu::runtime();
    let mut snapshots = Vec::new();
    for slot in topology
        .slots()
        .iter()
        .filter(|slot| slot.state.participates_in_rcu())
    {
        let cpu_id = slot.id;
        let local = runtime
            .cpu_local(cpu_id)
            .unwrap_or_else(|| panic!("RCU CPU {} has no CPU-local state", cpu_id));
        snapshots.push((cpu_id, local.remote().rcu_quiescent_count()));
    }
    drop(topology);

    let current_id = CurrentCpu::acquire().map(|current| {
        assert!(
            !current.rcu_read_active(),
            "synchronize_rcu called from an RCU read-side section"
        );
        current.note_rcu_quiescent();
        current.id()
    });
    for &(cpu_id, _) in &snapshots {
        if Some(cpu_id) == current_id {
            continue;
        }
        match crate::cpu::send_ipi(cpu_id, crate::cpu::IpiKind::ExecutorWake) {
            Ok(()) => {}
            Err(crate::cpu::CpuIpiError::CpuStateIneligible { .. })
                if !crate::cpu::snapshot()
                    .slot(cpu_id)
                    .is_some_and(|slot| slot.state.participates_in_rcu()) =>
            {
                continue;
            }
            Err(error) => {
                panic!(
                    "failed to request an RCU quiescent state from CPU {}: {:?}",
                    cpu_id, error
                );
            }
        }
    }

    for (cpu_id, snap_val) in snapshots {
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            if !crate::cpu::snapshot()
                .slot(cpu_id)
                .is_some_and(|slot| slot.state.participates_in_rcu())
            {
                break;
            }
            let local = runtime
                .cpu_local(cpu_id)
                .unwrap_or_else(|| panic!("RCU CPU {} lost its CPU-local state", cpu_id));
            if local.remote().rcu_quiescent_count() != snap_val {
                break;
            }
            core::hint::spin_loop();
        }
    }

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
static RCU_CALLBACK_QUEUE: IrqPoisonLock<VecDeque<RcuCallbackEntry>> =
    IrqPoisonLock::new(VecDeque::new());

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
    RCU_CALLBACK_QUEUE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push_back(entry);
}

/// 期限切れのRCUコールバックを処理
///
/// 定期的に呼び出す（スケジューラのアイドルループやタイマー割り込みから）
pub fn rcu_process_callbacks() {
    let current_epoch = rcu_current_epoch();
    let mut queue = RCU_CALLBACK_QUEUE
        .lock()
        .unwrap_or_else(|error| error.into_inner());

    // グレース期間が経過したコールバックを処理
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while let Some(entry) = queue.front() {
        // エポックが2以上離れていればグレース期間経過
        if current_epoch.wrapping_sub(entry.epoch) >= RCU_GRACE_PERIOD_SWITCHES {
            let entry = queue.pop_front().unwrap();
            drop(queue); // ロックを解放してからコールバック実行

            // コールバック呼び出し
            (entry.callback)(entry.ptr);

            // ロック再取得
            queue = RCU_CALLBACK_QUEUE
                .lock()
                .unwrap_or_else(|error| error.into_inner());
        } else {
            break;
        }
    }
}

/// ペンディング中のRCUコールバック数を取得
pub fn rcu_pending_callbacks() -> usize {
    RCU_CALLBACK_QUEUE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .len()
}

// ============================================================================
// RCU-protected pointer wrapper
// ============================================================================

/// RCU保護されたポインタ（統合版）
#[repr(transparent)]
pub struct RcuPointer<T> {
    ptr: AtomicPtr<T>,
}

impl<T> RcuPointer<T> {
    /// nullポインタで初期化
    pub const fn null() -> Self {
        Self {
            ptr: AtomicPtr::new(null_mut()),
        }
    }

    /// 初期値を持つRCUポインタを作成
    pub fn new(value: Box<T>) -> Self {
        Self {
            ptr: AtomicPtr::new(Box::into_raw(value)),
        }
    }

    /// RCU読み取りセクション内でポインタを取得
    #[inline]
    pub fn get<'a>(&self, _guard: &'a RcuReadGuard) -> Option<&'a T> {
        let ptr = self.ptr.load(Ordering::Acquire);
        if ptr.is_null() {
            None
        } else {
            // Safety: RcuReadGuard 内なので、ポインタは有効
            unsafe { Some(&*ptr) }
        }
    }

    /// RCU読み取りセクション内で生ポインタを取得
    #[inline]
    pub fn get_raw(&self, _guard: &RcuReadGuard) -> *const T {
        self.ptr.load(Ordering::Acquire)
    }

    /// RCUポインタを更新
    #[inline]
    pub fn rcu_assign(&self, new_value: Box<T>) -> *mut T {
        let new_ptr = Box::into_raw(new_value);
        self.ptr.swap(new_ptr, Ordering::Release)
    }

    /// 新しい値を公開（`swap` エイリアス、`rcu_assign` と同等）
    #[inline]
    pub fn swap(&self, new_value: Box<T>) -> *mut T {
        self.rcu_assign(new_value)
    }

    /// nullを設定
    #[inline]
    pub fn set_null(&self) -> *mut T {
        self.ptr.swap(null_mut(), Ordering::Release)
    }

    /// 現在の生ポインタを取得（デバッグ用）
    pub fn as_ptr(&self) -> *const T {
        self.ptr.load(Ordering::Acquire)
    }

    /// RCU読み取りセクション内でポインタをロード（unsafe版、RcuPtr互換）
    ///
    /// # Safety
    /// rcu_read_lock() のガードが生存している間のみ有効
    #[inline]
    pub unsafe fn load(&self, _guard: &RcuReadGuard) -> *const T {
        self.ptr.load(Ordering::Acquire)
    }
}

impl<T> Default for RcuPointer<T> {
    fn default() -> Self {
        Self::null()
    }
}

// Safety: AtomicPtr を介したアクセスのみ
unsafe impl<T: Send + Sync> Send for RcuPointer<T> {}
unsafe impl<T: Send + Sync> Sync for RcuPointer<T> {}

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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_rcu_epoch() {
        let epoch1 = rcu_current_epoch();
        rcu_advance_epoch();
        let epoch2 = rcu_current_epoch();
        assert_eq!(epoch2, epoch1 + 1);
    }
}
