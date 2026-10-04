// ============================================================================
// src/task/interrupt_waker.rs - Interrupt-Waker Bridge
// 設計書 4.2: 割り込みとWakerのブリッジ
// 設計書 4.2.1: デッドロック回避：割り込みフリーキューの採用
//
// ハードウェア割り込みとRustのasync/await Futureを連携させる機構
// ISRから安全に通知を保存し、schedulerにタスクの再開を通知する
//
// 重要: 2段階Wake方式を採用
// 1. ISR内ではCPU専用のソース通知集合へ記録するのみ
// 2. schedulerが有限のsnapshotを処理してwake()を呼び出す
// ============================================================================
use core::sync::atomic::{AtomicU64, Ordering};
use exorust_sync::{BroadcastEvent, EventListener};

// ============================================================================
// Interrupt Source Types
// ============================================================================

/// 割り込みソースの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InterruptSource {
    /// タイマー割り込み
    Timer,
    /// キーボード割り込み
    Keyboard,

    /// シリアルポート (COM1)
    Serial,
    /// 汎用IRQ
    Irq(u8),
}

impl InterruptSource {
    /// IRQベクターから割り込みソースに変換
    pub fn from_vector(vector: u8) -> Self {
        match vector {
            0x20 => InterruptSource::Timer,
            0x21 => InterruptSource::Keyboard,
            0x24 => InterruptSource::Serial, // COM1 = IRQ4 = 0x20 + 4

            _ => InterruptSource::Irq(vector),
        }
    }

    /// Named sources and raw vectors address the same delivery slot.
    fn to_index(self) -> usize {
        match self {
            Self::Timer => 0x20,
            Self::Keyboard => 0x21,
            Self::Serial => 0x24,
            Self::Irq(vector) => usize::from(vector),
        }
    }
}

/// x86 interrupt vector domain. CPU pending sets derive their size from this.
pub(crate) const MAX_INTERRUPT_INDICES: usize = 256;

// ============================================================================
// Atomic Waker - ISR-safe Waker storage
// ============================================================================

pub use crate::sync::AtomicWaker;

// ============================================================================
// Interrupt Waker Registry
// ============================================================================

/// Source notifications are deferred by CPU; each listener owns its receipt.
pub struct InterruptWakerRegistry {
    events: [BroadcastEvent; MAX_INTERRUPT_INDICES],
    /// 統計: 割り込み回数
    interrupt_count: AtomicU64,
    /// 統計: Wake回数
    wake_count: AtomicU64,
}

impl InterruptWakerRegistry {
    /// 新しいレジストリを作成
    const fn new() -> Self {
        Self {
            events: [const { BroadcastEvent::new() }; MAX_INTERRUPT_INDICES],
            interrupt_count: AtomicU64::new(0),
            wake_count: AtomicU64::new(0),
        }
    }

    /// 割り込みソースのWakerを起動要求（ISRから呼ばれる）
    ///
    /// 2段階Wake方式:
    /// ISR records a bit without initialization, allocation, locks, or callbacks.
    fn wake(&self, source: InterruptSource) {
        self.interrupt_count.fetch_add(1, Ordering::Relaxed);

        if let Some(current) = crate::cpu::CurrentCpu::acquire() {
            current.defer_interrupt_wake(source.to_index());
        }
    }

    /// 保留ソースの有限の snapshot を非割込みコンテキストで処理する。
    /// 同じソースへの通知は合流し、処理中の通知は次回の処理へ残る。
    fn process_pending_events(&self) {
        let Some(current) = crate::cpu::CurrentCpu::acquire() else {
            return;
        };
        current.drain_interrupt_wakes(|idx| {
            self.events[idx].notify();
            self.wake_count.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// 保留中のイベント数を取得
    fn pending_event_count(&self) -> usize {
        let Some(runtime) = crate::cpu::try_runtime() else {
            return 0;
        };
        let snapshot = runtime.snapshot();
        snapshot
            .present()
            .iter()
            .filter_map(|cpu| runtime.cpu_local(cpu))
            .map(|local| local.remote().pending_interrupt_wakes())
            .sum()
    }

    /// 統計を取得
    pub fn stats(&self) -> InterruptWakerStats {
        let registered = self
            .events
            .iter()
            .filter(|event| event.listener_count() > 0)
            .count();

        InterruptWakerStats {
            interrupt_count: self.interrupt_count.load(Ordering::Relaxed),
            wake_count: self.wake_count.load(Ordering::Relaxed),
            registered_sources: registered,
        }
    }
}

/// 割り込みWaker統計
#[derive(Debug, Clone)]
pub struct InterruptWakerStats {
    /// 総割り込み回数
    pub interrupt_count: u64,
    /// 総Wake回数
    pub wake_count: u64,
    /// 登録されている割り込みソース数
    pub registered_sources: usize,
}

// ============================================================================
// Global Registry
// ============================================================================

/// グローバルな割り込みWakerレジストリ
static INTERRUPT_WAKER_REGISTRY: InterruptWakerRegistry = InterruptWakerRegistry::new();

/// 割り込みWakerレジストリにアクセス
pub fn interrupt_waker_registry() -> &'static InterruptWakerRegistry {
    &INTERRUPT_WAKER_REGISTRY
}

/// 割り込みハンドラから呼ばれる（便利関数）
///
/// 【設計書 4.2】2段階Wake方式: ISR安全
/// CPU-local source bits coalesce repeated notifications without losing a source.
#[inline]
pub fn wake_from_interrupt(source: InterruptSource) {
    INTERRUPT_WAKER_REGISTRY.wake(source);
}

/// scheduler の通常コンテキストで割り込み通知を配送する。
///
/// 【設計書 4.2】2段階Wake方式: 非ISRコンテキストで呼び出す
/// ISR 完了後、タスクを選択する前に有限の snapshot を処理する。
#[inline]
pub fn process_interrupt_events() {
    INTERRUPT_WAKER_REGISTRY.process_pending_events();
}

/// 保留中の割り込みイベント数を取得
#[inline]
pub fn pending_interrupt_events() -> usize {
    INTERRUPT_WAKER_REGISTRY.pending_event_count()
}

// ============================================================================
// Interrupt-aware Future helpers
// ============================================================================

/// 割り込み待ちFutureを作成するヘルパー
///
/// 使用例:
/// ```ignore
/// let data = wait_for_interrupt(InterruptSource::Irq(0x60)).await;
/// ```
pub fn wait_for_interrupt(source: InterruptSource) -> InterruptFuture {
    INTERRUPT_WAKER_REGISTRY.events[source.to_index()].listen()
}

/// An IRQ receipt owns its registration until completion or cancellation.
/// Repolling after an unrelated task wake leaves the receipt pending.
pub type InterruptFuture = EventListener<'static>;

// ============================================================================
// Integration with Timer
// ============================================================================

/// タイマー割り込みハンドラのブリッジ
/// interrupts/mod.rs の `poll_timer_events()` から呼ばれる。
/// Timer-specific wakeups are intentionally deferred until non-ISR context.
pub fn handle_timer_interrupt_waker() {
    wake_from_interrupt(InterruptSource::Timer);

    // NOTE: handle_timer_interrupt() は poll_timer_events() で既に呼ばれているため
    // ここでは呼ばない（二重インクリメント防止）
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::task::Waker;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_atomic_waker() {
        let atomic_waker = AtomicWaker::new();
        let waker = Waker::noop();

        assert!(!atomic_waker.has_waker());

        atomic_waker.register(waker);
        assert!(atomic_waker.has_waker());

        atomic_waker.wake();
        assert!(!atomic_waker.has_waker());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_interrupt_source_from_vector() {
        assert_eq!(InterruptSource::from_vector(0x20), InterruptSource::Timer);
        assert_eq!(
            InterruptSource::from_vector(0x21),
            InterruptSource::Keyboard
        );
        assert_eq!(
            InterruptSource::from_vector(0x30),
            InterruptSource::Irq(0x30)
        );
        assert_eq!(
            InterruptSource::Timer.to_index(),
            InterruptSource::Irq(0x20).to_index()
        );
        assert_eq!(
            InterruptSource::Irq(u8::MAX).to_index(),
            MAX_INTERRUPT_INDICES - 1
        );
    }
}
