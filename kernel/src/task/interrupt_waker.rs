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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;

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
    /// NVMe
    Nvme(u16), // queue ID
    /// 汎用IRQ
    Irq(u8),
}

impl InterruptSource {
    /// IRQベクターから割り込みソースに変換
    pub fn from_vector(vector: u8) -> Option<Self> {
        match vector {
            0x20 => Some(InterruptSource::Timer),
            0x21 => Some(InterruptSource::Keyboard),
            0x24 => Some(InterruptSource::Serial), // COM1 = IRQ4 = 0x20 + 4

            0x50..=0x5F => Some(InterruptSource::Nvme((vector - 0x50) as u16)),
            _ => Some(InterruptSource::Irq(vector)),
        }
    }

    /// インデックスに変換（配列アクセス用）
    pub fn to_index(&self) -> usize {
        match self {
            InterruptSource::Timer => 0,
            InterruptSource::Keyboard => 1,

            InterruptSource::Serial => 3,
            InterruptSource::Nvme(id) => 16 + 32 + 32 + 16 + 16 + 16 + 16 + (*id as usize),
            InterruptSource::Irq(irq) => 16 + 32 + 32 + 16 + 16 + 16 + 16 + 256 + (*irq as usize),
        }
    }
}

/// 最大インデックスサイズ（配列サイズ）
pub(crate) const MAX_INTERRUPT_INDICES: usize = 2048;

// ============================================================================
// Atomic Waker - ISR-safe Waker storage
// ============================================================================

pub use crate::sync::AtomicWaker;

// ============================================================================
// Interrupt Waker Registry
// ============================================================================

/// 割り込みソースごとのWaker管理（ロックフリー版）
pub struct InterruptWakerRegistry {
    /// 割り込みソース -> AtomicWakerのマッピング（配列）
    /// crate::sync::InitOnceを使って遅延初期化（カーネルヒープ初期化後）
    wakers: crate::sync::InitOnce<Vec<AtomicWaker>>,
    /// 統計: 割り込み回数
    interrupt_count: AtomicU64,
    /// 統計: Wake回数
    wake_count: AtomicU64,
}

impl InterruptWakerRegistry {
    /// 新しいレジストリを作成
    pub const fn new() -> Self {
        Self {
            wakers: crate::sync::InitOnce::new(),
            interrupt_count: AtomicU64::new(0),
            wake_count: AtomicU64::new(0),
        }
    }

    /// Waker配列を取得（未初期化なら初期化）
    fn get_wakers(&self) -> &[AtomicWaker] {
        self.wakers.call_once(|| {
            let mut v = Vec::with_capacity(MAX_INTERRUPT_INDICES);
            for _ in 0..MAX_INTERRUPT_INDICES {
                v.push(AtomicWaker::new());
            }
            v
        })
    }

    /// 割り込みソースのWakerを起動要求（ISRから呼ばれる）
    ///
    /// 2段階Wake方式:
    /// ISRではイベントキューに積むのみ。実際のwake()は非ISR側で実行する。
    pub fn wake(&self, source: InterruptSource) {
        self.interrupt_count.fetch_add(1, Ordering::Relaxed);

        let idx = source.to_index();
        if idx >= MAX_INTERRUPT_INDICES {
            return;
        }

        // crate::sync::InitOnceが初期化済みかチェック（初期化前はwake不可）
        if self.wakers.get().is_some() {
            if let Some(current) = crate::cpu::CurrentCpu::acquire() {
                current.defer_interrupt_wake(idx);
            }
        }
    }

    /// 複数の割り込みソースのWakerを一度に起動
    pub fn wake_many(&self, sources: &[InterruptSource]) {
        self.interrupt_count
            .fetch_add(sources.len() as u64, Ordering::Relaxed);

        if self.wakers.get().is_some() {
            if let Some(current) = crate::cpu::CurrentCpu::acquire() {
                for source in sources {
                    let idx = source.to_index();
                    if idx < MAX_INTERRUPT_INDICES {
                        current.defer_interrupt_wake(idx);
                    }
                }
            }
        }
    }

    /// 保留ソースの有限の snapshot を非割込みコンテキストで処理する。
    /// 同じソースへの通知は合流し、処理中の通知は次回の処理へ残る。
    pub fn process_pending_events(&self) {
        let Some(wakers) = self.wakers.get() else {
            return;
        };
        let Some(current) = crate::cpu::CurrentCpu::acquire() else {
            return;
        };
        current.drain_interrupt_wakes(|idx| {
            wakers[idx].wake();
            self.wake_count.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// 保留中のイベント数を取得
    pub fn pending_event_count(&self) -> usize {
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
        let registered = if let Some(wakers) = self.wakers.get() {
            wakers.iter().filter(|w| w.has_waker()).count()
        } else {
            0
        };

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
/// イベントキューに積むのみで、実際のwake()は呼ばない
#[inline]
pub fn wake_from_interrupt(source: InterruptSource) {
    INTERRUPT_WAKER_REGISTRY.wake(source);
}

/// 保留中の割り込みイベントを処理（Executorから呼び出す）
///
/// 【設計書 4.2】2段階Wake方式: 非ISRコンテキストで呼び出す
/// Executorのイベントループの各イテレーションで呼び出すべき
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
    InterruptFuture {
        source,
        registered: false,
    }
}

/// 割り込み待ちFuture
pub struct InterruptFuture {
    source: InterruptSource,
    registered: bool,
}

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
    use core::task::{RawWaker, RawWakerVTable};

    fn dummy_waker() -> Waker {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(core::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );

        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_atomic_waker() {
        let atomic_waker = AtomicWaker::new();
        let waker = dummy_waker();

        assert!(!atomic_waker.has_waker());

        atomic_waker.register(&waker);
        assert!(atomic_waker.has_waker());

        atomic_waker.wake();
        assert!(!atomic_waker.has_waker());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_interrupt_source_from_vector() {
        assert_eq!(
            InterruptSource::from_vector(0x20),
            Some(InterruptSource::Timer)
        );
        assert_eq!(
            InterruptSource::from_vector(0x21),
            Some(InterruptSource::Keyboard)
        );
        assert_eq!(
            InterruptSource::from_vector(0x30),
            Some(InterruptSource::Irq(0x30))
        );
    }
}
