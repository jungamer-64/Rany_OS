// ============================================================================
// src/task/interrupt_waker.rs - Interrupt-Waker Bridge
// 設計書 4.2: 割り込みとWakerのブリッジ
//
// ハードウェア割り込みとRustのasync/await Futureを連携させる機構
// ISRから安全にWakerを起動し、Executorにタスクの再開を通知する
// ============================================================================
#![allow(dead_code)]

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::Waker;
use spin::Mutex;

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
    /// VirtIO ネットワーク
    VirtioNet(u8), // queue index
    /// VirtIO ブロック
    VirtioBlk(u8), // queue index
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
            0x30..=0x3F => Some(InterruptSource::VirtioNet((vector - 0x30) as u8)),
            0x40..=0x4F => Some(InterruptSource::VirtioBlk((vector - 0x40) as u8)),
            0x50..=0x5F => Some(InterruptSource::Nvme((vector - 0x50) as u16)),
            _ => Some(InterruptSource::Irq(vector)),
        }
    }
}

// ============================================================================
// Atomic Waker - ISR-safe Waker storage
// ============================================================================

/// ISR-safe な Waker ストレージ
///
/// 割り込みハンドラ内から安全にWakerを操作できる
pub struct AtomicWaker {
    /// Wakerが設定されているか
    has_waker: AtomicBool,
    /// Waker (Mutex保護)
    waker: Mutex<Option<Waker>>,
    /// Wake要求フラグ（ISRから設定）
    wake_requested: AtomicBool,
}

impl AtomicWaker {
    /// 新しいAtomicWakerを作成
    pub const fn new() -> Self {
        Self {
            has_waker: AtomicBool::new(false),
            waker: Mutex::new(None),
            wake_requested: AtomicBool::new(false),
        }
    }

    /// Wakerを登録
    pub fn register(&self, waker: &Waker) {
        // 既存のWakerと比較して、異なる場合のみ更新
        let mut guard = self.waker.lock();
        let should_update = match &*guard {
            Some(existing) => !existing.will_wake(waker),
            None => true,
        };

        if should_update {
            *guard = Some(waker.clone());
            self.has_waker.store(true, Ordering::Release);
        }

        // 保留中のwake要求があれば処理
        if self.wake_requested.swap(false, Ordering::AcqRel) {
            if let Some(w) = guard.take() {
                self.has_waker.store(false, Ordering::Release);
                drop(guard);
                w.wake();
            }
        }
    }

    /// Wakerを起動（ISRから呼ばれる）
    ///
    /// # Safety
    /// ISR内から呼ばれることを想定。ロック取得に失敗した場合は
    /// wake_requestedフラグを設定して、次のregister時にwakeする
    pub fn wake(&self) {
        // try_lockでロックを試みる
        if let Some(mut guard) = self.waker.try_lock() {
            if let Some(waker) = guard.take() {
                self.has_waker.store(false, Ordering::Release);
                drop(guard);
                waker.wake();
                return;
            }
        }

        // ロック取得に失敗した場合はフラグを設定
        if self.has_waker.load(Ordering::Acquire) {
            self.wake_requested.store(true, Ordering::Release);
        }
    }

    /// Wakerが登録されているか
    pub fn has_waker(&self) -> bool {
        self.has_waker.load(Ordering::Acquire)
    }

    /// Wake要求が保留中か
    pub fn is_wake_pending(&self) -> bool {
        self.wake_requested.load(Ordering::Acquire)
    }

    /// Wakerをクリア
    pub fn clear(&self) {
        *self.waker.lock() = None;
        self.has_waker.store(false, Ordering::Release);
        self.wake_requested.store(false, Ordering::Release);
    }
}

impl Default for AtomicWaker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Interrupt Waker Registry
// ============================================================================

/// 割り込みソースごとのWaker管理
pub struct InterruptWakerRegistry {
    /// 割り込みソース -> AtomicWakerのマッピング
    wakers: Mutex<BTreeMap<InterruptSource, AtomicWaker>>,
    /// 統計: 割り込み回数
    interrupt_count: AtomicU64,
    /// 統計: Wake回数
    wake_count: AtomicU64,
}

impl InterruptWakerRegistry {
    /// 新しいレジストリを作成
    pub const fn new() -> Self {
        Self {
            wakers: Mutex::new(BTreeMap::new()),
            interrupt_count: AtomicU64::new(0),
            wake_count: AtomicU64::new(0),
        }
    }

    /// 割り込みソースにWakerを登録
    pub fn register(&self, source: InterruptSource, waker: &Waker) {
        let mut wakers = self.wakers.lock();

        let atomic_waker = wakers.entry(source).or_insert_with(AtomicWaker::new);

        atomic_waker.register(waker);
    }

    /// 割り込みソースのWakerを起動（ISRから呼ばれる）
    pub fn wake(&self, source: InterruptSource) {
        self.interrupt_count.fetch_add(1, Ordering::Relaxed);

        // try_lockでデッドロックを回避
        if let Some(wakers) = self.wakers.try_lock() {
            if let Some(atomic_waker) = wakers.get(&source) {
                atomic_waker.wake();
                self.wake_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// 複数の割り込みソースのWakerを一度に起動
    pub fn wake_many(&self, sources: &[InterruptSource]) {
        self.interrupt_count
            .fetch_add(sources.len() as u64, Ordering::Relaxed);

        if let Some(wakers) = self.wakers.try_lock() {
            for source in sources {
                if let Some(atomic_waker) = wakers.get(source) {
                    atomic_waker.wake();
                    self.wake_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// 割り込みソースの登録を解除
    pub fn unregister(&self, source: InterruptSource) {
        self.wakers.lock().remove(&source);
    }

    /// 統計を取得
    pub fn stats(&self) -> InterruptWakerStats {
        InterruptWakerStats {
            interrupt_count: self.interrupt_count.load(Ordering::Relaxed),
            wake_count: self.wake_count.load(Ordering::Relaxed),
            registered_sources: self.wakers.lock().len(),
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

/// 割り込みソースにWakerを登録（便利関数）
pub fn register_interrupt_waker(source: InterruptSource, waker: &Waker) {
    INTERRUPT_WAKER_REGISTRY.register(source, waker);
}

/// 割り込みハンドラから呼ばれる（便利関数）
pub fn wake_from_interrupt(source: InterruptSource) {
    INTERRUPT_WAKER_REGISTRY.wake(source);
}

// ============================================================================
// Interrupt-aware Future helpers
// ============================================================================

/// 割り込み待ちFutureを作成するヘルパー
///
/// 使用例:
/// ```ignore
/// let data = wait_for_interrupt(InterruptSource::VirtioNet(0)).await;
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

impl core::future::Future for InterruptFuture {
    type Output = ();

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if !self.registered {
            // 最初のpollでWakerを登録
            register_interrupt_waker(self.source, cx.waker());
            self.registered = true;
            core::task::Poll::Pending
        } else {
            // 割り込みが来てwakeされた
            core::task::Poll::Ready(())
        }
    }
}

// ============================================================================
// Integration with Timer
// ============================================================================

/// タイマー割り込みハンドラのブリッジ
/// interrupts/mod.rs のタイマーハンドラから呼ばれる
pub fn handle_timer_interrupt_waker() {
    // タイマー関連のWakerを起動
    wake_from_interrupt(InterruptSource::Timer);

    // タイマーモジュールに通知
    super::timer::handle_timer_interrupt();
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

    #[test]
    fn test_atomic_waker() {
        let atomic_waker = AtomicWaker::new();
        let waker = dummy_waker();

        assert!(!atomic_waker.has_waker());

        atomic_waker.register(&waker);
        assert!(atomic_waker.has_waker());

        atomic_waker.wake();
        assert!(!atomic_waker.has_waker());
    }

    #[test]
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
            Some(InterruptSource::VirtioNet(0))
        );
    }
}
