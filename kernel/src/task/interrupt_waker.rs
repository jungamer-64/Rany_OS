// ============================================================================
// src/task/interrupt_waker.rs - Interrupt-Waker Bridge
// 設計書 4.2: 割り込みとWakerのブリッジ
// 設計書 4.2.1: デッドロック回避：割り込みフリーキューの採用
//
// ハードウェア割り込みとRustのasync/await Futureを連携させる機構
// ISRから安全にWakerを起動し、Executorにタスクの再開を通知する
//
// 重要: 2段階Wake方式を採用
// 1. ISR内ではイベントキューにイベントIDをpushするのみ
// 2. Executorのメインループでキューをチェックしwake()を呼び出す
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
const MAX_INTERRUPT_INDICES: usize = 2048;
const INTERRUPT_EVENT_QUEUE_SIZE: usize = 1024;
const INTERRUPT_EVENT_QUEUE_BACKING_SIZE: usize = INTERRUPT_EVENT_QUEUE_SIZE + 1;
const MAX_CPUS: usize = crate::per_cpu::MAX_CPUS;

// ============================================================================
// Atomic Waker - ISR-safe Waker storage
// ============================================================================

pub use crate::sync::AtomicWaker;
use crate::sync::MpscRingBuffer;

// ============================================================================
// Interrupt Waker Registry
// ============================================================================

/// 割り込みソースごとのWaker管理（ロックフリー版）
pub struct InterruptWakerRegistry {
    /// 割り込みソース -> AtomicWakerのマッピング（配列）
    /// spin::Onceを使って遅延初期化（カーネルヒープ初期化後）
    wakers: spin::Once<Vec<AtomicWaker>>,
    /// 統計: 割り込み回数
    interrupt_count: AtomicU64,
    /// 統計: Wake回数
    wake_count: AtomicU64,
    /// ISRから投入される遅延Wakeイベントキュー（CPUローカル）
    event_queues: [InterruptEventQueue; MAX_CPUS],
}

impl InterruptWakerRegistry {
    /// 新しいレジストリを作成
    pub const fn new() -> Self {
        Self {
            wakers: spin::Once::new(),
            interrupt_count: AtomicU64::new(0),
            wake_count: AtomicU64::new(0),
            event_queues: [const { InterruptEventQueue::new() }; MAX_CPUS],
        }
    }

    #[inline]
    fn current_cpu_index(&self) -> usize {
        crate::cpu::try_current_id()
            .unwrap_or_else(|| crate::cpu::current_id())
            .min(MAX_CPUS.saturating_sub(1))
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

    /// 割り込みソースにWakerを登録
    pub fn register(&self, source: InterruptSource, waker: &Waker) {
        let idx = source.to_index();
        if idx >= MAX_INTERRUPT_INDICES {
            return; // 範囲外は無視
        }

        self.get_wakers()[idx].register(waker);
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

        // spin::Onceが初期化済みかチェック（初期化前はwake不可）
        if self.wakers.get().is_some() {
            // +1 して 0 を空スロットに使う
            let cpu_idx = self.current_cpu_index();
            let _ = self.event_queues[cpu_idx].push_once(idx + 1);
        }
    }

    /// 複数の割り込みソースのWakerを一度に起動
    pub fn wake_many(&self, sources: &[InterruptSource]) {
        self.interrupt_count
            .fetch_add(sources.len() as u64, Ordering::Relaxed);

        if self.wakers.get().is_some() {
            let cpu_idx = self.current_cpu_index();
            for source in sources {
                let idx = source.to_index();
                if idx < MAX_INTERRUPT_INDICES {
                    let _ = self.event_queues[cpu_idx].push_once(idx + 1);
                }
            }
        }
    }

    /// イベントキューから保留中の割り込みイベントを処理
    pub fn process_pending_events(&self) {
        let Some(wakers) = self.wakers.get() else {
            return;
        };
        let cpu_idx = self.current_cpu_index();
        let queue = &self.event_queues[cpu_idx];
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(encoded_idx) = queue.pop() {
            if encoded_idx == 0 {
                continue;
            }
            let idx = encoded_idx - 1;
            if idx >= MAX_INTERRUPT_INDICES {
                continue;
            }
            wakers[idx].wake();
            self.wake_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 保留中のイベント数を取得
    pub fn pending_event_count(&self) -> usize {
        self.event_queues.iter().map(InterruptEventQueue::len).sum()
    }

    /// 割り込みソースの登録を解除
    pub fn unregister(&self, source: InterruptSource) {
        let idx = source.to_index();
        if idx >= MAX_INTERRUPT_INDICES {
            return;
        }

        // 初期化済みならクリア
        if let Some(wakers) = self.wakers.get() {
            // AtomicWakerにはclear()がない？
            // registerで上書きされるので実質問題ないが、厳密には残る。
            // AtomicWakerの実装を確認する必要があるが、明示的なunregisterは通常不要。
            // register(noop_waker) で消す手はあるが、Wakerが必要。
            // そもそもAtomicWakerは "one-shot" の性質を持つ場合が多いが、
            // ここの実装は "register" されたら次の "wake" まで有効。
            // unregisterは実はあまり必要ない（タスクがドロップされればWakerも無効になるはずだが、
            // AtomicWakerはWakerを保持し続けるので、メモリリークのリスクはある？）
            // 前の BTreeMap 実装では remove していた。
            // AtomicWakerに clear() メソッドを追加するのも一つの手。

            // AtomicWaker.rs (step 796) says:
            // pub fn clear(&self) { ... }
            // So we can use clear().

            wakers[idx].clear();
        }
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

#[repr(C, align(64))]
struct InterruptEventQueue {
    buffer: MpscRingBuffer<usize, INTERRUPT_EVENT_QUEUE_BACKING_SIZE>,
}

impl InterruptEventQueue {
    const fn new() -> Self {
        Self {
            buffer: MpscRingBuffer::new(),
        }
    }

    #[inline]
    fn push_once(&self, value: usize) -> bool {
        self.buffer.try_push(value).is_ok()
    }

    #[inline]
    fn pop(&self) -> Option<usize> {
        self.buffer.pop()
    }

    #[inline]
    fn len(&self) -> usize {
        self.buffer.len()
    }

    #[inline]
    fn capacity(&self) -> usize {
        INTERRUPT_EVENT_QUEUE_SIZE
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn interrupt_event_queue_preserves_full_capacity() {
        let queue = InterruptEventQueue::new();
        assert!(queue.is_empty());

        for i in 0..INTERRUPT_EVENT_QUEUE_SIZE {
            assert!(queue.push_once(i + 1), "failed at {}", i);
        }
        assert!(!queue.push_once(usize::MAX));
        assert_eq!(queue.len(), INTERRUPT_EVENT_QUEUE_SIZE);
        assert_eq!(queue.capacity(), INTERRUPT_EVENT_QUEUE_SIZE);
        assert!(!queue.is_empty());

        for i in 0..INTERRUPT_EVENT_QUEUE_SIZE {
            assert_eq!(queue.pop(), Some(i + 1));
        }
        assert_eq!(queue.pop(), None);
        assert!(queue.is_empty());
    }
}
