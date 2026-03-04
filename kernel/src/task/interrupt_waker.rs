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
#![allow(dead_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;
use core::sync::atomic::AtomicUsize;




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
    /// VirtIO コンソール
    VirtioConsole(u8), // queue index
    /// VirtIO 入力
    VirtioInput(u8), // queue index
    /// VirtIO バルーン
    VirtioBalloon(u8), // queue index
    /// VirtIO GPU
    VirtioGpu(u8), // queue index
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

    /// インデックスに変換（配列アクセス用）
    pub fn to_index(&self) -> usize {
        match self {
            InterruptSource::Timer => 0,
            InterruptSource::Keyboard => 1,

            InterruptSource::Serial => 3,
            InterruptSource::VirtioNet(idx) => 16 + (*idx as usize),
            InterruptSource::VirtioBlk(idx) => 16 + 32 + (*idx as usize),
            InterruptSource::VirtioConsole(idx) => 16 + 32 + 32 + (*idx as usize),
            InterruptSource::VirtioInput(idx) => 16 + 32 + 32 + 16 + (*idx as usize),
            InterruptSource::VirtioBalloon(idx) => 16 + 32 + 32 + 16 + 16 + (*idx as usize),
            InterruptSource::VirtioGpu(idx) => 16 + 32 + 32 + 16 + 16 + 16 + (*idx as usize),
            InterruptSource::Nvme(id) => 16 + 32 + 32 + 16 + 16 + 16 + 16 + (*id as usize),
            InterruptSource::Irq(irq) => 16 + 32 + 32 + 16 + 16 + 16 + 16 + 256 + (*irq as usize),
        }
    }
}

/// 最大インデックスサイズ（配列サイズ）
const MAX_INTERRUPT_INDICES: usize = 2048;
const INTERRUPT_EVENT_QUEUE_SIZE: usize = 1024;
const INTERRUPT_EVENT_QUEUE_MASK: usize = INTERRUPT_EVENT_QUEUE_SIZE - 1;

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
    /// spin::Onceを使って遅延初期化（カーネルヒープ初期化後）
    wakers: spin::Once<Vec<AtomicWaker>>,
    /// 統計: 割り込み回数
    interrupt_count: AtomicU64,
    /// 統計: Wake回数
    wake_count: AtomicU64,
    /// ISRから投入される遅延Wakeイベントキュー
    event_queue: InterruptEventQueue,
}

impl InterruptWakerRegistry {
    /// 新しいレジストリを作成
    pub const fn new() -> Self {
        Self {
            wakers: spin::Once::new(),
            interrupt_count: AtomicU64::new(0),
            wake_count: AtomicU64::new(0),
            event_queue: InterruptEventQueue::new(),
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
            let _ = self.event_queue.push_once(idx + 1);
        }
    }

    /// 複数の割り込みソースのWakerを一度に起動
    pub fn wake_many(&self, sources: &[InterruptSource]) {
        self.interrupt_count
            .fetch_add(sources.len() as u64, Ordering::Relaxed);

        if self.wakers.get().is_some() {
            for source in sources {
                let idx = source.to_index();
                if idx < MAX_INTERRUPT_INDICES {
                    let _ = self.event_queue.push_once(idx + 1);
                }
            }
        }
    }

    /// イベントキューから保留中の割り込みイベントを処理
    pub fn process_pending_events(&self) {
        let Some(wakers) = self.wakers.get() else {
            return;
        };
        while let Some(encoded_idx) = self.event_queue.pop() {
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
        self.event_queue.len()
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
    head: AtomicUsize,
    tail: AtomicUsize,
    buffer: [AtomicUsize; INTERRUPT_EVENT_QUEUE_SIZE],
}

impl InterruptEventQueue {
    const fn new() -> Self {
        const ZERO: AtomicUsize = AtomicUsize::new(0);
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buffer: [ZERO; INTERRUPT_EVENT_QUEUE_SIZE],
        }
    }

    #[inline]
    fn push_once(&self, value: usize) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= INTERRUPT_EVENT_QUEUE_SIZE {
            return false;
        }
        let idx = head & INTERRUPT_EVENT_QUEUE_MASK;
        if self
            .head
            .compare_exchange_weak(
                head,
                head.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            self.buffer[idx].store(value, Ordering::Release);
            true
        } else {
            false
        }
    }

    #[inline]
    fn pop(&self) -> Option<usize> {
        loop {
            let tail = self.tail.load(Ordering::Relaxed);
            let head = self.head.load(Ordering::Acquire);
            if tail == head {
                return None;
            }

            let idx = tail & INTERRUPT_EVENT_QUEUE_MASK;
            if self
                .tail
                .compare_exchange_weak(
                    tail,
                    tail.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                let value = self.buffer[idx].load(Ordering::Acquire);
                self.buffer[idx].store(0, Ordering::Release);
                return Some(value);
            }

            core::hint::spin_loop();
        }
    }

    #[inline]
    fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail)
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

/// タイマータスクを起床（タイマーISRから呼ばれる便利関数）
///
/// 【設計書 4.2】2段階Wake方式: ISR安全
/// ISR内では軽量な処理のみ実行（イベントキューへのpush）
#[inline]
pub fn wake_timer_task() {
    wake_from_interrupt(InterruptSource::Timer);
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

    #[test_case]
    fn test_atomic_waker() {
        let atomic_waker = AtomicWaker::new();
        let waker = dummy_waker();

        assert!(!atomic_waker.has_waker());

        atomic_waker.register(&waker);
        assert!(atomic_waker.has_waker());

        atomic_waker.wake();
        assert!(!atomic_waker.has_waker());
    }

    #[test_case]
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
