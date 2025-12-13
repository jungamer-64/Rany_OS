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

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::Waker;
use spin::Mutex;

// ============================================================================
// 2段階Wake用イベントキュー（ロックフリーMPMCリングバッファ）
// 設計書 4.2.1: ISRから直接wake()を呼ばない
// ============================================================================

/// イベントキューのサイズ（2のべき乗）
const EVENT_QUEUE_SIZE: usize = 256;
const EVENT_QUEUE_MASK: usize = EVENT_QUEUE_SIZE - 1;

/// ISRからのイベントを格納するロックフリーキュー
///
/// ISR内ではpush()のみを行い、wake()はExecutorコンテキストで実行
#[repr(C, align(64))]
struct InterruptEventQueue {
    /// 書き込みインデックス
    head: AtomicUsize,
    /// 読み取りインデックス
    tail: AtomicUsize,
    /// イベントバッファ（InterruptSourceを直接格納）
    /// 0 = 空、1-255 = InterruptSource の判別値
    buffer: [AtomicU64; EVENT_QUEUE_SIZE],
}

impl InterruptEventQueue {
    const fn new() -> Self {
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buffer: [ZERO; EVENT_QUEUE_SIZE],
        }
    }

    /// イベントをキューに追加（ISRから呼ばれる、ロックフリー）
    ///
    /// # Safety
    /// - ISR内から呼び出し可能
    /// - メモリ割り当てなし
    /// - ロック取得なし
    #[inline]
    fn push(&self, source: InterruptSource) -> bool {
        let value = interrupt_source_to_u64(source);

        // 楽観的に書き込み位置を取得
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        // キューがフルの場合は失敗（ドロップ）
        if head.wrapping_sub(tail) >= EVENT_QUEUE_SIZE {
            return false;
        }

        let idx = head & EVENT_QUEUE_MASK;

        // イベントを書き込み
        self.buffer[idx].store(value, Ordering::Release);

        // headを進める
        self.head.store(head.wrapping_add(1), Ordering::Release);

        true
    }

    /// イベントをキューから取得（Executorから呼ばれる）
    #[inline]
    fn pop(&self) -> Option<InterruptSource> {
        loop {
            let tail = self.tail.load(Ordering::Relaxed);
            let head = self.head.load(Ordering::Acquire);

            // キューが空
            if tail == head {
                return None;
            }

            let idx = tail & EVENT_QUEUE_MASK;
            let value = self.buffer[idx].load(Ordering::Acquire);

            // CASでtailを進める
            if self
                .tail
                .compare_exchange_weak(
                    tail,
                    tail.wrapping_add(1),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                // スロットをクリア（次の書き込みのため）
                self.buffer[idx].store(0, Ordering::Release);
                return u64_to_interrupt_source(value);
            }

            // CAS失敗、リトライ
            core::hint::spin_loop();
        }
    }

    /// キューが空かどうか
    #[inline]
    fn is_empty(&self) -> bool {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        tail == head
    }

    /// キュー内のイベント数
    #[inline]
    fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }
}

/// InterruptSourceをu64にエンコード
fn interrupt_source_to_u64(source: InterruptSource) -> u64 {
    match source {
        InterruptSource::Timer => 1,
        InterruptSource::Keyboard => 2,
        InterruptSource::Mouse => 3,
        InterruptSource::Serial => 4,
        InterruptSource::VirtioNet(idx) => 0x100 | (idx as u64),
        InterruptSource::VirtioBlk(idx) => 0x200 | (idx as u64),
        InterruptSource::Nvme(id) => 0x300 | (id as u64),
        InterruptSource::Irq(irq) => 0x400 | (irq as u64),
    }
}

/// u64からInterruptSourceにデコード
fn u64_to_interrupt_source(value: u64) -> Option<InterruptSource> {
    match value {
        0 => None,
        1 => Some(InterruptSource::Timer),
        2 => Some(InterruptSource::Keyboard),
        3 => Some(InterruptSource::Mouse),
        4 => Some(InterruptSource::Serial),
        v if (0x100..0x200).contains(&v) => Some(InterruptSource::VirtioNet((v & 0xFF) as u8)),
        v if (0x200..0x300).contains(&v) => Some(InterruptSource::VirtioBlk((v & 0xFF) as u8)),
        v if (0x300..0x400).contains(&v) => Some(InterruptSource::Nvme((v & 0xFFFF) as u16)),
        v if v >= 0x400 => Some(InterruptSource::Irq((v & 0xFF) as u8)),
        _ => None,
    }
}

/// グローバルイベントキュー
static INTERRUPT_EVENT_QUEUE: InterruptEventQueue = InterruptEventQueue::new();

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
    /// マウス割り込み (IRQ12)
    Mouse,
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
            0x2C => Some(InterruptSource::Mouse),  // IRQ12 = 0x20 + 12
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
    ///
    /// 【設計書 4.2】2段階Wake方式:
    /// ISRからは直接wake()を呼ばず、イベントキューに積むのみ。
    /// 実際のwake()呼び出しはExecutorのイベントループで行う。
    /// これによりISR内でのロック取得・デッドロックを完全に回避。
    pub fn wake(&self, source: InterruptSource) {
        self.interrupt_count.fetch_add(1, Ordering::Relaxed);

        // 【重要】ISRコンテキストでは直接wake()を呼ばない
        // イベントキューに積んでExecutorに処理を委譲
        INTERRUPT_EVENT_QUEUE.push(source);
    }

    /// 複数の割り込みソースのWakerを一度に起動
    ///
    /// 【設計書 4.2】2段階Wake方式対応版
    pub fn wake_many(&self, sources: &[InterruptSource]) {
        self.interrupt_count
            .fetch_add(sources.len() as u64, Ordering::Relaxed);

        // 各ソースをイベントキューに積む
        for source in sources {
            INTERRUPT_EVENT_QUEUE.push(*source);
        }
    }

    /// イベントキューから保留中の割り込みイベントを処理
    ///
    /// 【設計書 4.2】2段階Wake方式: Executorのイベントループから呼び出す
    /// ISRコンテキスト外で安全にロックを取得してwake()を実行
    pub fn process_pending_events(&self) {
        while let Some(source) = INTERRUPT_EVENT_QUEUE.pop() {
            // ISRコンテキスト外なので安全にロックを取得可能
            let wakers = self.wakers.lock();
            if let Some(atomic_waker) = wakers.get(&source) {
                atomic_waker.wake();
                self.wake_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// 保留中のイベント数を取得
    pub fn pending_event_count(&self) -> usize {
        INTERRUPT_EVENT_QUEUE.len()
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
