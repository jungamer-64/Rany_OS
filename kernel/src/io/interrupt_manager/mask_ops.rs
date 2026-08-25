use super::*;
use crate::sync::MpscRingBuffer;

/// 割り込みをマスク
pub fn mask_interrupt(vector: u8) -> Result<(), InterruptError> {
    if let Some(allocation) = INTERRUPT_MANAGER.allocations.write().get_mut(&vector) {
        allocation.config.masked = true;

        match allocation.source {
            InterruptSourceType::LegacyIoApic { gsi } => {
                configure_ioapic_interrupt(gsi, &allocation.config)?;
            }
            InterruptSourceType::Msi { .. } | InterruptSourceType::MsiX { .. } => {
                // MSI/MSI-Xはデバイス側でマスク
            }
            _ => {}
        }

        Ok(())
    } else {
        Err(InterruptError::InvalidVector)
    }
}

/// 割り込みをアンマスク
pub fn unmask_interrupt(vector: u8) -> Result<(), InterruptError> {
    if let Some(allocation) = INTERRUPT_MANAGER.allocations.write().get_mut(&vector) {
        allocation.config.masked = false;

        match allocation.source {
            InterruptSourceType::LegacyIoApic { gsi } => {
                configure_ioapic_interrupt(gsi, &allocation.config)?;
            }
            InterruptSourceType::Msi { .. } | InterruptSourceType::MsiX { .. } => {
                // MSI/MSI-Xはデバイス側でアンマスク
            }
            _ => {}
        }

        Ok(())
    } else {
        Err(InterruptError::InvalidVector)
    }
}

// ============================================================================
// Interrupt-Waker Bridge (設計書 4.2節)
// ============================================================================
//
// ISR内でロックを取得するとデッドロックが発生するため、2段階Wake方式を採用:
// 1. ISR: push_interrupt_event() でロックフリーキューにpush
// 2. Executor: process_pending_interrupts() で通常コンテキストでwake()
//
// これにより割り込みコンテキストと通常コンテキスト間のロック競合を根本的に回避

use core::task::Waker;

/// ロックフリー割り込みイベントキュー
///
/// ISRから安全に呼び出せるよう、Atomic操作のみを使用
pub struct InterruptQueue {
    buffer: MpscRingBuffer<u8, INTERRUPT_QUEUE_BACKING_CAPACITY>,
}

const INTERRUPT_QUEUE_BACKING_CAPACITY: usize = InterruptQueue::CAPACITY + 1;

impl InterruptQueue {
    /// キューのサイズ（2の冪乗）
    pub(super) const CAPACITY: usize = 1024;

    /// 新しいキューを作成
    pub const fn new() -> Self {
        Self {
            buffer: MpscRingBuffer::new(),
        }
    }

    /// 割り込みイベントをキューに追加（ISR用 - ロックフリー）
    ///
    /// # Safety
    /// ISRコンテキストから呼び出し可能。ロックを取得しない。
    #[inline]
    pub fn push(&self, vector: u8) -> bool {
        self.buffer.push(vector).is_ok()
    }

    /// 割り込みイベントをキューから取得（Executor用）
    ///
    /// 通常コンテキストから呼び出すこと
    #[inline]
    pub fn pop(&self) -> Option<u8> {
        self.buffer.pop()
    }

    /// キューが空か確認
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// キューの論理容量を取得
    #[inline]
    pub const fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    /// キューの長さを取得（テスト用）
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
}

/// WakerレジストリのエントリID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WakerId(pub u8);

/// Wakerレジストリ（ベクタ → Waker の対応表）
///
/// 通常コンテキストでのみアクセスされる（Mutex保護）
pub struct WakerRegistry {
    wakers: Mutex<BTreeMap<u8, Waker>>,
}

impl WakerRegistry {
    /// 新しいレジストリを作成
    pub const fn new() -> Self {
        Self {
            wakers: Mutex::new(BTreeMap::new()),
        }
    }

    /// Wakerを登録
    ///
    /// ドライバが非同期操作を開始する際に呼び出す
    pub fn register(&self, vector: u8, waker: Waker) {
        self.wakers.lock().insert(vector, waker);
    }

    /// Waker登録を解除
    pub fn unregister(&self, vector: u8) {
        self.wakers.lock().remove(&vector);
    }

    /// 指定されたベクタのWakerを起床
    ///
    /// 通常コンテキストから呼び出すこと
    pub fn wake(&self, vector: u8) {
        if let Some(waker) = self.wakers.lock().get(&vector) {
            waker.wake_by_ref();
        }
    }

    /// 登録されているWakerの数
    pub fn count(&self) -> usize {
        self.wakers.lock().len()
    }
}

// ============================================================================
// Global Waker Bridge Instances
// ============================================================================

/// グローバル割り込みイベントキュー
pub(crate) static INTERRUPT_QUEUE: InterruptQueue = InterruptQueue::new();

/// グローバルWakerレジストリ
pub(crate) static WAKER_REGISTRY: WakerRegistry = WakerRegistry::new();

// ============================================================================
// Public Waker Bridge API
// ============================================================================

/// 割り込みイベントをキューに追加（ISR用）
///
/// **ISRから安全に呼び出し可能** - ロックを取得しない
///
/// # Example
/// ```ignore
/// // 割り込みハンドラ内で使用
/// fn keyboard_handler(_: InterruptStackFrame) {
///     push_interrupt_event(33); // キーボード割り込みベクタ
///     send_eoi(1);
/// }
/// ```
#[inline]
pub fn push_interrupt_event(vector: u8) -> bool {
    INTERRUPT_QUEUE.push(vector)
}

/// 保留中の割り込みを処理（Executor用）
///
/// Executorのメインループの先頭で呼び出す。
/// キューからイベントを取り出し、対応するWakerを起床する。
///
/// # Example
/// ```ignore
/// // Executorメインループ
/// loop {
///     // 1. 保留中の割り込みを処理
///     process_pending_interrupts();
///     
///     // 2. Ready状態のタスクをポーリング
///     poll_ready_tasks();
/// }
/// ```
pub fn process_pending_interrupts() {
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while let Some(vector) = INTERRUPT_QUEUE.pop() {
        // 統計を記録
        INTERRUPT_MANAGER.record_interrupt(vector);
        // 対応するWakerを起床
        WAKER_REGISTRY.wake(vector);
    }
}

/// Wakerを登録（ドライバ用）
///
/// 非同期操作の開始時に呼び出し、割り込み完了時にWakerが起床されるようにする
pub fn register_waker(vector: u8, waker: Waker) {
    WAKER_REGISTRY.register(vector, waker);
}

/// Waker登録を解除（ドライバ用）
pub fn unregister_waker(vector: u8) {
    WAKER_REGISTRY.unregister(vector);
}

/// 保留中の割り込みがあるか確認
#[inline]
pub fn has_pending_interrupts() -> bool {
    !INTERRUPT_QUEUE.is_empty()
}

/// 登録されているWaker数を取得
pub fn waker_count() -> usize {
    WAKER_REGISTRY.count()
}

// ============================================================================
// Direct Callback Support (for Event-Driven Reactor)
// ============================================================================

/// 割り込みハンドラの型
pub type InterruptHandler = Box<dyn Fn() + Send + Sync>;

/// 直接実行される割り込みハンドラのレジストリ
///
/// ISRコンテキストで実行されるため、IrqMutexで保護する必要がある。
/// これにより、ISR内でのロック取得時のデッドロックを防ぐ。
pub(crate) static DIRECT_HANDLERS: OnceBox<IrqMutex<Vec<Option<InterruptHandler>>>> =
    OnceBox::new();

/// ハンドラレジストリを取得（必要に応じて初期化）
#[inline]
pub(crate) fn direct_handlers() -> &'static IrqMutex<Vec<Option<InterruptHandler>>> {
    DIRECT_HANDLERS.get_or_init(|| {
        let mut v = Vec::with_capacity(256);
        for _ in 0..256 {
            v.push(None);
        }
        Box::new(IrqMutex::new(v))
    })
}

/// 割り込みハンドラを登録（直接実行用）
///
/// ベクタに対応するハンドラを登録する。このハンドラはISR内で直接呼び出されるため、
/// 実行時間は極力短くし、ブロックする操作を行ってはならない。
///
/// # Errors
///
/// Returns a typed error when the vector is invalid or already has an owner.
pub fn register_handler(vector: u8, handler: InterruptHandler) -> Result<(), InterruptError> {
    let mut handlers = direct_handlers().lock();
    let destination = handlers
        .get_mut(vector as usize)
        .ok_or(InterruptError::InvalidVector)?;
    if destination.is_some() {
        return Err(InterruptError::HandlerInUse { vector });
    }
    *destination = Some(handler);
    Ok(())
}

/// 直接割り込みハンドラを解除する。
pub fn unregister_handler(vector: u8) {
    let mut handlers = direct_handlers().lock();
    if (vector as usize) < handlers.len() {
        handlers[vector as usize] = None;
    }
}

/// 直接ハンドラをディスパッチ試行
///
/// ISRから呼び出され、登録されたハンドラがあれば実行する。
///
/// # Returns
/// ハンドラが実行された場合は `true`
pub fn try_dispatch_direct(vector: u8) -> bool {
    // try_lockを使用することで、万が一の再入時のデッドロックも回避
    // (ただしIrqMutexは割り込みを無効化するため、通常は再入しない)
    if let Some(handlers) = direct_handlers().try_lock() {
        if let Some(ref handler) = handlers.get(vector as usize).and_then(|h| h.as_ref()) {
            handler();
            return true;
        }
    }
    false
}

// NVMe ISR Entry Point (Static)
//
// IDTに登録される関数。ダイレクトディスパッチを試み、
// 失敗した場合はイベントキューにフォールバックする。
define_interrupt!(
    pub fn nvme_entry_point(_stack_frame: InterruptStackFrame) {
        // 1. ダイレクトディスパッチ（高速パス）
        if try_dispatch_direct(NVME_VECTOR) {
            // ハンドラが処理を行ったので、ここでは何もしない
        } else {
            // 2. フォールバック（低速パス）- Executorで処理
            push_interrupt_event(NVME_VECTOR);
        }

        // 3. EOI送信
        send_eoi();
    }
);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
