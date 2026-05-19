// ============================================================================
// src/sync/lockfree/channel.rs - コア間メッセージチャネル & Bounded Channel
// ============================================================================

use alloc::boxed::Box;
use core::marker::PhantomData;
use core::sync::atomic::Ordering;

use super::mpsc::MpscRingBuffer;
use super::spsc::SpscRingBuffer;

// ============================================================================
// コア間メッセージチャネル
// ============================================================================

/// コア間メッセージの種類
#[derive(Debug, Clone)]
pub enum InterCoreMessage {
    /// タスクの移動要求
    MigrateTask {
        task_id: u64,
        from_core: u32,
        to_core: u32,
    },
    /// Work Stealing 要求
    StealRequest { from_core: u32 },
    /// Work Stealing 応答
    StealResponse { task_id: Option<u64> },
    /// 割り込みのリレー
    RelayInterrupt { vector: u8 },
    /// シャットダウン通知
    Shutdown,
    /// カスタムメッセージ
    Custom(u64),
}

/// デフォルトのメッセージキューサイズ
pub const DEFAULT_QUEUE_SIZE: usize = 256;

/// コア間通信チャネル
pub type InterCoreChannel = SpscRingBuffer<InterCoreMessage, DEFAULT_QUEUE_SIZE>;

/// コア間チャネルを作成
pub const fn create_inter_core_channel() -> InterCoreChannel {
    SpscRingBuffer::new()
}

// ============================================================================
// Bounded Channel (mpsc)
// ============================================================================

/// Bounded MPSC チャネル (Arc-free by default)
///
/// For inter-domain or inter-core communication prefer this Arc-free API which
/// either allocates a long-lived buffer (via `new()`, which leaks an allocator
/// allocation intentionally) or accepts a caller-provided `'static` buffer via
/// `from_static`. This avoids `Arc`'s atomic reference counting overhead which
/// is detrimental to NUMA and cross-domain scalability.
pub struct BoundedChannel<T: 'static, const N: usize> {
    _marker: PhantomData<fn() -> T>,
}

impl<T: 'static, const N: usize> BoundedChannel<T, N> {
    /// Create a new bounded channel. Allocates a `MpscRingBuffer` on the heap
    /// and leaks it to obtain a `'static` reference. This is suitable for
    /// long-lived kernel channels and avoids `Arc` overhead.
    pub fn new() -> (BoundedSender<T, N>, BoundedReceiver<T, N>) {
        let boxed = Box::new(MpscRingBuffer::new());
        let inner: &'static MpscRingBuffer<T, N> = Box::leak(boxed);
        (BoundedSender { inner }, BoundedReceiver { inner })
    }

    /// Create a channel from a caller-provided static buffer.
    pub const fn from_static(
        inner: &'static MpscRingBuffer<T, N>,
    ) -> (BoundedSender<T, N>, BoundedReceiver<T, N>) {
        (BoundedSender { inner }, BoundedReceiver { inner })
    }
}

/// MPSC チャネルの送信側
pub struct BoundedSender<T: 'static, const N: usize> {
    inner: &'static MpscRingBuffer<T, N>,
}

impl<T: 'static, const N: usize> BoundedSender<T, N> {
    pub fn send(&self, value: T) -> Result<(), T> {
        self.inner.push(value)
    }

    pub fn is_full(&self) -> bool {
        // capacity check
        let head = self.inner.head.load(Ordering::Relaxed);
        let tail = self.inner.tail.load(Ordering::Relaxed);
        (head + 1) % N == tail
    }
}

impl<T: 'static, const N: usize> Clone for BoundedSender<T, N> {
    fn clone(&self) -> Self {
        Self { inner: self.inner }
    }
}

/// MPSC チャネルの受信側
pub struct BoundedReceiver<T: 'static, const N: usize> {
    inner: &'static MpscRingBuffer<T, N>,
}

impl<T: 'static, const N: usize> BoundedReceiver<T, N> {
    pub fn recv(&self) -> Option<T> {
        self.inner.pop()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Alternative static helper types for explicit static usage
///
/// These are convenience wrappers for users that prefer to declare the buffer
/// as a `static` rather than using `Box::leak` in `BoundedChannel::new()`.
pub struct BoundedSenderStatic<T: 'static, const N: usize> {
    inner: &'static MpscRingBuffer<T, N>,
}

pub struct BoundedReceiverStatic<T: 'static, const N: usize> {
    inner: &'static MpscRingBuffer<T, N>,
}

impl<T: 'static, const N: usize> BoundedSenderStatic<T, N> {
    pub fn send(&self, value: T) -> Result<(), T> {
        self.inner.push(value)
    }

    pub fn is_full(&self) -> bool {
        let head = self.inner.head.load(Ordering::Relaxed);
        let tail = self.inner.tail.load(Ordering::Relaxed);
        (head + 1) % N == tail
    }
}

impl<T: 'static, const N: usize> Clone for BoundedSenderStatic<T, N> {
    fn clone(&self) -> Self {
        Self { inner: self.inner }
    }
}

impl<T: 'static, const N: usize> BoundedReceiverStatic<T, N> {
    pub fn recv(&self) -> Option<T> {
        self.inner.pop()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<T: 'static, const N: usize> BoundedChannel<T, N> {
    /// Convenience constructor to create Static sender/receiver wrappers from
    /// a `'static` buffer
    pub const fn into_static_wrappers(
        inner: &'static MpscRingBuffer<T, N>,
    ) -> (BoundedSenderStatic<T, N>, BoundedReceiverStatic<T, N>) {
        (
            BoundedSenderStatic { inner },
            BoundedReceiverStatic { inner },
        )
    }
}
