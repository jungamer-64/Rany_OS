// ============================================================================
// src/sync/mod.rs - 同期プリミティブ
// カーネル用の割り込み安全なロック機構とロックフリーデータ構造
// ============================================================================

pub mod irq_mutex;
pub mod lockfree;

#[allow(unused_imports)]
pub use irq_mutex::{IrqMutex, IrqMutexGuard};

#[allow(unused_imports)]
pub use lockfree::{
    // Backoff strategy
    Backoff,
    // Bounded channel
    BoundedChannel,
    BoundedReceiver,
    BoundedSender,
    // Cache-line optimization
    CacheLinePadded,
    DEFAULT_QUEUE_SIZE,
    InterCoreChannel,
    // Inter-core communication
    InterCoreMessage,
    // MPMC Ring Buffer
    MpmcRingBuffer,
    // MPSC Ring Buffer
    MpscRingBuffer,
    // Seqlock
    Seqlock,
    SeqlockWriteGuard,
    // SPSC Ring Buffer
    SpscRingBuffer,
    create_inter_core_channel,
};
