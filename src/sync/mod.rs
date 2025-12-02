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
    // SPSC Ring Buffer
    SpscRingBuffer,
    // MPSC Ring Buffer
    MpscRingBuffer,
    // Inter-core communication
    InterCoreMessage, InterCoreChannel, create_inter_core_channel,
    DEFAULT_QUEUE_SIZE,
    // Bounded channel
    BoundedChannel, BoundedSender, BoundedReceiver,
    // Seqlock
    Seqlock, SeqlockWriteGuard,
};
