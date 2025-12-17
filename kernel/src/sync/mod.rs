// ============================================================================
// src/sync/mod.rs - 同期プリミティブ
// カーネル用の割り込み安全なロック機構とロックフリーデータ構造
// ============================================================================
//!
//! # 同期プリミティブの使用ガイドライン
//!
//! ## 【設計書】ドメイン間通信でのArc<Mutex<T>>使用禁止
//!
//! ドメイン境界をまたぐデータ共有には`Arc<Mutex<T>>`を使用**しないでください**。
//! 代わりに`ipc::RRef<T>`を使用して、所有権の追跡とゼロコピー転送を実現します。
//!
//! ### ✅ 許可される使用例（同一ドメイン内）
//! ```ignore
//! // 同一ドメイン内のスレッド間共有
//! let shared = Arc::new(Mutex::new(data));
//! ```
//!
//! ### ❌ 禁止される使用例（ドメイン間）
//! ```ignore
//! // ドメイン間で Arc<Mutex<T>> を共有してはいけない
//! // 代わりに RRef<T> を使用する
//! let rref = RRef::new(source_domain, data);
//! let rref = rref.move_to(target_domain); // 所有権移動
//! ```
//!
//! ## 推奨される同期プリミティブ
//!
//! - `IrqMutex<T>`: 割り込みを無効化してロックする（ISRセーフ）
//! - `spin::Mutex<T>`: 軽量スピンロック（同一ドメイン内のみ）
//! - `PoisonLock<T>`: パニック時自動毒入れMutex（推奨）
//! - `IrqPoisonLock<T>`: 割り込み禁止 + パニック時毒入れ
//! - `Seqlock<T>`: 読み取り優先のシーケンスロック
//! - `MpmcRingBuffer<T>`: ロックフリーな複数プロデューサ・複数コンシューマキュー
//!

pub mod atomic_waker;
pub mod irq_mutex;
pub mod lockfree;
pub mod poison_lock;

pub use atomic_waker::AtomicWaker;

#[allow(unused_imports)]
pub use irq_mutex::{IrqMutex, IrqMutexGuard};

#[allow(unused_imports)]
pub use poison_lock::{
    IrqPoisonLock, IrqPoisonLockGuard, LockResult, PoisonError, PoisonLock, PoisonLockGuard,
    set_panicking,
};

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
