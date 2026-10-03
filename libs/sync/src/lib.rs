// ============================================================================
// libs/sync/src/lib.rs - Synchronization Primitives (外部クレート向け)
// ============================================================================
//!
//! # `ExoRust` 共有同期プリミティブ
//!
//! kernel と独立ビルドされる driver / storage / tool が共有する同期の
//! 境界を所有します。HAL の CPU ローカルな guard によってロックと
//! 同期的一回初期化を保護し、kernel crate への依存は持ちません。
//!
//! ロックの guard はロック解放後に切替抑止を解除します。抑止の解除は
//! スタックを切り替えず、保留要求は次のタイマー割込みが処理します。
//! IRQ と共有するデータは別途 IRQ-safe なロックで保護してください。
//! deferred notification は通知先の所有権を保持し、ISR の allocation と
//! callback 実行を必要とせずに通知を合流します。CPU queue の所有と
//! callback の実行場所は kernel 側の責務です。

#![no_std]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;
mod backoff;
mod critical_lock;
mod event;
mod init_once;
mod notification;
mod poison_lock;
mod waker;

pub use backoff::Backoff;
pub use critical_lock::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
pub use event::{BroadcastEvent, EventListener};
pub use init_once::InitOnce;
pub use notification::{DeferredNotification, NotificationQueue};
pub use poison_lock::{
    IrqPoisonLock, IrqPoisonLockGuard, LockResult, PoisonError, PoisonLock, PoisonLockGuard,
    PoisonRwLock, PoisonRwLockReadGuard, PoisonRwLockWriteGuard, set_panicking,
};
pub use waker::WakerSlot;
