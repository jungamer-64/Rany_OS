// ============================================================================
// libs/sync/src/lib.rs - Synchronization Primitives
// ============================================================================
//!
//! # `ExoRust` Synchronization Primitives
//!
//! このクレートは、`ExoRust`カーネルとファイルシステム実装で共通して使用される
//! 同期プリミティブを提供します。
//!
//! ## 主なコンポーネント
//!
//! - [`PoisonLock`] - パニック時に自動的に毒入れされるMutex
//! - [`Backoff`] - 指数バックオフアルゴリズム
//!
//! ## 設計方針
//!
//! `ExoRust`の設計書8.4に基づき、共有リソースへのアクセスにはPoisoning対応の
//! ロックを必須としています。これにより、ドメインがMutexを保持したまま
//! パニックした場合のデッドロックを防止します。

#![no_std]
#![allow(dead_code)]

mod poison_lock;
mod backoff;

pub use poison_lock::{LockResult, PoisonError, PoisonLock, PoisonLockGuard};
pub use backoff::Backoff;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    pub use crate::poison_lock::qemu_tests::{
        basic_lock_smoke, clear_poison_smoke, default_lock_smoke, initial_poison_state_smoke,
        try_lock_smoke,
    };
}
