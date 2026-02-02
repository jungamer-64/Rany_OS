// ============================================================================
// libs/sync/src/lib.rs - Synchronization Primitives
// ============================================================================
//!
//! # ExoRust Synchronization Primitives
//!
//! このクレートは、ExoRustカーネルとファイルシステム実装で共通して使用される
//! 同期プリミティブを提供します。
//!
//! ## 主なコンポーネント
//!
//! - [`PoisonLock`]: パニック時に自動的に毒入れされるMutex
//! - [`Backoff`]: 指数バックオフアルゴリズム
//!
//! ## 設計方針
//!
//! ExoRustの設計書8.4に基づき、共有リソースへのアクセスにはPoisoning対応の
//! ロックを必須としています。これにより、ドメインがMutexを保持したまま
//! パニックした場合のデッドロックを防止します。

#![no_std]
#![allow(dead_code)]

mod poison_lock;
mod backoff;

pub use poison_lock::{LockResult, PoisonError, PoisonLock, PoisonLockGuard};
pub use backoff::Backoff;
