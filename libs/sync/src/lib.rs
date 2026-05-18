// ============================================================================
// libs/sync/src/lib.rs - Synchronization Primitives (外部クレート向け)
// ============================================================================
//!
//! # `ExoRust` Synchronization Primitives（スタンドアロン版）
//!
//! このクレートは、カーネル本体に依存できない外部クレート
//! （独立ビルドされるストレージ / ドライバ / ツール等）向けに、
//! 同期プリミティブのスタンドアロン版を提供します。
//!
//! ## 正規版との関係
//!
//! | プリミティブ | 正規版（カーネル内） | 本クレート |
//! |-------------|---------------------|-----------|
//! | `PoisonLock` | `kernel/src/sync/poison_lock.rs` | `libs/sync/src/poison_lock.rs` |
//! | `Backoff` | `kernel/src/sync/lockfree.rs` | `libs/sync/src/backoff.rs` |
//!
//! **カーネル内コードは `crate::sync` を使用してください。**
//! 本クレートはカーネル外のファイルシステム等でのみ使用されます。
//!
//! 正規版は `IrqPoisonLock`、ロックメトリクス、`YIELD_LIMIT` 等の
//! カーネル固有機能を追加で提供します。
//! API契約（公開メソッドのシグネチャ）は正規版に準拠しています。
//!
//! ## 設計方針
//!
//! `ExoRust`の設計書8.4に基づき、共有リソースへのアクセスにはPoisoning対応の
//! ロックを必須としています。これにより、ドメインがMutexを保持したまま
//! パニックした場合のデッドロックを防止します。

#![no_std]
mod backoff;
mod poison_lock;

pub use backoff::Backoff;
pub use poison_lock::{
    IrqPoisonLock, IrqPoisonLockGuard, LockResult, PoisonError, PoisonLock, PoisonLockGuard,
    PoisonRwLock, PoisonRwLockReadGuard, PoisonRwLockWriteGuard,
};
