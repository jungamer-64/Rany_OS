// ============================================================================
// src/sync/lockfree.rs - Lock-Free Ring Buffer for Inter-Core Communication
// 設計書 4.3: マルチコアスケーリングとShare-Nothingアーキテクチャ
// コア間でのデータ共有を避け、ロックフリーなリングバッファでメッセージパッシング
// ============================================================================
//!
//! # Lock-Free データ構造
//!
//! このモジュールは、高性能なコア間通信のためのロックフリーデータ構造を提供します。
//!
//! ## 主な機能
//! - SPSC (Single-Producer Single-Consumer) リングバッファ
//! - MPSC (Multi-Producer Single-Consumer) リングバッファ
//! - MPMC (Multi-Producer Multi-Consumer) リングバッファ
//! - 指数バックオフによるスピン最適化
//! - キャッシュライン最適化（False Sharing防止）
//!
//! ## 設計原則
//! - ゼロコピー通信
//! - CASベースの競合解決
//! - キャッシュ効率の最大化
// サブモジュール
// ============================================================================

pub mod backoff;
mod channel;
mod index_stack;
mod mpmc;
mod mpsc;
mod seqlock;
mod spsc;

#[cfg(test)]
#[path = "lockfree/tests.rs"]
mod tests;

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    pub use super::mpmc::qemu_tests::*;
}

// ============================================================================
// CacheLinePadded (全サブモジュールで使用)
// ============================================================================

/// キャッシュラインパディング（False Sharing防止）
/// x86_64のキャッシュラインは通常64バイト
#[repr(C, align(64))]
pub struct CacheLinePadded<T> {
    value: T,
}

impl<T> CacheLinePadded<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T> core::ops::Deref for CacheLinePadded<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

// ============================================================================
// 再エクスポート
// ============================================================================

pub use backoff::Backoff;
pub use channel::{
    BoundedChannel, BoundedReceiver, BoundedReceiverStatic, BoundedSender, BoundedSenderStatic,
    DEFAULT_QUEUE_SIZE, InterCoreChannel, InterCoreMessage, create_inter_core_channel,
};
pub use index_stack::{LockFreeIndexStack, LockFreeIndexStackPushError};
pub use mpmc::MpmcRingBuffer;
pub use mpsc::MpscRingBuffer;
pub use seqlock::{Seqlock, SeqlockWriteGuard};
pub use spsc::SpscRingBuffer;
