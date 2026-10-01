//! 物理フレームアロケータ群
//!
//! PMM fast allocator（bitmap + per-CPU magazine）を主経路とし、
//! Buddyはサブプールとして動作。

#[cfg(feature = "buddy_freelist")]
pub mod buddy_freelist; // フリーリストベースBuddy + ページモビリティ
pub mod fast_allocator; // High-Performance Bitmap Allocator
pub mod frame_allocator; // PMM物理フレーム管理（主インターフェース）
