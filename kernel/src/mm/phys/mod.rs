//! 物理フレームアロケータ群
//!
//! PMM fast allocator（bitmap + per-CPU magazine）を主経路とし、
//! Buddyはサブプールとして動作。

pub mod buddy_allocator; // O(log n) バディシステム
#[cfg(feature = "buddy_freelist")]
pub mod buddy_freelist; // フリーリストベースBuddy + ページモビリティ
pub mod fast_allocator; // High-Performance Bitmap Allocator
pub mod frame_allocator; // PMM物理フレーム管理（主インターフェース）
pub mod frame_magazine; // Per-CPU Frame Magazine (PCP)
pub mod per_node_buddy; // Per-NUMA-Node Buddy Allocator
pub mod unified_alloc; // 統一フレームアロケータAPI
