//! 物理フレームアロケータ群
//!
//! PMM fast allocator（bitmap + per-CPU magazine）を主経路とし、
//! Buddyはサブプールとして動作。新規コードは `mm::allocator` 経由でアクセス推奨。

pub use super::buddy_allocator;
#[cfg(feature = "buddy_freelist")]
pub use super::buddy_freelist;
pub use super::fast_allocator;
pub use super::frame_allocator;
pub use super::per_node_buddy;
pub use super::frame_magazine;
pub use super::unified_alloc;
