//! キャッシュ・最適化レイヤー
//!
//! Per-CPU/Per-Core キャッシュ、マガジン、Arena、Exchange Heap等。

pub mod arena; // Single-Writer Arena
pub mod exchange_heap; // ゼロコピーIPC用ヒープ
pub mod magazine; // ジェネリックマガジンキャッシュ
pub mod slab_cache; // Per-Core Slabキャッシュ
pub mod slab_registry; // Slab Merging Registry
pub mod zero_page;
pub mod zeroed_pool; // PMM Idle Zeroing // Non-Temporal ゼロクリア + スクラビング
