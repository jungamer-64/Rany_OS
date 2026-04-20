// ============================================================================
// kernel/src/net/datapath/mod.rs - データパス最適化
// ============================================================================
//! # データパス最適化
//!
//! ゼロコピー、メモリプール、適応的ポーリング、GRO、
//! チェックサムオフロード、スキャッタギャザーI/O等。

pub mod adaptive_polling;
pub mod checksum_offload;
pub mod header_cache;
pub mod mempool;
pub mod optimization;
pub mod per_cpu_batch;
pub mod scatter_gather;
pub mod zero_copy;
