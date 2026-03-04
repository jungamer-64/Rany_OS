//! # データパス最適化
//!
//! ゼロコピー、メモリプール、適応的ポーリング、GRO、
//! チェックサムオフロード、スキャッタギャザーI/O等。

pub mod mempool;
pub mod zero_copy;
pub mod adaptive_polling;
pub mod optimization;
pub mod checksum_offload;
pub mod scatter_gather;
pub mod per_cpu_batch;
pub mod header_cache;
