//! ページ回収・圧力管理
//!
//! LRU/MGLRU、Shrinker Framework、ZSWAP、非同期スワップアウト。

pub mod async_swapout; // 非同期スワップアウト
pub mod oom_killer;
pub mod page_reclaim; // Page Reclaim + LRU + MGLRU
pub mod shrinker; // Shrinker Framework
pub mod workingset; // Workingset Refault Detection
pub mod zswap; // ZSWAP - スワップ前メモリ圧縮キャッシュ // OOM Killer（旧 memory/oom_killer.rs から移動）
