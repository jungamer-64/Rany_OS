//! ページ回収・圧力管理
//!
//! LRU/MGLRU、Shrinker Framework、ZSWAP、非同期スワップアウト。

pub use super::page_reclaim;
pub use super::shrinker;
pub use super::workingset;
pub use super::zswap;
pub use super::async_swapout;
