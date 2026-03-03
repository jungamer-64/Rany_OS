// ============================================================================
// mm/reclaim/oom_killer.rs - OOM Killer re-export
// ============================================================================
// OOM Killer の実体は memory/oom_killer.rs にあります。
// ページ回収 (reclaim) サブシステムの一部として、ここからもアクセス可能です。
//
// 使用例:
//   use crate::mm::reclaim::oom_killer::try_free_memory;
//   use crate::memory::oom_killer::try_free_memory; // 互換パス
// ============================================================================

#[allow(unused_imports)]
pub use crate::memory::oom_killer::*;
