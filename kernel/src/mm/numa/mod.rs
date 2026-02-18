//! NUMA サポート
//!
//! NUMAトポロジ検出、AutoNUMA自動ページマイグレーション、ドメインオーナーシップ追跡。

pub mod topology;          // NUMAトポロジ (旧 numa.rs)
pub mod autonuma;          // AutoNUMA - 自動ページマイグレーション
pub mod domain_ownership;  // ドメインオーナーシップ追跡
