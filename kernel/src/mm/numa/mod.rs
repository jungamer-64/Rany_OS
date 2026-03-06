//! NUMA サポート
//!
//! NUMAトポロジ検出、AutoNUMA自動ページマイグレーション、ドメインオーナーシップ追跡。

pub mod autonuma; // AutoNUMA - 自動ページマイグレーション
pub mod domain_ownership;
pub mod topology; // NUMAトポロジ (旧 numa.rs) // ドメインオーナーシップ追跡
