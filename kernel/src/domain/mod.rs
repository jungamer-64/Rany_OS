// ============================================================================
// src/domain/mod.rs - Domain (Cell) Management
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 8: フォールトアイソレーションと回復メカニズム
// 設計書 9.3: リソースアカウンティングとQoS
// ============================================================================
pub mod lifecycle;
pub mod quota;
pub mod registry;

pub use quota::{DomainPriority, DomainQuota, QuotaError, quota_manager};
