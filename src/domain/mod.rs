// ============================================================================
// src/domain/mod.rs - Domain (Cell) Management
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 8: フォールトアイソレーションと回復メカニズム
// ============================================================================
pub mod registry;
pub mod lifecycle;

pub use registry::{Domain, DomainState, DomainRegistry, get_domain, register_domain};
pub use lifecycle::{spawn_domain_task, terminate_domain, DomainError};
