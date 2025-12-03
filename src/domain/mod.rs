// ============================================================================
// src/domain/mod.rs - Domain (Cell) Management
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 8: フォールトアイソレーションと回復メカニズム
// ============================================================================
pub mod lifecycle;
pub mod registry;

pub use lifecycle::{DomainError, spawn_domain_task, terminate_domain};
pub use registry::{Domain, DomainRegistry, DomainState, get_domain, register_domain};
