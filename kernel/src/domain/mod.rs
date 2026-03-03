// ============================================================================
// src/domain/mod.rs - ドメイン支援モジュール（型定義・クォータ・ライフサイクル）
// ============================================================================
//!
//! # 責務の分界
//!
//! - **`domain/`（本モジュール）**: ドメインのクォータ管理とライフサイクル操作を提供。
//!   `DomainError`, `DomainContext`, `DomainTask` 等のヘルパー型を定義する。
//!
//! - **`domain_system`**: ドメインの中核管理システム。`DomainId`, `DomainState`,
//!   レジストリ、Exchange Heap連携、`terminate_domain()` 等の統合APIを提供。
//!   ドメインの作成・検索・状態変更はすべて `domain_system` 経由で行う。
//!
//! - **`driver_domain/`**: ドライバセル固有のライフサイクル管理。
//!
//! ## 使用ガイドライン
//!
//! - ドメインの作成・終了・状態変更 → `crate::domain_system`
//! - リソースクォータの設定・確認 → `crate::domain::quota`
//! - ドメイン境界でのタスクラップ → `crate::domain::lifecycle`
//!
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 8: フォールトアイソレーションと回復メカニズム
// 設計書 9.3: リソースアカウンティングとQoS
// ============================================================================
pub mod lifecycle;
pub mod quota;

#[allow(unused_imports)]
pub use quota::{DomainPriority, DomainQuota, QuotaError, quota_manager};
