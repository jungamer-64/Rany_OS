// ============================================================================
// src/shell/exoshell/namespaces/cap.rs - Capability Namespace
// ============================================================================

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::shell::exoshell::types::*;

/// Capability 名前空間（権限管理）
pub struct CapNamespace;

impl CapNamespace {
    /// 現在のCapabilityを一覧
    pub fn list() -> ExoValue {
        // TODO: 実際のCapabilityレジストリと連携
        let caps = vec![
            Capability {
                id: 1,
                resource: String::from("/"),
                operations: vec![CapOperation::Read, CapOperation::List],
                issuer: String::from("kernel"),
                expires: None,
                delegatable: false,
            },
            Capability {
                id: 2,
                resource: String::from("/home"),
                operations: vec![
                    CapOperation::Read,
                    CapOperation::Write,
                    CapOperation::Create,
                    CapOperation::Delete,
                ],
                issuer: String::from("kernel"),
                expires: None,
                delegatable: true,
            },
        ];
        
        ExoValue::Array(caps.into_iter().map(ExoValue::Capability).collect())
    }

    /// 権限を付与
    pub fn grant(resource: &str, operations: &[CapOperation], target_domain: &str) -> ExoValue {
        // TODO: 実際の権限付与処理
        let cap = Capability {
            id: 100, // 新しいID
            resource: resource.to_string(),
            operations: operations.to_vec(),
            issuer: String::from("shell"),
            expires: None,
            delegatable: false,
        };
        
        crate::log!("[CAP] Granted {:?} on {} to {}\n", operations, resource, target_domain);
        ExoValue::Capability(cap)
    }

    /// 権限を剥奪
    pub fn revoke(cap_id: u64) -> ExoValue {
        // TODO: 実際の権限剥奪処理
        crate::log!("[CAP] Revoked capability {}\n", cap_id);
        ExoValue::Bool(true)
    }
}
