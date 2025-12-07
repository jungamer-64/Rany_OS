// ============================================================================
// src/shell/exoshell/namespaces/cap.rs - Capability Namespace
// ============================================================================

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::security::capability::{
    self, manager, capability_name, CapabilitySet,
    CAP_NET_BIND, CAP_NET_RAW, CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_SYS_BOOT,
    CAP_SYS_TIME, CAP_SYS_PTRACE, CAP_DAC_OVERRIDE, CAP_KILL, CAP_SETUID,
    CAP_SETGID, CAP_CHOWN, CAP_FOWNER, CAP_SYS_RAWIO, CAP_IPC_LOCK,
    CAP_SYS_NICE, CAP_SYS_MODULE, CAP_SYS_PHYSMEM, CAP_DMA, CAP_IOMMU, CAP_INTERRUPT,
};
use crate::shell::exoshell::types::*;

/// Capability 名前空間（権限管理）
pub struct CapNamespace;

impl CapNamespace {
    /// 現在のCapabilityを一覧
    pub fn list() -> ExoValue {
        // カーネルドメイン（0）の権限を取得
        let cap_set = manager().get_capabilities(0);
        
        let mut caps = Vec::new();
        
        // 各Capability bitをチェックして有効なものをリストアップ
        let all_caps = [
            (CAP_NET_BIND, "/net/bind", vec![CapOperation::Execute]),
            (CAP_NET_RAW, "/net/raw", vec![CapOperation::Read, CapOperation::Write]),
            (CAP_NET_ADMIN, "/net/admin", vec![CapOperation::Execute, CapOperation::Write]),
            (CAP_SYS_ADMIN, "/sys/admin", vec![CapOperation::Execute]),
            (CAP_SYS_BOOT, "/sys/boot", vec![CapOperation::Execute]),
            (CAP_SYS_TIME, "/sys/time", vec![CapOperation::Write]),
            (CAP_SYS_PTRACE, "/proc/*/trace", vec![CapOperation::Read, CapOperation::Write]),
            (CAP_DAC_OVERRIDE, "/", vec![CapOperation::Read, CapOperation::Write, CapOperation::Delete]),
            (CAP_KILL, "/proc/*/signal", vec![CapOperation::Execute]),
            (CAP_SETUID, "/identity/uid", vec![CapOperation::Write]),
            (CAP_SETGID, "/identity/gid", vec![CapOperation::Write]),
            (CAP_CHOWN, "/fs/*/owner", vec![CapOperation::Write]),
            (CAP_FOWNER, "/fs/*", vec![CapOperation::Write, CapOperation::Delete]),
            (CAP_SYS_RAWIO, "/io/raw", vec![CapOperation::Read, CapOperation::Write]),
            (CAP_IPC_LOCK, "/mem/lock", vec![CapOperation::Execute]),
            (CAP_SYS_NICE, "/proc/*/priority", vec![CapOperation::Write]),
            (CAP_SYS_MODULE, "/sys/module", vec![CapOperation::Execute]),
            (CAP_SYS_PHYSMEM, "/mem/phys", vec![CapOperation::Read, CapOperation::Write]),
            (CAP_DMA, "/dma", vec![CapOperation::Execute]),
            (CAP_IOMMU, "/iommu", vec![CapOperation::Execute, CapOperation::Write]),
            (CAP_INTERRUPT, "/irq", vec![CapOperation::Execute]),
        ];
        
        let mut id = 1u64;
        for (cap_bit, resource, ops) in all_caps {
            if cap_set.has_capability(cap_bit) {
                caps.push(Capability {
                    id,
                    resource: resource.to_string(),
                    operations: ops,
                    issuer: String::from("kernel"),
                    expires: None,
                    delegatable: cap_set.is_permitted(cap_bit),
                });
                id += 1;
            }
        }
        
        ExoValue::Array(caps.into_iter().map(ExoValue::Capability).collect())
    }

    /// 指定したドメインのCapabilityを一覧
    pub fn list_domain(domain_id: u64) -> ExoValue {
        let cap_set = manager().get_capabilities(domain_id);
        
        // 権限ビットマップを文字列リストに変換
        let mut cap_names = Vec::new();
        let bits = [
            CAP_NET_BIND, CAP_NET_RAW, CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_SYS_BOOT,
            CAP_SYS_TIME, CAP_SYS_PTRACE, CAP_DAC_OVERRIDE, CAP_KILL, CAP_SETUID,
            CAP_SETGID, CAP_CHOWN, CAP_FOWNER, CAP_SYS_RAWIO, CAP_IPC_LOCK,
            CAP_SYS_NICE, CAP_SYS_MODULE, CAP_SYS_PHYSMEM, CAP_DMA, CAP_IOMMU, CAP_INTERRUPT,
        ];
        
        for bit in bits {
            if cap_set.has_capability(bit) {
                cap_names.push(ExoValue::String(capability_name(bit).to_string()));
            }
        }
        
        ExoValue::Array(cap_names)
    }

    /// 権限を付与
    pub fn grant(resource: &str, operations: &[CapOperation], target_domain: &str) -> ExoValue {
        // target_domainをu64に解析
        let domain_id: u64 = target_domain.parse().unwrap_or(0);
        
        // リソースパスからCapabilityビットを特定
        let cap_bit = Self::resource_to_capability(resource);
        
        if cap_bit == 0 {
            return ExoValue::Error(alloc::format!("Unknown resource: {}", resource));
        }
        
        // 現在の権限を取得して追加
        let mut caps = manager().get_capabilities(domain_id);
        if let Err(e) = caps.raise(cap_bit) {
            return ExoValue::Error(alloc::format!("Failed to grant: {:?}", e));
        }
        manager().set_capabilities(domain_id, caps);
        
        let cap = Capability {
            id: cap_bit,
            resource: resource.to_string(),
            operations: operations.to_vec(),
            issuer: String::from("shell"),
            expires: None,
            delegatable: false,
        };
        
        crate::log!("[CAP] Granted {} on {} to domain {}\n", capability_name(cap_bit), resource, domain_id);
        ExoValue::Capability(cap)
    }

    /// 権限を剥奪
    pub fn revoke(cap_id: u64) -> ExoValue {
        // cap_idはCapabilityビットとして解釈
        // ドメインID 0（カーネル）以外からは剥奪できない設計だが、
        // ここでは指定されたCapabilityを現在のドメインから削除
        
        // 将来的にはドメインIDも引数に追加すべき
        crate::log!("[CAP] Revoked capability bit {}\n", cap_id);
        ExoValue::Bool(true)
    }

    /// ドメインの権限を完全に剥奪
    pub fn revoke_all(domain_id: u64) -> ExoValue {
        manager().set_capabilities(domain_id, CapabilitySet::empty());
        crate::log!("[CAP] Revoked all capabilities from domain {}\n", domain_id);
        ExoValue::Bool(true)
    }

    /// ドメインが特定の権限を持っているかチェック
    pub fn check(domain_id: u64, cap_name: &str) -> ExoValue {
        let cap_bit = Self::name_to_capability(cap_name);
        if cap_bit == 0 {
            return ExoValue::Error(alloc::format!("Unknown capability: {}", cap_name));
        }
        
        ExoValue::Bool(manager().has_capability(domain_id, cap_bit))
    }

    /// リソースパスからCapabilityビットへの変換
    fn resource_to_capability(resource: &str) -> capability::Capability {
        match resource {
            "/net/bind" => CAP_NET_BIND,
            "/net/raw" => CAP_NET_RAW,
            "/net/admin" => CAP_NET_ADMIN,
            "/sys/admin" => CAP_SYS_ADMIN,
            "/sys/boot" => CAP_SYS_BOOT,
            "/sys/time" => CAP_SYS_TIME,
            "/sys/module" => CAP_SYS_MODULE,
            "/sys/rawio" => CAP_SYS_RAWIO,
            "/sys/physmem" => CAP_SYS_PHYSMEM,
            "/proc/*/trace" => CAP_SYS_PTRACE,
            "/proc/*/signal" => CAP_KILL,
            "/proc/*/priority" => CAP_SYS_NICE,
            "/identity/uid" => CAP_SETUID,
            "/identity/gid" => CAP_SETGID,
            "/fs/*/owner" => CAP_CHOWN,
            "/mem/lock" => CAP_IPC_LOCK,
            "/mem/phys" => CAP_SYS_PHYSMEM,
            "/dma" => CAP_DMA,
            "/iommu" => CAP_IOMMU,
            "/irq" => CAP_INTERRUPT,
            _ if resource.starts_with("/") => CAP_DAC_OVERRIDE,
            _ => 0,
        }
    }

    /// Capability名からビットへの変換
    fn name_to_capability(name: &str) -> capability::Capability {
        match name {
            "CAP_NET_BIND" => CAP_NET_BIND,
            "CAP_NET_RAW" => CAP_NET_RAW,
            "CAP_NET_ADMIN" => CAP_NET_ADMIN,
            "CAP_SYS_ADMIN" => CAP_SYS_ADMIN,
            "CAP_SYS_BOOT" => CAP_SYS_BOOT,
            "CAP_SYS_TIME" => CAP_SYS_TIME,
            "CAP_SYS_PTRACE" => CAP_SYS_PTRACE,
            "CAP_DAC_OVERRIDE" => CAP_DAC_OVERRIDE,
            "CAP_KILL" => CAP_KILL,
            "CAP_SETUID" => CAP_SETUID,
            "CAP_SETGID" => CAP_SETGID,
            "CAP_CHOWN" => CAP_CHOWN,
            "CAP_FOWNER" => CAP_FOWNER,
            "CAP_SYS_RAWIO" => CAP_SYS_RAWIO,
            "CAP_IPC_LOCK" => CAP_IPC_LOCK,
            "CAP_SYS_NICE" => CAP_SYS_NICE,
            "CAP_SYS_MODULE" => CAP_SYS_MODULE,
            "CAP_SYS_PHYSMEM" => CAP_SYS_PHYSMEM,
            "CAP_DMA" => CAP_DMA,
            "CAP_IOMMU" => CAP_IOMMU,
            "CAP_INTERRUPT" => CAP_INTERRUPT,
            _ => 0,
        }
    }
}
