// ============================================================================
// src/shell/exoshell/namespaces/cap.rs - Capability Namespace
// ============================================================================

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::security::capability::{
    self, CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DMA, CAP_FOWNER, CAP_INTERRUPT, CAP_IOMMU, CAP_IPC_LOCK,
    CAP_KILL, CAP_NET_ADMIN, CAP_NET_BIND, CAP_NET_RAW, CAP_SETGID, CAP_SETUID, CAP_SYS_ADMIN,
    CAP_SYS_BOOT, CAP_SYS_MODULE, CAP_SYS_NICE, CAP_SYS_PHYSMEM, CAP_SYS_PTRACE, CAP_SYS_RAWIO,
    CAP_SYS_TIME, CapabilitySet, capability_name, manager,
};
use crate::shell::exoshell::types::*;
use crate::task::process::getpid;
use alloc::boxed::Box;

/// Capability 名前空間（権限管理）
pub struct CapNamespace;

impl CapNamespace {
    /// 現在のCapabilityを一覧
    pub fn list() -> ExoValue<'static> {
        // 現在のプロセス（ドメイン）の権限を取得
        let pid = getpid().as_u64();
        let cap_set = manager().get_capabilities(pid);

        let mut caps = Vec::new();

        // 各Capability bitをチェックして有効なものをリストアップ
        let all_caps = [
            (CAP_NET_BIND, "/net/bind", vec![CapOperation::Execute]),
            (
                CAP_NET_RAW,
                "/net/raw",
                vec![CapOperation::Read, CapOperation::Write],
            ),
            (
                CAP_NET_ADMIN,
                "/net/admin",
                vec![CapOperation::Execute, CapOperation::Write],
            ),
            (CAP_SYS_ADMIN, "/sys/admin", vec![CapOperation::Execute]),
            (CAP_SYS_BOOT, "/sys/boot", vec![CapOperation::Execute]),
            (CAP_SYS_TIME, "/sys/time", vec![CapOperation::Write]),
            (
                CAP_SYS_PTRACE,
                "/proc/*/trace",
                vec![CapOperation::Read, CapOperation::Write],
            ),
            (
                CAP_DAC_OVERRIDE,
                "/",
                vec![
                    CapOperation::Read,
                    CapOperation::Write,
                    CapOperation::Delete,
                ],
            ),
            (CAP_KILL, "/proc/*/signal", vec![CapOperation::Execute]),
            (CAP_SETUID, "/identity/uid", vec![CapOperation::Write]),
            (CAP_SETGID, "/identity/gid", vec![CapOperation::Write]),
            (CAP_CHOWN, "/fs/*/owner", vec![CapOperation::Write]),
            (
                CAP_FOWNER,
                "/fs/*",
                vec![CapOperation::Write, CapOperation::Delete],
            ),
            (
                CAP_SYS_RAWIO,
                "/io/raw",
                vec![CapOperation::Read, CapOperation::Write],
            ),
            (CAP_IPC_LOCK, "/mem/lock", vec![CapOperation::Execute]),
            (CAP_SYS_NICE, "/proc/*/priority", vec![CapOperation::Write]),
            (CAP_SYS_MODULE, "/sys/module", vec![CapOperation::Execute]),
            (
                CAP_SYS_PHYSMEM,
                "/mem/phys",
                vec![CapOperation::Read, CapOperation::Write],
            ),
            (CAP_DMA, "/dma", vec![CapOperation::Execute]),
            (
                CAP_IOMMU,
                "/iommu",
                vec![CapOperation::Execute, CapOperation::Write],
            ),
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
    pub fn list_domain(domain_id: u64) -> ExoValue<'static> {
        // 他ドメインの権限確認には CAP_SYS_PTRACE または CAP_SYS_ADMIN が必要かもしれないが、
        // とりあえず読み取りは許可する方針とする（psコマンド同様）
        let cap_set = manager().get_capabilities(domain_id);

        // 権限ビットマップを文字列リストに変換
        let mut cap_names = Vec::new();
        let bits = [
            CAP_NET_BIND,
            CAP_NET_RAW,
            CAP_NET_ADMIN,
            CAP_SYS_ADMIN,
            CAP_SYS_BOOT,
            CAP_SYS_TIME,
            CAP_SYS_PTRACE,
            CAP_DAC_OVERRIDE,
            CAP_KILL,
            CAP_SETUID,
            CAP_SETGID,
            CAP_CHOWN,
            CAP_FOWNER,
            CAP_SYS_RAWIO,
            CAP_IPC_LOCK,
            CAP_SYS_NICE,
            CAP_SYS_MODULE,
            CAP_SYS_PHYSMEM,
            CAP_DMA,
            CAP_IOMMU,
            CAP_INTERRUPT,
        ];

        for bit in bits {
            if cap_set.has_capability(bit) {
                cap_names.push(ExoValue::String(Cow::Owned(
                    capability_name(bit).to_string(),
                )));
            }
        }

        ExoValue::Array(cap_names)
    }

    /// 権限を付与 (Requires CAP_SYS_ADMIN)
    pub fn grant(
        resource: &str,
        operations: &[CapOperation],
        target_domain: &str,
    ) -> ExoValue<'static> {
        let caller_pid = getpid().as_u64();

        // target_domainをu64に解析
        let domain_id: u64 = match target_domain.parse() {
            Ok(v) => v,
            Err(_) => {
                return ExoValue::Error(format!("Invalid target domain id: {}", target_domain));
            }
        };

        // リソースパスからCapabilityビットを特定
        let cap_bit = Self::resource_to_capability(resource);
        if cap_bit == 0 {
            return ExoValue::Error(format!("Unknown resource: {}", resource));
        }

        // Delegate actual grant logic to the capability manager so it can be
        // tested independently from the shell layer.
        let caller_caps = manager().get_capabilities(caller_pid);
        if let Err(e) = manager().grant_capability(caller_pid, domain_id, cap_bit) {
            return ExoValue::Error(format!("Failed to grant: {:?}", e));
        }

        let cap = Capability {
            id: cap_bit,
            resource: resource.to_string(),
            operations: operations.to_vec(),
            issuer: format!("domain:{}", caller_pid),
            expires: None,
            delegatable: caller_caps.is_permitted(cap_bit),
        };

        crate::log!(
            "[CAP] Granted {} on {} to domain {} by domain {}\n",
            capability_name(cap_bit),
            resource,
            domain_id,
            caller_pid
        );
        ExoValue::Capability(cap)
    }

    /// 自分の権限を放棄 (Revoke from self)
    pub fn revoke(cap_id: u64) -> ExoValue<'static> {
        let pid = getpid().as_u64();
        let mut caps = manager().get_capabilities(pid);

        // cap_idはここでの実装ではCapabilityビットと仮定
        // IDからビットへの変換が必要だが、ここでは簡略化して cap_id = bit とする
        // あるいは `list` で返した ID (1..N) とのマッピングが必要。
        // リストのインデックスに依存するのは脆弱なので、
        // 実際には cap_id はビットマスクか、名前で指定させるべき。
        // ここでは ExoShell の仕様上 cap_id が渡されるので、ビットとして扱うか、
        // 名前解決ロジックが必要だが、とりあえずビットとして扱う（既存コード準拠）

        caps.drop(cap_id);
        // 永続的に放棄するか、effectiveだけ落とすか？
        // 通常 revoke と言えば二度と使えないようにすること
        caps.drop_permanently(cap_id);

        manager().set_capabilities(pid, caps);

        crate::log!("[CAP] Revoked capability bit {} from self\n", cap_id);
        ExoValue::Bool(true)
    }

    /// ドメインの権限を完全に剥奪 (Requires CAP_SYS_ADMIN)
    pub fn revoke_all(domain_id: u64) -> ExoValue<'static> {
        let caller_pid = getpid().as_u64();
        if !manager().has_capability(caller_pid, CAP_SYS_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_ADMIN required"));
        }

        manager().set_capabilities(domain_id, CapabilitySet::empty());
        crate::log!("[CAP] Revoked all capabilities from domain {}\n", domain_id);
        ExoValue::Bool(true)
    }

    /// ドメインが特定の権限を持っているかチェック
    pub fn check(domain_id: u64, cap_name: &str) -> ExoValue<'static> {
        let cap_bit = Self::name_to_capability(cap_name);
        if cap_bit == 0 {
            return ExoValue::Error(format!("Unknown capability: {}", cap_name));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::capability::*;
    use crate::task::process::{ProcessId, process_manager, set_current_process};

    #[test]
    fn test_grant_requires_permissions() {
        let caller = process_manager().create(ProcessId::INIT, "caller").unwrap();
        set_current_process(caller);
        // caller has no capabilities
        manager().set_capabilities(caller.as_u64(), CapabilitySet::empty());

        let target = process_manager().create(ProcessId::INIT, "target").unwrap();

        let res = CapNamespace::grant("/net/bind", &[], &format!("{}", target.as_u64()));
        match res {
            ExoValue::Error(_) => {}
            other => panic!("Expected error, got {:?}", other),
        }
    }

    #[test]
    fn test_grant_with_permitted() {
        let caller = process_manager()
            .create(ProcessId::INIT, "caller2")
            .unwrap();
        set_current_process(caller);
        // give caller permitted CAP_NET_BIND
        manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

        let target = process_manager()
            .create(ProcessId::INIT, "target2")
            .unwrap();

        let res = CapNamespace::grant("/net/bind", &[], &format!("{}", target.as_u64()));

        match res {
            ExoValue::Capability(cap) => {
                assert_eq!(cap.resource, "/net/bind");
                // target should now have effective capability
                assert!(manager().has_capability(target.as_u64(), CAP_NET_BIND));
            }
            other => panic!("grant failed: {:?}", other),
        }
    }
}

impl ShellNamespace for CapNamespace {
    fn name(&self) -> &str {
        "cap"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "list" => Self::list(),
                "revoke" => {
                    let id = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as u64),
                            _ => None,
                        })
                        .unwrap_or(0);
                    Self::revoke(id)
                }
                "grant" => {
                    // grant(resource: &str, ops: &[CapOperation], target: &str)
                    // Parse args: resource (string), ops (array|string) optional, target (int|string)
                    let resource = args
                        .get(0)
                        .and_then(|v| match v {
                            ExoValue::String(s) => Some(s.as_ref()),
                            _ => None,
                        })
                        .unwrap_or("");
                    if resource.is_empty() {
                        return ExoValue::Error(String::from(
                            "grant(resource, [ops], target) requires a resource string",
                        ));
                    }

                    // Helper to parse a single operation string
                    fn parse_op(s: &str) -> Option<CapOperation> {
                        match s.to_lowercase().as_str() {
                            "read" => Some(CapOperation::Read),
                            "write" => Some(CapOperation::Write),
                            "execute" => Some(CapOperation::Execute),
                            "delete" => Some(CapOperation::Delete),
                            "grant" => Some(CapOperation::Grant),
                            "revoke" => Some(CapOperation::Revoke),
                            "create" => Some(CapOperation::Create),
                            "list" => Some(CapOperation::List),
                            _ => None,
                        }
                    }

                    let mut ops: Vec<CapOperation> = Vec::new();
                    // Determine if ops is provided as second arg
                    if let Some(v) = args.get(1) {
                        match v {
                            ExoValue::Array(arr) => {
                                for item in arr {
                                    if let ExoValue::String(s) = item {
                                        if let Some(op) = parse_op(s.as_ref()) {
                                            ops.push(op);
                                        }
                                    }
                                }
                            }
                            ExoValue::String(s) => {
                                if let Some(op) = parse_op(s.as_ref()) {
                                    ops.push(op);
                                }
                            }
                            _ => {}
                        }
                    }

                    // Determine target: either args[2] or args[1] if ops omitted
                    let target_arg = if args.len() >= 3 {
                        args.get(2)
                    } else if args.len() == 2 {
                        // if second arg isn't ops but target
                        match args.get(1) {
                            Some(ExoValue::String(_)) | Some(ExoValue::Int(_)) => args.get(1),
                            _ => None,
                        }
                    } else {
                        None
                    };

                    let target = match target_arg {
                        Some(ExoValue::Int(n)) => n.to_string(),
                        Some(ExoValue::String(s)) => s.to_string(),
                        _ => {
                            return ExoValue::Error(String::from(
                                "grant requires target domain id as second or third argument",
                            ));
                        }
                    };

                    Self::grant(resource, &ops, target.as_str())
                }
                "revoke_all" => {
                    let domain_id = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as u64),
                            _ => None,
                        })
                        .unwrap_or(0);
                    Self::revoke_all(domain_id)
                }
                "check" => {
                    let domain_id = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as u64),
                            _ => None,
                        })
                        .unwrap_or(0);
                    let cap = args
                        .get(1)
                        .and_then(|v| match v {
                            ExoValue::String(s) => Some(s.as_ref()),
                            _ => None,
                        })
                        .unwrap_or("");
                    Self::check(domain_id, cap)
                }
                _ => ExoValue::Error(format!(
                    "Unknown method 'cap.{}'\nValid methods: list, revoke, grant, check",
                    method
                )),
            }
        })
    }
}
