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
use alloc::boxed::Box;
mod namespace_impl;

const TRACE_RESOURCE: &str = "/sys/cell/*/trace";
const SIGNAL_RESOURCE: &str = "/sys/cell/*/signal";
const PRIORITY_RESOURCE: &str = "/sys/cell/*/priority";

/// Capability 名前空間（権限管理）
pub struct CapNamespace;

impl CapNamespace {
    /// 現在のCapabilityを一覧
    pub fn list() -> ExoValue<'static> {
        // 現在のプロセス（ドメイン）の権限を取得
        let domain_id = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_domain())
            .unwrap_or(0);
        let cap_set = manager().get_capabilities(domain_id);

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
                TRACE_RESOURCE,
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
            (CAP_KILL, SIGNAL_RESOURCE, vec![CapOperation::Execute]),
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
            (CAP_SYS_NICE, PRIORITY_RESOURCE, vec![CapOperation::Write]),
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

    /// 権限を付与 (Requires CAP_SYS_ADMIN or permitted capability).
    ///
    /// Signature: grant(resource, [ops], target, [expires], [delegatable])
    pub fn grant(
        resource: &str,
        operations: &[CapOperation],
        target_domain: &str,
        expires: Option<u64>,
        delegatable: bool,
    ) -> ExoValue<'static> {
        let caller_domain = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_domain())
            .unwrap_or(0);

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
        // tested independently from the shell layer. We use the `_with_opts`
        // variant which returns a token id.
        let caller_caps = manager().get_capabilities(caller_domain);
        match manager().grant_capability_with_opts(
            caller_domain,
            domain_id,
            cap_bit,
            expires,
            delegatable,
        ) {
            Ok(token_id) => {
                let cap = Capability {
                    id: token_id,
                    resource: resource.to_string(),
                    operations: operations.to_vec(),
                    issuer: format!("domain:{}", caller_domain),
                    expires,
                    delegatable: caller_caps.is_permitted(cap_bit) || delegatable,
                };

                log::info!(
                    "[CAP] Granted {} on {} to domain {} by domain {} (token={})\n",
                    capability_name(cap_bit),
                    resource,
                    domain_id,
                    caller_domain,
                    token_id
                );
                ExoValue::Capability(cap)
            }
            Err(e) => ExoValue::Error(format!("Failed to grant: {:?}", e)),
        }
    }

    /// 自分の権限を放棄 (Revoke a grant by token id)
    pub fn revoke(cap_id: u64) -> ExoValue<'static> {
        let domain_id = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_domain())
            .unwrap_or(0);

        // First, attempt to revoke a grant token with the given id.
        match manager().revoke_grant(domain_id, cap_id, false) {
            Ok(_) => {
                log::info!(
                    "[CAP] Revoked token {} by domain {}\n",
                    cap_id,
                    domain_id
                );
                return ExoValue::Bool(true);
            }
            Err(capability::CapabilityError::InvalidCapability) => {
                // If no token with that id exists, fall back to self-revocation
                // treating cap_id as a capability bit (legacy behavior).
                let mut caps = manager().get_capabilities(domain_id);
                caps.drop(cap_id);
                caps.drop_permanently(cap_id);
                manager().set_capabilities(domain_id, caps);

                log::info!("[CAP] Revoked capability bit {} from self (legacy)\n", cap_id);
                return ExoValue::Bool(true);
            }
            Err(e) => return ExoValue::Error(format!("Failed to revoke: {:?}", e)),
        }
    }

    /// ドメインの権限を完全に剥奪 (Requires CAP_SYS_ADMIN)
    pub fn revoke_all(domain_id: u64) -> ExoValue<'static> {
        let caller_domain = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_domain())
            .unwrap_or(0);
        if !manager().has_capability(caller_domain, CAP_SYS_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_ADMIN required"));
        }

        manager().set_capabilities(domain_id, CapabilitySet::empty());
        log::info!("[CAP] Revoked all capabilities from domain {}\n", domain_id);
        ExoValue::Bool(true)
    }

    /// List active grant tokens for a domain
    pub fn tokens(domain: Option<u64>) -> ExoValue<'static> {
        let caller_domain = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_domain())
            .unwrap_or(0);
        let target = domain.unwrap_or(caller_domain);

        // If requesting another domain's tokens, require CAP_SYS_ADMIN
        if target != caller_domain && !manager().has_capability(caller_domain, CAP_SYS_ADMIN) {
            return ExoValue::Error(String::from(
                "Permission denied: CAP_SYS_ADMIN required",
            ));
        }

        let grants = manager().list_grants(target);
        let mut caps: Vec<Capability> = Vec::new();
        for g in grants {
            caps.push(Capability {
                id: g.id,
                resource: capability_name(g.cap).to_string(),
                operations: Vec::new(),
                issuer: format!("domain:{}", g.issuer),
                expires: g.expires,
                delegatable: g.delegatable,
            });
        }
        ExoValue::Array(caps.into_iter().map(ExoValue::Capability).collect())
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
    pub(crate) fn resource_to_capability(resource: &str) -> capability::Capability {
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
            "/sys/cell/*/trace" => CAP_SYS_PTRACE,
            "/sys/cell/*/signal" => CAP_KILL,
            "/sys/cell/*/priority" => CAP_SYS_NICE,
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

    // ================================================================
    // Shell dispatch helpers (extracted to reduce CC of `call`)
    // ================================================================

    /// Parse a single operation string into a `CapOperation`.
    fn parse_op(s: &str) -> Option<CapOperation> {
        const OP_TABLE: &[(&str, CapOperation)] = &[
            ("read", CapOperation::Read),
            ("write", CapOperation::Write),
            ("execute", CapOperation::Execute),
            ("delete", CapOperation::Delete),
            ("grant", CapOperation::Grant),
            ("revoke", CapOperation::Revoke),
            ("create", CapOperation::Create),
            ("list", CapOperation::List),
        ];
        let lower = s.to_lowercase();
        OP_TABLE
            .iter()
            .find(|(name, _)| *name == lower.as_str())
            .map(|(_, op)| *op)
    }

    /// Extract `ops` from the grant arguments.
    fn parse_grant_ops(args: &[ExoValue<'static>]) -> Vec<CapOperation> {
        let mut ops: Vec<CapOperation> = Vec::new();
        if let Some(v) = args.get(1) {
            match v {
                ExoValue::Array(arr) => {
                    for item in arr {
                        if let ExoValue::String(s) = item {
                            if let Some(op) = Self::parse_op(s.as_ref()) {
                                ops.push(op);
                            }
                        }
                    }
                }
                ExoValue::String(s) => {
                    if let Some(op) = Self::parse_op(s.as_ref()) {
                        ops.push(op);
                    }
                }
                _ => {}
            }
        }
        ops
    }

    /// Extract target domain string from grant arguments.
    fn parse_grant_target(args: &[ExoValue<'static>]) -> Result<String, ExoValue<'static>> {
        let target_arg = if args.len() >= 3 {
            args.get(2)
        } else if args.len() == 2 {
            match args.get(1) {
                Some(ExoValue::String(_)) | Some(ExoValue::Int(_)) => args.get(1),
                _ => None,
            }
        } else {
            None
        };

        match target_arg {
            Some(ExoValue::Int(n)) => Ok(n.to_string()),
            Some(ExoValue::String(s)) => Ok(s.to_string()),
            _ => Err(ExoValue::Error(String::from(
                "grant requires target domain id as second or third argument",
            ))),
        }
    }

    /// Apply a single option value to expires / delegatable.
    fn apply_option_value(
        v: &ExoValue<'static>,
        expires: &mut Option<u64>,
        delegatable: &mut bool,
    ) {
        match v {
            ExoValue::Int(n) => *expires = Some(*n as u64),
            ExoValue::Bool(b) => *delegatable = *b,
            ExoValue::Map(map) => {
                if let Some(ExoValue::Int(n)) = map.get("expires") {
                    *expires = Some(*n as u64);
                }
                if let Some(ExoValue::Bool(b)) = map.get("delegatable") {
                    *delegatable = *b;
                }
            }
            _ => {}
        }
    }

    /// Extract optional expires / delegatable from grant arguments.
    fn parse_grant_options(args: &[ExoValue<'static>]) -> (Option<u64>, bool) {
        let mut expires: Option<u64> = None;
        let mut delegatable: bool = false;
        if let Some(v) = args.get(3) {
            Self::apply_option_value(v, &mut expires, &mut delegatable);
        }
        if let Some(ExoValue::Bool(b)) = args.get(4) {
            delegatable = *b;
        }
        (expires, delegatable)
    }

    /// Dispatch handler for `cap.grant(...)` shell call.
    fn call_grant(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let resource = args
            .first()
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

        let ops = Self::parse_grant_ops(args);
        let target = match Self::parse_grant_target(args) {
            Ok(t) => t,
            Err(e) => return e,
        };
        let (expires, delegatable) = Self::parse_grant_options(args);
        Self::grant(resource, &ops, target.as_str(), expires, delegatable)
    }

    /// Dispatch handler for `cap.revoke(...)` shell call.
    fn call_revoke(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let id = args
            .first()
            .and_then(|v| match v {
                ExoValue::Int(n) => Some(*n as u64),
                _ => None,
            })
            .unwrap_or(0);
        Self::revoke(id)
    }

    /// Dispatch handler for `cap.revoke_all(...)` shell call.
    fn call_revoke_all(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let domain_id = args
            .first()
            .and_then(|v| match v {
                ExoValue::Int(n) => Some(*n as u64),
                _ => None,
            })
            .unwrap_or(0);
        Self::revoke_all(domain_id)
    }

    /// Dispatch handler for `cap.tokens(...)` shell call.
    fn call_tokens(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let domain = args
            .first()
            .and_then(|v| match v {
                ExoValue::Int(n) => Some(*n as u64),
                ExoValue::String(s) => s.parse().ok(),
                _ => None,
            });
        Self::tokens(domain)
    }

    /// Dispatch handler for `cap.check(...)` shell call.
    fn call_check(args: &[ExoValue<'static>]) -> ExoValue<'static> {
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
}
