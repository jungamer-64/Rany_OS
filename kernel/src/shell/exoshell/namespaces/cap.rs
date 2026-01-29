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

#[cfg(feature = "posix-compat")]
const TRACE_RESOURCE: &str = "/proc/*/trace";
#[cfg(not(feature = "posix-compat"))]
const TRACE_RESOURCE: &str = "/sys/cell/*/trace";
#[cfg(feature = "posix-compat")]
const SIGNAL_RESOURCE: &str = "/proc/*/signal";
#[cfg(not(feature = "posix-compat"))]
const SIGNAL_RESOURCE: &str = "/sys/cell/*/signal";
#[cfg(feature = "posix-compat")]
const PRIORITY_RESOURCE: &str = "/proc/*/priority";
#[cfg(not(feature = "posix-compat"))]
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
            #[cfg(feature = "posix-compat")]
            "/proc/*/trace" => CAP_SYS_PTRACE,
            #[cfg(feature = "posix-compat")]
            "/proc/*/signal" => CAP_KILL,
            #[cfg(feature = "posix-compat")]
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
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use crate::security::capability::*;
    use crate::domain_system::{DomainCredentials, DomainId, DomainSecurity};
    use crate::task::context::{get_current_task, set_current_task, TaskControlBlock};

    fn idle_entry(_: u64) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    struct CurrentTaskGuard {
        prev: Option<*mut TaskControlBlock>,
        current: *mut TaskControlBlock,
    }

    impl Drop for CurrentTaskGuard {
        fn drop(&mut self) {
            let cpu_id = crate::smp::current_cpu() as usize;
            let prev_ptr = self.prev.unwrap_or(core::ptr::null_mut());
            unsafe {
                set_current_task(cpu_id, prev_ptr);
                drop(Box::from_raw(self.current));
            }
        }
    }

    fn set_current_subject(domain_id: DomainId) -> CurrentTaskGuard {
        let cpu_id = crate::smp::current_cpu() as usize;
        let prev = get_current_task(cpu_id);
        let mut tcb = TaskControlBlock::new(idle_entry, 0, 0, domain_id)
            .expect("failed to create test TCB");
        let caps = manager().get_capabilities(domain_id.as_u64());
        tcb.security = Arc::new(DomainSecurity {
            credentials: DomainCredentials::ROOT,
            caps,
        });
        let boxed = Box::new(tcb);
        let current = Box::into_raw(boxed);
        unsafe {
            set_current_task(cpu_id, current);
        }
        CurrentTaskGuard { prev, current }
    }

    #[test_case]
    fn test_grant_requires_permissions() {
        let caller = DomainId::new(100);
        let _guard = set_current_subject(caller);
        // caller has no capabilities
        manager().set_capabilities(caller.as_u64(), CapabilitySet::empty());

        let target = DomainId::new(101);

        let res = CapNamespace::grant("/net/bind", &[], &format!("{}", target.as_u64()), None, false);
        match res {
            ExoValue::Error(_) => {}
            other => panic!("Expected error, got {:?}", other),
        }
    }

    #[test_case]
    fn test_grant_with_permitted() {
        let caller = DomainId::new(110);
        let _guard = set_current_subject(caller);
        // give caller permitted CAP_NET_BIND
        manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

        let target = DomainId::new(111);

        let res = CapNamespace::grant("/net/bind", &[], &format!("{}", target.as_u64()), None, false);

        match res {
            ExoValue::Capability(cap) => {
                assert_eq!(cap.resource, "/net/bind");
                // Should have a token id
                assert!(cap.id > 0);
                // target should now have effective capability
                assert!(manager().has_capability(target.as_u64(), CAP_NET_BIND));
                let grants = manager().list_grants(target.as_u64());
                assert_eq!(grants.len(), 1);
                assert_eq!(grants[0].id, cap.id);
            }
            other => panic!("grant failed: {:?}", other),
        }
    }

    #[test_case]
    fn test_tokens_listing_and_revoke() {
        let caller = DomainId::new(120);
        let mut _guard = set_current_subject(caller);
        manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

        let target = DomainId::new(121);

        // Grant a token
        let res = CapNamespace::grant("/net/bind", &[], &format!("{}", target.as_u64()), None, false);
        let token_id = match res {
            ExoValue::Capability(cap) => cap.id,
            other => panic!("grant failed: {:?}", other),
        };

        // Switch to target and list tokens
        _guard = set_current_subject(target);
        match CapNamespace::tokens(None) {
            ExoValue::Array(arr) => {
                assert_eq!(arr.len(), 1);
                match &arr[0] {
                    ExoValue::Capability(cap) => assert_eq!(cap.id, token_id),
                    other => panic!("Expected capability token, got {:?}", other),
                }
            }
            other => panic!("tokens() failed: {:?}", other),
        }

        // Try to revoke as non-issuer (should fail)
        _guard = set_current_subject(target);
        match CapNamespace::revoke(token_id) {
            ExoValue::Error(_) => {}
            other => panic!("Expected error on unauthorized revoke, got {:?}", other),
        }

        // Revoke as issuer
        _guard = set_current_subject(caller);
        match CapNamespace::revoke(token_id) {
            ExoValue::Bool(true) => {}
            other => panic!("Expected success on revoke by issuer, got {:?}", other),
        }

        // Token removed
        assert!(manager().list_grants(target.as_u64()).is_empty());
    }

    #[test_case]
    fn test_sysadmin_can_revoke() {
        let issuer = DomainId::new(130);
        let mut _guard = set_current_subject(issuer);
        manager().set_capabilities(issuer.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

        let target = DomainId::new(131);

        let res = CapNamespace::grant("/net/bind", &[], &format!("{}", target.as_u64()), None, false);
        let token_id = match res {
            ExoValue::Capability(cap) => cap.id,
            other => panic!("grant failed: {:?}", other),
        };

        let admin = DomainId::new(132);
        manager().set_capabilities(admin.as_u64(), CapabilitySet::with_permitted(CAP_SYS_ADMIN));

        _guard = set_current_subject(admin);
        match CapNamespace::revoke(token_id) {
            ExoValue::Bool(true) => {}
            other => panic!("Expected admin revoke to succeed, got {:?}", other),
        }

        assert!(manager().list_grants(target.as_u64()).is_empty());
    }

    #[test_case]
    fn test_delegation_allows_regrant() {
        let parent = DomainId::new(140);
        let mut _guard = set_current_subject(parent);
        manager().set_capabilities(parent.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

        let child = DomainId::new(141);
        let grand = DomainId::new(142);

        // Parent grants to child with delegatable=true
        let _t = match CapNamespace::grant("/net/bind", &[], &format!("{}", child.as_u64()), None, true) {
            ExoValue::Capability(cap) => cap.id,
            other => panic!("grant failed: {:?}", other),
        };

        // Child re-grants to grand
        _guard = set_current_subject(child);
        let res = CapNamespace::grant("/net/bind", &[], &format!("{}", grand.as_u64()), None, false);
        match res {
            ExoValue::Capability(cap) => {
                assert!(manager().has_capability(grand.as_u64(), CAP_NET_BIND));
            }
            other => panic!("regrant failed: {:?}", other),
        }
    }

    #[test_case]
    fn test_delegation_denies_regrant_when_not_delegatable() {
        let parent = DomainId::new(150);
        let mut _guard = set_current_subject(parent);
        manager().set_capabilities(parent.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

        let child = DomainId::new(151);
        let grand = DomainId::new(152);

        // Parent grants to child with delegatable=false
        let _t = match CapNamespace::grant("/net/bind", &[], &format!("{}", child.as_u64()), None, false) {
            ExoValue::Capability(cap) => cap.id,
            other => panic!("grant failed: {:?}", other),
        };

        // Child tries to re-grant to grand and should fail
        _guard = set_current_subject(child);
        match CapNamespace::grant("/net/bind", &[], &format!("{}", grand.as_u64()), None, false) {
            ExoValue::Error(_) => {}
            other => panic!("Expected regrant to fail, got {:?}", other),
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
        _caps: &'a crate::security::CapabilitySet,
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

                    // Parse optional arguments after target: expires (int) and delegatable (bool)
                    // Or accept a Map with keys "expires" and "delegatable"
                    let mut expires: Option<u64> = None;
                    let mut delegatable: bool = false;
                    if args.len() > 3 {
                        if let Some(v) = args.get(3) {
                            match v {
                                ExoValue::Int(n) => expires = Some(*n as u64),
                                ExoValue::Bool(b) => delegatable = *b,
                                ExoValue::Map(map) => {
                                    if let Some(e) = map.get("expires") {
                                        if let ExoValue::Int(n) = e {
                                            expires = Some(*n as u64);
                                        }
                                    }
                                    if let Some(d) = map.get("delegatable") {
                                        if let ExoValue::Bool(b) = d {
                                            delegatable = *b;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    // Also accept delegatable as 4th argument if present
                    if args.len() > 4 {
                        if let Some(ExoValue::Bool(b)) = args.get(4) {
                            delegatable = *b;
                        }
                    }

                    Self::grant(resource, &ops, target.as_str(), expires, delegatable)
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
                "tokens" => {
                    // Optional domain id as first arg
                    let domain = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as u64),
                            ExoValue::String(s) => s.parse().ok(),
                            _ => None,
                        });
                    Self::tokens(domain)
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
                    "Unknown method 'cap.{}'\nValid methods: list, tokens, revoke, grant, check",
                    method
                )),
            }
        })
    }
}

