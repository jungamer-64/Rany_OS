// ============================================================================
// src/shell/exoshell/namespaces/shell.rs - Shell control namespace (ShellProxy)
// ============================================================================

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::ToString;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;

use super::{BoxFuture, ShellNamespace};
use crate::shell::exoshell::types::*;
use crate::security::capability::{self, CapabilitySet, capability_name, manager, CAP_SYS_ADMIN, Capability as BitCapability};
use crate::task::process::{self, ProcessId};

/// Shell namespace that provides a `spawn()` API returning a ShellProxy map
/// which can be chained with `with_cap`/`revoke`/`run` to spawn processes
/// with specific capabilities.
pub struct ShellControlNamespace;

impl ShellControlNamespace {
    /// Create a new ShellProxy map
    pub fn spawn_proxy() -> ExoValue<'static> {
        let pid = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_pid())
            .unwrap_or(0);

        let mut map = BTreeMap::new();
        map.insert(
            "__proxy_type".to_string(),
            ExoValue::String(Cow::Owned(String::from("shell_proxy"))),
        );
        map.insert("__parent".to_string(), ExoValue::Int(pid as i64));
        // requested caps: list of maps {resource, cap, expires, delegatable}
        map.insert("__requested".to_string(), ExoValue::Array(Vec::new()));

        ExoValue::Map(map)
    }

    /// Convenience spawn_with_caps: accept name and array of cap maps
    pub fn spawn_with_caps(name: &str, caps: &[ExoValue<'static>]) -> ExoValue<'static> {
        // Build a proxy map and then run
        let mut proxy = match Self::spawn_proxy() {
            ExoValue::Map(m) => m,
            _ => return ExoValue::Error(String::from("Internal error creating proxy")),
        };

        // push requested caps
        let reqs = proxy.remove("__requested").unwrap_or(ExoValue::Array(Vec::new()));
        let mut arr = match reqs {
            ExoValue::Array(a) => a,
            _ => Vec::new(),
        };

        for c in caps {
            arr.push(c.clone());
        }

        proxy.insert("__requested".to_string(), ExoValue::Array(arr));
        // return the proxy map; caller can call `run` on it.
        ExoValue::Map(proxy)
    }

    /// Internal: handle proxy method dispatch (called from shell.apply_map_method)
    pub(crate) fn proxy_dispatch(
        mut m: BTreeMap<String, ExoValue<'static>>,
        method: &str,
        args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        match method {
            "with_cap" => {
                // args: resource (string), optional options (map/int/bool)
                let resource = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.as_ref()),
                        _ => None,
                    })
                    .unwrap_or("");
                if resource.is_empty() {
                    return ExoValue::Error(String::from(
                        "with_cap(resource, [options]) requires a resource string",
                    ));
                }

                // resolve resource -> cap bit
                let cap_bit = crate::security::capability::resource_to_capability(resource);
                if cap_bit == 0 {
                    return ExoValue::Error(format!("Unknown resource: {}", resource));
                }

                // parse options
                let mut expires: Option<u64> = None;
                let mut delegatable: bool = false;

                if let Some(v) = args.get(1) {
                    match v {
                        ExoValue::Int(n) => expires = Some(*n as u64),
                        ExoValue::Bool(b) => delegatable = *b,
                        ExoValue::Map(mapopts) => {
                            if let Some(e) = mapopts.get("expires") {
                                if let ExoValue::Int(n) = e { expires = Some(*n as u64); }
                            }
                            if let Some(d) = mapopts.get("delegatable") {
                                if let ExoValue::Bool(b) = d { delegatable = *b; }
                            }
                        }
                        _ => {}
                    }
                }

                // permission check: parent must be issuer or sysadmin or permitted
                let parent = match m.get("__parent") {
                    Some(ExoValue::Int(n)) => *n as u64,
                    _ => return ExoValue::Error(String::from("Invalid proxy parent")),
                };

                let caller_caps = crate::security::capability::manager().get_capabilities(parent);
                let mut allowed = false;
                if crate::security::capability::manager().has_capability(parent, crate::security::capability::CAP_SYS_ADMIN) {
                    allowed = true;
                } else if caller_caps.is_permitted(cap_bit) {
                    allowed = true;
                } else {
                    let grants = crate::security::capability::manager().list_grants(parent);
                    if grants.iter().any(|t| t.cap == cap_bit && t.delegatable) {
                        allowed = true;
                    }
                }

                if !allowed {
                    return ExoValue::Error(String::from("Permission denied: parent cannot grant this capability"));
                }

                // append to __requested
                let reqs = m.remove("__requested").unwrap_or(ExoValue::Array(Vec::new()));
                let mut arr = match reqs {
                    ExoValue::Array(a) => a,
                    _ => Vec::new(),
                };

                let mut entry = BTreeMap::new();
                entry.insert("resource".to_string(), ExoValue::String(Cow::Owned(resource.to_string())));
                entry.insert("cap".to_string(), ExoValue::Int(cap_bit as i64));
                if let Some(e) = expires { entry.insert("expires".to_string(), ExoValue::Int(e as i64)); }
                entry.insert("delegatable".to_string(), ExoValue::Bool(delegatable));

                arr.push(ExoValue::Map(entry));
                m.insert("__requested".to_string(), ExoValue::Array(arr));
                ExoValue::Map(m)
            }

            "revoke" => {
                // remove requested cap by resource string or cap number
                let target = args.first();
                let mut reqs = match m.remove("__requested") {
                    Some(ExoValue::Array(a)) => a,
                    _ => Vec::new(),
                };

                if let Some(targ) = target {
                    reqs.retain(|item| {
                        match (item, targ) {
                            (ExoValue::Map(map), ExoValue::String(s)) => {
                                let res = map.get("resource").and_then(|v| v.as_str());
                                res.map(|r| r != s.as_ref()).unwrap_or(true)
                            }
                            (ExoValue::Map(map), ExoValue::Int(n)) => {
                                let cap = map.get("cap").and_then(|v| v.as_int()).unwrap_or(-1);
                                cap != *n
                            }
                            _ => true,
                        }
                    });
                } else {
                    // no arg = clear all
                    reqs.clear();
                }

                m.insert("__requested".to_string(), ExoValue::Array(reqs));
                ExoValue::Map(m)
            }

            "list_caps" | "requested_caps" => {
                let reqs = match m.get("__requested") {
                    Some(ExoValue::Array(a)) => a.clone(),
                    _ => Vec::new(),
                };
                // Convert to Capability list
                let mut out: Vec<ExoValue<'static>> = Vec::new();
                for r in reqs {
                    if let ExoValue::Map(map) = r {
                        let cap = map.get("cap").and_then(|v| v.as_int()).unwrap_or(0) as u64;
                        let resource = map.get("resource").and_then(|v| v.as_str()).unwrap_or("");
                        let expires = map.get("expires").and_then(|v| v.as_int()).map(|n| n as u64);
                        let delegatable = map.get("delegatable").and_then(|v| match v { ExoValue::Bool(b) => Some(*b), _ => None }).unwrap_or(false);
                        let c = Capability {
                            id: cap,
                            resource: resource.to_string(),
                            operations: Vec::new(),
                            issuer: format!("domain:{}", m.get("__parent").and_then(|v| v.as_int()).unwrap_or(0)),
                            expires,
                            delegatable,
                        };
                        out.push(ExoValue::Capability(c));
                    }
                }
                ExoValue::Array(out)
            }

            "run" => {
                // run(name) -> spawn a child process and apply requested caps
                let name = args
                    .first()
                    .and_then(|v| match v {
                        ExoValue::String(s) => Some(s.as_ref()),
                        _ => None,
                    })
                    .unwrap_or("");
                if name.is_empty() {
                    return ExoValue::Error(String::from("run(name) requires process name"));
                }

                let parent = match m.get("__parent") {
                    Some(ExoValue::Int(n)) => *n as u64,
                    _ => return ExoValue::Error(String::from("Invalid proxy parent")),
                };

                let cur = kernel_api::services::kernel().shell().map(|s| s.current_pid()).unwrap_or(0);
                if cur != parent && !crate::security::capability::manager().has_capability(cur, crate::security::capability::CAP_SYS_ADMIN) {
                    return ExoValue::Error(String::from("Permission denied: must be proxy owner or CAP_SYS_ADMIN"));
                }

                // Build requested cap list
                let reqs = match m.get("__requested") {
                    Some(ExoValue::Array(a)) => a.clone(),
                    _ => Vec::new(),
                };

                let mut requested_caps: Vec<crate::task::process::RequestedCap> = Vec::new();
                for r in reqs {
                    if let ExoValue::Map(map) = r {
                        let cap = map.get("cap").and_then(|v| v.as_int()).unwrap_or(0) as u64;
                        let expires = map.get("expires").and_then(|v| v.as_int()).map(|n| n as u64);
                        let delegatable = map.get("delegatable").and_then(|v| match v { ExoValue::Bool(b) => Some(*b), _ => None }).unwrap_or(false);
                        requested_caps.push(crate::task::process::RequestedCap{ cap, expires, delegatable });
                    }
                }

                // Spawn child with caps via process API
                match crate::task::process::spawn_with_caps(name, &requested_caps) {
                    Ok((child, tokens_vec)) => {
                        let tokens = tokens_vec.into_iter().map(|t| ExoValue::Int(t as i64)).collect();
                        let mut res = BTreeMap::new();
                        res.insert("pid".to_string(), ExoValue::Int(child.as_u64() as i64));
                        res.insert("tokens".to_string(), ExoValue::Array(tokens));
                        return ExoValue::Map(res);
                    }
                    Err(e) => return ExoValue::Error(format!("spawn_with_caps failed: {:?}", e)),
                }
            }

            _ => ExoValue::Error(format!("Shell proxy does not have method '{}'", method)),
        }
    }
}
impl ShellNamespace for ShellControlNamespace {
    fn name(&self) -> &str {
        "shell"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        _caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "spawn" => Self::spawn_proxy(),
                "spawn_with_caps" => {
                    let name = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::String(s) => Some(s.as_ref()),
                            _ => None,
                        })
                        .unwrap_or("");
                    if name.is_empty() {
                        return ExoValue::Error(String::from("spawn_with_caps(name, caps) requires a name"));
                    }
                    let caps_arr = args.get(1).and_then(|v| match v {
                        ExoValue::Array(arr) => Some(arr.as_slice()),
                        _ => None,
                    }).unwrap_or(&[]);
                    Self::spawn_with_caps(name, caps_arr)
                }
                _ => ExoValue::Error(format!("Unknown method 'shell.{}'\nValid methods: spawn, spawn_with_caps", method)),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::process::{process_manager, ProcessId, set_current_process};
    use crate::security::capability::{manager, CapabilitySet, CAP_NET_BIND};

    #[test]
    fn test_spawn_proxy_basic() {
        let caller = process_manager().create(ProcessId::INIT, "p").unwrap();
        set_current_process(caller);

        match ShellControlNamespace::spawn_proxy() {
            ExoValue::Map(m) => {
                assert!(m.contains_key("__proxy_type"));
                assert!(m.contains_key("__parent"));
                assert!(m.contains_key("__requested"));
            }
            other => panic!("Expected proxy map, got {:?}", other),
        }
    }

    #[test]
    fn test_spawn_with_caps_helper() {
        let caller = process_manager().create(ProcessId::INIT, "caller").unwrap();
        set_current_process(caller);
        manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

        // Create caps array for spawn_with_caps
        let cap_map = {
            let mut m = BTreeMap::new();
            m.insert("resource".to_string(), ExoValue::String(Cow::Owned("/net/bind".to_string())));
            m.insert("expires".to_string(), ExoValue::Int(0));
            ExoValue::Map(m)
        };

        let res = ShellControlNamespace::spawn_with_caps("child", &[cap_map]);
        match res {
            ExoValue::Map(_) => {}
            _ => panic!("spawn_with_caps returned unexpected value: {:?}", res),
        }
    }

    #[test]
    fn test_proxy_chain_with_cap_and_run() {
        let caller = process_manager().create(ProcessId::INIT, "caller_chain").unwrap();
        set_current_process(caller);
        manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

        // spawn proxy
        let proxy = match ShellControlNamespace::spawn_proxy() {
            ExoValue::Map(m) => m,
            other => panic!("spawn_proxy failed: {:?}", other),
        };

        // with_cap
        let res = ShellControlNamespace::proxy_dispatch(proxy, "with_cap", &[
            ExoValue::String(Cow::Owned("/net/bind".to_string())),
        ]);

        let proxy2 = match res {
            ExoValue::Map(m) => m,
            other => panic!("with_cap failed: {:?}", other),
        };

        // run
        let run_res = ShellControlNamespace::proxy_dispatch(proxy2, "run", &[
            ExoValue::String(Cow::Owned("child_chain".to_string())),
        ]);

        match run_res {
            ExoValue::Map(m) => {
                let pid = m.get("pid").and_then(|v| match v { ExoValue::Int(n) => Some(*n as u64), _ => None }).unwrap();
                // token present
                let tokens = m.get("tokens").and_then(|v| match v { ExoValue::Array(a) => Some(a.clone()), _ => None }).unwrap();
                assert!(!tokens.is_empty());
                // child has cap
                assert!(manager().has_capability(pid, CAP_NET_BIND));
            }
            other => panic!("run failed: {:?}", other),
        }
    }
}
