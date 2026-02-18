#![no_std]
//! CapabilitySetテストハーネス
//!
//! QEMUテスト用の簡略版CapabilitySet。
//! 正規版: `libs/security/src/lib.rs`

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub type Capability = u64;

// Capability bit constants (subset of kernel's values)
pub const CAP_NET_BIND: Capability = 1 << 0;
pub const CAP_NET_RAW: Capability = 1 << 1;
pub const CAP_NET_ADMIN: Capability = 1 << 2;
pub const CAP_SYS_ADMIN: Capability = 1 << 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapOperation {
    Read,
    Write,
    Execute,
    Delete,
    Grant,
    Revoke,
    Create,
    List,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityItem {
    pub id: Capability,
    pub resource: String,
    pub operations: Vec<CapOperation>,
    pub issuer: String,
    pub expires: Option<u64>,
    pub delegatable: bool,
}

#[derive(Clone, Debug, Default)]
pub struct CapabilitySet {
    pub permitted: Capability,
    pub effective: Capability,
}

impl CapabilitySet {
    pub fn empty() -> Self {
        Self {
            permitted: 0,
            effective: 0,
        }
    }

    pub fn with_permitted(bit: Capability) -> Self {
        Self {
            permitted: bit,
            effective: 0,
        }
    }

    pub fn is_permitted(&self, bit: Capability) -> bool {
        (self.permitted & bit) != 0
    }

    pub fn has_capability(&self, bit: Capability) -> bool {
        (self.effective & bit) != 0
    }

    /// Raise the effective capability if permitted
    pub fn raise(&mut self, bit: Capability) -> Result<(), &'static str> {
        if self.is_permitted(bit) {
            self.effective |= bit;
            Ok(())
        } else {
            Err("not permitted")
        }
    }

    pub fn drop(&mut self, bit: Capability) {
        self.effective &= !bit;
    }

    pub fn drop_permanently(&mut self, bit: Capability) {
        self.permitted &= !bit;
        self.effective &= !bit;
    }
}

#[derive(Default, Debug)]
pub struct Manager {
    map: BTreeMap<u64, CapabilitySet>,
}

impl Manager {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    pub fn get_capabilities(&self, domain: u64) -> CapabilitySet {
        self.map.get(&domain).cloned().unwrap_or_default()
    }

    pub fn set_capabilities(&mut self, domain: u64, caps: CapabilitySet) {
        self.map.insert(domain, caps);
    }

    pub fn has_capability(&self, domain: u64, bit: Capability) -> bool {
        self.get_capabilities(domain).has_capability(bit)
    }
}

fn resource_to_capability(resource: &str) -> Capability {
    match resource {
        "/net/bind" => CAP_NET_BIND,
        "/net/raw" => CAP_NET_RAW,
        "/net/admin" => CAP_NET_ADMIN,
        _ if resource.starts_with("/") => 0,
        _ => 0,
    }
}

pub fn grant(
    manager: &mut Manager,
    caller_pid: u64,
    resource: &str,
    _ops: &[CapOperation],
    target_domain: u64,
) -> Result<CapabilityItem, String> {
    // parse target domain id provided by caller (already u64)

    let cap_bit = resource_to_capability(resource);
    if cap_bit == 0 {
        return Err(format!("Unknown resource: {}", resource));
    }

    // check caller permissions: must be CAP_SYS_ADMIN or have the capability permitted
    let caller_caps = manager.get_capabilities(caller_pid);
    if !manager.has_capability(caller_pid, CAP_SYS_ADMIN) && !caller_caps.is_permitted(cap_bit) {
        return Err(String::from(
            "Permission denied: insufficient capability to grant this resource",
        ));
    }

    let mut caps = manager.get_capabilities(target_domain);

    // permitted OR= cap_bit
    caps.permitted |= cap_bit;

    if caps.raise(cap_bit).is_err() {
        return Err(String::from("Failed to grant: raise failed"));
    }

    manager.set_capabilities(target_domain, caps.clone());

    let cap = CapabilityItem {
        id: cap_bit,
        resource: resource.to_string(),
        operations: _ops.to_vec(),
        issuer: format!("domain:{}", caller_pid),
        expires: None,
        delegatable: caller_caps.is_permitted(cap_bit),
    };

    Ok(cap)
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn grant_requires_permissions_smoke() -> bool {
        let mut manager = Manager::new();
        let caller = 1u64;
        // caller has no capabilities
        manager.set_capabilities(caller, CapabilitySet::empty());

        let target = 2u64;
        grant(&mut manager, caller, "/net/bind", &[], target).is_err()
    }

    pub fn grant_with_permitted_smoke() -> bool {
        let mut manager = Manager::new();
        let caller = 3u64;
        manager.set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

        let target = 4u64;
        let res = grant(&mut manager, caller, "/net/bind", &[], target);
        if res.is_err() { return false; }
        let cap = res.unwrap();
        if cap.resource != "/net/bind" { return false; }
        manager.has_capability(target, CAP_NET_BIND)
    }
}
