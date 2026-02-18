use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::security::capability::CAP_SYS_ADMIN;
use crate::shell::exoshell::types::ExoValue;

pub struct ReclaimNamespace;

impl ReclaimNamespace {
    fn to_bool(v: &ExoValue<'static>) -> Option<bool> {
        match v {
            ExoValue::Bool(b) => Some(*b),
            ExoValue::Int(i) => Some(*i != 0),
            _ => None,
        }
    }

    pub fn status() -> ExoValue<'static> {
        let stats = crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.stats();
        let mut map = BTreeMap::new();

        map.insert(
            String::from("unsafe_eviction_enabled"),
            ExoValue::Bool(stats.unsafe_eviction_enabled),
        );
        map.insert(
            String::from("pending_async"),
            ExoValue::Int(stats.pending_async as i64),
        );
        map.insert(
            String::from("direct_reclaim_count"),
            ExoValue::Int(stats.direct_reclaim_count as i64),
        );
        map.insert(
            String::from("background_reclaim_count"),
            ExoValue::Int(stats.background_reclaim_count as i64),
        );
        map.insert(
            String::from("total_reclaimed"),
            // Includes both synchronous reclaim and async swapout/writeback success.
            ExoValue::Int(stats.total_reclaimed as i64),
        );
        map.insert(
            String::from("writeback_skipped"),
            ExoValue::Int(stats.writeback_skipped as i64),
        );
        map.insert(
            String::from("async_enqueued"),
            ExoValue::Int(stats.async_enqueued as i64),
        );
        map.insert(
            String::from("async_success"),
            ExoValue::Int(stats.async_success as i64),
        );
        map.insert(
            String::from("async_fail"),
            ExoValue::Int(stats.async_fail as i64),
        );
        map.insert(String::from("requeued"), ExoValue::Int(stats.requeued as i64));
        map.insert(
            String::from("blocked_unsafe"),
            ExoValue::Int(stats.blocked_unsafe as i64),
        );

        let mut lru_stats = Vec::new();
        for (node, s) in stats.lru_stats.iter().enumerate() {
            let mut node_map = BTreeMap::new();
            node_map.insert(String::from("node"), ExoValue::Int(node as i64));
            node_map.insert(String::from("gen0"), ExoValue::Int(s.gen_sizes[0] as i64));
            node_map.insert(String::from("gen1"), ExoValue::Int(s.gen_sizes[1] as i64));
            node_map.insert(String::from("gen2"), ExoValue::Int(s.gen_sizes[2] as i64));
            node_map.insert(String::from("gen3"), ExoValue::Int(s.gen_sizes[3] as i64));
            node_map.insert(
                String::from("aging_cycles"),
                ExoValue::Int(s.aging_cycles as i64),
            );
            node_map.insert(String::from("reclaimed"), ExoValue::Int(s.reclaimed as i64));
            node_map.insert(
                String::from("rejuvenated"),
                ExoValue::Int(s.rejuvenated as i64),
            );
            lru_stats.push(ExoValue::Map(node_map));
        }
        map.insert(String::from("lru_stats"), ExoValue::Array(lru_stats));

        ExoValue::Map(map)
    }

    fn set_with_caps(
        enabled: bool,
        caps: &crate::security::CapabilitySet,
    ) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_ADMIN required"));
        }
        crate::mm::reclaim::page_reclaim::set_unsafe_eviction_enabled(enabled);
        ExoValue::Bool(true)
    }
}

impl ShellNamespace for ReclaimNamespace {
    fn name(&self) -> &str {
        "reclaim"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "status" | "get" => Self::status(),
                "set" => {
                    let Some(raw) = args.get(0) else {
                        return ExoValue::Error(String::from("set requires 1 argument (bool)"));
                    };
                    let Some(enabled) = Self::to_bool(raw) else {
                        return ExoValue::Error(String::from("set argument must be bool or int"));
                    };
                    Self::set_with_caps(enabled, caps)
                }
                _ => ExoValue::Error(format!("Unknown method 'reclaim.{}'. Valid: status,get,set", method)),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::CapabilitySet;

    #[test_case]
    fn test_status_contains_expected_keys() {
        let val = ReclaimNamespace::status();
        match val {
            ExoValue::Map(m) => {
                assert!(m.contains_key("unsafe_eviction_enabled"));
                assert!(m.contains_key("pending_async"));
                assert!(m.contains_key("total_reclaimed"));
                assert!(m.contains_key("lru_stats"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test_case]
    fn test_set_requires_cap() {
        let ns = ReclaimNamespace;
        let caps = CapabilitySet::empty();
        let args = [ExoValue::Bool(true)];
        let fut = ns.call("set", &args, &caps);
        let res = futures::executor::block_on(fut);
        match res {
            ExoValue::Error(s) => assert!(s.contains("Permission denied")),
            _ => panic!("expected permission error"),
        }
    }

    #[test_case]
    fn test_set_with_admin() {
        let ns = ReclaimNamespace;
        let caps = CapabilitySet::full();
        let args = [ExoValue::Bool(true)];
        let fut = ns.call("set", &args, &caps);
        let res = futures::executor::block_on(fut);
        match res {
            ExoValue::Bool(b) => assert!(b),
            _ => panic!("expected true"),
        }
        crate::mm::reclaim::page_reclaim::set_unsafe_eviction_enabled(false);
    }
}
