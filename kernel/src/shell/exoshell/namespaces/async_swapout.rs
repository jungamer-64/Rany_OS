use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;

use super::{BoxFuture, ShellNamespace};
use crate::security::capability::CAP_SYS_ADMIN;
use crate::shell::exoshell::types::ExoValue;

pub struct AsyncSwapoutNamespace;

impl AsyncSwapoutNamespace {
    pub fn status() -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        let (total, file_q) = crate::mm::reclaim::async_swapout::queued_counts();
        map.insert(String::from("queue_total"), ExoValue::Int(total as i64));
        map.insert(String::from("file_queue"), ExoValue::Int(file_q as i64));
        map.insert(
            String::from("token_count"),
            ExoValue::Int(crate::mm::reclaim::async_swapout::token_count() as i64),
        );
        map.insert(
            String::from("token_bucket_capacity"),
            ExoValue::Int(crate::mm::reclaim::async_swapout::token_bucket_capacity() as i64),
        );
        map.insert(
            String::from("token_refill_per_batch"),
            ExoValue::Int(crate::mm::reclaim::async_swapout::token_refill_per_batch() as i64),
        );
        map.insert(
            String::from("reserved_file_slots"),
            ExoValue::Int(crate::mm::reclaim::async_swapout::reserved_file_slots() as i64),
        );
        map.insert(
            String::from("worker_running"),
            ExoValue::Bool(crate::mm::reclaim::async_swapout::is_worker_running()),
        );

        // Expose ZSWAP / async dealloc metrics
        map.insert(
            String::from("zswap_fail_count"),
            ExoValue::Int(crate::mm::reclaim::async_swapout::stats_zswap_fail_count() as i64),
        );
        map.insert(
            String::from("async_dealloc_count"),
            ExoValue::Int(crate::mm::reclaim::async_swapout::stats_async_dealloc_count() as i64),
        );
        // Huge-page related metrics (2MiB)
        map.insert(
            String::from("huge_2m_skipped"),
            ExoValue::Int(crate::mm::reclaim::async_swapout::stats_huge_2m_skip_count() as i64),
        );

        // Buffer pool stats for 4K, 2M, 1G
        let (h4k, m4k, o4k) = crate::mm::reclaim::async_swapout::buffer_pool_4k_stats();
        let mut p4k = BTreeMap::new();
        p4k.insert(String::from("hits"), ExoValue::Int(h4k as i64));
        p4k.insert(String::from("misses"), ExoValue::Int(m4k as i64));
        p4k.insert(String::from("occupancy"), ExoValue::Int(o4k as i64));
        map.insert(String::from("buffer_pool_4k"), ExoValue::Map(p4k));

        let (h2m, m2m, o2m) = crate::mm::reclaim::async_swapout::buffer_pool_2m_stats();
        let mut p2m = BTreeMap::new();
        p2m.insert(String::from("hits"), ExoValue::Int(h2m as i64));
        p2m.insert(String::from("misses"), ExoValue::Int(m2m as i64));
        p2m.insert(String::from("occupancy"), ExoValue::Int(o2m as i64));
        map.insert(String::from("buffer_pool_2m"), ExoValue::Map(p2m));

        let (h1g, m1g, o1g) = crate::mm::reclaim::async_swapout::buffer_pool_1g_stats();
        let mut p1g = BTreeMap::new();
        p1g.insert(String::from("hits"), ExoValue::Int(h1g as i64));
        p1g.insert(String::from("misses"), ExoValue::Int(m1g as i64));
        p1g.insert(String::from("occupancy"), ExoValue::Int(o1g as i64));
        map.insert(String::from("buffer_pool_1g"), ExoValue::Map(p1g));

        ExoValue::Map(map)
    }

    fn set_with_caps(
        token_capacity: Option<i64>,
        refill: Option<i64>,
        reserved: Option<i64>,
        caps: &crate::security::CapabilitySet,
    ) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_ADMIN required"));
        }

        if let Some(tc) = token_capacity {
            if tc < 0 {
                return ExoValue::Error(String::from("token_capacity must be >= 0"));
            }
            crate::mm::reclaim::async_swapout::set_token_bucket_capacity(tc as usize);
        }
        if let Some(rf) = refill {
            if rf < 0 {
                return ExoValue::Error(String::from("refill must be >= 0"));
            }
            crate::mm::reclaim::async_swapout::set_token_refill_per_batch(rf as usize);
        }
        if let Some(rs) = reserved {
            if rs < 0 {
                return ExoValue::Error(String::from("reserved must be >= 0"));
            }
            crate::mm::reclaim::async_swapout::set_reserved_file_slots(rs as usize);
        }

        ExoValue::Bool(true)
    }
}

impl ShellNamespace for AsyncSwapoutNamespace {
    fn name(&self) -> &str {
        "async_swapout"
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
                    // args: token_capacity (int | omit), refill (int | omit), reserved (int | omit)
                    let token_capacity = args.get(0).and_then(|v| v.as_int());
                    let refill = args.get(1).and_then(|v| v.as_int());
                    let reserved = args.get(2).and_then(|v| v.as_int());
                    Self::set_with_caps(token_capacity, refill, reserved, caps)
                }
                _ => ExoValue::Error(format!(
                    "Unknown method 'async_swapout.{}'. Valid: status,get,set",
                    method
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::CapabilitySet;
    use crate::shell::exoshell::types::ExoValue;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_status_contains_expected_keys() {
        let val = AsyncSwapoutNamespace::status();
        match val {
            ExoValue::Map(m) => {
                assert!(m.contains_key("token_bucket_capacity"));
                assert!(m.contains_key("token_refill_per_batch"));
                assert!(m.contains_key("reserved_file_slots"));
                assert!(m.contains_key("queue_total"));
            }
            _ => panic!("expected map"),
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_set_requires_cap() {
        let ns = AsyncSwapoutNamespace;
        let caps = CapabilitySet::empty();
        // call set without admin cap
        let fut = ns.call("set", &[], &caps);
        let res = futures::executor::block_on(fut);
        match res {
            ExoValue::Error(s) => assert!(s.contains("Permission denied")),
            _ => panic!("expected permission error"),
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_set_with_admin() {
        let ns = AsyncSwapoutNamespace;
        let caps = CapabilitySet::full();
        // call set with admin cap
        let args = [ExoValue::Int(32), ExoValue::Int(4), ExoValue::Int(128)];
        let fut = ns.call("set", &args, &caps);
        let res = futures::executor::block_on(fut);
        match res {
            ExoValue::Bool(b) => assert!(b),
            _ => panic!("expected true"),
        }
    }
}
