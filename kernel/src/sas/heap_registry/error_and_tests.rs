/// レジストリエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    AlreadyRegistered,
    NotFound,
    PermissionDenied,
    Overlapping,
}

// ============================================================================
// Tests / Micro-benchmarks
// ============================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::sas::{DomainId, HeapRegistry};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use crate::sync::poison_lock::{get_lock_metrics, reset_lock_metrics};

    /// Measurement sweep for HeapRegistry: varies shard count and thread counts
    /// and prints CSV-style metrics for analysis. This test is intentionally
    /// placed under the `tests` module so it can reuse the `reset/get` imports.
    #[test_case]
    pub(super) fn test_heap_registry_shard_sweep() {
        let configs = [
            (32usize, 8usize, 200usize, 50u64),
            (16usize, 16usize, 300usize, 100u64),
            (8usize, 32usize, 300usize, 200u64),
            (4usize, 64usize, 150usize, 500u64),
        ];

        println!("shards,threads,ops,hold_us,acq_count,contention,avg_acq_ticks,object_count");

        for (shard_count, num_threads, ops, hold_us) in configs.iter().cloned() {
            reset_lock_metrics();

            let registry = std::sync::Arc::new(HeapRegistry::new(shard_count));

            // address pool distributed across shards
            let addresses_per_shard = 16usize;
            let mut pool = Vec::new();
            for s in 0..shard_count {
                for i in 0..addresses_per_shard {
                    let addr = (s << 4) + i * (shard_count << 4);
                    pool.push(addr);
                }
            }
            let pool = std::sync::Arc::new(pool);

            let mut handles = Vec::new();
            for t in 0..num_threads {
                let reg = std::sync::Arc::clone(&registry);
                let pool = std::sync::Arc::clone(&pool);
                let handle = std::thread::spawn(move || {
                    let owner = DomainId::new((t + 1) as u64);
                    for i in 0..ops {
                        let addr = pool[(i + t) % pool.len()];
                        match reg.register(addr, 64, owner, 0) {
                            Ok(_) => {
                                let _ = reg.unregister(addr, owner);
                            }
                            Err(_) => {
                                let _ = reg.check_access(addr, owner);
                            }
                        }
                        if hold_us > 0 {
                            std::thread::sleep(std::time::Duration::from_micros(hold_us));
                        }
                    }
                });
                handles.push(handle);
            }

            for h in handles {
                h.join().unwrap();
            }

            let m = get_lock_metrics();
            println!(
                "{},{},{},{},{},{},{},{}",
                shard_count,
                num_threads,
                ops,
                hold_us,
                m.acquire_count,
                m.contention_events,
                m.average_acquire_ticks,
                registry.object_count(),
            );
        }
    }

    /// 簡易コンテンションテスト：1スレッドがシャードを長時間保持し、別スレッドが同シャードにアクセスする。
    /// PoisonLock の計測 (コンテンション検知) が記録されることを確認する。
    #[test_case]
    pub(super) fn test_shard_lock_contention() {
        // テスト用に計測値をリセット
        reset_lock_metrics();

        let registry = Arc::new(HeapRegistry::default());
        let shard_idx = core::cmp::min(3usize, registry.shards.len() - 1);

        // 長時間ロックを保持するスレッド
        let r1 = Arc::clone(&registry);
        let t1 = thread::spawn(move || {
            let _g = r1.shards[shard_idx].lock().unwrap();
            thread::sleep(Duration::from_millis(200));
        });

        // 少し待ってから別スレッドで同シャードにアクセスさせる（コンテンションを発生させる）
        thread::sleep(Duration::from_millis(10));

        let r2 = Arc::clone(&registry);
        let t2 = thread::spawn(move || {
            let addr = (shard_idx << 4) + 0usize;
            let owner = DomainId::new(1);
            // 登録操作はシャードロックを取るため、ここでスピンが発生するはず
            let _ = r2.register(addr, 64, owner, 0);
        });

        t2.join().unwrap();
        t1.join().unwrap();

        let m = get_lock_metrics();
        assert!(
            m.acquire_count >= 1,
            "expected at least one lock acquisition"
        );
        assert!(
            m.contention_events >= 1,
            "expected at least one contention event"
        );
    }

    /// マルチスレッド負荷テスト：複数スレッドで同一または近傍シャードに対して登録/解除を繰り返す。
    /// 実行時間が長くなりすぎないように控えめなループ回数を採用。
    #[test_case]
    pub(super) fn test_heap_registry_multithreaded_stress() {
        reset_lock_metrics();

        let registry = Arc::new(HeapRegistry::default());
        let num_threads = 8;
        // Increase ops to make contention more likely and reduce test flakiness
        let ops_per_thread = 2000usize;
        let shard_ids = [0usize, 1usize];
        let addresses_per_shard = 16usize;

        // アドレスプール（各アドレスは同一シャードにハッシュされるように算出）
        let shard_count = registry.shards.len();
        let mut pool: Vec<usize> = Vec::new();
        for &s_orig in &shard_ids {
            let s = s_orig % shard_count;
            for i in 0..addresses_per_shard {
                let addr = (s << 4) + i * (shard_count << 4);
                pool.push(addr);
            }
        }
        let pool = Arc::new(pool);

        let mut handles = Vec::new();
        for t in 0..num_threads {
            let reg = Arc::clone(&registry);
            let pool = Arc::clone(&pool);
            let handle = thread::spawn(move || {
                let owner = DomainId::new((t + 1) as u64);
                for i in 0..ops_per_thread {
                    let addr = pool[(i + t) % pool.len()];
                    match reg.register(addr, 64, owner, 0) {
                        Ok(_) => {
                            let _ = reg.unregister(addr, owner);
                        }
                        Err(_) => {
                            let _ = reg.check_access(addr, owner);
                        }
                    }
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let m = get_lock_metrics();
        // 少なくともいくつかのロック獲得とコンテンションが発生していることを期待
        assert!(m.acquire_count > 0, "expected some lock activity");
        assert!(m.contention_events > 0, "expected some contention events");
    }

    #[test_case]
    pub(super) fn test_register_spanning_shards() {
        reset_lock_metrics();

        let registry = HeapRegistry::new(4); // small shard count to force spanning
        let owner = DomainId::new(1);
        let addr = 0usize;
        let size = 64usize; // with 16-byte blocks and 4 shards this will cover all shards

        // Register spanning object
        let generation = registry
            .register(addr, size, owner, 0)
            .expect("register failed");
        assert!(generation > 0);

        // Mid-range access should resolve to owner
        assert!(registry.check_access(addr + 32, owner));
        assert_eq!(registry.get_owner(addr + 32), Some(owner));

        // Object should appear in every shard
        for s in 0..registry.shards.len() {
            let g = registry.shards[s].lock().unwrap();
            assert!(g.objects.contains_key(&addr));
        }

        // Transfer ownership and validate across shards
        registry
            .transfer_ownership(addr, owner, DomainId::new(2))
            .expect("transfer failed");
        assert_eq!(registry.get_owner(addr + 1), Some(DomainId::new(2)));

        // Unregister should remove object from all shards
        registry
            .unregister(addr, DomainId::new(2))
            .expect("unregister failed");
        assert_eq!(registry.object_count(), 0);
        assert!(!registry.check_access(addr, DomainId::new(2)));
    }

    #[test_case]
    pub(super) fn test_overlapping_detection_across_shards() {
        let registry = HeapRegistry::new(4);
        let owner = DomainId::new(1);

        // Register large object
        registry.register(0, 64, owner, 0).unwrap();

        // Attempt to register overlapping object at offset 48 (overlaps)
        match registry.register(48, 16, DomainId::new(2), 0) {
            Err(RegistryError::Overlapping) => {}
            _ => panic!("expected overlap error"),
        }
    }

    #[test_case]
    pub(super) fn test_shard_node_mapping() {
        let shards = 8usize;
        let registry = HeapRegistry::new(shards);
        assert_eq!(registry.shards.len(), shards);
        // num_nodes() in test harness is 1, so all shards should be Some(0)
        for i in 0..shards {
            assert_eq!(registry.shard_node(i), Some(0));
        }

        // In lib-test builds the domain NUMA query may be unavailable; ensure
        // the API returns an empty set in that case.
        let preferred = registry.preferred_shards_for_owner(DomainId::new(1));
        // When domain NUMA info is not available, we expect an empty vector
        assert_eq!(preferred.len(), 0usize);
    }

    #[test_case]
    pub(super) fn test_register_poisoned_returns_permission_denied() {
        let registry = HeapRegistry::new(4);
        let owner = DomainId::new(1);
        // Poison primary shard
        {
            let _guard = registry.shards[0].lock().unwrap();
            crate::sync::set_panicking(true);
        }
        crate::sync::set_panicking(false);
        assert_eq!(
            registry.register(0x1000, 64, owner, 0),
            Err(RegistryError::PermissionDenied)
        );
    }

    #[test_case]
    pub(super) fn test_unregister_poisoned_returns_permission_denied() {
        let registry = HeapRegistry::new(4);
        let owner = DomainId::new(1);
        let addr = 0x1000usize;
        registry
            .register(addr, 64, owner, 0)
            .expect("register failed");
        {
            let _guard = registry.shards[0].lock().unwrap();
            crate::sync::set_panicking(true);
        }
        crate::sync::set_panicking(false);
        assert_eq!(
            registry.unregister(addr, owner),
            Err(RegistryError::PermissionDenied)
        );
    }

    #[test_case]
    pub(super) fn test_transfer_poisoned_returns_permission_denied() {
        let registry = HeapRegistry::new(4);
        let owner = DomainId::new(1);
        let addr = 0x1000usize;
        registry
            .register(addr, 64, owner, 0)
            .expect("register failed");
        {
            let _guard = registry.shards[0].lock().unwrap();
            crate::sync::set_panicking(true);
        }
        crate::sync::set_panicking(false);
        assert_eq!(
            registry.transfer_ownership(addr, owner, DomainId::new(2)),
            Err(RegistryError::PermissionDenied)
        );
    }

    #[test_case]
    pub(super) fn test_get_owner_poisoned_returns_none() {
        let registry = HeapRegistry::new(4);
        let owner = DomainId::new(1);
        let addr = 0x2000usize;
        registry
            .register(addr, 64, owner, 0)
            .expect("register failed");
        {
            let _guard = registry.shards[registry.get_shard_index(addr)]
                .lock()
                .unwrap();
            crate::sync::set_panicking(true);
        }
        crate::sync::set_panicking(false);
        assert_eq!(registry.get_owner(addr), None);
    }

    #[test_case]
    pub(super) fn test_check_access_poisoned_returns_false() {
        let registry = HeapRegistry::new(4);
        let owner = DomainId::new(1);
        let addr = 0x2000usize;
        registry
            .register(addr, 64, owner, 0)
            .expect("register failed");
        {
            let _guard = registry.shards[registry.get_shard_index(addr)]
                .lock()
                .unwrap();
            crate::sync::set_panicking(true);
        }
        crate::sync::set_panicking(false);
        assert!(!registry.check_access(addr, owner));
    }

    #[test_case]
    pub(super) fn test_unregister_any_poisoned_returns_none() {
        let registry = HeapRegistry::new(4);
        let owner = DomainId::new(1);
        let addr = 0x1000usize;
        registry
            .register(addr, 64, owner, 0)
            .expect("register failed");
        {
            let _guard = registry.shards[0].lock().unwrap();
            crate::sync::set_panicking(true);
        }
        crate::sync::set_panicking(false);
        assert_eq!(registry.unregister_any(addr), None);
    }
}
