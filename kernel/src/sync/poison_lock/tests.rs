

// ============================================================================
// テスト
// ============================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    // bring types and helpers into scope when running with std feature
    use crate::sync::PoisonLock;
    use crate::sync::set_panicking;
    use crate::sync::poison_lock::{reset_lock_metrics, get_lock_metrics};
    use alloc::sync::Arc;

    #[test_case]
    pub(super) fn test_basic_lock() {
        let lock = PoisonLock::new(42);

        let guard = lock.lock().unwrap();
        assert_eq!(*guard, 42);
        drop(guard);

        assert!(!lock.is_locked());
        assert!(!lock.is_poisoned());
    }

    #[test_case]
    pub(super) fn test_poisoned_after_simulated_panic() {
        let lock = PoisonLock::new(42);

        // パニックをシミュレート
        {
            let _guard = lock.lock().unwrap();
            set_panicking(true);
        } // ドロップ時に毒入れされる
        set_panicking(false);

        assert!(lock.is_poisoned());

        // 毒入れ後のアクセス
        match lock.lock() {
            Ok(_) => panic!("Expected PoisonError"),
            Err(err) => {
                // 回復可能
                let guard = err.into_inner();
                assert_eq!(*guard, 42);
            }
        }
    }

    #[test_case]
    pub(super) fn test_lock_for_init_recovers_on_poison() {
        use crate::sync::set_panicking;

        let lock = PoisonLock::new(0usize);

        // Poison the lock by simulating a panic while holding the guard
        set_panicking(true);
        {
            let _guard = lock.lock().unwrap();
            // dropping _guard while panicking will mark the lock as poisoned
        }
        set_panicking(false);

        // Recover via lock_for_init and mutate value
        {
            let mut g = lock.lock_for_init("test_lock_for_init");
            *g = 123usize;
        }

        // Subsequent lock should reflect the updated value, either via Ok or Err with inner reference
        match lock.lock() {
            Ok(g) => assert_eq!(*g, 123usize),
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                assert_eq!(*guard, 123usize);
            }
        }
    }

    #[test_case]
    pub(super) fn test_lock_contention_metrics() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        reset_lock_metrics();

        let lock = Arc::new(PoisonLock::new(0usize));
        let l2 = Arc::clone(&lock);

        // Hold the lock in a background thread to force contention
        let th = thread::spawn(move || {
            let _g = l2.lock().unwrap();
            thread::sleep(Duration::from_millis(100));
        });

        // Give the other thread a moment to acquire the lock
        thread::sleep(Duration::from_millis(10));

        // This acquisition should experience contention
        let _guard = lock.lock().unwrap();

        th.join().unwrap();

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

    /// Sharded-style stress test that simulates a sharded registry by creating
    /// multiple `PoisonLock` instances and having many threads randomly lock
    /// them repeatedly. This approximates contention patterns seen in
    /// sharded registries without depending on the full `sas` module.
    #[test_case]
    pub(super) fn test_sharded_poisonlock_stress() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        reset_lock_metrics();

        let shard_count = 32usize;
        let mut vec = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            vec.push(Arc::new(PoisonLock::new(0usize)));
        }
        let shards = Arc::new(vec);

        let num_threads = 16usize;
        let ops = 300usize;
        let mut handles = Vec::new();

        for t in 0..num_threads {
            let shards = Arc::clone(&shards);
            let handle = thread::spawn(move || {
                for i in 0..ops {
                    let idx = (i + t) % shard_count;
                    let _g = shards[idx].lock().unwrap();
                    // occasional short hold to increase contention likelihood
                    if i % 2 == 0 {
                        thread::sleep(Duration::from_micros(50));
                    }
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let m = get_lock_metrics();
        assert!(m.acquire_count > 0, "expected some lock acquisitions");
        assert!(m.contention_events > 0, "expected some contention events");
    }

    /// Higher contention scenario: fewer shards, more threads and longer holds.
    #[test_case]
    pub(super) fn test_sharded_poisonlock_high_contention() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        reset_lock_metrics();

        let shard_count = 4usize;
        let mut vec = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            vec.push(Arc::new(PoisonLock::new(0usize)));
        }
        let shards = Arc::new(vec);

        let num_threads = 32usize;
        let ops = 200usize;
        let mut handles = Vec::new();

        for t in 0..num_threads {
            let shards = Arc::clone(&shards);
            let handle = thread::spawn(move || {
                for i in 0..ops {
                    let idx = (i + t) % shard_count;
                    let _g = shards[idx].lock().unwrap();
                    // hold slightly longer to force spins on other threads
                    thread::sleep(Duration::from_micros(200));
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let m = get_lock_metrics();
        assert!(m.acquire_count > 0, "expected some lock acquisitions");
        assert!(m.contention_events > 0, "expected some contention events");
    }

    /// Measurement helper: sweep a few shard/thread configurations and print
    /// CSV-style measurements so we can pick shard counts and judge contention.
    /// This test is intended to run on the host (cfg(test)) only and prints
    /// results to stdout for quick inspection.
    #[test_case]
    pub(super) fn test_lock_metrics_sweep() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let configs = [
            (32usize, 8usize, 200usize, 50u64),
            (16usize, 16usize, 300usize, 100u64),
            (8usize, 32usize, 300usize, 200u64),
            (4usize, 64usize, 150usize, 500u64),
        ];

        println!("shards,threads,ops,hold_us,acq_count,contention,avg_acq_ticks");

        for (shard_count, num_threads, ops, hold_us) in configs.iter().cloned() {
            reset_lock_metrics();

            let mut vec = Vec::with_capacity(shard_count);
            for _ in 0..shard_count {
                vec.push(Arc::new(PoisonLock::new(0usize)));
            }
            let shards = Arc::new(vec);

            let mut handles = Vec::new();
            for t in 0..num_threads {
                let shards = Arc::clone(&shards);
                let handle = thread::spawn(move || {
                    for i in 0..ops {
                        let idx = (i + t) % shard_count;
                        let _g = shards[idx].lock().unwrap();
                        if hold_us > 0 {
                            thread::sleep(Duration::from_micros(hold_us));
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
                "{},{},{},{},{},{},{}",
                shard_count,
                num_threads,
                ops,
                hold_us,
                m.acquire_count,
                m.contention_events,
                m.average_acquire_ticks
            );
        }
    }
}

