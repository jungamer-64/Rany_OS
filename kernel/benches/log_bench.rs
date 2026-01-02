#![cfg(feature = "bench")]

use criterion::{Criterion, criterion_group, criterion_main};
use std::time::{Duration, Instant};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;

use rany_os::io::log::{
    bench_clear_buffers,
    bench_push_per_core,
    bench_push_global,
    bench_pop_global_buf,
    bench_pop_per_core_buf,
    bench_total_pending_bytes,
};

fn run_benchmark(per_core: bool, threads: usize, entries: usize, entry_size: usize) -> Duration {
    bench_clear_buffers();
    let payload = vec![0x55u8; entry_size];

    let producers_done = Arc::new(AtomicBool::new(false));

    // Consumer thread: drains global and per-core buffers until producers are done
    let producers_done_consumer = producers_done.clone();
    let consumer = thread::spawn(move || {
        let mut tmp = vec![0u8; 1024];
        loop {
            let mut consumed = 0usize;
            consumed += bench_pop_global_buf(&mut tmp);
            for core in 0..max_cpus() {
                consumed += bench_pop_per_core_buf(core, &mut tmp);
            }

            if consumed == 0 {
                if producers_done_consumer.load(Ordering::Relaxed) {
                    if bench_total_pending_bytes() == 0 {
                        break;
                    }
                }
                thread::yield_now();
            }
        }
    });

    let start = Instant::now();

    // Spawn producers
    let mut handles = vec![];
    for t in 0..threads {
        let payload = payload.clone();
        let producers_done_producer = producers_done.clone();
        let handle = thread::spawn(move || {
            if per_core {
                // Target a unique per-core buffer when possible
                let core_id = t % max_cpus();
                for _ in 0..entries {
                    let written = bench_push_per_core(core_id, &payload);
                    if written < payload.len() {
                        // Fallback to global buffer if per-core is full
                        let _ = bench_push_global(&payload);
                    }
                }
            } else {
                for _ in 0..entries {
                    let _ = bench_push_global(&payload);
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }

    producers_done.store(true, Ordering::Relaxed);

    let _ = consumer.join();

    start.elapsed()
}

// Helper to retrieve MAX_CPUS at runtime; used via per-core loop bounds.
fn max_cpus() -> usize {
    // Use the same constant as kernel
    rany_os::mm::per_cpu::MAX_CPUS
}

fn bench_log_per_core(c: &mut Criterion) {
    let threads = std::cmp::min(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4), max_cpus());
    let entries = std::env::var("RANY_BENCH_LOG_ENTRIES").ok().and_then(|s| s.parse().ok()).unwrap_or(10000usize);
    let entry_size = std::env::var("RANY_BENCH_ENTRY_SIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(64usize);

    c.bench_function("log_per_core_concurrent", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::new(0, 0);
            for _ in 0..iters {
                total += run_benchmark(true, threads, entries, entry_size);
            }
            total
        })
    });
}

fn bench_log_global(c: &mut Criterion) {
    let threads = std::cmp::min(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4), max_cpus());
    let entries = std::env::var("RANY_BENCH_LOG_ENTRIES").ok().and_then(|s| s.parse().ok()).unwrap_or(10000usize);
    let entry_size = std::env::var("RANY_BENCH_ENTRY_SIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(64usize);

    c.bench_function("log_global_concurrent", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::new(0, 0);
            for _ in 0..iters {
                total += run_benchmark(false, threads, entries, entry_size);
            }
            total
        })
    });
}

criterion_group!(log_benches, bench_log_per_core, bench_log_global);
criterion_main!(log_benches);
