#![cfg(feature = "bench")]

use criterion::{Criterion, criterion_group, criterion_main};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use rany_os::io::log::{
    bench_clear_buffers, bench_pop_global_buf, bench_push_global, bench_total_pending_bytes,
};

fn run_benchmark(threads: usize, entries: usize, entry_size: usize) -> Duration {
    bench_clear_buffers();
    let payload = vec![0x55u8; entry_size];
    let producers_done = Arc::new(AtomicBool::new(false));

    let producers_done_consumer = producers_done.clone();
    let consumer = thread::spawn(move || {
        let mut temporary = vec![0u8; 1024];
        loop {
            let consumed = bench_pop_global_buf(&mut temporary);
            if consumed == 0 {
                if producers_done_consumer.load(Ordering::Relaxed)
                    && bench_total_pending_bytes() == 0
                {
                    break;
                }
                thread::yield_now();
            }
        }
    });

    let start = Instant::now();
    let mut producers = Vec::with_capacity(threads);
    for _ in 0..threads {
        let payload = payload.clone();
        producers.push(thread::spawn(move || {
            for _ in 0..entries {
                let _ = bench_push_global(&payload);
            }
        }));
    }

    for producer in producers {
        let _ = producer.join();
    }
    producers_done.store(true, Ordering::Relaxed);
    let _ = consumer.join();
    start.elapsed()
}

fn bench_log_global(c: &mut Criterion) {
    let threads = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(4);
    let entries = std::env::var("RANY_BENCH_LOG_ENTRIES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000usize);
    let entry_size = std::env::var("RANY_BENCH_ENTRY_SIZE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64usize);

    c.bench_function("log_global_concurrent", |benchmark| {
        benchmark.iter_custom(|iterations| {
            let mut total = Duration::ZERO;
            for _ in 0..iterations {
                total += run_benchmark(threads, entries, entry_size);
            }
            total
        });
    });
}

criterion_group!(log_benches, bench_log_global);
criterion_main!(log_benches);
