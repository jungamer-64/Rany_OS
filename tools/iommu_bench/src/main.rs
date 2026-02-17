use criterion::{black_box, Criterion};
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use rany_os::io::iommu_cmdqueue::{CommandQueue, IommuCommandKind};

fn bench_submit_sync_single_thread(c: &mut Criterion) {
    let q = Arc::new(CommandQueue::new());
    let q_worker = q.clone();

    let running = Arc::new(AtomicBool::new(true));
    let r2 = running.clone();
    let worker = thread::spawn(move || {
        while r2.load(Ordering::Relaxed) {
            let n = q_worker.process_up_to(|_k| Ok(0), 256);
            if n == 0 {
                thread::yield_now();
            }
        }
    });

    c.bench_function("cq_submit_sync_single_thread", |b| {
        b.iter(|| {
            q.submit_sync(IommuCommandKind::InvalidateIotlbDomain { domain: 0 }).unwrap();
        })
    });

    running.store(false, Ordering::Relaxed);
    worker.join().unwrap();
}

fn bench_submit_sync_4_producers(c: &mut Criterion) {
    let q = Arc::new(CommandQueue::new());
    let q_worker = q.clone();

    let running = Arc::new(AtomicBool::new(true));
    let r2 = running.clone();
    let worker = thread::spawn(move || {
        while r2.load(Ordering::Relaxed) {
            let n = q_worker.process_up_to(|_k| Ok(0), 256);
            if n == 0 {
                thread::yield_now();
            }
        }
    });

    let threads = 4usize;
    c.bench_function("cq_submit_sync_4_producers", |b| {
        b.iter_custom(|iters| {
            let per_thread = ((iters as usize) + threads - 1) / threads;
            let start = Instant::now();
            let mut handles = Vec::new();
            for _ in 0..threads {
                let q_clone = q.clone();
                handles.push(thread::spawn(move || {
                    for _ in 0..per_thread {
                        q_clone.submit_sync(IommuCommandKind::InvalidateIotlbDomain { domain: 0 }).unwrap();
                    }
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
            start.elapsed()
        })
    });

    running.store(false, Ordering::Relaxed);
    worker.join().unwrap();
}

fn bench_submit_async_single_thread(c: &mut Criterion) {
    let q = Arc::new(CommandQueue::new());
    let q_worker = q.clone();

    let running = Arc::new(AtomicBool::new(true));
    let r2 = running.clone();
    let worker = thread::spawn(move || {
        while r2.load(Ordering::Relaxed) {
            let n = q_worker.process_up_to(|_k| Ok(0), 256);
            if n == 0 {
                thread::yield_now();
            }
        }
    });

    c.bench_function("cq_submit_async_single_thread", |b| {
        b.iter(|| {
            let rc = rany_os::task::block_on(async {
                let comp = q.submit_async(IommuCommandKind::InvalidateIotlbDomain { domain: 1 }).await.expect("submit_async");
                comp.await
            });
            black_box(rc);
        })
    });

    running.store(false, Ordering::Relaxed);
    worker.join().unwrap();
}

/// Scaling bench: run submit_sync with multiple producer threads (1/2/4/8/... up to available CPUs)
fn bench_submit_sync_scaling(c: &mut Criterion) {
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut counts = vec![1usize, 2, 4, 8];
    counts.retain(|&n| n <= cpus);
    if !counts.contains(&cpus) {
        counts.push(cpus);
    }
    counts.sort();

    for &threads in counts.iter() {
        let name = format!("cq_submit_sync_{}producers", threads);
        let q = Arc::new(CommandQueue::new());
        let q_worker = q.clone();

        let running = Arc::new(AtomicBool::new(true));
        let r2 = running.clone();
        let worker = thread::spawn(move || {
            while r2.load(Ordering::Relaxed) {
                let n = q_worker.process_up_to(|_k| Ok(0), 256);
                if n == 0 { thread::yield_now(); }
            }
        });

        c.bench_function(&name, |b| {
            b.iter_custom(|iters| {
                let per_thread = ((iters as usize) + threads - 1) / threads;
                let start = Instant::now();
                let mut handles = Vec::new();
                for _ in 0..threads {
                    let q_clone = q.clone();
                    handles.push(thread::spawn(move || {
                        for _ in 0..per_thread {
                            q_clone.submit_sync(IommuCommandKind::InvalidateIotlbDomain { domain: 0 }).unwrap();
                        }
                    }));
                }
                for h in handles { h.join().unwrap(); }
                start.elapsed()
            })
        });

        running.store(false, Ordering::Relaxed);
        worker.join().unwrap();
    }
}

/// NUMA bench: allocate queue with a NUMA hint and run a simple submit_sync loop
fn bench_submit_sync_numa(c: &mut Criterion) {
    let nodes = rany_os::mm::numa::num_nodes();
    for node in 0..nodes {
        let name = format!("cq_submit_sync_numa_node_{}", node);
        let q = Arc::new(CommandQueue::new_with_numa(Some(node)));
        let q_worker = q.clone();

        let running = Arc::new(AtomicBool::new(true));
        let r2 = running.clone();
        let worker = thread::spawn(move || {
            while r2.load(Ordering::Relaxed) {
                let n = q_worker.process_up_to(|_k| Ok(0), 256);
                if n == 0 { thread::yield_now(); }
            }
        });

        c.bench_function(&name, |b| {
            b.iter(|| {
                q.submit_sync(IommuCommandKind::InvalidateIotlbDomain { domain: 0 }).unwrap();
            })
        });

        running.store(false, Ordering::Relaxed);
        worker.join().unwrap();
    }
}

fn run_harness(args: &Vec<String>) {
    // Parse simple flags: --runs=N --iters=N --threads=1,2,4 or 1-8 --numa
    let mut runs: usize = 5;
    let mut iters: usize = 10000; // total submits per run
    let mut threads: Option<Vec<usize>> = None;
    let mut numa = false;

    for arg in args.iter() {
        if let Some(s) = arg.strip_prefix("--runs=") {
            if let Ok(n) = s.parse::<usize>() { runs = n; }
        } else if let Some(s) = arg.strip_prefix("--iters=") {
            if let Ok(n) = s.parse::<usize>() { iters = n; }
        } else if let Some(s) = arg.strip_prefix("--threads=") {
            // Parse like "1,2,4" or "1-8"
            let mut out = Vec::new();
            if s.contains(',') {
                for tok in s.split(',') {
                    if let Ok(n) = tok.parse::<usize>() { out.push(n); }
                }
            } else if s.contains('-') {
                let parts: Vec<&str> = s.split('-').collect();
                if parts.len() == 2 {
                    if let (Ok(a), Ok(b)) = (parts[0].parse::<usize>(), parts[1].parse::<usize>()) {
                        for n in a..=b { out.push(n); }
                    }
                }
            } else if let Ok(n) = s.parse::<usize>() {
                out.push(n);
            }
            if !out.is_empty() {
                threads = Some(out);
            }
        } else if arg == "--numa" {
            numa = true;
        }
    }

    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let default_counts = vec![1usize, 2, 4, 8].into_iter().filter(|&n| n <= cpus).chain(std::iter::once(cpus)).collect::<Vec<_>>();
    let thread_counts = threads.unwrap_or(default_counts);

    // CSV header
    println!("scenario,threads,run,duration_ns");

    for &thr in thread_counts.iter() {
        if numa {
            let nodes = rany_os::mm::numa::num_nodes();
            for node in 0..nodes {
                let scenario = format!("sync_numa_node_{}", node);
                let mut durations: Vec<u128> = Vec::new();
                for r in 0..runs {
                    let q = Arc::new(CommandQueue::new_with_numa(Some(node)));
                    let q_worker = q.clone();
                    let running = Arc::new(AtomicBool::new(true));
                    let r2 = running.clone();
                    let worker = thread::spawn(move || {
                        while r2.load(Ordering::Relaxed) {
                            let n = q_worker.process_up_to(|_k| Ok(0), 256);
                            if n == 0 { thread::yield_now(); }
                        }
                    });
                    let per_thread = (iters + thr - 1) / thr;
                    let start = Instant::now();
                    let mut handles = Vec::new();
                    for _ in 0..thr {
                        let q_clone = q.clone();
                        handles.push(thread::spawn(move || {
                            for _ in 0..per_thread {
                                q_clone.submit_sync(IommuCommandKind::InvalidateIotlbDomain { domain: 0 }).unwrap();
                            }
                        }));
                    }
                    for h in handles { h.join().unwrap(); }
                    let dur = start.elapsed().as_nanos();
                    durations.push(dur);
                    println!("{},{},{},{}", scenario, thr, r, dur);
                    running.store(false, Ordering::Relaxed);
                    worker.join().unwrap();
                }
                // Print a short summary
                durations.sort_unstable();
                let median = durations[durations.len() / 2];
                let sum: u128 = durations.iter().copied().sum();
                let mean = sum / (durations.len() as u128);
                println!("SUMMARY,{},{},runs={},median_ns={},mean_ns={}", scenario, thr, runs, median, mean);
            }
        } else {
            let scenario = format!("sync_{}producers", thr);
            let mut durations: Vec<u128> = Vec::new();
            for r in 0..runs {
                let q = Arc::new(CommandQueue::new());
                let q_worker = q.clone();
                let running = Arc::new(AtomicBool::new(true));
                let r2 = running.clone();
                let worker = thread::spawn(move || {
                    while r2.load(Ordering::Relaxed) {
                        let n = q_worker.process_up_to(|_k| Ok(0), 256);
                        if n == 0 { thread::yield_now(); }
                    }
                });
                let per_thread = (iters + thr - 1) / thr;
                let start = Instant::now();
                let mut handles = Vec::new();
                for _ in 0..thr {
                    let q_clone = q.clone();
                    handles.push(thread::spawn(move || {
                        for _ in 0..per_thread {
                            q_clone.submit_sync(IommuCommandKind::InvalidateIotlbDomain { domain: 0 }).unwrap();
                        }
                    }));
                }
                for h in handles { h.join().unwrap(); }
                let dur = start.elapsed().as_nanos();
                durations.push(dur);
                println!("{},{},{},{}", scenario, thr, r, dur);
                running.store(false, Ordering::Relaxed);
                worker.join().unwrap();
            }
            durations.sort_unstable();
            let median = durations[durations.len() / 2];
            let sum: u128 = durations.iter().copied().sum();
            let mean = sum / (durations.len() as u128);
            println!("SUMMARY,{},{},runs={},median_ns={},mean_ns={}", scenario, thr, runs, median, mean);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect(); // nosemgrep: codacy.tools-configs.rust.lang.security.args.args
    if args.iter().any(|a| a == "harness") {
        run_harness(&args);
        return;
    }

    if args.iter().any(|a| a == "criterion") {
        let mut c = Criterion::default();
        bench_submit_sync_single_thread(&mut c);
        bench_submit_sync_4_producers(&mut c);
        bench_submit_sync_scaling(&mut c);
        bench_submit_sync_numa(&mut c);
        bench_submit_async_single_thread(&mut c);
        c.final_summary();
    } else {
        println!("Running quick CQ benches (use `cargo run --release --manifest-path tools/iommu_bench/Cargo.toml --criterion` for full Criterion run)");
        let mut c = Criterion::default();
        bench_submit_sync_single_thread(&mut c);
        bench_submit_sync_4_producers(&mut c);
        bench_submit_sync_scaling(&mut c);
        bench_submit_sync_numa(&mut c);
        bench_submit_async_single_thread(&mut c);
        c.final_summary();
    }
}
