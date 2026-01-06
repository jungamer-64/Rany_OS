use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwapKind {
    File,
    Anon,
}

#[derive(Clone, Copy, Debug)]
struct SwapEntry {
    frame: usize,
    kind: SwapKind,
}

#[test]
fn async_swapout_sim_short_baseline() {
    // Simulation parameters (short baseline run)
    const CHANNEL_SIZE: usize = 512;
    const BATCH_SIZE: usize = 16;
    const RESERVED_FILE_SLOTS: usize = CHANNEL_SIZE / 8; // ~12.5%
    const TOKEN_BUCKET_CAPACITY: usize = CHANNEL_SIZE / 4;
    const TOKEN_REFILL_PER_BATCH: usize = BATCH_SIZE / 2;

    const THREADS: usize = 8;
    const ITERS: usize = 400; // each thread iterations

    // Shared state
    let queue = Arc::new((Mutex::new(VecDeque::<SwapEntry>::new()), Condvar::new()));
    let pending = Arc::new(Mutex::new(HashSet::<usize>::new()));
    let file_queue_count = Arc::new(AtomicUsize::new(0));
    let queue_len_max = Arc::new(AtomicUsize::new(0));
    let tokens = Arc::new(AtomicUsize::new(TOKEN_BUCKET_CAPACITY));

    let enqueue_success = Arc::new(AtomicUsize::new(0));
    let enqueue_failures = Arc::new(AtomicUsize::new(0));
    let processed = Arc::new(AtomicUsize::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));

    // Worker thread
    {
        let queue = queue.clone();
        let pending = pending.clone();
        let file_queue_count = file_queue_count.clone();
        let queue_len_max = queue_len_max.clone();
        let tokens = tokens.clone();
        let processed = processed.clone();
        let shutdown = shutdown.clone();

        thread::spawn(move || {
            loop {
                // Wait for work or shutdown
                let mut batch = Vec::new();
                {
                    let (lock, cvar) = &*queue;
                    let mut q = lock.lock().unwrap();
                    while q.is_empty() && !shutdown.load(Ordering::Acquire) {
                        q = cvar.wait(q).unwrap();
                    }

                    if q.is_empty() && shutdown.load(Ordering::Acquire) {
                        break;
                    }

                    for _ in 0..BATCH_SIZE {
                        if let Some(e) = q.pop_front() {
                            batch.push(e);
                        } else {
                            break;
                        }
                    }

                    // update observed queue length
                    let cur = q.len();
                    loop {
                        let old = queue_len_max.load(Ordering::Acquire);
                        if cur <= old || queue_len_max.compare_exchange(old, cur, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                            break;
                        }
                    }
                }

                if batch.is_empty() {
                    continue;
                }

                // process batch (simulate I/O)
                for entry in batch.iter() {
                    match entry.kind {
                        SwapKind::File => {
                            // simulate page writeback latency
                            thread::sleep(Duration::from_millis(1));
                            file_queue_count.fetch_sub(1, Ordering::AcqRel);
                        }
                        SwapKind::Anon => {
                            // simulate zswap store latency (faster)
                            thread::sleep(Duration::from_millis(1));
                        }
                    }

                    // mark processed and clear pending
                    processed.fetch_add(1, Ordering::AcqRel);
                    pending.lock().unwrap().remove(&entry.frame);
                }

                // refill tokens after processing batch
                loop {
                    let cur = tokens.load(Ordering::Acquire);
                    if cur >= TOKEN_BUCKET_CAPACITY { break; }
                    let new = (cur + TOKEN_REFILL_PER_BATCH).min(TOKEN_BUCKET_CAPACITY);
                    if tokens.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire).is_ok() { break; }
                }
            }
        });
    }

    // Enqueuer threads
    let mut joiners = Vec::new();
    let start = Instant::now();
    for t in 0..THREADS {
        let queue = queue.clone();
        let pending = pending.clone();
        let file_queue_count = file_queue_count.clone();
        let tokens = tokens.clone();
        let enqueue_success = enqueue_success.clone();
        let enqueue_failures = enqueue_failures.clone();

        let j = thread::spawn(move || {
            for i in 0..ITERS {
                let is_file = ((i + t) % 2) == 0;
                let frame = (t * ITERS) + i; // unique frame id per attempt

                // try pending check
                {
                    let mut p = pending.lock().unwrap();
                    if p.contains(&frame) {
                        enqueue_failures.fetch_add(1, Ordering::AcqRel);
                        continue;
                    }

                    // capacity check
                    let (lock, cvar) = &*queue;
                    let mut q = lock.lock().unwrap();
                    if q.len() >= CHANNEL_SIZE {
                        enqueue_failures.fetch_add(1, Ordering::AcqRel);
                        continue;
                    }

                    // reservation for file writes
                    if !is_file {
                        let total = q.len();
                        let file_q = file_queue_count.load(Ordering::Acquire);
                        let free_slots = CHANNEL_SIZE.saturating_sub(total);
                        if free_slots <= RESERVED_FILE_SLOTS && file_q >= RESERVED_FILE_SLOTS {
                            enqueue_failures.fetch_add(1, Ordering::AcqRel);
                            continue;
                        }
                    }

                    // token consumption for anon
                    if !is_file {
                        let ok = loop {
                            let cur = tokens.load(Ordering::Acquire);
                            if cur == 0 {
                                enqueue_failures.fetch_add(1, Ordering::AcqRel);
                                break false;
                            }
                            if tokens.compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                                break true;
                            }
                        };
                        if !ok { continue; }
                    }

                    // all checks passed: insert
                    p.insert(frame);
                    if is_file {
                        file_queue_count.fetch_add(1, Ordering::AcqRel);
                    }
                    q.push_back(SwapEntry { frame, kind: if is_file { SwapKind::File } else { SwapKind::Anon } });
                    cvar.notify_one();
                    enqueue_success.fetch_add(1, Ordering::AcqRel);
                }
            }
        });
        joiners.push(j);
    }

    for j in joiners { j.join().unwrap(); }

    // Give worker time to finish processing
    loop {
        let (lock, _) = &*queue;
        let q = lock.lock().unwrap();
        if q.is_empty() { break; }
        drop(q);
        thread::sleep(Duration::from_millis(10));
    }

    // shutdown and wait a moment
    shutdown.store(true, Ordering::Release);
    {
        let (lock, cvar) = &*queue;
        drop(lock.lock().unwrap());
        cvar.notify_all();
    }
    thread::sleep(Duration::from_millis(50));

    let elapsed = start.elapsed();
    let success = enqueue_success.load(Ordering::Acquire);
    let failures = enqueue_failures.load(Ordering::Acquire);
    let processed = processed.load(Ordering::Acquire);
    let tokens_left = tokens.load(Ordering::Acquire);
    let max_q = queue_len_max.load(Ordering::Acquire);

    println!("async_swapout_sim_short_baseline: threads={} iters={} time={:?}", THREADS, ITERS, elapsed);
    println!("enq_success={}, enq_failures={}, processed={}, tokens_left={}, max_queue_len={}", success, failures, processed, tokens_left, max_q);

    // Basic sanity checks
    assert_eq!(processed, success);
    assert!(success > 0);
}
