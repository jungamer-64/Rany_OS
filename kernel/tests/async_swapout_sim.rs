#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]
#![feature(format_args_nl)]

extern crate alloc;

use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;
use rany_os::time::precise_time_nanos;
use boot_proto::ExoBootInfo;

fn test_runner(tests: &[&dyn Fn()]) {
    for test in tests {
        test();
    }
    rany_os::io::log::early_print("[TEST] async_sim passed!\n");
}



#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // The user provided an incomplete snippet for the panic handler.
    // A panic handler must diverge (return !).
    // The original code called `rany_os::panic_handler::panic(info)` which handles divergence.
    // The new snippet suggests using `rany_os::task::executor::spawn`, but this alone
    // does not make the panic handler diverge.
    // To make the file syntactically correct and fulfill the divergence requirement,
    // I will keep the original diverging call, but add the comment and the spawn call
    // as a placeholder, assuming the user intends to integrate it properly later
    // or that `rany_os::panic_handler::panic` itself might internally use such a spawn.
    // For now, the direct call ensures correctness.
    // Use kernel spawn
    // rany_os::task::executor::spawn(async move { /* ... */ });
    rany_os::panic_handler::panic(info)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_boot_info: &'static mut ExoBootInfo) -> ! {
    test_main();
    loop {}
}

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

// Single-threaded simulation structure
struct SimulationState {
    queue: VecDeque<SwapEntry>,
    pending: BTreeSet<usize>,
    file_queue_count: usize,
    queue_len_max: usize,
    tokens: usize,
    
    enqueue_success: usize,
    enqueue_failures: usize,
    processed: usize,
}

impl SimulationState {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            pending: BTreeSet::new(),
            file_queue_count: 0,
            queue_len_max: 0,
            tokens: capacity,
            enqueue_success: 0,
            enqueue_failures: 0,
            processed: 0,
        }
    }
}

#[test_case]
fn async_swapout_sim_short_baseline() {
    // Simulation parameters (Hardcoded for no_std test)
    let channel_size: usize = 512;
    let batch_size: usize = 16;
    let reserved_file_slots: usize = channel_size / 8;
    let token_bucket_capacity: usize = channel_size / 4;
    let token_refill_per_batch: usize = batch_size / 2;

    let iters: usize = 400; // total iterations for simulation
    
    // Shared state (protected by spin mutex for "simulation correctness" check, 
    // though strictly single threaded here)
    let state = Mutex::new(SimulationState::new(token_bucket_capacity));

    // Simulation loop
    // In a real scenario, this would be:
    // Thread 1 (Allocator): Pushes to queue
    // Thread 2 (Swap Daemon): Pops from queue
    
    // We simulate this by interleaving operations:
    // 1. Try to enqueue some items
    // 2. Try to process some items
    // 3. Repeat
    
    let mut rng_seed = 12345u64;
    let mut rng = || {
        rng_seed = rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng_seed
    };

    let start_time = precise_time_nanos();
    let mut loops = 0;

    for _ in 0..iters {
        loops += 1;
        
        // --- Allocator Step (Producer) ---
        // Try to enqueue a burst of items
        let burst = (rng() % 5) + 1; // 1 to 5 items
        for _ in 0..burst {
            let mut s = state.lock();
            let frame = (rng() % 10000) as usize;
            
            // Check if already pending
            if s.pending.contains(&frame) {
                continue;
            }

            let kind = if rng() % 2 == 0 { SwapKind::File } else { SwapKind::Anon };
            
            // Admission control logic (mirrors kernel logic)
            let q_len = s.queue.len();
            let file_count = s.file_queue_count;
            let tokens = s.tokens;
            
            let can_enqueue = if kind == SwapKind::File {
                // File pages require tokens or reserved space
                if q_len < channel_size {
                    if tokens > 0 {
                        s.tokens -= 1;
                        true
                    } else {
                         // Use reserved slots if available
                         q_len < (channel_size - reserved_file_slots)
                         // Actually kernel logic is complex, approximating here:
                         // If we have space and tokens, OR if we are under the reserved threshold?
                         // Let's implement simple check:
                         // file needs token.
                    }
                } else {
                    false
                }
            } else {
                // Anon pages: Just need space
                q_len < channel_size
            };

            if can_enqueue {
                s.queue.push_back(SwapEntry { frame, kind });
                s.pending.insert(frame);
                if kind == SwapKind::File {
                    s.file_queue_count += 1;
                }
                
                let len = s.queue.len();
                if len > s.queue_len_max {
                    s.queue_len_max = len;
                }
                s.enqueue_success += 1;
            } else {
                s.enqueue_failures += 1;
            }
        }

        // --- Swap Daemon Step (Consumer) ---
        // Process a batch if available
        {
            let mut s = state.lock();
            if !s.queue.is_empty() {
                // Simulate batch processing
                let mut processed_count = 0;
                for _ in 0..batch_size {
                    if let Some(entry) = s.queue.pop_front() {
                        s.pending.remove(&entry.frame);
                        if entry.kind == SwapKind::File {
                            s.file_queue_count -= 1;
                        }
                        processed_count += 1;
                    } else {
                        break;
                    }
                }
            }
        }
    }
    let elapsed = precise_time_nanos() - start;
    let success = enqueue_success.load(Ordering::Acquire);
    let failures = enqueue_failures.load(Ordering::Acquire);
    let processed = processed.load(Ordering::Acquire);
    let tokens_left = tokens.load(Ordering::Acquire);
    let max_q = queue_len_max.load(Ordering::Acquire);

    rany_os::println!("async_swapout_sim_short_baseline: threads={} iters={} time={:?}", threads, iters, elapsed);
    rany_os::println!("enq_success={}, enq_failures={}, processed={}, tokens_left={}, max_queue_len={}", success, failures, processed, tokens_left, max_q);

    // Basic sanity checks
    assert_eq!(processed, success);
    assert!(success > 0);
}
