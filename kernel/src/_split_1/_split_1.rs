use super::*;


// time shim removed



pub mod pcid_support;

#[cfg(all(test, not(feature = "bench"), not(feature = "full_mm_tests")))]
pub mod io {
    // Include only the IOMMU implementation for test builds to avoid
    // pulling in the whole I/O subsystem and its wide dependency graph.
    #[path = "iommu/mod.rs"]
    pub mod iommu;

    /// Minimal logger shim for test builds. Kernel code calls `io::log::early_print`,
    /// `io::log::init()` and `io::log::notify_heap_available()` during early boot. We
    /// provide lightweight no-op implementations here so unit tests can run without
    /// pulling the full I/O logging subsystem into the test build.
    pub mod log {
        /// Early boot serial-like print used before the full logger is initialized.
        pub fn early_print(s: &str) {
            // Write to COM1 (0x3F8) for test output
            unsafe {
                let port = 0x3F8u16;
                for byte in s.bytes() {
                     core::arch::asm!("out dx, al", in("dx") port, in("al") byte);
                }
            }
        }

        pub fn early_print_dec(mut n: u64) {
             if n == 0 {
                 early_print("0");
                 return;
             }
             let mut buf = [0u8; 20];
             let mut i = 0;
             while n > 0 {
                 buf[i] = (n % 10) as u8 + b'0';
                 n /= 10;
                 i += 1;
             }
             while i > 0 {
                 i -= 1;
                 early_print(core::str::from_utf8(&buf[i..=i]).unwrap());
             }
        }
        
        pub fn early_print_hex(n: u64) {
            early_print("0x");
            for i in (0..16).rev() {
                let digit = (n >> (i * 4)) & 0xF;
                let c = if digit < 10 { b'0' + digit as u8 } else { b'a' + (digit - 10) as u8 };
                early_print(core::str::from_utf8(&[c]).unwrap());
            }
        }

        /// Early boot single-character print used by low-level routines.
        pub fn early_print_char(c: u8) {
            unsafe {
                core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") c);
            }
        }

        /// Initialize the logger. Returns Ok(()) for the test shim.
        pub fn init() -> Result<(), ()> {
            Ok(())
        }

        /// Notify the logging subsystem that the heap is now available.
        pub fn notify_heap_available() {}
    }

    pub mod interrupt_manager {
        pub fn send_ipi(_apic_id: u32, _vector: u8) {}
        pub fn broadcast_ipi(_vector: u8) {}
    }

    // Minimal PCI stub for test builds so IOMMU functions that reference
    // `crate::io::pci::PciDeviceInfo` compile.
    pub mod pci {
        #[derive(Debug, Clone, Copy)]
        pub struct Bus(pub u8);
        #[derive(Debug, Clone, Copy)]
        pub struct Device(pub u8);
        #[derive(Debug, Clone, Copy)]
        pub struct Function(pub u8);

        #[derive(Debug, Clone, Copy)]
        pub struct Bdf {
            pub bus: Bus,
            pub device: Device,
            pub function: Function,
        }

        #[derive(Debug)]
        pub struct PciDeviceInfo {
            pub bdf: Bdf,
            pub iommu_domain_id: Option<u16>,
        }

        impl PciDeviceInfo {
            pub fn is_pci_bridge(&self) -> bool {
                false
            }
        }
    }

    pub mod nvme {
        // Re-export the task-scoped NVMe driver for compatibility in test builds.
        // Tests expect `crate::io::nvme::NvmePollingDriver` and driver-global helpers.
        pub use crate::task::io::nvme::NvmePollingDriver;

        pub mod global {
            use crate::task::io::nvme::NvmePollingDriver;

            pub fn with_driver<F, R>(_f: F) -> Option<R>
            where
                F: FnOnce(&NvmePollingDriver) -> R,
            {
                None
            }

            pub fn with_driver_mut<F, R>(_f: F) -> Option<R>
            where
                F: FnOnce(&mut NvmePollingDriver) -> R,
            {
                None
            }
        }
    }

    // Minimal MMIO stubs used by the IOMMU unit tests. These provide
    // deterministic behavior suitable for unit testing.
    pub mod mmio {
        pub fn mmio_read_u8(_addr: usize) -> u8 {
            0
        }
        pub fn mmio_read_u16(_addr: usize) -> u16 {
            0
        }
        pub fn mmio_read_u32(_addr: usize) -> u32 {
            0
        }
        pub fn mmio_read_u64(_addr: usize) -> u64 {
            0
        }
        pub fn mmio_write_u8(_addr: usize, _v: u8) {}
        pub fn mmio_write_u16(_addr: usize, _v: u16) {}
        pub fn mmio_write_u32(_addr: usize, _v: u32) {}
        pub fn mmio_write_u64(_addr: usize, _v: u64) {}
    }

    // Expose a minimal ACPI module in tests so IOMMU init can call into
    // `crate::io::acpi::dmar::parse_dmar` without pulling the full ACPI
    // runtime dependencies into every unit test. This delegates only the
    // DMAR parsing API to the acpi driver crate.
    pub mod acpi {
        pub mod dmar {
            pub use acpi_driver::dmar::*;
        }
        pub mod ivrs {
            pub use acpi_driver::ivrs::*;
        }
    }
}

// When building benches enable a *minimal* I/O module that only includes
// `crate::io::log` so benchmark harnesses can access logging helpers while
// avoiding the heavy dependencies of the full I/O subsystem.
#[cfg(feature = "bench")]
#[path = "io/bench_mod.rs"]
pub mod io;

#[cfg(any(test, feature = "bench"))]
pub use hal;


#[cfg(all(test, not(feature = "full_mm_tests")))]
pub mod unwind;

#[cfg(any(not(test), test, feature = "bench", feature = "full_mm_tests"))]
pub mod driver_registry;
#[cfg(any(all(test, not(feature = "full_mm_tests")), feature = "bench"))]
pub mod loader;
#[cfg(any(all(test, not(feature = "full_mm_tests")), feature = "bench"))]
pub mod sync;

#[cfg(any(all(test, not(feature = "full_mm_tests")), feature = "bench"))]
pub mod sas;

#[cfg(any(all(test, not(feature = "full_mm_tests")), feature = "bench"))]
pub mod util;

#[cfg(any(test, feature = "bench"))]
pub mod nvme {
    pub use crate::io::nvme::*;
}

// Re-export task-scoped shims at crate root so modules that reference
// `crate::memory`, `crate::smp`, `crate::interrupts`, and
// `crate::domain_system` compile in test builds without changes.
#[cfg(any(all(test, not(feature = "full_mm_tests")), feature = "bench"))]
// pub use crate::task::memory as memory;
#[cfg(any(all(test, not(feature = "full_mm_tests")), feature = "bench"))]
pub use crate::task::smp as smp;
#[cfg(any(all(test, not(feature = "full_mm_tests")), feature = "bench"))]
pub use crate::task::interrupts as interrupts;
#[cfg(any(all(test, not(feature = "full_mm_tests")), feature = "bench"))]
pub use crate::task::domain_system as domain_system;

#[cfg(any(not(test), feature = "full_mm_tests"))]
pub mod domain_system;

#[cfg(all(test, feature = "std", not(target_os = "none")))]
mod async_swapout_sim_lib {
    use super::*;
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

    #[test_case]
    fn async_swapout_sim_short_baseline() {
        // Simulation parameters (short baseline run)
        // Allow overriding via environment variables for quick parameter sweeps
        let channel_size: usize = std::env::var("ASYNC_SWAPOUT_CHANNEL_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(512);
        let batch_size: usize = std::env::var("ASYNC_SWAPOUT_BATCH_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(16);
        let reserved_file_slots: usize = std::env::var("ASYNC_SWAPOUT_RESERVED_FILE_SLOTS").ok().and_then(|v| v.parse().ok()).unwrap_or(channel_size / 8);
        let token_bucket_capacity: usize = std::env::var("ASYNC_SWAPOUT_TOKEN_CAPACITY").ok().and_then(|v| v.parse().ok()).unwrap_or(channel_size / 4);
        let token_refill_per_batch: usize = std::env::var("ASYNC_SWAPOUT_TOKEN_REFILL").ok().and_then(|v| v.parse().ok()).unwrap_or(batch_size / 2);

        let threads: usize = std::env::var("ASYNC_SWAPOUT_THREADS").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
        let iters: usize = std::env::var("ASYNC_SWAPOUT_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(400); // each thread iterations
        // Optional processing delay (ms) to simulate slower I/O via env var
        let proc_delay_ms: u64 = std::env::var("ASYNC_SWAPOUT_PROCESSING_DELAY_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(1);

        // Shared state
        let queue = Arc::new((Mutex::new(VecDeque::<SwapEntry>::new()), Condvar::new()));
        let pending = Arc::new(Mutex::new(HashSet::<usize>::new()));
        let file_queue_count = Arc::new(AtomicUsize::new(0));
        let queue_len_max = Arc::new(AtomicUsize::new(0));
        let tokens = Arc::new(AtomicUsize::new(token_bucket_capacity));

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

                        for _ in 0..batch_size {
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
                                thread::sleep(Duration::from_millis(proc_delay_ms));
                                file_queue_count.fetch_sub(1, Ordering::AcqRel);
                            }
                            SwapKind::Anon => {
                                // simulate zswap store latency (faster)
                                thread::sleep(Duration::from_millis(proc_delay_ms));
                            }
                        }

                        // mark processed and clear pending
                        processed.fetch_add(1, Ordering::AcqRel);
                        pending.lock().unwrap().remove(&entry.frame);
                    }

                    // refill tokens after processing batch
                    loop {
                        let cur = tokens.load(Ordering::Acquire);
                        if cur >= token_bucket_capacity { break; }
                        let new = (cur + token_refill_per_batch).min(token_bucket_capacity);
                        if tokens.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire).is_ok() { break; }
                    }
                }
            });
        }

        // Enqueuer threads
        let mut joiners = Vec::new();
        let start = Instant::now();
        for t in 0..threads {
            let queue = queue.clone();
            let pending = pending.clone();
            let file_queue_count = file_queue_count.clone();
            let tokens = tokens.clone();
            let enqueue_success = enqueue_success.clone();
            let enqueue_failures = enqueue_failures.clone();

            let j = thread::spawn(move || {
                for i in 0..iters {
                    let is_file = ((i + t) % 2) == 0;
                    let frame = (t * iters) + i; // unique frame id per attempt

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
                        if q.len() >= channel_size {
                            enqueue_failures.fetch_add(1, Ordering::AcqRel);
                            continue;
                        }

                        // reservation for file writes
                        if !is_file {
                            let total = q.len();
                            let file_q = file_queue_count.load(Ordering::Acquire);
                            let free_slots = channel_size.saturating_sub(total);
                            if free_slots <= reserved_file_slots && file_q >= reserved_file_slots {
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
        // Wait for workers to finish processing enqueued items (respect proc_delay_ms)
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while processed.load(Ordering::Acquire) < enqueue_success.load(Ordering::Acquire) && Instant::now() < wait_deadline {
            thread::sleep(Duration::from_millis(10));
        }

        let elapsed = start.elapsed();
        let success = enqueue_success.load(Ordering::Acquire);
        let failures = enqueue_failures.load(Ordering::Acquire);
        let processed = processed.load(Ordering::Acquire);
        let tokens_left = tokens.load(Ordering::Acquire);
        let max_q = queue_len_max.load(Ordering::Acquire);

        println!("async_swapout_sim_short_baseline: threads={} iters={} time={:?}", threads, iters, elapsed);
        println!("enq_success={}, enq_failures={}, processed={}, tokens_left={}, max_queue_len={}", success, failures, processed, tokens_left, max_q);

        // Basic sanity checks
        assert_eq!(processed, success);
        assert!(success > 0);
    }
}
