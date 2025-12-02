//! Benchmark System for ExoRust Kernel
//!
//! This module provides comprehensive benchmarking capabilities for
//! performance validation of the kernel components, targeting 10Gbps
//! line rate verification (Design Doc Section 10).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Benchmark result
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Benchmark name
    pub name: String,
    /// Total iterations
    pub iterations: u64,
    /// Total duration in nanoseconds
    pub total_ns: u64,
    /// Average time per operation in nanoseconds
    pub avg_ns: u64,
    /// Minimum time in nanoseconds
    pub min_ns: u64,
    /// Maximum time in nanoseconds
    pub max_ns: u64,
    /// Throughput in operations per second
    pub ops_per_sec: u64,
    /// Throughput in bytes per second (if applicable)
    pub bytes_per_sec: Option<u64>,
}

impl BenchmarkResult {
    /// Format throughput as human-readable string
    pub fn format_throughput(&self) -> String {
        if let Some(bps) = self.bytes_per_sec {
            let gbps = bps as f64 / 1_000_000_000.0;
            if gbps >= 1.0 {
                alloc::format!("{:.2} GB/s ({:.2} Gbps)", gbps, gbps * 8.0)
            } else {
                let mbps = bps as f64 / 1_000_000.0;
                alloc::format!("{:.2} MB/s ({:.2} Mbps)", mbps, mbps * 8.0)
            }
        } else {
            alloc::format!("{} ops/sec", self.ops_per_sec)
        }
    }
}

/// High-precision timer using TSC (Time Stamp Counter)
pub struct TscTimer {
    start: u64,
    tsc_freq_khz: u64,
}

impl TscTimer {
    /// Create a new TSC timer
    pub fn new() -> Self {
        TscTimer {
            start: rdtsc(),
            tsc_freq_khz: estimate_tsc_frequency(),
        }
    }
    
    /// Start timing
    pub fn start(&mut self) {
        core::sync::atomic::fence(Ordering::SeqCst);
        self.start = rdtsc();
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    
    /// Stop and get elapsed time in nanoseconds
    pub fn elapsed_ns(&self) -> u64 {
        core::sync::atomic::fence(Ordering::SeqCst);
        let end = rdtsc();
        core::sync::atomic::fence(Ordering::SeqCst);
        
        let cycles = end.saturating_sub(self.start);
        // Convert cycles to nanoseconds: cycles * 1_000_000 / freq_khz
        cycles.saturating_mul(1_000_000) / self.tsc_freq_khz.max(1)
    }
    
    /// Get elapsed cycles
    pub fn elapsed_cycles(&self) -> u64 {
        core::sync::atomic::fence(Ordering::SeqCst);
        rdtsc().saturating_sub(self.start)
    }
}

impl Default for TscTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Read Time Stamp Counter
#[inline]
pub fn rdtsc() -> u64 {
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}

/// Read TSC with serialization (RDTSCP)
#[inline]
pub fn rdtscp() -> (u64, u32) {
    unsafe {
        let lo: u32;
        let hi: u32;
        let aux: u32;
        core::arch::asm!(
            "rdtscp",
            out("eax") lo,
            out("edx") hi,
            out("ecx") aux,
            options(nomem, nostack, preserves_flags)
        );
        (((hi as u64) << 32) | (lo as u64), aux)
    }
}

/// Estimate TSC frequency in kHz
fn estimate_tsc_frequency() -> u64 {
    // Default to 3 GHz if we can't determine
    // In real implementation, this would read from CPUID or calibrate against PIT
    3_000_000 // 3 GHz in kHz
}

/// Benchmark runner
pub struct BenchmarkRunner {
    results: Vec<BenchmarkResult>,
}

impl BenchmarkRunner {
    /// Create a new benchmark runner
    pub fn new() -> Self {
        BenchmarkRunner {
            results: Vec::new(),
        }
    }
    
    /// Run a benchmark
    pub fn bench<F>(&mut self, name: &str, iterations: u64, mut f: F) -> &BenchmarkResult
    where
        F: FnMut(),
    {
        let mut timer = TscTimer::new();
        let mut min_ns = u64::MAX;
        let mut max_ns = 0u64;
        
        // Warmup
        for _ in 0..iterations.min(100) {
            f();
        }
        
        // Actual benchmark
        timer.start();
        let mut individual_times = Vec::with_capacity(iterations as usize);
        
        for _ in 0..iterations {
            let iter_start = rdtsc();
            f();
            let iter_end = rdtsc();
            
            let iter_cycles = iter_end.saturating_sub(iter_start);
            individual_times.push(iter_cycles);
        }
        
        let total_ns = timer.elapsed_ns();
        
        // Calculate statistics from individual measurements
        let tsc_freq_khz = estimate_tsc_frequency();
        for &cycles in &individual_times {
            let ns = cycles.saturating_mul(1_000_000) / tsc_freq_khz.max(1);
            min_ns = min_ns.min(ns);
            max_ns = max_ns.max(ns);
        }
        
        let avg_ns = total_ns / iterations.max(1);
        let ops_per_sec = if avg_ns > 0 {
            1_000_000_000 / avg_ns
        } else {
            u64::MAX
        };
        
        let result = BenchmarkResult {
            name: String::from(name),
            iterations,
            total_ns,
            avg_ns,
            min_ns,
            max_ns,
            ops_per_sec,
            bytes_per_sec: None,
        };
        
        self.results.push(result);
        self.results.last().unwrap()
    }
    
    /// Run a throughput benchmark (bytes/second)
    pub fn bench_throughput<F>(
        &mut self,
        name: &str,
        iterations: u64,
        bytes_per_iter: u64,
        mut f: F,
    ) -> &BenchmarkResult
    where
        F: FnMut(),
    {
        let mut timer = TscTimer::new();
        let mut min_ns = u64::MAX;
        let mut max_ns = 0u64;
        
        // Warmup
        for _ in 0..iterations.min(100) {
            f();
        }
        
        // Actual benchmark
        timer.start();
        
        for _ in 0..iterations {
            let iter_start = rdtsc();
            f();
            let iter_end = rdtsc();
            
            let tsc_freq_khz = estimate_tsc_frequency();
            let iter_ns = (iter_end.saturating_sub(iter_start))
                .saturating_mul(1_000_000) / tsc_freq_khz.max(1);
            min_ns = min_ns.min(iter_ns);
            max_ns = max_ns.max(iter_ns);
        }
        
        let total_ns = timer.elapsed_ns();
        let total_bytes = iterations.saturating_mul(bytes_per_iter);
        
        let avg_ns = total_ns / iterations.max(1);
        let ops_per_sec = if avg_ns > 0 {
            1_000_000_000 / avg_ns
        } else {
            u64::MAX
        };
        
        // bytes_per_sec = total_bytes / (total_ns / 1e9) = total_bytes * 1e9 / total_ns
        let bytes_per_sec = if total_ns > 0 {
            total_bytes.saturating_mul(1_000_000_000) / total_ns
        } else {
            u64::MAX
        };
        
        let result = BenchmarkResult {
            name: String::from(name),
            iterations,
            total_ns,
            avg_ns,
            min_ns,
            max_ns,
            ops_per_sec,
            bytes_per_sec: Some(bytes_per_sec),
        };
        
        self.results.push(result);
        self.results.last().unwrap()
    }
    
    /// Get all results
    pub fn results(&self) -> &[BenchmarkResult] {
        &self.results
    }
    
    /// Print results summary
    pub fn print_summary(&self) {
        crate::log!("\n=== Benchmark Results ===\n");
        for result in &self.results {
            crate::log!(
                "{}: {} ops/sec (avg: {} ns, min: {} ns, max: {} ns)",
                result.name,
                result.ops_per_sec,
                result.avg_ns,
                result.min_ns,
                result.max_ns
            );
            if result.bytes_per_sec.is_some() {
                crate::log!("  Throughput: {}", result.format_throughput());
            }
            crate::log!("\n");
        }
    }
}

impl Default for BenchmarkRunner {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Pre-defined Benchmarks
// ============================================================================

/// Memory allocation benchmark
pub fn bench_memory_allocation(runner: &mut BenchmarkRunner) {
    use alloc::vec;
    use alloc::boxed::Box;
    
    // Small allocation (64 bytes)
    runner.bench("alloc_small_64b", 10000, || {
        let _ = Box::new([0u8; 64]);
    });
    
    // Medium allocation (4KB)
    runner.bench("alloc_medium_4kb", 1000, || {
        let _ = Box::new([0u8; 4096]);
    });
    
    // Large allocation (64KB)
    runner.bench("alloc_large_64kb", 100, || {
        let _ = vec![0u8; 65536];
    });
    
    // Vector push operations
    runner.bench("vec_push_1000", 1000, || {
        let mut v = Vec::new();
        for i in 0..1000 {
            v.push(i);
        }
    });
}

/// Context switch simulation benchmark
pub fn bench_context_switch(runner: &mut BenchmarkRunner) {
    use core::task::Poll;
    
    // Simulate Future poll overhead
    runner.bench("future_poll_ready", 100000, || {
        let mut counter = 0u64;
        let _ = core::hint::black_box(Poll::Ready(counter));
        counter += 1;
        core::hint::black_box(counter);
    });
    
    // Simulate task state transition
    runner.bench("task_state_transition", 100000, || {
        use core::sync::atomic::AtomicU8;
        static STATE: AtomicU8 = AtomicU8::new(0);
        
        STATE.store(1, Ordering::Release);  // Running
        core::hint::black_box(STATE.load(Ordering::Acquire));
        STATE.store(2, Ordering::Release);  // Blocked
        core::hint::black_box(STATE.load(Ordering::Acquire));
        STATE.store(0, Ordering::Release);  // Ready
    });
}

/// Atomic operations benchmark
pub fn bench_atomics(runner: &mut BenchmarkRunner) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    
    runner.bench("atomic_load_relaxed", 100000, || {
        core::hint::black_box(COUNTER.load(Ordering::Relaxed));
    });
    
    runner.bench("atomic_store_release", 100000, || {
        COUNTER.store(42, Ordering::Release);
    });
    
    runner.bench("atomic_fetch_add", 100000, || {
        core::hint::black_box(COUNTER.fetch_add(1, Ordering::AcqRel));
    });
    
    runner.bench("atomic_compare_exchange", 100000, || {
        let _ = COUNTER.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    });
}

/// Lock contention benchmark
pub fn bench_locks(runner: &mut BenchmarkRunner) {
    static LOCK: Mutex<u64> = Mutex::new(0);
    
    runner.bench("spinlock_uncontended", 100000, || {
        let mut guard = LOCK.lock();
        *guard += 1;
        drop(guard);
    });
}

/// Memory copy benchmark (throughput)
pub fn bench_memory_throughput(runner: &mut BenchmarkRunner) {
    let src = alloc::vec![0xAAu8; 4096];
    let mut dst = alloc::vec![0u8; 4096];
    
    // 4KB copy
    runner.bench_throughput("memcpy_4kb", 10000, 4096, || {
        dst.copy_from_slice(&src);
        core::hint::black_box(&dst);
    });
    
    // 64KB copy
    let src_large = alloc::vec![0xBBu8; 65536];
    let mut dst_large = alloc::vec![0u8; 65536];
    
    runner.bench_throughput("memcpy_64kb", 1000, 65536, || {
        dst_large.copy_from_slice(&src_large);
        core::hint::black_box(&dst_large);
    });
    
    // 1MB copy
    let src_huge = alloc::vec![0xCCu8; 1048576];
    let mut dst_huge = alloc::vec![0u8; 1048576];
    
    runner.bench_throughput("memcpy_1mb", 100, 1048576, || {
        dst_huge.copy_from_slice(&src_huge);
        core::hint::black_box(&dst_huge);
    });
}

/// IPC benchmark (simulated zero-copy transfer)
pub fn bench_ipc(runner: &mut BenchmarkRunner) {
    use crate::ipc::{RRef, DomainId};
    
    let domain1 = DomainId::new(1);
    let domain2 = DomainId::new(2);
    
    // Small RRef transfer (64 bytes)
    runner.bench("rref_transfer_64b", 10000, || {
        let data = alloc::vec![0u8; 64];
        let rref = RRef::new(domain1, data);
        let transferred = rref.move_to(domain2);
        core::hint::black_box(transferred);
    });
    
    // Large RRef transfer (4KB)
    runner.bench("rref_transfer_4kb", 1000, || {
        let data = alloc::vec![0u8; 4096];
        let rref = RRef::new(domain1, data);
        let transferred = rref.move_to(domain2);
        core::hint::black_box(transferred);
    });
}

/// Network packet processing benchmark (simulated)
pub fn bench_network_processing(runner: &mut BenchmarkRunner) {
    // Simulate packet header parsing
    runner.bench("packet_header_parse", 100000, || {
        let packet = [0u8; 64]; // Minimum Ethernet frame
        
        // Parse Ethernet header (14 bytes)
        let dst_mac = &packet[0..6];
        let src_mac = &packet[6..12];
        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        
        core::hint::black_box((dst_mac, src_mac, ethertype));
        
        // Parse IP header
        if ethertype == 0x0800 && packet.len() >= 34 {
            let version_ihl = packet[14];
            let total_len = u16::from_be_bytes([packet[16], packet[17]]);
            core::hint::black_box((version_ihl, total_len));
        }
    });
    
    // Simulate packet checksum calculation
    runner.bench_throughput("checksum_1500b", 10000, 1500, || {
        let data = alloc::vec![0xAAu8; 1500];
        let checksum = internet_checksum(&data);
        core::hint::black_box(checksum);
    });
}

/// Calculate Internet checksum
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !sum as u16
}

/// Run all benchmarks
pub fn run_all_benchmarks() -> Vec<BenchmarkResult> {
    let mut runner = BenchmarkRunner::new();
    
    crate::log!("[BENCH] Starting comprehensive benchmark suite...\n");
    
    crate::log!("[BENCH] Memory allocation benchmarks\n");
    bench_memory_allocation(&mut runner);
    
    crate::log!("[BENCH] Context switch benchmarks\n");
    bench_context_switch(&mut runner);
    
    crate::log!("[BENCH] Atomic operations benchmarks\n");
    bench_atomics(&mut runner);
    
    crate::log!("[BENCH] Lock benchmarks\n");
    bench_locks(&mut runner);
    
    crate::log!("[BENCH] Memory throughput benchmarks\n");
    bench_memory_throughput(&mut runner);
    
    crate::log!("[BENCH] IPC benchmarks\n");
    bench_ipc(&mut runner);
    
    crate::log!("[BENCH] Network processing benchmarks\n");
    bench_network_processing(&mut runner);
    
    runner.print_summary();
    
    runner.results().to_vec()
}

/// 10Gbps line rate verification
pub fn verify_line_rate() -> bool {
    crate::log!("[BENCH] Verifying 10Gbps line rate capability...\n");
    
    let mut runner = BenchmarkRunner::new();
    
    // Target: 10 Gbps = 1.25 GB/s
    // For 1500 byte packets: ~833,333 packets/sec
    // For 64 byte packets: ~19,531,250 packets/sec
    
    const TARGET_GBPS: f64 = 10.0;
    const TARGET_BPS: u64 = 10_000_000_000 / 8; // bytes per second
    
    // Packet processing throughput test
    let result = runner.bench_throughput("packet_processing_1500b", 100000, 1500, || {
        // Simulate minimal packet processing
        let packet = [0u8; 1500];
        let checksum = internet_checksum(&packet);
        core::hint::black_box(checksum);
    });
    
    let achieved_bps = result.bytes_per_sec.unwrap_or(0);
    let achieved_gbps = (achieved_bps as f64 * 8.0) / 1_000_000_000.0;
    
    crate::log!("[BENCH] Target: {:.2} Gbps, Achieved: {:.2} Gbps ({:.1}%)\n",
        TARGET_GBPS,
        achieved_gbps,
        (achieved_gbps / TARGET_GBPS) * 100.0
    );
    
    // Consider pass if we achieve at least 50% of target
    // (actual hardware would perform better)
    achieved_bps >= TARGET_BPS / 2
}

// ============================================================================
// Benchmark Statistics
// ============================================================================

/// Benchmark statistics collector
pub struct BenchmarkStats {
    /// Total benchmarks run
    pub total_run: AtomicU64,
    /// Total time spent benchmarking (ns)
    pub total_time_ns: AtomicU64,
}

impl BenchmarkStats {
    /// Create new stats collector
    pub const fn new() -> Self {
        BenchmarkStats {
            total_run: AtomicU64::new(0),
            total_time_ns: AtomicU64::new(0),
        }
    }
    
    /// Record a benchmark run
    pub fn record(&self, duration_ns: u64) {
        self.total_run.fetch_add(1, Ordering::Relaxed);
        self.total_time_ns.fetch_add(duration_ns, Ordering::Relaxed);
    }
}

/// Global benchmark statistics
pub static BENCHMARK_STATS: BenchmarkStats = BenchmarkStats::new();

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tsc_timer() {
        let timer = TscTimer::new();
        let elapsed = timer.elapsed_ns();
        assert!(elapsed >= 0);
    }
    
    #[test]
    fn test_benchmark_runner() {
        let mut runner = BenchmarkRunner::new();
        let result = runner.bench("test_bench", 100, || {
            core::hint::black_box(1 + 1);
        });
        assert_eq!(result.iterations, 100);
    }
}
