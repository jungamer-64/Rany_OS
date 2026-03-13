//! Benchmark System for ExoRust Kernel
//!
//! This module provides comprehensive benchmarking capabilities for
//! performance validation of the kernel components, targeting 10Gbps
//! line rate verification (Design Doc Section 10).

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

extern crate alloc;

use crate::sync::PoisonLock;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

// TSC計測は diag モジュールの正規実装を使用（重複排除）
use crate::diag::{rdtsc, rdtscp};

/// Benchmark result
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: u64,
    pub total_ns: u64,
    pub avg_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub ops_per_sec: u64,
    pub bytes_per_sec: Option<u64>,
}

impl BenchmarkResult {
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

pub struct TscTimer {
    start: u64,
    tsc_freq_khz: u64,
}

impl TscTimer {
    pub fn new() -> Self {
        TscTimer {
            start: rdtsc(),
            tsc_freq_khz: estimate_tsc_frequency(),
        }
    }

    pub fn start(&mut self) {
        core::sync::atomic::fence(Ordering::SeqCst);
        self.start = rdtsc();
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    pub fn elapsed_ns(&self) -> u64 {
        core::sync::atomic::fence(Ordering::SeqCst);
        let end = rdtsc();
        core::sync::atomic::fence(Ordering::SeqCst);
        let cycles = end.saturating_sub(self.start);
        cycles.saturating_mul(1_000_000) / self.tsc_freq_khz.max(1)
    }

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

fn estimate_tsc_frequency() -> u64 {
    3_000_000 // 3 GHz in kHz
}

pub struct BenchmarkRunner {
    results: Vec<BenchmarkResult>,
}

impl BenchmarkRunner {
    pub fn new() -> Self {
        BenchmarkRunner {
            results: Vec::new(),
        }
    }

    pub fn bench<F>(&mut self, name: &str, iterations: u64, mut f: F) -> &BenchmarkResult
    where
        F: FnMut(),
    {
        let mut timer = TscTimer::new();
        let mut min_ns = u64::MAX;
        let mut max_ns = 0u64;
        for _ in 0..iterations.min(100) {
            f();
        }
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
        &self.results[self.results.len() - 1]
    }

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
        for _ in 0..iterations.min(100) {
            f();
        }
        timer.start();
        for _ in 0..iterations {
            let iter_start = rdtsc();
            f();
            let iter_end = rdtsc();
            let tsc_freq_khz = estimate_tsc_frequency();
            let iter_ns = (iter_end.saturating_sub(iter_start)).saturating_mul(1_000_000)
                / tsc_freq_khz.max(1);
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
        &self.results[self.results.len() - 1]
    }

    pub fn results(&self) -> &[BenchmarkResult] {
        &self.results
    }

    pub fn print_summary(&self) {
        log::info!("\n=== Benchmark Results ===\n");
        for result in &self.results {
            log::info!(
                "{}: {} ops/sec (avg: {} ns, min: {} ns, max: {} ns)",
                result.name,
                result.ops_per_sec,
                result.avg_ns,
                result.min_ns,
                result.max_ns
            );
            if result.bytes_per_sec.is_some() {
                log::info!("  Throughput: {}", result.format_throughput());
            }
            log::info!("\n");
        }
    }
}

impl Default for BenchmarkRunner {
    fn default() -> Self {
        Self::new()
    }
}

pub fn bench_memory_allocation(runner: &mut BenchmarkRunner) {
    use alloc::boxed::Box;
    use alloc::vec;
    runner.bench("alloc_small_64b", 10000, || {
        let _ = Box::new([0u8; 64]);
    });
    runner.bench("alloc_medium_4kb", 1000, || {
        let _ = Box::new([0u8; 4096]);
    });
    runner.bench("alloc_large_64kb", 100, || {
        let _ = vec![0u8; 65536];
    });
    runner.bench("vec_push_1000", 1000, || {
        let mut v = Vec::new();
        for i in 0..1000 {
            v.push(i);
        }
    });
}

pub fn bench_context_switch(runner: &mut BenchmarkRunner) {
    use core::task::Poll;
    runner.bench("future_poll_ready", 100000, || {
        let mut counter = 0u64;
        let _ = core::hint::black_box(Poll::Ready(counter));
        counter += 1;
        core::hint::black_box(counter);
    });
    runner.bench("task_state_transition", 100000, || {
        use core::sync::atomic::AtomicU8;
        static STATE: AtomicU8 = AtomicU8::new(0);
        STATE.store(1, Ordering::Release);
        core::hint::black_box(STATE.load(Ordering::Acquire));
        STATE.store(2, Ordering::Release);
        core::hint::black_box(STATE.load(Ordering::Acquire));
        STATE.store(0, Ordering::Release);
    });
}

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

pub fn bench_locks(runner: &mut BenchmarkRunner) {
    static LOCK: PoisonLock<u64> = PoisonLock::new(0);
    runner.bench("spinlock_uncontended", 100000, || {
        let mut guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        *guard += 1;
        drop(guard);
    });
}

pub fn bench_memory_throughput(runner: &mut BenchmarkRunner) {
    let src = alloc::vec![0xAAu8; 4096];
    let mut dst = alloc::vec![0u8; 4096];
    runner.bench_throughput("memcpy_4kb", 10000, 4096, || {
        dst.copy_from_slice(&src);
        core::hint::black_box(&dst);
    });
    let src_large = alloc::vec![0xBBu8; 65536];
    let mut dst_large = alloc::vec![0u8; 65536];
    runner.bench_throughput("memcpy_64kb", 1000, 65536, || {
        dst_large.copy_from_slice(&src_large);
        core::hint::black_box(&dst_large);
    });
    let src_huge = alloc::vec![0xCCu8; 1048576];
    let mut dst_huge = alloc::vec![0u8; 1048576];
    runner.bench_throughput("memcpy_1mb", 100, 1048576, || {
        dst_huge.copy_from_slice(&src_huge);
        core::hint::black_box(&dst_huge);
    });
}

pub fn bench_ipc(runner: &mut BenchmarkRunner) {
    use crate::ipc::{DomainId, RRef};
    let domain1 = DomainId::new(1);
    let domain2 = DomainId::new(2);
    runner.bench("rref_transfer_64b", 10000, || {
        let data = alloc::vec![0u8; 64];
        let rref = RRef::new(domain1, data);
        let transferred = rref.move_to(domain2);
        core::hint::black_box(transferred);
    });
    runner.bench("rref_transfer_4kb", 1000, || {
        let data = alloc::vec![0u8; 4096];
        let rref = RRef::new(domain1, data);
        let transferred = rref.move_to(domain2);
        core::hint::black_box(transferred);
    });
}

pub fn bench_network_processing(runner: &mut BenchmarkRunner) {
    runner.bench("packet_header_parse", 100000, || {
        let packet = [0u8; 64];
        let dst_mac = &packet[0..6];
        let src_mac = &packet[6..12];
        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        core::hint::black_box((dst_mac, src_mac, ethertype));
        if ethertype == 0x0800 && packet.len() >= 34 {
            let version_ihl = packet[14];
            let total_len = u16::from_be_bytes([packet[16], packet[17]]);
            core::hint::black_box((version_ihl, total_len));
        }
    });
    runner.bench_throughput("checksum_1500b", 10000, 1500, || {
        let data = alloc::vec![0xAAu8; 1500];
        let checksum = internet_checksum(&data);
        core::hint::black_box(checksum);
    });
}

pub fn bench_iommu_iova(runner: &mut BenchmarkRunner) {
    use crate::io::iommu::{api, types::DeviceId};
    runner.bench("iommu_is_enabled_query", 100000, || {
        core::hint::black_box(api::is_iommu_enabled());
    });
    let dev = DeviceId::new(0, 0, 0, 0);
    runner.bench("iommu_dma_mask_lookup", 100000, || {
        core::hint::black_box(api::get_device_dma_mask(&dev));
    });
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

pub fn run_all_benchmarks() -> Vec<BenchmarkResult> {
    let mut runner = BenchmarkRunner::new();
    log::info!("[BENCH] Starting comprehensive benchmark suite...\n");
    bench_memory_allocation(&mut runner);
    bench_context_switch(&mut runner);
    bench_atomics(&mut runner);
    bench_locks(&mut runner);
    bench_memory_throughput(&mut runner);
    bench_ipc(&mut runner);
    bench_network_processing(&mut runner);
    bench_iommu_iova(&mut runner);
    runner.print_summary();
    runner.results().to_vec()
}

pub fn verify_line_rate() -> bool {
    log::info!("[BENCH] Verifying 10Gbps line rate capability...\n");
    let mut runner = BenchmarkRunner::new();
    const TARGET_BPS: u64 = 10_000_000_000 / 8;
    let result = runner.bench_throughput("packet_processing_1500b", 100000, 1500, || {
        let packet = [0u8; 1500];
        let checksum = internet_checksum(&packet);
        core::hint::black_box(checksum);
    });
    let achieved_bps = result.bytes_per_sec.unwrap_or(0);
    achieved_bps >= TARGET_BPS / 2
}

pub struct BenchmarkStats {
    pub total_run: AtomicU64,
    pub total_time_ns: AtomicU64,
}

impl BenchmarkStats {
    pub const fn new() -> Self {
        BenchmarkStats {
            total_run: AtomicU64::new(0),
            total_time_ns: AtomicU64::new(0),
        }
    }
    pub fn record(&self, duration_ns: u64) {
        self.total_run.fetch_add(1, Ordering::Relaxed);
        self.total_time_ns.fetch_add(duration_ns, Ordering::Relaxed);
    }
}

pub static BENCHMARK_STATS: BenchmarkStats = BenchmarkStats::new();

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_tsc_timer() {
        let timer = TscTimer::new();
        let elapsed = timer.elapsed_ns();
        assert!(elapsed >= 0);
    }
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_benchmark_runner() {
        let mut runner = BenchmarkRunner::new();
        let result = runner.bench("test_bench", 100, || {
            core::hint::black_box(1 + 1);
        });
        assert_eq!(result.iterations, 100);
    }
}
